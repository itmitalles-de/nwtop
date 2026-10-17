use super::endpoints::socket_endpoints;
use super::rows::link_in_scope;
use super::status::{extended_status, pcap_status};
use super::*;
use crate::model::{CaptureStatus, ConnectionRow, ProcessRow};
use packet::Protocol;

fn interface(index: u32, loopback: bool, address: &str) -> KernelInterface {
    KernelInterface {
        info: Interface::default(),
        index,
        addresses: vec![address.parse().unwrap()],
        loopback,
        topology: LinkTopology::default(),
    }
}

fn flow(direction: Direction, interface_index: u32) -> Flow {
    Flow {
        source: "127.0.0.1".parse().unwrap(),
        destination: "127.0.0.1".parse().unwrap(),
        source_port: Some(12345),
        destination_port: Some(8080),
        protocol: Protocol::Tcp,
        direction,
        interface_index,
    }
}

#[test]
fn reset_counters_never_produce_wrapped_or_negative_rates() {
    assert_eq!(counter_rate(100, 200, 1.0), 0.0);
    assert_eq!(counter_rate(300, 100, 0.5), 400.0);
}

#[test]
fn loopback_has_sender_tx_and_receiver_rx_exactly_once() {
    let interfaces = vec![interface(1, true, "127.0.0.1")];
    let packet = flow(Direction::Outgoing, 1);
    assert_eq!(
        traffic_sides(&packet, &LocalView::new(&interfaces)),
        (true, true)
    );
    assert_eq!(socket_endpoints(&packet, false).unwrap().0.port(), 12345);
    assert_eq!(socket_endpoints(&packet, true).unwrap().0.port(), 8080);
}

#[test]
fn interface_selection_uses_capture_ifindex_not_ip_guesses() {
    assert!(link_in_scope(Link::plain(42), Some(42)));
    assert!(!link_in_scope(Link::plain(43), Some(42)));
    assert!(!link_in_scope(Link::plain(0), Some(42)));
    assert!(link_in_scope(Link::plain(43), None));
    let interfaces = vec![interface(2, false, "192.0.2.1")];
    assert_eq!(
        traffic_sides(&flow(Direction::Outgoing, 2), &LocalView::new(&interfaces)),
        (false, true)
    );
    assert_eq!(
        traffic_sides(&flow(Direction::Incoming, 2), &LocalView::new(&interfaces)),
        (true, false)
    );
}

#[test]
fn closed_sockets_with_traffic_this_interval_stay_listed() {
    let start = Instant::now();
    let mut attribution = Attribution::new(Inventory::new(), None);
    let socket = Socket {
        key: SocketKey {
            namespace: Inventory::new().host_namespace(),
            inode: 321,
            protocol: Protocol::Tcp,
            local: "192.0.2.1:23456".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
        },
        state: "ESTABLISHED".to_string(),
        uid: 1000,
        observed: start,
        current: false,
        ipv6_only: None,
        owners: vec![Owner {
            identity: ProcessIdentity {
                pid: 43,
                start_time: 1,
            },
            user: "test".to_string(),
            name: "brief".to_string(),
        }],
    };
    let mut deltas = Deltas::default();
    assert!(attribution.counters.record_owned(
        Link::plain(1),
        &socket,
        true,
        Bytes { rx: 10, tx: 20 },
        start,
        &mut deltas
    ));
    // A long refresh interval samples well after the socket closed.
    let sample = start + RECENT_TRAFFIC + Duration::from_secs(10);
    let (processes, connections) = attribution.rows(None, &[], sample, 20.0, &deltas, true);
    let row = processes.iter().find(|row| row.name == "brief").unwrap();
    assert_eq!((row.rx_bytes, row.tx_bytes), (10, 20));
    assert_eq!(connections.len(), 1);
    let (processes, connections) =
        attribution.rows(None, &[], sample, 20.0, &Deltas::default(), true);
    assert!(processes.iter().all(|row| row.name != "brief"));
    assert!(connections.is_empty());
}

#[test]
fn kernel_interface_snapshot_matches_proc_totals() {
    let interfaces = read_interfaces().unwrap();
    assert!(
        interfaces
            .iter()
            .any(|interface| interface.info.name == "lo" && interface.loopback)
    );
    assert!(interfaces.iter().all(|interface| interface.index > 0));
    assert!(default_interface().is_some());
}

#[test]
fn reused_pids_and_interface_scopes_keep_distinct_counters() {
    let now = Instant::now();
    let mut attribution = Attribution::new(Inventory::new(), None);
    let mut socket = Socket {
        key: SocketKey {
            namespace: Inventory::new().host_namespace(),
            inode: 123,
            protocol: Protocol::Tcp,
            local: "192.0.2.1:12345".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
        },
        state: "ESTABLISHED".to_string(),
        uid: 1000,
        observed: now,
        current: true,
        ipv6_only: None,
        owners: vec![Owner {
            identity: ProcessIdentity {
                pid: 42,
                start_time: 1,
            },
            user: "test".to_string(),
            name: "first".to_string(),
        }],
    };
    let mut deltas = Deltas::default();
    assert!(attribution.counters.record_owned(
        Link::plain(1),
        &socket,
        true,
        Bytes { rx: 0, tx: 100 },
        now,
        &mut deltas
    ));
    socket.owners[0].identity.start_time = 2;
    socket.owners[0].name = "second".to_string();
    assert!(attribution.counters.record_owned(
        Link::plain(1),
        &socket,
        true,
        Bytes { rx: 0, tx: 50 },
        now,
        &mut deltas
    ));
    assert!(attribution.counters.record_owned(
        Link::plain(2),
        &socket,
        true,
        Bytes { rx: 0, tx: 200 },
        now,
        &mut deltas
    ));
    let (selected, _) = attribution.rows(Some(1), &[], now, 1.0, &deltas, true);
    assert_eq!(selected.len(), 2);
    assert_eq!(
        selected
            .iter()
            .find(|row| row.name == "second")
            .unwrap()
            .tx_bytes,
        50
    );
    let (all, _) = attribution.rows(None, &[], now, 1.0, &deltas, true);
    assert_eq!(
        all.iter()
            .find(|row| row.name == "second")
            .unwrap()
            .tx_bytes,
        250
    );
    assert_eq!(
        all.iter().find(|row| row.name == "first").unwrap().tx_bytes,
        100
    );
    attribution.inventory.sockets.push(socket);
    let after_idle = now + COUNTER_RETENTION + Duration::from_secs(1);
    attribution.prune(after_idle, &[]);
    assert_eq!(
        attribution.counters.processes.len(),
        2,
        "open owner totals survive idle on both interfaces"
    );
    assert_eq!(
        attribution.counters.connections.len(),
        2,
        "open socket totals survive idle"
    );
    assert!(
        attribution
            .counters
            .processes
            .keys()
            .all(|(_, identity)| identity.start_time == 2)
    );
    attribution.inventory.sockets.clear();
    attribution.prune(after_idle, &[]);
    assert!(attribution.counters.processes.is_empty());
    assert!(attribution.counters.connections.is_empty());
}

#[test]
fn vanished_interface_is_empty_and_preserves_other_kernel_devices() {
    let mut collector = Collector::new(false).unwrap();
    let snapshot = collector
        .sample(Some("nwtop-test-interface-does-not-exist"))
        .unwrap();
    assert!(!snapshot.interfaces.is_empty());
    assert!(snapshot.processes.is_empty());
    assert!(snapshot.connections.is_empty());
    assert!(!snapshot.capture.active);
    assert!(snapshot.capture.message.starts_with("F2:"));
}

#[test]
fn forwarded_packets_cannot_match_host_wildcard_sockets() {
    let interfaces = vec![interface(2, false, "192.0.2.1")];
    let mut packet = flow(Direction::Incoming, 2);
    packet.source = "198.51.100.1".parse().unwrap();
    packet.destination = "203.0.113.2".parse().unwrap();
    assert_eq!(
        traffic_sides(&packet, &LocalView::new(&interfaces)),
        (true, false)
    );
    assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_none());
    packet.direction = Direction::Outgoing;
    assert!(local_socket_endpoints(&packet, false, &LocalView::new(&interfaces)).is_none());
    packet.destination = "192.0.2.1".parse().unwrap();
    assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_some());
    packet.destination = "224.0.0.251".parse().unwrap();
    assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_none());
    packet.source = "192.0.2.1".parse().unwrap();
    assert!(local_socket_endpoints(&packet, false, &LocalView::new(&interfaces)).is_some());
}

fn owned(local: &str, remote: &str, inode: u64, name: &str) -> Socket {
    Socket {
        key: SocketKey {
            namespace: Inventory::new().host_namespace(),
            inode,
            protocol: Protocol::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        },
        state: "LISTEN".to_string(),
        uid: 0,
        observed: Instant::now(),
        current: true,
        ipv6_only: None,
        owners: vec![Owner {
            identity: ProcessIdentity {
                pid: 4242,
                start_time: 1,
            },
            user: "root".to_string(),
            name: name.to_string(),
        }],
    }
}

#[test]
fn dnat_traffic_is_not_credited_to_docker_proxy_listener() {
    let interfaces = vec![
        interface(1, true, "127.0.0.1"),
        interface(2, false, "192.0.2.1"),
    ];
    let listener = owned("0.0.0.0:8080", "0.0.0.0:0", 1, "docker-proxy");
    let mut packet = flow(Direction::Incoming, 2);
    packet.destination = "192.0.2.1".parse().unwrap();
    assert!(published_port_proxy(
        &packet,
        &listener,
        &LocalView::new(&interfaces)
    ));
    // Loopback connections really reach the proxy.
    assert!(!published_port_proxy(
        &flow(Direction::Outgoing, 1),
        &listener,
        &LocalView::new(&interfaces)
    ));
    // Accepted proxy connections and other listeners keep attribution.
    let accepted = owned("192.0.2.1:8080", "198.51.100.1:5000", 2, "docker-proxy");
    assert!(!published_port_proxy(
        &packet,
        &accepted,
        &LocalView::new(&interfaces)
    ));
    let server = owned("0.0.0.0:8080", "0.0.0.0:0", 3, "nginx");
    assert!(!published_port_proxy(
        &packet,
        &server,
        &LocalView::new(&interfaces)
    ));
}

#[test]
fn flows_without_a_socket_wait_for_a_newer_table_once() {
    let interfaces = vec![interface(2, false, "192.0.2.1")];
    let view = LocalView::new(&interfaces);
    let mut inventory = Inventory::new();
    let table = Instant::now();
    inventory.set_refreshed_at(Some(table));
    let mut attribution = Attribution::new(inventory, None);
    let mut packet = flow(Direction::Incoming, 2);
    packet.source = "198.51.100.1".parse().unwrap();
    packet.destination = "192.0.2.1".parse().unwrap();
    // Drained after the latest table read: the socket may be newer.
    let drained = table + Duration::from_millis(10);
    attribution.attribute(&packet, true, 100, drained, drained, &view);
    assert_eq!(attribution.deferred.len(), 1);
    assert!(attribution.counters.unattributed.is_empty());
    // A table read after the drain still lacks it: give up.
    attribution
        .inventory
        .set_refreshed_at(Some(drained + Duration::from_millis(5)));
    let retry = drained + Duration::from_millis(20);
    attribution.deferred.clear();
    attribution.attribute(&packet, true, 100, drained, retry, &view);
    assert!(attribution.deferred.is_empty());
    assert_eq!(
        attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
        100
    );
    // Forwarded traffic never waits, whatever the table age.
    attribution.inventory.set_refreshed_at(None);
    packet.destination = "203.0.113.9".parse().unwrap();
    attribution.attribute(&packet, true, 100, retry, retry, &view);
    assert!(attribution.deferred.is_empty());
    assert_eq!(
        attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
        200
    );
}

#[test]
fn endpoint_packet_pressure_preserves_bytes_and_host_scope() {
    let mut attribution = Attribution::new(Inventory::new(), None);
    attribution.extended = Some(extended::Extended::empty_for_test());
    let now = Instant::now();
    let packet = events::PacketEvent {
        ip_bytes: 128,
        receive: 1,
        ifindex: 1,
        ..Default::default()
    };
    for _ in 0..MAX_DEFERRED + 17 {
        attribution.attribute_packet(packet, now, now);
    }
    assert_eq!(
        attribution.extended.as_ref().unwrap().pending_packets.len(),
        MAX_DEFERRED
    );
    assert_eq!(attribution.status.attribution_overflow, 17);
    assert_eq!(attribution.status.overflow, 0);
    assert_eq!(
        attribution.counters.unattributed[&Link::plain(0)].bytes.rx,
        17 * 128
    );
    let pending = std::mem::take(&mut attribution.extended.as_mut().unwrap().pending_packets);
    let later = now + Duration::from_secs(3);
    for item in pending {
        attribution.attribute_packet(item.packet, item.since, later);
    }
    assert!(
        attribution
            .extended
            .as_ref()
            .unwrap()
            .pending_packets
            .is_empty()
    );
    assert_eq!(
        attribution.counters.unattributed[&Link::plain(0)].bytes.rx,
        (MAX_DEFERRED as u64 + 17) * 128
    );
    assert!(link_in_scope(Link::plain(0), None));
    assert!(
        !link_in_scope(Link::plain(0), Some(1)),
        "foreign namespace lo must not select host lo"
    );
}

#[test]
fn deferral_outlasts_the_owner_scan_gap_within_bounds() {
    let attribution = Attribution::new(Inventory::new(), None);
    assert!(attribution.max_defer() >= MIN_DEFER);
    assert!(attribution.max_defer() >= attribution.inventory.owner_scan_gap());
    assert!(attribution.max_defer() <= MAX_DEFER);
}

#[test]
fn reuseport_ties_credit_the_process_but_no_single_connection() {
    let interfaces = vec![interface(2, false, "192.0.2.1")];
    let view = LocalView::new(&interfaces);
    let mut inventory = Inventory::new();
    inventory.sockets = [1, 2]
        .map(|inode| owned("0.0.0.0:8080", "0.0.0.0:0", inode, "server"))
        .into();
    inventory.rebuild_index();
    let mut attribution = Attribution::new(inventory, None);
    let mut packet = flow(Direction::Incoming, 2);
    packet.source = "198.51.100.1".parse().unwrap();
    packet.destination = "192.0.2.1".parse().unwrap();
    let now = Instant::now();
    attribution.attribute(&packet, true, 100, now, now, &view);
    assert!(attribution.counters.unattributed.is_empty());
    assert!(attribution.counters.connections.is_empty());
    let (processes, _) = attribution.rows(None, &interfaces, now, 1.0, &attribution.deltas, true);
    let row = processes.iter().find(|row| row.name == "server").unwrap();
    assert_eq!(row.rx_bytes, 100);
}

fn stacked(index: u32, address: Option<&str>, master: bool, uppers: Vec<u32>) -> KernelInterface {
    KernelInterface {
        info: Interface::default(),
        index,
        addresses: address.into_iter().map(|ip| ip.parse().unwrap()).collect(),
        loopback: false,
        topology: LinkTopology { master, uppers },
    }
}

#[test]
fn lower_devices_do_not_double_host_traffic_in_all_mode() {
    // eth0 is a bridge port of br0; eth1 carries VLAN eth1.100 and its own
    // untagged address.
    let interfaces = vec![
        stacked(2, None, true, vec![3]),
        stacked(3, Some("192.0.2.1"), false, vec![]),
        stacked(4, Some("198.51.100.1"), false, vec![5]),
        stacked(5, Some("203.0.113.1"), false, vec![]),
    ];
    let view = LocalView::new(&interfaces);
    let host: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(view.lower_observation(2, host));
    assert!(!view.lower_observation(3, host));
    assert!(view.lower_observation(4, "203.0.113.1".parse().unwrap()));
    assert!(!view.lower_observation(4, "198.51.100.1".parse().unwrap()));
    assert!(!view.lower_observation(5, "203.0.113.1".parse().unwrap()));

    let mut inventory = Inventory::new();
    inventory.sockets = vec![owned("0.0.0.0:8080", "0.0.0.0:0", 1, "server")];
    inventory.rebuild_index();
    let mut attribution = Attribution::new(inventory, None);
    let now = Instant::now();
    for index in [2, 3] {
        let mut packet = flow(Direction::Incoming, index);
        packet.source = "192.0.2.50".parse().unwrap();
        packet.destination = host;
        attribution.attribute(&packet, true, 100, now, now, &view);
    }
    let rx = |selected| {
        let (rows, _) =
            attribution.rows(selected, &interfaces, now, 1.0, &attribution.deltas, true);
        rows.iter()
            .find(|row| row.name == "server")
            .map_or(0, |row| row.rx_bytes)
    };
    assert_eq!(rx(None), 100, "the bridge port copy is not added again");
    assert_eq!(rx(Some(2)), 100, "a selected bridge port still shows it");
    assert_eq!(rx(Some(3)), 100);
}

#[test]
fn flows_of_unscanned_sockets_are_deferred_briefly() {
    let interfaces = vec![interface(2, false, "192.0.2.1")];
    let mut socket = owned("192.0.2.1:8080", "198.51.100.1:5000", 9, "server");
    socket.owners.clear();
    socket.state = "ESTABLISHED".to_string();
    let mut inventory = Inventory::new();
    inventory.sockets = vec![socket];
    inventory.rebuild_index();
    let mut attribution = Attribution::new(inventory, None);
    let mut packet = flow(Direction::Incoming, 2);
    packet.source = "198.51.100.1".parse().unwrap();
    packet.source_port = Some(5000);
    packet.destination = "192.0.2.1".parse().unwrap();
    let now = Instant::now();
    let view = LocalView::new(&interfaces);
    attribution.attribute(&packet, true, 100, now, now, &view);
    attribution.attribute(&packet, true, 50, now, now, &view);
    assert_eq!(attribution.deferred.len(), 1, "one flow, merged");
    assert_eq!(attribution.deferred[&(packet.clone(), true)].bytes, 150);
    assert!(attribution.counters.unattributed.is_empty());
    // After the retry window the bytes are reported as unattributed.
    let later = now + attribution.max_defer();
    attribution.attribute(&packet, true, 100, now, later, &view);
    assert_eq!(attribution.deferred.len(), 1);
    assert_eq!(
        attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
        100
    );
}
#[test]
fn selected_host_links_seed_only_host_sockets_but_keep_foreign_capture_counters() {
    let mut inventory = Inventory::new();
    let host = inventory.host_namespace();
    let owner = Owner {
        identity: ProcessIdentity {
            pid: 200,
            start_time: 100,
        },
        user: "test".into(),
        name: "container-service".into(),
    };
    for (inode, local) in [(200, "127.0.0.1:8080"), (201, "0.0.0.0:8081")] {
        inventory.sockets.push(Socket {
            key: SocketKey {
                namespace: host + 1,
                inode,
                protocol: Protocol::Tcp,
                local: local.parse().unwrap(),
                remote: "0.0.0.0:0".parse().unwrap(),
            },
            state: "LISTEN".into(),
            uid: 1000,
            owners: vec![owner.clone()],
            observed: Instant::now(),
            current: true,
            ipv6_only: None,
        });
    }
    let mut host_socket = inventory.sockets[0].clone();
    host_socket.key.namespace = host;
    host_socket.key.inode = 202;
    host_socket.owners[0].identity.pid = 300;
    inventory.sockets.push(host_socket);
    let interfaces = vec![
        interface(1, true, "127.0.0.1"),
        interface(2, false, "192.0.2.1"),
    ];
    let mut attribution = Attribution::new(inventory, None);
    let now = Instant::now();
    let (all, _) = attribution.rows(None, &interfaces, now, 1.0, &Deltas::default(), true);
    assert!(all.iter().any(|r| r.pid == Some(200) && r.connections == 2));
    for selected in [1, 2] {
        let (processes, connections) = attribution.rows(
            Some(selected),
            &interfaces,
            now,
            1.0,
            &Deltas::default(),
            true,
        );
        assert!(!processes.iter().any(|r| r.pid == Some(200)));
        assert!(!connections.iter().any(|r| r.pid == Some(200)));
    }
    let (host_lo, _) = attribution.rows(Some(1), &interfaces, now, 1.0, &Deltas::default(), true);
    assert!(
        host_lo
            .iter()
            .any(|r| r.pid == Some(300) && r.connections == 1)
    );
    let observed = attribution.inventory.sockets[0].clone();
    assert!(attribution.counters.record_owned(
        Link::plain(2),
        &observed,
        true,
        Bytes { rx: 1028, tx: 0 },
        now,
        &mut attribution.deltas
    ));
    let (processes, connections) =
        attribution.rows(Some(2), &interfaces, now, 1.0, &attribution.deltas, true);
    assert!(processes.iter().any(|r| r.pid == Some(200)
        && r.rx_bytes == 1028
        && r.rx_rate == 1028.0
        && r.connections == 1));
    assert!(
        connections
            .iter()
            .any(|r| r.pid == Some(200) && r.rx_bytes == 1028 && r.state == "LISTEN")
    );
    let (host_lo, _) = attribution.rows(Some(1), &interfaces, now, 1.0, &attribution.deltas, true);
    assert!(!host_lo.iter().any(|r| r.pid == Some(200)));
}

#[test]
fn disabled_capture_snapshots_report_status_and_kernel_rates() {
    let mut collector = Collector::new(false).unwrap();
    for interface in [None, Some("lo")] {
        let snapshot = collector.sample(interface).unwrap();
        let status = &snapshot.capture;
        assert!(!status.active);
        assert_eq!(status.dropped, 0);
        assert_eq!(status.notes.first(), Some(&CaptureNote::Disabled));
        assert!(status.notes[1..].iter().all(|note| matches!(
            note,
            CaptureNote::OwnersInaccessible | CaptureNote::CounterLimit
        )));
        assert_eq!(
            status.message,
            Lang::En.capture_status(status, true).unwrap_or_default()
        );
        // Without capture, listed sockets have no measured rates.
        assert!(
            snapshot
                .processes
                .iter()
                .all(|row| row.rx_rate == 0.0 && row.tx_rate == 0.0)
        );
        assert!(
            snapshot
                .connections
                .iter()
                .all(|row| row.rx_rate == 0.0 && row.tx_rate == 0.0)
        );
        assert!(
            snapshot
                .interfaces
                .iter()
                .all(|interface| interface.rx_rate >= 0.0 && interface.tx_rate >= 0.0)
        );
        // The next interval starts from exactly these kernel counters.
        assert_eq!(
            collector.previous_interfaces.len(),
            snapshot.interfaces.len()
        );
        for interface in &snapshot.interfaces {
            let (_, rx, tx) = collector.previous_interfaces[&interface.name];
            assert_eq!((rx, tx), (interface.rx_bytes, interface.tx_bytes));
        }
    }
}

#[test]
fn row_totals_rates_scope_and_order_are_stable() {
    let now = Instant::now();
    let mut attribution = Attribution::new(Inventory::new(), None);
    let host = attribution.inventory.host_namespace();
    let socket = |inode: u64, pid: u32, local: &str, remote: &str, current: bool| Socket {
        key: SocketKey {
            namespace: host,
            inode,
            protocol: Protocol::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        },
        state: "ESTABLISHED".to_string(),
        uid: 0,
        observed: now,
        current,
        ipv6_only: None,
        owners: vec![Owner {
            identity: ProcessIdentity { pid, start_time: 1 },
            user: "root".to_string(),
            name: format!("p{pid}"),
        }],
    };
    let listed = socket(1, 10, "192.0.2.1:1000", "198.51.100.1:443", true);
    let closed = socket(2, 20, "192.0.2.1:2000", "198.51.100.1:443", false);
    let mut ownerless = socket(3, 30, "192.0.2.1:3000", "198.51.100.1:443", true);
    ownerless.owners.clear();
    attribution
        .inventory
        .sockets
        .extend([listed.clone(), ownerless]);
    let mut deltas = Deltas::default();
    for (link, socket, bytes) in [
        (1, &listed, Bytes { rx: 100, tx: 50 }),
        (2, &listed, Bytes { rx: 7, tx: 0 }),
        (1, &closed, Bytes { rx: 300, tx: 0 }),
    ] {
        assert!(attribution.counters.record_owned(
            Link::plain(link),
            socket,
            true,
            bytes,
            now,
            &mut deltas
        ));
    }
    attribution.counters.record_unknown(
        Link::plain(1),
        Bytes { rx: 5, tx: 6 },
        now,
        &mut deltas.unknown,
    );
    let interfaces = [
        interface(1, false, "192.0.2.1"),
        interface(2, false, "192.0.2.1"),
    ];
    let summary = |(processes, connections): (Vec<ProcessRow>, Vec<ConnectionRow>)| {
        (
            processes
                .iter()
                .map(|r| {
                    format!(
                        "{:?} {} {} {} {} {} {} {}",
                        r.pid,
                        r.name,
                        r.connections,
                        r.rx_bytes,
                        r.tx_bytes,
                        r.rx_rate,
                        r.tx_rate,
                        r.user
                    )
                })
                .collect::<Vec<_>>(),
            connections
                .iter()
                .map(|r| {
                    format!(
                        "{:?} {} {} {} {} {} {} {}",
                        r.pid,
                        r.local,
                        r.state,
                        r.rx_bytes,
                        r.tx_bytes,
                        r.rx_rate,
                        r.tx_rate,
                        r.process
                    )
                })
                .collect::<Vec<_>>(),
        )
    };
    let later = now + RECENT_TRAFFIC + Duration::from_secs(1);
    let all = summary(attribution.rows(None, &interfaces, now, 2.0, &deltas, true));
    assert_eq!(
        all,
        (
            vec![
                "Some(20) p20 0 300 0 150 0 root".to_string(),
                "Some(10) p10 1 107 50 53.5 25 root".to_string(),
                "None [unattributed] 1 5 6 2.5 3 -".to_string(),
            ],
            vec![
                "Some(20) 192.0.2.1:2000 RECENT/CLOSED 300 0 150 0 p20".to_string(),
                "Some(10) 192.0.2.1:1000 ESTABLISHED 107 50 53.5 25 p10".to_string(),
                "None 192.0.2.1:3000 ESTABLISHED 0 0 0 0 [unknown]".to_string(),
            ],
        )
    );
    let selected = summary(attribution.rows(Some(2), &interfaces, now, 2.0, &deltas, false));
    assert_eq!(
        selected,
        (
            vec![
                "None [unattributed] 1 0 0 0 0 -".to_string(),
                "Some(10) p10 1 7 0 0 0 root".to_string(),
            ],
            vec![
                "None 192.0.2.1:3000 ESTABLISHED 0 0 0 0 [unknown]".to_string(),
                "Some(10) 192.0.2.1:1000 ESTABLISHED 7 0 0 0 p10".to_string(),
            ],
        )
    );
    let quiet = summary(attribution.rows(None, &interfaces, later, 2.0, &Deltas::default(), true));
    assert_eq!(
        quiet,
        (
            vec![
                "None [unattributed] 1 5 6 0 0 -".to_string(),
                "Some(10) p10 1 107 50 0 0 root".to_string(),
            ],
            vec![
                "None 192.0.2.1:3000 ESTABLISHED 0 0 0 0 [unknown]".to_string(),
                "Some(10) 192.0.2.1:1000 ESTABLISHED 107 50 0 0 p10".to_string(),
            ],
        )
    );
}

#[test]
fn pcap_status_reports_scope_interval_problems_and_stops() {
    let start = || CaptureStatus {
        active: true,
        notes: vec![CaptureNote::Disabled],
        ..CaptureStatus::default()
    };
    let quiet = IntervalStatus::default();
    let mut status = start();
    pcap_status(&mut status, &quiet, false, false, None, None);
    assert!(status.active);
    assert_eq!(status.notes, vec![CaptureNote::AllInterfaces]);
    let mut status = start();
    pcap_status(&mut status, &quiet, true, false, None, None);
    assert!(!status.active);
    assert_eq!(status.notes, vec![CaptureNote::NoInterfaceIndexes]);
    let problems = IntervalStatus {
        timestamp_invalid: 9,
        dropped: 1,
        overflow: 2,
        attribution_overflow: 3,
        unsupported: 0,
        truncated: 4,
    };
    let mut status = start();
    pcap_status(&mut status, &problems, true, true, Some("worker"), None);
    assert!(status.active);
    assert_eq!(status.dropped, 3);
    assert_eq!(
        status.notes,
        vec![
            CaptureNote::Sampled,
            CaptureNote::PcapMissed { packets: 1 },
            CaptureNote::CaptureQueueLimit { packets: 2 },
            CaptureNote::AttributionQueueLimit { packets: 3 },
            CaptureNote::Unreadable {
                unsupported: 0,
                truncated: 4,
            },
            CaptureNote::AttributionAtRefresh {
                error: "worker".into(),
            },
        ]
    );
    let mut status = start();
    pcap_status(
        &mut status,
        &problems,
        false,
        true,
        Some("worker"),
        Some("gone"),
    );
    assert!(!status.active);
    assert_eq!(status.dropped, 3);
    assert_eq!(
        status.notes,
        vec![CaptureNote::Stopped {
            error: "gone".into()
        }]
    );
}

#[test]
fn extended_status_lists_issues_and_consumes_unconfirmed_flows() {
    let mut extended = extended::Extended::empty_for_test();
    extended.issues = vec!["conntrack: initial synchronization pending".into()];
    extended.unconfirmed.set(true);
    let mut status = CaptureStatus {
        active: true,
        notes: vec![CaptureNote::AllInterfaces, CaptureNote::Sampled],
        ..CaptureStatus::default()
    };
    let problems = IntervalStatus {
        timestamp_invalid: 2,
        ..IntervalStatus::default()
    };
    extended_status(&mut status, &extended, &problems, true);
    assert!(status.active);
    assert!(!extended.unconfirmed.get());
    assert_eq!(
        status.notes,
        vec![
            CaptureNote::AllInterfaces,
            CaptureNote::Sampled,
            CaptureNote::ExtendedIssue {
                detail: "conntrack: initial synchronization pending".into()
            },
            CaptureNote::ExtendedIssue {
                detail: "no confirmed conntrack entry for some flows; only positive socket events can attribute them".into()
            },
        ]
    );
    extended_status(&mut status, &extended, &problems, true);
    assert_eq!(status.notes.len(), 5);
}
