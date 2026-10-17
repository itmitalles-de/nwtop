use super::owner_index::MAX_OWNER_INODES;
use super::*;
use crate::collector::{
    events::Event,
    packet::Protocol,
    sockets::{Owner, ProcessIdentity, SocketKey},
};
use std::net::{Ipv4Addr, SocketAddr};

fn extended() -> Extended {
    Extended {
        veth: HashSet::from([100, 101]),
        ..Extended::empty_for_test()
    }
}
fn packet(source: &str, destination: &str, index: u32, direction: Direction) -> Flow {
    let source: SocketAddr = source.parse().unwrap();
    let destination: SocketAddr = destination.parse().unwrap();
    Flow {
        source: source.ip(),
        destination: destination.ip(),
        source_port: Some(source.port()),
        destination_port: Some(destination.port()),
        protocol: Protocol::Udp,
        interface_index: index,
        direction,
    }
}
fn bytes() -> TimedBytes {
    TimedBytes {
        bytes: 1024,
        first: 15_000_000,
        last: 15_000_000,
    }
}
fn view() -> LocalView {
    let mut view = LocalView::default();
    view.addresses.insert("192.0.2.1".parse().unwrap());
    view.loopback.insert(1);
    view
}
fn listener(inventory: &Inventory, inode: u64) -> Socket {
    Socket {
        key: SocketKey {
            namespace: inventory.host_namespace(),
            inode,
            protocol: Protocol::Udp,
            local: "0.0.0.0:8080".parse().unwrap(),
            remote: "0.0.0.0:0".parse().unwrap(),
        },
        state: "BOUND".into(),
        uid: 1000,
        owners: vec![Owner {
            identity: ProcessIdentity {
                pid: 42,
                start_time: 100,
            },
            user: "test".into(),
            name: "unrelated-service".into(),
        }],
        observed: Instant::now(),
        current: true,
        ipv6_only: None,
    }
}
fn actor(namespace: u64, id: u64, local: &str, remote: &str, receive: bool) -> Event {
    let local: SocketAddr = local.parse().unwrap();
    let remote: SocketAddr = remote.parse().unwrap();
    let mut local_addr = [0; 16];
    let mut remote_addr = [0; 16];
    local_addr[..4].copy_from_slice(&local.ip().to_string().parse::<Ipv4Addr>().unwrap().octets());
    remote_addr[..4].copy_from_slice(
        &remote
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    Event {
        netns: namespace.try_into().unwrap(),
        inode: id,
        socket_id: id,
        tgid: id as u32,
        process_start_ns: 1_000_000_000,
        started_ns: 10_000_000,
        timestamp_ns: 20_000_000,
        family: libc::AF_INET as u16,
        protocol: 17,
        local_addr,
        remote_addr,
        local_port: local.port(),
        remote_port: remote.port(),
        kind: if receive { 2 } else { 1 },
        ..Event::default()
    }
}

#[test]
fn actual_foreign_socket_packet_needs_no_conntrack_but_vetoes_changed_owners() {
    let mut inventory = Inventory::new();
    let namespace = inventory.host_namespace() + 1;
    let mut socket = listener(&inventory, 200);
    socket.key.namespace = namespace;
    socket.key.local = "127.0.0.1:8080".parse().unwrap();
    socket.key.remote = "127.0.0.1:40000".parse().unwrap();
    socket.owners[0].identity = ProcessIdentity {
        pid: 200,
        start_time: unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64,
    };
    inventory.sockets.push(socket);
    let event = actor(namespace, 200, "127.0.0.1:8080", "127.0.0.1:40000", true);
    let packet = PacketEvent {
        timestamp_ns: 25_000_000,
        socket_id: 200,
        inode: 200,
        netns: namespace as u32,
        ifindex: 1, // Not the host's loopback despite sharing its index.
        ip_bytes: 1052,
        family: libc::AF_INET as u16,
        protocol: 17,
        local_port: 8080,
        remote_port: 40000,
        local_addr: event.local_addr,
        remote_addr: event.remote_addr,
        receive: 1,
        ..PacketEvent::default()
    };
    let mut extended = extended();
    extended
        .owners
        .update(vec![event], 0, 30_000_000, &inventory);
    extended.sampled_owners.refresh(&inventory);
    assert!(
        matches!(extended.resolve_packet(&packet, &inventory, false), PacketResult::Owned(socket, _) if socket.key.namespace == namespace && socket.owner().unwrap().identity.pid == 200)
    );
    // Distinct peers on one unconnected UDP descriptor must not inherit
    // the inventory wildcard or the previous lifecycle event's peer.
    inventory.sockets[0].key.remote = "0.0.0.0:0".parse().unwrap();
    for remote_port in [41000, 42000] {
        let peer_packet = PacketEvent {
            flags: 1,
            remote_port,
            ..packet
        };
        let PacketResult::Owned(socket, known) =
            extended.resolve_packet(&peer_packet, &inventory, true)
        else {
            panic!("same proven descriptor");
        };
        assert!(known);
        assert_eq!(socket.key.remote.port(), remote_port);
        assert_eq!(socket.key.inode, packet.inode);
    }
    assert!(
        matches!(
            extended.resolve_packet(&packet, &inventory, true),
            PacketResult::Owned(_, false)
        ),
        "incomplete transport headers must only credit process bytes"
    );
    // Same PID number with a new start time is not the packet's actor.
    inventory.sockets[0].owners[0].identity.start_time += 1;
    extended.sampled_owners.refresh(&inventory);
    assert!(matches!(
        extended.resolve_packet(&packet, &inventory, false),
        PacketResult::Pending
    ));
    assert!(matches!(
        extended.resolve_packet(&packet, &inventory, true),
        PacketResult::Unknown
    ));
}

#[test]
fn packet_loss_or_shared_descriptors_never_select_one_actor() {
    let mut inventory = Inventory::new();
    let namespace = inventory.host_namespace();
    let event = actor(namespace, 200, "192.0.2.1:8080", "198.51.100.2:40000", true);
    let packet = PacketEvent {
        timestamp_ns: 15_000_000,
        socket_id: 200,
        inode: 200,
        netns: namespace as u32,
        ifindex: 2,
        ip_bytes: 1052,
        family: libc::AF_INET as u16,
        protocol: 17,
        receive: 1,
        local_port: event.local_port,
        remote_port: event.remote_port,
        local_addr: event.local_addr,
        remote_addr: event.remote_addr,
        ..PacketEvent::default()
    };
    let mut extended = extended();
    extended
        .owners
        .update(vec![event], 0, 21_000_000, &inventory);
    assert!(matches!(
        extended.resolve_packet(&packet, &inventory, true),
        PacketResult::Owned(_, _)
    ));
    let mut shared = listener(&inventory, 200);
    shared.owners.push(shared.owners[0].clone());
    inventory.sockets.push(shared);
    extended.sampled_owners.refresh(&inventory);
    assert!(matches!(
        extended.resolve_packet(&packet, &inventory, true),
        PacketResult::Unknown
    ));
    inventory.sockets.clear();
    extended.sampled_owners.refresh(&inventory);
    extended
        .owners
        .update(Vec::new(), 1, 22_000_000, &inventory);
    assert!(matches!(
        extended.resolve_packet(&packet, &inventory, true),
        PacketResult::Unknown
    ));
}

#[test]
fn missing_or_lost_conntrack_cannot_credit_a_pre_dnat_host_listener() {
    let mut inventory = Inventory::new();
    inventory.sockets.push(listener(&inventory, 10));
    inventory.rebuild_index();
    let extended = extended();
    let flow = packet(
        "198.51.100.2:40000",
        "192.0.2.1:8080",
        2,
        Direction::Incoming,
    );
    for state in [
        None,
        Some(conntrack::Outcome::Missing),
        Some(conntrack::Outcome::Unavailable),
    ] {
        assert!(matches!(
            extended.resolve_with_translation(&flow, bytes(), &inventory, &view(), false, state),
            Result::Pending
        ));
        let Result::Owned(owners, unknown) =
            extended.resolve_with_translation(&flow, bytes(), &inventory, &view(), true, state)
        else {
            panic!("expired bytes must remain unknown");
        };
        assert!(owners.is_empty());
        assert_eq!(unknown, vec![(true, false)]);
    }
    let Result::Owned(owners, unknown) = extended.resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        false,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("confirmed local traffic should resolve");
    };
    assert_eq!(owners.len(), 1);
    assert!(owners[0].3);
    assert!(unknown.is_empty());
}

#[test]
fn queued_receive_needs_matching_current_descriptor_and_conntrack() {
    let mut inventory = Inventory::new();
    inventory.sockets.push(listener(&inventory, 42));
    inventory.rebuild_index();
    let mut extended = extended();
    extended.owners.update(
        vec![actor(
            inventory.host_namespace(),
            42,
            "192.0.2.1:8080",
            "198.51.100.2:40000",
            true,
        )],
        0,
        21_000_000,
        &inventory,
    );
    extended.sampled_owners.refresh(&inventory);
    let flow = packet(
        "198.51.100.2:40000",
        "192.0.2.1:8080",
        2,
        Direction::Incoming,
    );
    let queued = TimedBytes {
        bytes: 1024,
        first: 9_500_000,
        last: 9_500_000,
    };
    let Result::Owned(owners, unknown) = extended.resolve_with_translation(
        &flow,
        queued,
        &inventory,
        &view(),
        false,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("current descriptor must corroborate the observed actor");
    };
    assert_eq!(owners.len(), 1);
    assert!(unknown.is_empty());
    assert!(matches!(
        extended.resolve_with_translation(
            &flow,
            queued,
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unavailable),
        ),
        Result::Pending
    ));
    inventory.sockets[0].owners[0].identity.pid = 99;
    extended.sampled_owners.refresh(&inventory);
    assert!(matches!(
        extended.resolve_with_translation(
            &flow,
            queued,
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ),
        Result::Pending
    ));
}

#[test]
fn reuseport_ties_credit_the_process_without_inventing_a_connection() {
    let mut inventory = Inventory::new();
    inventory.sockets = vec![listener(&inventory, 10), listener(&inventory, 11)];
    inventory.rebuild_index();
    let flow = packet(
        "198.51.100.2:40000",
        "192.0.2.1:8080",
        2,
        Direction::Incoming,
    );
    let Result::Owned(owners, _) = extended().resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        false,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("process should be certain");
    };
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].0.owner().unwrap().identity.pid, 42);
    assert!(!owners[0].3);
}

#[test]
fn container_to_container_observations_count_each_boundary_once() {
    let inventory = Inventory::new();
    let mut extended = extended();
    extended.owners.update(
        vec![
            actor(
                inventory.host_namespace() + 1,
                200,
                "172.18.0.2:40000",
                "172.18.0.3:8080",
                false,
            ),
            actor(
                inventory.host_namespace() + 2,
                300,
                "172.18.0.3:8080",
                "172.18.0.2:40000",
                true,
            ),
        ],
        0,
        21_000_000,
        &inventory,
    );
    for (index, direction, sender_lower, receiver_lower) in [
        (100, Direction::Incoming, false, true),
        (101, Direction::Outgoing, true, false),
        (2, Direction::Incoming, true, true),
    ] {
        let flow = packet("172.18.0.2:40000", "172.18.0.3:8080", index, direction);
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("event evidence should resolve");
        };
        assert_eq!(owners.len(), 2);
        assert_eq!((owners[0].1, owners[0].2), (false, sender_lower));
        assert_eq!((owners[1].1, owners[1].2), (true, receiver_lower));
        assert!(unknown.is_empty());
    }
}

#[test]
fn dnat_uses_receiver_translated_endpoints_and_preserves_selected_physical_link() {
    let inventory = Inventory::new();
    let mut extended = extended();
    extended.owners.update(
        vec![actor(
            inventory.host_namespace() + 1,
            200,
            "172.18.0.2:80",
            "198.51.100.2:40000",
            true,
        )],
        0,
        21_000_000,
        &inventory,
    );
    let flow = packet(
        "198.51.100.2:40000",
        "192.0.2.1:8080",
        2,
        Direction::Incoming,
    );
    let translation = conntrack::Translation {
        before: conntrack::Tuple {
            protocol: Protocol::Udp,
            source: "198.51.100.2:40000".parse().unwrap(),
            destination: "192.0.2.1:8080".parse().unwrap(),
        },
        after: conntrack::Tuple {
            protocol: Protocol::Udp,
            source: "198.51.100.2:40000".parse().unwrap(),
            destination: "172.18.0.2:80".parse().unwrap(),
        },
        zones: (0, 0),
    };
    let Result::Owned(owners, _) = extended.resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        false,
        Some(conntrack::Outcome::Translated(translation)),
    ) else {
        panic!("container event should resolve through DNAT");
    };
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].0.owner().unwrap().identity.pid, 200);
    assert!(owners[0].1 && owners[0].2);
}

#[test]
fn ambiguous_namespace_addresses_and_nonlocal_wildcards_are_not_guessed() {
    let mut inventory = Inventory::new();
    inventory.sockets.push(listener(&inventory, 10));
    inventory.rebuild_index();
    let mut extended = extended();
    let flow = packet(
        "198.51.100.2:40000",
        "172.18.0.2:8080",
        100,
        Direction::Outgoing,
    );
    assert!(matches!(
        extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged)
        ),
        Result::Unknown
    ));
    extended.owners.update(
        vec![
            actor(
                inventory.host_namespace() + 1,
                200,
                "172.18.0.2:8080",
                "198.51.100.2:40000",
                true,
            ),
            actor(
                inventory.host_namespace() + 2,
                300,
                "172.18.0.2:8080",
                "198.51.100.3:40000",
                true,
            ),
        ],
        0,
        21_000_000,
        &inventory,
    );
    let Result::Owned(owners, unknown) = extended.resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        false,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("ambiguous receiver must remain unknown");
    };
    assert!(owners.is_empty());
    assert_eq!(unknown, vec![(true, false)]);
}

#[test]
fn partial_loopback_ownership_keeps_the_other_endpoints_bytes_after_defer() {
    let inventory = Inventory::new();
    let mut extended = extended();
    extended.owners.update(
        vec![actor(
            inventory.host_namespace(),
            200,
            "127.0.0.1:40000",
            "127.0.0.1:8080",
            false,
        )],
        0,
        21_000_000,
        &inventory,
    );
    let flow = packet("127.0.0.1:40000", "127.0.0.1:8080", 1, Direction::Incoming);
    assert!(matches!(
        extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged)
        ),
        Result::Pending
    ));
    let Result::Owned(owners, unknown) = extended.resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        true,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("partial result expected after timeout");
    };
    assert_eq!(owners.len(), 1);
    assert!(!owners[0].1);
    assert_eq!(unknown, vec![(true, false)]);
}

#[test]
fn ambiguous_receiver_does_not_erase_certain_sender_evidence() {
    let inventory = Inventory::new();
    let mut extended = extended();
    let host = inventory.host_namespace();
    extended.owners.update(
        vec![
            actor(host, 200, "127.0.0.1:40000", "127.0.0.1:8080", false),
            actor(host, 300, "127.0.0.1:8080", "127.0.0.1:40000", true),
            actor(host, 301, "127.0.0.1:8080", "127.0.0.1:40000", true),
        ],
        0,
        21_000_000,
        &inventory,
    );
    let flow = packet("127.0.0.1:40000", "127.0.0.1:8080", 1, Direction::Incoming);
    assert!(matches!(
        extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged)
        ),
        Result::Pending
    ));
    let Result::Owned(owners, unknown) = extended.resolve_with_translation(
        &flow,
        bytes(),
        &inventory,
        &view(),
        true,
        Some(conntrack::Outcome::Unchanged),
    ) else {
        panic!("certain sender must survive receiver ambiguity");
    };
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].0.owner().unwrap().identity.pid, 200);
    assert!(!owners[0].1);
    assert_eq!(unknown, vec![(true, false)]);
}
#[test]
fn owner_index_combines_current_holders_and_clears_stale_vetoes() {
    let mut inventory = Inventory::new();
    let socket = listener(&inventory, 42);
    let mut index = OwnerIndex::default();
    inventory.sockets.push(socket.clone());
    index.refresh(&inventory);
    assert!(!index.vetoes(&socket));
    let mut conflicting = socket.clone();
    conflicting.owners[0].identity.start_time += 1;
    inventory.sockets.push(conflicting.clone());
    index.refresh(&inventory);
    assert!(index.vetoes(&socket) && index.vetoes(&conflicting));
    inventory.sockets[1].current = false;
    index.refresh(&inventory);
    assert!(!index.vetoes(&socket));
    assert!(index.vetoes(&conflicting));
    inventory.sockets[1].current = true;
    inventory.sockets[1].key.namespace += 1;
    index.refresh(&inventory);
    assert!(!index.vetoes(&socket));
    inventory.sockets.clear();
    index.refresh(&inventory);
    assert!(!index.vetoes(&conflicting));
}

#[test]
fn owner_index_rejects_shared_descriptors_and_overflow_without_guessing() {
    let mut inventory = Inventory::new();
    let socket = listener(&inventory, 42);
    let mut shared = socket.clone();
    shared.owners.push(Owner {
        identity: ProcessIdentity {
            pid: 99,
            start_time: 100,
        },
        ..shared.owners[0].clone()
    });
    inventory.sockets.push(shared);
    let mut index = OwnerIndex::default();
    index.refresh(&inventory);
    assert!(index.vetoes(&socket));
    inventory.sockets = (0..=MAX_OWNER_INODES as u64)
        .map(|inode| {
            let mut value = socket.clone();
            value.key.inode = inode;
            value
        })
        .collect();
    index.refresh(&inventory);
    assert!(index.limited && index.entries.is_empty());
    assert!(index.vetoes(&socket));
}
#[test]
fn udp_read_without_peer_uses_packet_identity_and_exact_current_descriptor() {
    let mut inventory = Inventory::new();
    let ns = inventory.host_namespace();
    let mut socket = listener(&inventory, 200);
    socket.owners[0].identity = ProcessIdentity {
        pid: 200,
        start_time: unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64,
    };
    inventory.sockets.push(socket);
    let recv = Event {
        flags: 2,
        remote_port: 0,
        remote_addr: [0; 16],
        ..actor(ns, 200, "127.0.0.1:8080", "127.0.0.1:40000", true)
    };
    let packet = PacketEvent {
        timestamp_ns: 8_000_000,
        socket_id: 200,
        inode: 200,
        netns: ns as u32,
        ip_bytes: 1028,
        family: libc::AF_INET as u16,
        protocol: 17,
        receive: 1,
        flags: 1,
        local_addr: recv.local_addr,
        remote_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        local_port: 8080,
        remote_port: 40000,
        ..PacketEvent::default()
    };
    let mut ext = extended();
    ext.owners.update(vec![recv], 0, 30_000_000, &inventory);
    ext.sampled_owners.refresh(&inventory);
    let PacketResult::Owned(observed, known) = ext.resolve_packet(&packet, &inventory, true) else {
        panic!("actual socket packet and matching current reader must resolve");
    };
    assert!(known);
    assert_eq!(observed.owner().unwrap().identity.pid, 200);
    assert_eq!(observed.key.remote, "127.0.0.1:40000".parse().unwrap());
    assert!(matches!(
        ext.resolve_packet(
            &PacketEvent {
                socket_id: 201,
                ..packet
            },
            &inventory,
            true
        ),
        PacketResult::Unknown
    ));
    assert!(matches!(
        ext.resolve_packet(
            &PacketEvent {
                inode: 201,
                ..packet
            },
            &inventory,
            true
        ),
        PacketResult::Unknown
    ));
    inventory.sockets[0].owners[0].identity.start_time += 1;
    ext.sampled_owners.refresh(&inventory);
    assert!(matches!(
        ext.resolve_packet(&packet, &inventory, true),
        PacketResult::Unknown
    ));
    inventory.sockets[0].owners[0].identity.start_time -= 1;
    let mut second = inventory.sockets[0].owners[0].clone();
    second.identity.pid += 1;
    inventory.sockets[0].owners.push(second);
    ext.sampled_owners.refresh(&inventory);
    for timestamp_ns in [8_000_000, 15_000_000] {
        assert!(
            matches!(
                ext.resolve_packet(
                    &PacketEvent {
                        timestamp_ns,
                        ..packet
                    },
                    &inventory,
                    true
                ),
                PacketResult::Unknown
            ),
            "shared current descriptors veto both observed and direct-call evidence"
        );
    }
}
