use super::*;
use crate::collector::{
    capture::TimedBytes,
    events::{Event, PacketEvent},
    sockets::Inventory,
};

#[test]
fn packet_socket_identity_proves_demux_but_not_a_shared_or_unobserved_actor() {
    let actor = event(7, 8, 10_000_000, 15_000_000);
    let mut owners = Owners::default();
    owners.update(vec![actor], 0, 20_000_000, &Inventory::new());
    let mut packet = PacketEvent {
        timestamp_ns: 12_000_000,
        socket_id: 8,
        netns: 1,
        protocol: 17,
        ip_bytes: 42,
        // The wire tuple can have changed at NAT; incarnation is proof.
        local_addr: [0; 16],
        ..PacketEvent::default()
    };
    assert!(matches!(owners.resolve_packet(&packet), Match::Owned(_)));
    packet.timestamp_ns = 18_000_000;
    assert!(matches!(owners.resolve_packet(&packet), Match::Observed(_)));
    packet.socket_id = 9;
    assert!(matches!(owners.resolve_packet(&packet), Match::Missing));
    packet.socket_id = 8;
    packet.netns = 2;
    assert!(matches!(owners.resolve_packet(&packet), Match::Missing));
    packet.netns = 1;
    owners.update(
        vec![Event { tgid: 9, ..actor }],
        0,
        21_000_000,
        &Inventory::new(),
    );
    assert!(matches!(owners.resolve_packet(&packet), Match::Ambiguous));
    owners.update(Vec::new(), 1, 22_000_000, &Inventory::new());
    assert!(matches!(owners.resolve_packet(&packet), Match::Ambiguous));
}

#[test]
fn packet_incarnation_rejects_inode_reuse_and_packets_after_final_close() {
    let actor = Event {
        inode: 7,
        ..event(7, 8, 10_000_000, 15_000_000)
    };
    let mut owners = Owners::default();
    owners.update(vec![actor], 0, 20_000_000, &Inventory::new());
    let mut packet = PacketEvent {
        timestamp_ns: 12_000_000,
        socket_id: 8,
        netns: 1,
        inode: 99,
        protocol: 17,
        ip_bytes: 42,
        ..PacketEvent::default()
    };
    assert!(matches!(owners.resolve_packet(&packet), Match::Ambiguous));
    packet.inode = 7;
    let close = Event {
        kind: 4,
        timestamp_ns: 16_000_000,
        ..actor
    };
    owners.update(vec![close], 0, 21_000_000, &Inventory::new());
    assert!(matches!(owners.resolve_packet(&packet), Match::Owned(_)));
    packet.timestamp_ns = 18_000_000;
    assert!(matches!(owners.resolve_packet(&packet), Match::Ambiguous));
}
fn event(pid: u32, id: u64, start: u64, end: u64) -> Event {
    Event {
        tgid: pid,
        socket_id: id,
        started_ns: start,
        timestamp_ns: end,
        process_start_ns: 1_000_000_000,
        netns: 1,
        family: libc::AF_INET as u16,
        protocol: 17,
        local_port: 1234,
        remote_port: 80,
        kind: 1,
        local_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        remote_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..Event::default()
    }
}
fn resolve(owners: &Owners, first: u64, last: u64) -> Match {
    owners.resolve(
        1,
        Protocol::Udp,
        "127.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        false,
        TimedBytes {
            bytes: 42,
            first,
            last,
        },
    )
}
#[test]
fn closed_before_poll_is_still_owned() {
    let mut o = Owners::default();
    let e = event(7, 8, 10_000_000, 11_000_000);
    let close = Event {
        kind: 4,
        timestamp_ns: 12_000_000,
        ..e
    };
    o.update(vec![e, close], 0, 20_000_000, &Inventory::new());
    assert!(
        matches!(resolve(&o,10_500_000,10_600_000),Match::Owned(s) if s.owner().unwrap().identity.pid==7)
    );
    assert!(matches!(
        resolve(&o, 14_000_000, 15_000_000),
        Match::Missing
    ));
}
#[test]
fn reuse_spanning_batch_and_lost_events_are_not_guessed() {
    let mut o = Owners::default();
    let a = event(7, 8, 10_000_000, 11_000_000);
    let close = Event {
        kind: 4,
        timestamp_ns: 12_000_000,
        ..a
    };
    let b = event(9, 10, 20_000_000, 21_000_000);
    o.update(vec![a, close, b], 0, 22_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&o, 10_000_000, 21_000_000),
        Match::Ambiguous
    ));
    assert!(
        matches!(resolve(&o,20_500_000,21_000_000),Match::Owned(s) if s.owner().unwrap().identity.pid==9)
    );
    o.update(vec![], 1, 22_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&o, 23_000_000, 24_000_000),
        Match::Ambiguous
    ));
}
#[test]
fn a_prior_actor_does_not_own_future_packets_or_unobserved_gaps() {
    let mut owners = Owners::default();
    let first = event(7, 8, 10_000_000, 11_000_000);
    let later = Event {
        started_ns: 20_000_000,
        timestamp_ns: 21_000_000,
        ..first
    };
    owners.update(vec![first, later], 0, 22_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&owners, 10_500_000, 10_600_000),
        Match::Owned(_)
    ));
    assert!(matches!(
        resolve(&owners, 15_000_000, 16_000_000),
        Match::Missing
    ));
    assert!(matches!(
        resolve(&owners, 10_500_000, 20_500_000),
        Match::Observed(_)
    ));
    assert!(matches!(
        resolve(&owners, 25_000_000, 26_000_000),
        Match::Missing
    ));
    // A timestamp just outside a syscall is uncertain, never expanded
    // into positive evidence by the pcap clock tolerance.
    assert!(matches!(
        resolve(&owners, 9_500_000, 10_500_000),
        Match::Observed(_)
    ));
    assert!(matches!(
        resolve(&owners, 20_500_000, 21_500_000),
        Match::Observed(_)
    ));
}

#[test]
fn overlapping_shared_or_inherited_socket_actors_conflict() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let inheritor = Event {
        tgid: 9,
        started_ns: 12_000_000,
        timestamp_ns: 16_000_000,
        ..first
    };
    for events in [vec![first, inheritor], vec![inheritor, first]] {
        let mut owners = Owners::default();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 12_500_000, 13_000_000),
            Match::Ambiguous
        ));
        assert!(matches!(
            resolve(&owners, 10_000_000, 16_000_000),
            Match::Ambiguous
        ));
    }
}

#[test]
fn pid_reuse_conflicts_even_within_one_proc_clock_tick() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let reused = Event {
        process_start_ns: first.process_start_ns + 1,
        ..first
    };
    let mut owners = Owners::default();
    owners.update(vec![first, reused], 0, 20_000_000, &Inventory::new());
    assert_eq!(owners.records.len(), 2);
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Ambiguous
    ));
}

#[test]
fn namespaces_keep_identical_tuples_and_socket_ids_separate() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let other = Event {
        netns: 2,
        tgid: 9,
        ..first
    };
    let mut owners = Owners::default();
    owners.update(vec![first, other], 0, 20_000_000, &Inventory::new());
    assert_eq!(owners.namespaces(), HashSet::from([1, 2]));
    assert!(owners.has_address(1, "127.0.0.1".parse().unwrap()));
    assert!(!owners.has_address(3, "127.0.0.1".parse().unwrap()));
    assert!(
        matches!(resolve(&owners, 12_000_000, 13_000_000), Match::Owned(socket) if socket.owner().unwrap().identity.pid == 7)
    );
    let closed = Event {
        kind: 4,
        timestamp_ns: 11_000_000,
        ..other
    };
    owners.update(vec![closed], 0, 20_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Owned(_)
    ));
}

#[test]
fn reordered_close_tombstones_also_handle_unknown_udp_peers() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let close = Event {
        kind: 4,
        flags: 2,
        timestamp_ns: 12_000_000,
        remote_port: 0,
        ..first
    };
    for events in [vec![first, close], vec![close, first]] {
        let mut owners = Owners::default();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 10_500_000, 11_000_000),
            Match::Owned(_)
        ));
        assert!(matches!(
            resolve(&owners, 14_000_000, 15_000_000),
            Match::Missing
        ));
    }
}

#[test]
fn direction_and_malformed_windows_are_not_guessed() {
    let receive = Event {
        kind: 2,
        ..event(7, 8, 10_000_000, 15_000_000)
    };
    let mut owners = Owners::default();
    owners.update(vec![receive], 0, 20_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Observed(_)
    ));
    assert!(matches!(
        resolve(&owners, 13_000_000, 12_000_000),
        Match::Ambiguous
    ));
    assert!(matches!(resolve(&owners, 0, 13_000_000), Match::Ambiguous));
    assert!(matches!(
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first: 12_000_000,
                last: 13_000_000
            }
        ),
        Match::Owned(_)
    ));
}

#[test]
fn losses_and_unreliable_actors_quarantine_even_later_drain_batches() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let mut owners = Owners::default();
    owners.update(vec![first], 1, 20_000_000, &Inventory::new());
    owners.describe_loss("kernel read=1".into());
    assert!(owners.suppressed());
    assert!(!owners.limited());
    assert!(owners.records.is_empty());
    let during = Event {
        started_ns: 21_000_000,
        timestamp_ns: 23_000_000,
        ..first
    };
    owners.update(vec![during], 0, 24_000_000, &Inventory::new());
    assert_eq!(
        owners.suppression_reason(),
        Some("socket events lost: kernel read=1")
    );
    assert!(owners.records.is_empty());
    let after = Event {
        started_ns: 4_000_000_000,
        timestamp_ns: 4_010_000_000,
        ..first
    };
    owners.update(vec![after], 0, 4_020_000_000, &Inventory::new());
    assert_eq!(owners.suppression_reason(), None);
    assert!(matches!(
        resolve(&owners, 4_005_000_000, 4_006_000_000),
        Match::Owned(_)
    ));
    let worker = Event { flags: 1, ..after };
    owners.update(vec![worker], 0, 4_020_000_000, &Inventory::new());
    assert!(owners.suppressed());
    assert!(owners.records.is_empty());
    assert!(matches!(
        resolve(&owners, 4_025_000_000, 4_026_000_000),
        Match::Ambiguous
    ));
}

#[test]
fn record_overflow_preserves_uncertainty_instead_of_evicting_conflicts() {
    let mut owners = Owners::default();
    let events = (1..=MAX_RECORDS as u64 + 1)
        .map(|id| event(7, id, 10_000_000, 15_000_000))
        .collect();
    owners.update(events, 0, 20_000_000, &Inventory::new());
    assert!(owners.records.is_empty());
    assert_eq!(owners.windows, 0);
    assert!(owners.limited() && owners.suppressed());
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Ambiguous
    ));
}

#[test]
fn expired_and_unknown_events_cannot_resurrect_old_ownership() {
    let first = event(7, 8, 10_000_000, 15_000_000);
    let mut owners = Owners::default();
    owners.update(vec![first], 0, 4_000_000_000, &Inventory::new());
    assert!(owners.records.is_empty());
    owners.update(
        vec![Event { kind: 7, ..first }],
        0,
        20_000_000,
        &Inventory::new(),
    );
    assert!(owners.records.is_empty());
    let flags = Event { flags: 4, ..first };
    owners.update(vec![flags], 0, 20_000_000, &Inventory::new());
    assert!(owners.records.is_empty());
}
#[test]
fn accept_does_not_attribute_pre_accept_packets_to_the_accepting_actor() {
    let mut owners = Owners::default();
    let accepted = Event {
        kind: 5,
        started_ns: 15_000_000,
        timestamp_ns: 15_000_000,
        protocol: 6,
        ..event(7, 8, 10_000_000, 15_000_000)
    };
    owners.update(vec![accepted], 0, 20_000_000, &Inventory::new());
    let result = owners.resolve(
        1,
        Protocol::Tcp,
        "127.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        true,
        TimedBytes {
            bytes: 42,
            first: 14_000_000,
            last: 15_000_000,
        },
    );
    assert!(matches!(result, Match::Observed(_)));
    assert_eq!(owners.records.len(), 1);
}
#[test]
fn indices_expire_with_evidence_and_bound_namespace_and_tuple_floods() {
    let mut owners = Owners::default();
    let first = event(7, 8, 10_000_000, 15_000_000);
    owners.update(vec![first], 0, 20_000_000, &Inventory::new());
    assert_eq!(owners.tuples.len(), 1);
    assert!(owners.has_address(1, "127.0.0.1".parse().unwrap()));
    owners.update(vec![], 0, 4_000_000_000, &Inventory::new());
    assert!(owners.tuples.is_empty() && owners.namespaces().is_empty());
    assert!(!owners.has_address(1, "127.0.0.1".parse().unwrap()));

    let events = (1..=MAX_NAMESPACES as u32 + 1)
        .map(|namespace| Event {
            netns: namespace,
            ..first
        })
        .collect();
    owners.update(events, 0, 20_000_000, &Inventory::new());
    assert!(owners.records.is_empty() && owners.namespaces().is_empty());
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Ambiguous
    ));

    let mut owners = Owners::default();
    let events = (1..=MAX_CANDIDATES as u64 + 1)
        .map(|id| Event {
            socket_id: id,
            ..first
        })
        .collect();
    owners.update(events, 0, 20_000_000, &Inventory::new());
    assert_eq!(owners.tuples.values().next(), Some(&None));
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Ambiguous
    ));
}

#[test]
fn window_index_preserves_directions_and_merges_only_overlaps() {
    let mut owners = Owners::default();
    let first = event(7, 8, 10_000_000, 15_000_000);
    let overlapping = Event {
        started_ns: 14_000_000,
        timestamp_ns: 19_000_000,
        ..first
    };
    let recv = Event {
        kind: 2,
        started_ns: 11_000_000,
        timestamp_ns: 20_000_000,
        ..first
    };
    owners.update(
        vec![overlapping, recv, first],
        0,
        22_000_000,
        &Inventory::new(),
    );
    assert_eq!(owners.windows, 2);
    assert!(matches!(
        resolve(&owners, 12_000_000, 18_000_000),
        Match::Owned(_)
    ));
    assert!(matches!(
        resolve(&owners, 18_000_000, 20_000_000),
        Match::Observed(_)
    ));

    let later = Event {
        started_ns: 25_000_000,
        timestamp_ns: 26_000_000,
        ..first
    };
    owners.update(vec![later], 0, 27_000_000, &Inventory::new());
    assert_eq!(owners.windows, 3);
    assert!(matches!(
        resolve(&owners, 22_000_000, 23_000_000),
        Match::Missing
    ));
}

#[test]
fn many_unrelated_tuples_do_not_enter_a_packet_lookup() {
    let mut owners = Owners::default();
    let first = event(7, 8, 10_000_000, 15_000_000);
    let events = (1..=8192)
        .map(|port| Event {
            local_port: port,
            socket_id: u64::from(port),
            ..first
        })
        .collect();
    owners.update(events, 0, 20_000_000, &Inventory::new());
    assert_eq!(owners.tuples.len(), 8192);
    let tuple = (1, Protocol::Udp, 1234, "127.0.0.1:80".parse().unwrap());
    assert_eq!(owners.tuples[&tuple].as_ref().unwrap().len(), 1);
    assert!(matches!(
        resolve(&owners, 12_000_000, 13_000_000),
        Match::Owned(_)
    ));
}
#[test]
fn closed_single_actor_lifetime_covers_queued_receive_and_syscall_gaps() {
    let mut owners = Owners::default();
    let recv = Event {
        kind: 2,
        ..event(7, 8, 20_000_000, 21_000_000)
    };
    let bind = Event {
        kind: 6,
        flags: 2,
        remote_port: 0,
        started_ns: 10_000_000,
        timestamp_ns: 11_000_000,
        ..recv
    };
    let close = Event {
        kind: 4,
        flags: 2,
        remote_port: 0,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..recv
    };
    let lookup = |owners: &Owners| {
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first: 15_000_000,
                last: 16_000_000,
            },
        )
    };
    owners.update(vec![bind, recv], 0, 25_000_000, &Inventory::new());
    assert!(matches!(lookup(&owners), Match::Missing));
    owners.update(vec![close], 0, 35_000_000, &Inventory::new());
    assert!(matches!(lookup(&owners), Match::Owned(_)));
    assert!(matches!(
        resolve(&owners, 25_000_000, 26_000_000),
        Match::Owned(_)
    ));
    assert!(matches!(
        resolve(&owners, 8_000_000, 9_000_000),
        Match::Ambiguous
    ));
    assert!(matches!(
        resolve(&owners, 32_000_000, 33_000_000),
        Match::Missing
    ));
}

#[test]
fn different_binder_or_closer_prevents_closed_lifetime_ownership() {
    let send = event(7, 8, 20_000_000, 21_000_000);
    let bind = Event {
        kind: 6,
        flags: 2,
        remote_port: 0,
        started_ns: 10_000_000,
        timestamp_ns: 11_000_000,
        ..send
    };
    let close = Event {
        kind: 4,
        flags: 2,
        remote_port: 0,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..send
    };
    for events in [
        vec![Event { tgid: 9, ..bind }, send, close],
        vec![
            bind,
            send,
            Event {
                process_start_ns: close.process_start_ns + 1,
                ..close
            },
        ],
        vec![close, send, Event { tgid: 9, ..bind }],
    ] {
        let mut owners = Owners::default();
        owners.update(events, 0, 35_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 20_500_000, 20_600_000),
            Match::Ambiguous
        ));
        assert!(matches!(
            resolve(&owners, 25_000_000, 26_000_000),
            Match::Ambiguous
        ));
    }
}

#[test]
fn close_without_an_observed_begin_cannot_backdate_queued_receive() {
    let recv = Event {
        kind: 2,
        ..event(7, 8, 20_000_000, 21_000_000)
    };
    let close = Event {
        kind: 4,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..recv
    };
    let mut owners = Owners::default();
    owners.update(vec![recv, close], 0, 35_000_000, &Inventory::new());
    assert!(matches!(
        resolve(&owners, 15_000_000, 16_000_000),
        Match::Missing
    ));
    assert!(
        owners
            .records
            .values()
            .all(|record| record.lifetime.is_none())
    );
}
#[test]
fn udp_reuseport_bind_without_recv_vetoes_lifetime_only_rx() {
    let first = event(7, 8, 20_000_000, 21_000_000);
    let bind = Event {
        kind: 6,
        flags: 2,
        remote_port: 0,
        started_ns: 10_000_000,
        timestamp_ns: 11_000_000,
        ..first
    };
    let recv = Event { kind: 2, ..first };
    let competing = Event {
        socket_id: 9,
        tgid: 9,
        started_ns: 12_000_000,
        timestamp_ns: 13_000_000,
        ..bind
    };
    let close = Event {
        kind: 4,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..first
    };
    let mut owners = Owners::default();
    owners.update(
        vec![bind, recv, competing, close],
        0,
        35_000_000,
        &Inventory::new(),
    );
    let lookup = |first, last| {
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first,
                last,
            },
        )
    };
    assert!(matches!(lookup(15_000_000, 16_000_000), Match::Ambiguous));
    // Direct evidence of the actual receiving call is still decisive.
    assert!(matches!(lookup(20_500_000, 20_600_000), Match::Owned(_)));
    assert!(matches!(
        resolve(&owners, 15_000_000, 16_000_000),
        Match::Owned(_)
    ));
}

#[test]
fn preexisting_udp_inventory_binding_vetoes_queued_rx_to_another_inode() {
    let first = event(7, 8, 20_000_000, 21_000_000);
    let close = Event {
        kind: 4,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..first
    };
    let mut owners = Owners::default();
    let mut inventory = Inventory::new();
    owners.update(vec![first, close], 0, 35_000_000, &inventory);
    let mut competing = owners.records.values().next().unwrap().socket.clone();
    competing.key.inode = 99;
    competing.key.remote = "0.0.0.0:0".parse().unwrap();
    inventory.sockets.push(competing);
    owners.update(vec![], 0, 36_000_000, &inventory);
    assert!(matches!(
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first: 25_000_000,
                last: 26_000_000
            }
        ),
        Match::Ambiguous
    ));
}

#[test]
fn actorless_tcp_birth_requires_accept_and_close_before_queued_rx_is_owned() {
    let accepted = Event {
        protocol: 6,
        kind: 5,
        started_ns: 20_000_000,
        timestamp_ns: 20_000_000,
        ..event(7, 8, 20_000_000, 21_000_000)
    };
    let birth = Event {
        kind: 7,
        flags: 2,
        tgid: 0,
        process_start_ns: 0,
        started_ns: 10_000_000,
        timestamp_ns: 10_000_000,
        local_addr: [0; 16],
        remote_addr: [0; 16],
        ..accepted
    };
    let close = Event {
        kind: 4,
        started_ns: 30_000_000,
        timestamp_ns: 30_000_000,
        ..accepted
    };
    let mut owners = Owners::default();
    let lookup = |owners: &Owners| {
        owners.resolve(
            1,
            Protocol::Tcp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first: 15_000_000,
                last: 16_000_000,
            },
        )
    };
    owners.update(vec![birth], 0, 19_000_000, &Inventory::new());
    assert!(matches!(lookup(&owners), Match::Missing));
    owners.update(vec![accepted], 0, 25_000_000, &Inventory::new());
    assert!(matches!(lookup(&owners), Match::Missing));
    owners.update(vec![close], 0, 35_000_000, &Inventory::new());
    assert!(
        matches!(lookup(&owners), Match::Owned(socket) if socket.owner().unwrap().identity.pid == 7)
    );
}
#[test]
fn unknown_udp_peer_keeps_only_exact_socket_actor_evidence() {
    let read = Event {
        kind: 2,
        flags: 2,
        inode: 123,
        remote_port: 0,
        remote_addr: [0; 16],
        ..event(7, 8, 10_000_000, 15_000_000)
    };
    let mut owners = Owners::default();
    owners.update(vec![read], 0, 20_000_000, &Inventory::new());
    assert!(
        owners.tuples.is_empty(),
        "unknown peer must never invent tuple matches"
    );
    let packet = PacketEvent {
        timestamp_ns: 12_000_000,
        socket_id: 8,
        netns: 1,
        inode: 123,
        protocol: 17,
        receive: 1,
        ip_bytes: 1028,
        ..PacketEvent::default()
    };
    assert!(
        matches!(owners.resolve_packet(&packet),Match::Owned(socket) if socket.owner().unwrap().identity.pid==7)
    );
    assert!(matches!(
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 1028,
                first: 12_000_000,
                last: 12_000_000
            }
        ),
        Match::Missing
    ));
    let queued = PacketEvent {
        timestamp_ns: 8_000_000,
        ..packet
    };
    assert!(
        matches!(owners.resolve_packet(&queued), Match::Observed(_)),
        "outside-call packets require caller descriptor corroboration"
    );
    assert!(matches!(
        owners.resolve_packet(&PacketEvent {
            socket_id: 9,
            ..packet
        }),
        Match::Missing
    ));
    assert!(matches!(
        owners.resolve_packet(&PacketEvent {
            inode: 124,
            ..packet
        }),
        Match::Ambiguous
    ));
    owners.update(
        vec![Event { tgid: 9, ..read }],
        0,
        21_000_000,
        &Inventory::new(),
    );
    assert!(
        matches!(owners.resolve_packet(&packet), Match::Ambiguous),
        "unknown-peer actors still conflict on a shared socket"
    );
    owners.update(Vec::new(), 1, 22_000_000, &Inventory::new());
    assert!(matches!(owners.resolve_packet(&packet), Match::Ambiguous));

    let mut owners = Owners::default();
    owners.update(
        vec![
            read,
            Event {
                kind: 4,
                started_ns: 18_000_000,
                timestamp_ns: 18_000_000,
                ..read
            },
        ],
        0,
        20_000_000,
        &Inventory::new(),
    );
    assert!(matches!(
        owners.resolve_packet(&PacketEvent {
            timestamp_ns: 19_000_000,
            ..packet
        }),
        Match::Ambiguous
    ));
    assert!(
        matches!(owners.resolve_packet(&queued), Match::Ambiguous),
        "read alone cannot backdate a closed socket lifetime"
    );
}
