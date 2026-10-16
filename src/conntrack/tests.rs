use super::codec::{attributes, parse_entry};
use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn tuple(source: &str, destination: &str) -> Tuple {
    Tuple {
        protocol: Protocol::Tcp,
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
    }
}

fn entry(original: Tuple, translated: Tuple, now: Instant) -> Entry {
    Entry {
        identity: Identity {
            id: 42,
            original,
            zones: (0, 0),
        },
        reply: translated.reversed(),
        expires: now + Duration::from_secs(40),
    }
}

fn ready_cache(now: Instant) -> Cache {
    let mut cache = Cache::new(now);
    cache.ready = true;
    cache.error = None;
    cache.valid_until = now + MAX_CACHE_AGE;
    cache
}

fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    result.extend_from_slice(&kind.to_ne_bytes());
    result.extend_from_slice(payload);
    result.resize((result.len() + 3) & !3, 0);
    result
}

fn tuple_payload(tuple: Tuple, zone: Option<u16>) -> Vec<u8> {
    let mut ip = Vec::new();
    for (source, address) in [(true, tuple.source.ip()), (false, tuple.destination.ip())] {
        match address {
            IpAddr::V4(address) => {
                ip.extend(attribute(if source { 1 } else { 2 }, &address.octets()))
            }
            IpAddr::V6(address) => {
                ip.extend(attribute(if source { 3 } else { 4 }, &address.octets()))
            }
        }
    }
    let mut proto = attribute(
        1,
        &[if tuple.protocol == Protocol::Tcp {
            6
        } else {
            17
        }],
    );
    proto.extend(attribute(2, &tuple.source.port().to_be_bytes()));
    proto.extend(attribute(3, &tuple.destination.port().to_be_bytes()));
    let mut result = attribute(0x8001, &ip);
    result.extend(attribute(0x8002, &proto));
    if let Some(zone) = zone {
        result.extend(attribute(3, &zone.to_be_bytes()));
    }
    result
}

fn entry_payload(entry: &Entry, timeout: u32) -> Vec<u8> {
    let mut result = vec![
        if entry.identity.original.source.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        },
        0,
        0,
        0,
    ];
    result.extend(attribute(
        0x8001,
        &tuple_payload(entry.identity.original, Some(entry.identity.zones.0)),
    ));
    result.extend(attribute(
        0x8002,
        &tuple_payload(entry.reply, Some(entry.identity.zones.1)),
    ));
    result.extend(attribute(7, &timeout.to_be_bytes()));
    result.extend(attribute(12, &entry.identity.id.to_be_bytes()));
    result
}

fn message(kind: u16, flags: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    result.extend_from_slice(&kind.to_ne_bytes());
    result.extend_from_slice(&flags.to_ne_bytes());
    result.extend_from_slice(&sequence.to_ne_bytes());
    result.extend_from_slice(&0_u32.to_ne_bytes());
    result.extend_from_slice(body);
    result.resize((result.len() + 3) & !3, 0);
    result
}

#[test]
fn combined_nat_maps_three_stages_and_both_directions() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let after = tuple("172.18.0.1:45000", "172.18.0.2:80");
    let mut cache = ready_cache(now);
    cache
        .apply(Event::Upsert(entry(before, after, now)))
        .unwrap();
    for observation in [
        before,
        Tuple {
            destination: after.destination,
            ..before
        },
        after,
    ] {
        assert_eq!(
            cache.translate(observation, now),
            Outcome::Translated(Translation {
                before,
                after,
                zones: (0, 0)
            })
        );
        assert_eq!(
            cache.translate(observation.reversed(), now),
            Outcome::Translated(Translation {
                before: after.reversed(),
                after: before.reversed(),
                zones: (0, 0)
            })
        );
    }
    let nonexistent_stage = Tuple {
        source: after.source,
        ..before
    };
    assert_eq!(cache.translate(nonexistent_stage, now), Outcome::Missing);
}

#[test]
fn dnat_snat_no_nat_and_ipv6_udp_share_exact_tuple_matching() {
    let now = Instant::now();
    for (before, after) in [
        (
            tuple("198.51.100.2:40000", "192.0.2.1:8080"),
            tuple("198.51.100.2:40000", "172.18.0.2:80"),
        ),
        (
            tuple("172.18.0.2:40000", "198.51.100.2:80"),
            tuple("192.0.2.1:45000", "198.51.100.2:80"),
        ),
        (
            tuple("192.0.2.1:40000", "198.51.100.2:80"),
            tuple("192.0.2.1:40000", "198.51.100.2:80"),
        ),
        (
            Tuple {
                protocol: Protocol::Udp,
                ..tuple("[2001:db8::1]:40000", "[2001:db8::2]:8080")
            },
            Tuple {
                protocol: Protocol::Udp,
                ..tuple("[2001:db8::1]:40000", "[fd00::2]:80")
            },
        ),
    ] {
        let mut cache = ready_cache(now);
        cache
            .apply(Event::Upsert(entry(before, after, now)))
            .unwrap();
        let expected = if before == after {
            Outcome::Unchanged
        } else {
            Outcome::Translated(Translation {
                before,
                after,
                zones: (0, 0),
            })
        };
        assert_eq!(cache.translate(before, now), expected);
        assert_eq!(cache.translate(after, now), expected);
        let other_protocol = Tuple {
            protocol: if before.protocol == Protocol::Tcp {
                Protocol::Udp
            } else {
                Protocol::Tcp
            },
            ..before
        };
        assert_eq!(cache.translate(other_protocol, now), Outcome::Missing);
    }
}

#[test]
fn conflicting_zones_and_generations_never_choose_an_arbitrary_mapping() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let after = tuple("198.51.100.2:40000", "172.18.0.2:80");
    for other_zone in [false, true] {
        let mut cache = ready_cache(now);
        let first = entry(before, after, now);
        let mut second = first.clone();
        if other_zone {
            second.identity.zones = (1, 2);
        } else {
            second.identity.id += 1;
        }
        cache.apply(Event::Upsert(first.clone())).unwrap();
        cache.apply(Event::Upsert(second.clone())).unwrap();
        assert_eq!(cache.translate(before, now), Outcome::Ambiguous);
        cache.apply(Event::Delete(second)).unwrap();
        assert!(matches!(
            cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)),
            Outcome::Translated(_)
        ));
        cache.apply(Event::Delete(first)).unwrap();
        assert!(cache.index.is_empty());
    }
}

#[test]
fn update_replaces_old_translation_and_expiry_is_absolute() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let old_after = tuple("198.51.100.2:40000", "172.18.0.2:80");
    let after = tuple("198.51.100.2:40000", "172.18.0.3:80");
    let mut cache = ready_cache(now);
    cache
        .apply(Event::Upsert(entry(before, old_after, now)))
        .unwrap();
    cache
        .apply(Event::Upsert(entry(before, after, now)))
        .unwrap();
    assert_eq!(cache.translate(old_after, now), Outcome::Ambiguous);
    assert_eq!(cache.translate(before, now), Outcome::Ambiguous);
    assert!(
        matches!(cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)), Outcome::Translated(translation) if translation.after == after)
    );
    assert_eq!(
        cache.translate(before, now + Duration::from_secs(40)),
        Outcome::Missing
    );
    assert_eq!(
        cache.translate(before, now + MAX_CACHE_AGE),
        Outcome::Unavailable
    );
    cache.prune(now + Duration::from_secs(40)).unwrap();
    assert!(cache.entries.is_empty() && cache.index.is_empty());
}

#[test]
fn loss_invalidates_even_already_obtained_views() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let after = tuple("198.51.100.2:40000", "172.18.0.2:80");
    let mut cache = ready_cache(now);
    cache
        .apply(Event::Upsert(entry(before, after, now)))
        .unwrap();
    let shared = Arc::new(Mutex::new(cache));
    let view = View {
        ready: true,
        error: None,
        lost: 0,
        shared: shared.clone(),
    };
    assert!(matches!(
        view.translate(before.protocol, before.source, before.destination),
        Outcome::Translated(_)
    ));
    locked(&shared).invalidate("ENOBUFS");
    assert_eq!(
        view.translate(before.protocol, before.source, before.destination),
        Outcome::Unavailable
    );
    assert_eq!(locked(&shared).lost, 1);
}

#[test]
fn dump_replays_notifications_after_rows_including_destroy() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let old = entry(before, tuple("198.51.100.2:40000", "172.18.0.2:80"), now);
    let new = entry(before, tuple("198.51.100.2:40000", "172.18.0.3:80"), now);
    let mut dump = Dump::new(1, now);
    // The update notification arrived before a stale dump row.
    dump.events.push(Event::Upsert(new.clone()));
    dump.cache.apply(Event::Upsert(old.clone())).unwrap();
    let mut previous = ready_cache(now);
    previous.lost = 3;
    let cache = dump.finish(now, &previous).unwrap();
    assert_eq!(cache.lost, 3);
    assert!(
        matches!(cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)), Outcome::Translated(translation) if translation.after == new.reply.reversed())
    );
    let mut dump = Dump::new(2, now);
    dump.events.push(Event::Delete(old.clone()));
    dump.cache.apply(Event::Upsert(old)).unwrap();
    assert_eq!(
        dump.finish(now, &previous).unwrap().translate(before, now),
        Outcome::Ambiguous
    );
}

#[test]
fn deleted_generation_cannot_relabel_deferred_packets_after_tuple_reuse() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let old = entry(before, tuple("172.18.0.1:45000", "172.18.0.2:80"), now);
    let mut new = entry(before, tuple("172.18.0.1:45001", "172.18.0.3:80"), now);
    new.identity.id += 1;
    let mut cache = ready_cache(now);
    cache.apply_at(Event::Upsert(old.clone()), now).unwrap();
    cache.apply_at(Event::Delete(old.clone()), now).unwrap();
    cache.apply_at(Event::Upsert(new.clone()), now).unwrap();
    for (observation, _) in old.observations() {
        assert_eq!(
            cache.translate(observation, now + Duration::from_secs(5)),
            Outcome::Ambiguous
        );
    }
    assert!(
        matches!(cache.translate(before, now + REUSE_QUARANTINE), Outcome::Translated(translation) if translation.after == new.reply.reversed())
    );
    // Ordinary timeout refreshes neither introduce nor extend quarantine.
    cache
        .apply_at(Event::Upsert(new), now + REUSE_QUARANTINE)
        .unwrap();
    assert!(matches!(
        cache.translate(before, now + REUSE_QUARANTINE),
        Outcome::Translated(_)
    ));
}

#[test]
fn resync_preserves_tombstones_and_detects_disappeared_or_replaced_generations() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let old = entry(before, tuple("198.51.100.2:40000", "172.18.0.2:80"), now);
    let mut new = entry(before, tuple("198.51.100.2:40000", "172.18.0.3:80"), now);
    new.identity.id += 1;
    for deleted in [false, true] {
        let mut previous = ready_cache(now);
        previous.apply_at(Event::Upsert(old.clone()), now).unwrap();
        if deleted {
            previous.apply_at(Event::Delete(old.clone()), now).unwrap();
        }
        let mut dump = Dump::new(2, now);
        dump.cache
            .apply_at(Event::Upsert(new.clone()), now)
            .unwrap();
        let result = dump.finish(now, &previous).unwrap();
        assert_eq!(result.translate(before, now), Outcome::Ambiguous);
        assert_eq!(result.translate(old.reply, now), Outcome::Ambiguous);
        let mut second = Dump::new(3, now);
        second
            .cache
            .apply_at(Event::Upsert(new.clone()), now)
            .unwrap();
        let result = second
            .finish(now + Duration::from_secs(1), &result)
            .unwrap();
        assert_eq!(
            result.translate(before, now + Duration::from_secs(5)),
            Outcome::Ambiguous
        );
        assert!(matches!(
            result.translate(before, now + REUSE_QUARANTINE),
            Outcome::Translated(_)
        ));
    }
    let mut previous = ready_cache(now);
    previous.apply_at(Event::Upsert(old), now).unwrap();
    let result = Dump::new(4, now).finish(now, &previous).unwrap();
    assert_eq!(result.translate(before, now), Outcome::Ambiguous);
}

#[test]
fn loss_quarantines_even_previously_unknown_tuples_after_resync() {
    let now = Instant::now();
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let mut previous = ready_cache(now);
    previous.invalidate("ENOBUFS");
    let mut dump = Dump::new(2, now);
    dump.cache
        .apply_at(Event::Upsert(entry(before, before, now)), now)
        .unwrap();
    let result = dump.finish(now, &previous).unwrap();
    assert_eq!(
        result.translate(before, now + Duration::from_secs(5)),
        Outcome::Ambiguous
    );
    assert_eq!(
        result.translate(before, now + REUSE_QUARANTINE),
        Outcome::Unchanged
    );
    assert_eq!(result.lost, 1);
}

#[test]
fn tombstone_memory_is_bounded_and_overflow_reports_failure() {
    let now = Instant::now();
    let mut cache = ready_cache(now);
    for value in 0..MAX_TOMBSTONES {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(value as u32)), 1);
        cache.tombstones.insert(
            Tuple {
                protocol: Protocol::Tcp,
                source: address,
                destination: address,
            },
            now + REUSE_QUARANTINE,
        );
    }
    let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
    let error = cache
        .apply_at(Event::Delete(entry(before, before, now)), now)
        .unwrap_err();
    assert!(error.to_string().contains("tombstone limit"));
    assert_eq!(cache.tombstones.len(), MAX_TOMBSTONES);
}

#[test]
fn parses_kernel_layout_ipv4_ipv6_and_directional_zones() {
    let now = Instant::now();
    for (before, after) in [
        (
            tuple("198.51.100.2:40000", "192.0.2.1:8080"),
            tuple("198.51.100.2:40000", "172.18.0.2:80"),
        ),
        (
            Tuple {
                protocol: Protocol::Udp,
                ..tuple("[2001:db8::1]:40000", "[2001:db8::2]:8080")
            },
            Tuple {
                protocol: Protocol::Udp,
                ..tuple("[2001:db8::1]:40000", "[fd00::2]:80")
            },
        ),
    ] {
        let mut expected = entry(before, after, now);
        expected.identity.zones = (7, 9);
        let body = entry_payload(&expected, 12);
        let data = message(CT_NEW, 2, 3, &body);
        let parsed = parse_datagram(&data, now).unwrap();
        let Message::Event {
            sequence,
            event: Event::Upsert(parsed),
        } = &parsed[0]
        else {
            panic!("expected entry");
        };
        assert_eq!(*sequence, 3);
        assert_eq!(parsed.identity, expected.identity);
        assert_eq!(parsed.reply, expected.reply);
        assert_eq!(parsed.expires, now + Duration::from_secs(12));
        assert!(
            matches!(parse_entry(&body, true, now).unwrap(), Some(Event::Delete(entry)) if entry.identity == expected.identity)
        );
    }
}

#[test]
fn malformed_truncated_duplicate_or_interrupted_dumps_fail_closed() {
    let now = Instant::now();
    let expected = entry(
        tuple("198.51.100.2:40000", "192.0.2.1:8080"),
        tuple("198.51.100.2:40000", "172.18.0.2:80"),
        now,
    );
    let body = entry_payload(&expected, 10);
    let valid = message(CT_NEW, 2, 1, &body);
    for length in 1..valid.len() {
        assert!(
            parse_datagram(&valid[..length], now).is_err(),
            "accepted truncation at {length}"
        );
    }
    let mut duplicate = body.clone();
    duplicate.extend(attribute(12, &42_u32.to_be_bytes()));
    assert!(parse_entry(&duplicate, false, now).is_err());
    for data in [
        message(3, 0x10, 1, &0_i32.to_ne_bytes()),
        message(3, 0, 1, &(-libc::EINTR).to_ne_bytes()),
        message(4, 0, 0, &[]),
        message(2, 0, 1, &(-libc::EPERM).to_ne_bytes()),
    ] {
        assert!(parse_datagram(&data, now).is_err());
    }
    let excessive: Vec<_> = (0..=MAX_ATTRIBUTES)
        .flat_map(|_| attribute(0, &[]))
        .collect();
    assert!(attributes(&excessive).is_err());
    assert!(matches!(
        parse_datagram(&message(3, 0, 1, &0_i32.to_ne_bytes()), now).unwrap()[0],
        Message::Done(1)
    ));
}
