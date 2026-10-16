use super::procfs::{namespace_addresses, parse_address};
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};

fn key(local: &str, remote: &str, inode: u64) -> SocketKey {
    SocketKey {
        namespace: namespace_id(std::process::id()).unwrap(),
        inode,
        protocol: Protocol::Tcp,
        local: local.parse().unwrap(),
        remote: remote.parse().unwrap(),
    }
}

fn owned_socket(key: SocketKey, pid: u32, current: bool) -> Socket {
    Socket {
        key,
        state: "BOUND".to_string(),
        uid: 1000,
        owners: vec![Owner {
            identity: ProcessIdentity {
                pid,
                start_time: 100,
            },
            user: "test".to_string(),
            name: "test".to_string(),
        }],
        observed: Instant::now(),
        current,
        ipv6_only: None,
    }
}

#[test]
fn namespace_keys_isolate_identical_endpoints_and_wildcards() {
    let host = namespace_id(std::process::id()).unwrap();
    let foreign = host + 1;
    let local = "192.0.2.1:8080".parse().unwrap();
    let remote = "198.51.100.2:40000".parse().unwrap();
    for wildcard in [false, true] {
        let host_key = if wildcard {
            key("0.0.0.0:8080", "0.0.0.0:0", 10)
        } else {
            key("192.0.2.1:8080", "198.51.100.2:40000", 10)
        };
        let mut foreign_key = host_key.clone();
        foreign_key.namespace = foreign;
        foreign_key.inode = 11;
        let inventory = inventory_with(vec![
            owned_socket(host_key, 100, true),
            owned_socket(foreign_key, 200, true),
        ]);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
            Some(100)
        );
        assert_eq!(
            resolved_pid(inventory.resolve_in(foreign, Protocol::Tcp, local, remote)),
            Some(200)
        );
        assert!(matches!(
            inventory.resolve_in(foreign + 1, Protocol::Tcp, local, remote),
            Resolution::Missing
        ));
    }
}

#[test]
fn host_diagnostics_never_populate_foreign_ipv6_modes() {
    let mut inventory = Inventory::new();
    let mut socket_key = key("[::]:8080", "[::]:0", 12);
    socket_key.namespace = inventory.host_namespace() + 1;
    inventory.ipv6_modes.insert(socket_key.clone(), false);
    let foreign = owned_socket(socket_key, 200, true);
    inventory.refresh_ipv6_modes(&[foreign], Instant::now());
    assert!(inventory.ipv6_modes.is_empty());
    assert!(inventory.ipv6_attempts.is_empty());
}

#[test]
fn namespace_discovery_is_opt_in_and_disabling_removes_foreign_sockets() {
    let mut inventory = Inventory::new();
    let host = inventory.host_namespace();
    assert!(!inventory.namespace_discovery);
    assert_eq!(inventory.namespaces().len(), 1);
    assert_eq!(inventory.namespaces()[&host].id, host);
    inventory.set_namespace_discovery(true);
    let mut foreign_key = key("192.0.2.1:8080", "198.51.100.2:40000", 13);
    foreign_key.namespace = host + 1;
    inventory.sockets.push(owned_socket(foreign_key, 200, true));
    inventory.namespaces.insert(
        host + 1,
        Namespace {
            id: host + 1,
            representative_pid: 200,
            addresses: HashSet::new(),
        },
    );
    inventory.rebuild_index();
    inventory.set_namespace_discovery(false);
    assert!(inventory.sockets.is_empty());
    assert!(inventory.exact.is_empty());
    assert_eq!(inventory.namespaces().len(), 1);
    assert!(inventory.last_scan.is_none());
}

#[test]
fn namespace_addresses_require_local_routes_and_ready_ipv6_addresses() {
    let ipv4 = "Main:\n  |-- 192.0.2.0\n    /24 link UNICAST\n  |-- 192.0.2.7\n    /32 host LOCAL\n  |-- 192.0.2.255\n    /32 link BROADCAST\n  |-- 127.0.0.1\n    /32 host LOCAL\n  |-- 203.0.113.1\n    /32 universe UNICAST\n    /32 host LOCAL\n";
    let ipv6 = "20010db8000000000000000000000007 02 40 00 80 eth0\n20010db8000000000000000000000008 02 40 00 40 eth0\n20010db8000000000000000000000009 02 40 00 08 eth0\n00000000000000000000000000000001 01 80 10 80 lo\nnot-an-address 01 80 10 80 lo\n";
    assert_eq!(
        namespace_addresses(ipv4, ipv6),
        HashSet::from([
            "192.0.2.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "2001:db8::7".parse().unwrap(),
            "::1".parse().unwrap(),
        ])
    );
}

#[test]
fn proc_reads_reject_truncated_files_and_exhausted_budget() {
    // memfd supplies an owned deterministic input without temporary paths
    // or changing any namespace/network configuration.
    let raw = unsafe { libc::memfd_create(c"nwtop-proc-bound".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0);
    let mut file = unsafe { fs::File::from_raw_fd(raw) };
    use std::io::Write;
    file.write_all(b"0123456789").unwrap();
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let mut restricted = false;
    let mut limited = false;
    let mut budget = 10;
    assert_eq!(
        read_proc_bounded(Path::new(&path), &mut budget, &mut restricted, &mut limited).as_deref(),
        Some("0123456789")
    );
    assert_eq!(budget, 0);
    assert!(!restricted && !limited);
    assert!(
        read_proc_bounded(Path::new(&path), &mut budget, &mut restricted, &mut limited).is_none()
    );
    assert!(limited);
    budget = 9;
    limited = false;
    assert!(
        read_proc_bounded(Path::new(&path), &mut budget, &mut restricted, &mut limited).is_none()
    );
    assert_eq!(budget, 0);
    assert!(limited && !restricted);
}

#[test]
fn proc_addresses_use_native_endian_words() {
    let ipv4_word = u32::from_ne_bytes([127, 0, 0, 1]);
    assert_eq!(
        parse_address(&format!("{ipv4_word:08X}:1F90"), false).unwrap(),
        "127.0.0.1:8080".parse().unwrap()
    );
    if cfg!(target_endian = "little") {
        assert_eq!(
            parse_address("00000000000000000000000001000000:01BB", true).unwrap(),
            "[::1]:443".parse().unwrap()
        );
        assert_eq!(
            parse_address("0000000000000000FFFF00000100007F:01BB", true).unwrap(),
            "127.0.0.1:443".parse().unwrap()
        );
    }
}

#[test]
fn established_connections_outrank_wildcard_listener() {
    let local = "192.0.2.1:443".parse().unwrap();
    let remote = "198.51.100.2:23456".parse().unwrap();
    assert_eq!(
        match_score(
            &owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true),
            local,
            remote
        ),
        Some(1)
    );
    assert_eq!(
        match_score(
            &owned_socket(key("192.0.2.1:443", "198.51.100.2:23456", 2), 2, true),
            local,
            remote
        ),
        Some(6)
    );
    assert_eq!(
        match_score(
            &owned_socket(key("192.0.2.1:443", "198.51.100.3:23456", 3), 3, true),
            local,
            remote
        ),
        None
    );
}

fn resolved_pid(resolution: Resolution<'_>) -> Option<u32> {
    match resolution {
        Resolution::Owned(socket) => Some(socket.owner().unwrap().identity.pid),
        Resolution::Process(_)
        | Resolution::Pending
        | Resolution::Missing
        | Resolution::Unattributed => None,
    }
}

fn inventory_with(sockets: Vec<Socket>) -> Inventory {
    let mut inventory = Inventory::new();
    inventory.sockets = sockets;
    inventory.rebuild_index();
    inventory
}

#[test]
fn ambiguous_and_shared_sockets_do_not_get_a_pid() {
    let local = "192.0.2.1:443".parse().unwrap();
    let remote = "198.51.100.2:23456".parse().unwrap();
    let mut inventory = inventory_with(
        [1, 2]
            .map(|inode| owned_socket(key("0.0.0.0:443", "0.0.0.0:0", inode), inode as u32, true))
            .into(),
    );
    assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
    let shared_owner = inventory.sockets[1].owners[0].clone();
    inventory.sockets.truncate(1);
    inventory.sockets[0].owners.push(shared_owner);
    inventory.rebuild_index();
    assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
}

#[test]
fn retained_connected_socket_cannot_steal_rebound_wildcard_traffic() {
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        for current in [true, false] {
            let mut sockets = vec![
                owned_socket(key("192.0.2.1:53000", "198.51.100.2:53001", 1), 101, false),
                owned_socket(key("0.0.0.0:53000", "0.0.0.0:0", 2), 102, current),
            ];
            for socket in &mut sockets {
                socket.key.protocol = protocol;
            }
            let mut inventory = inventory_with(sockets);
            let local = "192.0.2.1:53000".parse().unwrap();
            let remote = "198.51.100.2:53001".parse().unwrap();
            assert!(resolved_pid(inventory.resolve(protocol, local, remote)).is_none());
            // Once the conflicting incarnation expires, attribution resumes.
            inventory.sockets.remove(0);
            inventory.rebuild_index();
            assert_eq!(
                resolved_pid(inventory.resolve(protocol, local, remote)),
                Some(102)
            );
        }
    }
}

#[test]
fn closed_tcp_connection_keeps_owner_despite_open_listener() {
    let local = "192.0.2.1:443".parse().unwrap();
    let remote = "198.51.100.2:50000".parse().unwrap();
    let mut listener = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true);
    listener.state = "LISTEN".to_string();
    let retained = owned_socket(key("192.0.2.1:443", "198.51.100.2:50000", 2), 2, false);
    let inventory = inventory_with(vec![listener.clone(), retained]);
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
        Some(2)
    );
    // UDP has no listen state: a rebound wildcard socket can receive the
    // same datagrams, so overlapping incarnations stay unattributed.
    let mut sockets = vec![
        owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true),
        owned_socket(key("192.0.2.1:443", "198.51.100.2:50000", 2), 2, false),
    ];
    for socket in &mut sockets {
        socket.key.protocol = Protocol::Udp;
    }
    let inventory = inventory_with(sockets);
    assert!(resolved_pid(inventory.resolve(Protocol::Udp, local, remote)).is_none());
}

#[test]
fn busy_ports_use_the_exact_endpoint_index() {
    let mut sockets = vec![owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true)];
    for client in 0..10_000_u32 {
        let remote = format!(
            "198.51.{}.{}:{}",
            client / 250,
            client % 250,
            40_000 + client % 1000
        );
        sockets.push(owned_socket(
            key("192.0.2.1:443", &remote, 10 + client as u64),
            10 + client,
            true,
        ));
    }
    let inventory = inventory_with(sockets);
    // Only the listener needs a per-port scan; connections are looked up directly.
    assert_eq!(
        inventory.by_port[&(inventory.host_namespace(), Protocol::Tcp, 443)].len(),
        1
    );
    let local = "192.0.2.1:443".parse().unwrap();
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, "198.51.0.7:40007".parse().unwrap())),
        Some(17)
    );
    // Unknown peers still fall back to the wildcard listener.
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, "203.0.113.9:1".parse().unwrap())),
        Some(1)
    );
}

#[test]
fn closing_remnant_does_not_hide_retained_owner() {
    let local = "192.0.2.1:50000".parse().unwrap();
    let remote = "198.51.100.2:443".parse().unwrap();
    let retained = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 7), 70, false);
    let mut remnant = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 0), 0, true);
    remnant.owners.clear();
    remnant.state = "TIME-WAIT".to_string();
    let mut inventory = inventory_with(vec![retained.clone(), remnant.clone()]);
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
        Some(70)
    );
    // An ownerless remnant alone stays unattributed.
    inventory.sockets.remove(0);
    inventory.rebuild_index();
    assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
    // A queued, not yet accepted connection is a real competing incarnation.
    remnant.state = "ESTABLISHED".to_string();
    let inventory = inventory_with(vec![retained, remnant]);
    assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
}

#[test]
fn accept_queue_entry_does_not_compete_with_the_accepted_socket() {
    let local = "127.0.0.1:8080".parse().unwrap();
    let remote = "127.0.0.1:50000".parse().unwrap();
    let queued_at = Instant::now();
    let mut queued = owned_socket(key("127.0.0.1:8080", "127.0.0.1:50000", 0), 0, false);
    queued.owners.clear();
    queued.state = "ESTABLISHED".to_string();
    queued.observed = queued_at;
    let mut accepted = owned_socket(key("127.0.0.1:8080", "127.0.0.1:50000", 7), 70, true);
    accepted.observed = queued_at + Duration::from_millis(250);
    let mut listener = owned_socket(key("127.0.0.1:8080", "0.0.0.0:0", 1), 1, true);
    listener.state = "LISTEN".to_string();
    let inventory = inventory_with(vec![listener.clone(), queued.clone(), accepted.clone()]);
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
        Some(70)
    );
    // Still the same connection after the accepted socket closed, too.
    accepted.current = false;
    let inventory = inventory_with(vec![listener.clone(), queued.clone(), accepted.clone()]);
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
        Some(70)
    );
    // A queue entry seen after an older connection closed is a different
    // incarnation, and stays unattributed.
    queued.observed = accepted.observed + Duration::from_millis(250);
    let inventory = inventory_with(vec![listener, queued, accepted]);
    assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
}

#[test]
fn unscanned_new_sockets_are_pending_not_lost() {
    let mut socket = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 9), 0, true);
    socket.owners.clear();
    let mut inventory = inventory_with(vec![
        socket.clone(),
        owned_socket(key("0.0.0.0:50000", "0.0.0.0:0", 1), 1, true),
    ]);
    let local = "192.0.2.1:50000".parse().unwrap();
    let remote = "198.51.100.2:443".parse().unwrap();
    assert!(matches!(
        inventory.resolve(Protocol::Tcp, local, remote),
        Resolution::Pending
    ));
    // Once scanned without an owner, the socket is simply unattributed.
    inventory.owner_keys.insert(9, socket.key);
    assert!(matches!(
        inventory.resolve(Protocol::Tcp, local, remote),
        Resolution::Unattributed
    ));
}

#[test]
fn new_sockets_trigger_a_prompt_owner_rescan() {
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut inventory = Inventory::new();
    inventory.refresh();
    let own_pid = std::process::id();
    let owner_of = |inventory: &Inventory, listener: &std::net::TcpListener| {
        let local = listener.local_addr().unwrap();
        resolved_pid(inventory.resolve(Protocol::Tcp, local, "127.0.0.1:9".parse().unwrap()))
    };
    assert_eq!(owner_of(&inventory, &first), Some(own_pid));
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // Well inside the periodic full-rescan period, but past the minimum gap.
    inventory.last_scan = None;
    inventory.last_owner_scan = Some(Instant::now() - Duration::from_millis(300));
    inventory.owner_scan_cost = Duration::ZERO;
    inventory.refresh();
    assert_eq!(owner_of(&inventory, &second), Some(own_pid));
}

#[test]
fn exited_or_reused_pids_lose_cached_ownership() {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let alive = Owner {
        identity: ProcessIdentity {
            pid: std::process::id(),
            start_time: start_time(&stat).unwrap(),
        },
        user: "test".to_string(),
        name: "test".to_string(),
    };
    let mut reused = alive.clone();
    reused.identity.start_time += 1;
    let mut owners = HashMap::from([(1, vec![alive.clone(), reused]), (2, vec![alive.clone()])]);
    assert!(remove_exited_owners(&mut owners));
    assert_eq!(owners[&1], vec![alive.clone()]);
    assert_eq!(owners[&2], vec![alive]);
    assert!(!remove_exited_owners(&mut owners));
}

#[test]
fn ipv6_wildcard_modes_are_cached_per_socket() {
    let Ok(listener) = std::net::TcpListener::bind("[::]:0") else {
        return; // No IPv6 in this environment.
    };
    let local = listener.local_addr().unwrap();
    let mut inventory = Inventory::new();
    inventory.refresh();
    let key = inventory
        .sockets
        .iter()
        .find(|socket| {
            socket.current && socket.key.protocol == Protocol::Tcp && socket.key.local == local
        })
        .map(|socket| socket.key.clone())
        .unwrap();
    let Some(&mode) = inventory.ipv6_modes.get(&key) else {
        return; // SOCK_DIAG unavailable; unknown must stay unknown.
    };
    inventory.last_scan = None;
    inventory.refresh();
    assert_eq!(inventory.ipv6_modes.get(&key), Some(&mode));
    // Other live system sockets may still require diagnostic retries.
    assert!(!inventory.ipv6_attempts.contains_key(&key));
    drop(listener);
    inventory.last_scan = None;
    inventory.refresh();
    assert!(
        !inventory.ipv6_modes.contains_key(&key),
        "closed sockets leave the cache"
    );
}

#[test]
fn socket_diagnostics_request_only_needed_states() {
    assert_eq!(state_mask("LISTEN", Protocol::Tcp), 1 << 10);
    assert_eq!(state_mask("CLOSE", Protocol::Tcp), 1 << 7);
    assert_eq!(state_mask("BOUND", Protocol::Udp), 1 << 7);
    assert_eq!(state_mask("CONNECTED", Protocol::Udp), 1 << 1);
}

#[test]
fn ipv4_matches_only_confirmed_dual_stack_wildcards() {
    let mut socket = owned_socket(key("[::]:53000", "[::]:0", 1), 101, true);
    let local = "127.0.0.1:53000".parse().unwrap();
    let remote = "127.0.0.1:53001".parse().unwrap();
    assert_eq!(match_score(&socket, local, remote), None);
    socket.ipv6_only = Some(true);
    assert_eq!(match_score(&socket, local, remote), None);
    socket.ipv6_only = Some(false);
    assert_eq!(match_score(&socket, local, remote), Some(1));
    assert_eq!(
        match_score(
            &socket,
            "[::1]:53000".parse().unwrap(),
            "[::1]:53001".parse().unwrap()
        ),
        Some(1)
    );
}

#[test]
fn ipv4_to_an_ipv6_wildcard_of_unknown_mode_waits() {
    let mut socket = owned_socket(key("[::]:53000", "[::]:0", 1), 101, true);
    socket.key.protocol = Protocol::Udp;
    let mut inventory = inventory_with(vec![socket]);
    let local = "127.0.0.1:53000".parse().unwrap();
    let remote = "127.0.0.1:53001".parse().unwrap();
    assert!(matches!(
        inventory.resolve(Protocol::Udp, local, remote),
        Resolution::Pending
    ));
    inventory.sockets[0].ipv6_only = Some(false);
    assert_eq!(
        resolved_pid(inventory.resolve(Protocol::Udp, local, remote)),
        Some(101)
    );
    // An IPv6-only wildcard can never own it.
    inventory.sockets[0].ipv6_only = Some(true);
    assert!(matches!(
        inventory.resolve(Protocol::Udp, local, remote),
        Resolution::Missing
    ));
    // IPv6 packets and closed sockets never wait for the mode.
    inventory.sockets[0].ipv6_only = None;
    assert_eq!(
        resolved_pid(inventory.resolve(
            Protocol::Udp,
            "[::1]:53000".parse().unwrap(),
            "[::1]:53001".parse().unwrap()
        )),
        Some(101)
    );
    inventory.sockets[0].current = false;
    assert!(matches!(
        inventory.resolve(Protocol::Udp, local, remote),
        Resolution::Missing
    ));
}

#[test]
fn endpoints_without_any_socket_are_missing() {
    let inventory = inventory_with(vec![owned_socket(
        key("127.0.0.1:8080", "0.0.0.0:0", 1),
        1,
        true,
    )]);
    assert!(matches!(
        inventory.resolve(
            Protocol::Tcp,
            "127.0.0.1:9090".parse().unwrap(),
            "127.0.0.1:50000".parse().unwrap()
        ),
        Resolution::Missing
    ));
}

#[test]
fn reuseport_sockets_of_one_process_credit_that_process() {
    let local = "192.0.2.1:443".parse().unwrap();
    let remote = "198.51.100.2:23456".parse().unwrap();
    let mut sockets: Vec<_> = [1, 2]
        .map(|inode| owned_socket(key("0.0.0.0:443", "0.0.0.0:0", inode), 7, true))
        .into();
    let inventory = inventory_with(sockets.clone());
    match inventory.resolve(Protocol::Tcp, local, remote) {
        Resolution::Process(socket) => assert_eq!(socket.owner().unwrap().identity.pid, 7),
        _ => panic!("tied sockets of one process credit the process"),
    }
    // A socket still awaiting its owner scan may belong to someone else.
    sockets[1].owners.clear();
    let inventory = inventory_with(sockets.clone());
    assert!(matches!(
        inventory.resolve(Protocol::Tcp, local, remote),
        Resolution::Pending
    ));
    // Different processes, or a reused PID, stay unattributed.
    sockets[1] = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 2), 8, true);
    let inventory = inventory_with(sockets.clone());
    assert!(matches!(
        inventory.resolve(Protocol::Tcp, local, remote),
        Resolution::Unattributed
    ));
    sockets[1] = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 2), 7, true);
    sockets[1].owners[0].identity.start_time += 1;
    let inventory = inventory_with(sockets);
    assert!(matches!(
        inventory.resolve(Protocol::Tcp, local, remote),
        Resolution::Unattributed
    ));
}

#[test]
fn process_identity_handles_parentheses_in_comm() {
    let mut fields = vec!["0"; 20];
    fields[19] = "123456";
    assert_eq!(
        start_time(&format!("42 (name (test)) {}", fields.join(" "))),
        Some(123456)
    );
    assert_ne!(
        ProcessIdentity {
            pid: 42,
            start_time: 10
        },
        ProcessIdentity {
            pid: 42,
            start_time: 11
        }
    );
}

#[test]
fn owner_closing_during_a_scan_is_kept_for_one_scan() {
    let closing = owned_socket(key("127.0.0.1:40000", "127.0.0.1:8080", 7), 7, true);
    let reused = owned_socket(key("127.0.0.1:40002", "127.0.0.1:8080", 8), 8, true);
    let moved = owned_socket(key("127.0.0.1:40004", "127.0.0.1:8080", 9), 9, true);
    let current = vec![closing.clone(), reused.clone(), moved.clone()];
    let previous: HashMap<_, _> = current
        .iter()
        .map(|socket| (socket.key.inode, socket.owners.clone()))
        .collect();
    let mut previous_keys: HashMap<_, _> = current
        .iter()
        .map(|socket| (socket.key.inode, socket.key.clone()))
        .collect();
    // Inode 8 was a different endpoint pair at the previous scan.
    previous_keys.insert(8, key("127.0.0.1:39999", "127.0.0.1:8080", 8));
    // The descriptor of inode 9 now belongs to another process.
    let mut owners = HashMap::from([(9, owned_socket(moved.key.clone(), 90, true).owners)]);
    let carried = carry_closing_owners(
        &current,
        &mut owners,
        &previous,
        &previous_keys,
        &HashSet::new(),
    );
    assert_eq!(carried, HashSet::from([7]));
    assert_eq!(owners[&7], closing.owners);
    assert!(!owners.contains_key(&8));
    assert_eq!(owners[&9][0].identity.pid, 90);

    // A socket still listed without any owner at the next scan is dropped.
    let mut next = HashMap::new();
    let again = carry_closing_owners(&current[..1], &mut next, &owners, &previous_keys, &carried);
    assert!(again.is_empty());
    assert!(next.is_empty());
}

#[test]
fn process_and_user_labels_cannot_inject_terminal_controls() {
    assert_eq!(sanitize_label("evil\u{1b}[31m\n\tname"), "evil?[31m??name");
    assert_eq!(sanitize_label("unicode-äöü\u{7f}"), "unicode-äöü?");
    assert_eq!(sanitize_label(&"x".repeat(1024)).len(), 128);
}
