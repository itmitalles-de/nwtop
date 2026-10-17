//! Event intake: validates lifecycle and syscall events, keeps bounded
//! evidence windows and rebuilds the lookup indices after each batch.
use super::{
    BOTH, Binding, IPPROTO_TCP, IPPROTO_UDP, Key, Lifetime, MAX_NAMESPACES, MAX_RECORDS, Owners,
    RETAIN, RX, Record, TX, Window, at_capacity, push_candidate,
};
use crate::collector::{
    events::Event,
    packet::Protocol,
    sockets::{Inventory, Owner, ProcessIdentity, Socket, SocketKey, canonical_ip},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

// Event kinds and flags mirror `bpf/lifecycle.bpf.c`.
const SEND: u8 = 1;
const RECV: u8 = 2;
const CONNECT: u8 = 3;
const CLOSE: u8 = 4;
const ACCEPT: u8 = 5;
const BIND: u8 = 6;
const BIRTH: u8 = 7;
const UNRELIABLE_ACTOR: u8 = 1;
const UNKNOWN_PEER: u8 = 2;

impl Owners {
    pub fn update(&mut self, events: Vec<Event>, lost: u64, now: u64, inventory: &Inventory) {
        self.limited = false;
        self.updated_at = now;
        self.expire(now);
        if lost > 0 {
            self.invalidate(now, "socket events lost");
        }
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks <= 0 {
            self.invalidate(now, "process clock unavailable");
            return;
        }
        for event in &events {
            self.ingest(event, now, ticks, inventory);
        }
        self.rebuild(now, inventory);
    }

    /// Forgets evidence older than the retention window.
    fn expire(&mut self, now: u64) {
        self.records.retain(|_, record| {
            record
                .windows
                .retain(|window| now.saturating_sub(window.last) <= RETAIN);
            !record.windows.is_empty()
                && now.saturating_sub(record.closed.unwrap_or(record.seen)) <= RETAIN
        });
        self.closed
            .retain(|_, closed| now.saturating_sub(*closed) <= RETAIN);
        self.lifetimes
            .retain(|_, lifetime| now.saturating_sub(lifetime.seen) <= RETAIN);
        self.windows = self
            .records
            .values()
            .map(|record| record.windows.len())
            .sum();
    }

    fn ingest(&mut self, event: &Event, now: u64, ticks: libc::c_long, inventory: &Inventory) {
        if event.socket_id == 0
            || event.netns == 0
            || event.timestamp_ns == 0
            || now.saturating_sub(event.timestamp_ns) > RETAIN
        {
            return;
        }
        match event.kind {
            BIRTH => self.record_birth(event, now),
            SEND..=BIND => self.record_actor(event, now, ticks, inventory),
            _ => {}
        }
    }

    /// TCP clone happens before accept and may run in a kernel receive
    /// context. It proves birth, never a process identity.
    fn record_birth(&mut self, event: &Event, now: u64) {
        if event.protocol != IPPROTO_TCP
            || event.started_ns == 0
            || event.started_ns > event.timestamp_ns
            || event.started_ns <= self.unsafe_until
        {
            return;
        }
        let Some(lifetime) = self.lifetime(socket_identity(event), now) else {
            return;
        };
        lifetime.seen = lifetime.seen.max(event.timestamp_ns);
        lifetime.begin(event.started_ns);
    }

    /// A syscall or close by an identified process.
    fn record_actor(
        &mut self,
        event: &Event,
        now: u64,
        ticks: libc::c_long,
        inventory: &Inventory,
    ) {
        if event.flags & UNRELIABLE_ACTOR != 0 {
            self.invalidate(now, "kernel or io_uring actor cannot be identified");
            return;
        }
        if event.tgid == 0
            || event.process_start_ns == 0
            || event.reserved != 0
            || event.flags & !UNKNOWN_PEER != 0
            || event.started_ns == 0
            || event.started_ns > event.timestamp_ns
            || event.started_ns <= self.unsafe_until
        {
            return;
        }
        let socket_identity = socket_identity(event);
        let Some(lifetime) = self.lifetime(socket_identity, now) else {
            return;
        };
        lifetime.observe(event);
        if event.kind == CLOSE {
            self.record_close(socket_identity, event.timestamp_ns, now);
        } else {
            self.record_syscall(event, now, ticks, inventory);
        }
    }

    /// Appends the syscall's evidence window to the record of this socket
    /// incarnation, process and endpoint pair.
    fn record_syscall(
        &mut self,
        event: &Event,
        now: u64,
        ticks: libc::c_long,
        inventory: &Inventory,
    ) {
        let Some((protocol, local, remote)) = event_endpoints(event) else {
            return;
        };
        // /proc reports process start times in clock ticks.
        let identity = ProcessIdentity {
            pid: event.tgid,
            start_time: ((u128::from(event.process_start_ns) * ticks as u128) / 1_000_000_000)
                as u64,
        };
        let key = Key {
            namespace: u64::from(event.netns),
            socket: event.socket_id,
            owner: identity,
            process_started_ns: event.process_start_ns,
            protocol,
            local,
            remote,
        };
        if at_capacity(&self.records, &key) {
            self.reject_overflow(now);
            return;
        }
        let closed = self.closed.get(&socket_identity(event)).copied();
        let record = self.records.entry(key).or_insert_with(|| Record {
            socket: Socket {
                key: SocketKey {
                    namespace: u64::from(event.netns),
                    inode: event.inode,
                    protocol,
                    local,
                    remote,
                },
                state: "OBSERVED".into(),
                uid: event.uid,
                owners: vec![event_owner(event, identity, inventory)],
                observed: Instant::now(),
                current: false,
                ipv6_only: None,
            },
            closed_conflict: false,
            lifetime: None,
            seen: event.timestamp_ns,
            closed,
            windows: Vec::new(),
        });
        record.seen = record.seen.max(event.timestamp_ns);
        // Append in O(1); coalesce once per batch in `rebuild`, not once per
        // event, so one hot socket cannot cause quadratic update work.
        record.windows.push(Window {
            first: event.started_ns,
            last: event.timestamp_ns,
            directions: match event.kind {
                SEND => TX,
                RECV => RX,
                CONNECT => BOTH,
                _ => 0,
            },
        });
        self.windows += 1;
        if self.windows > MAX_RECORDS {
            self.limited = true;
            self.invalidate(now, "socket event window limit reached");
        }
    }

    /// The lifetime entry of a socket incarnation, or `None` once the
    /// identity bound has quarantined all evidence.
    fn lifetime(&mut self, socket_identity: (u64, u64), now: u64) -> Option<&mut Lifetime> {
        if at_capacity(&self.lifetimes, &socket_identity) {
            self.reject_overflow(now);
            return None;
        }
        Some(self.lifetimes.entry(socket_identity).or_default())
    }

    /// Keeps the earliest close of a socket incarnation.
    fn record_close(&mut self, socket_identity: (u64, u64), timestamp: u64, now: u64) {
        if at_capacity(&self.closed, &socket_identity) {
            self.reject_overflow(now);
            return;
        }
        let closed = self.closed.entry(socket_identity).or_insert(timestamp);
        *closed = (*closed).min(timestamp);
    }

    fn reject_overflow(&mut self, now: u64) {
        self.limited = true;
        self.invalidate(now, "socket identity limit reached");
    }

    fn rebuild(&mut self, now: u64, inventory: &Inventory) {
        self.clear_indices();
        for (key, record) in &mut self.records {
            let socket_id = (key.namespace, key.socket);
            record.closed = self.closed.get(&socket_id).copied();
            if let Some(closed) = record.closed
                && let Some(lifetime) = self.lifetimes.get(&socket_id)
            {
                record.bound_by_close(lifetime, closed);
            }
            record.coalesce_windows();
            self.windows += record.windows.len();
            self.namespaces.insert(key.namespace);
            if !key.local.ip().is_unspecified() {
                self.addresses.insert((key.namespace, key.local.ip()));
            }
            let records = self
                .socket_records
                .entry(socket_id)
                .or_insert_with(|| Some(Vec::new()));
            self.limited |= push_candidate(records, key.clone());
            if key.remote.port() == 0 || key.remote.ip().is_unspecified() {
                continue;
            }
            let candidates = self
                .tuples
                .entry((key.namespace, key.protocol, key.local.port(), key.remote))
                .or_insert_with(|| Some(Vec::new()));
            self.limited |= push_candidate(candidates, key.clone());
        }
        self.index_bindings(inventory);
        self.limited |= self.bindings_limited || self.bindings.values().any(Option::is_none);
        if self.namespaces.len() > MAX_NAMESPACES {
            self.limited = true;
            self.invalidate(now, "socket namespace limit reached");
        }
    }

    /// Indexes UDP local bindings that can compete for queued receives.
    fn index_bindings(&mut self, inventory: &Inventory) {
        for (&(namespace, socket), lifetime) in &self.lifetimes {
            if let Some((local, inode)) = lifetime.binding {
                self.bindings_limited |= !Self::index_binding(
                    &mut self.bindings,
                    namespace,
                    Binding {
                        socket: Some(socket),
                        inode,
                        local,
                        first: lifetime.first.unwrap_or(0),
                        last: self
                            .closed
                            .get(&(namespace, socket))
                            .copied()
                            .unwrap_or(u64::MAX),
                    },
                );
            }
        }
        // A socket bound before tracing started has no BIND event. Existing
        // inventory evidence must also block lifetime-only guesses among UDP
        // SO_REUSEPORT members, even if their queued packet was never read.
        for socket in inventory
            .sockets
            .iter()
            .filter(|socket| socket.key.protocol == Protocol::Udp)
        {
            self.bindings_limited |= !Self::index_binding(
                &mut self.bindings,
                socket.key.namespace,
                Binding {
                    socket: None,
                    inode: socket.key.inode,
                    local: socket.key.local,
                    first: 0,
                    last: u64::MAX,
                },
            );
        }
    }

    fn index_binding(
        index: &mut HashMap<(u64, u16), Option<Vec<Binding>>>,
        namespace: u64,
        binding: Binding,
    ) -> bool {
        let key = (namespace, binding.local.port());
        if at_capacity(index, &key) {
            return false;
        }
        let candidates = index.entry(key).or_insert_with(|| Some(Vec::new()));
        push_candidate(candidates, binding);
        true
    }
}

impl Lifetime {
    fn begin(&mut self, started: u64) {
        self.first = Some(self.first.map_or(started, |first| first.min(started)));
    }

    fn observe(&mut self, event: &Event) {
        self.seen = self.seen.max(event.timestamp_ns);
        let actor = (event.tgid, event.process_start_ns);
        if self.actor.is_some_and(|previous| previous != actor) {
            self.conflict = true;
        }
        self.actor.get_or_insert(actor);
        // A successful bind/accept/send/connect proves the socket existed
        // from this point. A receive alone cannot backdate ownership to
        // when an already-queued packet arrived.
        if matches!(event.kind, SEND | CONNECT | ACCEPT | BIND) {
            self.begin(event.started_ns);
        }
        if event.kind == BIND
            && event.protocol == IPPROTO_UDP
            && let Some(local) = address(event.family, event.local_addr, event.local_port)
            && local.port() != 0
        {
            self.binding = Some((local, event.inode));
        }
    }
}

impl Record {
    /// Last-reference release occurs after all active socket calls. A closed
    /// socket with exactly one observed actor provides a bounded lifetime,
    /// including packets queued before recv.
    fn bound_by_close(&mut self, lifetime: &Lifetime, closed: u64) {
        let Some(first) = lifetime.first.filter(|first| *first <= closed) else {
            return;
        };
        self.closed_conflict = lifetime.conflict;
        self.lifetime = Some(Window {
            first,
            last: closed,
            directions: if lifetime.conflict { 0 } else { BOTH },
        });
    }

    /// Sorts windows by direction and merges only genuinely overlapping
    /// syscall intervals. A first..last envelope would invent evidence in
    /// inherited-FD gaps.
    fn coalesce_windows(&mut self) {
        self.windows
            .sort_unstable_by_key(|window| (window.directions, window.first, window.last));
        self.windows.dedup_by(|next, previous| {
            if previous.directions == next.directions && next.first <= previous.last {
                previous.last = previous.last.max(next.last);
                true
            } else {
                false
            }
        });
    }
}

fn socket_identity(event: &Event) -> (u64, u64) {
    (u64::from(event.netns), event.socket_id)
}

/// The protocol and canonical endpoints of a socket event. An unconnected
/// UDP read without a peer keeps an unspecified remote.
fn event_endpoints(event: &Event) -> Option<(Protocol, SocketAddr, SocketAddr)> {
    let protocol = match event.protocol {
        IPPROTO_TCP => Protocol::Tcp,
        IPPROTO_UDP => Protocol::Udp,
        _ => return None,
    };
    let local = address(event.family, event.local_addr, event.local_port)?;
    let remote = address(event.family, event.remote_addr, event.remote_port)?;
    let peer_known =
        event.flags & UNKNOWN_PEER == 0 && remote.port() != 0 && !remote.ip().is_unspecified();
    if local.port() == 0 || (!peer_known && protocol != Protocol::Udp) {
        return None;
    }
    if peer_known {
        return Some((protocol, local, remote));
    }
    // read()/recv() need not request the peer of an unconnected UDP socket.
    // Preserve the actor and exact socket incarnation for endpoint packets,
    // never invent tuple evidence from it.
    let unspecified = if local.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    Some((protocol, local, SocketAddr::new(unspecified, 0)))
}

fn event_owner(event: &Event, identity: ProcessIdentity, inventory: &Inventory) -> Owner {
    let comm = &event.comm[..event
        .comm
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(event.comm.len())];
    Owner {
        identity,
        user: inventory
            .users
            .get(&event.uid)
            .cloned()
            .unwrap_or_else(|| event.uid.to_string()),
        name: String::from_utf8_lossy(comm)
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect(),
    }
}

fn address(family: u16, bytes: [u8; 16], port: u16) -> Option<SocketAddr> {
    let ip = match i32::from(family) {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(bytes)),
        _ => return None,
    };
    Some(SocketAddr::new(canonical_ip(ip), port))
}
