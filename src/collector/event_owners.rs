//! Bounded process-context evidence for captured IP packets.
//!
//! `ingest` turns socket lifecycle and syscall events into bounded evidence
//! windows and lookup indices; `lookup` answers packet and flow queries from
//! them. Every limit quarantines uncertain evidence instead of evicting it.
use super::{
    packet::Protocol,
    sockets::{ProcessIdentity, Socket, canonical_ip},
};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};

mod ingest;
mod lookup;

const RETAIN: u64 = 3_000_000_000;
const SLOP: u64 = 1_000_000; // pcap realtime conversion / microsecond timestamps
const MAX_RECORDS: usize = 32_768;
const MAX_NAMESPACES: usize = 128;
const MAX_CANDIDATES: usize = 128;
type Tuple = (u64, Protocol, u16, SocketAddr);

/// Window direction bits: sending, receiving or both.
const TX: u8 = 1;
const RX: u8 = 2;
const BOTH: u8 = TX | RX;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    namespace: u64,
    socket: u64,
    owner: ProcessIdentity,
    process_started_ns: u64,
    protocol: Protocol,
    local: SocketAddr,
    remote: SocketAddr,
}
#[derive(Clone, Copy)]
struct Window {
    first: u64,
    last: u64,
    directions: u8,
}
#[derive(Default)]
struct Lifetime {
    first: Option<u64>,
    seen: u64,
    actor: Option<(u32, u64)>,
    conflict: bool,
    binding: Option<(SocketAddr, u64)>,
}
struct Binding {
    socket: Option<u64>,
    inode: u64,
    local: SocketAddr,
    first: u64,
    last: u64,
}
struct Record {
    socket: Socket,
    closed_conflict: bool,
    lifetime: Option<Window>,
    seen: u64,
    closed: Option<u64>,
    windows: Vec<Window>,
}
#[derive(Default)]
pub(super) struct Owners {
    records: HashMap<Key, Record>,
    // Reservations from different CPUs can reach the ring in an order that
    // differs from event timestamps. A CLOSE must survive a later-drained SEND.
    closed: HashMap<(u64, u64), u64>,
    lifetimes: HashMap<(u64, u64), Lifetime>,
    unsafe_until: u64,
    quarantine_reason: Option<String>,
    limited: bool,
    updated_at: u64,
    bindings_limited: bool,
    windows: usize,
    namespaces: HashSet<u64>,
    addresses: HashSet<(u64, IpAddr)>,
    // None marks an overfull tuple. Never drop only the conflicting owners.
    tuples: HashMap<Tuple, Option<Vec<Key>>>,
    socket_records: HashMap<(u64, u64), Option<Vec<Key>>>,
    bindings: HashMap<(u64, u16), Option<Vec<Binding>>>,
}
pub(super) enum Match {
    Owned(Socket),
    Observed(Socket),
    Missing,
    Ambiguous,
}

impl Owners {
    fn invalidate(&mut self, now: u64, reason: &'static str) {
        self.records.clear();
        self.closed.clear();
        self.lifetimes.clear();
        self.clear_indices();
        self.unsafe_until = self.unsafe_until.max(now.saturating_add(RETAIN));
        self.quarantine_reason = Some(reason.into());
    }

    /// Drops everything derived from `records`, `closed` and `lifetimes`.
    fn clear_indices(&mut self) {
        self.windows = 0;
        self.namespaces.clear();
        self.addresses.clear();
        self.tuples.clear();
        self.socket_records.clear();
        self.bindings.clear();
        self.bindings_limited = false;
    }

    pub fn limited(&self) -> bool {
        self.limited
    }

    pub fn suppressed(&self) -> bool {
        self.suppression_reason().is_some()
    }

    pub fn describe_loss(&mut self, details: String) {
        if self.quarantine_reason.as_deref() == Some("socket events lost") && !details.is_empty() {
            self.quarantine_reason = Some(format!("socket events lost: {details}"));
        }
    }

    pub fn suppression_reason(&self) -> Option<&str> {
        if self.unsafe_until > self.updated_at {
            self.quarantine_reason.as_deref()
        } else if self.limited() {
            Some("socket evidence index limit reached")
        } else {
            None
        }
    }

    pub fn namespaces(&self) -> HashSet<u64> {
        self.namespaces.clone()
    }

    pub fn has_address(&self, namespace: u64, address: IpAddr) -> bool {
        self.addresses.contains(&(namespace, canonical_ip(address)))
    }
}

/// A new key would exceed the record bound of `map`.
fn at_capacity<K: Eq + Hash, V>(map: &HashMap<K, V>, key: &K) -> bool {
    map.len() >= MAX_RECORDS && !map.contains_key(key)
}

/// Appends a candidate unless the list is already overfull. A list that
/// reaches the bound becomes `None` and stays so; returns whether this push
/// made it overfull.
fn push_candidate<T>(candidates: &mut Option<Vec<T>>, candidate: T) -> bool {
    let Some(list) = candidates else {
        return false;
    };
    if list.len() >= MAX_CANDIDATES {
        *candidates = None;
        true
    } else {
        list.push(candidate);
        false
    }
}

#[cfg(test)]
mod tests;
