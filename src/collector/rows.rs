//! Process and connection rows built from current sockets and counters.
use super::sockets::{Inventory, Owner, ProcessIdentity, Socket, SocketKey, canonical_ip};
use super::{Attribution, Bytes, Deltas, KernelInterface, Link, RECENT_TRAFFIC};
use crate::model::{ConnectionRow, ProcessRow};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

impl Attribution {
    pub(super) fn rows(
        &self,
        selected: Option<u32>,
        interfaces: &[KernelInterface],
        now: Instant,
        interval: f64,
        deltas: &Deltas,
        rates_available: bool,
    ) -> (Vec<ProcessRow>, Vec<ConnectionRow>) {
        let mut rows = RowSet::new();
        self.list_current_sockets(&mut rows, selected, interfaces, now, deltas);
        let rates = Rates {
            interval,
            available: rates_available,
        };
        self.add_process_counters(&mut rows, selected, now, deltas, rates);
        self.add_connection_counters(&mut rows, selected, now, deltas, rates);
        for (&link, counter) in &self.counters.unattributed {
            if link_in_scope(link, selected) {
                rates.add(&mut rows.unknown, counter.bytes, deltas.unknown.get(&link));
            }
        }
        rows.finish()
    }

    /// Lists current sockets in scope: on a selected link, also foreign
    /// namespace connections that recently carried traffic there.
    fn list_current_sockets(
        &self,
        rows: &mut RowSet,
        selected: Option<u32>,
        interfaces: &[KernelInterface],
        now: Instant,
        deltas: &Deltas,
    ) {
        let host = self.inventory.host_namespace();
        let scope = selected.map(|selected| {
            interfaces
                .iter()
                .find(|interface| interface.index == selected)
        });
        let observed_foreign: HashSet<_> = if selected.is_some() {
            self.counters
                .connections
                .iter()
                .filter(|((link, key, identity), entry)| {
                    key.namespace != host
                        && link_in_scope(*link, selected)
                        && (now.duration_since(entry.counter.last_seen) <= RECENT_TRAFFIC
                            || deltas
                                .connections
                                .contains_key(&(*link, key.clone(), *identity)))
                })
                .map(|((_, key, identity), _)| (key.clone(), *identity))
                .collect()
        } else {
            HashSet::new()
        };
        for socket in self
            .inventory
            .sockets
            .iter()
            .filter(|socket| socket.current)
        {
            if !socket_in_scope(socket, scope, host)
                && !socket.owner().is_some_and(|owner| {
                    observed_foreign.contains(&(socket.key.clone(), owner.identity))
                })
            {
                continue;
            }
            let owner = socket.owner();
            rows.connections.insert(
                (socket.key.clone(), owner.map(|owner| owner.identity)),
                connection_row(socket, &self.inventory),
            );
            if let Some(owner) = owner {
                rows.processes
                    .entry(owner.identity)
                    .or_insert_with(|| process_row(owner))
                    .connections += 1;
            } else {
                rows.unknown.connections += 1;
            }
        }
    }

    /// Traffic within this interval stays visible even when the sockets
    /// closed more than RECENT_TRAFFIC before a long sample.
    fn add_process_counters(
        &self,
        rows: &mut RowSet,
        selected: Option<u32>,
        now: Instant,
        deltas: &Deltas,
        rates: Rates,
    ) {
        for (&(link, identity), entry) in &self.counters.processes {
            if !link_in_scope(link, selected) {
                continue;
            }
            let delta = deltas.processes.get(&(link, identity));
            if !rows.processes.contains_key(&identity)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && delta.is_none()
            {
                continue;
            }
            let row = rows
                .processes
                .entry(identity)
                .or_insert_with(|| process_row(&entry.owner));
            rates.add(row, entry.counter.bytes, delta);
        }
    }

    fn add_connection_counters(
        &self,
        rows: &mut RowSet,
        selected: Option<u32>,
        now: Instant,
        deltas: &Deltas,
        rates: Rates,
    ) {
        for ((link, socket_key, identity), entry) in &self.counters.connections {
            if !link_in_scope(*link, selected) {
                continue;
            }
            let key = (socket_key.clone(), Some(*identity));
            let delta = deltas
                .connections
                .get(&(*link, socket_key.clone(), *identity));
            if !rows.connections.contains_key(&key)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && delta.is_none()
            {
                continue;
            }
            let row = rows.connections.entry(key).or_insert_with(|| {
                let mut row = connection_row(&entry.socket, &self.inventory);
                row.state = "RECENT/CLOSED".to_string();
                row
            });
            rates.add(row, entry.counter.bytes, delta);
        }
    }
}

/// Process and connection rows of one snapshot under construction.
struct RowSet {
    processes: HashMap<ProcessIdentity, ProcessRow>,
    connections: HashMap<(SocketKey, Option<ProcessIdentity>), ConnectionRow>,
    unknown: ProcessRow,
}

impl RowSet {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            connections: HashMap::new(),
            unknown: ProcessRow {
                pid: None,
                user: "-".to_string(),
                name: "[unattributed]".to_string(),
                ..ProcessRow::default()
            },
        }
    }

    /// Busiest rows first; the unattributed row only when it has anything.
    fn finish(self) -> (Vec<ProcessRow>, Vec<ConnectionRow>) {
        let mut rows: Vec<_> = self.processes.into_values().collect();
        let unknown = self.unknown;
        if unknown.connections > 0 || unknown.rx_bytes > 0 || unknown.tx_bytes > 0 {
            rows.push(unknown);
        }
        rows.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        let mut connections: Vec<_> = self.connections.into_values().collect();
        connections.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.local.cmp(&b.local))
        });
        (rows, connections)
    }
}

/// Byte totals and rates shared by process and connection rows.
trait TrafficRow {
    fn traffic(&mut self) -> (&mut u64, &mut u64, &mut f64, &mut f64);
}

impl TrafficRow for ProcessRow {
    fn traffic(&mut self) -> (&mut u64, &mut u64, &mut f64, &mut f64) {
        (
            &mut self.rx_bytes,
            &mut self.tx_bytes,
            &mut self.rx_rate,
            &mut self.tx_rate,
        )
    }
}

impl TrafficRow for ConnectionRow {
    fn traffic(&mut self) -> (&mut u64, &mut u64, &mut f64, &mut f64) {
        (
            &mut self.rx_bytes,
            &mut self.tx_bytes,
            &mut self.rx_rate,
            &mut self.tx_rate,
        )
    }
}

/// Rates divide this snapshot's deltas by its interval, and only while
/// capture is active.
#[derive(Clone, Copy)]
struct Rates {
    interval: f64,
    available: bool,
}

impl Rates {
    fn add(self, row: &mut impl TrafficRow, total: Bytes, delta: Option<&Bytes>) {
        let (rx_bytes, tx_bytes, rx_rate, tx_rate) = row.traffic();
        *rx_bytes = rx_bytes.saturating_add(total.rx);
        *tx_bytes = tx_bytes.saturating_add(total.tx);
        if self.available
            && let Some(bytes) = delta
        {
            *rx_rate += bytes.rx as f64 / self.interval;
            *tx_rate += bytes.tx as f64 / self.interval;
        }
    }
}

/// All-interface views skip lower-device duplicates of host traffic.
pub(super) fn link_in_scope(link: Link, selected: Option<u32>) -> bool {
    selected.map_or(!link.lower, |selected| selected == link.index)
}

/// `scope` is `None` for all interfaces, `Some(None)` for a vanished one.
fn socket_in_scope(
    socket: &Socket,
    scope: Option<Option<&KernelInterface>>,
    host_namespace: u64,
) -> bool {
    let Some(selected) = scope else {
        return true;
    };
    let Some(interface) = selected else {
        return false;
    };
    // Namespace-local loopback and wildcard bindings cannot prove that a
    // socket serves a selected host link. Foreign endpoints are added below
    // from counters with positive observations on that exact host interface.
    if socket.key.namespace != host_namespace {
        return false;
    }
    let ip = canonical_ip(socket.key.local.ip());
    // A wildcard is a kernel-wide binding and can serve the selected interface.
    ip.is_unspecified() || interface_has_ip(interface, ip)
}

fn interface_has_ip(interface: &KernelInterface, ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    (interface.loopback && ip.is_loopback())
        || interface
            .addresses
            .iter()
            .any(|address| canonical_ip(*address) == ip)
}

fn process_row(owner: &Owner) -> ProcessRow {
    ProcessRow {
        pid: Some(owner.identity.pid),
        user: owner.user.clone(),
        name: owner.name.clone(),
        ..ProcessRow::default()
    }
}

fn connection_row(socket: &Socket, inventory: &Inventory) -> ConnectionRow {
    let owner = socket.owner();
    ConnectionRow {
        pid: owner.map(|owner| owner.identity.pid),
        user: owner
            .map(|owner| owner.user.clone())
            .unwrap_or_else(|| inventory.user(socket.uid)),
        process: owner.map(|owner| owner.name.clone()).unwrap_or_else(|| {
            if socket.owners.len() > 1 {
                "[shared]".to_string()
            } else {
                "[unknown]".to_string()
            }
        }),
        protocol: socket.key.protocol.label().to_string(),
        local: socket.key.local.to_string(),
        remote: socket.key.remote.to_string(),
        state: socket.state.clone(),
        ..ConnectionRow::default()
    }
}
