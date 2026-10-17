//! Real Linux kernel counters and best-effort, header-only process attribution.

#[path = "capture.rs"]
mod capture;
#[path = "conntrack.rs"]
mod conntrack;
#[path = "events.rs"]
mod events;
#[path = "links.rs"]
mod links;
#[path = "packet.rs"]
mod packet;
#[path = "sockets.rs"]
mod sockets;

mod endpoints;
mod event_owners;
mod extended;
mod interfaces;
mod rows;
mod status;

use endpoints::{LocalView, local_socket_endpoints, published_port_proxy, traffic_sides};
pub use interfaces::default_interface;
use interfaces::{TopologyCache, local_interfaces, read_interfaces};

use crate::i18n::Lang;
use crate::model::{CaptureNote, Interface, Snapshot};
use anyhow::{Context, Result};
use packet::{Direction, Flow};
use sockets::{Inventory, Owner, ProcessIdentity, Resolution, Socket, SocketKey};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_PROCESS_COUNTERS: usize = 16_384;
const MAX_CONNECTION_COUNTERS: usize = 32_768;
/// Each link can have a lower-device entry besides its own (see `Link`).
const MAX_INTERFACE_COUNTERS: usize = 512;
const COUNTER_RETENTION: Duration = Duration::from_secs(300);
const RECENT_TRAFFIC: Duration = Duration::from_secs(3);
/// Captured flows are matched to sockets on this cadence, independent of the
/// UI refresh interval, so closed and short-lived sockets are still known.
const ATTRIBUTION_TICK: Duration = Duration::from_millis(250);
const MAX_ATTRIBUTION_WAIT: Duration = Duration::from_millis(500);
/// Flows whose socket awaits its first owner scan are retried until that scan
/// can have run: at least one second, longer while the cost-dependent owner
/// scan gap is longer, and never past the periodic full rescan.
const MAX_DEFERRED: usize = 4_096;
const MIN_DEFER: Duration = Duration::from_secs(1);
const MAX_DEFER: Duration = Duration::from_secs(6);
#[derive(Clone, Debug)]
struct KernelInterface {
    info: Interface,
    index: u32,
    addresses: Vec<IpAddr>,
    loopback: bool,
    topology: LinkTopology,
}

/// Stacked-device relations from sysfs: a bridge port or bond slave has a
/// master; VLAN, macvlan and bond devices are uppers of their lower links.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinkTopology {
    master: bool,
    uppers: Vec<u32>,
}

/// The capture link of counted bytes. `lower` marks an observation on a
/// bridge port, bond slave or VLAN parent of host traffic that the upper
/// device also captures. All-interface totals skip those duplicates;
/// selecting that link still shows them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Link {
    index: u32,
    lower: bool,
}

impl Link {
    fn plain(index: u32) -> Self {
        Self {
            index,
            lower: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Bytes {
    rx: u64,
    tx: u64,
}

impl Bytes {
    /// `bytes` received (`receive`) or sent.
    fn one_way(receive: bool, bytes: u64) -> Self {
        if receive {
            Self { rx: bytes, tx: 0 }
        } else {
            Self { rx: 0, tx: bytes }
        }
    }

    fn add(&mut self, other: Self) {
        self.rx = self.rx.saturating_add(other.rx);
        self.tx = self.tx.saturating_add(other.tx);
    }
}

struct Counter {
    bytes: Bytes,
    last_seen: Instant,
}

impl Counter {
    fn new(now: Instant) -> Self {
        Self {
            bytes: Bytes::default(),
            last_seen: now,
        }
    }

    fn add(&mut self, bytes: Bytes, now: Instant) {
        self.bytes.add(bytes);
        self.last_seen = now;
    }
}

struct ProcessCounter {
    owner: Owner,
    counter: Counter,
}

struct ConnectionCounter {
    socket: Socket,
    counter: Counter,
}

type ProcessCounterKey = (Link, ProcessIdentity);
type ConnectionCounterKey = (Link, SocketKey, ProcessIdentity);

/// Bytes attributed since the previous snapshot; rates divide these by the
/// snapshot interval.
#[derive(Default)]
struct Deltas {
    processes: HashMap<ProcessCounterKey, Bytes>,
    connections: HashMap<ConnectionCounterKey, Bytes>,
    unknown: HashMap<Link, Bytes>,
}

/// Capture problems observed since the previous snapshot.
#[derive(Default)]
struct IntervalStatus {
    timestamp_invalid: u64,
    dropped: u64,
    overflow: u64,
    attribution_overflow: u64,
    unsupported: u64,
    truncated: u64,
}

impl IntervalStatus {
    fn add_batch(&mut self, batch: &capture::Batch) {
        self.dropped = self.dropped.saturating_add(batch.dropped);
        self.overflow = self.overflow.saturating_add(batch.overflow);
        self.unsupported = self.unsupported.saturating_add(batch.unsupported);
        self.truncated = self.truncated.saturating_add(batch.truncated);
        self.timestamp_invalid = self
            .timestamp_invalid
            .saturating_add(batch.timestamp_invalid);
    }
}

#[derive(Default)]
struct Counters {
    processes: HashMap<ProcessCounterKey, ProcessCounter>,
    connections: HashMap<ConnectionCounterKey, ConnectionCounter>,
    unattributed: HashMap<Link, Counter>,
    /// A counter bound rejected bytes since the previous snapshot.
    limit_hit: bool,
}

/// Bytes of one flow direction awaiting a retry, merged across passes.
struct Deferred {
    bytes: u64,
    since: Instant,
}

/// Socket inventory, capture session and counters. Shared between snapshot
/// requests and the background attribution worker.
struct Attribution {
    inventory: Inventory,
    capture: Option<capture::Capture>,
    counters: Counters,
    deltas: Deltas,
    status: IntervalStatus,
    capture_error: Option<String>,
    deferred: HashMap<(Flow, bool), Deferred>,
    worker_error: Option<String>,
    extended: Option<extended::Extended>,
}

fn lock(shared: &Mutex<Attribution>) -> MutexGuard<'_, Attribution> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stops and joins the background attribution thread on drop.
struct Worker {
    stop: Arc<AtomicBool>,
    wake: Arc<capture::Wake>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    /// Started from the sampling thread, so it inherits exactly that thread's
    /// capabilities and NO_NEW_PRIVS: in the helper only the /proc read
    /// capabilities, never the capture capability.
    fn start(shared: Arc<Mutex<Attribution>>) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let wake = lock(&shared)
            .capture
            .as_ref()
            .map(|capture| Arc::clone(&capture.wake))
            .unwrap_or_default();
        let thread_wake = Arc::clone(&wake);
        let handle = thread::Builder::new()
            .name("nwtop-attrib".to_string())
            .spawn(move || {
                let mut wait = ATTRIBUTION_TICK;
                let mut topology = TopologyCache::default();
                loop {
                    thread_wake.wait(wait);
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let started = Instant::now();
                    let interfaces = local_interfaces(&mut topology);
                    lock(&shared).tick(&interfaces);
                    // Back off on hosts where one pass is expensive.
                    wait = (started.elapsed() * 4).clamp(ATTRIBUTION_TICK, MAX_ATTRIBUTION_WAIT);
                }
            })
            .context("starting socket attribution worker")?;
        Ok(Self {
            stop,
            wake,
            handle: Some(handle),
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake.notify();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A collector owns one capture worker; dropping it closes its own pcap session.
pub struct Collector {
    started: Instant,
    last_sample: Instant,
    previous_interfaces: HashMap<String, (u32, u64, u64)>,
    /// Why capture is off from the start, if it is.
    capture_note: Option<CaptureNote>,
    /// The worker starts on the first snapshot, from the sampling thread.
    start_worker: bool,
    // Declared before `shared` so the worker stops before the capture closes.
    worker: Option<Worker>,
    shared: Arc<Mutex<Attribution>>,
}

impl Collector {
    pub fn new(capture_enabled: bool) -> Result<Self> {
        let started = Instant::now();
        let mut inventory = Inventory::new();
        let wake = Arc::new(capture::Wake::default());
        let extended = (capture_enabled && cfg!(feature = "ebpf"))
            .then(|| extended::Extended::start(Arc::clone(&wake)));
        inventory.set_namespace_discovery(extended.as_ref().is_some_and(|e| e.available()));
        let interfaces = read_interfaces()?;
        let previous_interfaces = interface_counters(&interfaces);
        let last_sample = Instant::now();
        let (capture, capture_note) = if capture_enabled {
            match capture::Capture::start(wake) {
                Ok(capture) => (Some(capture), None),
                Err(error) => {
                    let note = match error.downcast_ref::<capture::StartError>() {
                        Some(known) => known.0.clone(),
                        None => CaptureNote::Unavailable {
                            detail: format!("{error:#}"),
                        },
                    };
                    (None, Some(note))
                }
            }
        } else {
            (None, Some(CaptureNote::Disabled))
        };
        // Open capture before the potentially expensive initial descriptor
        // scan. Traffic during that scan must reach the normal bounded flow
        // queue instead of disappearing before capture starts.
        inventory.refresh();
        let start_worker = capture.is_some();
        let mut attribution = Attribution::new(inventory, capture);
        attribution.extended = extended;
        Ok(Self {
            started,
            last_sample,
            previous_interfaces,
            capture_note,
            start_worker,
            worker: None,
            shared: Arc::new(Mutex::new(attribution)),
        })
    }

    /// `None` means all captured interfaces, including virtual links. The status
    /// warns about duplicate observations across host bridges and veth devices.
    pub fn sample(&mut self, interface: Option<&str>) -> Result<Snapshot> {
        self.start_worker_once();
        let mut interfaces = read_interfaces()?;
        // Hot unplug is an empty scope, never a silent switch to all devices.
        // The CLI validates an explicit initial selection itself.
        let selected = interface.map(|name| {
            interfaces
                .iter()
                .find(|candidate| candidate.info.name == name)
                .map_or(u32::MAX, |candidate| candidate.index)
        });
        let missing_interface = selected == Some(u32::MAX);
        let mut state = lock(&self.shared);
        // Attribute everything captured up to now; the background worker has
        // already handled earlier packets against then-current sockets.
        state.tick(&interfaces);
        let now = Instant::now();
        let interval = now
            .duration_since(self.last_sample)
            .as_secs_f64()
            .max(0.001);
        set_interface_rates(&mut interfaces, &self.previous_interfaces, interval);
        self.previous_interfaces = interface_counters(&interfaces);
        self.last_sample = now;
        state.prune(now, &interfaces);
        let deltas = std::mem::take(&mut state.deltas);
        let problems = std::mem::take(&mut state.status);
        let counter_limit = std::mem::take(&mut state.counters.limit_hit);

        let mut status = state.capture_status(
            &problems,
            interface,
            self.capture_note.as_ref(),
            counter_limit,
        );
        if missing_interface {
            status.active = false;
            status.notes = vec![CaptureNote::InterfaceMissing {
                name: interface.unwrap_or_default().to_string(),
            }];
        }
        status.message = Lang::En.capture_status(&status, true).unwrap_or_default();
        let (processes, connections) =
            state.rows(selected, &interfaces, now, interval, &deltas, status.active);
        drop(state);
        Ok(Snapshot {
            elapsed: now.duration_since(self.started).as_secs_f64(),
            interfaces: interfaces
                .into_iter()
                .map(|interface| interface.info)
                .collect(),
            processes,
            connections,
            capture: status,
        })
    }

    /// Started once, on the first snapshot; on failure, attribution falls
    /// back to snapshots.
    fn start_worker_once(&mut self) {
        if std::mem::take(&mut self.start_worker) {
            match Worker::start(Arc::clone(&self.shared)) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => lock(&self.shared).worker_error = Some(format!("{error:#}")),
            }
        }
    }
}

/// Kernel byte counters by interface name, with the ifindex that owns them.
fn interface_counters(interfaces: &[KernelInterface]) -> HashMap<String, (u32, u64, u64)> {
    interfaces
        .iter()
        .map(|interface| {
            (
                interface.info.name.clone(),
                (
                    interface.index,
                    interface.info.rx_bytes,
                    interface.info.tx_bytes,
                ),
            )
        })
        .collect()
}

/// Rates need the same name and ifindex in the previous sample; a recreated
/// device starts again from zero.
fn set_interface_rates(
    interfaces: &mut [KernelInterface],
    previous: &HashMap<String, (u32, u64, u64)>,
    interval: f64,
) {
    for current in interfaces {
        if let Some(&(old_index, rx, tx)) = previous.get(&current.info.name)
            && old_index == current.index
        {
            current.info.rx_rate = counter_rate(current.info.rx_bytes, rx, interval);
            current.info.tx_rate = counter_rate(current.info.tx_bytes, tx, interval);
        }
    }
}

impl Attribution {
    fn new(inventory: Inventory, capture: Option<capture::Capture>) -> Self {
        Self {
            inventory,
            capture,
            counters: Counters::default(),
            deltas: Deltas::default(),
            status: IntervalStatus::default(),
            capture_error: None,
            deferred: HashMap::new(),
            worker_error: None,
            extended: None,
        }
    }

    /// Drains the flows captured so far, then refreshes sockets and attributes
    /// the flows while the sockets that carried them are still current or
    /// briefly retained. Draining first keeps the socket tables at least as new
    /// as every packet matched against them; otherwise a socket created
    /// between a refresh and a later drain would have no candidate.
    fn tick(&mut self, interfaces: &[KernelInterface]) {
        let Some(capture) = &self.capture else {
            self.inventory.refresh();
            return;
        };
        let batch = capture.drain();
        let drained = Instant::now();
        self.inventory.refresh();
        let view = LocalView::new(interfaces);
        let now = Instant::now();
        if let Some(extended) = &mut self.extended {
            extended.refresh(&self.inventory);
        }
        self.status.add_batch(&batch);
        if batch.error.is_some() {
            self.capture_error = batch.error;
        }
        self.retry_waiting(drained, now, &view);
        for (flow, bytes) in batch.flows.into_iter().chain(batch.timed_flows) {
            if self.extended.as_ref().is_some_and(|e| e.available()) {
                self.attribute_extended(flow, bytes, drained, now, &view);
                continue;
            }
            let (rx, tx) = traffic_sides(&flow, &view);
            for receive in [false, true] {
                if (receive && rx) || (!receive && tx) {
                    self.attribute(&flow, receive, bytes.bytes, drained, now, &view);
                }
            }
        }
        self.count_untracked(batch.untracked, now, &view);
    }

    /// Retries deferred flows, then attributes queued and new socket packets
    /// and queued extended flows, oldest evidence first.
    fn retry_waiting(&mut self, drained: Instant, now: Instant, view: &LocalView) {
        for ((flow, receive), deferred) in std::mem::take(&mut self.deferred) {
            self.attribute(&flow, receive, deferred.bytes, deferred.since, now, view);
        }
        if let Some(extended) = &mut self.extended {
            let pending = std::mem::take(&mut extended.pending);
            let pending_packets = std::mem::take(&mut extended.pending_packets);
            let packets = extended.take_packets();
            for item in pending_packets {
                self.attribute_packet(item.packet, item.since, now);
            }
            for packet in packets {
                self.attribute_packet(packet, drained, now);
            }
            for item in pending {
                self.attribute_extended(item.flow, item.bytes, item.since, now, view);
            }
        }
    }

    /// Bytes the capture could not tie to a flow. With socket packet capture,
    /// socket-protocol bytes on a link duplicate the All-interface source.
    fn count_untracked(
        &mut self,
        untracked: HashMap<(u32, Direction, bool), capture::Untracked>,
        now: Instant,
        view: &LocalView,
    ) {
        for ((index, direction, socket_protocol), untracked) in untracked {
            let bytes = match direction {
                _ if view.loopback.contains(&index) => Bytes {
                    rx: untracked.bytes,
                    tx: untracked.bytes,
                },
                Direction::Incoming => Bytes {
                    rx: untracked.bytes,
                    tx: 0,
                },
                Direction::Outgoing => Bytes {
                    rx: 0,
                    tx: untracked.bytes,
                },
                Direction::Unknown => Bytes::default(),
            };
            self.counters.record_unknown(
                Link {
                    index,
                    lower: socket_protocol
                        && self
                            .extended
                            .as_ref()
                            .is_some_and(|e| e.packet_capture_active()),
                },
                bytes,
                now,
                &mut self.deltas.unknown,
            );
        }
    }

    /// Socket-bound IP packet observations are the sole All-interface source
    /// when enabled. Namespace-local ifindexes must never select host links.
    fn attribute_packet(&mut self, packet: events::PacketEvent, since: Instant, now: Instant) {
        let extended = self.extended.as_mut().expect("extended packet path");
        let expired = now.saturating_duration_since(since) >= Duration::from_secs(2);
        let mut result = extended.resolve_packet(&packet, &self.inventory, expired);
        if matches!(result, extended::PacketResult::Pending) {
            if extended.pending_packets.len() < MAX_DEFERRED {
                extended
                    .pending_packets
                    .push(extended::PendingPacket { packet, since });
                return;
            }
            self.status.attribution_overflow = self.status.attribution_overflow.saturating_add(1);
            result = extended.resolve_packet(&packet, &self.inventory, true);
        }
        let bytes = Bytes::one_way(packet.receive != 0, u64::from(packet.ip_bytes));
        let link = Link::plain(0);
        if let extended::PacketResult::Owned(socket, connection_known) = result
            && self.counters.record_owned(
                link,
                &socket,
                connection_known,
                bytes,
                now,
                &mut self.deltas,
            )
        {
            return;
        }
        self.counters
            .record_unknown(link, bytes, now, &mut self.deltas.unknown);
    }

    fn attribute_extended(
        &mut self,
        flow: Flow,
        bytes: capture::TimedBytes,
        since: Instant,
        now: Instant,
        view: &LocalView,
    ) {
        let extended = self.extended.as_mut().expect("extended path");
        let selected_only = extended.packet_capture_active()
            && matches!(flow.protocol, packet::Protocol::Tcp | packet::Protocol::Udp);
        let expired = now.saturating_duration_since(since) >= Duration::from_secs(2);
        let resolution = extended.resolve(&flow, bytes, &self.inventory, view, expired);
        let resolution = if matches!(resolution, extended::Result::Pending)
            && !expired
            && extended.pending.len() >= MAX_DEFERRED
        {
            // Preserve whichever endpoint is already proven. Queue pressure
            // ends the wait, never turns known bytes into unknown bytes or
            // permits an otherwise ambiguous owner.
            self.status.attribution_overflow = self.status.attribution_overflow.saturating_add(1);
            extended.resolve(&flow, bytes, &self.inventory, view, true)
        } else {
            resolution
        };
        match resolution {
            extended::Result::Owned(owners, unresolved) => {
                self.credit_endpoints(
                    owners,
                    unresolved,
                    flow.interface_index,
                    bytes.bytes,
                    selected_only,
                    now,
                );
                return;
            }
            extended::Result::Pending if !expired && extended.pending.len() < MAX_DEFERRED => {
                extended
                    .pending
                    .push(extended::Pending { flow, bytes, since });
                return;
            }
            _ => {}
        }
        let (rx, tx) = traffic_sides(&flow, view);
        self.counters.record_unknown(
            Link {
                index: flow.interface_index,
                lower: selected_only,
            },
            Bytes {
                rx: if rx { bytes.bytes } else { 0 },
                tx: if tx { bytes.bytes } else { 0 },
            },
            now,
            &mut self.deltas.unknown,
        );
    }

    /// Credits each resolved endpoint of an extended flow; unresolved
    /// endpoints and rejected owners count as unknown on the same link.
    fn credit_endpoints(
        &mut self,
        owners: Vec<(Socket, bool, bool, bool)>,
        unresolved: Vec<(bool, bool)>,
        index: u32,
        bytes: u64,
        selected_only: bool,
        now: Instant,
    ) {
        for (socket, receive, lower, connection_known) in owners {
            let increment = Bytes::one_way(receive, bytes);
            let link = Link {
                index,
                lower: lower || selected_only,
            };
            if !self.counters.record_owned(
                link,
                &socket,
                connection_known,
                increment,
                now,
                &mut self.deltas,
            ) {
                self.counters
                    .record_unknown(link, increment, now, &mut self.deltas.unknown);
            }
        }
        for (receive, lower) in unresolved {
            self.counters.record_unknown(
                Link {
                    index,
                    lower: lower || selected_only,
                },
                Bytes::one_way(receive, bytes),
                now,
                &mut self.deltas.unknown,
            );
        }
    }

    /// How long a flow may wait for its socket's owner: until the next owner
    /// scan can have run. Retrying deferred flows is a hash lookup each, so a
    /// longer wait costs bounded memory (`MAX_DEFERRED`), not extra scans.
    fn max_defer(&self) -> Duration {
        (self.inventory.owner_scan_gap() + 2 * MAX_ATTRIBUTION_WAIT).clamp(MIN_DEFER, MAX_DEFER)
    }

    /// `since` is when the bytes were first drained from the capture.
    fn attribute(
        &mut self,
        flow: &Flow,
        receive: bool,
        bytes: u64,
        since: Instant,
        now: Instant,
        view: &LocalView,
    ) {
        let increment = Bytes::one_way(receive, bytes);
        let endpoints = local_socket_endpoints(flow, receive, view);
        let link = Link {
            index: flow.interface_index,
            lower: endpoints
                .is_some_and(|(local, _)| view.lower_observation(flow.interface_index, local.ip())),
        };
        let resolution = endpoints.map_or(Resolution::Unattributed, |(local, remote)| {
            self.inventory.resolve(flow.protocol, local, remote)
        });
        let defer = match resolution {
            Resolution::Owned(socket) if !published_port_proxy(flow, socket, view) => {
                if self
                    .counters
                    .record_owned(link, socket, true, increment, now, &mut self.deltas)
                {
                    return;
                }
                false
            }
            // Tied sockets of one process (SO_REUSEPORT): the process is
            // known, the individual socket is not.
            Resolution::Process(socket) if !published_port_proxy(flow, socket, view) => {
                if self
                    .counters
                    .record_owned(link, socket, false, increment, now, &mut self.deltas)
                {
                    return;
                }
                false
            }
            // The socket exists, but its owner or IPv6 mode is not known yet.
            Resolution::Pending => true,
            // No socket of a local endpoint matched. A table read before the
            // bytes were drained can lack a just-created socket; retry once
            // the tables are newer. Nonlocal traffic never gets here.
            Resolution::Missing => self
                .inventory
                .refreshed_at()
                .is_none_or(|refreshed| refreshed <= since),
            _ => false,
        };
        if defer && now.saturating_duration_since(since) < self.max_defer() {
            let key = (flow.clone(), receive);
            if let Some(waiting) = self.deferred.get_mut(&key) {
                waiting.bytes = waiting.bytes.saturating_add(bytes);
                waiting.since = waiting.since.min(since);
                return;
            }
            if self.deferred.len() < MAX_DEFERRED {
                self.deferred.insert(key, Deferred { bytes, since });
                return;
            }
        }
        self.counters
            .record_unknown(link, increment, now, &mut self.deltas.unknown);
    }

    fn prune(&mut self, now: Instant, interfaces: &[KernelInterface]) {
        let current_sockets: HashSet<_> = self
            .inventory
            .sockets
            .iter()
            .filter(|socket| socket.current)
            .filter_map(|socket| {
                socket
                    .owner()
                    .map(|owner| (socket.key.clone(), owner.identity))
            })
            .collect();
        let current_processes: HashSet<_> = current_sockets
            .iter()
            .map(|(_, identity)| *identity)
            .collect();
        let links: HashSet<_> = interfaces.iter().map(|interface| interface.index).collect();
        self.counters.processes.retain(|(_, identity), entry| {
            current_processes.contains(identity)
                || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
        });
        self.counters
            .connections
            .retain(|(_, key, identity), entry| {
                current_sockets.contains(&(key.clone(), *identity))
                    || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
            });
        self.counters.unattributed.retain(|link, entry| {
            links.contains(&link.index) || now.duration_since(entry.last_seen) <= COUNTER_RETENTION
        });
    }
}

impl Counters {
    /// Clones the owner or socket only when a counter is created or its view
    /// changed, never per packet batch. Without `connection`, only the
    /// process is credited.
    fn record_owned(
        &mut self,
        link: Link,
        socket: &Socket,
        connection: bool,
        bytes: Bytes,
        now: Instant,
        deltas: &mut Deltas,
    ) -> bool {
        let Some(owner) = socket.owner() else {
            return false;
        };
        let process_key = (link, owner.identity);
        let connection_key = (link, socket.key.clone(), owner.identity);
        if (self.processes.len() >= MAX_PROCESS_COUNTERS
            && !self.processes.contains_key(&process_key))
            || (connection
                && self.connections.len() >= MAX_CONNECTION_COUNTERS
                && !self.connections.contains_key(&connection_key))
        {
            self.limit_hit = true;
            return false;
        }
        let process = self
            .processes
            .entry(process_key)
            .or_insert_with(|| ProcessCounter {
                owner: owner.clone(),
                counter: Counter::new(now),
            });
        if process.owner != *owner {
            process.owner = owner.clone();
        }
        process.counter.add(bytes, now);
        deltas.processes.entry(process_key).or_default().add(bytes);
        if !connection {
            return true;
        }
        let connection = self
            .connections
            .entry(connection_key.clone())
            .or_insert_with(|| ConnectionCounter {
                socket: socket.clone(),
                counter: Counter::new(now),
            });
        if connection.socket.current != socket.current
            || connection.socket.state != socket.state
            || connection.socket.owners != socket.owners
        {
            connection.socket = socket.clone();
        }
        connection.counter.add(bytes, now);
        deltas
            .connections
            .entry(connection_key)
            .or_default()
            .add(bytes);
        true
    }

    fn record_unknown(
        &mut self,
        link: Link,
        bytes: Bytes,
        now: Instant,
        delta: &mut HashMap<Link, Bytes>,
    ) {
        if self.unattributed.len() >= MAX_INTERFACE_COUNTERS
            && !self.unattributed.contains_key(&link)
        {
            self.limit_hit = true;
            return;
        }
        self.unattributed
            .entry(link)
            .or_insert_with(|| Counter::new(now))
            .add(bytes, now);
        delta.entry(link).or_default().add(bytes);
    }
}

fn counter_rate(current: u64, previous: u64, interval: f64) -> f64 {
    current.saturating_sub(previous) as f64 / interval
}

#[cfg(test)]
mod tests;
