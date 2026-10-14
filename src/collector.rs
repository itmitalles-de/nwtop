//! Real Linux kernel counters and best-effort, header-only process attribution.

#[path = "capture.rs"]
mod capture;
#[path = "conntrack.rs"]
mod conntrack;
#[path = "event_owners.rs"]
mod event_owners;
#[path = "events.rs"]
mod events;
#[path = "extended.rs"]
mod extended;
#[path = "links.rs"]
mod links;
#[path = "packet.rs"]
mod packet;
#[path = "sockets.rs"]
mod sockets;

mod interfaces;

pub use interfaces::default_interface;
use interfaces::{TopologyCache, local_interfaces, read_interfaces};

use crate::i18n::Lang;
use crate::model::{CaptureNote, CaptureStatus, ConnectionRow, Interface, ProcessRow, Snapshot};
use anyhow::{Context, Result};
use packet::{Direction, Flow};
use sockets::{Inventory, Owner, ProcessIdentity, Resolution, Socket, SocketKey, canonical_ip};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
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
        let previous_interfaces = interfaces
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
            .collect();
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
        if std::mem::take(&mut self.start_worker) {
            // Started once; on failure, attribution falls back to snapshots.
            match Worker::start(Arc::clone(&self.shared)) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => lock(&self.shared).worker_error = Some(format!("{error:#}")),
            }
        }
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
        for current in &mut interfaces {
            if let Some(&(old_index, rx, tx)) = self.previous_interfaces.get(&current.info.name)
                && old_index == current.index
            {
                current.info.rx_rate = counter_rate(current.info.rx_bytes, rx, interval);
                current.info.tx_rate = counter_rate(current.info.tx_bytes, tx, interval);
            }
        }
        self.previous_interfaces = interfaces
            .iter()
            .map(|current| {
                (
                    current.info.name.clone(),
                    (current.index, current.info.rx_bytes, current.info.tx_bytes),
                )
            })
            .collect();
        self.last_sample = now;
        state.prune(now, &interfaces);
        let deltas = std::mem::take(&mut state.deltas);
        let problems = std::mem::take(&mut state.status);
        let counter_limit = std::mem::take(&mut state.counters.limit_hit);

        let mut status = CaptureStatus {
            active: state.capture.is_some(),
            notes: self.capture_note.iter().cloned().collect(),
            ..CaptureStatus::default()
        };
        if let Some(capture) = &state.capture {
            // Per-interval values: a past burst must not taint later snapshots.
            status.dropped = problems.dropped.saturating_add(problems.overflow);
            status.notes = vec![if interface.is_some() && !capture.interface_indexes {
                status.active = false;
                CaptureNote::NoInterfaceIndexes
            } else if interface.is_none() {
                CaptureNote::AllInterfaces
            } else {
                CaptureNote::Sampled
            }];
            if problems.dropped > 0 {
                status.notes.push(CaptureNote::PcapMissed {
                    packets: problems.dropped,
                });
            }
            if problems.overflow > 0 {
                status.notes.push(CaptureNote::CaptureQueueLimit {
                    packets: problems.overflow,
                });
            }
            if problems.attribution_overflow > 0 {
                status.notes.push(CaptureNote::AttributionQueueLimit {
                    packets: problems.attribution_overflow,
                });
            }
            if problems.unsupported > 0 || problems.truncated > 0 {
                status.notes.push(CaptureNote::Unreadable {
                    unsupported: problems.unsupported,
                    truncated: problems.truncated,
                });
            }
            if let Some(error) = &state.worker_error {
                status.notes.push(CaptureNote::AttributionAtRefresh {
                    error: error.clone(),
                });
            }
            if let Some(error) = &state.capture_error {
                status.active = false;
                status.notes = vec![CaptureNote::Stopped {
                    error: error.clone(),
                }];
            }
        }
        if let Some(extended) = &state.extended {
            let socket_packets = interface.is_none() && extended.packet_capture_active();
            if socket_packets {
                for note in &mut status.notes {
                    if *note == CaptureNote::AllInterfaces {
                        *note = CaptureNote::AllSocketPackets;
                    }
                }
            }
            if interface.is_none() && extended.packet_capture_failed() {
                status.active = false;
            }
            if extended.available() {
                status.notes.retain(|note| *note != CaptureNote::Sampled);
                status.notes.push(CaptureNote::Extended);
            }
            if extended.available() && !socket_packets && problems.timestamp_invalid > 0 {
                status.notes.push(CaptureNote::ExtendedIssue {
                    detail: format!(
                        "{} packet timestamps unavailable; uncertain event owners withheld",
                        problems.timestamp_invalid
                    ),
                });
            }
            for detail in &extended.issues {
                status.notes.push(CaptureNote::ExtendedIssue {
                    detail: detail.clone(),
                });
            }
            if extended.unconfirmed.replace(false) && !socket_packets {
                status.notes.push(CaptureNote::ExtendedIssue {
                    detail: "no confirmed conntrack entry for some flows; only positive socket events can attribute them".into(),
                });
            }
        }
        if state.inventory.restricted {
            status.notes.push(CaptureNote::OwnersInaccessible);
        }
        if state.inventory.limited || counter_limit {
            status.notes.push(CaptureNote::CounterLimit);
        }
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
        self.status.dropped = self.status.dropped.saturating_add(batch.dropped);
        self.status.overflow = self.status.overflow.saturating_add(batch.overflow);
        self.status.unsupported = self.status.unsupported.saturating_add(batch.unsupported);
        self.status.truncated = self.status.truncated.saturating_add(batch.truncated);
        self.status.timestamp_invalid = self
            .status
            .timestamp_invalid
            .saturating_add(batch.timestamp_invalid);
        if batch.error.is_some() {
            self.capture_error = batch.error;
        }
        for ((flow, receive), deferred) in std::mem::take(&mut self.deferred) {
            self.attribute(&flow, receive, deferred.bytes, deferred.since, now, &view);
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
                self.attribute_extended(item.flow, item.bytes, item.since, now, &view);
            }
        }
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
        for ((index, direction, socket_protocol), untracked) in batch.untracked {
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
        let bytes = if packet.receive != 0 {
            Bytes {
                rx: u64::from(packet.ip_bytes),
                tx: 0,
            }
        } else {
            Bytes {
                rx: 0,
                tx: u64::from(packet.ip_bytes),
            }
        };
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
                for (socket, receive, lower, connection_known) in owners {
                    let increment = if receive {
                        Bytes {
                            rx: bytes.bytes,
                            tx: 0,
                        }
                    } else {
                        Bytes {
                            rx: 0,
                            tx: bytes.bytes,
                        }
                    };
                    let link = Link {
                        index: flow.interface_index,
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
                        self.counters.record_unknown(
                            link,
                            increment,
                            now,
                            &mut self.deltas.unknown,
                        );
                    }
                }
                for (receive, lower) in unresolved {
                    let increment = if receive {
                        Bytes {
                            rx: bytes.bytes,
                            tx: 0,
                        }
                    } else {
                        Bytes {
                            rx: 0,
                            tx: bytes.bytes,
                        }
                    };
                    self.counters.record_unknown(
                        Link {
                            index: flow.interface_index,
                            lower: lower || selected_only,
                        },
                        increment,
                        now,
                        &mut self.deltas.unknown,
                    );
                }
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
        let increment = if receive {
            Bytes { rx: bytes, tx: 0 }
        } else {
            Bytes { rx: 0, tx: bytes }
        };
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

    fn rows(
        &self,
        selected: Option<u32>,
        interfaces: &[KernelInterface],
        now: Instant,
        interval: f64,
        deltas: &Deltas,
        rates_available: bool,
    ) -> (Vec<ProcessRow>, Vec<ConnectionRow>) {
        let mut processes: HashMap<ProcessIdentity, ProcessRow> = HashMap::new();
        let mut connections: HashMap<(SocketKey, Option<ProcessIdentity>), ConnectionRow> =
            HashMap::new();
        let mut unknown = ProcessRow {
            pid: None,
            user: "-".to_string(),
            name: "[unattributed]".to_string(),
            ..ProcessRow::default()
        };
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
                    key.namespace != self.inventory.host_namespace()
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
            if !socket_in_scope(socket, scope, self.inventory.host_namespace())
                && !socket.owner().is_some_and(|owner| {
                    observed_foreign.contains(&(socket.key.clone(), owner.identity))
                })
            {
                continue;
            }
            let owner = socket.owner();
            connections.insert(
                (socket.key.clone(), owner.map(|owner| owner.identity)),
                connection_row(socket, &self.inventory),
            );
            if let Some(owner) = owner {
                processes
                    .entry(owner.identity)
                    .or_insert_with(|| process_row(owner))
                    .connections += 1;
            } else {
                unknown.connections += 1;
            }
        }
        for (&(link, identity), entry) in &self.counters.processes {
            if !link_in_scope(link, selected) {
                continue;
            }
            // Traffic within this interval stays visible even when the
            // sockets closed more than RECENT_TRAFFIC before a long sample.
            if !processes.contains_key(&identity)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas.processes.contains_key(&(link, identity))
            {
                continue;
            }
            let row = processes
                .entry(identity)
                .or_insert_with(|| process_row(&entry.owner));
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.processes.get(&(link, identity)) {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for ((link, socket_key, identity), entry) in &self.counters.connections {
            if !link_in_scope(*link, selected) {
                continue;
            }
            let key = (socket_key.clone(), Some(*identity));
            if !connections.contains_key(&key)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas
                    .connections
                    .contains_key(&(*link, socket_key.clone(), *identity))
            {
                continue;
            }
            let row = connections.entry(key).or_insert_with(|| {
                let mut row = connection_row(&entry.socket, &self.inventory);
                row.state = "RECENT/CLOSED".to_string();
                row
            });
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available
                && let Some(bytes) = deltas
                    .connections
                    .get(&(*link, socket_key.clone(), *identity))
            {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for (&link, counter) in &self.counters.unattributed {
            if !link_in_scope(link, selected) {
                continue;
            }
            unknown.rx_bytes = unknown.rx_bytes.saturating_add(counter.bytes.rx);
            unknown.tx_bytes = unknown.tx_bytes.saturating_add(counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.unknown.get(&link) {
                unknown.rx_rate += bytes.rx as f64 / interval;
                unknown.tx_rate += bytes.tx as f64 / interval;
            }
        }
        let mut rows: Vec<_> = processes.into_values().collect();
        if unknown.connections > 0 || unknown.rx_bytes > 0 || unknown.tx_bytes > 0 {
            rows.push(unknown);
        }
        rows.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        let mut connections: Vec<_> = connections.into_values().collect();
        connections.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.local.cmp(&b.local))
        });
        (rows, connections)
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

/// All-interface views skip lower-device duplicates of host traffic.
fn link_in_scope(link: Link, selected: Option<u32>) -> bool {
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

/// Host addresses and link relations, built once per attribution pass so
/// per-flow checks are set lookups rather than scans of every interface.
#[derive(Default)]
struct LocalView {
    addresses: HashSet<IpAddr>,
    loopback: HashSet<u32>,
    /// Links whose host traffic is also captured on an upper device.
    lower: HashMap<u32, LowerLink>,
}

struct LowerLink {
    /// Bridge ports and bond slaves hand every locally delivered packet to
    /// their master, and transmit what the master sends.
    enslaved: bool,
    own: HashSet<IpAddr>,
    /// Addresses of (transitive) upper devices such as VLANs or macvlans.
    upper: HashSet<IpAddr>,
}

impl LocalView {
    fn new(interfaces: &[KernelInterface]) -> Self {
        let mut view = Self::default();
        let by_index: HashMap<u32, &KernelInterface> = interfaces
            .iter()
            .map(|interface| (interface.index, interface))
            .collect();
        for interface in interfaces {
            view.addresses
                .extend(interface.addresses.iter().map(|ip| canonical_ip(*ip)));
            if interface.loopback {
                view.loopback.insert(interface.index);
            }
            let topology = &interface.topology;
            if !topology.master && topology.uppers.is_empty() {
                continue;
            }
            let mut upper = HashSet::new();
            let mut pending = topology.uppers.clone();
            let mut seen = HashSet::from([interface.index]);
            // Stacks are shallow (VLAN on bond on ports); bound malformed loops.
            while let Some(index) = pending.pop() {
                if !seen.insert(index) || seen.len() > 16 {
                    continue;
                }
                if let Some(device) = by_index.get(&index) {
                    upper.extend(device.addresses.iter().map(|ip| canonical_ip(*ip)));
                    pending.extend(&device.topology.uppers);
                }
            }
            view.lower.insert(
                interface.index,
                LowerLink {
                    enslaved: topology.master,
                    own: interface
                        .addresses
                        .iter()
                        .map(|ip| canonical_ip(*ip))
                        .collect(),
                    upper,
                },
            );
        }
        view
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        (!self.loopback.is_empty() && ip.is_loopback()) || self.addresses.contains(&ip)
    }

    /// Host traffic for `local` seen on link `index` that its upper device
    /// also captures, so all-interface totals would count it twice.
    fn lower_observation(&self, index: u32, local: IpAddr) -> bool {
        let local = canonical_ip(local);
        self.lower.get(&index).is_some_and(|link| {
            link.enslaved || (link.upper.contains(&local) && !link.own.contains(&local))
        })
    }
}

/// Traffic between two local endpoints, observed once on a loopback link.
fn loopback_path(flow: &Flow, view: &LocalView) -> bool {
    view.loopback.contains(&flow.interface_index)
        || (flow.interface_index == 0
            && view.is_local(flow.source)
            && view.is_local(flow.destination))
}

fn traffic_sides(flow: &Flow, view: &LocalView) -> (bool, bool) {
    if loopback_path(flow, view) {
        // On loopback, libpcap drops the outgoing copy and keeps the incoming
        // one; that single observation belongs to both the sender's TX and
        // the receiver's RX, never twice to either endpoint.
        return (true, true);
    }
    match flow.direction {
        Direction::Incoming => (true, false),
        Direction::Outgoing => (false, true),
        Direction::Unknown => (view.is_local(flow.destination), view.is_local(flow.source)),
    }
}

fn socket_endpoints(flow: &Flow, receive: bool) -> Option<(SocketAddr, SocketAddr)> {
    let source = SocketAddr::new(canonical_ip(flow.source), flow.source_port?);
    let destination = SocketAddr::new(canonical_ip(flow.destination), flow.destination_port?);
    Some(if receive {
        (destination, source)
    } else {
        (source, destination)
    })
}

fn local_socket_endpoints(
    flow: &Flow,
    receive: bool,
    view: &LocalView,
) -> Option<(SocketAddr, SocketAddr)> {
    let (local, remote) = socket_endpoints(flow, receive)?;
    // Captured interface direction is not proof of a local socket endpoint.
    // Bridges, forwarding and container links also expose nonlocal traffic;
    // matching it to a wildcard listener merely by port assigns the wrong PID.
    // Multicast/broadcast receiver membership is not known from /proc, so leave
    // those receive bytes unattributed too. Sender attribution remains possible.
    view.is_local(local.ip()).then_some((local, remote))
}

/// Docker publishes ports by DNAT in PREROUTING, but AF_PACKET observes packets
/// before translation, so forwarded container traffic still carries the host
/// port of docker-proxy's wildcard listener. With Docker's NAT rules that proxy
/// only serves loopback connections, and its accepted connections match
/// exactly. Do not credit wildcard-only matches from other links to it; the
/// bytes stay unattributed instead of naming the wrong process.
fn published_port_proxy(flow: &Flow, socket: &Socket, view: &LocalView) -> bool {
    let remote = socket.key.remote;
    remote.ip().is_unspecified()
        && remote.port() == 0
        && socket
            .owner()
            .is_some_and(|owner| owner.name == "docker-proxy")
        && !loopback_path(flow, view)
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

#[cfg(test)]
mod tests;
