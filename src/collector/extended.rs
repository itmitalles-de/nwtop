//! Optional socket-bound IP-packet and namespace/NAT attribution.
use super::{
    capture::{TimedBytes, monotonic_ns},
    conntrack::{self, Conntrack},
    endpoints::{LocalView, loopback_path, published_port_proxy, socket_endpoints},
    event_owners::{self, Owners},
    events::{Events, PacketEvent},
    links,
    packet::{Direction, Flow},
    sockets::{Inventory, Resolution, Socket},
};
use owner_index::OwnerIndex;
use std::cell::Cell;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod owner_index;

pub(super) struct Extended {
    events: Option<Events>,
    conntrack: Option<Conntrack>,
    owners: Owners,
    sampled_owners: OwnerIndex,
    errors: Vec<String>,
    conntrack_lost: u64,
    pub issues: Vec<String>,
    pub unconfirmed: Cell<bool>,
    veth: HashSet<u32>,
    links_at: Instant,
    links_error: Option<String>,
    pub pending: Vec<Pending>,
    pub pending_packets: Vec<PendingPacket>,
    packets: Vec<PacketEvent>,
    packet_failed: bool,
}
pub(super) struct PendingPacket {
    pub packet: PacketEvent,
    pub since: Instant,
}
pub(super) enum PacketResult {
    Owned(Socket, bool),
    Pending,
    Unknown,
}
pub(super) struct Pending {
    pub flow: Flow,
    pub bytes: TimedBytes,
    pub since: Instant,
}
pub(super) enum Result {
    /// Socket, receive direction, duplicate observation, exact socket known.
    Owned(Vec<(Socket, bool, bool, bool)>, Vec<(bool, bool)>),
    Pending,
    Unknown,
}

/// One flow endpoint in the namespace that alone can own it.
struct Endpoint {
    namespace: u64,
    local: SocketAddr,
    remote: SocketAddr,
    receive: bool,
}

/// The owner evidence for one flow endpoint.
enum EndpointOwner {
    /// Socket and whether that exact connection is known.
    Socket(Socket, bool),
    /// The owner may become known; retry before giving up.
    Uncertain,
    /// No owner can be credited.
    Unattributed,
}

impl Extended {
    fn with_sources(
        events: Option<Events>,
        conntrack: Option<Conntrack>,
        errors: Vec<String>,
        links_at: Instant,
    ) -> Self {
        Self {
            events,
            conntrack,
            owners: Owners::default(),
            sampled_owners: OwnerIndex::default(),
            conntrack_lost: 0,
            issues: errors.clone(),
            unconfirmed: Cell::new(false),
            errors,
            veth: HashSet::new(),
            links_at,
            links_error: None,
            pending: Vec::new(),
            pending_packets: Vec::new(),
            packets: Vec::new(),
            packet_failed: false,
        }
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Self {
        Self::with_sources(None, None, Vec::new(), Instant::now())
    }

    pub fn available(&self) -> bool {
        self.events.is_some() || self.conntrack.is_some()
    }

    pub fn start(wake: Arc<super::capture::Wake>) -> Self {
        let mut errors = Vec::new();
        let events = Events::start(wake)
            .map_err(|e| errors.push(format!("socket events: {e:#}")))
            .ok();
        let conntrack = Conntrack::start()
            .map_err(|e| errors.push(format!("conntrack: {e:#}")))
            .ok();
        Self::with_sources(
            events,
            conntrack,
            errors,
            Instant::now() - Duration::from_secs(3),
        )
    }

    /// Startup is atomic: Events exists only if every packet/lifecycle hook
    /// was attached. Runtime errors never turn on a second All byte source.
    pub fn packet_capture_active(&self) -> bool {
        self.events.is_some()
    }

    pub fn packet_capture_failed(&self) -> bool {
        self.packet_failed
    }

    pub fn take_packets(&mut self) -> Vec<PacketEvent> {
        std::mem::take(&mut self.packets)
    }

    pub fn resolve_packet(
        &self,
        packet: &PacketEvent,
        inventory: &Inventory,
        allow_partial: bool,
    ) -> PacketResult {
        let resolved = match self.owners.resolve_packet(packet) {
            event_owners::Match::Owned(socket) if !self.sampled_owners.vetoes(&socket) => {
                Some(socket)
            }
            // The packet itself identifies the actual socket incarnation,
            // even when it was queued outside the owner's syscall window.
            event_owners::Match::Observed(observed) => self
                .sampled_owners
                .current(inventory, &observed)
                .filter(|socket| self.sampled_owners.corroborates(socket, &observed))
                .cloned(),
            _ => None,
        };
        match resolved {
            Some(mut socket) => {
                // Resolve ownership first. A UDP socket can serve many peers;
                // neither its sampled wildcard nor a previous syscall's peer
                // identifies this packet's connection.
                let endpoints = packet_endpoints(packet);
                if let Some((local, remote)) = endpoints {
                    socket.key.local = local;
                    socket.key.remote = remote;
                }
                PacketResult::Owned(socket, endpoints.is_some())
            }
            None if !allow_partial => PacketResult::Pending,
            None => PacketResult::Unknown,
        }
    }

    pub fn refresh(&mut self, inventory: &Inventory) {
        self.issues.clone_from(&self.errors);
        self.sampled_owners.refresh(inventory);
        if self.sampled_owners.limited {
            self.issues
                .push("socket owner index full; uncertain owners withheld".into());
        }
        self.refresh_events(inventory);
        self.refresh_conntrack();
        self.refresh_links();
    }

    fn refresh_events(&mut self, inventory: &Inventory) {
        let Some(events) = &self.events else {
            return;
        };
        let batch = events.drain();
        self.packets = batch.packets;
        if let Some(error) = batch.error {
            self.packet_failed = true;
            self.issues.push(format!("socket events: {error}"));
        }
        let loss_details = batch.losses.describe();
        if batch.lost > 0 {
            self.issues.push(format!(
                "{} socket events lost ({}); uncertain owners withheld",
                batch.lost, loss_details
            ));
        }
        self.owners
            .update(batch.events, batch.lost, monotonic_ns(), inventory);
        if batch.lost > 0 {
            self.owners.describe_loss(loss_details);
        }
        if self.owners.suppressed() {
            self.issues.push(format!(
                "socket event evidence incomplete ({}); uncertain owners withheld",
                self.owners.suppression_reason().unwrap_or("unknown reason")
            ));
        }
    }

    fn refresh_conntrack(&mut self) {
        let Some(ct) = &self.conntrack else {
            return;
        };
        let view = ct.snapshot();
        if let Some(error) = view.error {
            self.issues.push(format!("conntrack: {error}"));
        } else if !view.ready {
            self.issues
                .push("conntrack: initial synchronization pending".into());
        }
        if view.lost > self.conntrack_lost {
            self.issues.push(format!(
                "conntrack: {} synchronization failures",
                view.lost - self.conntrack_lost
            ));
        }
        self.conntrack_lost = view.lost;
    }

    fn refresh_links(&mut self) {
        if self.links_at.elapsed() >= Duration::from_secs(2) {
            match links::veth_indexes() {
                Ok(v) => {
                    self.veth = v;
                    self.links_error = None;
                }
                Err(e) => {
                    self.veth.clear();
                    self.links_error = Some(format!("veth discovery: {e}"));
                }
            }
            self.links_at = Instant::now();
        }
        if let Some(error) = &self.links_error {
            self.issues.push(error.clone());
        }
    }

    pub fn resolve(
        &self,
        flow: &Flow,
        bytes: TimedBytes,
        inventory: &Inventory,
        view: &LocalView,
        allow_partial: bool,
    ) -> Result {
        let Some((source, destination)) = socket_endpoints(flow, false) else {
            return Result::Unknown;
        };
        let translation = self
            .conntrack
            .as_ref()
            .map(|c| c.snapshot().translate(flow.protocol, source, destination));
        self.resolve_with_translation(flow, bytes, inventory, view, allow_partial, translation)
    }

    fn resolve_with_translation(
        &self,
        flow: &Flow,
        bytes: TimedBytes,
        inventory: &Inventory,
        view: &LocalView,
        allow_partial: bool,
        translation: Option<conntrack::Outcome>,
    ) -> Result {
        let Some((source, destination)) = socket_endpoints(flow, false) else {
            return Result::Unknown;
        };
        if matches!(translation, Some(conntrack::Outcome::Ambiguous)) {
            return Result::Unknown;
        }
        let (sender, receiver) = match translation {
            // The sender owns the pre-NAT tuple, the receiver the translated one.
            Some(conntrack::Outcome::Translated(t)) => (
                (t.before.source, t.before.destination),
                (t.after.destination, t.after.source),
            ),
            _ => ((source, destination), (destination, source)),
        };
        // Without a current conntrack answer, raw endpoints might be the
        // pre-DNAT address of an unrelated local wildcard listener. A positive
        // socket event can stand on its own; sampled sockets cannot prove that
        // a packet was delivered before/after NAT.
        let sampled_endpoints_proven = matches!(
            translation,
            Some(conntrack::Outcome::Unchanged | conntrack::Outcome::Translated(_))
        );
        let host = inventory.host_namespace();
        let mut namespaces = self.owners.namespaces();
        namespaces.extend(inventory.namespaces().keys().copied());
        let mut results = Vec::new();
        let mut unresolved = Vec::new();
        let mut uncertain = false;
        for (receive, (local, remote)) in [(false, sender), (true, receiver)] {
            let candidates =
                self.candidate_namespaces(&namespaces, host, flow, local.ip(), inventory, view);
            if candidates.len() > 1 {
                // Ambiguity at one endpoint must not erase certain evidence
                // for the other endpoint. Only suppress the unknown copy from
                // All when every possible namespace identifies it as duplicate.
                let lower = candidates
                    .iter()
                    .all(|namespace| self.lower(*namespace, host, flow, local.ip(), view, receive));
                unresolved.push((receive, lower));
                continue;
            }
            let Some(namespace) = candidates.first().copied() else {
                continue;
            };
            let endpoint = Endpoint {
                namespace,
                local,
                remote,
                receive,
            };
            let owner = self.endpoint_owner(
                flow,
                bytes,
                inventory,
                view,
                &endpoint,
                sampled_endpoints_proven,
            );
            let lower = self.lower(namespace, host, flow, local.ip(), view, receive);
            match owner {
                EndpointOwner::Socket(socket, connection_known) => {
                    results.push((socket, receive, lower, connection_known));
                }
                EndpointOwner::Uncertain => {
                    uncertain = true;
                    unresolved.push((receive, lower));
                }
                EndpointOwner::Unattributed => unresolved.push((receive, lower)),
            }
        }
        if allow_partial
            && !unresolved.is_empty()
            && matches!(translation, Some(conntrack::Outcome::Missing))
        {
            self.unconfirmed.set(true);
        }
        conclude(results, unresolved, uncertain, allow_partial, translation)
    }

    /// Namespaces in which `local` is an address of this flow endpoint.
    fn candidate_namespaces(
        &self,
        namespaces: &HashSet<u64>,
        host: u64,
        flow: &Flow,
        local: IpAddr,
        inventory: &Inventory,
        view: &LocalView,
    ) -> Vec<u64> {
        namespaces
            .iter()
            .copied()
            .filter(|ns| {
                if *ns == host {
                    view.is_local(local)
                } else {
                    !loopback_path(flow, view)
                        && !local.is_loopback()
                        && (inventory
                            .namespaces()
                            .get(ns)
                            .is_some_and(|n| n.id == *ns && n.addresses.contains(&local))
                            || self.owners.has_address(*ns, local))
                }
            })
            .collect()
    }

    /// Socket events take precedence; sampled sockets can only corroborate
    /// them or stand in when events have no evidence and NAT is proven.
    fn endpoint_owner(
        &self,
        flow: &Flow,
        bytes: TimedBytes,
        inventory: &Inventory,
        view: &LocalView,
        endpoint: &Endpoint,
        sampled_endpoints_proven: bool,
    ) -> EndpointOwner {
        let &Endpoint {
            namespace,
            local,
            remote,
            receive,
        } = endpoint;
        match self
            .owners
            .resolve(namespace, flow.protocol, local, remote, receive, bytes)
        {
            // Existing shared/contradictory descriptor evidence vetoes a
            // single actor event, rather than silently choosing it.
            event_owners::Match::Owned(socket) if self.sampled_owners.vetoes(&socket) => {
                EndpointOwner::Unattributed
            }
            event_owners::Match::Owned(socket) => EndpointOwner::Socket(socket, true),
            event_owners::Match::Ambiguous => EndpointOwner::Uncertain,
            // Events identify one possible actor but do not cover this
            // packet's timestamp. Current descriptor evidence can corroborate
            // that exact still-open socket, never an unproven NAT endpoint.
            event_owners::Match::Observed(observed) => {
                match inventory.resolve_in(namespace, flow.protocol, local, remote) {
                    Resolution::Owned(socket)
                        if sampled_endpoints_proven
                            && self.sampled_owners.corroborates(socket, &observed) =>
                    {
                        EndpointOwner::Socket(socket.clone(), true)
                    }
                    _ => EndpointOwner::Uncertain,
                }
            }
            event_owners::Match::Missing if !sampled_endpoints_proven => EndpointOwner::Uncertain,
            event_owners::Match::Missing => {
                match inventory.resolve_in(namespace, flow.protocol, local, remote) {
                    Resolution::Owned(s) if !published_port_proxy(flow, s, view) => {
                        EndpointOwner::Socket(s.clone(), true)
                    }
                    Resolution::Process(s) if !published_port_proxy(flow, s, view) => {
                        EndpointOwner::Socket(s.clone(), false)
                    }
                    Resolution::Pending | Resolution::Missing => EndpointOwner::Uncertain,
                    _ => EndpointOwner::Unattributed,
                }
            }
        }
    }

    fn lower(
        &self,
        namespace: u64,
        host: u64,
        flow: &Flow,
        local: IpAddr,
        view: &LocalView,
        receive: bool,
    ) -> bool {
        if namespace == host {
            view.lower_observation(flow.interface_index, local)
        } else {
            !(self.veth.contains(&flow.interface_index)
                && matches!(
                    (receive, flow.direction),
                    (true, Direction::Outgoing) | (false, Direction::Incoming)
                ))
        }
    }
}

/// Without an endpoint verdict, uncertain or not yet synchronized NAT state
/// is worth a retry; otherwise the flow stays unknown.
fn conclude(
    results: Vec<(Socket, bool, bool, bool)>,
    unresolved: Vec<(bool, bool)>,
    uncertain: bool,
    allow_partial: bool,
    translation: Option<conntrack::Outcome>,
) -> Result {
    if uncertain && !allow_partial {
        Result::Pending
    } else if !results.is_empty() || !unresolved.is_empty() {
        Result::Owned(results, unresolved)
    } else if uncertain
        || matches!(
            translation,
            Some(conntrack::Outcome::Missing | conntrack::Outcome::Unavailable)
        )
    {
        Result::Pending
    } else {
        Result::Unknown
    }
}

/// The packet's own wire tuple, when the BPF program could read it.
fn packet_endpoints(packet: &PacketEvent) -> Option<(SocketAddr, SocketAddr)> {
    if packet.flags & 1 == 0 {
        return None;
    }
    let address = |bytes: [u8; 16], port| match packet.family as i32 {
        libc::AF_INET => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            port,
        )),
        libc::AF_INET6 => Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port)),
        _ => None,
    };
    address(packet.local_addr, packet.local_port)
        .zip(address(packet.remote_addr, packet.remote_port))
}

#[cfg(test)]
mod tests;
