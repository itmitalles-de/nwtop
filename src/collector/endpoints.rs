//! Which endpoints of a captured flow are local, and on which link.
use super::KernelInterface;
use super::packet::{Direction, Flow};
use super::sockets::{Socket, canonical_ip};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

/// Host addresses and link relations, built once per attribution pass so
/// per-flow checks are set lookups rather than scans of every interface.
#[derive(Default)]
pub(super) struct LocalView {
    pub(super) addresses: HashSet<IpAddr>,
    pub(super) loopback: HashSet<u32>,
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
    pub(super) fn new(interfaces: &[KernelInterface]) -> Self {
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

    pub(super) fn is_local(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        (!self.loopback.is_empty() && ip.is_loopback()) || self.addresses.contains(&ip)
    }

    /// Host traffic for `local` seen on link `index` that its upper device
    /// also captures, so all-interface totals would count it twice.
    pub(super) fn lower_observation(&self, index: u32, local: IpAddr) -> bool {
        let local = canonical_ip(local);
        self.lower.get(&index).is_some_and(|link| {
            link.enslaved || (link.upper.contains(&local) && !link.own.contains(&local))
        })
    }
}

/// Traffic between two local endpoints, observed once on a loopback link.
pub(super) fn loopback_path(flow: &Flow, view: &LocalView) -> bool {
    view.loopback.contains(&flow.interface_index)
        || (flow.interface_index == 0
            && view.is_local(flow.source)
            && view.is_local(flow.destination))
}

pub(super) fn traffic_sides(flow: &Flow, view: &LocalView) -> (bool, bool) {
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

pub(super) fn socket_endpoints(flow: &Flow, receive: bool) -> Option<(SocketAddr, SocketAddr)> {
    let source = SocketAddr::new(canonical_ip(flow.source), flow.source_port?);
    let destination = SocketAddr::new(canonical_ip(flow.destination), flow.destination_port?);
    Some(if receive {
        (destination, source)
    } else {
        (source, destination)
    })
}

pub(super) fn local_socket_endpoints(
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
pub(super) fn published_port_proxy(flow: &Flow, socket: &Socket, view: &LocalView) -> bool {
    let remote = socket.key.remote;
    remote.ip().is_unspecified()
        && remote.port() == 0
        && socket
            .owner()
            .is_some_and(|owner| owner.name == "docker-proxy")
        && !loopback_path(flow, view)
}
