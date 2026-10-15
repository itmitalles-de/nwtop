//! Linux socket tables and their visible inode owners. Socket queues are not rates.

#[path = "sockets/diagnostics.rs"]
mod diagnostics;
#[path = "sockets/procfs.rs"]
mod procfs;

use diagnostics::{DIAG_DEADLINE, DiagAttempt, read_ipv6_modes};
use procfs::{
    discover_namespaces, namespace_id, parse_socket, read_namespace_addresses, read_proc_bounded,
    sanitize_label, scan_owners, start_time, state_label,
};

use super::packet::Protocol;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_SOCKETS: usize = 32_768;
const MAX_NAMESPACES: usize = 128;
const MAX_PROC_FILE: usize = 4 * 1024 * 1024;
const MAX_PROC_BYTES: usize = 32 * 1024 * 1024;
const NAMESPACE_DISCOVERY_GAP: Duration = Duration::from_secs(2);
const MAX_PROCESSES: usize = 32_768;
const MAX_FD_LINKS: usize = 262_144;
const RETAIN_CLOSED: Duration = Duration::from_secs(3);
/// Socket tables are reread at most this often, below the collector's
/// background attribution cadence.
const MIN_REFRESH: Duration = Duration::from_millis(200);
const MIN_OWNER_SCAN_GAP: Duration = Duration::from_millis(200);
const FULL_OWNER_RESCAN: Duration = Duration::from_secs(5);
const OWNER_CHECK: Duration = Duration::from_secs(1);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Owner {
    pub identity: ProcessIdentity,
    pub user: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct SocketKey {
    /// Network namespace inode, as exposed by /proc/PID/ns/net.
    pub namespace: u64,
    pub inode: u64,
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Debug)]
pub(super) struct Socket {
    pub key: SocketKey,
    pub state: String,
    pub uid: u32,
    pub owners: Vec<Owner>,
    pub observed: Instant,
    pub current: bool,
    // /proc/net/{tcp,udp}6 omits this per-socket option. Unknown is deliberately
    // not treated as dual stack: an IPv6-only listener cannot own IPv4 traffic.
    pub ipv6_only: Option<bool>,
}

impl Socket {
    pub(super) fn owner(&self) -> Option<&Owner> {
        if self.owners.len() == 1 {
            self.owners.first()
        } else {
            None
        }
    }
}

/// Outcome of matching one flow endpoint against the socket inventory.
pub(super) enum Resolution<'a> {
    /// Exactly one best socket with a single owning process.
    Owned(&'a Socket),
    /// Several equally good sockets (SO_REUSEPORT) of one process; the
    /// socket is a representative only, the process is certain.
    Process(&'a Socket),
    /// The best socket is new and its owner has not been scanned yet, or the
    /// only candidate is an IPv6 wildcard whose V6ONLY mode is still unknown.
    Pending,
    /// No listed socket matches this endpoint.
    Missing,
    /// An ambiguous, or a shared/ownerless match.
    Unattributed,
}

/// A visible namespace and addresses verified from its kernel routing tables.
#[derive(Clone, Debug)]
pub(super) struct Namespace {
    pub id: u64,
    pub representative_pid: u32,
    pub addresses: HashSet<IpAddr>,
}

type ExactKey = (u64, Protocol, SocketAddr, SocketAddr);

pub(super) struct Inventory {
    host_namespace: u64,
    namespace_discovery: bool,
    namespaces: HashMap<u64, Namespace>,
    last_namespace_discovery: Option<Instant>,
    namespace_flags: (bool, bool),
    pub sockets: Vec<Socket>,
    pub users: HashMap<u32, String>,
    /// Some socket tables or process descriptors were inaccessible during the
    /// latest table refresh or owner scan (not "ever since startup").
    pub restricted: bool,
    /// A socket, process or descriptor bound was hit during the latest table
    /// refresh or owner scan.
    pub limited: bool,
    /// Connected sockets by their full endpoint pair: one lookup per flow
    /// instead of scanning every connection sharing a busy local port.
    exact: HashMap<ExactKey, Vec<usize>>,
    /// Listeners, unconnected and wildcard sockets by local port.
    by_port: HashMap<(u64, Protocol, u16), Vec<usize>>,
    owners: HashMap<u64, Vec<Owner>>,
    owner_keys: HashMap<u64, SocketKey>,
    owner_flags: (bool, bool),
    owners_stale: bool,
    /// Inodes whose previous owner the latest scan kept although no
    /// descriptor was found; a second miss drops it.
    carried_owners: HashSet<u64>,
    owner_scan_cost: Duration,
    ipv6_modes: HashMap<SocketKey, bool>,
    ipv6_attempts: HashMap<SocketKey, DiagAttempt>,
    last_scan: Option<Instant>,
    last_owner_scan: Option<Instant>,
    last_owner_check: Option<Instant>,
}

impl Inventory {
    pub(super) fn new() -> Self {
        let users = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                Some((
                    fields.get(2)?.parse().ok()?,
                    sanitize_label(fields.first()?),
                ))
            })
            .collect();
        let host_namespace = namespace_id(std::process::id()).unwrap_or(0);
        Self {
            host_namespace,
            namespace_discovery: false,
            namespaces: HashMap::from([(
                host_namespace,
                Namespace {
                    id: host_namespace,
                    representative_pid: std::process::id(),
                    addresses: HashSet::new(),
                },
            )]),
            last_namespace_discovery: None,
            namespace_flags: (false, false),
            sockets: Vec::new(),
            users,
            restricted: false,
            limited: false,
            exact: HashMap::new(),
            by_port: HashMap::new(),
            owners: HashMap::new(),
            owner_keys: HashMap::new(),
            owner_flags: (false, false),
            owners_stale: false,
            carried_owners: HashSet::new(),
            owner_scan_cost: Duration::ZERO,
            ipv6_modes: HashMap::new(),
            ipv6_attempts: HashMap::new(),
            last_scan: None,
            last_owner_scan: None,
            last_owner_check: None,
        }
    }

    pub(super) fn refresh(&mut self) {
        let now = Instant::now();
        if self
            .last_scan
            .is_some_and(|last| now.duration_since(last) < MIN_REFRESH)
        {
            return;
        }
        if self.namespace_discovery
            && self
                .last_namespace_discovery
                .is_none_or(|last| now.saturating_duration_since(last) >= NAMESPACE_DISCOVERY_GAP)
        {
            let (discovered, restricted, limited) = discover_namespaces(self.host_namespace);
            self.namespaces = discovered;
            self.namespace_flags = (restricted, limited);
            self.last_namespace_discovery = Some(now);
        }
        let (mut restricted, mut limited) = self.namespace_flags;
        let mut current = Vec::new();
        let mut budget = MAX_PROC_BYTES;
        // Always read the host first so many containers cannot crowd it out.
        let mut ids: Vec<_> = self.namespaces.keys().copied().collect();
        ids.sort_unstable_by_key(|id| (*id != self.host_namespace, *id));
        for id in ids {
            let namespace = self
                .namespaces
                .get_mut(&id)
                .expect("namespace collected above");
            let pid = namespace.representative_pid;
            if namespace_id(pid).ok() != Some(id) || id == 0 {
                namespace.addresses.clear();
                restricted = true;
                continue;
            }
            let first = current.len();
            let root = format!("/proc/{pid}/net");
            for (file, protocol, ipv6) in [
                ("tcp", Protocol::Tcp, false),
                ("tcp6", Protocol::Tcp, true),
                ("udp", Protocol::Udp, false),
                ("udp6", Protocol::Udp, true),
            ] {
                let Some(contents) = read_proc_bounded(
                    Path::new(&format!("{root}/{file}")),
                    &mut budget,
                    &mut restricted,
                    &mut limited,
                ) else {
                    continue;
                };
                for line in contents.lines().skip(1) {
                    if current.len() >= MAX_SOCKETS {
                        limited = true;
                        break;
                    }
                    if let Some(socket) = parse_socket(line, protocol, ipv6, now, id) {
                        current.push(socket);
                    }
                }
            }
            if self.namespace_discovery {
                namespace.addresses = read_namespace_addresses(
                    Path::new(&root),
                    &mut budget,
                    &mut restricted,
                    &mut limited,
                );
            }
            // A process may exit, be reused, or change namespace while the files
            // are read. Never publish a table under the wrong namespace identity.
            if namespace_id(pid).ok() != Some(id) {
                current.truncate(first);
                namespace.addresses.clear();
                restricted = true;
            }
        }
        self.refresh_owners(&current, now);
        for socket in &mut current {
            // An inode reused for a different endpoint must not inherit stale
            // cached ownership before the next bounded descriptor scan.
            if self.owner_keys.get(&socket.key.inode) == Some(&socket.key) {
                socket.owners = self
                    .owners
                    .get(&socket.key.inode)
                    .cloned()
                    .unwrap_or_default();
            }
        }
        self.refresh_ipv6_modes(&current, now);
        for socket in &mut current {
            socket.ipv6_only = self.ipv6_modes.get(&socket.key).copied();
        }
        let live_keys: HashSet<_> = current.iter().map(|socket| socket.key.clone()).collect();
        for mut socket in self.sockets.drain(..) {
            if current.len() >= MAX_SOCKETS {
                limited = true;
                break;
            }
            if !live_keys.contains(&socket.key)
                && now.duration_since(socket.observed) <= RETAIN_CLOSED
            {
                socket.current = false;
                current.push(socket);
            }
        }
        self.sockets = current;
        self.rebuild_index();
        let (owner_restricted, owner_limited) = self.owner_flags;
        self.restricted = restricted || owner_restricted;
        self.limited = limited || owner_limited;
        self.last_scan = Some(now);
    }

    pub(super) fn host_namespace(&self) -> u64 {
        self.host_namespace
    }

    pub(super) fn namespaces(&self) -> &HashMap<u64, Namespace> {
        &self.namespaces
    }

    /// Namespace discovery is deliberately opt-in; the standard sampling path
    /// continues to inspect only its own network namespace.
    pub(super) fn set_namespace_discovery(&mut self, enabled: bool) {
        if self.namespace_discovery == enabled {
            return;
        }
        self.namespace_discovery = enabled;
        self.last_namespace_discovery = None;
        self.last_scan = None;
        if !enabled {
            self.namespaces.retain(|id, _| *id == self.host_namespace);
            self.sockets
                .retain(|socket| socket.key.namespace == self.host_namespace);
            self.namespace_flags = (false, false);
            self.rebuild_index();
        }
    }

    /// Descriptor scans are the expensive part. Scan promptly when sockets
    /// without a scanned owner appear or a cached owner exited, but never more
    /// often than a gap proportional to the previous scan's cost; otherwise
    /// rescan only periodically to notice inherited or passed descriptors.
    fn refresh_owners(&mut self, current: &[Socket], now: Instant) {
        if self
            .last_owner_check
            .is_none_or(|last| now.saturating_duration_since(last) >= OWNER_CHECK)
        {
            // Cheap PID-reuse protection between full scans: drop owners whose
            // process exited or whose PID now belongs to another process.
            self.owners_stale |= remove_exited_owners(&mut self.owners);
            self.last_owner_check = Some(now);
        }
        let unscanned = current.iter().any(|socket| {
            socket.key.inode != 0 && self.owner_keys.get(&socket.key.inode) != Some(&socket.key)
        });
        let gap = self.owner_scan_gap();
        let due = self.last_owner_scan.is_none_or(|last| {
            let since = now.saturating_duration_since(last);
            since >= FULL_OWNER_RESCAN || ((unscanned || self.owners_stale) && since >= gap)
        });
        if !due {
            return;
        }
        let live_inodes: HashSet<_> = current
            .iter()
            .map(|socket| socket.key.inode)
            .filter(|inode| *inode != 0)
            .collect();
        let started = Instant::now();
        let (mut owners, restricted, limited) = scan_owners(&live_inodes, &self.users);
        self.owner_scan_cost = started.elapsed();
        self.carried_owners = carry_closing_owners(
            current,
            &mut owners,
            &self.owners,
            &self.owner_keys,
            &self.carried_owners,
        );
        self.owners = owners;
        self.owner_keys = current
            .iter()
            .filter(|socket| socket.key.inode != 0)
            .map(|socket| (socket.key.inode, socket.key.clone()))
            .collect();
        self.owner_flags = (restricted, limited);
        self.owners_stale = false;
        self.last_owner_scan = Some(now);
        self.last_owner_check = Some(now);
    }

    /// Minimum spacing of prompt owner scans: ten times the previous scan's
    /// cost, so scans use at most about a tenth of one CPU.
    pub(super) fn owner_scan_gap(&self) -> Duration {
        (self.owner_scan_cost * 10).clamp(MIN_OWNER_SCAN_GAP, FULL_OWNER_RESCAN)
    }

    /// When the socket tables were last reread, if ever.
    pub(super) fn refreshed_at(&self) -> Option<Instant> {
        self.last_scan
    }

    #[cfg(test)]
    pub(super) fn set_refreshed_at(&mut self, at: Option<Instant>) {
        self.last_scan = at;
    }

    /// IPV6_V6ONLY cannot change after bind, so results are cached per socket
    /// incarnation and only new wildcard sockets are queried. Sockets missing
    /// from a complete answer are retried after a pause instead of on every
    /// refresh; an incomplete dump is retried promptly a few times.
    fn refresh_ipv6_modes(&mut self, current: &[Socket], now: Instant) {
        let wanted: HashMap<&SocketKey, u32> = current
            .iter()
            .filter(|socket| {
                socket.key.namespace == self.host_namespace
                    && socket.key.local.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            })
            .map(|socket| (&socket.key, state_mask(&socket.state, socket.key.protocol)))
            .collect();
        self.ipv6_modes.retain(|key, _| wanted.contains_key(key));
        self.ipv6_attempts.retain(|key, _| wanted.contains_key(key));
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut states = 0;
            let mut missing = HashSet::new();
            for (&key, &mask) in &wanted {
                if key.protocol == protocol
                    && !self.ipv6_modes.contains_key(key)
                    && self
                        .ipv6_attempts
                        .get(key)
                        .is_none_or(|attempt| attempt.due(now))
                {
                    missing.insert(key.clone());
                    states |= mask;
                }
            }
            if missing.is_empty() {
                continue;
            }
            // Each protocol has its own deadline; a slow TCP dump cannot starve UDP.
            let outcome = read_ipv6_modes(
                protocol,
                states,
                &missing,
                &mut self.ipv6_modes,
                DIAG_DEADLINE,
            );
            for key in missing {
                if self.ipv6_modes.contains_key(&key) {
                    self.ipv6_attempts.remove(&key);
                } else {
                    let attempt = DiagAttempt::next(self.ipv6_attempts.get(&key), outcome, now);
                    self.ipv6_attempts.insert(key, attempt);
                }
            }
        }
    }

    pub(super) fn rebuild_index(&mut self) {
        self.exact.clear();
        self.by_port.clear();
        for (index, socket) in self.sockets.iter().enumerate() {
            let key = &socket.key;
            if !key.local.ip().is_unspecified() && !key.remote.ip().is_unspecified() {
                self.exact
                    .entry((key.namespace, key.protocol, key.local, key.remote))
                    .or_default()
                    .push(index);
            } else {
                self.by_port
                    .entry((key.namespace, key.protocol, key.local.port()))
                    .or_default()
                    .push(index);
            }
        }
    }

    /// Exact connected sockets outrank listeners. Tied inodes or shared owners
    /// remain unassigned instead of choosing an arbitrary PID.
    pub(super) fn resolve(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Resolution<'_> {
        self.resolve_in(self.host_namespace, protocol, local, remote)
    }

    /// The caller must establish that this endpoint belongs to this namespace
    /// before trying wildcard listeners (e.g. verified addresses or kernel events).
    pub(super) fn resolve_in(
        &self,
        namespace: u64,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Resolution<'_> {
        let exact = self
            .exact
            .get(&(namespace, protocol, local, remote))
            .map_or(&[][..], Vec::as_slice);
        let wildcard = self
            .by_port
            .get(&(namespace, protocol, local.port()))
            .map_or(&[][..], Vec::as_slice);
        // After a local close the kernel keeps the same endpoint pair without
        // an inode (FIN-WAIT, TIME-WAIT, LAST-ACK). That remnant continues the
        // retained socket; it is not a competing incarnation.
        let continued = exact.iter().any(|&index| {
            let socket = &self.sockets[index];
            !socket.current && socket.key.inode != 0
        });
        // A connection waiting in the accept queue is listed without an inode
        // until accept() gives it one. The vanished queue entry is that same
        // connection, not a competing incarnation of the later inode socket.
        let accepted_since = exact
            .iter()
            .map(|&index| &self.sockets[index])
            .filter(|socket| socket.key.inode != 0)
            .map(|socket| socket.observed)
            .max();
        let mut best = None;
        let mut best_score = 0;
        let mut tied: Vec<&Socket> = Vec::new();
        let mut matching_incarnations = 0;
        let mut retained_match = false;
        let mut unknown_mode = false;
        let candidates = exact
            .iter()
            .map(|&index| (index, true))
            .chain(wildcard.iter().map(|&index| (index, false)));
        let mut exact_match = false;
        for (index, is_exact) in candidates {
            let socket = &self.sockets[index];
            if is_exact && continued && closing_remnant(socket) {
                continue;
            }
            if is_exact && accepted_since.is_some_and(|seen| accepted_queue_entry(socket, seen)) {
                continue;
            }
            // Segments of an existing TCP connection never reach a listener on
            // the same port (they go to the connection or its TIME-WAIT
            // remnant), so a listener is no competing incarnation for them.
            if exact_match && protocol == Protocol::Tcp && socket.state == "LISTEN" {
                continue;
            }
            let Some(score) = match_score(socket, local, remote) else {
                unknown_mode |= socket.current && unknown_ipv6_mode(socket, local, remote);
                continue;
            };
            exact_match |= is_exact;
            matching_incarnations += 1;
            retained_match |= !socket.current;
            if score > best_score {
                best = Some(socket);
                best_score = score;
                tied.clear();
            } else if score == best_score
                && best.is_some_and(|other: &Socket| other.key != socket.key)
            {
                tied.push(socket);
            }
        }
        // A batch can straddle a close/rebind. Prefer neither incarnation when
        // both match, even after both have closed: a retained connected socket
        // must not steal a later wildcard socket's packets, or vice versa.
        if retained_match && matching_incarnations > 1 {
            return Resolution::Unattributed;
        }
        let Some(best) = best else {
            // An IPv4 packet and a dual-stack-capable IPv6 wildcard whose
            // V6ONLY lookup is still outstanding: wait instead of losing it.
            return if unknown_mode {
                Resolution::Pending
            } else {
                Resolution::Missing
            };
        };
        if !tied.is_empty() {
            // SO_REUSEPORT groups and similar ties: credit the process when
            // every tied socket belongs to the same single owner.
            let identity = best.owner().map(|owner| owner.identity);
            let pending = std::iter::once(best)
                .chain(tied.iter().copied())
                .any(|socket| self.awaiting_owner(socket));
            return if pending {
                Resolution::Pending
            } else if identity.is_some()
                && tied
                    .iter()
                    .all(|socket| socket.owner().map(|owner| owner.identity) == identity)
            {
                Resolution::Process(best)
            } else {
                Resolution::Unattributed
            };
        }
        if best.owner().is_some() {
            Resolution::Owned(best)
        } else if self.awaiting_owner(best) {
            Resolution::Pending
        } else {
            Resolution::Unattributed
        }
    }

    /// A live socket whose inode has not been part of a descriptor scan yet.
    fn awaiting_owner(&self, socket: &Socket) -> bool {
        socket.current
            && socket.key.inode != 0
            && socket.owners.is_empty()
            && self.owner_keys.get(&socket.key.inode) != Some(&socket.key)
    }

    pub(super) fn user(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}

/// The socket tables are read before descriptors are scanned. A process that
/// closes a socket in between leaves it listed but without a visible owner,
/// although that owner sent and received the bytes still awaiting attribution
/// in this pass. Keep the owner from the previous scan of the same socket
/// incarnation for one scan; the closed socket then leaves the table, or a
/// second scan without any owner drops it. Returns the carried inodes.
fn carry_closing_owners(
    current: &[Socket],
    owners: &mut HashMap<u64, Vec<Owner>>,
    previous: &HashMap<u64, Vec<Owner>>,
    previous_keys: &HashMap<u64, SocketKey>,
    previously_carried: &HashSet<u64>,
) -> HashSet<u64> {
    let mut carried = HashSet::new();
    for socket in current {
        let inode = socket.key.inode;
        if inode == 0
            || owners.contains_key(&inode)
            || previously_carried.contains(&inode)
            || previous_keys.get(&inode) != Some(&socket.key)
        {
            continue;
        }
        if let Some(known) = previous.get(&inode).filter(|known| !known.is_empty()) {
            owners.insert(inode, known.clone());
            carried.insert(inode);
        }
    }
    carried
}

/// A retained, inode-less TCP entry superseded by a socket of the same
/// endpoint pair that was still listed afterwards.
fn accepted_queue_entry(socket: &Socket, accepted_seen: Instant) -> bool {
    socket.key.protocol == Protocol::Tcp
        && !socket.current
        && socket.key.inode == 0
        && socket.owners.is_empty()
        && socket.observed < accepted_seen
}

fn closing_remnant(socket: &Socket) -> bool {
    socket.current
        && socket.key.inode == 0
        && socket.owners.is_empty()
        && matches!(
            socket.state.as_str(),
            "FIN-WAIT-1" | "FIN-WAIT-2" | "TIME-WAIT" | "CLOSE" | "LAST-ACK" | "CLOSING"
        )
}

fn remove_exited_owners(owners: &mut HashMap<u64, Vec<Owner>>) -> bool {
    let identities: HashSet<ProcessIdentity> = owners
        .values()
        .flatten()
        .map(|owner| owner.identity)
        .collect();
    let exited: HashSet<_> = identities
        .into_iter()
        .filter(|identity| {
            fs::read_to_string(format!("/proc/{}/stat", identity.pid))
                .ok()
                .and_then(|stat| start_time(&stat))
                != Some(identity.start_time)
        })
        .collect();
    if exited.is_empty() {
        return false;
    }
    for entries in owners.values_mut() {
        entries.retain(|owner| !exited.contains(&owner.identity));
    }
    true
}

/// SOCK_DIAG state bit for a socket table state label.
fn state_mask(label: &str, protocol: Protocol) -> u32 {
    let state = if protocol == Protocol::Udp {
        // Unconnected UDP sockets are TCP_CLOSE; connected ones TCP_ESTABLISHED.
        if label == "CONNECTED" { 1 } else { 7 }
    } else {
        (1..=12)
            .find(|state| state_label(*state, protocol) == label)
            .unwrap_or(10)
    };
    1 << state
}

fn match_score(socket: &Socket, local: SocketAddr, remote: SocketAddr) -> Option<u8> {
    endpoint_score(&socket.key, socket.ipv6_only, local, remote)
}

fn endpoint_score(
    key: &SocketKey,
    ipv6_only: Option<bool>,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u8> {
    if key.local.port() != local.port() {
        return None;
    }
    let local_ip = canonical_ip(key.local.ip());
    let packet_local = canonical_ip(local.ip());
    let local_score = if local_ip == packet_local {
        2
    } else if local_ip.is_unspecified()
        && (local_ip.is_ipv4() == packet_local.is_ipv4()
            || (local_ip.is_ipv6() && ipv6_only == Some(false)))
    {
        1
    } else {
        return None;
    };
    let remote_ip = canonical_ip(key.remote.ip());
    let packet_remote = canonical_ip(remote.ip());
    if remote_ip.is_unspecified() && key.remote.port() == 0 {
        Some(local_score)
    } else if remote_ip == packet_remote && key.remote.port() == remote.port() {
        Some(local_score + 4)
    } else {
        None
    }
}

/// An IPv4 packet that an IPv6 wildcard socket would own if it is dual
/// stack, while its V6ONLY mode is not known yet.
fn unknown_ipv6_mode(socket: &Socket, local: SocketAddr, remote: SocketAddr) -> bool {
    socket.ipv6_only.is_none()
        && socket.key.local.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        && canonical_ip(local.ip()).is_ipv4()
        && endpoint_score(&socket.key, Some(false), local, remote).is_some()
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[cfg(test)]
#[path = "sockets/tests.rs"]
mod tests;
