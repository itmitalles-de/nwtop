//! Bounded host-namespace SOCK_DIAG queries and retry bookkeeping.

use super::{Protocol, SocketKey, canonical_ip};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

/// Budget for receiving one SOCK_DIAG dump, counted from after the request
/// was sent: the first query can autoload inet_diag/udp_diag synchronously
/// inside sendto().
pub(super) const DIAG_DEADLINE: Duration = Duration::from_millis(50);
/// Pause after a complete or rejected dump that lacked a socket.
const DIAG_RETRY: Duration = Duration::from_secs(2);
/// Incomplete dumps (deadline, interruption) are retried on the next refresh
/// this many times in a row before backing off like failed lookups.
const DIAG_PROMPT_RETRIES: u8 = 3;

/// The latest SOCK_DIAG lookup for one IPv6 wildcard socket that lacked it.
#[derive(Clone, Copy, Debug)]
pub(super) struct DiagAttempt {
    at: Instant,
    /// Incomplete dumps in a row; a complete answer sets the full backoff.
    incomplete: u8,
}

impl DiagAttempt {
    pub(super) fn due(&self, now: Instant) -> bool {
        self.incomplete < DIAG_PROMPT_RETRIES
            || now.saturating_duration_since(self.at) >= DIAG_RETRY
    }

    pub(super) fn next(previous: Option<&Self>, outcome: DiagOutcome, now: Instant) -> Self {
        Self {
            at: now,
            incomplete: match outcome {
                DiagOutcome::Incomplete => {
                    previous.map_or(0, |attempt| attempt.incomplete.min(DIAG_PROMPT_RETRIES)) + 1
                }
                DiagOutcome::Complete | DiagOutcome::Rejected => DIAG_PROMPT_RETRIES,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiagOutcome {
    /// The dump ended (NLMSG_DONE); an open socket missing from it stays
    /// unknown, retried after DIAG_RETRY.
    Complete,
    /// The kernel rejected the query, e.g. without udp_diag support.
    Rejected,
    /// Deadline, interruption or a malformed reply: retry promptly.
    Incomplete,
}

/// SOCK_DIAG exposes IPV6_V6ONLY without opening another process's descriptor.
/// Only wildcard IPv6 sockets need it; a denied/unsupported query leaves IPv4
/// attribution unknown. The kernel filters by state (listeners for TCP,
/// unconnected sockets for UDP), and both elapsed time and retained response
/// data are bounded. `budget` starts once the request is sent.
pub(super) fn read_ipv6_modes(
    protocol: Protocol,
    states: u32,
    wanted: &HashSet<SocketKey>,
    modes: &mut HashMap<SocketKey, bool>,
    budget: Duration,
) -> DiagOutcome {
    // The request/response layouts are Linux UAPI inet_diag_req_v2 and
    // inet_diag_msg. Integer headers are native endian; addresses/ports are not.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return DiagOutcome::Rejected;
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = [0_u8; 72];
    request[0..4].copy_from_slice(&72_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = libc::AF_INET6 as u8;
    request[17] = if protocol == Protocol::Tcp { 6 } else { 17 };
    request[20..24].copy_from_slice(&states.to_ne_bytes());
    request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = loop {
        let sent = unsafe {
            libc::sendto(
                descriptor.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break sent;
        }
    };
    if sent != request.len() as isize {
        return DiagOutcome::Rejected;
    }
    // The first query can autoload diag modules synchronously inside
    // sendto(), so the receive deadline only starts now.
    let deadline = Instant::now() + budget;
    let mut buffer = [0_u8; 65_536];
    while Instant::now() < deadline {
        let mut ready = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .max(1) as i32;
        match unsafe { libc::poll(&mut ready, 1, timeout) } {
            0 => return DiagOutcome::Incomplete,
            ready if ready < 0 => {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return DiagOutcome::Incomplete;
            }
            _ => {}
        }
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
        let length = unsafe {
            libc::recvfrom(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut sender_len,
            )
        };
        if length < 0 {
            let error = std::io::Error::last_os_error().kind();
            if matches!(
                error,
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return DiagOutcome::Incomplete;
        }
        if length == 0 || length as usize > buffer.len() || sender.nl_pid != 0 {
            return DiagOutcome::Incomplete;
        }
        if let Some(outcome) =
            parse_diag_datagram(&buffer[..length as usize], protocol, wanted, modes)
        {
            return outcome;
        }
    }
    DiagOutcome::Incomplete
}

/// Records the wanted sockets of one netlink datagram. `None` means the dump
/// continues in a later datagram.
fn parse_diag_datagram(
    mut messages: &[u8],
    protocol: Protocol,
    wanted: &HashSet<SocketKey>,
    modes: &mut HashMap<SocketKey, bool>,
) -> Option<DiagOutcome> {
    while messages.len() >= 16 {
        let length = u32::from_ne_bytes(messages[..4].try_into().unwrap()) as usize;
        if length < 16 || length > messages.len() {
            return Some(DiagOutcome::Incomplete);
        }
        let kind = u16::from_ne_bytes(messages[4..6].try_into().unwrap());
        let sequence = u32::from_ne_bytes(messages[8..12].try_into().unwrap());
        if sequence != 1 {
            return Some(DiagOutcome::Incomplete);
        }
        match kind {
            2 => return Some(DiagOutcome::Rejected), // NLMSG_ERROR
            3 => return Some(DiagOutcome::Complete), // NLMSG_DONE
            20 => {
                if let Some((mut key, only)) = parse_ipv6_mode(&messages[16..length], protocol) {
                    // This diagnostic socket queries the host namespace only.
                    // Raw parser keys are namespace-neutral until the request's
                    // identity is applied; wanted never mixes namespaces.
                    key.namespace = wanted.iter().next().map_or(0, |key| key.namespace);
                    if wanted.contains(&key) {
                        modes.insert(key, only);
                    }
                }
            }
            _ => {}
        }
        let aligned = (length + 3) & !3;
        messages = messages.get(aligned..).unwrap_or_default();
    }
    None
}

fn parse_ipv6_mode(message: &[u8], protocol: Protocol) -> Option<(SocketKey, bool)> {
    if message.len() < 72 || message[0] != libc::AF_INET6 as u8 {
        return None;
    }
    let key = SocketKey {
        namespace: 0,
        protocol,
        inode: u32::from_ne_bytes(message[68..72].try_into().ok()?) as u64,
        local: SocketAddr::new(
            canonical_ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&message[8..24]).ok()?,
            ))),
            u16::from_be_bytes(message[4..6].try_into().ok()?),
        ),
        remote: SocketAddr::new(
            canonical_ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&message[24..40]).ok()?,
            ))),
            u16::from_be_bytes(message[6..8].try_into().ok()?),
        ),
    };
    let mut attributes = &message[72..];
    while attributes.len() >= 4 {
        let length = u16::from_ne_bytes(attributes[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().ok()?);
        if length < 4 || length > attributes.len() {
            return None;
        }
        if kind == 11 && length == 5 {
            // INET_DIAG_SKV6ONLY
            return Some((key, attributes[4] != 0));
        }
        attributes = attributes.get(((length + 3) & !3)..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::Inventory;
    use super::*;

    #[test]
    fn incomplete_diag_dumps_retry_promptly_then_back_off() {
        let start = Instant::now();
        let mut attempt = None;
        for _ in 0..DIAG_PROMPT_RETRIES - 1 {
            let next = DiagAttempt::next(attempt.as_ref(), DiagOutcome::Incomplete, start);
            assert!(next.due(start), "a timed-out dump is retried next refresh");
            attempt = Some(next);
        }
        let exhausted = DiagAttempt::next(attempt.as_ref(), DiagOutcome::Incomplete, start);
        assert!(!exhausted.due(start + Duration::from_millis(250)));
        assert!(exhausted.due(start + DIAG_RETRY));
        for outcome in [DiagOutcome::Complete, DiagOutcome::Rejected] {
            let answered = DiagAttempt::next(None, outcome, start);
            assert!(!answered.due(start + Duration::from_millis(250)));
            assert!(answered.due(start + DIAG_RETRY));
        }
    }

    fn netlink_message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut message = Vec::new();
        message.extend_from_slice(&(length as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&0_u16.to_ne_bytes());
        message.extend_from_slice(&sequence.to_ne_bytes());
        message.extend_from_slice(&0_u32.to_ne_bytes());
        message.extend_from_slice(payload);
        message.resize((length + 3) & !3, 0);
        message
    }

    #[test]
    fn diag_dumps_distinguish_complete_rejected_and_partial_replies() {
        let mut socket = vec![0; 80];
        socket[0] = libc::AF_INET6 as u8;
        socket[4..6].copy_from_slice(&53000_u16.to_be_bytes());
        socket[68..72].copy_from_slice(&123_u32.to_ne_bytes());
        socket[72..74].copy_from_slice(&5_u16.to_ne_bytes());
        socket[74..76].copy_from_slice(&11_u16.to_ne_bytes());
        let wanted = HashSet::from([SocketKey {
            namespace: 0,
            inode: 123,
            protocol: Protocol::Udp,
            local: "[::]:53000".parse().unwrap(),
            remote: "[::]:0".parse().unwrap(),
        }]);
        let mut modes = HashMap::new();
        let partial = netlink_message(20, 1, &socket);
        assert_eq!(
            parse_diag_datagram(&partial, Protocol::Udp, &wanted, &mut modes),
            None,
            "the dump continues in the next datagram"
        );
        assert_eq!(modes.values().copied().collect::<Vec<_>>(), vec![false]);
        let mut done = partial.clone();
        done.extend(netlink_message(3, 1, &[0; 4]));
        assert_eq!(
            parse_diag_datagram(&done, Protocol::Udp, &wanted, &mut modes),
            Some(DiagOutcome::Complete)
        );
        assert_eq!(
            parse_diag_datagram(
                &netlink_message(2, 1, &[0; 20]),
                Protocol::Udp,
                &wanted,
                &mut modes
            ),
            Some(DiagOutcome::Rejected)
        );
        for broken in [netlink_message(20, 2, &socket), partial[..20].to_vec()] {
            assert_eq!(
                parse_diag_datagram(&broken, Protocol::Udp, &wanted, &mut modes),
                Some(DiagOutcome::Incomplete)
            );
        }
    }

    #[test]
    fn live_diag_query_finishes_within_its_budget() {
        let Ok(socket) = std::net::UdpSocket::bind("[::]:0") else {
            return; // No IPv6 in this environment.
        };
        let port = socket.local_addr().unwrap().port();
        let mut inventory = Inventory::new();
        inventory.refresh();
        let Some(key) = inventory
            .sockets
            .iter()
            .find(|socket| socket.current && socket.key.local.port() == port)
            .map(|socket| socket.key.clone())
        else {
            return;
        };
        let mut modes = HashMap::new();
        let outcome = read_ipv6_modes(
            Protocol::Udp,
            1 << 7,
            &HashSet::from([key.clone()]),
            &mut modes,
            Duration::from_secs(2),
        );
        // Some sandboxes deny SOCK_DIAG; a granted query must complete.
        assert_ne!(outcome, DiagOutcome::Incomplete);
        if outcome == DiagOutcome::Complete {
            assert!(modes.contains_key(&key));
        }
    }

    #[test]
    fn socket_diagnostics_validate_attribute_lengths_and_addresses() {
        let mut message = vec![0; 80];
        message[0] = libc::AF_INET6 as u8;
        message[4..6].copy_from_slice(&53000_u16.to_be_bytes());
        message[68..72].copy_from_slice(&123_u32.to_ne_bytes());
        message[72..74].copy_from_slice(&5_u16.to_ne_bytes());
        message[74..76].copy_from_slice(&11_u16.to_ne_bytes());
        let (socket, only) = parse_ipv6_mode(&message, Protocol::Udp).unwrap();
        assert_eq!(socket.local, "[::]:53000".parse().unwrap());
        assert_eq!(socket.inode, 123);
        assert!(!only);
        message[76] = 1;
        assert!(parse_ipv6_mode(&message, Protocol::Udp).unwrap().1);
        message[72..74].copy_from_slice(&3_u16.to_ne_bytes());
        assert!(parse_ipv6_mode(&message, Protocol::Udp).is_none());
        message[72..74].copy_from_slice(&100_u16.to_ne_bytes());
        assert!(parse_ipv6_mode(&message, Protocol::Udp).is_none());
        assert!(parse_ipv6_mode(&message[..40], Protocol::Udp).is_none());
    }
}
