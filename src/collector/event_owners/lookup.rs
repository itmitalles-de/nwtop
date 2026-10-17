//! Packet and flow queries against the indexed socket event evidence.
use super::{
    BOTH, IPPROTO_TCP, IPPROTO_UDP, Key, MAX_CANDIDATES, Match, Owners, RETAIN, RX, Record, SLOP,
    TX, Window,
};
use crate::collector::{
    capture::TimedBytes, events::PacketEvent, packet::Protocol, sockets::canonical_ip,
};
use std::net::SocketAddr;

impl Owners {
    /// The kernel supplied the actual socket incarnation, so a distinct
    /// SO_REUSEPORT socket or pre-DNAT listener cannot compete for this packet.
    /// Shared actors on this very socket still veto ownership. An open actor
    /// outside its syscall needs exact current descriptor corroboration by the
    /// caller (Observed); positive socket identity is not a process identity.
    pub fn resolve_packet(&self, packet: &PacketEvent) -> Match {
        if !self.packet_trusted(packet) {
            return Match::Ambiguous;
        }
        let id = (u64::from(packet.netns), packet.socket_id);
        let Some(keys) = self.socket_records.get(&id) else {
            return Match::Missing;
        };
        let Some(keys) = keys else {
            return Match::Ambiguous;
        };
        let protocol = match packet.protocol {
            IPPROTO_TCP => Protocol::Tcp,
            IPPROTO_UDP => Protocol::Udp,
            _ => return Match::Missing,
        };
        let mut selection = Selection::default();
        let bit = if packet.receive == 1 { RX } else { TX };
        for key in keys {
            let record = &self.records[key];
            if key.protocol != protocol
                || (packet.inode != 0
                    && record.socket.key.inode != 0
                    && packet.inode != record.socket.key.inode)
                || record.closed_conflict
                || !selection.agrees(key, record)
            {
                return Match::Ambiguous;
            }
            selection.contained |= record.covers(packet.timestamp_ns, bit);
        }
        // Packets outside a closed socket's observed windows stay uncertain.
        let closed = selection
            .candidate
            .is_some_and(|(_, record)| record.closed.is_some());
        selection.verdict(closed)
    }

    /// A well-formed, retained packet of a socket incarnation without
    /// conflicting actors that had not closed before it.
    fn packet_trusted(&self, packet: &PacketEvent) -> bool {
        if packet.socket_id == 0
            || packet.netns == 0
            || packet.ip_bytes == 0
            || packet.timestamp_ns <= self.unsafe_until
            || packet.receive > 1
            || packet.reserved != 0
            || packet.flags & !3 != 0
            || self.updated_at.saturating_sub(packet.timestamp_ns) > RETAIN
        {
            return false;
        }
        let id = (u64::from(packet.netns), packet.socket_id);
        !(self
            .lifetimes
            .get(&id)
            .is_some_and(|lifetime| lifetime.conflict)
            || self
                .closed
                .get(&id)
                .is_some_and(|closed| packet.timestamp_ns > *closed))
    }

    pub fn resolve(
        &self,
        namespace: u64,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
        receive: bool,
        window: TimedBytes,
    ) -> Match {
        if window.bytes == 0
            || window.first == 0
            || window.last < window.first
            || window.first <= self.unsafe_until
        {
            return Match::Ambiguous;
        }
        let local = SocketAddr::new(canonical_ip(local.ip()), local.port());
        let remote = SocketAddr::new(canonical_ip(remote.ip()), remote.port());
        let Some(candidates) = self
            .tuples
            .get(&(namespace, protocol, local.port(), remote))
        else {
            return Match::Missing;
        };
        let Some(candidates) = candidates else {
            return Match::Ambiguous;
        };
        let mut selection = Selection::default();
        let mut veto_observed = false;
        let mut examined = 0;
        let bit = if receive { RX } else { TX };
        for key in candidates {
            if !key.local.ip().is_unspecified() && key.local.ip() != local.ip() {
                continue;
            }
            let record = &self.records[key];
            let lifetime_receive_conflict = receive
                && protocol == Protocol::Udp
                && self.competing_udp_binding(key, record, local, window);
            let lifetime = record.lifetime.map(|mut observed| {
                if lifetime_receive_conflict {
                    observed.directions = 0;
                }
                observed
            });
            for direction in 0..=BOTH {
                // Windows are sorted and coalesced independently by direction.
                // Binary search avoids rescanning a busy socket's full history
                // for every captured packet; suspiciously dense matches stop.
                let windows = overlapping(record.windows_with(direction), window);
                let lifetime = lifetime.filter(|observed| observed.directions == direction);
                examined += windows.len() + usize::from(lifetime.is_some());
                if examined > MAX_CANDIDATES {
                    return Match::Ambiguous;
                }
                for observed in windows.iter().chain(lifetime.iter()) {
                    let end = record.closed.unwrap_or(observed.last).min(observed.last);
                    // Clock uncertainty widens conflicts, never positive evidence.
                    if observed.first > end
                        || window.last.saturating_add(SLOP) < observed.first
                        || window.first > end.saturating_add(SLOP)
                    {
                        continue;
                    }
                    if record.closed_conflict {
                        return Match::Ambiguous;
                    }
                    veto_observed |= lifetime_receive_conflict || record.closed.is_some();
                    if !selection.agrees(key, record) {
                        return Match::Ambiguous;
                    }
                    selection.contained |= window.first >= observed.first
                        && window.last <= end
                        && observed.directions & bit != 0;
                }
            }
        }
        selection.verdict(veto_observed)
    }

    fn competing_udp_binding(
        &self,
        key: &Key,
        record: &Record,
        local: SocketAddr,
        window: TimedBytes,
    ) -> bool {
        if self.bindings_limited {
            return true;
        }
        let Some(candidates) = self.bindings.get(&(key.namespace, local.port())) else {
            return false;
        };
        let Some(candidates) = candidates else {
            return true;
        };
        candidates.iter().any(|binding| {
            binding.socket != Some(key.socket)
                && !(binding.inode != 0 && binding.inode == record.socket.key.inode)
                && (binding.local.ip().is_unspecified() || binding.local.ip() == local.ip())
                && window.last.saturating_add(SLOP) >= binding.first
                && window.first <= binding.last.saturating_add(SLOP)
        })
    }
}

impl Record {
    /// The windows of exactly these direction bits, ordered by time.
    fn windows_with(&self, directions: u8) -> &[Window] {
        let from = self
            .windows
            .partition_point(|observed| observed.directions < directions);
        let to = self
            .windows
            .partition_point(|observed| observed.directions <= directions);
        &self.windows[from..to]
    }

    /// Evidence for direction `bit` covers the instant `at`.
    fn covers(&self, at: u64, bit: u8) -> bool {
        self.lifetime
            .is_some_and(|life| life.first <= at && at <= life.last && life.directions & bit != 0)
            || [bit, BOTH].into_iter().any(|direction| {
                let windows = self.windows_with(direction);
                windows
                    .get(windows.partition_point(|w| w.last < at))
                    .is_some_and(|w| w.first <= at && at <= w.last)
            })
    }
}

/// The one actor all matching evidence must agree on.
#[derive(Default)]
struct Selection<'a> {
    candidate: Option<(&'a Key, &'a Record)>,
    contained: bool,
}

impl<'a> Selection<'a> {
    /// Selects the first actor; false once evidence names a different socket,
    /// process or process incarnation.
    fn agrees(&mut self, key: &'a Key, record: &'a Record) -> bool {
        match self.candidate {
            Some((previous, _)) => {
                previous.owner == key.owner
                    && previous.socket == key.socket
                    && previous.process_started_ns == key.process_started_ns
            }
            None => {
                self.candidate = Some((key, record));
                true
            }
        }
    }

    fn verdict(self, veto_observed: bool) -> Match {
        match self.candidate {
            Some((_, record)) if self.contained => Match::Owned(record.socket.clone()),
            Some((_, record)) if !veto_observed => Match::Observed(record.socket.clone()),
            Some(_) => Match::Ambiguous,
            None => Match::Missing,
        }
    }
}

/// The time-ordered windows that may overlap `window` within clock slop.
fn overlapping(windows: &[Window], window: TimedBytes) -> &[Window] {
    let from =
        windows.partition_point(|observed| observed.last.saturating_add(SLOP) < window.first);
    let to = windows.partition_point(|observed| observed.first <= window.last.saturating_add(SLOP));
    &windows[from..to.max(from)]
}
