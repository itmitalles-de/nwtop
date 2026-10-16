//! Read-only, bounded conntrack metadata. Packet bytes still come from pcap.
//!
//! This worker alone retains NET_ADMIN. It subscribes before the initial dump,
//! queues concurrent events during dumps, and never publishes partial state.

#[path = "conntrack/codec.rs"]
mod codec;

use super::packet::Protocol;
use anyhow::{Context, Result, anyhow, bail};
use codec::parse_datagram;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 32_768;
const MAX_TOMBSTONES: usize = MAX_ENTRIES * 6;
// Capture accepts packets up to three seconds old and attribution can defer
// them another two seconds. Never reinterpret those bytes as a new generation.
const REUSE_QUARANTINE: Duration = Duration::from_secs(6);
const MAX_QUEUED_EVENTS: usize = 65_536;
const MAX_DATAGRAM: usize = 256 * 1024;
const MAX_ATTRIBUTES: usize = 64;
const REFRESH: Duration = Duration::from_secs(30);
const MAX_CACHE_AGE: Duration = Duration::from_secs(45);
const DUMP_DEADLINE: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_secs(5);
const POLL_MS: i32 = 50;
const CT_NEW: u16 = 0x100;
const CT_GET: u16 = 0x101;
const CT_DELETE: u16 = 0x102;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Tuple {
    pub protocol: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl Tuple {
    fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            ..self
        }
    }
}

/// Both endpoint pairs in the observed packet's direction, including a
/// connection with simultaneous source and destination NAT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Translation {
    pub before: Tuple,
    pub after: Tuple,
    pub zones: (u16, u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// The complete view has no current matching entry. This is not proof
    /// that a just-created/unconfirmed connection does not use NAT.
    Missing,
    Unchanged,
    Translated(Translation),
    Ambiguous,
    Unavailable,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Identity {
    id: u32,
    original: Tuple,
    zones: (u16, u16),
}

#[derive(Clone, Debug)]
struct Entry {
    identity: Identity,
    reply: Tuple,
    expires: Instant,
}

impl Entry {
    fn translation(&self, reverse: bool) -> Translation {
        let after = self.reply.reversed();
        if reverse {
            Translation {
                before: self.reply,
                after: self.identity.original.reversed(),
                zones: (self.identity.zones.1, self.identity.zones.0),
            }
        } else {
            Translation {
                before: self.identity.original,
                after,
                zones: self.identity.zones,
            }
        }
    }

    fn observations(&self) -> Vec<(Tuple, bool)> {
        let before = self.identity.original;
        let after = self.reply.reversed();
        // In original direction DNAT happens before SNAT. The reverse packet
        // traverses the inverse stages. Do not invent the other Cartesian
        // combination (SNAT applied but DNAT not applied).
        let middle = Tuple {
            destination: after.destination,
            ..before
        };
        let mut seen = HashSet::new();
        let mut observations = Vec::with_capacity(6);
        for tuple in [before, middle, after] {
            for (tuple, reverse) in [(tuple, false), (tuple.reversed(), true)] {
                if seen.insert((tuple, reverse)) {
                    observations.push((tuple, reverse));
                }
            }
        }
        observations
    }
}

#[derive(Clone)]
struct Candidate {
    entry: Arc<Entry>,
    reverse: bool,
}

struct Cache {
    entries: HashMap<Identity, Arc<Entry>>,
    index: HashMap<Tuple, Vec<Candidate>>,
    tombstones: HashMap<Tuple, Instant>,
    quarantine_until: Instant,
    quarantine_after_resync: bool,
    ready: bool,
    error: Option<String>,
    lost: u64,
    valid_until: Instant,
}

impl Cache {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            index: HashMap::new(),
            tombstones: HashMap::new(),
            quarantine_until: now,
            quarantine_after_resync: false,
            ready: false,
            error: Some("initial conntrack synchronization pending".into()),
            lost: 0,
            valid_until: now,
        }
    }

    fn remove(&mut self, identity: &Identity) {
        if let Some(entry) = self.entries.remove(identity) {
            for (tuple, _) in entry.observations() {
                if let Some(candidates) = self.index.get_mut(&tuple) {
                    candidates.retain(|candidate| candidate.entry.identity != *identity);
                    if candidates.is_empty() {
                        self.index.remove(&tuple);
                    }
                }
            }
        }
    }

    fn apply(&mut self, event: Event) -> Result<()> {
        self.apply_at(event, Instant::now())
    }

    fn quarantine(&mut self, entry: &Entry, now: Instant) -> Result<()> {
        for (tuple, _) in entry.observations() {
            if self.tombstones.len() >= MAX_TOMBSTONES && !self.tombstones.contains_key(&tuple) {
                self.tombstones.retain(|_, until| *until > now);
                if self.tombstones.len() >= MAX_TOMBSTONES {
                    bail!("conntrack generation tombstone limit reached");
                }
            }
            let until = self.tombstones.entry(tuple).or_insert(now);
            *until = (*until).max(now + REUSE_QUARANTINE);
        }
        Ok(())
    }

    fn apply_at(&mut self, event: Event, now: Instant) -> Result<()> {
        match event {
            Event::Delete(entry) => {
                // DESTROY includes both tuples even if its NEW was not in our
                // previous dump, so quarantine all observed NAT stages.
                self.quarantine(&entry, now)?;
                if let Some(previous) = self.entries.get(&entry.identity).cloned() {
                    self.quarantine(&previous, now)?;
                }
                self.remove(&entry.identity);
            }
            Event::Upsert(entry) => {
                let mut conflicts = HashMap::new();
                for (tuple, _) in entry.observations() {
                    if let Some(candidates) = self.index.get(&tuple) {
                        for candidate in candidates {
                            let previous = &candidate.entry;
                            if previous.identity != entry.identity || previous.reply != entry.reply
                            {
                                conflicts.insert(previous.identity.clone(), previous.clone());
                            }
                        }
                    }
                }
                if !conflicts.is_empty() {
                    self.quarantine(&entry, now)?;
                    for previous in conflicts.values() {
                        self.quarantine(previous, now)?;
                    }
                }
                self.remove(&entry.identity);
                if self.entries.len() >= MAX_ENTRIES {
                    bail!("conntrack entry limit reached");
                }
                let entry = Arc::new(entry);
                for (tuple, reverse) in entry.observations() {
                    self.index.entry(tuple).or_default().push(Candidate {
                        entry: entry.clone(),
                        reverse,
                    });
                }
                self.entries.insert(entry.identity.clone(), entry);
            }
        }
        Ok(())
    }

    fn prune(&mut self, now: Instant) -> Result<()> {
        self.tombstones.retain(|_, until| *until > now);
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
            .map(|(identity, _)| identity.clone())
            .collect();
        for identity in expired {
            if let Some(entry) = self.entries.get(&identity).cloned() {
                self.quarantine(&entry, now)?;
            }
            self.remove(&identity);
        }
        Ok(())
    }

    fn invalidate(&mut self, error: impl Into<String>) {
        self.ready = false;
        self.error = Some(error.into());
        self.lost = self.lost.saturating_add(1);
        self.quarantine_after_resync = true;
        self.entries.clear();
        self.index.clear();
    }

    fn translate(&self, tuple: Tuple, now: Instant) -> Outcome {
        if !self.ready || now >= self.valid_until {
            return Outcome::Unavailable;
        }
        if now < self.quarantine_until
            || self
                .tombstones
                .get(&tuple)
                .is_some_and(|until| now < *until)
        {
            return Outcome::Ambiguous;
        }
        let Some(candidates) = self.index.get(&tuple) else {
            return Outcome::Missing;
        };
        let mut found: Option<(&Identity, Translation)> = None;
        for candidate in candidates {
            if candidate.entry.expires <= now {
                continue;
            }
            let translation = candidate.entry.translation(candidate.reverse);
            if let Some((identity, previous)) = found {
                // Even identical translations in separate zones/entries are
                // ambiguous: an AF_PACKET observation has no conntrack zone.
                if identity != &candidate.entry.identity || previous != translation {
                    return Outcome::Ambiguous;
                }
            } else {
                found = Some((&candidate.entry.identity, translation));
            }
        }
        match found {
            None => Outcome::Missing,
            Some((_, translation)) if translation.before == translation.after => Outcome::Unchanged,
            Some((_, translation)) => Outcome::Translated(translation),
        }
    }
}

/// A cheap live view. Each lookup rechecks readiness/expiry under the cache
/// lock, so an earlier snapshot cannot keep using state after packet loss.
pub(super) struct View {
    pub ready: bool,
    pub error: Option<String>,
    /// Cumulative synchronization failures/loss incidents, not packet counts.
    pub lost: u64,
    shared: Arc<Mutex<Cache>>,
}

impl View {
    pub(super) fn translate(
        &self,
        protocol: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Outcome {
        locked(&self.shared).translate(
            Tuple {
                protocol,
                source,
                destination,
            },
            Instant::now(),
        )
    }
}

pub(super) struct Conntrack {
    shared: Arc<Mutex<Cache>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Conntrack {
    pub(super) fn start() -> Result<Self> {
        let shared = Arc::new(Mutex::new(Cache::new(Instant::now())));
        let stop = Arc::new(AtomicBool::new(false));
        let (send, receive) = mpsc::sync_channel(1);
        let thread_shared = shared.clone();
        let thread_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("nwtop-conntrack".into())
            .spawn(move || {
                let result = Socket::open().and_then(|socket| {
                    crate::privilege::retain_conntrack_privileges()?;
                    socket.request_dump(1)?;
                    Ok(socket)
                });
                match result {
                    Ok(socket) => {
                        if send.send(Ok(())).is_ok() {
                            run(socket, thread_shared, thread_stop);
                        }
                    }
                    Err(error) => {
                        let _ = send.send(Err(error));
                    }
                }
            })
            .context("starting conntrack worker")?;
        match receive.recv() {
            Ok(Ok(())) => Ok(Self {
                shared,
                stop,
                worker: Some(worker),
            }),
            result => {
                stop.store(true, Ordering::Relaxed);
                let _ = worker.join();
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(anyhow!("conntrack worker exited during startup")),
                }
            }
        }
    }

    pub(super) fn snapshot(&self) -> View {
        let cache = locked(&self.shared);
        let ready = cache.ready && Instant::now() < cache.valid_until;
        View {
            ready,
            error: if cache.ready && Instant::now() < cache.quarantine_until {
                Some("conntrack generation quarantine after synchronization loss".into())
            } else if cache.ready && !ready {
                Some("conntrack view expired".into())
            } else {
                cache.error.clone()
            },
            lost: cache.lost,
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Conntrack {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn locked(shared: &Mutex<Cache>) -> MutexGuard<'_, Cache> {
    match shared.lock() {
        Ok(cache) => cache,
        Err(poisoned) => {
            let mut cache = poisoned.into_inner();
            if cache.error.as_deref() != Some("conntrack cache poisoned") {
                cache.invalidate("conntrack cache poisoned");
            }
            cache
        }
    }
}

struct Socket(OwnedFd);

impl Socket {
    fn open() -> Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .context("opening conntrack netlink socket");
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 0b111; // NEW, UPDATE and DESTROY, before dumping.
        if unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("subscribing to conntrack events (NET_ADMIN required)");
        }
        let size: libc::c_int = 4 * 1024 * 1024;
        // Best effort: the kernel may clamp the buffer. ENOBUFS remains enabled
        // and is fatal to the current view; never request NETLINK_NO_ENOBUFS.
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            );
        }
        Ok(Self(descriptor))
    }

    fn request_dump(&self, sequence: u32) -> Result<()> {
        let mut request = [0_u8; 20];
        request[..4].copy_from_slice(&20_u32.to_ne_bytes());
        request[4..6].copy_from_slice(&CT_GET.to_ne_bytes());
        request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[16] = libc::AF_UNSPEC as u8;
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent != request.len() as isize {
            return Err(std::io::Error::last_os_error()).context("requesting conntrack dump");
        }
        Ok(())
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<Option<usize>> {
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let length = unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Ok(None);
            }
            return Err(error).context("receiving conntrack events");
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            bail!("truncated conntrack datagram");
        }
        if message.msg_namelen as usize != std::mem::size_of_val(&source)
            || source.nl_family != libc::AF_NETLINK as u16
            || source.nl_pid != 0
        {
            bail!("conntrack datagram was not sent by the kernel");
        }
        if length == 0 {
            bail!("conntrack socket closed");
        }
        Ok(Some(length as usize))
    }
}

#[derive(Clone)]
enum Event {
    Upsert(Entry),
    Delete(Entry),
}

enum Message {
    Event { sequence: u32, event: Event },
    Done(u32),
}

struct Dump {
    sequence: u32,
    deadline: Instant,
    cache: Cache,
    events: Vec<Event>,
}

impl Dump {
    fn new(sequence: u32, now: Instant) -> Self {
        Self {
            sequence,
            deadline: now + DUMP_DEADLINE,
            cache: Cache::new(now),
            events: Vec::new(),
        }
    }

    fn finish(mut self, now: Instant, previous: &Cache) -> Result<Cache> {
        // Replay all notifications after the dump, even when a dump row was
        // delivered later than its DESTROY or UPDATE notification.
        for event in self.events {
            self.cache.apply_at(event, now)?;
        }
        self.cache.prune(now)?;
        // A periodic dump replaces entries, never the evidence that a tuple
        // recently belonged to another generation.
        for (tuple, until) in &previous.tombstones {
            if *until > now {
                if self.cache.tombstones.len() >= MAX_TOMBSTONES
                    && !self.cache.tombstones.contains_key(tuple)
                {
                    bail!("conntrack generation tombstone limit reached");
                }
                let target = self.cache.tombstones.entry(*tuple).or_insert(*until);
                *target = (*target).max(*until);
            }
        }
        for old in previous.entries.values() {
            if !self
                .cache
                .entries
                .get(&old.identity)
                .is_some_and(|new| new.reply == old.reply)
            {
                self.cache.quarantine(old, now)?;
            }
        }
        let replacements: Vec<_> = self
            .cache
            .entries
            .values()
            .filter(|new| {
                new.observations().iter().any(|(tuple, _)| {
                    previous.index.get(tuple).is_some_and(|candidates| {
                        candidates.iter().any(|old| {
                            old.entry.identity != new.identity || old.entry.reply != new.reply
                        })
                    })
                })
            })
            .cloned()
            .collect();
        for new in replacements {
            self.cache.quarantine(&new, now)?;
        }
        self.cache.quarantine_until = previous.quarantine_until;
        if previous.quarantine_after_resync {
            self.cache.quarantine_until = now + REUSE_QUARANTINE;
        }
        self.cache.ready = true;
        self.cache.error = None;
        self.cache.valid_until = now + MAX_CACHE_AGE;
        self.cache.lost = previous.lost;
        Ok(self.cache)
    }
}

fn run(socket: Socket, shared: Arc<Mutex<Cache>>, stop: Arc<AtomicBool>) {
    let mut sequence: u32 = 1;
    let mut dump = Some(Dump::new(sequence, Instant::now()));
    let mut next_dump = Instant::now() + REFRESH;
    let mut prune_at = Instant::now();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let result = (|| -> Result<()> {
            if dump.as_ref().is_some_and(|dump| now >= dump.deadline) {
                bail!("conntrack dump timed out");
            }
            if dump.is_none() && now >= next_dump {
                sequence = sequence.wrapping_add(1).max(1);
                socket.request_dump(sequence)?;
                dump = Some(Dump::new(sequence, Instant::now()));
            }
            // Bound work before checking stop/deadlines again, even under flood.
            for _ in 0..32 {
                let Some(length) = socket.receive(&mut buffer)? else {
                    break;
                };
                let messages = parse_datagram(&buffer[..length], Instant::now())?;
                for message in messages {
                    match message {
                        Message::Event { sequence: 0, event } => {
                            if let Some(active) = &mut dump {
                                if active.events.len() == MAX_QUEUED_EVENTS {
                                    bail!("conntrack event queue limit reached");
                                }
                                active.events.push(event.clone());
                            }
                            let mut cache = locked(&shared);
                            if cache.ready {
                                cache.apply(event)?;
                            }
                        }
                        Message::Event { sequence, event } => {
                            if let Some(active) = &mut dump
                                && active.sequence == sequence
                            {
                                active.cache.apply(event)?;
                            }
                        }
                        Message::Done(sequence) => {
                            if dump
                                .as_ref()
                                .is_some_and(|active| active.sequence == sequence)
                            {
                                let completed = dump.take().expect("matched active dump");
                                let now = Instant::now();
                                let mut cache = locked(&shared);
                                *cache = completed.finish(now, &cache)?;
                                next_dump = now + REFRESH;
                            }
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            locked(&shared).invalidate(format!("{error:#}"));
            dump = None;
            next_dump = Instant::now() + RETRY;
        }
        if Instant::now() >= prune_at {
            let mut cache = locked(&shared);
            if let Err(error) = cache.prune(Instant::now()) {
                cache.invalidate(format!("{error:#}"));
                dump = None;
                next_dump = Instant::now() + RETRY;
            }
            prune_at = Instant::now() + Duration::from_secs(1);
        }
        let mut descriptor = libc::pollfd {
            fd: socket.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut descriptor, 1, POLL_MS);
        }
    }
}

#[cfg(test)]
#[path = "conntrack/tests.rs"]
mod tests;
