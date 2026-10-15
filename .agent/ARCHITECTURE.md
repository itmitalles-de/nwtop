# Architecture

`main.rs` owns CLI validation, source selection, refresh timing and terminal
restoration. `ui.rs` owns application state and input; its private `ui/render`
modules draw the nvtop-style layout from snapshots. `ui/format.rs` supplies
display units, and `ui/demo.rs` supplies only explicitly requested demo data.
The renderer never derives measurements from queue lengths or substitutes demo values.
`config/settings.rs` owns the versioned preference schema and pure validation;
`config.rs` keeps XDG path resolution and atomic private writes together.
`main.rs` applies explicit CLI overrides, `NO_COLOR` and the
unavailable-interface fallback to a runtime copy only; the UI tracks fields the
user changed by key or in F2 Setup, and F12 writes the file values plus only
those fields. Unknown keys warn and are preserved on save. As root, saving into a
non-root-owned settings tree is refused. The collector never loads this configuration.
`i18n.rs` provides English and German TUI text; the `language` preference
(`auto` follows LC_ALL/LC_MESSAGES/LANG) is editable in Setup. CLI help, errors,
`--once` and `--json` stay English. Runtime sample errors become notices; a failed
helper falls back to direct unprivileged collection instead of exiting.
UI colors use native ANSI colors and inverse styles, inheriting the terminal theme.
`shutdown.rs` registers cooperative SIGINT/SIGTERM/SIGHUP handlers so raw mode,
the alternate screen and the cursor are restored even with long refresh periods.
`input.rs` reads crossterm events on a `nwtop-input` thread, because crossterm's
reader retries end-of-file/EIO from a hung-up terminal forever inside
`event::poll`/`read`. The event loop waits on that channel in 100 ms steps and
also exits (code 0, like SIGHUP) when stdin reports POLLHUP/POLLERR, which covers
closed terminals that send no SIGHUP to non-session-leaders. Final restore errors
are written without `eprintln!`, which would panic on a dead stderr.

Normal-user capture uses the optional root-owned, group-restricted
`/usr/local/libexec/nwtop-collector`, which clears its whole environment before
loading libpcap, because libibverbs honors driver variables via plain getenv. `helper.rs` provides a versioned, bounded
stdio protocol; replies have a deadline and cancellation so a stalled helper
cannot trap the UI. `privilege.rs` drops per-thread capabilities: the capture
worker keeps none after opening pcap; the sampling thread keeps only
DAC_READ_SEARCH and SYS_PTRACE for process descriptors, as does the
`nwtop-attrib` thread it starts. All set NO_NEW_PRIVS.
`scripts/setup-capture.sh` builds unprivileged, authenticates only for root-owned
installation, copies the build into a root-only file (no final symlink), verifies
that copy's digest before granting group access and capabilities, and refuses
untracked replacements. It refuses a primary group that is not a user private
group or has other members (`--allow-shared-group`) and a silent takeover from
another group (`--reassign-group`). The authenticating administrator trusts the
user's checkout. Collector status is sent both as English `message` and as
structured `notes` (serde default, unknown codes decode as `Unknown`), which the
UI translates; older helpers without notes keep working with English text, so
the protocol version is unchanged.
The UI itself never receives capabilities or elevated user IDs.

`collector/interfaces.rs` reads `/proc/net/dev`, sysfs interface metadata and getifaddrs;
`collector.rs` owns sampling, worker orchestration, counters and attribution.
Interface indexes come from `if_nametoindex`/AF_PACKET entries, never a 0
fallback; IPv4 alias labels (`eth0:1`) map to their device, so VIPs are local.
Interface rates are monotonic counter deltas divided by the measured interval.
Device removal preserves the UI and permits selection of another device.
With capture, a background `nwtop-attrib` thread, started from the sampling
thread on the first snapshot (so it inherits exactly that thread's
capabilities), refreshes sockets and attributes captured flows every 250–500 ms,
independent of the UI interval; snapshots only add the final pass and divide
accumulated deltas by the interval. Each pass drains captured flows before
rereading socket tables, so tables are never older than the packets. Flows of
sockets awaiting their first owner scan or V6ONLY metadata are retried until
the next owner scan can have run (one to six seconds, derived from the
cost-dependent scan gap, at most 4096 merged flow directions). Local flows
without any candidate wait once for a table read after their drain; nonlocal
flows never wait. Per pass, host addresses, loopback links and stacked-device
relations (`master`/`upper_*` in sysfs, cached two seconds in the worker) are
precomputed as sets. Counters carry their capture link and a lower-device flag:
host traffic seen on a bridge port, bond slave or VLAN parent is skipped in
all-interface rows but shown when that link is selected. Wildcard-only matches to a
`docker-proxy` listener from non-loopback links stay unattributed, since
AF_PACKET sees published-port traffic before Docker's DNAT.

`capture.rs` owns a single dynamically loaded, non-promiscuous libpcap session
and its worker thread. It captures a bounded prefix for parsing headers, stores
only flow byte counts (or bounded header-only packet timestamps for the optional
extended build), and closes its own worker/handle on drop. SLL2 interface
indexes make device filtering explicit. Queue and capture drops remain visible
as per-snapshot deltas (wrapping pcap_stats counters), as do unsupported or
unreadable packets, so a past burst does not taint later snapshots.

`packet.rs` handles IP/TCP/UDP headers, link formats, VLANs, IPv6 extensions and
fragments, including zero-length IPv4 BIG TCP/GSO frames. The capture worker
keeps a bounded two-second cache of first-fragment ports, scoped by capture
interface and direction. Conflicting ports quarantine that fragment identity
until expiry rather than selecting one datagram. Process rates count observed
IP bytes; interface totals also include
other protocols and link overhead. All-interface mode can observe the same
traffic at several virtual links and warns accordingly.

`sockets.rs` correlates flow endpoints with socket tables and inode owners acquired
by `sockets/procfs.rs`; `sockets/diagnostics.rs` owns host SOCK_DIAG queries and
their retry state. Identity includes PID and start time. Descriptor
scans run promptly when unscanned inodes or exited cached owners appear, spaced
by at least 200 ms or ten times the previous scan's cost, and otherwise every
five seconds; cached owners are revalidated against `/proc/PID/stat` each second.
Closed sockets survive briefly for late packets; an owner whose descriptor
closes between the socket-table read and the descriptor scan is kept for that
scan. Flows use an exact endpoint
index; only listeners and wildcard sockets are scanned per port.
Ambiguous and shared ownership remains unattributed, except that equally
matching sockets of one process (`SO_REUSEPORT`) credit that process only. Current sockets retain
totals through idle periods; expired closed entries and all maps are bounded.
Overlapping socket incarnations involving retained matches stay unattributed,
except that a TCP listener or an inode-less closing remnant (FIN-WAIT,
TIME-WAIT, LAST-ACK) of the same endpoint pair never competes with a connection,
nor does the inode-less accept-queue entry of a connection accepted afterwards.
Status flags describe the latest refresh/scan, not the process lifetime.
Only local endpoints can match host sockets. State-filtered, per-protocol
bounded SOCK_DIAG queries supply IPv6 wildcard V6ONLY metadata, cached per socket
incarnation; missing metadata never implies dual-stack support, but an IPv4 flow
whose only candidate is such a wildcard is deferred instead of lost. The 50 ms
receive budget starts after sendto(), which can synchronously autoload diag
modules; EINTR is retried. An incomplete dump is retried on the next refresh up
to three times, a complete or rejected one that lacks a socket after two seconds.

The live integration harness sends known payloads between separate processes on
loopback. It checks each transport/address family, both process directions,
capture drops, interface rates and duplicate counting. UI and parser boundary
behavior is also covered by Rust tests. Review evidence is local and excluded
from the repository.

The public project website is a dependency-free static site in `site/`, deployed
by `.github/workflows/pages.yml` from `main`. Only `site/` is uploaded to Pages;
the source repository is also public under GPL-3.0-or-later. `nettop.wutz.io` is a DNS-only Cloudflare
CNAME to `itmitalles-de.github.io`, with HTTPS enforced by Pages. Deployment checks
the public HTTPS endpoint. The site uses local fonts and explicit DEMO
captures as intentional public product assets; local QA evidence stays outside Git.

## Optional extended attribution

Cargo feature `ebpf` embeds a CO-RE object built from `bpf/lifecycle.bpf.c`.
`events.rs` dynamically loads libbpf, owns tracing links and a bounded ring
consumer, and drops its worker capabilities after attach. No kernel pointers or
payloads cross the event ABI. Hooks observe process-context bind, connect,
accept, send, receive and final release. Actorless TCP-child birth events cover
queued receive data before accept; final kernel socket freeing removes IDs of
children that were never accepted. Socket IDs and full process start times
separate reuse. `event_owners.rs` indexes bounded, direction-specific syscall
windows; a closed socket with one observed actor also supplies its observed
lifetime for packets queued before receive. Conflicting actors, event losses and
clock uncertainty suppress ownership. Competing bound UDP sockets veto inferred
receive lifetimes even if they never report a peer. A unique open event candidate
outside its syscall window requires corroboration by a current descriptor with
the same inode and process identity, plus proven conntrack endpoints for pcap
observations or the actual socket identity from endpoint packet capture.
This is not proof of exclusive descriptor
ownership; inventory evidence of sharing vetoes event matches.

`conntrack.rs` maintains a bounded ctnetlink snapshot with event subscription,
periodic resynchronization, zones, bidirectional translation and expiry. Loss or
partial dumps invalidate the view. Six-second tuple tombstones survive resync
and withhold translations across deletion/reuse; after event loss the restored
view is quarantined as well, so deferred packets cannot inherit a new NAT target.
Its worker alone retains NET_ADMIN.
`sockets.rs` optionally discovers namespace-scoped inventories via bounded
`/proc/PID/net` reads, verifying namespace identity before and after, without
setns or SYS_ADMIN. `links.rs` identifies actual veth devices through rtnetlink.

`extended.rs` combines independent endpoint evidence. Five additional hooks
capture TCP/UDP IP skbs at `ip_finish_output2`, `ip6_finish_output2`, the mutually
exclusive TCP established/state receive paths, and `__udp_enqueue_schedule_skb`.
The 80-byte packet ABI carries socket incarnation, namespace, inode, direction,
observed IP byte length and fixed header endpoints; no payload or kernel address.
All TCP/UDP process bytes come only from these observations (`Link` index zero),
including foreign loopback and non-veth devices. Namespace-local ifindexes never
select host interfaces. TX counts the observed post-routing skb before neighbor
delivery; RX counts the actual demultiplexed skb. GSO/GRO and fragmentation are
not expanded into guessed wire segments. Pure forwarding requires a selected
host interface; non-TCP/UDP host captures still contribute unknown All bytes.

Host pcap observations remain available on selected interfaces and are marked
excluded from All while endpoint capture is active. Their sender/receiver
correlation uses conntrack original/reply tuples; unproven endpoints never fall
back to an unrelated host listener. Missing conntrack can still leave selected
interface traffic unknown. Neither a completed dump nor identical header
fingerprints prove absence of NAT for packets delayed before PREROUTING.

Each capture path has a bounded 4096-entry attribution wait queue and waits at
most two seconds. At capacity, already proven endpoints remain credited and
unresolved bytes become unknown. The 16384-entry pcap queue wakes attribution at
one-quarter capacity using one coalesced notification. Capture and attribution
pressure have distinct notices; limits are unchanged. Capture starts before the
initial descriptor scan. Pcap realtime-to-monotonic uncertainty quarantines pcap
ownership; endpoint timestamps already use the kernel monotonic clock.

All hooks are armed together after attach. Runtime fatal errors keep the chosen
All source sticky and mark process rates unavailable rather than switching to
pcap and risking duplicate bytes. A failed socket-identity deletion disarms
recording and requires restart, preventing kernel pointer reuse from reviving an
old incarnation. Scoped links are destroyed on exit; nothing is pinned.

Both installer scripts require `--extended-attribution` to opt in. Standard
builds do not require clang/libbpf or extra capabilities. Runtime status exposes
backend errors and drops; F1/JSON distinguish extended from sampled collection.
VM-only `tests/extended.py` and `tests/namespaces.py` exercise short TCP/UDP
lifetimes, exited owners, namespace paths and NAT without tracing the host.

## Source inventory and refactoring boundaries (#22)

The 2026-10-15 pass inventoried all 73 tracked files at `f598a26`, including
20 `src` Rust files, `build.rs`, the BPF source, Python/C integration harnesses,
installers, CI and the static site. File size alone does not justify splitting
an evidence state machine: much of the large attribution files is regression
coverage. No dependencies, wire schemas, thresholds or measurements changed.

| Source boundary | Responsibility and decision |
| --- | --- |
| `ui.rs` | Public facade, input, filtering, sorting and runtime preferences; 2,435 lines became 674 after extracting rendering and tests. |
| `ui/render.rs`, `ui/render/{graph,overlays}.rs` | Main layout, history plots and modal panels; consume the existing `App` state without changing keys, text, colors or dimensions. |
| `ui/{format,demo}.rs` | Shared display units and explicit preview data; existing `ui` exports are preserved. |
| `config.rs`, `config/settings.rs` | Private atomic file operations separated from schema/defaults/validation. Symlink, ownership, hardlink and size checks stay in the file boundary. |
| `collector.rs`, `collector/interfaces.rs` | Attribution/counters separated from host counters, addresses, topology and default-route discovery. Worker timing and scope rules stay together in the collector. |
| `sockets.rs`, `sockets/{procfs,diagnostics}.rs` | Inventory and conservative endpoint resolution separated from bounded Linux metadata reads and host-only SOCK_DIAG transport/retry. PID identity, ambiguity, retention and limits are unchanged. |
| `conntrack.rs`, `conntrack/codec.rs` | Cache generations, quarantine and worker I/O remain together; pure netlink validation produces metadata without I/O or cache writes. |
| `event_owners.rs` | Keep the cohesive bounded evidence-window/actor/namespace state machine and its extensive adversarial tests. |
| `extended.rs` | Keep event, descriptor, packet and NAT evidence orchestration together; its ownership decisions share state. |
| `events.rs` | Keep the feature-gated libbpf ABI, attach order, owning worker and loss accounting together. |
| `capture.rs` | Keep the owning pcap lifecycle, capability boundary, fragment quarantine, bounded queues and clock conversion. |
| `packet.rs`, `links.rs` | Already separate bounded packet parsing and route-netlink link discovery. |
| `main.rs` | Keep CLI overrides, helper fallback, terminal lifetime and event-loop integration. |
| `helper.rs`, `bin/nwtop-collector.rs`, `privilege.rs` | Keep the bounded protocol and privileged entry point/capability operations separate from UI and configuration. |
| `input.rs`, `shutdown.rs` | Small existing event and cooperative signal lifetime boundaries. |
| `model.rs`, `i18n.rs`, `lib.rs` | Public snapshot schema, language text and crate surface remain unchanged. |
| `build.rs`, `bpf/` | Optional CO-RE compilation and matching BPF/Rust record ABI; retain layout assertions and kernel safety boundaries. |
| `tests/`, `scripts/`, `.github/workflows/` | Keep real traffic, isolation, installer, feature and MSRV checks. Add a public-API rendering characterization test. |
| `site/` | Existing static website and assets reviewed in the inventory; no UI, copy or build changes. |

The extracted modules are private; facade re-exports preserve existing public
paths. Tests for extracted internals live beside their owning modules, retaining
all existing safety cases. `tests/ui_contract.rs` records 48 deterministic full
terminal buffers, including symbols, colors and modifiers, through the public
API before the renderer split: both languages, narrow/wide terminals, all
panels, both chart styles, connections, search and unavailable capture.

Compiler/Clippy checks found no dead-code warning in either feature mode.
Similar parsers intentionally follow different procfs, packet and netlink wire
formats; sharing them would obscure bounds and endian rules. BPF/Rust layout
mirroring is an explicit cross-language ABI. No speculative removal of public
items or generic abstraction was introduced merely to reduce line counts.
