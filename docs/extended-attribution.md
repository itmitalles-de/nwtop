# Extended attribution (experimental)

> **Experimental.** This optional backend is maintained for bug fixes only and
> is not part of the release archives. The standard build covers most use; use
> extended mode only when you need the cases below and accept its extra
> capabilities and kernel requirements.

For sockets that live less than one scan interval and container published ports,
opt in to socket lifecycle events, network namespace discovery and conntrack NAT
translation. The default build and its permissions are unchanged.

```bash
# Additional build/runtime dependencies on Ubuntu 24.04+.
sudo apt install clang libbpf-dev
./scripts/install.sh --extended-attribution
./scripts/setup-capture.sh --extended-attribution
```

This requires Linux with BTF and supported BPF tracing hooks, a little-endian
x86_64 or aarch64 target, and `libbpf.so.1`. The kernel integration tests use
Linux 6.8 on x86_64; other kernel configurations can reject the hooks. Missing
support, permissions, event losses and stale conntrack data are reported in
capture status instead of silently guessing ownership. F1 shows the active mode.
If neither optional backend can start, standard sampled attribution remains
available alongside the startup errors.

The extended helper additionally receives `CAP_BPF`, `CAP_PERFMON` and
`CAP_NET_ADMIN`. Its BPF worker drops all capabilities after attaching; its
conntrack worker retains only `CAP_NET_ADMIN` for subsequent netlink queries.
The UI stays unprivileged. No permanent service or pinned BPF objects are created;
closing nwtop releases its probes. Run both installer scripts again without
`--extended-attribution` to return to the standard build and capability set.

Captured IP packets remain the only source of process byte counts. Event data
contains socket/process identities and endpoints, never payloads. Attribution
can be delayed by up to two seconds while late events arrive. Ambiguous owners,
shared descriptors, event loss and unsupported asynchronous I/O may still leave
traffic unattributed. This is monitoring, not complete per-process accounting.

In **All**, extended mode captures actual TCP/UDP IP packets at socket endpoints
across network namespaces, including foreign loopback, macvlan and ipvlan paths.
Each send/receive direction is counted at one endpoint capture point; bridge,
veth and VLAN copies do not multiply its bytes. A packet's kernel socket identity
supplies positive evidence even without conntrack, including queued receives on
long-lived NOTRACK sockets. Current descriptor evidence and ambiguity checks
still apply. A uniquely observed reader may receive credit after a descriptor
transfer; this does not claim historical ownership when the packet arrived.
Receive-only unconnected UDP sockets using `read()` or `recv()` are supported:
their socket identity and syscall window supply actor evidence even when the
syscall exposes no peer address. They do not create an incomplete tuple match.
Connection rows use the endpoints actually present in the captured packet;
packets without complete transport ports contribute only to process totals.

These are observed IP skb bytes, not syscall payload counts or reconstructed
wire frames. Segmentation, receive aggregation, fragmentation and packets later
dropped after the capture point can make them differ from interface counters.
Pure forwarding has no local socket endpoint: select a host interface to inspect
its captured bytes. Non-TCP/UDP host captures remain unattributed in All.

A **selected interface** continues to use host libpcap with conservative socket
and conntrack correlation. Untracked queued traffic can remain unattributed in
that view; an absent mapping never proves absence of NAT. Identical packet
headers are not used to guess a socket across namespaces. Foreign loopback does
not appear under the host's loopback interface. Interface graphs always use the
host kernel counters, so their scope differs from cross-namespace process totals.
nwtop neither enters namespaces nor changes firewall rules.

All packet hooks attach together or startup retains the existing capture path
with an explanation. A fatal runtime packet-backend failure makes All process
rates unavailable until restart, avoiding a switch that could double-count bytes.
Queues and history remain bounded. Capture-buffer pressure and attribution-wait
pressure have separate notices; the latter preserves already captured bytes and
any proven endpoint while ending the wait for remaining evidence.
