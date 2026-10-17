# What the numbers mean

Interface rates come from **kernel byte counters**. Process and connection rates
come from **captured TCP/UDP IP packets**, matched to socket inodes and PIDs.
Socket queue lengths are never used as traffic estimates. Missing capture,
dropped packets and unattributed traffic stay visible; unavailable measurements
are never replaced with demo data.

## Measurement boundaries and privacy

- Interface counters include protocols and link-layer overhead that captured
  TCP/UDP IP-byte totals do not. Interface totals are the kernel's cumulative
  counters; process totals contain observed captured IP bytes.
- Aggregating interfaces can count traffic more than once, for example across a
  bridge and its member interfaces. `--interface all` includes virtual links.
  Process rates there count host traffic once: copies seen on bridge ports, bond
  slaves or VLAN parents are left out, but still shown when that link is
  selected. Forwarded traffic can repeat in the unattributed row.
- Standard attribution covers accessible sockets in the host network namespace.
  The optional extended mode also correlates accessible container namespaces and
  conntrack NAT; its capture boundaries are described in [extended attribution](extended-attribution.md).
- Standard socket ownership is sampled. Short-lived, shared, and ambiguously reused
  sockets can remain in the unattributed bucket; per-PID rates are not a complete
  accounting ledger. Equally matching `SO_REUSEPORT` sockets of one process
  credit that process, without a single connection row.
- Forwarded traffic is not assigned to unrelated host listeners. Multicast and
  broadcast receiver membership is not inferred from ports. IPv6 wildcard
  sockets are matched to IPv4 only when Linux socket diagnostics confirm
  dual-stack operation.
- Packet headers are interpreted; payloads are not logged. nwtop does not
  perform DNS lookups.
