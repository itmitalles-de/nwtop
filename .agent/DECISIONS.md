# Decisions

Durable decisions and their rationale. Validation details of past rounds are in
Git history (`git log -- .agent/STATE.md`) and the merged PRs.

## Measurement

- Interface rates come from kernel counters; process and connection rates only
  from captured IP packets matched to socket inodes/PIDs. Socket queue lengths,
  syscall byte counters and guessed owners are never used. Unavailable or
  unattributed data stays visible; demo data appears only with `--demo`.
- Ambiguity is resolved conservatively: shared descriptors, reused socket
  identities, lost metadata and conflicting fragment evidence leave bytes
  unattributed rather than guessing. Absent conntrack never proves absence of NAT.
- No payload retention and no DNS lookups.

## Privilege model

- The UI has no capabilities. A root-owned helper (`nwtop-collector`, mode 0750,
  group = the user's private group) holds file capabilities, talks to the UI
  only over private pipes and exits with it. Threads drop capabilities they no
  longer need. No service, port or arbitrary command/file API.
- Setup builds (or, in a release archive, takes) the helper as the regular user,
  copies it once into a root-only file, verifies that copy's digest and only
  then grants group access and capabilities. Shared groups are refused unless
  explicitly allowed.

## Extended attribution (eBPF)

- Opt-in at build time (`--features ebpf`); adds CAP_BPF, CAP_PERFMON and
  CAP_NET_ADMIN to the helper. In All it counts IP skbs at socket endpoints
  across namespaces; selected interfaces keep libpcap plus conntrack.
- 2026-10-17: experimental, bug fixes only, not shipped in release archives.
  Rationale: about a third of the source for an opt-in path with diminishing
  returns; distribution and usability matter more now.

## Project

- 2026-10-10: relicensed MIT → GPL-3.0-or-later; renamed nettop → nwtop (legacy
  `nettop/config.json` is read when no nwtop config exists; removal planned for a
  later release).
- Repository moved to `itmitalles-software/nwtop`; website `nwtop.wutz.io`, the old
  `nettop.wutz.io` redirects.
- 2026-10-17: prebuilt standard release archives (x86_64/aarch64, glibc 2.35+)
  built by the tag-triggered Release workflow.
