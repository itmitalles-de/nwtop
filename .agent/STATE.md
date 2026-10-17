# Verified state

Current operational state only. Decisions and rationale: `DECISIONS.md`;
structure: `ARCHITECTURE.md`; past validation rounds: Git history of this file
(before 2026-10-17) and the merged PRs.

## Repository (2026-10-17)

- Public `itmitalles-software/nwtop`, GPL-3.0-or-later, version 0.1.0, branch
  `main`. Old `itmitalles-de/nwtop` and `itmitalles-de/nettop` URLs redirect.
- Refactoring #22 done in two passes (PR #23, PR #28): collector attribution
  modules under `src/collector/`, oversized functions split. Default 166 / ebpf
  176 Rust tests; CI (fmt, Clippy both modes, Rust 1.88, release build,
  terminal/Setup, isolated Docker capture/short-lived/helper tests, release
  layout, cargo audit) and CodeQL green.
- Release archives: `.github/workflows/release.yml` on a `vX.Y.Z` tag (standard
  build, x86_64/aarch64, glibc 2.35+). The scripts install from `bin/` when no
  `Cargo.toml` is present; `tests/release_layout.sh` covers that path.
- Extended attribution (`--features ebpf`) is experimental: bug fixes only,
  source-only. Its VM-only suites (`tests/extended.py`, `tests/namespaces.py`,
  `tests/adversarial.md`, `tests/pressure.py`) were last run 2026-10-15 on the
  pre-#28 structure; BPF code is unchanged since.
- Website: `site/`, Pages workflow, custom domain `nwtop.wutz.io`; the former
  `nettop.wutz.io` should redirect via a Cloudflare page rule. Verify both after
  any DNS or Pages change (`curl -sI`).

## Owner machine

- Installed: `~/.local/bin/nwtop` and `/usr/local/libexec/nwtop-collector`
  (extended build, root:tim 0750, DAC_READ_SEARCH, NET_RAW, SYS_PTRACE,
  NET_ADMIN, BPF, PERFMON) from 2026-10-10, before the behavior-neutral
  refactors. Reinstall with both scripts (`--extended-attribution`) to update.
- Local review evidence (logs, review pages) lives outside Git in
  `~/github/itmitalles-de/nettop-review/`; VM disk images there are disposable.

## Open work

GitHub Issues: #25 (remove nettop legacy in 0.2), #26 (packages), #27 (shared
code with dwtop), #29–#31 (behavior follow-ups from #22).
