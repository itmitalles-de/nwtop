# Development and test coverage

The core checks are listed in the [README](../README.md#development); the
[source map and boundaries](../.agent/ARCHITECTURE.md#source-inventory-and-refactoring-boundaries-22)
describe the private modules behind the public API.

## Isolated capture tests

Run capture and helper tests in an isolated environment. These Docker commands
use a read-only repository mount and a separate network namespace with no
external connectivity:

```bash
docker build -t nwtop-test tests
docker run --rm --network none -v "$PWD:/work:ro" nwtop-test \
  python3 tests/live_capture.py target/release/nwtop
docker run --rm --network none --cap-add DAC_READ_SEARCH --cap-add SYS_PTRACE \
  -v "$PWD:/work:ro" nwtop-test python3 tests/helper.py --isolated \
  target/release/nwtop target/release/nwtop-collector
```

The Python integration tests use standard-library loopback sockets. Separate
sender and receiver PIDs exchange real IPv4/IPv6 TCP and UDP traffic; assertions
cover measured rates, PID attribution, packet drops, and duplicate counting
without changing network configuration. `tests/helper.py` also checks capability
separation, unprivileged cross-user attribution, installer safeguards, bounded
protocol input, shutdown with a stopped helper, helper cleanup when the
terminal closes, and the fallback to direct counters when the helper stops
answering.

The optional backend's kernel tests run only in an owned disposable QEMU/KVM
guest. `tests/namespaces.py` covers 46 TCP/UDP namespace, NAT and NOTRACK cases,
including a competing pre-DNAT listener and separate All/selected-interface
assertions. [Adversarial test instructions](tests/adversarial.md) cover descriptor
sharing, io_uring, Fast Open, retransmission, metadata loss, clock changes and
tuple reuse. `tests/pressure.py` checks both capture scopes under bounded UDP
loads, including minimum captured bytes, duplicate totals and resident memory.
Keep raw process/packet evidence outside the repository.

[CI](.github/workflows/ci.yml) is configured to run formatting, linting, unit
tests on stable and Rust 1.88.0, release builds, terminal restoration, prompt exits after the terminal closes, Setup and
persistence checks, a dependency audit, and capture tests in isolated, digest-pinned
Ubuntu 24.04 containers.
Building the test image needs access to its base image and package repositories.

## Releases

Pushing a tag `vX.Y.Z` that matches the `Cargo.toml` version runs the
[Release workflow](../.github/workflows/release.yml). It builds the standard
`nwtop` and `nwtop-collector` for x86_64 and aarch64 on Ubuntu 22.04
(glibc 2.35), smoke-tests them, and publishes
`nwtop-X.Y.Z-<arch>-linux.tar.gz` archives with `SHA256SUMS` as a GitHub release.
Tag only a `main` commit whose CI has passed.
