# Loom

Rust-first, **peer-oriented** private networking and device services platform. Loom is the new independent project for the RelayProxy Rust rewrite and decentralized Peer Mesh design.

**Status: L-001 engineering-integrated / L-001 release BLOCKED / L-002A–C models integrated.** The historical stacked development branches have been consolidated into the default branch. This is a source-code integration, **not** an L-001 release approval. `loomd` remains disabled: no network listener, ServiceOpen, resource admission, proxy modification, operating-system driver, or VPN is enabled. Real independent anti-rollback storage, hardware acceptance and reviewed authorization remain NO-GO.

## Architecture

- Rust workspace: eight library crates + the `loomd` proof-of-structure binary.
- No permanent Server/Agent identity; each device will be one Peer with optional services.
- Target platforms: Windows, macOS, Linux Rust daemon + Tauri/React desktop, Android Kotlin/VpnService with Rust core; browser extension remains TypeScript.
- Future transport: Quinn QUIC, secure inner Peer channel, optional trusted Relay; no trust-all shortcuts.
- Security: Owner authorization, signed membership, revocation-first state, rollback protection, per-Space isolation.
- **Hardware-agnostic trusted state:** no mandatory TPM chip. Portable software settings and optional TPM 2.0, Apple Secure Enclave, Android Keystore, or independently verified quorum backends are isolated by a Rust capability gate. Self-declared hardware/key protection **never** upgrades authorization or proves antirollback; sensitive operations still require independently verified trust evidence.

- Migrating existing RelayProxy configurations or wire protocols is **not** implemented or implicitly trusted.

## Development

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p loomd --locked
```

The `loomd` bootstrap command only prints its disabled-runtime state. A passing test suite means the bootstrap skeleton compiles; it is **not** a demonstration of functioning secure networking.

## Design and gates

- [Full v1.1 architecture specification](docs/architecture/loom-rust-peer-mesh-architecture-v1.1.md)
- [Security ADR-19–23](docs/architecture/README.md)
- [Implementation gates](docs/implementation-gates.md)
- [Review tracker](docs/review-tracker.md)
- [Implementation status](docs/STATUS.md)
- [L-001 local macOS / Docker repair and revalidation](docs/acceptance/evidence/l001-local-docker-20261020/REPORT.md) — local profile passed: 248 tests per OS, fresh-quorum recovery, real TCP and process/container crash experiments; formal release remains blocked.
- [Latest existing-environment acceptance](docs/acceptance/evidence/l001-integrated-20261020/REPORT.md) — 268 tests each on macOS/Linux/Android; actual JNI membership/TUN/protected-socket checks and container restart passed. Production admission, platform and independent-review gates remain blocked.
- [Android Docker laboratory](docs/acceptance/android-docker-lab.md) — Android 14 ARM64/Bionic: 248 tests, TLS, SQLite and recovery experiments; the JP Linux host also passed a standalone VPN API APK. Production JNI/VPN and real-device acceptance remain blocked.

**Next development:** L-002D will address authenticated Witness append and durable crash recovery; L-002A file-read/revocation, L-002B provider gating and L-002C challenge-bound Witness diagnostics are integrated models. Engineering integration of the L-001 PoCs is complete; its separate hardware, cross-platform, signed-authorization and ServiceOpen release acceptance remains BLOCKED. See [implementation gates](docs/implementation-gates.md), [L-001 evidence](docs/acceptance/l001.json) and [L-002A test plan](docs/spikes/l-002a-lan-file-read-model.md).

## Compatibility and licensing

The RelayProxy baseline is `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is **a new protocol and implementation**, not a drop-in Rust binary replacing deployed Go agents.

Workspace packages are `publish = false`. A public license has **not yet been selected**; do not assume third-party redistribution rights from repository visibility.
