# Loom

Rust-first, **peer-oriented** private networking and device services platform. Loom is the new independent project for the RelayProxy Rust rewrite and decentralized Peer Mesh design.

**Status: unmerged security-engineering PoCs / NOT production-ready.** The default `main` branch still has only the initial README. Draft feature branches now contain a Rust workspace and isolated cryptographic, Owner lifecycle, SQLite journal, witness and TPM-probe experiments. `loomd` remains disabled: it does not listen on the network, admit resources, change proxy settings, load drivers, or operate a VPN. A passing PoC test suite does **not** grant ServiceOpen or establish a trusted anti-rollback anchor.

## Architecture

- Rust workspace: eight library crates + the `loomd` proof-of-structure binary.
- No permanent Server/Agent identity; each device will be one Peer with optional services.
- Target platforms: Windows, macOS, Linux Rust daemon + Tauri/React desktop, Android Kotlin/VpnService with Rust core; browser extension remains TypeScript.
- Future transport: Quinn QUIC, secure inner Peer channel, optional trusted Relay; no trust-all shortcuts.
- Security: Owner authorization, signed membership, revocation-first state, rollback protection, per-Space isolation.
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

**Next gates:** reconcile sibling security PRs (including mirror integrity), independently authenticate/replay a single unified policy journal, design a durable high-water provider with signed recovery, then run real OS networking and two-Peer LAN validation. See [current development progress](docs/STATUS.md) and [L-001P integration notes](docs/spikes/l-001p-unified-mirror-reconciliation.md). Do not merge a leaf Draft PR directly to `main` without its dependencies and threat-model review.

## Compatibility and licensing

The RelayProxy baseline is `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is **a new protocol and implementation**, not a drop-in Rust binary replacing deployed Go agents.

Workspace packages are `publish = false`. A public license has **not yet been selected**; do not assume third-party redistribution rights from repository visibility.
