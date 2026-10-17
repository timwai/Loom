# Loom

Rust-first, **peer-oriented** private networking and device services platform. Loom is the new independent project for the RelayProxy Rust rewrite and decentralized Peer Mesh design.

**Status: L-000 foundation only / not production-ready.** At this stage `loomd` does not listen on any network interface, change system proxy settings, load a driver, provide an exit, or accept remote credentials. The placeholder `loom-crypto`, `loom-identity`, `loom-policy` and `loom-store` interfaces explicitly fail closed.

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

Next independent spikes: `L-001A` secure Peer channel, `L-001B` canonical signed event vectors, `L-001C` SQLite admission barrier/outbox/anti-rollback, `L-001D` real Android/Windows/macOS networking.

## Compatibility and licensing

The RelayProxy baseline is `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is **a new protocol and implementation**, not a drop-in Rust binary replacing deployed Go agents.

Workspace packages are `publish = false`. A public license has **not yet been selected**; do not assume third-party redistribution rights from repository visibility.
