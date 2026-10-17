# Loom

Rust-first, **peer-oriented** private networking and device services platform. Loom is the new independent project for the RelayProxy Rust rewrite and decentralized Peer Mesh design.

**Status: stacked security-engineering PoCs / not production-ready.** The default `main` branch is still the initial repository baseline; feature work is on unmerged Draft PRs. The L-000 workspace has since been extended with experimental signed events, Owner lifecycle verification, an mTLS channel PoC, SQLite revocation/policy journals and local rollback-recovery diagnostics. These are not wired into a production Peer runtime. `loomd` still only prints its disabled state: no network listener, system proxy, driver, VPN, Relay, file sharing or RDP is started. The L-000 placeholder paths remain deny-by-default.

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

Next integration gates: resolve the single authoritative policy journal and signed migration, bind unified policy heads to an independently trusted anti-rollback provider and witnessed freshness, then complete `L-001D` OS networking spikes and `L-002` two-Peer LAN file-read/revoke test. See `docs/STATUS.md` and `docs/spikes/l-001j-mirror-integrity.md` for the latest draft-branch limits.

## Compatibility and licensing

The RelayProxy baseline is `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is **a new protocol and implementation**, not a drop-in Rust binary replacing deployed Go agents.

Workspace packages are `publish = false`. A public license has **not yet been selected**; do not assume third-party redistribution rights from repository visibility.
