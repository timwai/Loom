# L-001AD — Windows/macOS Rust host portability smoke tests

**Not PLATFORM acceptance.** This branch runs the existing locked Rust security-PoC workspace on GitHub-hosted Windows and macOS systems, in addition to Ubuntu's existing validation.

## Automated coverage

- `rust-host-portability` matrix uses `windows-latest` and `macos-latest` GitHub Actions runners, Rust toolchain 1.90.0, and `cargo test --workspace --all-targets --locked`.
- The tests exercise library code, signed journal and cryptographic fixtures, mTLS Peer association over in-process byte streams, and disabled daemon bootstrap where applicable.
- CI fails for platform-specific compiler errors, native dependency failures, tests or run-time assumptions. Rust host CI does not require administrative privileges, install drivers or touch real TPM NV.
- Ubuntu retains full Rustfmt, strict Clippy, locked tests, doc and cargo-deny; WIRE-01 stays independently verified in Rust/Go/Kotlin/JavaScript.

## What is still blocked

The repository's L-001D requires real Android Kotlin/VpnService, Windows packet/socket filtering, and macOS Network/System Extension entitlements on supported test devices. A GitHub-hosted Rust build/test runner has no authorized ability to load a system driver, ship signed extension entitlements or validate VPN routing, packet interception, UI permissions, rollback/reboot or actual mobile hardware. It must **not** mark `PLATFORM-WIN-01` or `PLATFORM-MAC-01` as passed.

Likewise, signed membership freshness, real device attestations, crash-durable antirollback, two-Peer service admission and security review remain separate hard blockers. `docs/acceptance/l001.json` remains `state=blocked`. No TPM write, ServiceOpen, user data migration or deployable network service is enabled.

## Next release work

1. Dedicated, isolated real Windows/macOS test hosts with signed driver/system-extension permissions and reproducible packet/filter tests.
2. Real Android emulator/physical-device Kotlin/VpnService lifecycle tests with user permission and traffic isolation.
3. Independently protected Root/Owner enrollment, signer/replay fence, signed recovery across power cuts and mandatory cross-process writer fencing.
4. Production Peer channel, signed membership/Owner admission, integration of revocation-to-live-session kill, and full security sign-off.
