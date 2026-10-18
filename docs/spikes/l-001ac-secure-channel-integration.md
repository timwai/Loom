# L-001AC — reintegrate L-001A secure Peer channel on the active stack

**Security engineering PoC / no deployable Mesh / no ServiceOpen.** Stacked on L-001AB / Draft PR #35.

## Why the original L-001A PR was insufficient

Draft PR #7 holds an isolated, tested TLS 1.3 Peer channel over an untrusted byte stream, but its feature branch was based on L-000 and was **not inherited** by the current L-001AA/AB security chain. A green result on that sibling PR cannot be counted as end-to-end integrated coverage.

This branch copies the original module into the **current** `loom-transport` crate and reconciles the legacy TLS dependencies into the current Rust workspace lock. It deliberately preserves the original L-001A security caveats and the default disabled `loomd` runtime.

## What is exercised

- TLS 1.3 with mutually pinned Ed25519 X.509 leaf certificates and an encrypted association frame binding Space, both Peer IDs and epoch; the bearer may be an untrusted relay.
- An experimental `MembershipVerifier` interface and strictly local test allowlist are used as **test fixtures**, not independently attested Root/Owner grants.
- Existing adversarial tests cover wrong Space/epoch, switched certificate, Relay confidentiality smoke-test and Relay corruption of TLS handshake bytes.
- No network listener, filesystem service, QUIC routing, transport 0-RTT, real revoked-session kill, OS VPN/interception, durable membership anchor or production identity enrollment is enabled.

## Security No-Go

The original leaf certificate is added to a trust store in the test; this is **not** an audited production exact-pin verifier, and it does not establish a CA/EKU/SAN/expiry policy. Lack of production signed membership freshness, Owner-specific admission, crash-safe revocation and live two-peer channel integration **prevents acceptance of E2EE-01/TLS-ID-01 at release level**. The imported PoC must be reviewed for updated crypto provider selection, identity scope and resource limits before deployment.

See `docs/acceptance/l001.json`: L-001 remains **blocked** until E2EE-01, TLS-ID-01, WIRE-01, AUTHZ-RACE/CRASH/ROLLBACK and OS PLATFORM-Android/Win/Mac all have actual reviewed evidence. An in-memory TLS test is not an Android VPN or Windows/macOS driver acceptance test.
