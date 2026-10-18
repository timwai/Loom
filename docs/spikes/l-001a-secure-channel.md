# L-001A SecurePeerChannel TLS 1.3 PoC

**Status: engineering PoC / NOT PRODUCTION-READY / L-ADR-19 remains PROPOSED.**

A SecurePeerChannel runs TLS 1.3 with mutual certificate verification on any reliable byte stream (Quinn stream, TCP, Relay bearer). In this PoC, each peer's **Ed25519 self-signed leaf certificate** is locally pinned as an explicitly trusted certificate and used by rustls as a trust anchor; it must not imply broad CA-based acceptance. Peer ID is checked from the certificate's Ed25519 SPKI as `SHA256("LOOM:PEER-ID:V1\\0" || raw-32-byte-public-key)`.

After TLS succeeds, each endpoint sends an **encrypted 98-byte association frame**: 10-byte fixed magic, 16-byte SpaceId, 32-byte intended remote PeerId, 32-byte own PeerId, 8-byte big-endian local key epoch. Both validate reciprocal intended target and space/epoch, then return an authenticated channel. The `MembershipVerifier` is *only a trait*; this PoC's tests implement a strict in-memory allowlist. **No signed membership chain, revocation witness or Owner resource authorization is implemented yet**. No incoming service stream or Internet listener is exposed.

## Positive and adversarial tests

- TLS mutual authentication with matching pinned certificates.
- After TLS, reject wrong Space association before returning channel.
- Reject attempted server certificate substitution.
- Reject mismatched membership/key epoch.
- Untrusted forwarding Relay observes TLS bytes but cannot find known application plaintext in captured ciphertext.
- Active Relay corrupting a TLS handshake record must fail before any channel is admitted.

The last test is a **basic confidentiality smoke test**, not a cryptographic security proof. Future validation must include active alteration, replay, truncation, downgrade, malicious authorized peer, certificate rollover, real QUIC/TCP integration, revocation races, memory/CPU/latency and 1000 concurrent streams.

## Engineering follow-ups before ADR acceptance

1. Replace temporary "leaf cert as trust anchor" with audited exact-certificate/SPKI pinning verifier, and explicitly constrain the certificate's CA, EKU, SAN, expiry and hostname semantics.
2. Verify member chain signatures, scope, key epoch and latest anti-rollback anchor, enforce expiry and PolicyStale before the channel is allowed to open a service. The current `MembershipVerifier` accepts an arbitrary caller-supplied implementation and must not be silently bypassed in release.
3. Constrain async handshake timeout, maximum concurrent handshakes and resource consumption. Test Relay injection, packet replay, stripped authentication, half-open sessions and service-open abuse.
4. Design the relation between TLS association and per-service Owner grant checks. `AuthenticatedPeer != AuthorizedResource`.
5. Add real Quinn and TCP fallback transport adapters; `tokio::io::duplex` does not represent WAN NAT/Relay flow control.
6. Measure full handshakes and rebinds; do not enable 0-RTT until its replay/scope tests are passed.

## Development

```sh
cargo test -p loom-transport --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

This branch is stacked on L-000, independent of L-001B wire candidate. New dependencies require Cargo.lock regeneration and license/source audits in CI before PR merge.
