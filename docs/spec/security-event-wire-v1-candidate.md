# L-001B / WIRE-01 Candidate Protocol Conformance (not frozen)

The authoritative candidate originates from Loom v1.1 §10.5. This commit establishes a deliberately **restricted** nine-field CBOR map and fixed signing transcript for security-event **transport bytes**, **not** the semantics of every security event.

Fields encoded in order as definite canonical CBOR map (integer keys only):

| Key | Name | Type |
|---:|---|---|
| 0 | version | unsigned integer, exactly `1` |
| 1 | kind | unsigned integer, 1=membership, 2=owner grant, 3=revoke, 4=checkpoint, 5=key binding |
| 2 | space_id | bytes, length 16 |
| 3 | signer_key_id | bytes, length 32 |
| 4 | issuer_epoch | unsigned integer |
| 5 | issued_at_ms | unsigned integer |
| 6 | expires_at_ms | unsigned integer, greater than issued |
| 7 | seq | unsigned integer |
| 8 | payload | bytes, at most 60 KiB |

The entire object must be at most 64 KiB. Reject indefinite lengths, unused CBOR majors (text/negative/tag/floats), non-minimal integers, duplicate/nonascending/unknown fields, wrong fixed lengths, truncated input, and tail bytes.

The outer 9-field map's CBOR-encoded `payload` is **opaque at this stage**. Typed event decoders must independently validate each payload using an audited schema, authenticate its signer, verify scope, policy epoch and revocation state, and persist before any access decision. **Successful decode or signature verification is never authorization.**

Transcript, as exact bytes:

```text
ASCII("LOOM:SECURITY-EVENT:V1\\0") || u32_be(len(cbor)) || cbor
event_id = SHA256(ASCII("LOOM:EVENT-ID:V1\\0") || cbor)
signature = Ed25519.sign(seed, transcript)
```

The `\\0` above denotes one zero byte. Golden fixture seed 00..1f is public and **MUST NEVER** be used for a real Peer key.

The vectors were generated separately with Python's `cryptography` Ed25519 implementation. CI compares Rust's serializer/parser/transcript to the same vector, and independent Go / Node.js implementations regenerate CBOR, transcript, event ID, and Ed25519 signature (and test signature tampering).

```sh
cargo test -p loom-wire --locked
go run ./test-vectors/wire-v1/check.go
node ./test-vectors/wire-v1/check.mjs
```

## Outstanding gates (not claimed passing)

- Rust Ed25519 signature verification with a pinned and audited library (currently deny-all Crypto module).
- Kotlin independent producer/verifier using JCA/Android-supported crypto; distinguish Android API levels.
- Typed security-event payload schemas + authorizer, parser fuzz/property corpus, duplicate/conflict event lifecycle.
- Protobuf/prost non-security control messages, handshake and version negotiation.
- Malicious Relay E2EE test and local SQLite admission barrier.
- Actual Rust/Go/Kotlin/JS cross-platform sign/verify; only Rust CBOR bytes plus Go/JS crypto are attempted here.
- Security review acceptance of wire schema, domain-separated IDs, and exact event-kind mapping.

**This is an engineering spike. Do not mark ADR-07 ACCEPTED or WIRE-01 fully passed until all gates pass.**
