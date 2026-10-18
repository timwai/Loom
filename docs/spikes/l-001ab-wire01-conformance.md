# L-001AB — WIRE-01 four-language candidate corpus and L-001 release truth

**2026-10-18. Scope: candidate security-event framing and domain-separated signing input, NOT admission authorization, end-to-end interop release or protocol standardization.**

## What actually runs

The existing Rust `loom-wire::security_event` defines deterministic CBOR: exact map of keys 0..8, V1, kinds 1..5, Space ID 16 bytes, signer ID 32 bytes, bounded payload, shortest integers/lengths, strictly increasing expiry, no additional fields or trailing bytes. Signing transcript is ASCII `LOOM:SECURITY-EVENT:V1` + NUL + four-byte big-endian canonical wire length + the canonical wire event. It is not itself a signature.

New independent standard-library-only verifiers:

- `interop/wire01/go/main.go` — Go strict CBOR map reader and signing bytes
- `interop/wire01/js/check.mjs` — JavaScript/Node strict CBOR reader using `BigInt` for exact u64 semantics
- `interop/wire01/kotlin/Main.kt` — Kotlin/JVM strict reader with `ULong` and exact transcript
- `crates/loom-wire/src/security_event.rs` — Rust existing canonical encoder/decoder and two additional vector tests

All four use the same **three** checked-in independent positive golden byte streams and transcript vectors: ordinary Revocation V1, PeerKeyBinding with `u64::MAX` epoch and `2^53+1` sequence (detects JS-number precision bugs), and MembershipGrant with 24-byte payload and 2^32 boundary. In addition, each non-Rust reader rejects all truncated versions of the original vector and nine constructed negative vectors: indefinite map, wrong map count, duplicate key, unsupported version, invalid kind, tag, malformed signer length, trailing bytes and nonminimal integer. Rust retains its own golden encode/decode, truncation, bit-flip and malformed cases.

The `wire01-four-languages` GitHub Actions job **fails** if any toolchain or verifier check fails. The existing workspace Rust job remains independent; the corpus is not generated at test time by one language.

## Limits

This only proves canonical framing and transcript agreement on a **bounded static corpus**, not broad property-based differential fuzz, key-signature interoperability, byte-for-byte canonical *typed payload* conformance, multi-version negotiation, production wire protocol freeze or the four actual application clients exchanging messages. Never use a syntactically valid event as an authorization token.

## Explicit L-001 completion gate

`docs/acceptance/l001.json` enumerates all mandatory E2EE-01 / TLS-ID-01, WIRE-01, AUTHZ-RACE-01 / AUTHZ-CRASH-02 / ROLLBACK-01, and Android/Windows/macOS `PLATFORM-*` gates. The Python `scripts/l001_gate.py` checker rejects inconsistent or premature `state=complete` and has an optional `--require-complete` mode that fails until all nine checked gates and four externally reviewed evidence files are present. The normal CI job verifies **truthful milestone reporting**, not the release itself.

No physical TPM NV writes, independently authenticated monotonic replay fence, admission, real OS drivers or `ServiceOpen` are enabled by this PR. The stacked PR must remain **Draft and unmerged** until the full dependency chain is security-reviewed.
