# L-001ABC — verified revocation ingress, candidate PoC

This branch stacks on L-001C PR #8 and imports the *same* L-001B canonical CBOR candidate implementation from PR #6. It is not a production mesh and none of L-ADR-07, 20 or 21 are accepted.

**Security boundary:** `loom-crypto::signed_revocation` decodes the exact nine-field canonical security envelope, performs strict Ed25519 verification over the domain-separated signing transcript, enforces a caller-supplied pinned issuer key, SpaceId, key epoch and time range, and validates a fixed 49-byte revocation payload (`resource-id[16] || target-peer-id[32] || action-mask[1]`). Unknown fields, changed bytes, invalid signatures, invalid action masks and stale signer epochs reject.

Only `VerifiedRevocation`, which has no public constructor, can be passed into `SqliteRevocationStore::commit_verified_revocation`. It also checks SpaceId, ResourceId and policy sequence exactly against `previous_epoch + 1`. The durable outbox stores `u32_be(cbor_len) || cbor || signature[64]` rather than an unverifiable event body. The **old raw-byte SQLite commit trait is compiled only under cfg(test)**. No unsigned production commit path is exposed.

## What this does *not* prove

1. **PinnedIssuerForSpike is not a signed Owner authorization chain.** Anyone constructing it can designate a key. Production admission is still **PAUSED**; no resource open decisions become possible.
2. There is no verified revocation witness/root, independent rollback anchor, owner transfer, emergency-revoker delegation, policy-freshness check or dual-identity access control yet.
3. The candidate revocation payload and persistence envelope require independent Go/Kotlin/JS test vectors and review; the L-001B generic golden event's 3-byte opaque payload is *not* a typed revocation.
4. The caller-provided clock must not be treated as secure time. Event expiry applies only to this live-ingest prototype; offline delayed revocation replication requires a signed chain/replay policy independent of wall clock.
5. The sqlite actor is synchronous from callers; Tokio must delegate to a blocking pool. No networking enabled.

## Checks

- Existing `loom-wire` positive/negative canonical tests and Go/JS static signature vectors.
- Rust Ed25519 verification of the shared golden signature plus tamper/wrong key negative tests.
- Typed revocation valid/invalid signature, scope, issuer epoch, deadline, payload validation.
- Test-only SQLite witnessed admission, exact resource+seq binding, durable signed outbox persisted through restart.

**No-Go:** enabling ServiceOpen or accepting `PinnedIssuerForSpike` as a true Owner proof; merging to main while upstream PR #6/#8 and full security/fault tests remain unresolved.
