# L-001I — Unified resource-policy SQLite journal (candidate)

**Stage:** signed and replay-verified persistence PoC; **NOT production admission**. Stacked on PR #14, with ADR-20/21 still PROPOSED.

## New atomic journal

`loom-store::unified_policy_journal` adds a **separate** SQLite schema and writer-thread actor for a single, ordered Resource Policy Chain:

- `unified_policy_events`: every signed delegated revocation, Owner-signed delegate cancellation and dual-signed Owner transfer, stored with exact sequence, kind, canonical evidence and policy-chain head
- `unified_policy_cursor`: sequence, computed policy-chain head and current Root-signed Owner manifest commitment
- `unified_policy_outbox`: critical event evidence, durably written in the same SQL transaction with a fixed monotonically increasing sequence
- `unified_policy_audit`: same sequence, kind and hash for forensic diagnostics, also in the same transaction

Each mutation begins `BEGIN IMMEDIATE`; under a single serialized database writer it **fully replays** all preceding signed evidence from the externally supplied, Root-verified genesis manifest, verifies contiguous versions and stored hash heads, then validates the proposed operation via `ResourceOwnerLifecycle`, commits all four tables and only then acknowledges the local write. SQL uses WAL + `synchronous=FULL`, strict typed fields and bounded evidence. Failing an Outbox insert rolls back policy epoch, event and audit together.

## Signed evidence

- Revocation: the L-001F two-signature Owner-delegation + signed revocation envelope, re-verified on replay.
- Delegate cancellation: fixed candidate `LOOM:DELEGATE-CANCEL:V1\0` transcript + Owner signature, replaying exact canceled key ID and key epoch.
- Owner transfer: fixed candidate `LOOM:OWNER-TRANSFER:V1\0` transcript, both Owners' signatures, plus the Root-signed successor resource manifest transcript and its signature. The replay verifier resolves the successor under the *externally* pinned Root, never from an unsigned database claim.

No event can skip a sequence. A later Owner/delegate revocation with valid but canceled credentials is rejected, including after process restart. Outbox has no public ACK operation; remote durable receipts and delivery fairness are missing.

## Tests

- Positive: revoke(1) → cancel delegate(2) → transfer Owner(3) → successor revoke(4), then close/reopen and replay every historical signature, Owner change, chain head and Outbox
- Negative: canceled delegate tries next sequence, old Owner tries after transfer, forged successor manifest, substituted Root, altered persisted evidence, competing concurrent writers
- Failure injection: SQLite Outbox trigger aborts INSERT; event, cursor, audit and outbox all roll back atomically; later retry succeeds
- Production service admission remains `Paused` at all times

## P0 blockers / NO-GO

1. **No production migration** from the old `sqlite_revocation` revocation-only schema/checkpoint hash to the new three-kind unified chain. Both candidate modules remain separate. No runtime ServiceOpen consumes this journal.
2. **No atomic external high-water CAS in the new journal.** The current high-water provider interface has no real OS/hardware implementation; local SQL alone cannot prove non-rollback.
3. **No secure time, currently witnessed/cross-device policy freshness or authenticated initial Root-pin provisioning.** Historical replay validates events at their signed issue-time, not whether they are globally newest; offline signed cancellations require independent anti-rollback witnesses.
4. The historical chained evidence is a candidate binary format, not standardized across Rust/Go/Kotlin/JS. Domain tags, replay semantics, transfer recovery and event-lifetime policy need review and conformance vectors.
5. Crash-injection coverage is limited to SQL transaction failure, not power loss/kill-9, disk corruption, multi-process race across different SQLite backups or witness eclipse.

**Important:** A successful `append` or `inspect` returns *only* an internally consistent local diagnostic. This code does not enable proxy, P2P Relay, VPN, file sharing, RDP or any network listener.
