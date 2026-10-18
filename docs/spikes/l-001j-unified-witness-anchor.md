# L-001J — Two-witness unified policy-head + external high-water recovery

Status: engineering **diagnostic PoC**, stacked on L-001I PR #15. **No production admission, no real external independent anchor, no released wire compatibility.**

## Security boundary

The unified policy journal mixes exactly three signed event types: resource revocation, Owner-signed delegate cancellation and dual-signed Owner transfer (plus Root-signed successor manifest). L-001J makes the distinction between two domain-separated digests explicit:

- `Checkpoint.head_hash` commits to the **entire unified resource policy sequence**, using `LOOM:RESOURCE-POLICY-CHAIN:V1\0` from L-001H. It MUST change on delegate cancellation, Owner transfer and resource revocation.
- `Checkpoint.revocation_root` commits only to signed resource revocations, using `LOOM:REVOKE-CHAIN:V1\0`, with the event's **global policy sequence** (not an independent revocation-only index). Owner transfer and delegate cancellation do not change this accumulator.
- `Checkpoint.seq` refers to the **unified policy sequence**, not the earlier revocation-only SQLite epoch. Prior L-001C/L-001E checkpoints are NOT interchangeable. These are candidate semantics and need versioned wire negotiation before any real deployment.

The new `UnifiedPolicyJournal::inspect_witnessed_recovery` API:

1. Holds the same synchronous journal mutex used for signed appends; it cannot race a journal append within the same instance.
2. Verifies two distinct Ed25519 receipts through **Root-authorized genesis witness keys**, including exact Scope, Writer epoch, signed head/root/seq and expiry checks.
3. Asks the single SQLite writer to **replay all persisted signed control and data events from Root-signed genesis** inside `BEGIN IMMEDIATE`. Revalidates each event signature and each stored policy head/cursor; computes revocation-only accumulator separately. Replays transferred Owner manifest from Root-signed successor evidence and rejects changes to witness keys absent a separately reviewed migration.
4. Requires local sequence and both digest roots to match the signed checkpoint. Distinguishes `LocalBehind`, `WitnessBehind`, `HistoryConflict` from a candidate match.
5. Reads an **externally authenticated** `UnifiedPolicyHighWater` record, bound to Space, Resource, Root key/epoch, genesis manifest commitment, *current* Owner manifest commitment, Writer epoch, unified seq, unified policy head, and revocation-only root. Rejects older checkpoints, equal-sequence competing policy heads, or Owner-manifest equivocation. Uses atomic compare-and-advance, failing closed on unknown/missing/uncertain storage.

All outcomes are **diagnostic only**. A candidate match never returns a session permit or flips a resource to Ready.

## Test gates

- A signed revoked delegate at policy seq=1 followed by a signed cancellation seq=2 has **different policy heads** and the **same revocation-only root**. Both are checked.
- Two matching signatures over an older-but-valid pre-cancellation checkpoint **cannot restore** an old SQLite snapshot after an independent high-water record has advanced.
- Even two valid signatures cannot substitute a different policy head at an equal sequence while retaining the same revocation root.
- Missing independent high-water or uncertain CAS prevents a candidate match.
- Wrong witness signature/writer epoch, witness newer than SQLite, SQLite newer than witness, changed revocation root, and successor Owner transition are checked.
- Restart retains paused admission and replays the verified journal before matching an external signed checkpoint.

## P0 blockers

1. **No production implementation of `IndependentUnifiedPolicyAnchor` exists.** The provided mutex-backed test fake is in-process and is **not** rollback resistant. Ordinary file/SQLite, OS Keychain/Keystore snapshots and in-memory records are not proof of independent monotonicity.
2. **Signed checkpoint freshness cannot be guaranteed during eclipse/collusion, offline operation or secure clock rollback.** Authenticated witness distribution and required witness policy migration are unresolved.
3. **Old revocation-only SQLite/checkpoint schema migration remains unimplemented.** Explicit versioned one-way conversion from L-001C to unified L-001I and independent re-witnessing are mandatory.
4. **Crash atomicity across SQLite and independent anchor is not achieved**. The present API verifies/persists a high-water after *already durable* local journal events; if a failure happens between local SQL COMMIT and external anchor flush, recovery must reject or reconcile without enabling ServiceOpen. Power-loss, file-corruption, kill-9 and real hardware testing remain required.
5. No live network authorization, Android/macOS/Windows platform integration, bounded replay checkpointing, cross-language event conformance, or PR-stack security approval.

L-ADR-20/L-ADR-21 remain **PROPOSED**. Never merge this PR directly to main or claim production-ready rollback protection based on passing CI alone.
