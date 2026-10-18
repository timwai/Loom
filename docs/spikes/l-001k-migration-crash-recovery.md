# L-001K: explicit legacy migration gate and post-anchor-CAS confirmation

**Status:** fail-closed engineering PoC. Stacked on L-001J PR #17. **Not an approved migration or production recovery path.**

## No silent legacy migration

The original L-001C `policy_versions`, `revocations`, `critical_outbox`, and `security_audit` schema describes revocation-only epochs and domain-separated roots. The new L-001I unified policy journal adds delegate cancellation and Owner transfer to one policy sequence. **These histories are not interchangeable.** The `legacy_migration::inspect_legacy_migration_gate` audit is *read only*: it identifies any of those legacy tables and reports their count, even if empty. `UnifiedPolicyJournal::open` now rejects a SQLite database containing any legacy schema **before** creating `unified_policy_*` tables. A partially present schema or even an empty legacy schema is a hard-stop; an old external high-water could still exist outside that local file.

No automatic copy of legacy bytes, epoch rebase, checkpoint substitution, or destructive table drop exists. Converting old records requires a separately security-reviewed explicit one-way process that replays all signed history from independently pinned genesis, proves no missing grants/revocations, witnesses a *new* domain-separated unified checkpoint and migrates independent high-water and policy grant states atomically or through a recoverable protocol.

**Scope:** This gate is applied when a legacy schema resides in the *same SQLite file* opened by the unified journal. It cannot discover an old database in another path/device or establish that no external legacy high-water exists. Discovery/installation and multiple-backup migration remain P0 blockers.

## Partial commit reconciliation

The external anchor and SQLite cannot be atomically committed together without an additional reviewed coordination protocol. After a fully verified, dual-signed `Checkpoint` matches SQLite's replayed unified history and the independent anchor confirms durable compare-and-advance, L-001K writes `unified_policy_witnessed`: `(space,resource,seq,policy_head,revocation_root,owner_manifest)`.

The confirmation write runs in a *second* `BEGIN IMMEDIATE` transaction. It **replays all signed journal evidence again**, recomputes the separate revocation accumulator and checks exact checkpoint sequence, both hashes and current manifest before recording confirmation. It cannot mint a ServiceOpen permit. If SQLite confirmation fails **after** successful external CAS, the method returns failure rather than claiming candidate consistency. On restart a caller can repeat the same signed witness verification and external anchor compare-and-advance, then restore the missing confirmation. The new marker is local bookkeeping, not trusted authority: an attacker can restore or tamper it alongside the SQLite DB. Any future real admission decision MUST still query and validate independent high-water and freshness.

Tests inject SQLite trigger abort after successful external CAS, assert high-water advance with absent SQLite confirmation, reopen DB and retry. Also test no marker before witnessing, hard rejection of legacy tables without modifying rows, no confirmation after ambiguous external CAS, and paused admission throughout.

## Remaining No-Go

- Independent `IndependentUnifiedPolicyAnchor` remains an **interface with in-memory test doubles only**. No trusted OS monotonic provider, secure Root-pin enrollment, hardware test, or power-loss barrier exists.
- This implementation does not automatically stop policy appends after a witness confirmation failure; it remains a diagnostic-only system where **production admission is permanently Paused**. A future ready-state engine must enforce witnessed/anchored freshness *before* opening any resource and cancel active sessions on invalidation.
- Confirmation records are not a full two-phase distributed commit protocol. Crash between SQLite commit and external anchor persistence, partial multi-device delivery, malicious witness replay/collusion and storage equivocation require further failure-state classification and actual trusted hardware integration.
- No programmatic legacy re-encryption/normalization, cross-language vectors, user migration UI or production cut-over is performed. L-ADR-20/21 remain PROPOSED.

**Never interpret passing CI as evidence that live Mesh security, ServiceOpen, VPN, proxy, file sharing or remote control is enabled.**
