# L-001J — Unified journal mirror integrity (candidate)

**Stage:** local SQLite consistency hardening, stacked on L-001I PR #15. Not a production admission gate.

## Gap addressed

L-001I replay-verified the signed policy event stream and authenticated Owner lifecycle, and compared the saved cursor against that replay. It did **not** verify that the durable Outbox and Audit rows still exactly matched each persisted event. Missing/modified/extra mirror rows were therefore not detected by `inspect()` or `append()`; `pending_outbox()` could return a corrupted queue.

## Changes

- A cross-resource check requires exactly one Outbox and one Audit row for **each** event, matched by (SpaceId, ResourceId, sequence).
- It compares event kind, exact evidence bytes (Outbox), and exact policy head (Audit), and rejects both missing and orphan mirror rows.
- The signed-history replay must pass parity verification before `inspect()` returns a diagnostic or `append()` proceeds. `append()` repeats the parity check **after all four writes and before COMMIT**, catching successful SQL trigger side effects and rolling the entire transaction back.
- The read-only `pending_outbox()` runs mirror verification and the read inside a single `BEGIN IMMEDIATE` SQLite transaction. It never acknowledges delivery or produces a `ServiceOpen` permit.
- Fail-closed negative tests inject deleted, modified, extra, and orphaned rows without changing the signed events; all three public operations must reject. Another test injects a trigger that silently rewrites Outbox evidence after Audit insertion and verifies atomic rollback. Existing valid lifecycle and atomic Outbox transaction tests must continue to pass.

## Explicit non-guarantees / NO-GO

1. **Not anti-rollback:** if an attacker rolls back events, cursor, Outbox and Audit **together**, local equality still succeeds. No independent high-water CAS/witness, secure clock or trusted monotonic provider is integrated into this journal.
2. **Not dispatch authorization:** `pending_outbox()` checks only cross-table agreement and does **not** independently authenticate Root pins, event signatures or current Owner policy. It must remain an internal diagnostic; callers must not deliver or admit a resource based on this output alone.
3. **Not crash proof:** no power-loss, kill -9, disk-corruption or multi-process Byzantine validation is claimed. An external writer with live SQLite access can still interfere outside an individual transaction.
4. The whole-table mirror check is O(n) per replay/append and has no bounded checkpoint/retention policy. This is deliberately conservative in the PoC, not a performance optimization.
5. The legacy revocation-only journal and the unified lifecycle journal still coexist as separate candidate modules. Signed migration, external witness freshness, secure Root pin provisioning, durable remote receipts and actual session cancellation remain unimplemented.

**Runtime remains PAUSED.** No P2P listener, proxy, RDP, VPN, relay or file-sharing service is enabled by this change.
