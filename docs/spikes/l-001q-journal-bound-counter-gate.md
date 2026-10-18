# L-001Q — journal-bound candidate TPM counter gate

**Status:** isolated Rust security-engineering PoC, stacked on Draft PR #23 (L-001P). **No hardware counter writes, trusted intent backend, network authorization or ServiceOpen.**

## Problem

L-001O's standalone `begin_candidate_advance` and `reconcile_candidate_advance` accepted a `VerifiedResourceTrust` argument from the caller and verified Root-approved witness signatures, but did **not** establish that the *same* signed checkpoint matched the complete persisted, current unified SQLite policy history. A caller could use forged/stale/partial SQLite state or mistake an ordinary counter numeric match for a fully replayed policy match.

L-001P restores event/Outbox/Audit parity but alone does not link the TPM-model state machine with one atomic SQLite inspection window.

## Implemented

- `UnifiedPolicyJournal::inspect_journal_bound_counter` accepts externally pinned Root and verified genesis, two signed witness receipts and **candidate I/O traits** (`Arc<dyn CandidateMonotonicCounter>` and `Arc<dyn CandidateIntentStore>`). The caller cannot supply a standalone current Owner trust: it is derived from replaying all signed SQLite Owner/delegate/revocation/transfer events.
- The actor runs `BEGIN IMMEDIATE`, replays signed events, checks full mirror parity and cursor, recomputes revocation-only accumulator and verifies the exact signed witness sequence, policy head, revocation root, resource/writer scope, and unchanged Root-selected witnesses. All must match **before** candidate counter staging/increment.
- While the SQLite write lock and journal append mutex are still held, run either a **single** candidate begin or a **reconcile** operation from L-001O. Errors after increment remain ambiguous; no auto-retry.
- Even a candidate `MatchingCounterOnly` result is rechecked against the *complete* replayed Root, manifest, writer, sequence, full policy head, revocation root and observed pinned counter. This specifically rejects a pre-existing number match with an obsolete local policy.
- Deterministic in-memory tests cover exact signed revoke+cancel state, forged/mismatched checkpoint head/root/seq, corrupted Audit parity, lost counter acknowledgment followed by exact signed recovery, second SQLite writer blocked during increment, numeric match against stale committed policy, and Owner transfer manifest binding.

## Verification

Run on the final branch head:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
cargo deny check
```

GitHub Actions passes only prove these model properties under deterministic CI, **not** physical TPM safety or real power-loss durability.

## Explicitly NOT solved

1. This method **does not establish independent trust**. Both candidate I/O implementations exist only in volatile test fakes; there is no production NV writer, provisioned TPM identity, authenticated durable Prepared journal, platform policy or physical-device attestation.
2. SQLite `BEGIN IMMEDIATE` prevents a *cooperating normal SQLite writer* from mutating that DB while the transaction is held. It does not prevent external filesystem corruption, privileged attackers, machine rollback, witness collusion/eclipse, or power loss. Neither local parity nor a bare counter number proves global freshness.
3. Holding a SQLite write transaction across external I/O is **a deliberate model-test barrier** and unsuitable as a production TPM architecture. In particular, an intent store backed by the **same SQLite connection/database** can deadlock. Before real TPM operations, design a separate durable, independently authenticated intent store with explicit process locking, bounded timeouts, crash protocol, high-water prefix proofs and failure classification.
4. The old revocation-only journal remains incompatible with unified policy sequence/hash domains and must not be auto-migrated. Device reset, counter wear/quotas and secure clock policy remain open.
5. `Diagnostic::MatchingCounterOnly` is **never a ServiceOpen or dispatch permit**. No file service, Mesh listener, VPN, relay, proxy or desktop access is created. All release gates remain NO-GO.

## Next engineering gate

L-001R should supply durable, independently authenticated intent-state and counter enrollment on sacrificial hardware **after** security review, plus an executable power-failure/restart acceptance matrix. It must not silently substitute ordinary local SQLite as a trusted anchor.
