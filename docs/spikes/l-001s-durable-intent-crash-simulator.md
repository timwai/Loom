# L-001S — simulated durable Prepared-intent crash protocol

**Status:** experimental, unmerged Rust **deterministic media simulator**, stacked on L-001R / Draft PR #25. **NOT a real persistent store, hardware enrollment or TPM NV implementation. NO ServiceOpen.**

## Why this gate exists

L-001O–R tested the TPM counter and policy-intent crash protocol with simple in-memory fakes. They did not model the difference between a process-local write, an acknowledged durable Prepared intent and an **irreversible counter increment**. When power cuts occur in these boundaries, a single error return cannot distinguish whether the durable write already took effect.

L-001S adds `crates/loom-store/src/durable_intent_simulator.rs`. The model has **two logically independent persistent variables**:

- `disk: StoredBinding` represents a hypothetical authenticated durable intent medium; `pending` represents volatile data staged *before* a pretend synchronization barrier. Only `disk` survives simulated reboot.
- `nv_counter: u64` represents an independently monotonically advancing device count. It survives reboot and **does not** roll back when an old intent backup is restored.
- `generation` invalidates stale pre-crash trait handles; `quarantined` prevents further I/O after an injected uncertain failure until an explicit reboot.
- The simulator implements existing `CandidateMonotonicCounter` and `CandidateIntentStore` traits, so L-001R's signed journal-bound prefix gate works unchanged. It rejects a counter increment if the **durable** (not merely pending) intent is not `Prepared`.

This abstraction has no cryptographic key, flash storage, real sync, TPM2 protocol, attestation, physical anti-rollback security, authorization token, or production admission API. The word *durable* always means **survives the simulator's restart operation**, not verified real-world durability.

## Fault-injection matrix

| Cut location | What survives simulated reboot | Safe journal-bound behavior |
|---|---|---|
| PrepareBeforeWrite | Committed(old), counter N | No durable next intent; never infer current policy from number alone |
| PrepareBeforeSync | Committed(old), counter N; staged state lost | No NV change; explicit new Begin needed |
| PrepareAfterSync | Prepared(old,next), counter N | `IntentBeforeIncrement`; never automatic increment |
| IncrementBeforeWrite | Prepared(old,next), counter N | `IntentBeforeIncrement`; never automatic increment |
| IncrementAfterWrite | Prepared(old,next), counter N+1 | Verify matching signed current Witness, saved old signed-prefix and finalize |
| FinalizeBeforeWrite | Prepared(old,next), counter N+1 | Same signed reconciliation required |
| FinalizeBeforeSync | Prepared(old,next), counter N+1; volatile finalize lost | Same signed reconciliation required |
| FinalizeAfterSync | Committed(next), counter N+1 | Numeric and **full policy** match; never increment again |

Additional tests cover no increment without durable `Prepared`, incorrect/stale finalize, stale pre-reboot trait handles, deliberate restore of an old untrusted intent image while the counter remains newer, Witness substitution at recovery, and SQLite Audit tampering while a pending post-increment recovery exists.

### Tests

The simulator itself has four deterministic media tests (including an eight-cut matrix), and the real `UnifiedPolicyJournal` harness has three integration tests against an independently supplied Root, replayed signed lifecycle and two Root-selected Witness receipts (including the eight-cut matrix). Those tests assert **zero automated NV re-increments on restart**.

CI contract (on the final PR head):

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
cargo deny check
```

## Critical security limits and next work

1. There is still **no independently authenticated durable intent store**. Merely persisting intent in an ordinary filesystem/SQLite file does not prevent malicious rollback, cloning or counterfeit records, and the current `Arc<Mutex<Medium>>` is **volatile process memory**. We are testing **protocol behavior**, not durability, attestation or real power-loss ordering.
2. The integrated L-001Q transaction holds SQLite `BEGIN IMMEDIATE` across the model operation. **Do not call real slow TPM I/O inside that transaction**. A reviewed real design must implement process/global serialization without an unbounded DB lock, separate protected intent I/O and race-safe snapshot revalidation.
3. The model currently enforces one successful +1 per durable `Prepared`, but does not provide authenticated enrollment, multi-resource shared TPM scheduling, secure counters under hardware reset, NV wear/quota semantics, secure time, witness global freshness or real-file anti-tearing guarantees.
4. A full rollback of the unprotected simulated NV variable *and* intent record is impossible by ordinary `restore_untrusted_intent_for_test` but **possible to an attacker who controls model process memory**. Never present this as a security certification.
5. No admission permit, Peer Mesh listener, proxy, file sharing, VPN or `ServiceOpen` is enabled. Keep stacked Draft PRs unmerged.

**Proposed next gate L-001T:** platform-independent authenticated-intent record framing, serialization/version/canonical validation and cryptographic MAC/signature verification with **externally provisioned key or hardware-sealed key assumption**; model record corruption, split-brain, rollback and key rotation, without using ordinary SQLite content as a root of trust.
