# L-001X — short-transaction signed-journal preflight and second revalidation

**Status:** Rust diagnostic PoC stacked on L-001W / Draft PR #30. This is NOT an approved hardware commit protocol. **NO ServiceOpen, no physical TPM NV writer, no independently protected signer/fence CAS, no deployable Mesh.**

## 1. Problem and bounded milestone

The older `UnifiedPolicyJournal::inspect_journal_bound_counter()` implementation holds a SQLite `BEGIN IMMEDIATE` while invoking candidate `IntentStore::prepare()`, `CandidateMonotonicCounter::increment()` and `IntentStore::finalize()`. That is acceptable **only as a synchronous in-memory consistency experiment**. It cannot be used for a slow external TPM, remote signing service or independent durable medium: I/O can hang or return ambiguously while SQLite retains a global writer lock.

L-001X adds **a separate optional proof/coordination path** without replacing the older transaction or claiming cross-medium atomicity.

## 2. Public Rust API

`crates/loom-store/src/unified_policy_journal.rs` now exposes:

- `CandidateJournalPreflight` — opaque-value journal proof with **private** fields: a signed replay-validated policy snapshot; prior `UnifiedPolicyHighWater` from the caller's independently authenticated record; exact Root-selected two-Witness checkpoint; and current manifest commitment. It contains no private signing key and is **never a capability to open a service**.
- `UnifiedPolicyJournal::preflight_candidate_journal(root, genesis, receipts, now_ms, prior)` — runs a **deferred, short SQLite transaction**: replay all signed Root/Owner events; audit/cursor/outbox mirror parity; validate two signed Root-selected Witness receipts against current sequence, policy head, revocation root, witness keys and writer epoch; replay the exact historical signed prefix for `prior`; then **commit and return**, releasing the SQLite transaction and the actor.
- `revalidate_candidate_journal(..., expected)` — repeat all the checks under a **new short transaction**, then compare the entire opaque proof with the earlier snapshot. Changed Owner, current policy head, signed history, manifest, revocation root, Receipt, or old prefix => reject.
- `coordinated_candidate_prepare_probe(..., external_step, model_publish)` — glue for **model-only** workflows: preflight; invoke potentially slow `external_step` **outside** SQLite transaction and journal actor gate; revalidate; call the supplied **model publisher** only if still identical. The publisher is intentionally injected and not a trusted production CAS implementation.

The separate `CandidatePreflight` command executes only journal replay and verification on the SQLite actor, and returns an immutable `CandidateJournalPreflight`. The application calling the coordinator waits for its external step without holding the database transaction or the actor-wide gate, permitting another journal append during slow signing. A stale candidate is refused **before** the `model_publish` callback starts.

## 3. Adversarial tests (six additional Rust tests)

| Situation during the external signing interval | Expected result |
|---|---|
| Separate SQLite connection requests `BEGIN IMMEDIATE; ROLLBACK;` | Acquires writer lock, proving no SQLite transaction spans external callback; stable proof permits a modeled signed Prepared CAS |
| Signed Owner cancellation appends a new journal sequence | Fresh replay/checkpoint differs; no model publish, no fence or NV increment |
| Signed dual-owner transfer changes current Owner manifest | Reject stale witness/snapshot; no Prepared write |
| SQLite Audit mirror row deleted through separate connection | Mirror parity check fails; no Prepared write |
| Incorrect Witness checkpoint or forged old historical prefix | Reject **before** external signer runs; no publish |
| External signer refuses or times out | Return error, leave existing signed record/fence/counter unchanged; matching proof independently revalidates |

Tests use the inherited L-001V **in-process authenticated CAS** as a model publisher. A successful Prepared CAS in the model is **not** a real durable commit and never increments real NV.

## 4. CRITICAL race that remains unsolved

The second journal validation returns **before** a separate physical durable Prepared CAS. There is still a **TOCTOU gap**: an adversary may append a new signed policy immediately *after* `revalidate_candidate_journal` and *before/during* `model_publish`.

L-001X's acceptance claim is strictly:

> If the journal (or its mirrors) changes **during** the external signing step, revalidation detects the change and the model publisher is not called.

L-001X **does not** claim:

> A successful revalidation prevents further journal changes until the physical CAS completes.

In fact, a production-grade design must use a separately authenticated, linearizable reservation/fencing mechanism that covers **both** journal evolution and external CAS, or reject/repair all Prepared intents made stale by a later signed policy. An ordinary SQLite mutex cannot furnish atomicity with a real TPM or external fence. A forged prior supplied by the caller also must be stopped at the independently authenticated signed-intent read gate (L-001U) before reaching preflight. The API's own signed prefix check is additional defense.

Other unresolved requirements: independently pinned nonrollbackable fence and device identity, hardware protected signer enrollment/rekey, physical power-cut ordering, cross-process/host writer exclusion, secure witness freshness and anti-eclipse policy, verified admission and session revocation.

## 5. Release and next gates

- Existing L-001Q/R long transaction path is **still in the repository**; never attach it to real blocking hardware I/O. No production workflow switches to L-001X automatically.
- All PRs remain stacked and Draft. `main` is still README-only.
- **L-001Y proposed:** build a two-phase **reservation/revalidation** model with a separately versioned journal writer fence that can be atomically invalidated by policy append; ensure the model refuses Prepared CAS **even when the policy changes after the second short transaction**. Then formalize device replacement/repair before any hardware validation.
