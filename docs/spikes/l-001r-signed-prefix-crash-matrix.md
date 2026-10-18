# L-001R — signed historical-prefix proof and counter crash-state matrix

**Status:** unmerged Rust Security PoC, stacked on L-001Q (PR #24). No TPM NV writes, trusted Prepared store, authenticated platform enrollment, usable Mesh or ServiceOpen.

## What was missing

L-001Q compared the *latest* dual-signed Witness checkpoint against the *latest* replayed SQLite journal state, then passed a caller-independent-but-still-**untrusted-model** `Committed` record to L-001O. Its `checked_unified_promotion` checked scope, root, writer and decreasing versions but did not prove that **the previous committed policy head, revocation root and Owner manifest at sequence N** belonged to the authenticated history that led to sequence N+k.

An attacker or broken restore process could therefore provide a valid latest signed checkpoint paired with a false historical `policy_head` or Owner/revocation commitment in the counter's local intent model. An acceptable latest state does not make that prior state genuine.

## New fail-closed prefix validation

The journal-bound operation obtains the currently saved `Committed.policy` or the `Prepared.before.policy` and calls `verify_signed_policy_prefix` **before** the candidate `prepare`, `increment` or `finalize`. It:

1. Requires exact Space, Resource, Root public key and epoch, authenticated genesis manifest and writer epoch; refuses an unrepresentable signed-DB sequence.
2. Within the same SQLite `BEGIN IMMEDIATE` that already verified the **entire** signed chain, cursor and Audit/Outbox parity, replays every signed lifecycle event from independently selected genesis **up to exactly the old policy sequence**. Verifies sequence continuity and each stored policy head during replay.
3. Independently accumulates only signed revocation evidence to the prior revocation root; cancellation and Owner transfer affect the policy head, not the revocation-only accumulator.
4. Compares the exact historical policy head, revocation root and contemporaneous Owner manifest against the saved prior counter record. Absent history, wrong Owner, missing sequence, forged head and forged revocation root fail closed **without touching the counter**.
5. Retains L-001Q's full-current-state Witness comparison and post-operation counter/current-policy equality check. Neither result is a network permission.

This is a **proof of consistency with the currently authenticated signed journal**. It is **not** proof that the external counter record was written by trusted hardware or that the journal is globally freshest.

## Crash and restart acceptance table

| Persisted candidate state | Counter observation | Expected action |
|---|---|---|
| Committed, exact counter | Exact signed prior prefix, latest checkpoint same | Diagnostic match or one new Begin if newer checkpoint and safe |
| Committed, different counter | Any | Refuse / quarantine; never adopt SQLite backup to counter |
| Prepared(before, next) | Equal to before | `IntentBeforeIncrement`; no automatic second increment, no finalization |
| Prepared(before, next) | before + 1 | Recheck same signed latest checkpoint **and** exact signed before-prefix; only then finalize modeled intent |
| Prepared(before, next) | Any other counter | Reject; no state rewrite or silent reset |
| Missing prior intent | Any | Reject; never import a replacement anchor from SQLite |
| Counter read/increment/finalize error | Outcome unknown | Fail closed; do not equate error with no increment |
| Signed latest checkpoint valid but prior head/root/manifest forged | Any | Reject **before** candidate counter modification |
| Valid next checkpoint but Owner transfer happened before prior seq | Any | Prior manifest must match the then-current Root-signed successor Owner |

## Deterministic test evidence

Six additional targeted tests cover: (1) forged prior policy head with valid latest dual Witness signatures, (2) forged prior revocation root and Owner manifest, (3) positive signed prior revocation followed by cancellation, (4) signed Owner transfer requiring *historical* successor manifest, (5) Prepared before increment never auto increments, and (6) missing intent and increment overshoot on restart. These supplement seven L-001Q journal-bound tests.

## Production NO-GO and next step

- **No durable authenticated Prepared store** is implemented. This run intentionally uses volatile model fakes. A real adapter must bind its full record to an independently authenticated, non-rollback identity and durable atomic protocol; writing the intent only to the same SQLite DB is insufficient.
- **No physical TPM counter** is incremented. No NV index provisioning, reset/re-enrollment or TPM device attestation. Counter limit, wear, secure clock, policy authorization and firmware properties remain untested.
- The `BEGIN IMMEDIATE` barrier models one SQLite snapshot for unit tests; hardware I/O under a long SQLite write transaction is **not** an approved production design. Before hardware code, separate durable intent I/O, process serialization, exact failure semantics and timeout behavior must be security reviewed.
- An attacker rolling back the entire signed SQLite database together with an unprotected fake counter/intent state remains out of scope. Root pin and witness independence are external assumptions; signature checks alone do not prove global freshness.
- Production admission, VPN, proxy, relay, file access and ServiceOpen remain disabled. Keep this PR Draft and stacked; do not merge directly to `main`.

**Proposed next gate L-001S:** implement a simulator of the durable authenticated Prepared-store interface with *explicit fault injection at every protocol boundary* and a hardware enrollment specification. Keep it separate from production authorization, and do not mistake volatile or filesystem-only mocks for anti-rollback persistence.
