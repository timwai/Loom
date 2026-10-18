# L-001Y — Versioned Journal Reservation / Prepared CAS Fence (in-process model)

> 2026-10-18. **Status: SECURITY_ENGINEERING_POC.** Stacked on L-001X / Draft PR #31. No hardware TPM NV writes, no trusted persistent replay-fence, no production journal-to-CAS atomicity, no network admission, and **NO ServiceOpen**.

## Why L-001X was insufficient

L-001X reduced the time SQLite held an open transaction to two short preflight and revalidation windows, allowing an external signer to run without holding the journal actor's database writer lock. But this left a **time-of-check/time-of-use gap** between the second signed journal replay and the caller's separate `Prepared` CAS.

L-001Y defines a **strictly process-local** versioned reservation model that closes that exact race for **policy appends routed through the same `UnifiedPolicyJournal` instance**. This is NOT a complete multi-process, multi-medium or physical TPM solution.

## New in-memory state and API

The journal's existing actor-wide `gate` mutex now contains `CandidateJournalGateState`: a process-unique journal instance number, monotonically increasing signed-append generation, one-shot ticket sequence, at most one outstanding reservation, and two diagnostic quarantine flags (`prepared_unreconciled` and `stale_prepared`).

- `reserve_candidate_journal(request)`: while holding the *same local gate as append*, run L-001X short SQLite deferred transaction replay, mirror parity, Root/Owner history, exact authenticated old-policy prefix, two Root-selected Witness signatures and checkpoints. Return an opaque `CandidateJournalReservation` containing the instance, generation, ticket and signed preflight. **External signing has not begun**. A competing reservation is rejected.
- **Unlocked signer phase**: the application obtains the already-authenticated old signed intent / independent counter and signs a proposed `Prepared` record *outside* SQLite transactions and outside the journal gate. This model makes no promise about how the real external trust medium is provisioned.
- `append(...)`: successful signed journal append **increments the in-process generation and invalidates the outstanding reservation**. Invalid signed evidence or a failed append does not consume it. New policy/revocation events remain appendable even if an earlier Prepared has already been published; later appended policy marks that modeled Prepared stale.
- `commit_candidate_reservation(request, token, prepared, model_publish)`: obtains the **same journal gate used by append**, demands exact journal instance/ticket/generation and prior policy, burns the one-shot ticket, repeats the full signed journal/Witness proof in a fresh short transaction, then runs the injected **in-memory** Prepared CAS callback before releasing the gate. **The SQLite transaction has already ended when the publisher runs.** The callback must not reenter the journal actor; a successful CAS records `prepared_unreconciled=true`. An ambiguous error also sets the quarantine flag; neither event ever grants admission.
- `cancel_candidate_reservation(token)`: burns only a matching outstanding ticket and advances the local generation.
- `candidate_reservation_health()`: reads two **nonpersistent diagnostic booleans** (unreconciled, stale). They cannot be used as production authorization or durable anti-rollback evidence.

A ticket is NOT a transferable cryptographic capability. Its contents, counters and locking are only valid for one process lifetime / journal object; after restart the signed frame and trusted device counter must be independently re-enrolled and recovered.

## Precise concurrency property demonstrated

For the same `UnifiedPolicyJournal` process instance, a policy append and a ticket commit share one lock:

- **Append before commit lock:** signed journal append is committed and advances generation; the old reservation cannot reach `model_publish` even if a separate L-001X revalidation had passed immediately before append.
- **Append after commit lock:** the commit validates the complete signed journal and performs the **model** CAS before the append can run. This excludes appending **between the final replay and the in-process model CAS**.
- **Append after Prepared CAS:** emergency revocation is still allowed; the prepared intent is marked **stale/quarantined in memory**, so new reservations fail until signed independent recovery. Never block revocation indefinitely while waiting for a TPM or signer.

Crucially, this does **NOT** serialize direct SQLite connections, a second `UnifiedPolicyJournal::open()` instance, other processes/hosts, a remote signer, physical TPM writes or independently persistent fence CAS. An uncoordinated database writer may still update immediately *after* the final check and *before* publication. Existing two-phase physical journal/fence/counter atomicity, global Witness freshness and crash-safe reservation state are unsolved **release NO-GO gates**. The model lock during `model_publish` can also delay same-instance appends if that callback blocks; **never install a slow/hung hardware publisher in this path**.

This PR does **not** replace or enable the legacy in-transaction L-001Q candidate path. That path must not be connected to real TPM I/O.

## Eight new adversarial tests

1. Healthy reservation: separate SQLite connection can obtain `BEGIN IMMEDIATE` **during signing**; the final journal replay and injected simulated CAS publish Prepared at the expected fence.
2. **Adversarial append after a separate second revalidation:** the signed cancellation advances local generation; the old ticket is refused before the model CAS.
3. Second writer is rejected while the ticket is outstanding; canceled token cannot be reused and old token cannot override a later reservation.
4. A raw SQLite Audit mirror deletion between reserve and commit causes strict replay to fail; the model CAS is never invoked.
5. Publisher returns ambiguous persistence failure: one-shot ticket is burned, no second reservation and explicit signed recovery is required.
6. A different journal instance sharing the same database cannot commit the original instance's ticket.
7. A signed revocation appended **after** a modeled Prepared commit still goes through, but marks the prepared state stale and blocks new reservations.
8. Two threads coordinate a signed journal append attempt **during final revalidation-to-CAS window**; the append cannot finish before the in-memory publisher, and the post-CAS append sets stale quarantine.

Inherited L-001X checks still cover mid-signing Owner transfer, policy changes, Witness mismatch, signed history prefix forgery, Audit mirror tamper and external signer refusal.

## Production security acceptance blockers

1. Replace process-local mutex/generation with an independently authenticated, persistent, cross-process **journal evolution vs external Prepared CAS fence**. Define linearization, ordering, idempotence, signed cancellation and recovery proofs under any combination of power loss, TPM clear, device swap, backup rollback, signer rotation and remote writer.
2. Persist and authenticate reservation state or refuse all new operations after crash until externally attested and signed full-history reconciled state is established. A process restart currently destroys the model's diagnostic quarantine.
3. Model a signed revocation that arrives **after** a Prepared publication while TPM counter N/N+1 is ambiguous. Admission must fail closed and signed emergency revoke must not be starved.
4. No SQLite transaction may await real TPM/keystore/network operations; no long-lived per-process mutex held around potentially hanging hardware calls. Use a real independently fenced CAS primitive or change the protocol.
5. Independent signer key protection, dual Root-selected Witness anti-eclipse freshness, device attestation, secure time and verified handshake-to-policy-to-session shutdown remain missing. **No ServiceOpen, no production Peer Mesh**.

**Next L-001Z proposed:** model cross-process/external-connection adversaries and independently durable reservation records with explicit crash ordering; prove the limitations of a local gate and define real-platform acceptance tests. No hardware writes without security sign-off.
