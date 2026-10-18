# L-001Z — independent-writer postflight and mandatory NO-GO demonstrations

> 2026-10-18. **SECURITY_ENGINEERING_POC / NO_SERVICE_OPEN / NO_REAL_TPM_NV_WRITES**. Stacked on L-001Y Draft PR #32.

## Result

L-001Y serialized *one `UnifiedPolicyJournal` instance's* append versus simulated Prepared CAS. Its process-local mutex did **not** serialize a second `UnifiedPolicyJournal::open()` actor sharing the SQLite database, or a direct SQLite connection. A signed Owner cancellation could commit while the first actor held its local gate; the first actor could then publish a stale signed Prepared record and report success.

L-001Z adds a **third full signed-history / two-Witness replay** *after* the injected model publisher returns, while the publishing journal's process-local gate remains held. Every result is strictly diagnostic:

- Exact matching signed journal snapshot, signed prefix, Root-selected two-Witness checkpoint, Audit/Outbox mirror parity and Owner manifest => the model call may report success, **but never authorizes ServiceOpen**.
- A second signed journal actor appends a cancellation **during** model publication => the final replay sees the new sequence and fails `StoreError::Conflict`. The signed Prepared may already have been published, so set `prepared_unreconciled=true` and `stale_prepared=true`, do **not** roll back or increment NV.
- A raw SQLite connection corrupts the Audit mirror during publication => final full replay fails. Return `Conflict` with the same quarantine.
- If the model publisher times out or returns a persistence error, do not assume its write was undone: burn the ticket, quarantine, refuse new reservations until signed independent recovery.
- A different actor changes the signed journal **after** postflight, or a new process starts after restart: **still not fenced**. An independent signed revalidation would notice the first case, but the process-local quarantine does not persist across restart.

## Five adversarial tests

1. Different journal actor appends a fully signed Owner cancellation **inside** the CAS publisher callback. Publisher may persist model Prepared; final replay prevents false success and quarantines stale intent.
2. Raw SQLite Audit mirror deletion **inside** the CAS publisher. Final replay rejects corrupt local integrity and quarantines.
3. Second journal actor's `inspect` can progress while first actor holds its local mutex for model publication; stable signed replay succeeds.
4. Fully signed Owner cancellation from another actor **after** postflight. Demonstrates remaining TOCTOU; local stale flag remains unset but next full replay rejects old Witness.
5. Fresh journal actor after simulated process restart has no durable quarantine; the separately pinned signed intent and counter remain essential. A clear **negative acceptance test** for durable global fence claims.

## Exact residual P0 blockers

These tests are not end-to-end rollback resistance. L-001Z **does not** stop uncoordinated direct SQL writes occurring after the third replay, multi-process/host writers, separate durable device-count and signer anti-rollback domains, signer compromise, TPM clear/replacement, global Witness eclipse, or post-power-cut resumption without a trusted reservation record.

Do not infer real cross-process linearizability from three separate SQLite reads. Doing the final replay under a per-process mutex is **not** an atomic transaction with hardware media. The legacy L-001Q `BEGIN IMMEDIATE` around simulated counter I/O is not a hardware-ready solution. The candidate code may not enable ServiceOpen or production Peer admission.

## Release prerequisites for closing L-001

Repository `docs/implementation-gates.md` defines L-001A/B/C/D, including real secure Peer channel tests, WIRE-01 across Rust/Go/Kotlin/JS, AUTHZ-RACE-01/AUTHZ-CRASH-02/ROLLBACK-01 and actual Android/Windows/macOS platform acceptance. These are **NOT complete merely because the L-001C journal experiments pass**. Root/Owner enrollment, secure time, independent witness freshness and full multi-process/hardware/power-loss verification remain blocking.

**Next candidate L-001AA:** standalone independently retained *logical* reservation fence simulator and crash-order acceptance table; cross-process signed SQL integration must remain NO-GO until all writers participate in the same independent trust protocol.
