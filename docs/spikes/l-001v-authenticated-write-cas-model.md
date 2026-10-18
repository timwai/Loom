# L-001V — authenticated signed Intent write + replay-fence CAS **model**

**Status:** unmerged Rust security PoC stacked on L-001U / Draft PR #28. **No physical TPM write, independently authenticated nonvolatile storage, real CAS, protected signing key or ServiceOpen.**

## What was missing

L-001T specified strictly signed and pinned intent records. L-001U made their read-only verification mandatory when using the authenticated read adapter, but every `prepare()` and `finalize()` operation on that adapter still failed closed. L-001V introduces a **separate in-memory writer model** to validate the proposed lifecycle without misrepresenting the existing read-only adapter as a real safe persistence provider.

A plain signed record is not rollback protection. The signer pin and replay-fence sequence/digest/counter floor must be maintained **independently of rollbackable SQLite and raw intent bytes**, and updates must have a reviewed failure-atomic contract. No such real-world trusted provider exists yet.

## New interfaces / explicit trust boundaries

`crates/loom-store/src/authenticated_intent_write_model.rs` defines:

- `CandidateExternalIntentSigner::sign(canonical_preimage)`: model abstraction for an **externally enrolled, authorized** signer; no production private key is created or held in the library. Tests provide an Ed25519 `SigningKey` mock.
- `AuthenticatedWriteSimulator::enrolled_for_test(...)`: consumes caller-supplied signed initial frame, separately pinned `ExternalSignerPin`, `ExternalReplayFence`, observed counter and signer trait. It accepts enrollment only if the frame and separately supplied digest/sequence match exactly. This constructor is for model tests, **not real trusted enrollment**.
- `CandidateIntentStore` with `load()` checking strict signatures, exact independently pinned record sequence/digest and observed counter; `prepare()` and `finalize()` may write **only** by checking an old signed state, preparing a higher versioned record, signing its canonical preimage, verifying it against the pinned key, and **CAS-comparing every observed input again before publication**.
- The signed frame and independent replay-fence structure publish together under a *single simulated mutex CAS*. Signer calls happen **outside** the CAS lock. A stale concurrent signing result cannot overwrite another writer's already published record.
- `CandidateMonotonicCounter::increment()` succeeds **only if signed and replay-checked Prepared already exists** at the old counter. It moves the model counter exactly +1 and rejects a second increment. Neither signature nor CAS record is an authorization token.
- `CandidateSignedIntentReader` and `CandidateTrustedIntentReader` are also implemented for the model's boot-scoped handles, so L-001U's read-only verifier can observe the same serialized record in tests.
- On simulated reboot, old trait handles are invalidated and new handles re-verify the signed frame + pinned fence + counter. Restoring an older signed raw frame cannot roll back the independent digest, sequence or modeled counter.

The model does **not** implement true two-device atomicity. Its single mutex is purely a deterministic oracle for the desired CAS property; no TPM, filesystem, or remote signer supports this interface by assumption.

## Failure boundary and recovery matrix

| One-shot failure | Persisted model outcome | Required safe behavior |
|---|---|---|
| PrepareBeforeCas | Old Committed, original fence/counter | Reject ambiguous operation; no increment |
| PrepareAfterCas | Signed Prepared + updated fence, old counter | Reboot, read signed Prepared; **never automatically increment** |
| CounterBeforeWrite | Prepared, old counter | Reboot, diagnostic `IntentBeforeIncrement` |
| CounterAfterWrite | Prepared, counter N+1 | Revalidate exact signed history + two Witness receipts before signed Finalize |
| FinalizeBeforeCas | Prepared, counter N+1 | Same signed recovery checks; no second increment |
| FinalizeAfterCas | New signed Committed and advanced fence, counter N+1 | Re-read and compare full policy; avoid duplicate finalize |

All failures return `PersistenceUncertain`, quarantine that boot's handles until reboot, and preserve whatever had actually committed. A caller must inspect the new observed state rather than infer whether the write happened from its return code.

## Adversarial test evidence

- Eight model unit tests: successful authenticated Prepare/NV/Finalize with two fence steps; six fault-cut matrix and post-crash observations; restored raw signed-frame rollback; refused signer and malformed transition; deterministically interleaved concurrent signers with stale CAS refusal; rebooted stale handles plus double-increment rejection; signed-but-unfenced future Prepared cannot increment NV; a substituted signing key cannot publish a new record under the existing pin.
- Three additional `UnifiedPolicyJournal` integration tests: successful signed Root/Owner replay and two-root-selected-Witness Begin+Reconcile; post-Prepare crash without re-increment; post-NV crash with Witness substitution refusal and successful later signed finalize.
- Both model read/write and journal-bound operations **never enable ServiceOpen**.

## Blocking architectural problems

1. The signer trait is only an abstraction. Tests use software keys. A real design needs explicit secure provisioning, hardware-backed signing or equivalent, rotation/revocation ceremony and attested device binding.
2. The authenticated replay fence and record currently live under **one in-memory mutex**; a real independent anti-rollback medium, durable fence CAS and reliable crash ordering across hardware/OS failure domains have **not** been provided. Ordinary SQLite, files, synchronized backups or signatures alone are insufficient.
3. The existing journal-bound candidate flow still holds `BEGIN IMMEDIATE` across the simulated counter operation. **Do not use slow real hardware operations inside SQLite write transactions.**
4. Full signed journal replay, historical owner prefix and dual Witness receipts are consistency checks, not global freshness, trusted time, anti-eclipse guarantees, or production Peer admission.
5. Authenticated legacy migration, platform-specific TPM behaviors (NV wear/quotas/reset), multi-resource coordination, multi-process fault injection and two-peer LAN revoke integration remain NO-GO.

**Proposed next gate L-001W:** formalize the proposed *two-phase* trusted signer/fence update contract and a non-blocking coordination protocol; define explicit handling of signer key rotation, witness-changing Owner transfer and incomplete external fence CAS under real-device failure assumptions. Only then plan sacrificial TPM hardware testing, never assume this model is deployable.
