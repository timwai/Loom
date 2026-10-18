# L-001AA — Restart-retained logical reservation-fence oracle

**Status:** Rust deterministic security-model spike. **No TPM NV write, no independently authenticated persistent storage, no physical power-cut claims, no signer enrollment, no ServiceOpen.** Stacked on L-001Z / Draft PR #33.

## Why this model exists

L-001Y and L-001Z demonstrated that process-local journal locks and even a third signed post-CAS replay cannot guarantee atomicity when another SQLite process or writer changes signed policy, or when a process restarts. The reservation/quarantine booleans vanish at restart.

L-001AA adds a **separate logical state machine** that represents the minimum continuity a future trusted reservation-fence provider would have to satisfy. `ReservationFenceSimulator` retains a `FenceImage` across simulated `reboot()` by keeping it in an `Arc<Mutex<Inner>>`. That is **NOT real crash-safe persistence**, and the code never stores the image to a filesystem, SQLite or TPM.

## Interfaces and required external proofs

- `JournalView`: space/resource, pinned Root and genesis, writer epoch, signed policy sequence, policy head, revocation root, Owner manifest. This struct contains **caller-supplied values**, not an authenticated certificate. The caller must independently validate them against a full signed journal and dual Witness receipts; construction alone establishes nothing.
- `FencePhase`: `Idle`, `Reserved {ticket,view}`, `Prepared {ticket,view,signed_intent_digest}`, and `StalePrepared`. No phase grants admission or NV increment.
- `handle().reserve(expected)`: exact full-image CAS, one writer, strictly increasing generation/ticket, rejects a second/stale reservation. Simulated before/after failure returns uncertain and halts the boot.
- `publish_prepared(expected,ticket,digest)`: exact matching one-shot Reserved state, nonzero *supplied* digest and CAS generation; places image in durable-model Prepared. The supplied digest is **NOT verified as a real signer attestation** by this model. Real integration must use L-001T's strict pinned signature + replay fence verifier.
- `observed_signed_append(expected,next)`: only accepts a one-step monotonic journal view with stable device policy scope and changed policy head. A signed append invalidates an outstanding reservation; if already Prepared, it becomes StalePrepared and stays so over model restart. This method **assumes** upstream signed history validation and universal cross-process writer participation; it does not verify signatures or enforce all other SQLite writers.
- `reboot()`: invalidates previous boot handles. `retained_image_for_test()` exposes the model-only preserved state for crash assertions.
- **No automatic recover/authorize method**: ambiguous Prepared needs independently attested signer/record/fence, actual NV and signed Root/Owner+Witness reconciliation. If unavailable, fail closed and require explicit repair.

## Eight deterministic adversarial tests

1. Reserve → Prepared → simulated reboot: retained image, old handle refusal and no auto-new reservation.
2. Signed append while Reserved invalidates ticket and prevents Prepared.
3. Signed emergency append after Prepared becomes StalePrepared and survives simulated reboot, blocking new reservation.
4. Six crash cuts: Reserve/Prepare/SignedAppend before and after image update. After uncertain error the exact simulated image survives restart.
5. Stale full-snapshot double reserve, zero signature digest and duplicate Prepared replay rejected.
6. Journal fork, pinned Root identity swap and signed sequence regression refused (as caller-view constraints).
7. Two threads race to reserve one generation: only one wins the logical mutex CAS.
8. **Negative example**: a direct SQLite writer changes the actual journal without calling the external fence. The model cannot know and would accept an obsolete Prepared: proof that optional update callbacks are NOT trusted cross-process admission.

## Deployment blockers and milestone exit

To make this model meaningful on real devices, a provider must authenticate the journal view, signer and replay fence independently of local SQLite; **force all journal writers (including another process/host)** to participate or reject their writes; provide crash-safe monotonic epochs and explicit power-cut ordering across the signed intent medium and hardware counter; prove reset/clone/rollback behavior and durable repair semantics. A process-memory mutex or ordinary file is insufficient.

The `docs/implementation-gates.md` acceptance criteria also include L-001A (E2EE-01/TLS-ID-01), L-001B (WIRE-01 across Rust/Go/Kotlin/JS), L-001C (AUTHZ-RACE-01/AUTHZ-CRASH-02/ROLLBACK-01) and L-001D (actual Android/Windows/macOS `PLATFORM-*` tests). The current stack of green PoC Draft PRs does **not** satisfy full L-001 completion.

**Next work:** replace proof-as-caller-input with a cryptographic, independently pinned cross-process writer protocol; validate realistic TPM/OS provider behavior on approved sacrificial hardware, and separately complete multi-language/real-OS test plans. No automatic enrollment or ServiceOpen can be shipped on model evidence.
