# L-001W — externally approved signer rotation, crash fencing & nonblocking trusted-media contract

**Review scope:** L-001W / stacked Draft based on L-001V PR #29. This document describes an executable **in-memory model** and a **proposed** platform contract; it does **not** assert that TPM2, an operating-system keystore, SQLite, a filesystem, or a network witness has actually implemented it.

**Global status:** `SECURITY_ENGINEERING_POC / NO_SERVICE_OPEN / NO_REAL_TPM_NV_WRITE / NO_DEPLOYABLE_MESH`.

## 1. Trust boundaries and adversaries

L-001V tests canonical Ed25519-signed `Committed`/`Prepared` records, a monotonic counter and a combined signed-record/replay-fence CAS under a **single in-process mutex**. That is useful for model checking but cannot establish hardware trust or failure-atomic updates between *physically independent* media.

L-001W extends `AuthenticatedWriteSimulator` with:

- `SimulatedRotationApproval { expected_pin, expected_fence, successor_public_key }`: an **untrusted-by-itself fixture representing a decision that must have been authorized elsewhere**. Constructing the value gives no authority in production; no actual verification of admin quorum or TPM-certified policy has been added.
- `rotate_signer_for_test(approval, successor)`: validates the exact old externally pinned key+epoch/fence and **Committed** record; requires a different successor key and checked `old_epoch+1` and `old_sequence+1`. Generates a new record bound to the same Counter identity, Space, Resource, Root, genesis and writer; signs with the new key **outside** the critical section; checks the signature with the successor public key; compares old frame, fence, pinned identity, counter, generation and key state again; then simulates one atomic publish of `frame + fence + pin + signer`. Stale old-key writes fail CAS.
- `RotateBeforeCas` and `RotateAfterCas` one-shot crash cuts: an uncertain error means **either** the old or the new signer pin may be authoritative after reboot. The old signed image and fence survive before-cut; the new signed image+fence+epoch survive after-cut. Read the truth on reboot, never guess from return codes.
- `reset_counter_for_test(reduced_counter)`: models TPM clear, hardware replacement, or an illicit counter decrease. The already authenticated fence remains unchanged, old handles are invalidated and subsequently signed loads/increments fail closed. No automatic enrollment/recovery from SQLite backups.

**Required external trust that is not implemented:** independent signer enrollment, certificate/pin attestation, identity/fence CAS at a nonrollbackable root, authorization to rotate keys (possibly old/new/admin-quorum proof), epoch monotonicity across hosts, TPM clear/swap detection, secure time, revocation propagation and physical anti-tearing guarantees.

## 2. Minimal proposed platform-neutral signed-media interface

These are **design requirements, not new production traits or assertions about TPM2**:

| Operation | Inputs | Trusted output / failure contract |
|---|---|---|
| `Observe()` | device enrolled identity | authenticated `pin + fence + observed NV count` with a stable generation token; never read pin/fence from rollbackable Intent bytes |
| `Sign()` | canonical record transcript, authorized signer identifier, bound session token | Ed25519 signature or error; no mutex/SQLite write transaction held; a sign error gives no write permission |
| `CompareAndAdvance()` | expected authenticated generation, full old signer pin, fence, count, old record digest; proposed *strictly verified* next signed frame and next pin | exactly one durable linearizable publish or explicit uncertain result; an error cannot prove no write occurred |
| `CounterIncrement()` | independently verified durable fenced Prepared record, exact device/NV index and expected counter | irreversible +1 **at most once**; power-loss ambiguity must be re-observed |
| `Recover()` | independently pinned generation/fence, observed counter, signed journal history + quorum Witness receipts | one of `Committed`, `PreparedBeforeIncrement`, `PreparedAfterIncrementNeedsSignedRecheck`, `Reject`; never return an authorization permit |

If a target platform cannot provide a trustworthy `CompareAndAdvance()` for the record+pin/fence, **NO-GO**. Simply storing the frame in SQLite and updating a local file in two `fsync` calls is not equivalent. A TPM NV counter also cannot atomically store entire Root/Owner/policy commitments; a complete protocol may need an independently protected durable intent and explicit two-phase reconciliation.

## 3. Nonblocking journal-to-trust protocol (design, not implemented in hardware)

1. **Preflight, short journal transaction:** replay Root/Owner/delegation/revocation signed history, verify Audit/Outbox parity, exact previous high-water signed prefix and two Root-selected Witness checkpoints. Capture a *versioned immutable journal snapshot token* bound to full Owner manifest, revocation root, sequence/head, device identity and intended next policy. Release the SQLite write transaction **before any hardware wait or signer call**.
2. **External signer phase:** fetch independently authenticated pin/fence/counter and verify the old signed record; create canonical `Prepared` and external signature. This phase must not hold the SQLite connection/lock. Cancellation or timeout creates **no** ServiceOpen.
3. **Revalidate precommit:** recheck the journal snapshot under a *new short* transaction, reject any changed head/owner or witness evidence. Serialize per-device writers (including other processes/hosts) at the trusted medium, not in the local SQLite actor.
4. **Durable Prepared CAS:** publish the new authenticated `Prepared` plus replay fence with an externally reviewed atomic/ordered contract. If ambiguous, quarantine operation and re-observe after restart; never infer from a timeout that the durable update failed.
5. **Irreversible device increment:** require the exact durable Prepared digest/fence, then increment **once**. An error may mean N or N+1. Do not retry automatically; inspect.
6. **Signed Finalize after revalidation:** recheck full Root/Owner signed history and both Witness checkpoints against the Prepared intent. Only then publish `Committed` with a second trusted fence CAS, inspect exact counter/policy, and record local audit confirmation.
7. **Admission remains out of scope:** even `Committed` consistency does not authorize ServiceOpen without a production Root/Owner policy-to-channel admission protocol, secure time, anti-eclipse/witness freshness, revocation-to-active-session kill and migration approval.

**Open correctness problem:** steps 3–6 cannot be a single atomic operation across SQLite, trusted pin/fence medium and a TPM NV counter. A changed journal after external Prepare can strand a safe-but-unresolvable Prepared intent. The acceptance criterion is **fail closed + explicit operator repair**, not claiming global all-or-nothing atomicity. Production design must formally verify this state machine under the platform's actual write-ordering and device error codes.

## 4. Signer rotation and Owner transfer are independent

A signer rotation changes the *device-local authentication key*, **not** the Root or Owner policy authorization. Its existing Committed policy payload is unchanged and independently pinned; a prepared transition must be resolved against the signed witness history first. Owner transfer/key rotation can alter current Owner manifest and must be replayed/authenticated independently. The model denies any signer rotation while a Prepared record exists; it does not claim to implement a trusted Owner transfer ceremony.

| Operation/failure | Model outcome |
|---|---|
| Valid externally provided approval, new signer, Committed | new signer key/epoch + signed record and fence advance, same policy/counter |
| Incorrect new signing key | signature verification failure; no CAS or fence update |
| Unchanged successor key, wrong old pin/fence, stale approval | reject; no mutation |
| Prepared record pending | reject rotation until signed reconciliation |
| Power cut **before** rotate CAS | old signed pin/fence survive reboot |
| Power cut **after** rotate CAS | new pin/fence/signature survive reboot, counter unchanged |
| Old signer paused while rotation publishes | old signature becomes stale and CAS rejects it |
| Old backup restored after rotation | rejected against new pin and pinned digest |
| External NV decrease/TPM clear | signed load and increment reject; no automatic re-enrollment |
| Epoch overflow | reject without state modification |

L-001W adds seven dedicated tests exercising this matrix, including deterministic concurrent signer pause/resume and both rotation crash cuts, in addition to inherited L-001V six write crash cuts and signed journal integration.

## 5. Hardware readiness/rollout criteria (all unresolved)

- Real independent enrollment of signer/Root/device binding, hardware-backed generation/epoch anti-rollback, and revocation of lost/compromised signer.
- Per-device, cross-process writer fencing and a verified nonblocking interface that never holds SQLite `BEGIN IMMEDIATE` while awaiting TPM/keystore/network operations.
- Real data-consistency guarantees for separate intent medium + replay fence + counter under abrupt power loss, torn writes, reset, NV wear/quotas/lockout and replay across restored device backups.
- Reviewed signer-rotation ceremonies (administrative authorization, two-person control where necessary, compromised-old-key handling) and external epoch advancement.
- Actual hardware experiments on **sacrificial** devices, a power-cut test harness, and audit sign-off. Current simulation is not evidence of these properties.
- Network ServiceOpen, two-peer LAN policy/revoke acceptance, multi-platform device support and deployable Rust mesh remain independently blocked.

**Proposed L-001X:** extract the journal preflight token + second signed-snapshot revalidation into a nonblocking coordination model, drive a mock signer with a paused/changed journal, and prove that a stale preflight never reaches a fenced Prepared CAS. No production TPM or ServiceOpen.
