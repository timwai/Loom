# L-002B — Hardware-agnostic Trusted State Provider (optional TPM)

> 2026-10-20 follow-up: [L-002D authenticated append](l-002d-authenticated-witness-append.md) and [L-002E isolated LAN read acceptance](l-002e-lan-file-read-acceptance.md) now implement and test the next candidate steps. The original model boundaries below are historical; independent Witness provisioning, production admission and release approval remain blocked.

> Design + Rust capability model, 2026-10-18. **Security PoC only.** No real TPM NV writes, Secure Enclave calls, Android KeyStore operations, quorum network endpoints, service admission, or production antirollback attestation. L-001 engineering integrated but L-001 release remains BLOCKED.

## Design decision

**Loom MUST NOT require TPM 2.0 or a particular vendor security processor to compile, launch its core libraries, store non-sensitive preferences, discover Peers, or run test simulations.** Windows TPM/fTPM, Secure Enclave on Apple platforms, Android KeyStore/TEE/StrongBox and a carefully authenticated independent quorum are different optional implementations of related—but not equivalent—security properties.

The independent security guarantee must be specified by **property**, not marketing name or operating system:

- *Software local-only*: volatile bytes and an in-process optimistic generation check are portable, but lack protected key custody, durable antirollback, or authentic Root/Owner policy. Not permitted to secure a production grant.
- *Verified hardware-backed key custody*: a device-validated key operation can reduce secret extraction risk; it does **not** prove that a SQLite policy head cannot roll back, nor supply a general monotonic counter.
- *Verified antirollback state*: requires an independently enrolled state floor, scope binding, fork/replay detection, writer fencing, full signed-policy/Witness verification and crash-safe reconciliation. This might use TPM hardware **or** a separately reviewed authenticated quorum protocol. Offline availability, loss of quorum and eclipse need explicit fail-closed semantics.
- *Network membership admission*: a separate signed Root/Owner/dual-Witness resource decision; never implied by a secure-storage Provider check.

## Rust implementation

`crates/loom-store/src/trusted_state_provider.rs` defines:

| Type | Role / trust boundary |
|---|---|
| `ProviderKind` | Descriptive: `Software`, `Tpm2`, `SecureEnclave`, `AndroidKeystore`, `ExternalQuorum`. Naming a backend never proves its existence. |
| `ProviderDescriptor` | Untrusted capability hints: reported key protection, rollback behavior and scope binding. Cannot authorize admission by itself. |
| `VerifiedProviderEvidence` | Opaque proof separately binding identity, independently verified key custody and optional independently checked state high-water. **No public constructor**; the production verifier is intentionally not implemented. |
| `StateUse` | Requirements `PortableLocalOnly`, `HardwareKeyRequired`, or `NonRollbackablePolicy`. Each kind is judged by actual vetted properties, not a platform enum. |
| `check_provider_requirements` | Fail-closed; no evidence = no high-security eligibility; scope mismatch/stale generation = reject; no silent fallback to software; result is never a Root/Owner/Peer grant. |
| `TrustedStateProvider` | Platform-neutral storage trait, exposing descriptor, local read and bounded compare-and-write of non-security settings. Future implementations must be separately reviewed. |
| `SoftwareStateProvider` | Mutex-protected, volatile <=4KiB settings with in-process generation CAS. Cross-platform **not durable**; never stores authoritative policy/keys or emits ServiceOpen. |

The old `tpm_counter_binding` module is retained as a **TPM-specific candidate crash experiment** and does not become mandatory for the Rust runtime. Removing or reinterpreting its device-bound proofs as generic portable state would break its threat model. No code path maps `StorageEligibility` to `ResourceAuthorizer::Allow`.

### Tests (11 adversarial/behavioral checks)

- Baseline software mode functions without probing a TPM; zero implicit enrollment.
- Sensitive antirollback/key requirements cannot be satisfied by software or a self-declared TPM/SE/KeyStore/quorum.
- Hardware key custody does not prove antirollback; independently anchored rollback evidence does not prove protected key custody.
- Separate scope and replay-floor mismatches refuse; hardware key provider lacking antirollback is rejected for high-water.
- A temporary local write does not survive a new software instance, so cannot be treated as trusted state.
- Bounded local settings, stale compare-and-write, and two concurrent writers with only one winner.
- All tests are non-network, use no real security hardware, and preserve the existing fail-closed `PeerCore`/DenyAll runtime.

## L-001 milestone acceptance update

The security requirement is **verified rollback resistance with authenticated binding**, not a mandatory TPM chip. `docs/acceptance/l001.json` has:

- `engineering.status = complete`: the earlier source integration at `main@d50eae4`.
- `state = blocked`: nine production safety/platform gates remain unpassed.
- `provider_policy.tpm_required = false`, software baseline restricted to local-only, **no silent downgrade**, hardware/remote-quorum options.
- `signoffs.trusted_state` (replaces misleading mandatory `hardware`) requiring independent validation of the selected trust mechanism. This does not skip security, interop or real platform approvals.

The CI `scripts/l001_gate.py` rejects a claimed `state=complete` without the original release gate evidence, and additionally checks optional TPM/mandatory trusted-state properties.

## Next implementation gates

1. Add a **vetted** proof-minting verifier and a real provider on each target platform. Key custody and antirollback must have separate reviewed evidence paths; do not infer one from the other.
2. For a no-TPM deployment, build authenticated remote Witness/quorum high-water with provable nonrollbackable enrollment, offline fail-closed handling, leader/fork detection, atomic recovery and denial under eclipse/network partition.
3. Integrate only a verified provider into signed journal→Prepared CAS→counter/fence recovery. The current volatile local-settings trait is deliberately **not** a drop-in for authoritative policy storage.
4. Keep `ServiceOpen` and network listening disabled until signed membership, Owner ACL, revoke-to-live-session shutdown, real OS network integration and all L-001 release evidence are reviewed.
5. Continue the L-002A dual-Peer file-read and revocation test program; no production file path is exposed.

**The absence of TPM must never silently downgrade an operation advertised as rollback-resistant.** Software operation is allowed only when the user-visible security guarantee remains satisfiable without hardware.
