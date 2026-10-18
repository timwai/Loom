# L-001N — Linux TPM 2.0 read-only device and NV capability probe

**Status: engineering experiment; NO operational monotonic anchor, no TPM NV writes, and no physical-device certification.** Stacked on Draft PR #20.

## Implemented

A new Rust module `loom-store::linux_tpm2_probe` performs a **real read-only** capability query on Linux when a compatible TPM resource-manager character device is present. `probe_linux_tpm2()` checks `/sys/class/tpm/tpmN/tpm_version_major` (Linux kernel sysfs ABI, major=2) for N=0..15 and requires the corresponding `/dev/tpmrmN` character device. It does **not** accept an ordinary file as an emulated TPM or quietly use a TPM 1.2 interface. Unsupported platforms and missing devices reject explicitly.

On Linux it writes only the standard **TPM2_GetCapability** read-only command (command code `0x0000017A`, no sessions): `TPM_CAP_TPM_PROPERTIES` to read `TPM_PT_FAMILY_INDICATOR` (`2.0\0`) and manufacturer property; and `TPM_CAP_HANDLES` to list a bounded first page of NV handles. Responses are bounded (≤4096 bytes), checked for tag, exact encoded total length, TPM return code, requested capability, entry count, ordered/in-range NV handles and truncated enumeration. `nv_list_incomplete` is raised if the TPM reports more handles than the returned page. The API reports only diagnostic candidates.

**No** `TPM2_NV_DefineSpace`, `TPM2_NV_Write`, `TPM2_NV_Increment`, `TPM2_Clear`, `TPM2_EvictControl`, key provisioning, credential access or authorization commands are called. Probe failure never initializes an anchor.

The `LinuxTpm2Candidate` type implements `IndependentUnifiedPolicyAnchor` as **deny-all** (`MissingOrUntrusted` on both read and CAS). This is intentional. TPM presence, unforgeable keys and listing NV counters are not an atomic compare-and-advance of the signed `UnifiedPolicyHighWater` fields. NV counter values and policy-chain commitments need a separately designed, trusted, crash-recoverable binding before this can become a usable provider.

## Evidence and CI

The Rust tests inject TPM response frames and cover a correct fixed-property/NV page, TPM 1.2 and fake family, truncated/oversized/error responses, wrong tag/capability, duplicated/unsorted/out-of-range NV handles, truncated enumeration and deny-all high-water behavior. These mock frames are **not** hardware test results.

For independent reference, the Linux kernel documents `tpm_version_major` at `Documentation/ABI/stable/sysfs-class-tpm`. The upstream tpm2-tools `tpm2_getcap` documentation shows `properties-fixed` and `handles-nv-index` capability queries; `tpm2_nvreadpublic` describes inspection of NV metadata. The actual Loom probe does not spawn shell commands or depend on tpm2-tools.

## Real-device test gate (not executed in GitHub CI)

1. Record exact Linux kernel, TPM vendor/firmware, `/sys/class/tpm` and `/dev/tpmrmN` permissions. Run `probe_linux_tpm2` against a **disposable test device** and record family, manufacturer, the NV handle page, TPM error status and read-only log. No secrets or private authorization values may be logged.
2. Inspect actual NV counter capabilities, required owner/platform authorization and NV quotas/wear. A present counter is not proof of a full transactional policy high-water store.
3. Design and formally review the binding between TPM monotonic counter/sequence, all signed Root and Owner manifest hashes, policy head and the witness quorum checkpoint. Prove cross-process CAS semantics and fail closed on security-authority loss, TPM reset or rollback.
4. On sacrificial hardware, test app-data disk snapshot restore, TPM reset, interrupted update, power cut, reboot and multi-process races. Use independent witness receipts and verify that stale snapshots **cannot** be accepted as Ready.
5. Only after hardware evidence is reviewed may a new adapter implement real `read` and `compare_and_advance`. **Do not toggle the existing deny-all implementation through a feature flag without a separate security review.**

## Limits / No-Go

- Not a TPM 2.0 attestation or freshness protocol: Linux sysfs, raw TPM commands and manufacturer ID do not authenticate the device origin or guarantee physical rollback resistance.
- Cannot be used on machines without an accessible /dev/tpmrmN; no automatic fallback to ordinary files, SQLite or TPM 1.2.
- The TPM command may block on a broken kernel/driver; real-device experiments must run in an externally supervised process with a deadline. The library probe itself does not enforce a wall-clock deadline.
- There are no hardware samples in CI, no TPM NV counter persistence, no crash-atomic Root/Owner/witness binding, and no production ServiceOpen.

**L-ADR-20/21 remain PROPOSED.** The entire PR stack is unmerged. Production Mesh, Relay, VPN, proxy and file sharing remain disabled.

Technical references:
- https://github.com/torvalds/linux/blob/master/Documentation/ABI/stable/sysfs-class-tpm
- https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getcap.1.md
- https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_nvreadpublic.1.md
