# L-001M — Independent anchor adapter behavioral conformance

**Status: executable model only. Not a device certification. Not production security.** Stacked on L-001L PR #19.

This branch adds `loom-store::anchor_conformance`, a public behavioral probe for prospective adapters implementing `IndependentUnifiedPolicyAnchor`. It does **not** claim that any TPM, Secure Enclave, Android StrongBox or Keychain/Keystore is independently monotonic.

## Contract and test environment

An `AnchorProbeRig` must supply three hooks: reopen an anchor provider; restore an old *application/SQLite-domain* snapshot, which MUST NOT control the claimed independent anchor; and inject specific failures. Run only with a **fresh, dedicated, disposable** test resource and trustworthy initial provisioning. The probe **writes** to its test high-water.

`run_behavioral_probe` checks the exact initial record; wrong-resource isolation; monotonic compare-and-swap; stale concurrent writer rejection; application snapshot rollback isolation across provider reopen; refusal of equal-sequence competing policy heads; abort before commit; commit that succeeds but returns an ambiguous error followed by fresh read; and denied read during simulated unavailability with later recovery.

On success it returns `ProbeReport { checks_passed: 9, physically_certified: false }`. **The flag is always false.** Passing simulated checks cannot establish durability after actual power loss, device attestation, physically independent storage, privacy properties or resistance to a malicious privileged user. A fake rig can lie about restoration. Reviewable device evidence must be collected separately.

## Model tests

The tests include a synthetic in-memory adapter that passes the behavioral contract and **still has zero physical monotonicity**. Two intentionally defective variants fail: (1) restoring application snapshots also restores the high-water; (2) the anchor allows equal-version competing policy heads. A mismatched initial record also fails rather than silently reprovisioning.

These tests exist to validate the **detection capability of the probe**, not to award a security certification to a Mutex or JSON file. They do not enable a network ServiceOpen or modify `UnifiedPolicyJournal` admission state.

## Real-device feasibility evidence required (NOT performed)

For each target device, record device model/board ID, OS build/version, cryptographic Root enrollment chain, storage backing and monotonic guarantee provenance, driver permissions, secure clock/freshness properties and exact storage deletion/migration behavior. Exercise:

1. Provision a disposable, uniquely scoped trust manifest and separately witnessed initial policy high-water; capture signed checksums of application backup and external anchor location.
2. Run the behavioral probe with a real platform adapter, under a disposable scope only. Capture structured outcomes for all nine checks, including failure injection and reopen semantics.
3. Physically reboot and power-cycle after anchor CAS success. Inject abrupt process death and interrupted writes before/after a durable external update; verify readback from a newly opened handle.
4. Restore old app/SQLite files, OS user profile and full system backup where permitted. Try disk cloning and VM snapshot restore on supported environments. Independent high-water must **not** revert to the backed-up value.
5. Test concurrent writers in separate processes and competing devices, storage reset/TPM clear, lost/migrated device keys, privilege escalation, clock rollback, device factory reset, and externally witnessed recovery. Missing or reset anchor must fail closed.
6. Document hardware wear/quota and atomicity behavior; repeatedly cycle reads/writes within the vendor-supported limits. Avoid destructive experiments on personal/production devices.

### Platform-specific probes to implement next

| Platform | Backend investigation | Must demonstrate | NO-GO |
|---|---|---|---|
| Android | Keystore / StrongBox / rollback-resistant hardware-backed keys where device truly supports them | Actual independent version anchoring after app-data and OS backup restoration, key attestation, uninstall/reinstall semantics | Key secrecy with rollbackable metadata is not sufficient |
| Windows | TPM-backed NV / platform counter where available; secure driver/service privilege model | Atomic monotonic CAS or equivalent signed witnessed protocol, physical disk clone and user-profile restore tests | DPAPI encrypted bytes alone cannot prove freshness |
| macOS | Secure Enclave-bound keys with external witness or separate monotonic trusted state | Keychain / backup restore, Secure Enclave loss and device migration acceptance criteria | Secure Enclave signatures by themselves do not ensure latest stored counter |
| Linux | TPM 2.0 NV counter/index on compatible hardware plus strict authorization and external witness | NV atomicity, TPM clear, quota, disk snapshot and power-loss behavior | Plain root-owned file cannot meet rollback resistance |

If hardware lacks a suitable monotonic facility, a **separately authenticated independent witness quorum** might provide the needed anti-rollback freshness; that protocol must be implemented and tested separately. Never silently downgrade to local SQLite.

## Remaining blockers

No actual Android/Windows/macOS/Linux implementation of `IndependentUnifiedPolicyAnchor` exists. No real-device tests have been performed, no remote durable witness ACK or independent secure time is available, and SQLite + external anchor commits remain non-atomic. The test harness does not settle those issues.

L-ADR-20/21 remain PROPOSED; all production Mesh listeners, VPN/proxy/RDP/File services and ServiceOpen stay disabled. Do not merge directly to main without the stacked PR review and platform security evidence.
