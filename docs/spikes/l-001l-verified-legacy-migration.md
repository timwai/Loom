# L-001L — Signed legacy migration audit & platform anchor validation

**Status: engineering PoC. No automatic migration, independent monotonic anchor implementation, or production ServiceOpen.** Stacked on L-001K PR #18.

## Implemented: read-only legacy migration preflight

`loom-store::legacy_history_audit::audit_single_resource_legacy()` accepts a SQLite connection, an **externally pinned** Space Root key/epoch and an already Root-verified resource genesis manifest. It performs a transactionally consistent **SELECT-only** audit for exactly one resource. It does not alter old tables, create unified tables or return a migration/permission token.

The verifier requires the complete four-table legacy schema, one exact `(space,resource)` policy cursor and a positive bounded policy epoch (≤10,000 events per candidate audit). Revocation rows must have contiguous epochs starting at one, byte-identical and epoch-matching critical Outbox records, and corresponding `security_audit` actions of `revoke`. Duplicate audit/outbox entries, missing records, extras from other resources, partial schemas and mixed unified/legacy tables reject.

For each event it replays the persisted candidate **Owner-signed revoke-only delegation + delegate-signed revocation**, checking signatures, scope, expected sequence, Owner key/epoch and the current resource lifecycle. This produces an audit report containing the legacy revocation root, a **candidate new unified policy-chain head**, candidate unified revocation-only root and Root-signed Owner-manifest commitment. The differing chain domains are intentional; the old revocation-only Checkpoint MUST NOT silently become a unified policy Checkpoint. `requires_external_rewitness` is **always true**.

**Limits:** The audit cannot detect a newer independent external high-water record, omitted remote changes, revoked delegates not represented in the old journal, a second database file, device clock rollback or malicious witness eclipse. It is intentionally restricted to a single-resource database. Old records in other formats are rejected rather than downgraded. A passing result only means locally stored evidence was internally coherent under the provided Root.

## What an approved migration must do later

1. Discover **every** legacy database, external witness, high-water record and Resource Owner scope through an authenticated inventory; lock all mutable policy writers.
2. Independently authenticate genesis/Root/Owner/witness keys and prove freshness/high-water outside the rollback domain.
3. Replay every signed legacy event and reconcile all explicitly scoped resources, including missing/canceled delegation and Owner transfer states. Reject any missing interval, history equivocation, or divergent critical Outbox.
4. Construct a **new versioned** unified chain and obtain fresh independent witness signatures explicitly binding the new domain and head. Never reuse legacy Checkpoint bytes.
5. Stage destination state, durable Outbox, immutable audit and new independent anchor using a reviewed crash-recoverable protocol; verify all checkpoints before any cutover.
6. Retire legacy writer *only after* separate signed migration acknowledgement and physical rollback tests. Keep `ServiceOpen` **Paused** throughout until final security gate.

## P0 platform security-anchor feasibility tests (not yet executed)

| Platform | Candidate mechanism to investigate | Necessary real-device evidence | Failure threshold |
|---|---|---|---|
| Android | Hardware-backed Keystore / StrongBox or attested platform facility, where present | Establish key origin and available rollback-resistance properties on specific devices; restore old app/data snapshots; uninstall/reinstall; reboot and power failure; validate atomic external monotonic state | Reject platforms where entire anchor can be restored alongside SQLite |
| Windows | TPM-bound signed state, platform key storage, and supported monotonic/counter capabilities if available | TPM provisioning attestation, backup/restore, disk cloning, profile move, interrupted writes, multiple processes | Do not assume DPAPI or TPM key protection alone creates an anti-rollback counter |
| macOS | Secure Enclave-bound identity and separately protected monotonic anchor candidates | Test Keychain restore/iCloud migration, Time Machine restore, power cycle, authorization changes and device loss | Key secrecy alone is insufficient to prevent signed old-value replay |
| Linux | TPM 2.0 NV indices/counter or other independently anchored state, if device policy permits | Check NV durability/wear, device reset, Linux permissions, storage rollback, VM snapshots and power-loss boundaries | Reject if anchor is only a writable ordinary disk file |

The table describes **experiments to perform, not demonstrated capabilities**. Availability, quotas, permissions and recovery semantics differ per device and OS release. No real-device tests have been run in this PR. The `IndependentUnifiedPolicyAnchor` in L-001J still has only test doubles.

### CI gates

`cargo fmt --all -- --check`, `cargo test --workspace --all-targets --locked`, strict `cargo clippy`, `cargo doc` and dependency policy. Specific negative tests cover fabricated Owner evidence, invalid Root, bad Outbox bytes, missing audit, missing sequence, extra scope, empty epoch, mixed schema and no mutation of the legacy DB during successful audit.

**ADR-20/21 remain PROPOSED. No network listener, Relay, transparent proxy, VPN, file sharing or remote control is enabled.**
