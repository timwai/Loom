# L-001P — reconcile unified policy journal mirror integrity

**Base:** L-001O Draft PR #22 (`feat/l-001o-tpm-counter-binding-model`).
**Source:** the implementation and adversarial tests from the earlier **sibling** L-001J Draft PR #16 (`feat/l-001j-journal-integrity`). Earlier PR #16 branches from L-001I/#15; the later high-water and TPM stack branched separately, so this fix was missing from its ancestry.
**Status:** security engineering PoC; no network, service-admission, TPM write, or production authorization path.

## Why the re-integration is necessary

Signed unified policy events and the Owner-manifest cursor were replayed, but the latest stacked branch did not validate that persistent `unified_policy_outbox` and `unified_policy_audit` were exact one-to-one mirrors. An attacker or faulty SQLite trigger could delete or rewrite forensic records without changing signed events and still obtain a successful policy inspection. Likewise, `pending_outbox()` could return silently corrupted queue entries.

## Change set

- Under the existing `BEGIN IMMEDIATE` replay transaction, verify **all resources** have exact event-to-Outbox and event-to-Audit parity: same Space/Resource/sequence/kind, byte-for-byte Outbox evidence and matching audit policy head. Reject missing and orphan rows.
- Validate again after the last append write and **before COMMIT**. Any trigger-induced successful mirror mutation aborts the entire signed append.
- Run `pending_outbox()` parity check and queue read within **one transaction**, preventing an external writer from creating a gap between checking and reading.
- Bring forward sibling PR #16 regression coverage: missing, tampered and extra mirrors; empty journal with injected orphan rows; an AFTER INSERT SQL trigger corrupting Outbox and a verified rollback. Existing witnessed-recovery and policy-chain tests remain part of workspace CI.
- Update the stale status/README to reflect the verified PoC **development stack**, not claim that the default `main` contains the Rust implementation.

## Test and review instructions

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
cargo deny check
```

Check CI on **this exact branch head**, not only PR #16 or PR #22. Negative tests must return `StoreError::Conflict` for mirror anomalies, and both journal replay and witness-snapshot introspection must continue to reject corrupt state.

## Deliberate limitations / NO-GO

1. An attacker rolling back all SQLite tables to a mutually consistent older snapshot is **not detected by local parity**. Only a genuine, separately protected anti-rollback anchor plus authenticated signed-history replay can address that class of attack.
2. `pending_outbox()` does **not** take an externally authenticated Root pin or replay Owner credentials on its own; it is a **diagnostic-only API**. Do not use it to grant delivery, dispatch, ServiceOpen, relay, VPN or file-access privileges.
3. A cross-resource O(n) SQL parity scan per replay or append is conservative PoC behavior and needs bounded resource use / performance validation.
4. The TPM2 Linux probe remains **read-only** and the counter binding is an in-memory state-machine candidate; no physical NV increment, attestation, external trusted store or platform certification is added.
5. PR #16 remains separately reviewable. This branch is an *integration successor*, not a claim that PR #16 was merged. Avoid double-applying its commits when stacking branches and review every resulting diff.

**Runtime stays closed.** This change hardens local forensic agreement, not remote admission or rollback recovery.
