# Loom — implementation status and security gates

> Updated: **2026-10-18**, through proposed L-001S Draft PR (on PR #25). Source of truth: repository branches, pull requests and GitHub Actions. This file describes the **stacked unmerged development branches**, not released features or the default branch.

## Executive status

**SECURITY_ENGINEERING_POC / MAIN_README_ONLY / NO_SERVICE_OPEN / NO_DEPLOYABLE_MESH**

- `main` remains the one-README bootstrap commit. No Rust code is merged there.
- The active stack through **L-001O / Draft PR #22** has eight Rust library crates, a `loomd` binary that does not start a service, signed protocol/Owner-lifecycle verifiers, SQLite policy journals, witness/rollback models and a **read-only** Linux TPM2 probe.
- Latest L-001O branch head `4683c432dd4b2530fcd4bd8db39c6bf03b5a3945` passed GitHub Actions (Rust fmt, workspace tests, Clippy with `-D warnings`, docs, dependency policy); see [run 39083991175](https://github.com/timwai/Loom/actions/runs/39083991175).
- **L-001P / PR #23** restored L-001J mirror-integrity checks; L-001Q / PR #24 tied SQLite signed journal replay to candidate counter steps; L-001R / PR #25 requires the prior committed policy to match the actual signed historical prefix. **L-001S** adds a deterministic simulated durable Prepared-intent medium with eight power-cut points, boot-bound handles and signed journal integration tests.
- A green test suite verifies isolated PoCs only. There is no production-admission authorization, usable Mesh service, production TPM anchor, deployment or hardware security certificate.

## What exists on development branches

| Area | Existing evidence / implementation | Actual status |
|---|---|---|
| L-000, PR #1 | Rust workspace, eight libraries, `loomd`, GitHub CI | Tested scaffolding, unmerged |
| L-001A, PR #7 | mTLS Peer channel over an untrusted bearer | Isolated transport spike, **not wired** into `loomd` |
| L-001B, PR #6 | Canonical security-event wire codec and golden vectors | Candidate format; interop/review incomplete |
| L-001C–H, PRs #8–#14 | SQLite revocations, Ed25519 Owner/Root/witness verification, delegation, transfers, signed replay, rollback interfaces | Security primitives and local model tests only |
| L-001I, PR #15 | Unified Owner/delegate/revocation policy lifecycle SQLite journal | Authenticated event replay PoC; no production source of truth |
| L-001J, PR #16 | Signed-event vs. Outbox/Audit parity, transaction-scoped pending queue | Separate branch, **not inherited by #22**; being integrated by L-001P |
| L-001J–L, PRs #17–#19 | Dual-witness policy high-water, crash reconciliation, legacy signed-history preflight | Diagnostic PoCs; no automatic migration or live authority |
| L-001M–O, PRs #20–#22 | Anchor behavioral conformance, read-only TPM2 capability probe, counter/intent crash-state model | Abstract or nonmutating models, **no trusted TPM NV writer** |
| L-001P, PR #23 | Reintegrate missing journal mirror-integrity checks and adversarial tests | Final-head CI passed; unmerged Draft |
| L-001Q, PR #24 | Bind fully replayed SQLite policy, signed witness checkpoint and candidate counter stages under a single model transaction | Seven new adversarial tests; model only, no trusted NV writes |
| L-001R, PR #25 | Verify prior committed policy root, revocation root and Owner manifest as an exact *signed journal prefix* before candidate counter mutation | Six new adversarial crash/forgery tests; no durable intent or TPM writer |
| L-001S, proposed PR | Model independent Prepared-intent sync boundaries, irreversible NV count, reboot, stale handles and signed journal recovery | 4 model + 3 integration tests; purely volatile simulator; no TPM writer |

**Branch topology caveat:** PRs #6 (wire), #7 (channel) and #16 (mirror integrity) branch from earlier ancestors; they are not all ancestors of PR #22. Count of open Draft PRs is not a count of integrated features. Do not merge leaf PRs into `main` out of order. Review and reconcile branches explicitly.

## Current P0 update after L-001S

- The L-001P integration (#23) succeeded in the final commit CI, and L-001Q (#24) now tests a journal-bound counter transition with matching dual witness receipts, full signed-history replay, mirror parity, current Owner manifest and a SQLite transaction barrier. Both remain **unmerged Draft PRs**.
- A matching counter/manifest pair is only a **diagnostic** result. No real independently protected TPM anchor, attested device binding, authenticated durable Prepared store or physical power-loss verification exists; ServiceOpen stays disabled.
- L-001R checks that a counter's earlier high-water record matches a replayed **signed historical prefix** (sequence, head, revocation root and then-current Owner manifest) before any modeled increment. A matching latest witness alone is not enough. These proofs depend on trusted external enrollment and retained signed journal history; physical and global freshness are still not guaranteed.
- L-001S explicitly models unacknowledged volatile writes vs. acknowledged simulated durable writes and all eight Prepare/Increment/Finalize cut points. A reboot preserves the simulated NV counter and acknowledged intent image but invalidates old handles. Those are *model semantics*, NOT physical persistence or anti-rollback protection.
- Production design must remove long-running external hardware I/O from SQLite write transactions. Independently authenticated real durable Prepared intent, TPM provisioning, real power-loss and cross-process/host adversarial acceptance remain blockers.

## Critical release blockers (P0)

1. **Canonical policy ledger & legacy migration:** No authenticated, one-way migration from the old revocation-only tables to the unified Owner lifecycle. Legacy databases are intentionally refused; the read-only audit produces evidence, not an authorized migration.
2. **Independent rollback resistance:** No production `IndependentUnifiedPolicyAnchor`. Neither SQLite, in-memory counters, the TPM2 read-only probe nor a numeric TPM counter alone authorize the policy high-water. Missing/rolled-back intent, reset, stolen TPM identity and crash windows remain deployment blockers.
3. **Trusted enrolment and witness freshness:** Root pin, Owner manifest, witness quorum, secure time, replay under a transaction, device attestation and global witness anti-eclipse policies lack production-grade end-to-end binding.
4. **Admission and transport:** No verified handshake-to-policy-to-ServiceOpen commit path; no revocation-to-session termination guarantee, membership convergence, relay path validation or tested two-Peer LAN file-read/revoke acceptance.
5. **Platform and rollout:** Android VPN, Windows filtering, macOS entitlements, LAN/WAN interoperability, multi-process crash/power-loss and real-device TPM failure-injection have not passed. Release/license review remains open.

## Next execution gates

- **Current (L-001S):** exercise model durability boundaries and complete eight-cut failure matrix with full signed journal + two-Witness checkpoint integration; preserve NO-SERVICE-OPEN.
- **Next (L-001T):** specify versioned canonical authenticated intent record framing and prove key/identity/manifest binding and mutation rejection using a separately provisioned authentication key assumption (still not a trusted real storage provider).
- **Platform validation:** independently evaluate hardware enrollment, monotonic NV semantics, attestation, reset/wear/quotas, and legacy signed-history migration (sacrificial TPM target only after review). Unsupported targets remain explicit NO-GO.
- **Vertical slice:** isolated two-Peer LAN read with Owner ACL and revoke-kills-session test **only after** production admission prerequisites pass.
- **Release:** threat-model sign-off, coverage across all intended OS targets, security review, reproducible builds, migration/rollback drills, support and license gates.

## External provenance

This repository is a separate Rust-first project, not an in-place deployable rewrite of RelayProxy. Go reference baseline: `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. No wire or operational compatibility is promised.
