# Loom implementation status

> Updated 2026-10-17. This tracks the **stacked, unmerged development branches**, not the default `main` branch. A green PoC CI job does not authorize production resource access.

## Current delivery status

**SECURITY_POC / NO_NETWORK_LISTENERS / NO_PRODUCTION_ADMISSION / NO_MESH_SERVICE**

- The default `main` branch contains the initial repository baseline; all Rust implementation work remains in Draft PRs stacked from L-000 through L-001J.
- The workspace contains eight library crates, one disabled `loomd` binary, candidate security codecs and authenticated Owner lifecycle verifiers.
- Local SQLite persistence PoCs include revocation-only history and a separate three-kind unified policy journal. **Neither is the production source of truth** until a reviewed, verifiable migration and independent rollback-resistant policy high-water are implemented.
- No wired two-Peer transport, membership convergence, privilege separation, platform network integration, ServiceOpen, file sharing, RDP, VPN or proxy is available.

## Implemented candidate work (unmerged)

| Milestone | Scope | Status |
|---|---|---|
| L-000 / PR #1 | Rust workspace; deny-by-default core; design and CI | Bootstrap PoC |
| L-001A / PR #7 | Experimental TLS 1.3 mTLS Peer channel over bearer | Channel PoC |
| L-001B / PR #6 | Candidate canonical CBOR + Go/Node golden vectors | Wire PoC |
| L-001C / PR #8 | Revocation-only SQLite transaction, Outbox and admission barrier | Store PoC |
| L-001ABC / PR #9 | Ed25519 verified revocation ingress | Verification PoC |
| L-001D Owner / PR #10 | Owner-issued revoke-only delegation and signed revocation | Authorization PoC |
| L-001E / PR #11 | Dual-witness checkpoints and local rollback diagnostics | Recovery PoC |
| L-001F / PR #12 | Root-authorized Owner/witness trust and signed replay | Trust PoC |
| L-001G / PR #13 | Dual-signed Root rotation and high-water CAS interface | Anti-rollback interface PoC |
| L-001H / PR #14 | Delegation cancellation and two-Owner transfer state machine | Lifecycle PoC |
| L-001I / PR #15 | Atomic unified resource-policy journal; full signed replay | Journal PoC |
| L-001J / Draft successor | Detect missing/modified/orphaned Outbox/Audit mirrors | Mirror-integrity PoC |

The real OS networking milestone also called `L-001D` in the original implementation plan is **not completed**; the Owner delegation work used an overlapping milestone label. Resolve the label before promotion.

## Verification boundary

- The L-001I head was checked by GitHub Actions, including Rust fmt, tests, strict Clippy, docs and cargo-deny. The L-001J head requires its **own** independent CI review.
- Existing tests cover signed-event replay, unauthorized Owner/delegate events, SQLite atomic transaction abort, process restart and local mirror tampering. These are engineering tests, not power-failure/Byzantine safety certification.
- Signed migration from `sqlite_revocation` to `unified_policy_*`, external monotonic storage, secure Root onboarding, clock integrity and cross-device convergence are **open P0 security gates**.
- Mirror verification only compares tables inside the same SQLite storage domain; a consistent whole-database rollback remains invisible without an independently trusted anchor.
- `pending_outbox()` is diagnostic, not authenticated delivery permission.

## Next gates (in order)

1. Review stacked PR diffs and this security boundary; keep every PR Draft until its final head checks and dependencies are verified.
2. Agree a single canonical journal and signed one-way migration; do not interpret old revocation-only hashes as a unified Owner lifecycle head.
3. Design and verify an actual independent Root/policy high-water anchor, witness freshness, recovery and remote receipt protocol.
4. Implement an isolated two-Peer LAN secure file-read/revoke vertical slice with production admission still gated on successful trust policy checks.
5. Then run Windows/macOS/Linux/Android integration, crash and failure-injection matrices.

## Baseline provenance

The RelayProxy Go comparison baseline is `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom intentionally does not claim wire or deployed-agent compatibility.

The original L-000 scaffolding deliberately rejected all production cryptography, policy admission and network operations. Later draft branches add **isolated** real verifier PoCs but have not converted that scaffolding into a production runtime.
