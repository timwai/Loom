# Loom v1.1 — implementation and release acceptance gates

> Updated 2026-10-18. **L-001 ENGINEERING INTEGRATION COMPLETE; L-001 PRODUCTION RELEASE NOT ACCEPTED.** All PoC branches were consolidated into `main` by PR #38 with full host CI. This is source-code completion, **not** signed security/hardware/platform acceptance; the independent L-001 release manifest stays blocked. A green PR workflow is not security-release approval. Source of truth: [status](STATUS.md), [machine-readable milestone](acceptance/l001.json), and [verification script](../scripts/l001_gate.py).

## Fixed provenance and scope

- RelayProxy comparison baseline: `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is a new Rust-first project, not a drop-in Go wire-compatible agent.
- Existing Rust security work includes eight library crates and disabled `loomd`, signed Owner/Root/dual-Witness journal models, independent rollback and crash simulations, and isolated Peer mTLS experiments. These are **not** a usable Mesh service.
- Never assume a signed frame, persistent SQLite record, volatile CAS mutex, numeric NV value or unverified Witness pair is sufficient for production authorization.

## L-001 acceptance is conjunctive

| Gate | Required executable, independently reviewed result | Current outcome |
|---|---|---|
| **L-001A / E2EE-01** | Real two-Peer encrypted channel through hostile relay/direct bearer; adversarial replay, tamper, substitution, key-rotation, resource limits; live daemon session tests | **PARTIAL:** isolated TLS 1.3 certificate-pinned PoC and malicious bearer tests, no live service |
| **L-001A / TLS-ID-01** | TLS peer cert/SPKI proof tied to current signed membership, Root/Space, authenticated key epoch, expiry, revocation and authorized Owner resource decision | **PARTIAL:** certificate + Space/Peer/epoch binding only, no production trust provisioning |
| **L-001B / WIRE-01** | Frozen canonical typed security event schema and signing input, Rust/Go/Kotlin/JS golden vectors, malformed/fuzz/differential interop, protocol version negotiation | **PARTIAL:** four-language 3-vector canonical CBOR/signing transcript CI, not final typed payload/fuzz/interoperability sign-off |
| **L-001C / AUTHZ-RACE-01** | No stale policy/Owner or two-Peer revoke bypass; real admission-to-session atomicity and cross-process writer coherence | **PARTIAL:** signed journal/recovery and in-memory reservation models; no production ServiceOpen |
| **L-001C / AUTHZ-CRASH-02** | Verified actual power-loss and restart around durable Prepared, independent replay fence, hardware NV, signed recovery/repair | **PARTIAL:** deterministic crash simulators only |
| **L-001C / ROLLBACK-01** | Root/device enrolled nonrollbackable anchor, provenance of signer/fence, TPM reset and backup-rollback acceptance across processes and hosts | **PARTIAL:** abstract/verifier/model only |
| **L-001D / PLATFORM-ANDROID-01** | Android VpnService lifecycle/permissions on real target, traffic/no-leak, driver/device failure and reboot | **BLOCKED:** no Android device or app integration |
| **L-001D / PLATFORM-WIN-01** | Windows filter/driver/socket real-host path, privileges, signed deployment, crash/reboot, fail-closed traffic behavior | **BLOCKED:** Windows-hosted Rust tests do not test drivers |
| **L-001D / PLATFORM-MAC-01** | macOS Network/System Extension real-host entitlement, user consent, traffic, crash/reboot and signed deployment | **BLOCKED:** macOS-hosted Rust tests do not test extensions |

**All nine** gates must be marked passed with independently reviewed, repository-attached evidence; required security, hardware, wire-interop and platform sign-offs must also be complete. Only then may `docs/acceptance/l001.json` be changed to `state=complete`, and `python3 scripts/l001_gate.py --require-complete` may return zero.

## Current evidence, not release approval

- L-001A / Draft #7 and reintegration #36: isolated mTLS Peer channel, malicious bearer and identity-bound tests.
- L-001B / Draft #35: independent strict Rust, Go, JavaScript, Kotlin golden CBOR/signing-input test runners executed in GitHub Actions.
- L-001C / Draft #8–#34: signed journal replay, outbox/Audit, Root/Owner/Witness, counter/intent, signed record and recovery state models. No physical trusted durable CAS.
- L-001D / post-#36 host portability smoke: GitHub Windows/macOS Rust workspace testing only; **PLATFORM-*** remains blocked.

See the actual CI results in PRs and `docs/STATUS.md`. Do not label an accepted model test as physical hardware proof. The consolidated `main` is **NOT** approved for production runtime, TPM writes or ServiceOpen.

## Next development and no-go

Engineering can advance the original L-001A/B/C/D code, but real TPM sacrificial hardware, Windows/macOS extension or filter deployment, and Android VpnService cannot be attested by in-memory GitHub runners. Owner authorization, revocation-to-open-session termination and independently pinned freshness must also be integrated into `loomd` before ServiceOpen is considered.

**No-Go:** public WAN relay, traffic interception without OS approval, auto-ban of self-reported RDP IP, automatic trust restoration from legacy databases, unverifiable signer/witness credentials, claimed Rust performance superiority without measurement, or any production ServiceOpen before nine-gate and human release sign-off.

**L-002A has started:** twelve test-only Rust model cases for two-Peer LAN file reads with simulated Owner ACL, exact Space/Peer/Resource/Epoch binding and revoke-on-next-chunk behavior. This is not a real LAN transfer and cannot relax any L-001 release gate; see [L-002A test plan](spikes/l-002a-lan-file-read-model.md).
