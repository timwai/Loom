# Loom v1.1 — implementation and release acceptance gates

> Updated 2026-10-18. **L-001 ENGINEERING INTEGRATION COMPLETE; L-001 PRODUCTION RELEASE NOT ACCEPTED.** All PoC branches were consolidated into `main` by PR #38 with full host CI. This is source-code completion, **not** signed security/hardware/platform acceptance; the independent L-001 release manifest stays blocked. A green PR workflow is not security-release approval. Source of truth: [status](STATUS.md), [machine-readable milestone](acceptance/l001.json), and [verification script](../scripts/l001_gate.py).

## Fixed provenance and scope

- **2026-10-20 L-002 formal acceptance FAILED:** the local macOS / Docker campaign reproduces full file reads after restoring the policy and both Witness logs to pre-revoke state. [Formal report](acceptance/evidence/l002-formal-20261020/REPORT.md). The laboratory regression passes; `--require-formal` and `--require-release` must fail. Independent reviews and inherited release gates remain required.

- RelayProxy comparison baseline: `timwai/RelayProxy main@e4254c81ed678198c948272c22981fd16c19be9a`. Loom is a new Rust-first project, not a drop-in Go wire-compatible agent.
- Existing Rust security work includes library crates and disabled `loomd`, signed Owner/Root/dual-Witness journal models, independent rollback and crash simulations, and isolated Peer mTLS experiments. These are **not** a usable Mesh service.
- Never assume a signed frame, persistent SQLite record, volatile CAS mutex, numeric NV value or unverified Witness pair is sufficient for production authorization.
- **Hardware neutrality:** TPM 2.0 is OPTIONAL. Windows TPM/fTPM, macOS Secure Enclave, Android Keystore/StrongBox and verified remote/quorum anchors have different security semantics and must not be treated as interchangeable. Portable software state must remain usable for ordinary, non-security-critical settings without any specific chip. Any operation requiring nonrollbackable authority instead needs independently verified, scoped high-water and crash recovery, provided by a supported backend or trusted remote protocol. Missing or stale evidence fails closed; no silent downgrade.

## L-001 acceptance is conjunctive

| Gate | Required executable, independently reviewed result | Current outcome |
|---|---|---|
| **L-001A / E2EE-01** | Real two-Peer encrypted channel through hostile relay/direct bearer; adversarial replay, tamper, substitution, key-rotation, resource limits; live daemon session tests | **PARTIAL:** isolated TLS 1.3 certificate-pinned PoC and malicious bearer tests, no live service |
| **L-001A / TLS-ID-01** | TLS peer cert/SPKI proof tied to current signed membership, Root/Space, authenticated key epoch, expiry, revocation and authorized Owner resource decision | **PARTIAL:** certificate + Space/Peer/epoch binding only, no production trust provisioning |
| **L-001B / WIRE-01** | Frozen canonical typed security event schema and signing input, Rust/Go/Kotlin/JS golden vectors, malformed/fuzz/differential interop, protocol version negotiation | **PARTIAL:** four-language 3-vector canonical CBOR/signing transcript CI, not final typed payload/fuzz/interoperability sign-off |
| **L-001C / AUTHZ-RACE-01** | No stale policy/Owner or two-Peer revoke bypass; real admission-to-session atomicity and cross-process writer coherence | **PARTIAL:** signed journal/recovery and in-memory reservation models; no production ServiceOpen |
| **L-001C / AUTHZ-CRASH-02** | Verified real power-loss/restart around durable Prepared, independently trustworthy replay fence and backend-specific monotonic state (hardware or authenticated independent quorum), signed recovery/repair | **PARTIAL:** deterministic crash simulators only; real provider failure semantics unverified |
| **L-001C / ROLLBACK-01** | Independently enrolled nonrollbackable or equivalently trustworthy antirollback anchor, proven signer/fence provenance, backup/clone/reset or remote quorum fault acceptance across processes and hosts; **no mandatory TPM chip** | **PARTIAL:** no vetted hardware or independent quorum adapter; model only |
| **L-001D / PLATFORM-ANDROID-01** | Android VpnService lifecycle/permissions on real target, traffic/no-leak, driver/device failure and reboot | **BLOCKED:** Android/Bionic and separate VPN API APK passed on JP Docker with PSI; production Rust/JNI VPN, full leak tests and real-device integration remain unverified |
| **L-001D / PLATFORM-WIN-01** | Windows filter/driver/socket real-host path, privileges, signed deployment, crash/reboot, fail-closed traffic behavior | **BLOCKED:** Windows-hosted Rust tests do not test drivers |
| **L-001D / PLATFORM-MAC-01** | macOS Network/System Extension real-host entitlement, user consent, traffic, crash/reboot and signed deployment | **BLOCKED:** macOS-hosted Rust tests do not test extensions |

**All nine** gates must be marked passed with independently reviewed, repository-attached evidence; required security, **trusted-state-provider/antirollback**, wire-interop and platform sign-offs must also be complete. Only then may `docs/acceptance/l001.json` be changed to `state=complete`, and `python3 scripts/l001_gate.py --require-complete` may return zero.

## Current evidence, not release approval

- **2026-10-20 JP Android Docker:** 248 native tests, TLS/storage recovery and a standalone debug VPN API APK passed before and after container restart. Actual system consent, TUN/protect routing, Settings disconnect and app-SIGKILL cleanup were exercised. [Report](acceptance/evidence/l001-android-jp-20261020/REPORT.md). The APK contains no Loom Rust/JNI forwarding or production authorization; it does not satisfy physical-device acceptance.
- **2026-10-19 macOS / Docker lab:** 244 Rust tests per OS, strict Clippy, four real TCP/mTLS paths, 20 fixture-identity/scope refusals and nine process/container SIGKILL recoveries. [Report, raw samples and logs](acceptance/evidence/l001-local-docker-20261019/REPORT.md). This adds concrete PoC evidence; signed production membership/Owner admission, independent rollback storage, physical power loss and platform-driver gates remain unpassed.
- L-001A / Draft #7 and reintegration #36: isolated mTLS Peer channel, malicious bearer and identity-bound tests.
- L-001B / Draft #35: independent strict Rust, Go, JavaScript, Kotlin golden CBOR/signing-input test runners executed in GitHub Actions.
- L-001C / Draft #8–#34: signed journal replay, outbox/Audit, Root/Owner/Witness, counter/intent, signed record and recovery state models. No proven independently durable, rollback-resistant CAS or authenticated remote quorum.
- L-001D / post-#36 host portability smoke: GitHub Windows/macOS Rust workspace testing only; **PLATFORM-*** remains blocked.

See the actual CI results in PRs and `docs/STATUS.md`. Do not label an accepted model test as physical hardware proof. The consolidated `main` is **NOT** approved for production runtime, TPM writes or ServiceOpen.

## Next development and no-go

Engineering can advance the original L-001A/B/C/D code, but **the selected trusted-state backend** (optional TPM, platform keystore with separately demonstrated properties, or independently authenticated quorum), Windows/macOS extension or filter deployment, and Android VpnService cannot be attested by in-memory GitHub runners. Owner authorization, revocation-to-open-session termination and independently pinned freshness must also be integrated into `loomd` before ServiceOpen is considered.

**No-Go:** public WAN relay, traffic interception without OS approval, auto-ban of self-reported RDP IP, automatic trust restoration from legacy databases, unverifiable signer/witness credentials, claimed Rust performance superiority without measurement, or any production ServiceOpen before nine-gate and human release sign-off.

**L-002 isolated laboratory accepted (2026-10-20):** A–C models are extended by authenticated Owner/Witness append, durable SQLite crash recovery and opt-in TLS file-snapshot reads/revocation. macOS/Linux each pass 282 tests, six grant/revoke SIGKILL cases per OS and a two-container internal LAN experiment. [Report](acceptance/evidence/l002-isolated-lab-20261020/REPORT.md), [machine-readable record](acceptance/l002.json), `python3 scripts/l002_gate.py --require-lab`. Public fixture keys and same-host Witness logs do not satisfy independent trust or production admission; **L-002 release stays BLOCKED**, `loomd` stays disabled and `--require-release` must fail.

2026-10-20: [Integrated existing-environment lab](acceptance/evidence/l001-integrated-20261020/REPORT.md) passes 268 tests on macOS, Linux and Android, including signed-member/Owner candidate verification and actual Rust JNI membership/TUN/protected-socket checks after container restart. This does not establish production VPN forwarding, revocation/session barriers, atomic ServiceOpen, trusted enrollment or antirollback. Windows is currently unavailable and macOS signing unavailable; no independent signoff is inferred.
