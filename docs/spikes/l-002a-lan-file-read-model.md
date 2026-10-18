# L-002A — two-Peer LAN file-read and revoke model

> 2026-10-18. **TEST-ONLY SECURITY_MODEL. NO SERVICEOPEN / NO NETWORK LISTENER / NO REAL FILE ACCESS / NO TRUSTED OWNER GRANTS.** L-001 Rust PoC engineering was consolidated at `main@d50eae4`, but all nine independent L-001 security/platform release checks remain BLOCKED.

## Scope and implementation

First vertical step toward L-002: model a single server-side file resource, a requesting Peer and its Owner's read grant, with revocation checked **on every byte-chunk boundary**. The implementation lives in `crates/loom-core/src/lan_file_read_model.rs` and is included only by `#[cfg(test)]` in `loom-core/src/lib.rs`. It is not compiled into normal library or `loomd` builds.

- The `ModelLanFileServer` has one fixed `SpaceId`, `ResourceId` and an in-memory byte fixture limited to 64 KiB. There is intentionally no user-controlled path traversal, symlink, real filesystem operation, network listener, or encryption scheme.
- The test harness alone can call `owner_grant_for_test(peer, membership_epoch)` and `owner_revoke_for_test(peer)`. These methods are **not signed Owner proofs**, not independently anchored, and never return production `Decision::Allow`.
- `open_read(claimed_principal, resource)` requires exact Space/Peer/Resource/member epoch and a matching model grant; missing grant, cross-Space Peer, wrong Resource or old Epoch are refused.
- A session has a model-only unique ID, private cursor and a frozen policy revision. Each `read_chunk(size)` acquires the shared in-memory mutex, rejects stale/revoked membership/epoch/revision **before copying any further data**, and caps requests at 4096 bytes.
- Every grant, revocation, or key epoch rotation invalidates all existing session IDs. A re-grant never reactivates an old stream; a fresh server process starts with zero grants. Zero epoch and zero/oversize chunks are rejected.

## Twelve adversarial/model tests

1. No grants and no open sessions on startup.
2. One authorized Peer reads exact bytes in chunks through EOF; another Peer remains denied.
3. Wrong Space, Resource and membership Epoch are denied.
4. Revoking an already opened session rejects the **next** chunk and all new opens.
5. Re-granting after revocation cannot resurrect an old session.
6. Membership key-epoch rotation rejects old principal and stream; new exact Epoch may open only with new model grant.
7. Any policy revision invalidates existing sessions conservatively.
8. Invalid chunk size never consumes the cursor.
9. Oversize fixture and zero member Epoch are refused.
10. Fresh process has no implicit grants; old in-process handle is explicitly not a durable token.
11. Concurrent Owner revoke is ordered before a subsequent session read.
12. **The real production `DenyAllPolicy` still refuses `Action::Read`**, even when the model fixture has an Owner grant.

## Critical safety boundaries / next stages

1. **Not signed authorization.** The fake Owner grant and `PeerPrincipal` are supplied directly by test code. No signed Root/Owner/dual Witness freshness, independently durable revocation anchor, cross-process CAS or attested membership is used. No calling code may export these model grants as Resource admission permits.
2. **No real LAN.** L-002B must integrate two separately identified TLS 1.3 Peer endpoints and hostile LAN bearer tests, including explicit signed membership binding and validated file Resource scope. This cannot be enabled for production before L-001's unfinished release requirements.
3. **No disk safety.** Before actual file reading, add canonical Owner-approved file descriptors, no-follow/path escape defense, OS ACL/open-handle behavior, symlink swap, cache invalidation and per-chunk kill after signed revocation.
4. **No global atomicity or persistence.** A process-local Mutex does not serialize other device writers or physical power loss. Signed policy/TPM/hardware boundary must be proven independently before a real ServiceOpen.
5. **No actual platform tests.** Windows/macOS Rust host tests are portability only. Android VpnService, Windows traffic filtering and macOS extension entitlement gates remain blocked.

Milestone records: `docs/acceptance/l001.json` has `engineering.status=complete` referencing the consolidated Git commit, while `state=blocked` and every release check remain accurate. `python3 scripts/l001_gate.py --require-complete` must still fail.

**Next L-002B:** separately verified signed Owner/Peer membership admission *interface* and cross-peer stream integration with negative replay/wrong resource/revocation tests, still isolated until actual hardware and platform release gates are accepted.
