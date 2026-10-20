# L-002E — isolated LAN file-read and revoke acceptance

2026-10-20. **`L-002-isolated-lab-v1` PASSED; formal L-002 release BLOCKED.** Implementation is opt-in `loom-core/experimental-lan`; `PeerCore`, `DenyAllPolicy` and the normal `loomd` command retain their disabled defaults.

The Owner supplies an already-open regular file to `LanReadCandidate::from_owner_file`. Enrollment seeks to its beginning, checks bounds and freezes at most 1 MiB as an immutable snapshot with a SHA-256 digest. The caller must select that handle using a trusted local enrollment flow and prevent concurrent editing during enrollment. The network receives only a typed resource ID; it never opens a path, follows a client symlink, seeks a caller offset or writes file data. Path/symlink replacement after the approved handle is opened cannot redirect the enrolled snapshot. Later file edits require explicit re-enrollment; this is snapshot transfer, not a live filesystem server.

The transport is existing TLS 1.3 mutual authentication with pinned Ed25519 certificates and Root-delegated signed membership. Each open/chunk matches the TLS peer identity, TLS key epoch, Space, membership epoch, current credential validity and the Root-selected signed read ACL. A live membership verifier is checked again after the external Witness callback. The file service generates a new OS-CSPRNG nonce per call and demands exactly two Root-pinned Witness signatures on the same nonce, full policy head, revocation root and generation. It then replays local policy under a SQLite read transaction, checks exact equality and releases at most 4096 bytes under the commit barrier. Offline, partial, replayed, split, restored or corrupt state refuses.

A session freezes policy head, member/key epochs and file digest. Any policy transition invalidates that session, even revoke followed by re-grant. Reopening after revocation is denied, and restart never inserts an implicit grant. Bytes already copied before the revocation may remain in TLS/kernel buffers; they cannot be recalled. The measured guarantee is that a chunk checked after committed revoke is refused.

The laboratory executable is one bounded pull session per process, with read-only resource IDs and explicit error frames. It rejects zero/oversize chunks, write operations and incorrect resources. It binds loopback by default. Public fixture credentials may be used on a nonloopback interface only under the explicit isolated-lab environment flag; the acceptance script uses a Docker **internal** network without published ports and removes only containers/network it created. It must never be run with fixture credentials on a user/public LAN.

Reproduce on macOS with Docker and the existing `loom-l001-lab:local` image:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --features loom-core/experimental-lan --locked
cargo clippy --workspace --all-targets --features loom-core/experimental-lan --locked -- -D warnings
python3 scripts/l002_acceptance.py
python3 scripts/l002_gate.py --require-lab
python3 scripts/l002_gate.py --require-release  # expected exit 1
```

The image is built by `docker build -f scripts/l001-lab.Dockerfile -t loom-l001-lab:local .` if absent. `--host-only` runs the process/TCP/crash subset and records `host-only-passed`; it cannot satisfy full lab acceptance. Runtime files and fixture credentials stay under ignored `target/`; archive only logs, transcripts, source hashes and summaries.

Fourteen added tests cover actual encrypted bytes, startup deny, wrong scope/member, revocation/re-grant/restart, partial quorum, nonce replay/offline, revocation or membership pause during observation, restored policy backups, path replacement/chunk bounds, signed fork/tamper/restart, cross-connection commit fencing, expired revocation replay, concurrent fork quarantine, key/member epoch rotation, missing logs, torn records and file bounds. Existing channel attack and signature tests remain part of the full 282-test suite.

The actual network experiment uses two container network namespaces on one host. Witness callbacks still read local logs and fixture signers synchronously; no remote Witness service is implemented. Production Tokio scheduling must move blocking storage/signing work off runtime workers. Membership pause and policy commits are separate authorities; a globally atomic membership-revocation barrier is not claimed. Root/key enrollment, independent rollback protection, cross-device writer fencing, platform deployment and independent reviews remain release blockers. No old Server can be retired on this evidence.
