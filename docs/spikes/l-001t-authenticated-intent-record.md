# L-001T — Canonical authenticated Prepared-intent record (Ed25519)

**Status:** unmerged Rust verification PoC based on L-001S / Draft PR #26. **No signing-key provisioning, real disk persistence, TPM2 NV writer, trusted replay-fence backend, ServiceOpen or operational mesh.**

## Purpose and threat boundary

A durable Prepared intent is useless as a rollback guard if an attacker can edit its bytes, replace it with another device's record, replay an older signed record, or silently switch the signing key. L-001S only simulates media effects. L-001T adds a **strict authenticated record envelope** for the existing `StoredBinding::{Committed,Prepared}` structures.

A frame may be *parsed and signature-verified*, but it is trusted only relative to **three external observations that this PoC deliberately does not create**:

1. An independently enrolled `ExternalSignerPin`: the exact Ed25519 signer public key + monotonically managed signer epoch, device binding + NV index, Space/Resource, Root public key and epoch, authenticated genesis manifest and writer epoch. Trust MUST NOT be imported from a backup or inbound network data.
2. An independently authenticated `ExternalReplayFence`: minimum durable record sequence, minimum independently protected counter and exact digest of the last committed record. The `last_record_digest` guards **same-sequence forks**. A missing external fence cannot be reconstructed securely from record content.
3. The independently observed counter value. Even a correctly signed `Committed` image is rejected if its counter differs; a `Prepared` image is accepted only when the count is exactly N or N+1, with distinct diagnostic states.

A successful result **is not authorization** and cannot enable resource, file, relay, proxy, VPN or ServiceOpen operations.

## Canonical signed V1 binary format

All integers are fixed-width **unsigned big-endian**. Every field has one positional encoding, with **no self-described lengths**, optional padding or trailing bytes.

| Offset | Width | Content |
|---:|---:|---|
| 0 | 8 | Magic ASCII `LOOMINT1` (signed domain separation) |
| 8 | 2 | Version 1 |
| 10 | 1 | Phase: 1 Committed or 2 Prepared |
| 11 | 1 | Reserved byte **0** |
| 12 | 8 | Monotonically issued record sequence, nonzero |
| 20 | 8 | Independently enrolled signer epoch, nonzero |
| 28 | 32 | Signer public key (compared to external pin) |
| 60 | 260 | `Committed`: device binding (32), NV index (4), counter (8), complete unified high-water (216) |
| 320 | 104, Prepared only | `after_sequence` (8), `after_head` (32), `after_revocation_root` (32), `after_manifest` (32) |
| End - 64 | 64 | Ed25519 signature over all bytes before the signature |

**Exact frame sizes:** Committed **384 bytes**; Prepared **488 bytes**. High-water is `Space(16), Resource(16), RootPublicKey(32), RootEpoch(8), GenesisManifest(32), CurrentManifest(32), WriterEpoch(8), PolicySequence(8), PolicyHead(32), RevocationRoot(32)`. All 260/216/104 lengths are enforced by parser constants.

Record digest is `SHA256("LOOM:INTENT-RECORD-DIGEST:V1\\0" || complete signed frame)`, not an unhashed SQLite cursor. This digest is meaningful as a replay fence only if it is recorded in **a separate authenticated, nonrollbackable domain**.

The signing API exports a *preimage builder* only: it **does not** hold or generate signing private keys. The verifier uses strict Ed25519 verification against the externally pinned key. An attacker cannot choose the signing key by inserting one into the frame.

## Fail-closed verification

- Reject unknown version/tag, nonzero reserved byte, truncated/oversized frames, trailing payload, nonzero tag without exact length, zero sequence/epoch, malformed Prepared transition.
- Reject any altered signed byte, wrong signature, wrong pinned device/NV index/Space/Resource/Root/genesis/writer or false signer epoch.
- Reject `record_sequence < minimum_record_sequence` and observed counter below the external minimum. At **equal** sequence, require exact signed-frame digest match; a distinct validly signed frame at the same sequence is still a fork.
- Accept a new key only after **explicit external pin rotation**, with signer epoch bound into the signature and a separate monotonic fence. A record cannot authorize its own key rotation.
- Compare the observed independent counter against `Committed` or `Prepared.before` exactly, allowing Prepared N or N+1 as different *diagnostic* results.
- `StoredBinding::Missing` has no valid signed frame.

## Verification and test coverage

Eight dedicated Rust tests cover canonical round trip, both frame lengths, dozens of bit flips and adversarial re-signing, version/reserved/length/phase mistakes, cross-device and cross-Root substitution, old-record and equal-sequence fork replay, explicit signing-key rotation, wrong counter and bad fence initialization, plus a signed-record integration test against the L-001S post-increment crash image and restored stale intent. Run full repository CI:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
cargo deny check
```

## Explicit blockers / next gate

1. An Ed25519 signature does **not** prove freshness; the external replay fence, signing-key pin, signer-epoch advancement and observed counter MUST be provisioned and updated durably and authentically. The code contains **no real authenticated monotonic storage implementation**.
2. Keys are synthetic, local **test-only** signing keys. No platform key protection, device attestation, rotation ceremony, failure-domain design, secure clock or anti-eclipse witness protocol has been implemented.
3. The candidate records are not automatically wired to a real IntentStore writer or the physical NV device. There is no persistence/tearing test with real fsync or TPM power loss, cross-process exclusion or atomic multi-medium commit.
4. The earlier L-001Q SQLite transaction lock across modeled external I/O remains unsuitable for real devices; production integration requires a reviewed nonblocking protocol with revalidation.
5. Legacy migration, network ServiceOpen, transport and deployable Mesh remain **NO-GO**.

**Proposed L-001U:** integrate authenticated record **read** validation at a fail-closed candidate-intent adapter boundary, and build deterministic tests for key-rotation + crash-recovery replay fences against the L-001S media simulator. Still no physical TPM writes or production authorization.
