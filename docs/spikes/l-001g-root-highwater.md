# L-001G: dual-signed Root rotation and independent high-water interface

**Status: engineering PoC, no production-ready platform anchor.** Stacked on PR #12.

## Implemented

The Root-rotation transcript is `LOOM:ROOT-ROTATION:V1\0 || space_id[16] || old_root_ed25519[32] || new_root_ed25519[32] || old_epoch_u64be || new_epoch_u64be || issued_ms_u64be || expires_ms_u64be`. Both old and new keys sign exactly these bytes. The verifier requires the previous key to equal an independently pinned trust root and the epoch to increase by **exactly one**; replay, wrong Space, wrong old/new key, forged signatures, reusing the same key and invalid validity windows fail closed.

A Root-verified resource manifest now keeps its verified signing Root identity, root epoch, and a deterministic manifest commitment. **An epoch match alone is not enough**: a different Owner or witness set under the same Root key is a separate manifest and must be explicitly migrated.

The `IndependentHighWaterAnchor` interface exposes `read(space,resource)` and atomic `compare_and_advance(expected,next)`. A record binds `space, resource, root key, root epoch, signed manifest digest, writer epoch, signed witness seq and revocation root`. The `checked_high_water_update` function rejects stale checkpoints, equal-version hash divergence, expired Root manifests and changes to Root/Owner/witness policy or Writer epoch without an explicit signed migration.

`SqliteRevocationStore::inspect_root_recovery_with_anchor()` holds the same admission gate, verifies both Root-selected witnesses, replays all signed Owner/delegate evidence, hashes the actual SQLite events, compares the result to the signed checkpoints, then **reads and conditionally advances an independently trusted high-water record**. Storage read errors, missing anchors, failed/ambiguous writes and CAS conflicts fail closed. Even on success, the result is *diagnostic only* and admission remains `Paused`.

## Crucial caveats

- There is **no production implementation** of an independently authenticated, rollback-resistant `IndependentHighWaterAnchor` for Windows/macOS/Linux/Android. Only deterministic test doubles are present. Plain JSON files, copied disk/SQLite backups, ordinary Keychain/Keystore records and untrusted Relay state are not accepted as proof of monotonicity.
- A successful dual Root signature verification returns a proposed new Root pin, **not** proof that a trusted external store committed it. Full atomic root-promotion/manifest-migration with crash recovery is not implemented; a rotation is not automatically installed.
- This PoC conservatively refuses a changed Root key/epoch or resource manifest in existing high-water state. It thereby favors safety over automatic Owner transfers or Root migration.
- Revoked revoke-only delegates, Owner transfer history, genuine offline/clock rollback, witness eclipse/collusion, disk full and process kill -9 remain unverified.
- The existing signed-history replay validates authorization at historical issuance. It does **not** guarantee that a delegation has not subsequently been revoked outside the evidence chain.
- Neither Root rotation nor a consistent high-water record can make `ServiceOpen` ready; **no service admission, Relay listener, VPN or transparent interception is enabled**. ADR-21 remains PROPOSED.

## Verification

`cargo test --workspace --all-targets --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`, and cargo-deny are enforced by GitHub Actions. Negative tests include forged old/new Root signatures, wrong epochs, changed Space, replayed rotation, high-water rollback, equal-seq divergent hash, CAS conflict, missing anchor, ambiguous anchor persistence and a good Root/Owner/witness/DB evidence chain with monotonically advanced test anchor.

**Safety gate:** The next step must be independent platform storage feasibility spikes and explicit Root key recovery/transfer protocols, not a production network release.
