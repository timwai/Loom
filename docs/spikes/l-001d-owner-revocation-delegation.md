# L-001D — Resource Owner revoke-only delegate chain (engineering PoC)

This branch is stacked on PR #9, and **does not authorize network ServiceOpen**.

## Source-aligned decision

Loom v1.1 §7 differentiates the SpaceRoot, MembershipWriter, EmergencyRevoker and **ResourceOwner**. A SpaceRoot does **not** automatically own arbitrary resources. This PoC instead starts from a locally *provisioned* `(space_id, resource_id, owner Ed25519 public key, owner_key_epoch)` anchor. Provisioning authenticity, owner transfers, independent witnesses, issuer high-water and rollback protection are not implemented.

- Validate signed, bounded **OwnerGrant** canonical CBOR issued by this **resource-specific Owner**, including owner key ID derived from `SHA256("LOOM:KEY-ID:V1\\0" || owner_pubkey)`, scope, epoch, timestamps, key-ID integrity, and nonzero sequence.
- Grant payload candidate (89 bytes): `resource_id[16] || delegate_pubkey[32] || derived_delegate_key_id[32] || revoke_only[1] || delegate_key_epoch_be[8]`.
- Strictly accept capability **0x01 = revoke only**; grant cannot authorize writes, new membership, new Grants, or delegation to other scopes.
- Verify a *second* canonical event, signed by the delegated key: `Revocation`, same Space, same delegated epoch, same resource, valid within both the grant's and event's time windows.
- Return **OwnerVerifiedRevocation** with private fields; unlike the untrusted `VerifiedRevocation` from PR #9, only this Owner-delegated proof type reaches the non-test SQLite commit entry.
- SQLite `commit_owner_revocation` enforces exact `(space, resource, seq=epoch+1)`. Stores both signatures and canonical CBOR blobs in a version-tagged replay envelope, atomically with local epoch, outbox and audit.
- The old `commit_verified_revocation` entry with a caller-provided `PinnedIssuerForSpike` is **absent from production builds**, retained only as `commit_spike_revocation_for_test` under `#[cfg(test)]`.

## Tests and unresolved gates

Six new adversarial Owner/delegation tests and one SQLite proof persistence/restart test exercise bad Owner/delegate signature, modified scope, cross-space, grant-expiry, key-epoch mismatch, wrong grant type and unauthorized delegation rights.

**Still NOT verified or implemented:** authenticity of the *provisioned Owner anchor*, independent signed witness freshness, scope of actual EmergencyRevoker, durable delegation revocation history, real time, chain equivocation checks, Owner transfer, and remote quorum. A formerly valid delegation could have been revoked while offline. An accepted signature therefore **does not prove current permission**.

`SqliteRevocationStore::open` remains **PAUSED** in production. No production method can transition to `READY` today. Tests simulate witness recovery solely to exercise the linearization and persistence code.

L-ADR-07/20/21 remain **PROPOSED**. Never publish a network listener or mark ServiceOpen safe based on this PoC.
