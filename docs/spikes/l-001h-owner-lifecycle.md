# L-001H — Ordered Owner lifecycle / delegate cancellation PoC

**Status: isolated verifier PoC. NOT integrated with persistent ResourcePolicyChain or ServiceOpen.** Stacked on PR #13.

The L-001D proof was a valid Owner-signed revoke-only grant plus delegated revocation. Its historical verifier did **not** check whether the delegate was subsequently canceled. Consequently, a valid Ed25519 signature alone is insufficient to infer live authorization.

This branch introduces a candidate resource policy lifecycle. Each operation consumes a **single strictly increasing resource policy sequence**. A valid delegated revocation consumes sequence N. An Owner-signed delegate cancellation consumes sequence N+1 and disables the exact delegated key ID and key epoch; a later revocation from that key at N+2 is refused even if the signature is valid and its wall-clock timestamp claims an earlier issuance. A separate fixed-width, domain-separated control transcript binds Space, Resource, Owner identity/epoch, delegate identity/epoch, sequence and validity window. Invalid signature, wrong Owner, wrong scope, stale sequence and duplicate cancellation fail closed.

Owner transfer is a distinct signed operation: it requires signatures from **both** the current Owner and the successor Owner, plus an independently **Root-signed successor ResourceTrust manifest**. The sequence and old/new manifest commitments are in one domain-separated transcript. The successor Owner epoch must increase exactly once. Older Owner delegates cease to be valid after transition; transfer cannot change the trusted Root/writer epoch without separately reviewed Root migration.

State is replayed from genesis in memory and commits to a deterministic `LOOM:RESOURCE-POLICY-CHAIN:V1\0` hash chain over ordered evidence. This is *different* from prior revocation-only history hashes and requires a versioned database/Checkpoint migration. No arbitrary caller-provided policy head or current sequence can initialize state.

## Critical remaining blockers

1. **Persistent unified event log**: SQLite currently persists revocations only, not delegate cancellation or Owner transfer. This PR does not yet prevent existing database APIs from accepting a signed but subsequently canceled delegate. Production store admission is **Paused**. Migration must integrate all operations into one atomic sequence, policy hash, outbox, and external high-water CAS.
2. **Authoritative lifecycle evidence**: cancellation and transfer must be replicated, witnessed, and checked under bounded freshness before any network-facing ServiceOpen. The current in-memory verifier alone cannot establish the latest state.
3. **Root/Owner recovery**: Root signature validity depends on independently trusted provisioning, Root rotation anchoring, secure time, Owner key compromise policy, and durable witness receipts.
4. **Protocol candidate**: the fixed binary control transcripts and policy chain domain need independent cross-language vectors and security review before freezing wire formats.

Do not accept ADR-20/21 or merge directly to main based solely on passing unit tests. No network service, VPN, file/desktop sharing or proxy access is activated.