# L-001F Root-bound witness provisioning and signed-history replay PoC

Stacked on L-001E PR #11. The prior checkpoint system accepted two caller-provided witness pins and compared SQLite history only by SHA-256. This branch creates an **authenticated relative chain** from an *externally pinned Space Root* to one Resource Owner and two distinct witness verification keys.

A Root-signed, fixed-width and domain-separated manifest binds SpaceId, ResourceId, Owner public key + epoch, two witness public keys, writer epoch, Root epoch and validity interval. A different Root, cross-Space manifest, modified Owner, replaced witness, expired manifest, wrong epoch or duplicate witness key is rejected. The Root public key itself MUST come from independent authenticated provisioning and cannot be imported from an untrusted Relay/SQLite snapshot. No secure external Root store or cryptographically guaranteed time is implemented yet.

The new store API `inspect_root_bound_recovery()` verifies both checkpoints against Root-selected witnesses, verifies writer epoch, and **replays each saved Owner-signed revoke-only delegation plus delegate-signed revocation** for the configured resource before rehashing the evidence and comparing sequence/root. Unsigned events that could pass hash-only comparison are rejected. It intentionally still does not validate delegation revocation after historical issuance, Owner transfers, writer equivocation, or cryptographic high-water stored outside the rollback domain.

All verification is diagnostics-only: the gate is paused on entry and remains Paused regardless of success; there is no production Permit or ServiceOpen. The old hash-only `inspect_witnessed_recovery` remains as an explicitly weaker diagnostic used for baseline tests and must **not** serve as an authorization gate.

Root epoch/manifest staleness, external trusted Root key storage, physical witness independence, secure time, delegation revocation and full historical Root evolution remain blocking work. The signed manifest is a protocol candidate pending cross-language vectors and review. ADR-21 stays PROPOSED.
