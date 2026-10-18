# L-001E Two-witness signed rollback checkpoint (engineering PoC)

This work is stacked on Loom PR #10. The prior test-only high-water number is replaced for diagnostic recovery by two independent Ed25519 checkpoint signatures.

The fixed checkpoint transcript commits to SpaceId, resource/chain ID, writer epoch, sequence, head hash, revocation root, issue time, and expiry. Two separately configured pinned witness keys MUST each sign exactly matching checkpoint contents. Forged, unknown, duplicate, missing, stale, wrong-scope and conflicting receipts reject. This does not claim globally latest state.

For each resource, SQLite history is replay-hashed using SHA-256 over the domain-separated previous root, increasing epoch, evidence length and signed evidence. Evidence gaps, wrong sequence, DB backdating and tampering cannot be reported consistent against an independently signed newer checkpoint. Recovery assessments distinguish ConsistentCandidate, RollbackDetected, WitnessBehind and HistoryDiverged.

The current PoC is explicit about limits: the resource ID is the chain ID, and head_hash is temporarily equal to the evidence root, not a real separate signed Owner/Writer linked head. Authenticated witness provisioning, external secure clock, independent durable anchor/key store, full Owner history verification, hostile network partition tests and real platform recovery are NOT complete.

Every call to inspect_witnessed_recovery pauses the admission gate, even with identical evidence. No production Ready transition, no ServiceOpen, no Relay, no transparent proxy, and no legacy wire compatibility. ADR-21 remains PROPOSED. Tests cover forged and duplicate witnesses, conflicting signed checkpoints, old SQLite backups, same-epoch tampering, lagged witnesses and corrupted local history.
