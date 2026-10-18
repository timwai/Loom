# L-001O — TPM NV counter / unified policy-chain binding candidate

**Scope:** a tested **crash/recovery state machine**, not a TPM NV storage implementation or security certification. Stacked on L-001N PR #21. Production `ServiceOpen` stays permanently disabled.

## Why a bare TPM counter is insufficient

A TPM NV monotonic counter can potentially resist ordinary disk rollback, but its numerical value **does not commit to** a Root key, Resource Owner, witness quorum, Writer epoch, full policy-chain head or revocation-only accumulator. Merely reading a number from TPM cannot authorize a resource or reconstruct missing signed evidence. Binding the counter to a SQLite record that itself can be rolled back requires strict mismatch detection, independently enrolled device/NV identity, signed and fresh witness evidence, historical SQLite signature replay, and a reviewed crash protocol.

L-001O creates `loom-store::tpm_counter_binding`:

- `PinnedCounterIdentity` represents an **externally enrolled** device binding and NV index. The module does not establish that binding cryptographically.
- `CandidateMonotonicCounter` defines `read` and irreversible `increment` behavior; `CandidateIntentStore` defines `load`, `prepare`, `finalize` durability semantics. **Only in-memory test doubles implement these interfaces.** The real Linux TPM2 capability probe in L-001N stays read-only and deny-all. No `TPM2_NV_Increment` command is sent.
- `Committed` ties an independently observed counter to a complete `UnifiedPolicyHighWater`: Space/Resource scope, Root identity/epoch, genesis and current Owner-manifest commitments, Writer epoch, global policy sequence, full policy head and revocation-only root.
- `Prepared` saves the prior committed state and the proposed next complete policy record. A numerically later high-water must be justified by two **Root-approved Ed25519 witness** signatures. It cannot reuse an unchanged sequence.
- `inspect_counter` recognizes matching committed state, prepared before increment, prepared after increment, and fail-closed mismatch/overflow. The result is explicitly a **diagnostic**, not a network authorization permit.

## Ordered candidate transition

1. Read the counter and committed binding; **reject** a missing binding, different pinned device identity, any mismatch or prepared state requiring recovery.
2. Verify both Root-selected witness signatures and bound scope, writer epoch, time, policy sequence, full policy head, revocation-only root and Owner manifest commitment through `checked_unified_promotion`. **The calling code must separately replay the entire persisted signed Owner/delegate/transfer journal.**
3. Persist a Prepared intent *before* touching the counter. A production store must durably fsync and serialize cross-process writers; this is not implemented.
4. Request exactly one monotonic increment, read back the observed counter, and reject unexpected values. Any error or lost response is **ambiguous** and must not be interpreted as a failed increment.
5. Finalize the local binding only when the physical counter equals the exact previous value +1. The marker itself is rollbackable; a restored older record with an older number is rejected when the separately protected TPM still has a larger counter.
6. On restart, read the actual counter again. Prepared before increment stays quarantined without automatic retry. Prepared after increment may be finalized only after **re-checking the identical signed witness policy**. If the signed policy differs, reject.

### Failure tests

Tests simulate a correct numeric transition, journal-stage error (no increment), increment error before/after state change, post-increment finalize error, forged witness on restart, old application/SQLite snapshot restoration, TPM reset, external counter interference, wrong pinned device identity, missing trusted binding, duplicate/nonadvancing sequence, and 64-bit counter overflow.

Passing these deterministic model tests **does not** prove physical durability, TPM attestation, secure clock, signed evidence freshness, TPM counter permissions/limits, command atomicity, multi-process synchronization, or crash recovery against hostile devices. A local in-memory journal is not an independently trusted anchor.

## Mandatory gates before real NV writes

- Confirm *on sacrificial hardware* whether the TPM NV counter/index supports the desired monotonic behavior, authorization policies, NV wear/quota, counter initialization and reset response; test through the L-001M behavioral probe. Do not use personal/production TPM resources.
- Independently authenticate TPM enrollment and anchor identity. The probe currently assumes a pinned 32-byte device binding but does not derive it from attestation or provisioning.
- Bind actual Root-approved, globally fresh dual witness receipts to independently replayed current SQLite history, with anti-eclipse/clock rollback policy. The L-001O model only verifies signatures and does not consume a verified journal snapshot.
- Specify and formally review durable Prepared intent recording, NV increment authorization, multi-process exclusion, hardware power-loss behavior and reconciliation when the TPM has advanced but application storage was lost.
- No automatic fallback to ordinary SQLite, JSON files or OS key storage on TPM absence; absent anchor must fail closed.
- Introduce actual `TPM2_NV_Increment` only in a **separate, reviewed hardware experiment** with explicit user/device consent, protective quotas, and actual recovery testing.

**L-ADR-20/21 remain PROPOSED.** PR is Draft and stacked, not merged. No Mesh listener, Relay, VPN, proxy, resource sharing, or ServiceOpen is enabled.
