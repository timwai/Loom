# L-002C — TPM-free challenge-bound Witness high-water verification

> 2026-10-20 follow-up: [L-002D authenticated append](l-002d-authenticated-witness-append.md) and [L-002E isolated LAN read acceptance](l-002e-lan-file-read-acceptance.md) now implement and test the next candidate steps. The original model boundaries below are historical; independent Witness provisioning, production admission and release approval remain blocked.

> 2026-10-18 — **SECURITY MODEL ONLY / DIAGNOSTIC / NO ServiceOpen**. Stacked on L-002B Draft PR #40. No networking, signed Owner admission, trusted remote persistence, real key provisioning or hardware state mutation.

## Problem and security boundary

L-002B made TPM optional and separated ordinary portable software preferences from high-assurance antirollback state. Merely introducing a `ProviderKind::ExternalQuorum` did NOT implement a secure remote Witness protocol: stale signed messages could be replayed after local backup restoration, Witness state could diverge, and a self-declared quorum could be mistaken for proof of durable antirollback.

L-002C supplies a concrete **two-of-two, Ed25519-signed, client-challenge-bound observation verifier** in `crates/loom-store/src/challenge_witness_quorum.rs`. It is protocol validation, not a deployable quorum service.

### Signed observation contract

- A `QuorumChallenge` contains an independently unpredictable, one-use 32-byte nonce, exact Space, Resource and writer epoch. **Nonce generation and outstanding challenge tracking are NOT provided in this spike**; the caller must obtain them from audited random/freshness handling and never reuse across restart.
- `QuorumHighWater` identifies Space/Resource/writer epoch, journal sequence, signed policy head and revocation root. A local SQLite value is never itself evidence of authenticity.
- Each `SignedQuorumObservation` signs the canonical, domain-separated `LOOM:WITNESS-LATEST:V1\0` transcript: nonce + request scope + independently observed Witness generation + full signed state identity. Integer encoding is fixed-width unsigned big-endian.
- `PinnedQuorum` carries **two separately Root-enrolled, distinct Ed25519 public keys**. Keys must be independently established out-of-band; merely having two keys in a configuration does not prove independent custody, remote operators or quorum anti-eclipse.
- `verify_challenge_bound_quorum()` checks exactly two receipts, correct unique key IDs, signatures, challenge, scope and writer epoch, exact **two-party equality**, externally trusted minimum Witness generation, and **exact equality to independently replayed signed local history**. Both remote-ahead and remote-behind/fork mismatch are refusal, not silent mutation.
- Only `VerifiedQuorumDiagnostic` is returned. No Root/Owner token, nonrollbackable proof minting, ResourceAuthorizer `Allow`, ServiceOpen or trusted-state `VerifiedProviderEvidence` is produced.

The client **must not assume** that valid signatures imply live independent servers. For offline or single-Witness availability, fail closed for a rollback-sensitive operation; ordinary nonsecurity-critical local preferences continue working without any TPM or remote network.

### Twelve adversarial tests

1. Two independently held test Ed25519 keys sign matching, nonce-bound read; yields diagnostics only.
2. Old valid replies supplied for a new challenge are rejected.
3. All-zero challenge is refused (but this alone cannot prove nonzero nonce unpredictability).
4. One Witness missing/offline refuses.
5. Duplicate receipt, duplicate pinned key, and substituted pin refuse.
6. Signature mutation and Witness ID replacement refuse.
7. Independently valid split-brain replies after only one test Witness advances refuse.
8. Both simulated Witnesses advance while local SQLite remains old: client detects restored local backup. Exact refreshed local history can be diagnostically verified.
9. An independently retained minimum generation rejects old valid signed responses.
10. Space/Resource/writer epoch mismatch refuses.
11. Stale writer generation, duplicate or forked sequence advancement refuses in the **test-only** simulated Witness CAS.
12. Tampered policy-head signature and valid-but-different local fork refuse.

### Missing release-critical properties

- No production, persisted and **truly independent** Witness servers, no authenticated transport, no durable fsync, no two-phase atomic commit between Witness nodes and local signed journal, no real device enrollment, operator independence or rotation procedure.
- No tested secure nonce issuer (CSPRNG), cross-reboot nonce replay cache, expiry/clock, global anti-eclipse, Byzantine/fork/collusion protection or anti-DoS. A previously recorded valid response can be accepted again if a caller reuses its challenge; the verifier is stateless.
- The fake Witness signer and counter are confined to `#[cfg(test)]`, isolated Mutex state per node. Test-only `advance_for_test` has no signed Owner authorization and is **not** an API for remote writes.
- Signature agreement is only a statement of what two pinned keys signed **for one nonce**. It cannot by itself ensure network-wide latest state or replace authenticated Root-selected dual Witness policy and full signed journal verification.
- There is deliberately **no connection** from these diagnostics to `trusted_state_provider::VerifiedProviderEvidence` because that would falsely claim production rollover/freshness assurance.

**Next L-002D:** design and test independent Witness append protocol with mandatory authenticated Owner writer requests, adversarial partial quorum CAS, durable crash records and fork evidence. Secure network transport and signed Root/Owner enrollment come before a deployable quorum; keep L-001 release `BLOCKED`.

References: `docs/spikes/l-002b-hardware-agnostic-trusted-state.md`, `docs/implementation-gates.md`, `docs/acceptance/l001.json`.
