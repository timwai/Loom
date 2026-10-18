# L-001U — authenticated, read-only IntentStore gate

**Status:** Rust security PoC, stacked on L-001T / Draft PR #27. **NO real trusted storage, physical TPM NV writer, admission permit, service startup or deployable Mesh.**

## Security objective

L-001T verifies authenticated intent record bytes, but the existing L-001O–S journal-bound code still consumes `CandidateIntentStore::load()` directly. A future production adapter could accidentally return attacker-supplied `Committed` or `Prepared` structs without a signature or durable replay-fence check. L-001U adds a **read-only CandidateIntentStore implementation** to make *every candidate load* go through the existing canonical signed-record validator.

## New boundary

`crates/loom-store/src/authenticated_intent_read_gate.rs` defines:

- `CandidateSignedIntentReader::read_frame()` — **untrusted** raw signed-record byte supplier (may return corrupted or restored data). This interface does **not** provide trusted public keys, counters or anti-rollback anchors.
- `CandidateTrustedIntentReader::read_trust()` — independently trusted observation of the signer/device/Root/genesis/Writer pin plus replay sequence, digest and counter floor. Its **platform implementation is NOT provided**, so tests use explicitly nontrusted fakes.
- `AuthenticatedReadOnlyIntent` — a wrapper with a pinned expected device identity and separately observed `CandidateMonotonicCounter`. Its `load()` checks pinned counter identity, reads the external trust, signed bytes and count, calls L-001T's strict verifier, then rereads all inputs. If any differ, returns `PersistenceUncertain` rather than adopting a second view.
- `prepare()` and `finalize()` return `PersistenceUncertain` **unconditionally**. Reading a trusted *Prepared* image at NV `N+1` does not grant authority to rewrite a durable record.
- Result is a `StoredBinding` only after verification; `inspect_read()` separately returns the diagnostic `VerifiedIntentRecord`.

This is an *adapter* for the existing experimental `CandidateIntentStore` interface, **not** a new production back-end. The existing `UnifiedPolicyJournal::inspect_journal_bound_counter(..., Reconcile)` checks signed journal replay, mirrors, signed old-history prefix and two-root-bound Witness receipts *before* giving a matching diagnostic. The same journal harness refuses a tampered record, tampered replay fence or unverifiable owner history. No new permission path was added.

**Important limitation:** two reads reject simple torn observations, but do not prove atomicity against ABA changes, malicious trust-provider substitutions, process races or power loss. The signed frame, counter and fence would require a separate authenticated atomic protocol and a globally serialized device writer to claim those properties.

## Adversarial acceptance matrix

| Scenario | Expected read-only outcome |
|---|---|
| Stable signed Committed, exact counter and independently pinned full trust | `load() -> Committed` and only diagnostic matching count |
| Any signed bytes modified | Reject before exposing binding |
| Old signed record below external high-water sequence, or wrong digest at equal sequence | Reject as replay/fork |
| Signer key rotated in record but external pin not rotated | Reject |
| New signer epoch/key independently pinned, matching valid signature/fence | Readable without granting write permission |
| Counter wrong or device binding changed | Reject |
| Trust/fence/raw bytes/counter change during observation | `PersistenceUncertain`; no adoption |
| Signed Prepared at counter N | `IntentBeforeIncrement` diagnostic; no auto-increment |
| Signed Prepared at N+1 | `IncrementNeedsSignedRecheck` diagnostic; **finalize refused** |
| Full signed journal current vs. saved signed older Committed mismatch | Reject, regardless of valid signature |
| Signed journal latest witness or Audit/Outbox corrupted | Reject |
| Candidate `Begin` or `Reconcile` attempts a state write using read-only adapter | Refuse mutation; no NV change |

Six new read-adapter tests plus two integration tests cover these paths, along with the inherited signed intent codec and eight-crash L-001S simulator.

## Production blockers and next work

1. Both provider traits are intentionally abstract: there is **no** hardware-protected pin, independent replay-fence storage, anti-rollback CAS, platform key enrollment, TPM NV writer or trusted durable authentication of actual media.
2. L-001Q still holds a SQLite `BEGIN IMMEDIATE` lock across *model* I/O; this is not suitable for a real platform counter. No real hardware transaction spans SQLite, the intent medium, and TPM atomic updates.
3. Full-history signed replay and dual Witness signatures do not prove global freshness, secure time or anti-eclipse independence.
4. All code remains diagnostic-only. **NO ServiceOpen, production Mesh service, file access, proxy, VPN or admission token.**
5. Do not merge a leaf stacked Draft PR directly into `main`.

**Proposed next gate L-001V:** specify and test a verified durable **write** protocol with external signer and independently protected replay fence, including atomic compare-and-advance, restart state revalidation and concurrent-writer exclusion. Start with in-memory adversarial model; production TPM enrollment/storage remains NO-GO.
