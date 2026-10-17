# L-001C SQLite revocation transaction PoC

Status: EXPERIMENTAL. Linked to L-ADR-20, L-ADR-21 and issue #4.

- All SQLite calls execute on a dedicated OS thread, never on a Tokio core.
- Admission mutex serializes test-only new SessionOpen and the SQL transaction.
- BEGIN IMMEDIATE + synchronous FULL + WAL commits epoch, event, outbox and audit in one transaction.
- Post-commit memory publish and old-permit invalidation occur before releasing admission mutex.
- Post-COMMIT error causes paused state; restart rehydrates epochs and outbox.
- Startup is always PAUSED in production. Recovery/admission test fixtures are behind cfg(test); no verified Owner signature, independent witness or ServiceOpen is implemented.
- Pending outbox is read-only; no unsafe ACK API or transmission.
- Not tested yet: real rollback-proof witness, signed payload verification, SQLite busy/disk-full/kill -9, fsync/power-loss guarantee, stream close QoS.

PoC scope: AUTHZ-RACE-01 (partial), AUTHZ-CRASH-02 (partial), OUTBOX-01 (partial), ROLLBACK-01 (simulated-only). ADRs remain proposed.
