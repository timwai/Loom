//! L-001K: explicit, fail-closed legacy-to-unified migration gate.
//!
//! A revocation-only checkpoint commits to a DIFFERENT sequence and hash
//! domain from the unified policy ledger. The two MUST NOT be interchanged.
//! This module *audits* the old schema and refuses implicit migration. It
//! deliberately never modifies or copies a legacy row.

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

const LEGACY_TABLES: [&str; 4] = [
    "policy_versions",
    "revocations",
    "critical_outbox",
    "security_audit",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationGate {
    /// No legacy tables were found. This is NOT proof of external trust,
    /// and does not mean this database was not restored from an old backup.
    NoLegacySchema,
    /// An old schema is present; require a separate reviewed one-way
    /// migration with full signature replay and fresh unified witnesses.
    RequiresExplicitMigration {
        legacy_tables: usize,
        legacy_rows: u64,
    },
}

/// An observation only. Never returns a "migration approved" token.
pub fn inspect_legacy_migration_gate(connection: &Connection) -> Result<MigrationGate, StoreError> {
    let mut tables = 0usize;
    let mut rows = 0u64;
    for name in LEGACY_TABLES {
        let exists: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::PersistenceFailure)?;
        if exists.is_none() {
            continue;
        }
        tables += 1;
        // Name is a compile-time allowlisted identifier, NOT user input.
        let sql = format!("SELECT COUNT(*) FROM \"{name}\"");
        let count: i64 = connection
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|_| StoreError::PersistenceFailure)?;
        rows = rows
            .checked_add(u64::try_from(count).map_err(|_| StoreError::Conflict)?)
            .ok_or(StoreError::Conflict)?;
    }
    if tables == 0 {
        Ok(MigrationGate::NoLegacySchema)
    } else {
        Ok(MigrationGate::RequiresExplicitMigration {
            legacy_tables: tables,
            legacy_rows: rows,
        })
    }
}

/// Used BEFORE any new unified tables are created. Fails closed even on an
/// empty legacy schema (which may still have external revocation high-water).
pub(crate) fn require_no_legacy_schema(connection: &Connection) -> Result<(), StoreError> {
    match inspect_legacy_migration_gate(connection)? {
        MigrationGate::NoLegacySchema => Ok(()),
        MigrationGate::RequiresExplicitMigration { .. } => Err(StoreError::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_database_is_eligible_only_for_empty_schema_creation() {
        let connection = Connection::open_in_memory().unwrap();
        assert_eq!(
            inspect_legacy_migration_gate(&connection).unwrap(),
            MigrationGate::NoLegacySchema
        );
        require_no_legacy_schema(&connection).unwrap();
    }

    #[test]
    fn an_empty_legacy_schema_is_not_safe_to_autoconvert() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE policy_versions(space BLOB, resource BLOB, epoch INTEGER);
             CREATE TABLE revocations(space BLOB, resource BLOB, epoch INTEGER, signed_event BLOB);",
        ).unwrap();
        assert_eq!(
            inspect_legacy_migration_gate(&connection).unwrap(),
            MigrationGate::RequiresExplicitMigration {
                legacy_tables: 2,
                legacy_rows: 0,
            }
        );
        assert_eq!(
            require_no_legacy_schema(&connection),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn old_unsigned_or_signed_rows_are_never_copied_without_review() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE revocations(space BLOB, resource BLOB, epoch INTEGER, signed_event BLOB);
             INSERT INTO revocations VALUES(x'01010101010101010101010101010101',
                 x'02020202020202020202020202020202',1,x'ffff');",
        ).unwrap();
        assert_eq!(
            inspect_legacy_migration_gate(&connection).unwrap(),
            MigrationGate::RequiresExplicitMigration {
                legacy_tables: 1,
                legacy_rows: 1,
            }
        );
        assert_eq!(
            require_no_legacy_schema(&connection),
            Err(StoreError::Conflict)
        );
        let actual: Vec<u8> = connection
            .query_row("SELECT signed_event FROM revocations LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(actual, vec![0xff, 0xff]);
    }

    #[test]
    fn partial_old_table_set_requires_explicit_resolution() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE security_audit(id INTEGER)")
            .unwrap();
        assert_eq!(
            require_no_legacy_schema(&connection),
            Err(StoreError::Conflict)
        );
    }
}
