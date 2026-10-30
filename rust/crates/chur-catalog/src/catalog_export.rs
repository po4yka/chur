//! The portable catalog export of a version 2 backup, ADR-0068.
//!
//! `chur_format::catalog_export` owns the bytes. This module maps them to and
//! from the SQLCipher catalog: [`export`] walks every ordinary table of a
//! catalog, and [`import`] fills a freshly created catalog with the rows.
//!
//! The table list is not written down twice. Export takes it from the catalog
//! it reads, and import takes it from the fresh catalog it has just created,
//! then requires the stream to name exactly those tables with exactly those
//! columns in the same order. A stream from another schema therefore fails
//! before a row is written, and a schema step that adds a table changes both
//! sides at once.
//!
//! The two FTS5 indexes are not exported. Their shadow tables hold SQLite's own
//! index pages, which are a storage detail in the same way that SQLCipher pages
//! are, and every term they hold is derived from rows the export carries.
//! Import rebuilds both indexes from those rows, with the same rule the live
//! catalog follows: an object is searchable while it is active, and every note
//! is searchable.

use chur_core::{Result, bail, ensure, err, limits::backup as bounds};
use chur_format::catalog_export::{
    ChunkSource, ExportHeader, ExportReader, ExportWriter, TableHeader, Value,
};
use chur_format::constants::{
    CATALOG_FORMAT_VERSION_V15, CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17,
    CATALOG_FORMAT_VERSION_V18, ObjectState,
};
use rusqlite::Connection;
use rusqlite::types::{ToSqlOutput, ValueRef};

use crate::db::{CatalogDb, map_sqlite};
use crate::schema;

/// How many rows pass between two cancellation probes.
const CANCEL_STRIDE: u64 = 256;

/// One exported table: its name, its columns, and the order of its rows.
struct Table {
    name: String,
    columns: Vec<String>,
    order: Vec<String>,
    strict: bool,
}

/// Quotes one identifier that [`chur_format::catalog_export::name_valid`]
/// already admits, so the quotes are a formality rather than a defence.
fn quoted(name: &str) -> String {
    format!("\"{name}\"")
}

/// The ordinary tables of the catalog in ascending byte order of their names.
///
/// `pragma_table_list` reports an FTS5 table as `virtual` and its shadow tables
/// as `shadow`, so the filter on `table` keeps both out. SQLite's own tables
/// begin with `sqlite_` and are not catalog state.
fn tables(connection: &Connection) -> Result<Vec<Table>> {
    let mut statement = connection
        .prepare(
            "SELECT name, strict FROM pragma_table_list
              WHERE schema = 'main' AND type = 'table' AND substr(name, 1, 7) <> 'sqlite_'",
        )
        .map_err(|error| map_sqlite(error, "the catalog table list could not be read"))?;
    let mut names = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? == 1))
        })
        .map_err(|error| map_sqlite(error, "the catalog table list could not be read"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite(error, "the catalog table list could not be read"))?;
    names.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut out = Vec::with_capacity(names.len());
    for (name, strict) in names {
        ensure!(
            chur_format::catalog_export::name_valid(&name),
            CatalogCorrupt,
            "a catalog table has a name the export refuses"
        );
        let mut statement = connection
            .prepare("SELECT name, pk FROM pragma_table_info(?1) ORDER BY cid")
            .map_err(|error| map_sqlite(error, "the catalog columns could not be read"))?;
        let columns = statement
            .query_map([&name], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| map_sqlite(error, "the catalog columns could not be read"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| map_sqlite(error, "the catalog columns could not be read"))?;
        let mut key: Vec<(i64, String)> = columns
            .iter()
            .filter(|(_, position)| *position > 0)
            .map(|(column, position)| (*position, column.clone()))
            .collect();
        key.sort_unstable();
        let names: Vec<String> = columns.into_iter().map(|(column, _)| column).collect();
        // A table without a declared primary key is ordered by every column in
        // declared order. `private_notes` is the one such table, and its first
        // column is the unique note identifier.
        let order = if key.is_empty() {
            names.clone()
        } else {
            key.into_iter().map(|(_, column)| column).collect()
        };
        out.push(Table {
            name,
            columns: names,
            order,
            strict,
        });
    }
    Ok(out)
}

/// Writes the catalog as one `CatalogExportV1` stream.
///
/// `sink` receives each chunk and whether it is the last. The caller owns the
/// consistency of the read: it passes a catalog that nothing else writes, which
/// for a backup is the private snapshot copy.
///
/// # Errors
///
/// Returns [`ChurStatus::Cancelled`](chur_core::ChurStatus::Cancelled) when
/// `cancelled` asks it to stop, [`ChurStatus::CatalogCorrupt`](chur_core::ChurStatus::CatalogCorrupt) for a value the
/// export cannot represent, and the errors of the sink.
pub fn export(
    db: &CatalogDb,
    sink: impl FnMut(&[u8], bool) -> Result<()>,
    cancelled: &dyn Fn() -> bool,
) -> Result<ExportHeader> {
    let connection = db.connection();
    let catalog_format_version = schema::recorded_version(connection)?
        .ok_or_else(|| err!(CatalogCorrupt, "the catalog schema is absent"))?;
    let tables = tables(connection)?;
    let header = ExportHeader {
        catalog_format_version,
        catalog_generation: schema::generation(db)?,
        table_count: u32::try_from(tables.len())
            .map_err(|_| err!(CatalogCorrupt, "the catalog holds too many tables"))?,
    };
    let mut writer = ExportWriter::new(sink, &header)?;
    for table in &tables {
        let row_count: i64 = connection
            .query_row(
                &format!("SELECT count(*) FROM {}", quoted(&table.name)),
                [],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "a catalog table could not be counted"))?;
        let row_count = u64::try_from(row_count)
            .map_err(|_| err!(CatalogCorrupt, "a catalog table count is negative"))?;
        writer.table(&TableHeader {
            name: table.name.clone(),
            columns: table.columns.clone(),
            row_count,
        })?;
        let columns: Vec<String> = table.columns.iter().map(|c| quoted(c)).collect();
        let order: Vec<String> = table.order.iter().map(|c| quoted(c)).collect();
        let sql = format!(
            "SELECT {} FROM {} ORDER BY {}",
            columns.join(", "),
            quoted(&table.name),
            order.join(", ")
        );
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| map_sqlite(error, "a catalog table could not be read"))?;
        let mut rows = statement
            .query([])
            .map_err(|error| map_sqlite(error, "a catalog table could not be read"))?;
        let mut written = 0u64;
        while let Some(row) = rows
            .next()
            .map_err(|error| map_sqlite(error, "a catalog row could not be read"))?
        {
            if written.is_multiple_of(CANCEL_STRIDE) && cancelled() {
                bail!(Cancelled, "the catalog export was cancelled");
            }
            for index in 0..table.columns.len() {
                match row
                    .get_ref(index)
                    .map_err(|error| map_sqlite(error, "a catalog value could not be read"))?
                {
                    ValueRef::Null => writer.null()?,
                    ValueRef::Integer(value) => writer.integer(value)?,
                    ValueRef::Text(bytes) => writer.text(bytes).map_err(|_| {
                        err!(CatalogCorrupt, "a catalog text value cannot be exported")
                    })?,
                    ValueRef::Blob(bytes) => writer.blob(bytes).map_err(|_| {
                        err!(CatalogCorrupt, "a catalog blob value cannot be exported")
                    })?,
                    ValueRef::Real(_) => bail!(
                        CatalogCorrupt,
                        "a catalog value is a floating-point number the export cannot represent"
                    ),
                }
            }
            written += 1;
        }
        ensure!(
            written == row_count,
            InternalFailure,
            "a catalog table changed while it was exported"
        );
    }
    writer.finish()?;
    Ok(header)
}

/// Fills an empty catalog from one `CatalogExportV1` stream.
///
/// The schema is created first, at the version the stream declares, and the
/// rows are then inserted into it in one transaction. Foreign keys are checked
/// once, after the last row, because the tables arrive in name order rather
/// than in reference order.
///
/// Every catalog table is `STRICT`, and import requires it: SQLite then
/// refuses a value whose type differs from its column's declared type, so a
/// TEXT in a BLOB column or a blob in an INTEGER column fails as a constraint
/// rather than entering the catalog. A row is also bounded to
/// [`bounds::CATALOG_EXPORT_ROW_MAX`] text and blob bytes.
///
/// Schema versions map one to one: the stream's `catalog_format_version` names
/// the schema its rows belong to, and it must equal `expected_version`, the
/// version the authenticated manifest and descriptor name. The fresh catalog is
/// built at exactly that version. Version 15 is the first that writes an export, so a stream of
/// an earlier version cannot exist; a later version than this build knows is
/// refused as unsupported. A future build that reads an older export builds
/// the schema of that version and runs the `CATALOG_SCHEMA_V1.md` §18
/// migration steps after the import, as it would for a live catalog.
///
/// # Errors
///
/// Returns [`ChurStatus::UnsupportedVersion`](chur_core::ChurStatus::UnsupportedVersion)
/// for a schema version this build does not know, and
/// [`ChurStatus::VaultCorrupt`](chur_core::ChurStatus::VaultCorrupt) for a
/// stream whose tables, columns, rows, or references do not fit the schema, or
/// whose state row contradicts its header.
pub fn import(
    db: &mut CatalogDb,
    source: impl ChunkSource,
    expected_version: u16,
    cancelled: &dyn Fn() -> bool,
) -> Result<ExportHeader> {
    ensure!(
        schema::recorded_version(db.connection())?.is_none(),
        Conflict,
        "a catalog export is imported into an empty catalog only"
    );
    let (mut reader, header) = ExportReader::new(source)?;
    ensure!(
        header.catalog_format_version == expected_version,
        VaultCorrupt,
        "the catalog export names another schema version than its package"
    );
    match header.catalog_format_version {
        CATALOG_FORMAT_VERSION_V15
        | CATALOG_FORMAT_VERSION_V16
        | CATALOG_FORMAT_VERSION_V17
        | CATALOG_FORMAT_VERSION_V18 => {}
        version if version > CATALOG_FORMAT_VERSION_V18 => bail!(
            UnsupportedVersion,
            "the catalog export belongs to a newer catalog schema"
        ),
        _ => bail!(
            VaultCorrupt,
            "no catalog export is written below catalog schema fifteen"
        ),
    }
    schema::install_export_version(db, header.catalog_format_version, 0)?;
    let tables = tables(db.connection())?;
    ensure!(
        tables.iter().all(|table| table.strict),
        InternalFailure,
        "a catalog table is not STRICT, so an import cannot rely on its type checks"
    );
    ensure!(
        header.table_count as usize == tables.len(),
        VaultCorrupt,
        "the catalog export names a different set of tables"
    );

    db.transaction(|transaction| {
        transaction
            .execute_batch("PRAGMA defer_foreign_keys = ON; DELETE FROM vault_state;")
            .map_err(|error| map_sqlite(error, "the fresh catalog could not be emptied"))?;
        for table in &tables {
            let head = reader.table()?;
            ensure!(
                head.name == table.name && head.columns == table.columns,
                VaultCorrupt,
                "the catalog export does not match the catalog schema it names"
            );
            let columns: Vec<String> = table.columns.iter().map(|c| quoted(c)).collect();
            let slots: Vec<String> = (1..=columns.len()).map(|i| format!("?{i}")).collect();
            let mut statement = transaction
                .prepare(&format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    quoted(&table.name),
                    columns.join(", "),
                    slots.join(", ")
                ))
                .map_err(|error| map_sqlite(error, "an import statement could not be prepared"))?;
            for row in 0..head.row_count {
                if row.is_multiple_of(CANCEL_STRIDE) && cancelled() {
                    bail!(Cancelled, "the catalog import was cancelled");
                }
                let mut values = Vec::with_capacity(columns.len());
                let mut row_bytes = 0u64;
                for _ in 0..columns.len() {
                    let value = reader.value()?;
                    row_bytes += match &value {
                        Value::Text(text) => text.len() as u64,
                        Value::Blob(bytes) => bytes.len() as u64,
                        Value::Null | Value::Integer(_) => 0,
                    };
                    ensure!(
                        row_bytes <= bounds::CATALOG_EXPORT_ROW_MAX,
                        VaultCorrupt,
                        "an exported row exceeds the catalog export row bound"
                    );
                    values.push(value);
                }
                let bound = values.iter().map(|value| {
                    ToSqlOutput::Borrowed(match value {
                        Value::Null => ValueRef::Null,
                        Value::Integer(integer) => ValueRef::Integer(*integer),
                        Value::Text(text) => ValueRef::Text(text.as_bytes()),
                        Value::Blob(bytes) => ValueRef::Blob(bytes),
                    })
                });
                statement
                    .execute(rusqlite::params_from_iter(bound))
                    .map_err(|error| refused(error, "an exported row does not fit the catalog"))?;
            }
        }
        rebuild_search(transaction)?;
        let violations: i64 = transaction
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .map_err(|error| map_sqlite(error, "the imported references could not be checked"))?;
        ensure!(
            violations == 0,
            VaultCorrupt,
            "the catalog export holds a reference to a row it does not carry"
        );
        let (version, generation): (i64, i64) = transaction
            .query_row(
                "SELECT catalog_format_version, catalog_generation FROM vault_state
                  WHERE only_row = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| refused(error, "the catalog export has no state row"))?;
        ensure!(
            i64::from(header.catalog_format_version) == version
                && u64::try_from(generation).ok() == Some(header.catalog_generation),
            VaultCorrupt,
            "the catalog export's state row contradicts its header"
        );
        Ok(())
    })?;
    reader.finish()?;
    db.checkpoint()?;
    Ok(header)
}

/// Rebuilds both FTS5 indexes from the imported rows.
///
/// The statements are the live catalog's own: `store::reindex_search` for an
/// active object and `notes::reindex` for a note, applied to every row at once.
fn rebuild_search(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO object_search (rowid, filename, caption, tag_names, content_body)
             SELECT o.search_key,
                    COALESCE(m.original_filename, ''),
                    COALESCE(m.caption, ''),
                    COALESCE((SELECT group_concat(t.name, ' ')
                                FROM object_tags ot JOIN tags t ON t.tag_id = ot.tag_id
                               WHERE ot.object_id = o.object_id), ''),
                    COALESCE((SELECT c.body FROM content_index c
                               WHERE c.object_id = o.object_id
                                 AND c.primary_stream_id = o.primary_stream_id), '')
               FROM objects o
               JOIN metadata_revisions m ON m.object_id = o.object_id AND m.active = 1
              WHERE o.state = ?1",
            [i64::from(ObjectState::Active.value())],
        )
        .map_err(|error| map_sqlite(error, "the object search could not be rebuilt"))?;
    transaction
        .execute(
            "INSERT INTO private_note_search (rowid, title, body)
             SELECT rowid, title, body FROM private_notes",
            [],
        )
        .map_err(|error| map_sqlite(error, "the note search could not be rebuilt"))?;
    Ok(())
}

/// A constraint the imported rows break is a forged or damaged export, not a
/// conflict with local state: the catalog was empty before the import began.
fn refused(error: rusqlite::Error, context: &'static str) -> chur_core::Error {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            chur_core::Error::new(chur_core::ChurStatus::VaultCorrupt, context)
        }
        rusqlite::Error::QueryReturnedNoRows => {
            chur_core::Error::new(chur_core::ChurStatus::VaultCorrupt, context)
        }
        _ => map_sqlite(error, context),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::db::{CatalogKey, CatalogLocation};
    use chur_core::{ChurStatus, Id};
    use chur_crypto::Key;
    use zeroize::Zeroizing;

    struct Chunks(std::vec::IntoIter<Vec<u8>>);

    impl ChunkSource for Chunks {
        fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.next().map(Zeroizing::new))
        }
    }

    fn empty_catalog() -> CatalogDb {
        let key =
            CatalogKey::derive(&Key::new([0x42; 32]), &Id::new([0x24; 16]).unwrap()).expect("key");
        CatalogDb::open(&CatalogLocation::Memory, &key).expect("open")
    }

    fn stream_of(db: &CatalogDb) -> Vec<u8> {
        let mut out = Vec::new();
        export(
            db,
            |chunk, _| {
                out.extend_from_slice(chunk);
                Ok(())
            },
            &|| false,
        )
        .expect("export");
        out
    }

    fn source() -> CatalogDb {
        let mut db = empty_catalog();
        schema::open_at_current_version(&mut db, 7).expect("install");
        crate::notes::save(
            &mut db,
            None,
            0,
            "kept",
            "a searchable note",
            false,
            crate::notes::NoteFormat::PlainText,
            7,
        )
        .expect("note");
        db
    }

    #[test]
    fn an_import_reproduces_every_row_and_the_note_search() {
        let original = source();
        let bytes = stream_of(&original);
        let mut copy = empty_catalog();
        let header = import(
            &mut copy,
            Chunks(vec![bytes.clone()].into_iter()),
            CATALOG_FORMAT_VERSION_V18,
            &|| false,
        )
        .expect("import");
        assert_eq!(header.catalog_format_version, CATALOG_FORMAT_VERSION_V18);
        assert_eq!(stream_of(&copy), bytes);
        let found: i64 = copy
            .connection()
            .query_row(
                "SELECT count(*) FROM private_note_search WHERE private_note_search MATCH 'searchable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1);
    }

    #[test]
    fn an_import_refuses_a_populated_catalog_and_a_foreign_schema() {
        let bytes = stream_of(&source());
        let mut populated = source();
        assert_eq!(
            import(
                &mut populated,
                Chunks(vec![bytes.clone()].into_iter()),
                CATALOG_FORMAT_VERSION_V18,
                &|| false
            )
            .unwrap_err()
            .status(),
            ChurStatus::Conflict
        );

        // A newer schema version is unsupported; an older one cannot exist.
        for (version, status) in [
            (
                CATALOG_FORMAT_VERSION_V18 + 1,
                ChurStatus::UnsupportedVersion,
            ),
            (CATALOG_FORMAT_VERSION_V15 - 1, ChurStatus::VaultCorrupt),
        ] {
            let mut changed = bytes.clone();
            changed[2..4].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                import(
                    &mut empty_catalog(),
                    Chunks(vec![changed].into_iter()),
                    version,
                    &|| false
                )
                .unwrap_err()
                .status(),
                status
            );
        }

        // The first table renamed to another valid identifier.
        let mut renamed = bytes.clone();
        renamed[20] = b'z';
        assert_eq!(
            import(
                &mut empty_catalog(),
                Chunks(vec![renamed].into_iter()),
                CATALOG_FORMAT_VERSION_V18,
                &|| false
            )
            .unwrap_err()
            .status(),
            ChurStatus::VaultCorrupt
        );

        // A generation that contradicts the state row.
        let mut generation = bytes;
        generation[11] ^= 0x01;
        assert_eq!(
            import(
                &mut empty_catalog(),
                Chunks(vec![generation].into_iter()),
                CATALOG_FORMAT_VERSION_V18,
                &|| false
            )
            .unwrap_err()
            .status(),
            ChurStatus::VaultCorrupt
        );
    }

    #[test]
    fn known_export_versions_restore_their_exact_schema_before_migration() {
        for version in [
            CATALOG_FORMAT_VERSION_V15,
            CATALOG_FORMAT_VERSION_V16,
            CATALOG_FORMAT_VERSION_V17,
            CATALOG_FORMAT_VERSION_V18,
        ] {
            let mut original = empty_catalog();
            schema::install_export_version(&mut original, version, 7)
                .expect("install declared schema");
            crate::notes::save(
                &mut original,
                None,
                0,
                "kept",
                "a searchable note",
                false,
                crate::notes::NoteFormat::PlainText,
                7,
            )
            .expect("note");
            let bytes = stream_of(&original);
            let mut copy = empty_catalog();
            let header = import(
                &mut copy,
                Chunks(vec![bytes.clone()].into_iter()),
                version,
                &|| false,
            )
            .expect("import declared schema");
            assert_eq!(header.catalog_format_version, version);
            assert_eq!(
                schema::recorded_version(copy.connection()).unwrap(),
                Some(version)
            );
            assert_eq!(stream_of(&copy), bytes);
            let playback_tables: i64 = copy.connection().query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'playback_positions'",
                [], |row| row.get(0)).unwrap();
            assert_eq!(
                playback_tables,
                i64::from(version >= CATALOG_FORMAT_VERSION_V17)
            );
            if version == CATALOG_FORMAT_VERSION_V15 {
                schema::migrate_v15_to_v16(&mut copy).expect("v15 to v16");
            }
            if version < CATALOG_FORMAT_VERSION_V17 {
                schema::migrate_v16_to_v17(&mut copy).expect("v16 to v17");
            }
            if version < CATALOG_FORMAT_VERSION_V18 {
                schema::migrate_v17_to_v18(&mut copy).expect("v17 to v18");
            }
            assert_eq!(
                schema::recorded_version(copy.connection()).unwrap(),
                Some(CATALOG_FORMAT_VERSION_V18)
            );
            let found: i64 = copy.connection().query_row(
                "SELECT count(*) FROM private_note_search WHERE private_note_search MATCH 'searchable'",
                [], |row| row.get(0)).unwrap();
            assert_eq!(found, 1);
            let positions: i64 = copy
                .connection()
                .query_row("SELECT count(*) FROM playback_positions", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(positions, 0);
        }
    }

    #[test]
    fn a_current_export_cannot_claim_an_older_table_set() {
        let bytes = stream_of(&source());
        for version in [
            CATALOG_FORMAT_VERSION_V15,
            CATALOG_FORMAT_VERSION_V16,
            CATALOG_FORMAT_VERSION_V17,
        ] {
            let mut changed = bytes.clone();
            changed[2..4].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                import(
                    &mut empty_catalog(),
                    Chunks(vec![changed].into_iter()),
                    version,
                    &|| false
                )
                .unwrap_err()
                .status(),
                ChurStatus::VaultCorrupt
            );
        }
    }

    /// Import relies on SQLite's type checks, which only a `STRICT` table
    /// applies, so every table the export carries must be one.
    #[test]
    fn every_exported_table_is_strict() {
        let db = source();
        let tables = tables(db.connection()).unwrap();
        assert!(tables.len() > 40);
        let loose: Vec<&str> = tables
            .iter()
            .filter(|table| !table.strict)
            .map(|table| table.name.as_str())
            .collect();
        assert!(loose.is_empty(), "{loose:?}");
    }
}
