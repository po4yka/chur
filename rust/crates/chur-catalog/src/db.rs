//! The encrypted catalog connection.
//!
//! `docs/format/CATALOG_SCHEMA_V1.md` §15 puts the physical database behind
//! SQLCipher opened directly by Rust, and ADR-0004 makes the connection, the
//! key, and the lifecycle Rust-owned. This module is that boundary: nothing
//! outside it holds a `rusqlite::Connection`, and nothing outside `chur-crypto`
//! produces the key it opens with.
//!
//! The key never reaches SQLCipher's own password KDF. `CatalogKey` is already
//! a full-entropy HKDF output under the `chur/v1/root/catalog-database` label,
//! so the connection uses the raw-key pragma; running PBKDF2 over it would add
//! cost without adding entropy and would put a second KDF profile into the
//! at-rest format.

use core::fmt;

use chur_core::{ChurStatus, Error, Id, Result, ensure, err};
use chur_crypto::{
    Key,
    kdf::{Context, Label, derive},
};
use rusqlite::Connection;
use zeroize::Zeroizing;

/// The one pragma that must precede the key.
///
/// SQLCipher applies `cipher_memory_security` to allocations it makes after the
/// setting is read, so setting it after the key would leave the key derivation
/// itself outside the protection.
const PRE_KEY_PRAGMAS: &str = "PRAGMA cipher_memory_security = ON;\n";

/// The cipher parameters of every catalog, set after the key and before the
/// first page is read.
///
/// They are the SQLCipher 4 defaults that every existing catalog was written
/// with. They are pinned so that a later SQLCipher with other defaults cannot
/// make an existing catalog unreadable, or write a new one in another format.
/// With the raw-key pragma, `kdf_iter` does not derive the page key; it is
/// pinned with the rest so the full profile is stated in one place.
const CIPHER_PRAGMAS: &str = "\
PRAGMA cipher_page_size = 4096;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
PRAGMA kdf_iter = 256000;
PRAGMA cipher_plaintext_header_size = 0;
";

/// The pragmas the connection sets once the key has opened a page.
///
/// `synchronous = FULL` is required rather than preferred:
/// `docs/format/CATALOG_SCHEMA_V1.md` §11 says a journal reservation is durable
/// only under a mode that survives power loss, and `NORMAL` in WAL mode flushes
/// to the operating system without waiting for the platter or the flash.
///
/// They run after the readability check of [`CatalogDb::check_readable`],
/// because `journal_mode` reads the database header: a wrong key would fail
/// here first and be reported as a pragma failure rather than as the credential
/// failure it is.
const SESSION_PRAGMAS: &str = "\
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 5000;
";

/// The SQLCipher key derived for one vault's catalog database.
///
/// It carries no `Debug`, is zeroized on drop through [`Key`], and exists only
/// between unlock and lock.
pub struct CatalogKey(Key);

impl CatalogKey {
    /// Derives the catalog database key from the vault root secret.
    ///
    /// `docs/security/KEY_HIERARCHY.md` §3 registers the label and fixes the
    /// context as `vault_id` alone.
    pub fn derive(root: &Key, vault_id: &Id) -> Result<Self> {
        let context = Context::vault(vault_id);
        Ok(Self(derive(
            root.expose(),
            Label::RootCatalogDatabase,
            &context,
        )?))
    }

    /// The raw-key pragma argument SQLCipher expects: `x'<64 hex digits>'`.
    ///
    /// The value is returned inside [`Zeroizing`] because it is the key in a
    /// second encoding, and a `String` cannot be overwritten in place after the
    /// allocator has reused it.
    fn raw_key_pragma(&self) -> Zeroizing<String> {
        let mut text = String::with_capacity(2 + 64 + 1);
        text.push_str("x'");
        for byte in self.0.expose() {
            // A two-digit lowercase hex pair, written without a formatter so no
            // intermediate allocation carries a copy of the key.
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            text.push(DIGITS[usize::from(byte >> 4)] as char);
            text.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        text.push('\'');
        Zeroizing::new(text)
    }
}

impl fmt::Debug for CatalogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CatalogKey(<redacted>)")
    }
}

/// Where a catalog database lives.
///
/// A path is a caller concern: `docs/ARCHITECTURE.md` §14.4 puts the file under
/// an opaque per-vault directory, and the platform storage adapter resolves it
/// from the object-store descriptor's path ID. This enum exists so a test and a
/// device share one open path.
pub enum CatalogLocation<'a> {
    /// A file on disk.
    File(&'a std::path::Path),
    /// A database that exists only for the life of the connection.
    ///
    /// It is used by tests and by the constant-work substitute open of
    /// `docs/security/KEY_SLOTS.md` §8; it never holds a real vault.
    Memory,
}

/// An open, decrypted catalog database.
///
/// Dropping it closes the connection, which is step 5 of the lock sequence in
/// `docs/security/PLAINTEXT_LIFECYCLE.md` §8 and must happen before the session
/// zeroizes the root.
pub struct CatalogDb {
    connection: Connection,
    pub(crate) sharing_log_cache: Option<crate::sharing_log::CachedCollectionLog>,
    pub(crate) own_source_cache: Option<crate::own_sync::SourceCache>,
    /// The process monotonic instant that the stored trusted-time mark reached; see `trusted_time`.
    pub(crate) trusted_anchor: Option<std::time::Instant>,
    #[cfg(test)]
    pub(crate) own_source_replays: usize,
}

impl fmt::Debug for CatalogDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CatalogDb")
    }
}

impl CatalogDb {
    /// Opens a catalog database, creating the file when it is absent.
    ///
    /// The key is applied before any other statement, because SQLCipher decides
    /// on the first read whether the file decrypts. A wrong key therefore fails
    /// here rather than later, and it fails as `AuthenticationFailed`: the file
    /// is not corrupt, the credential did not open it.
    pub fn open(location: &CatalogLocation<'_>, key: &CatalogKey) -> Result<Self> {
        let connection = match location {
            CatalogLocation::File(path) => Connection::open(path)
                .map_err(|error| map_sqlite(error, "the catalog database could not be opened"))?,
            CatalogLocation::Memory => Connection::open_in_memory()
                .map_err(|error| map_sqlite(error, "an in-memory catalog could not be created"))?,
        };
        let db = Self {
            connection,
            sharing_log_cache: None,
            own_source_cache: None,
            trusted_anchor: None,
            #[cfg(test)]
            own_source_replays: 0,
        };
        db.apply_batch(PRE_KEY_PRAGMAS, "a catalog memory pragma was refused")?;
        db.apply_key(key)?;
        db.apply_batch(CIPHER_PRAGMAS, "a catalog cipher pragma was refused")?;
        db.check_readable()?;
        db.apply_batch(SESSION_PRAGMAS, "a catalog session pragma was refused")?;
        Ok(db)
    }

    fn apply_key(&self, key: &CatalogKey) -> Result<()> {
        let pragma = key.raw_key_pragma();
        self.connection
            .pragma_update(None, "key", pragma.as_str())
            .map_err(|_| err!(InternalFailure, "the catalog key pragma was refused"))
    }

    /// Runs one pragma batch, keeping SQLite's classification of the failure.
    ///
    /// The classification matters more than it looks: a full or detached volume
    /// fails a pragma the same way a refused setting does, and collapsing both
    /// into `INTERNAL_FAILURE` turns "the disk is full" into an unexplained
    /// defect. `docs/ERROR_MODEL.md` still keeps the message out; only the code
    /// survives.
    fn apply_batch(&self, batch: &str, context: &'static str) -> Result<()> {
        self.connection
            .execute_batch(batch)
            .map_err(|error| map_sqlite(error, context))
    }

    /// Reads one page, which is where a wrong key is detected.
    ///
    /// SQLCipher does not verify the key when the pragma is set; it fails on
    /// the first page it must decrypt. Reading the schema is the cheapest such
    /// read, and it succeeds on an empty new database as well as on a
    /// populated one.
    fn check_readable(&self) -> Result<()> {
        self.connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|_| ())
            .map_err(|_| err!(AuthenticationFailed, "the catalog did not decrypt"))
    }

    /// Authenticates every physical SQLCipher page, including unused pages.
    /// This SQLCipher pragma performs a bounded-file scan inside prepare; callers
    /// check cancellation before and after it and never hold a live target session.
    pub fn verify_cipher_pages(&self) -> Result<()> {
        let mut statement = self
            .connection
            .prepare("PRAGMA cipher_integrity_check")
            .map_err(|_| err!(CatalogCorrupt, "the encrypted catalog page check failed"))?;
        ensure!(
            statement.column_count() == 1,
            UnsupportedVersion,
            "the encrypted catalog page check is unavailable"
        );
        let mut rows = statement
            .query([])
            .map_err(|_| err!(CatalogCorrupt, "the encrypted catalog page check failed"))?;
        ensure!(
            rows.next()
                .map_err(|_| err!(CatalogCorrupt, "the encrypted catalog page check failed"))?
                .is_none(),
            CatalogCorrupt,
            "the encrypted catalog contains an unauthenticated page"
        );
        Ok(())
    }

    /// The underlying connection, for the modules in this crate only.
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Runs `body` inside one immediate transaction.
    ///
    /// `IMMEDIATE` rather than `DEFERRED`: `docs/format/CATALOG_SCHEMA_V1.md`
    /// §17 requires an atomic boundary around operations that also touch the
    /// filesystem, and a deferred transaction takes its write lock at the first
    /// write, which turns a busy database into a mid-transaction failure rather
    /// than an immediate one.
    pub fn transaction<T>(
        &mut self,
        body: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| err!(Conflict, "the catalog is written by another transaction"))?;
        let value = body(&transaction)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite(error, "the catalog transaction did not commit"))?;
        Ok(value)
    }

    /// Closes the connection, reporting a failure rather than hiding it in a drop.
    ///
    /// Lock calls this so that a database which refuses to close is a status the
    /// session can act on, instead of a silently leaked handle holding decrypted
    /// pages after the root is gone.
    /// Folds the write-ahead log back into the database file.
    ///
    /// `docs/format/BACKUP_FORMAT_V1.md` §7 opens a backup on a consistent
    /// catalog snapshot, and this connection runs in WAL mode, so committed
    /// pages can live outside the database file. A package that copied only the
    /// file would carry a catalog older than the containers beside it.
    ///
    /// `TRUNCATE` rather than `PASSIVE`: a passive checkpoint returns without
    /// error when a reader blocks it, which would leave the same stale copy
    /// while reporting success.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::CatalogCorrupt`] or [`ChurStatus::IoFailure`] as
    /// the engine reports them.
    pub fn checkpoint(&mut self) -> Result<()> {
        let (busy, frames, checkpointed): (i64, i64, i64) = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| map_sqlite(error, "the catalog could not be checkpointed"))?;
        // SQLite reports a blocked TRUNCATE as a result row, not an SQL error.
        // In-memory catalogs have no WAL and report (-1, -1) for its size.
        chur_core::ensure!(
            busy == 0
                && ((frames == 0 && checkpointed == 0) || (frames == -1 && checkpointed == -1)),
            IoFailure,
            "the catalog WAL could not be fully truncated"
        );
        Ok(())
    }

    /// Closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::CatalogCorrupt`] or [`ChurStatus::IoFailure`] when
    /// the engine reports a failure while closing.
    pub fn close(self) -> Result<()> {
        self.connection
            .close()
            .map_err(|(_, error)| map_sqlite(error, "the catalog connection did not close"))
    }
}

/// Maps a `rusqlite` failure to the Chur status it belongs to.
///
/// `docs/ERROR_MODEL.md` forbids an untrusted string in an error, and a SQLite
/// message can quote a value from the row it failed on, so the message is
/// dropped here and only the classification survives.
pub(crate) fn map_sqlite(error: rusqlite::Error, context: &'static str) -> Error {
    let status = match &error {
        rusqlite::Error::QueryReturnedNoRows => ChurStatus::NotFound,
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            rusqlite::ErrorCode::ConstraintViolation => ChurStatus::Conflict,
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                ChurStatus::Conflict
            }
            rusqlite::ErrorCode::DiskFull => ChurStatus::StorageUnavailable,
            rusqlite::ErrorCode::NotADatabase => ChurStatus::AuthenticationFailed,
            rusqlite::ErrorCode::DatabaseCorrupt => ChurStatus::CatalogCorrupt,
            rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::CannotOpen => {
                ChurStatus::StorageUnavailable
            }
            _ => ChurStatus::InternalFailure,
        },
        _ => ChurStatus::InternalFailure,
    };
    Error::new(status, context)
}

/// Rejects a `u64` that SQLite cannot store, before it reaches a statement.
///
/// SQLite integers are signed 64-bit. Every catalog count and timestamp is
/// bounded well below this by `docs/format/CATALOG_SCHEMA_V1.md` §21, so a
/// value above it is a defect rather than user data, and it fails closed.
pub(crate) fn as_sqlite_integer(value: u64, context: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::new(ChurStatus::InvalidInput, context))
}

/// Reads a `u64` back from a column that stores it as a signed integer.
pub(crate) fn from_sqlite_integer(value: i64, context: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::new(ChurStatus::CatalogCorrupt, context))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;
    use chur_crypto::random;

    fn key() -> (Key, Id, CatalogKey) {
        let root: Key = random::secret::<32>().expect("root");
        let vault = random::id().expect("vault id");
        let catalog = CatalogKey::derive(&root, &vault).expect("catalog key");
        (root, vault, catalog)
    }

    #[test]
    fn key_deletion_overwrites_cells_and_truncates_the_wal() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let (_root, _vault, catalog) = key();
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("create");
        let secure_delete: i64 = db
            .connection()
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .expect("secure delete pragma");
        assert_eq!(secure_delete, 1, "deleted key cells must be overwritten");
        db.connection().execute_batch(
            "CREATE TABLE keys (body BLOB); INSERT INTO keys VALUES (randomblob(8192)); DELETE FROM keys;",
        ).expect("create deleted key pages");
        db.checkpoint().expect("erase old WAL frames");
        let wal = path.with_extension("db-wal");
        assert_eq!(std::fs::metadata(wal).expect("WAL").len(), 0);
        db.close().expect("close");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn a_reader_that_prevents_wal_truncation_is_a_failed_checkpoint() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let (_root, _vault, catalog) = key();
        let mut writer = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("writer");
        writer
            .connection()
            .execute_batch(
                "CREATE TABLE keys (body BLOB); INSERT INTO keys VALUES (randomblob(8192));",
            )
            .expect("write");
        let reader = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("reader");
        reader
            .connection()
            .execute_batch("BEGIN; SELECT body FROM keys;")
            .expect("retain old snapshot");
        writer
            .connection()
            .execute_batch("DELETE FROM keys; PRAGMA busy_timeout = 0;")
            .expect("delete");
        let error = writer
            .checkpoint()
            .expect_err("a busy checkpoint must not report erasure success");
        assert_eq!(error.status(), ChurStatus::IoFailure);
        reader
            .connection()
            .execute_batch("ROLLBACK;")
            .expect("release reader");
        writer.checkpoint().expect("retry checkpoint");
        reader.close().expect("close reader");
        writer.close().expect("close writer");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn a_catalog_opens_and_closes() {
        let (_root, _vault, catalog) = key();
        let db = CatalogDb::open(&CatalogLocation::Memory, &catalog).expect("open");
        db.close().expect("close");
    }

    #[test]
    fn the_key_is_bound_to_the_vault_identifier() {
        let root: Key = random::secret::<32>().expect("root");
        let first = random::id().expect("id");
        let second = random::id().expect("id");
        let one = CatalogKey::derive(&root, &first).expect("key");
        let other = CatalogKey::derive(&root, &second).expect("key");
        assert_ne!(
            one.raw_key_pragma().as_str(),
            other.raw_key_pragma().as_str()
        );
    }

    #[test]
    fn the_raw_key_pragma_is_the_key_in_hexadecimal() {
        let (_root, _vault, catalog) = key();
        let pragma = catalog.raw_key_pragma();
        assert_eq!(pragma.len(), 2 + 64 + 1);
        assert!(pragma.starts_with("x'"));
        assert!(pragma.ends_with('\''));
        let body = &pragma[2..pragma.len() - 1];
        assert!(
            body.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let mut expected = String::new();
        for byte in catalog.0.expose() {
            expected.push_str(&format!("{byte:02x}"));
        }
        assert_eq!(body, expected);
    }

    #[test]
    fn a_wrong_key_fails_as_a_credential_failure_and_not_as_corruption() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let root: Key = random::secret::<32>().expect("root");
        let vault = random::id().expect("id");
        let right = CatalogKey::derive(&root, &vault).expect("key");
        {
            let db = CatalogDb::open(&CatalogLocation::File(&path), &right).expect("create");
            db.connection()
                .execute_batch("CREATE TABLE probe (value INTEGER)")
                .expect("write a page");
            db.close().expect("close");
        }
        let other: Key = random::secret::<32>().expect("root");
        let wrong = CatalogKey::derive(&other, &vault).expect("key");
        let outcome = CatalogDb::open(&CatalogLocation::File(&path), &wrong);
        let Err(error) = outcome else {
            panic!("a wrong catalog key opened the database");
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }

    #[test]
    fn a_written_catalog_is_not_readable_as_plaintext_sqlite() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let (_root, _vault, catalog) = key();
        {
            let db = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("create");
            db.connection()
                .execute_batch(
                    "CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('canary')",
                )
                .expect("write");
            db.close().expect("close");
        }
        let bytes = std::fs::read(&path).expect("read the file");
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "the header is plaintext"
        );
        assert!(
            !bytes.windows(6).any(|window| window == b"canary"),
            "a written value appears in the file"
        );
    }

    /// Reads one cipher setting as text, whatever type SQLCipher reports.
    fn cipher_setting(connection: &Connection, name: &str) -> String {
        connection
            .query_row(&format!("PRAGMA {name}"), [], |row| {
                Ok(match row.get::<_, rusqlite::types::Value>(0)? {
                    rusqlite::types::Value::Integer(value) => value.to_string(),
                    rusqlite::types::Value::Text(value) => value,
                    other => panic!("unexpected {name} value {other:?}"),
                })
            })
            .expect(name)
    }

    /// The SQLCipher 4 profile that catalogs written before the parameters
    /// were pinned use, read from the bundled library's defaults.
    const V4_PROFILE: [(&str, &str); 5] = [
        ("cipher_page_size", "4096"),
        ("cipher_hmac_algorithm", "HMAC_SHA512"),
        ("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512"),
        ("kdf_iter", "256000"),
        ("cipher_plaintext_header_size", "0"),
    ];

    #[test]
    fn the_pinned_cipher_parameters_are_the_sqlcipher_4_defaults() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let (_root, _vault, catalog) = key();
        let db = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("create");
        for (name, value) in V4_PROFILE {
            assert_eq!(cipher_setting(db.connection(), name), value, "{name}");
        }
        // A connection with no cipher pragma reports the library defaults; they
        // must equal the pinned values, or catalogs written before the pin
        // would have another format.
        let unpinned = Connection::open_in_memory().expect("open");
        unpinned
            .pragma_update(None, "key", catalog.raw_key_pragma().as_str())
            .expect("key");
        for (name, value) in V4_PROFILE {
            assert_eq!(cipher_setting(&unpinned, name), value, "default {name}");
        }
        db.close().expect("close");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn a_catalog_written_without_pinned_parameters_still_opens() {
        let directory = tempdir();
        let path = directory.join("catalog.db");
        let (_root, _vault, catalog) = key();
        {
            // The open path before the pin: the memory pragma, the raw key,
            // and the session pragmas, with no cipher parameter.
            let old = Connection::open(&path).expect("create");
            old.execute_batch(PRE_KEY_PRAGMAS).expect("memory pragma");
            old.pragma_update(None, "key", catalog.raw_key_pragma().as_str())
                .expect("key");
            old.execute_batch(SESSION_PRAGMAS).expect("session pragmas");
            old.execute_batch(
                "CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('kept');",
            )
            .expect("write");
            old.close().map_err(|(_, error)| error).expect("close");
        }
        let db = CatalogDb::open(&CatalogLocation::File(&path), &catalog).expect("reopen");
        let value: String = db
            .connection()
            .query_row("SELECT value FROM probe", [], |row| row.get(0))
            .expect("read");
        assert_eq!(value, "kept");
        db.verify_cipher_pages().expect("every page authenticates");
        db.close().expect("close");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    /// A private temporary directory that outlives the test body.
    ///
    /// The catalog needs a real path for the WAL, so an in-memory database
    /// cannot exercise the at-rest tests above.
    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let suffix = random::id().expect("id");
        let mut name = String::from("chur-catalog-test-");
        for byte in suffix.as_bytes() {
            name.push_str(&format!("{byte:02x}"));
        }
        path.push(name);
        std::fs::create_dir_all(&path).expect("create the directory");
        path
    }
    #[test]
    fn cipher_page_check_authenticates_unused_pages() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let path = std::env::temp_dir().join(format!(
            "chur-cipher-pages-{}",
            chur_crypto::random::id().expect("id").to_hex()
        ));
        let root = chur_crypto::random::secret::<32>().expect("root");
        let vault = chur_crypto::random::id().expect("vault");
        let key = CatalogKey::derive(&root, &vault).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &key).expect("catalog");
        db.connection().execute_batch("CREATE TABLE unused(data BLOB); INSERT INTO unused VALUES(randomblob(65536)); DROP TABLE unused;").expect("unused pages");
        db.checkpoint().expect("checkpoint");
        db.verify_cipher_pages().expect("valid pages");
        db.close().expect("close");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("file");
        file.seek(SeekFrom::End(-100)).expect("seek");
        let mut byte = [0];
        file.read_exact(&mut byte).expect("read");
        byte[0] ^= 1;
        file.seek(SeekFrom::End(-100)).expect("seek");
        file.write_all(&byte).expect("flip");
        file.sync_all().expect("sync");
        drop(file);
        let db = CatalogDb::open(&CatalogLocation::File(&path), &key)
            .expect("unread page does not block open");
        assert!(db.verify_cipher_pages().is_err());
        drop(db);
        std::fs::remove_file(&path).expect("cleanup");
    }
}
