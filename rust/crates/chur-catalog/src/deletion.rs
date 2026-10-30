//! The deletion transaction and garbage collection.
//!
//! `docs/format/CATALOG_SCHEMA_V1.md` §14.1 fixes the order and this module
//! runs it and no other:
//!
//! 1. one catalog transaction sets `state` to `DELETING`, [`begin`];
//! 2. one catalog transaction destroys every object-key envelope and writes
//!    the tombstone; a verified WAL truncation then permits `TOMBSTONED`, [`erase`];
//! 3. unlink the derived-asset containers;
//! 4. unlink the original container;
//! 5. delete the object's scratch entries;
//! 6. delete the object row, leaving the tombstone.
//!
//! Steps 1 and 2 are the atomic boundary §17 requires. Steps 3 to 6 are
//! garbage collection: each is idempotent, none is required for the
//! crypto-erasure claim of SEC-026, and a crash inside them loses no security
//! property.
//!
//! Steps 3 and 4 unlink files, which the catalog does not own. [`sweep`]
//! therefore returns the opaque path identifiers and [`finish`] runs steps 5
//! and 6 once the caller reports the unlinks done. A caller that never reports
//! leaves the object at `TOMBSTONED`, which the next sweep picks up again.

use chur_core::{Id, Result, ensure};
use chur_format::constants::ObjectState;
use rusqlite::{Transaction, params};

use crate::db::{CatalogDb, as_sqlite_integer, map_sqlite};
use crate::schema::bump_generation;

/// What garbage collection must still do for one object, §14.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The object.
    pub object_id: Id,
    /// Whether step 2 and its durable WAL erasure barrier have completed.
    ///
    /// An object stays `DELETING` until old WAL frames have been removed.
    /// Missing envelopes alone cannot prove that the barrier completed.
    pub erased: bool,
    /// The opaque store identifiers of the containers steps 3 and 4 unlink, the
    /// derived assets first.
    pub containers: Vec<Id>,
}

/// What recovery does with a half-deleted object, §14.1.
///
/// Recovery rolls forward and never back, because rolling back would return to
/// `ACTIVE` an object whose key may already be gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rollforward {
    /// `DELETING`: repeat key removal and its WAL barrier.
    Erase,
    /// The envelopes are already destroyed: finish steps 3 to 6.
    Collect,
}

impl Pending {
    /// The step this object resumes at.
    #[must_use]
    pub const fn rollforward(&self) -> Rollforward {
        if self.erased {
            Rollforward::Collect
        } else {
            Rollforward::Erase
        }
    }
}

/// Step 1: the object stops being listable.
pub fn begin(db: &mut CatalogDb, object_id: &Id) -> Result<()> {
    let object_id = *object_id;
    db.transaction(|transaction| begin_in(transaction, &object_id))
}

/// Step 1 inside a caller's transaction.
pub(crate) fn begin_in(transaction: &Transaction<'_>, object_id: &Id) -> Result<()> {
    let object_id = *object_id;
    {
        let changed = transaction
            .execute(
                "UPDATE objects SET state = ?2 WHERE object_id = ?1 AND state IN (?3, ?4, ?5)",
                params![
                    object_id.as_bytes().as_slice(),
                    i64::from(ObjectState::Deleting.value()),
                    i64::from(ObjectState::Active.value()),
                    i64::from(ObjectState::Trashed.value()),
                    i64::from(ObjectState::Corrupt.value()),
                ],
            )
            .map_err(|error| map_sqlite(error, "the object could not enter deletion"))?;
        ensure!(
            changed == 1,
            NotFound,
            "no deletable object carries that id"
        );
        transaction
            .execute(
                "DELETE FROM trash_entries WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the trash entry could not be removed"))?;
        // The object is no longer listable, so it is no longer searchable.
        unindex_search(transaction, &object_id)?;
        bump_generation(transaction)
    }
}

/// Step 2: the erasure moment.
///
/// Once the key-removal transaction and verified WAL truncation complete, the
/// `ContentKey` is unrecoverable from
/// this vault's live state, and every copy of the container that state reaches,
/// including WAL pages and queued sync operations, is ciphertext no reachable
/// key opens.
///
/// It is idempotent: re-running it on an object whose envelopes are already
/// gone commits the same end state, which is what lets recovery roll forward
/// without first deciding whether the earlier attempt got there.
pub fn erase(db: &mut CatalogDb, object_id: &Id, now_ms: u64) -> Result<()> {
    let object_id = *object_id;
    let authored = as_sqlite_integer(now_ms, "the time is out of range")?;
    db.transaction(|transaction| {
        let (generation, collection): (i64, Vec<u8>) = transaction
            .query_row(
                "SELECT object_generation, collection_id FROM objects WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| map_sqlite(error, "the object could not be read"))?;
        transaction
            .execute(
                "DELETE FROM sync_object_envelope_epochs WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the envelope epoch could not be destroyed"))?;
        for statement in [
            "DELETE FROM object_key_requests WHERE object_id = ?1 AND collection_id = ?2",
            "DELETE FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2",
        ] {
            transaction
                .execute(
                    statement,
                    params![object_id.as_bytes().as_slice(), collection.as_slice()],
                )
                .map_err(|error| {
                    map_sqlite(error, "temporary object keys could not be destroyed")
                })?;
        }
        transaction
            .execute(
                "DELETE FROM object_key_envelopes WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the key envelopes could not be destroyed"))?;
        transaction
            .execute(
                "INSERT INTO tombstones (collection_id, object_id, authored_ms, object_generation)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(collection_id, object_id) DO NOTHING",
                params![
                    collection,
                    object_id.as_bytes().as_slice(),
                    authored,
                    generation
                ],
            )
            .map_err(|error| map_sqlite(error, "the tombstone could not be written"))?;
        transaction
            .execute(
                "UPDATE objects SET state = ?2 WHERE object_id = ?1",
                params![
                    object_id.as_bytes().as_slice(),
                    i64::from(ObjectState::Deleting.value())
                ],
            )
            .map_err(|error| map_sqlite(error, "the object could not await key erasure"))?;
        unindex_search(transaction, &object_id)?;
        bump_generation(transaction)
    })?;
    // secure_delete clears cells in the current pages; old WAL frames retain
    // their former contents until a verified TRUNCATE finishes. Keep DELETING
    // until this barrier, so recovery never treats a failed barrier as erasure.
    db.checkpoint()?;
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE objects SET state = ?2 WHERE object_id = ?1",
                params![
                    object_id.as_bytes().as_slice(),
                    i64::from(ObjectState::Tombstoned.value())
                ],
            )
            .map_err(|error| map_sqlite(error, "the object could not be tombstoned"))?;
        bump_generation(transaction)
    })
}

/// Removes all reachable local content keys in the transaction that accepts a
/// signed terminal purge. The caller must complete a verified WAL barrier.
pub(crate) fn project_purge(
    transaction: &Transaction<'_>,
    payload: &chur_sync_protocol::payload::OperationPayload,
) -> Result<()> {
    use chur_sync_protocol::payload::PayloadBody;
    let PayloadBody::PurgeObject {
        object_id,
        object_generation,
        authored_at_ms,
    } = payload.body()
    else {
        return Ok(());
    };
    let key = object_id.as_bytes().as_slice();
    let collection = payload.collection_id().as_bytes().as_slice();
    // A pending object has no `objects` row. Its custody rows carry their own
    // collection binding. Never let a foreign signed lifecycle erase them.
    for sql in [
        "DELETE FROM object_key_requests WHERE object_id = ?1 AND collection_id = ?2",
        "DELETE FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2",
        "DELETE FROM object_key_envelopes WHERE object_id = ?1 AND EXISTS (
            SELECT 1 FROM objects WHERE object_id = ?1 AND collection_id = ?2)",
        "DELETE FROM sync_object_envelope_epochs WHERE object_id = ?1 AND EXISTS (
            SELECT 1 FROM objects WHERE object_id = ?1 AND collection_id = ?2)",
        "DELETE FROM trash_entries WHERE object_id = ?1 AND EXISTS (
            SELECT 1 FROM objects WHERE object_id = ?1 AND collection_id = ?2)",
    ] {
        transaction
            .execute(sql, params![key, collection])
            .map_err(|error| map_sqlite(error, "purged keys could not be destroyed"))?;
    }
    transaction
        .execute(
            "INSERT INTO tombstones
        (collection_id, object_id, authored_ms, object_generation) VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(collection_id, object_id) DO NOTHING",
            params![
                collection,
                key,
                as_sqlite_integer(*authored_at_ms, "purge time is too large")?,
                as_sqlite_integer(*object_generation, "purge generation is too large")?
            ],
        )
        .map_err(|error| map_sqlite(error, "permanent purge tombstone could not be written"))?;
    let changed = transaction
        .execute(
            "UPDATE objects SET state = ?2 WHERE object_id = ?1 AND collection_id = ?3",
            params![key, i64::from(ObjectState::Deleting.value()), collection],
        )
        .map_err(|error| map_sqlite(error, "purged object could not await key erasure"))?;
    if changed != 0 {
        unindex_search(transaction, object_id)?;
    }
    Ok(())
}

/// Completes key erasure after durable source and own-vault tombstone publication.
/// Recovery repeats this service before physical collection.
pub fn erase_with_sync(
    db: &mut CatalogDb,
    root: &chur_crypto::Key,
    vault_id: Id,
    object_id: &Id,
    now_ms: u64,
) -> Result<()> {
    let object = crate::store::object(db, object_id)?;
    if crate::store::collection(db, &object.collection_id)?.policy_type
        == crate::model::COLLECTION_POLICY_SHARED
    {
        // A recipient removes only its local copy. Remote authorization and
        // epoch projections are not prerequisites for destroying its own key.
        return erase(db, object_id, now_ms);
    }
    let keys = crate::sync_keys::key_directory(db, root, vault_id)?;
    let accepted = crate::sync_receive::load_materialized_state(db, &keys)?;
    if !accepted.object_is_purged(object_id) {
        crate::sharing_publication::publish_deletion(db, root, vault_id, object_id, now_ms)?;
    }
    // A received own-vault purge has already removed the key. Its source
    // persisted the shared outbox event first; do not try to republish a
    // current-epoch prefix from an erased key on this receiving device.
    crate::own_sync::publish_deletion(db, root, vault_id, object_id, now_ms)?;
    erase(db, object_id, now_ms)
}

/// Steps 5 and 6: the scratch entries and the object row.
///
/// The tombstone survives. `docs/format/CATALOG_SCHEMA_V1.md` §14 lets a vault
/// with no enrolled peer discard it afterwards, which is [`discard_tombstone`].
pub fn finish(db: &mut CatalogDb, object_id: &Id) -> Result<()> {
    let object_id = *object_id;
    db.transaction(|transaction| {
        let key = object_id.as_bytes().as_slice();
        let unfinished: i64 = transaction
            .query_row(
                "SELECT count(*) FROM objects WHERE object_id = ?1 AND state != ?2",
                params![key, i64::from(ObjectState::Tombstoned.value())],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "the erasure state could not be read"))?;
        ensure!(unfinished == 0, Conflict, "key erasure has not completed");
        // Step 5.
        transaction
            .execute("DELETE FROM scratch_entries WHERE object_id = ?1", [key])
            .map_err(|error| map_sqlite(error, "the scratch entries could not be deleted"))?;
        // Step 6. The child rows go first because the schema declares plain
        // references rather than cascades: a cascade would delete a child on
        // any future path that removed an object row, and §14.1 wants exactly
        // one such path.
        for statement in [
            "DELETE FROM derived_assets WHERE object_id = ?1",
            "DELETE FROM object_streams WHERE object_id = ?1",
            "DELETE FROM metadata_revisions WHERE object_id = ?1",
            "DELETE FROM album_memberships WHERE object_id = ?1",
            "DELETE FROM favorites WHERE object_id = ?1",
            "DELETE FROM object_tags WHERE object_id = ?1",
            "DELETE FROM integrity_records WHERE object_id = ?1",
            "DELETE FROM sync_object_envelope_epochs WHERE object_id = ?1",
            "DELETE FROM object_key_envelopes WHERE object_id = ?1",
            "DELETE FROM objects WHERE object_id = ?1",
        ] {
            transaction
                .execute(statement, [key])
                .map_err(|error| map_sqlite(error, "a deleted object row could not be removed"))?;
        }
        unindex_search(transaction, &object_id)?;
        bump_generation(transaction)
    })
}

/// Lists damaged objects for the explicit irreversible cleanup action.
pub fn corrupt_objects(db: &CatalogDb) -> Result<Vec<Id>> {
    let mut statement = db
        .connection()
        .prepare("SELECT object_id FROM objects WHERE state = ?1 ORDER BY object_id")
        .map_err(|error| map_sqlite(error, "corrupt objects could not be prepared"))?;
    let rows = statement
        .query_map([i64::from(ObjectState::Corrupt.value())], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|error| map_sqlite(error, "corrupt objects could not be listed"))?;
    rows.map(|row| {
        crate::row::id(
            &row.map_err(|error| map_sqlite(error, "corrupt object ID could not be read"))?,
            "corrupt object ID is malformed",
        )
    })
    .collect()
}

/// Discards a tombstone under the peerless retention rule of §14.
///
/// It applies only in a vault with no enrolled peer device, because nothing
/// local can resurrect an object whose row, envelopes, and containers are all
/// gone. Every other vault follows the membership rule of
/// `docs/sync/OPERATION_LOG.md` §11, and v1 enrols no peer.
pub fn discard_tombstone(db: &mut CatalogDb, object_id: &Id) -> Result<()> {
    let object_id = *object_id;
    db.transaction(|transaction| {
        let live: i64 = transaction
            .query_row(
                "SELECT count(*) FROM objects WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "the object could not be read"))?;
        ensure!(
            live == 0,
            Conflict,
            "a tombstone is discarded only after its object row is gone"
        );
        transaction
            .execute(
                "DELETE FROM tombstones WHERE object_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM sharing_object_operations WHERE object_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM sync_operations)",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the tombstone could not be discarded"))?;
        Ok(())
    })
}

/// Every object garbage collection must still act on, §14.1.
///
/// A sweep runs at the first unlock of a session and again after each deletion
/// that session performs, so an interrupted deletion always completes rather
/// than being repaired.
pub fn sweep(db: &CatalogDb) -> Result<Vec<Pending>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare(
            "SELECT o.object_id,
                    (SELECT count(*) FROM object_key_envelopes e WHERE e.object_id = o.object_id),
                    o.state
               FROM objects o
              WHERE o.state IN (?1, ?2)
              ORDER BY o.object_id",
        )
        .map_err(|error| map_sqlite(error, "the sweep query could not be prepared"))?;
    let rows = statement
        .query_map(
            params![
                i64::from(ObjectState::Deleting.value()),
                i64::from(ObjectState::Tombstoned.value()),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|error| map_sqlite(error, "the sweep could not be read"))?;
    let mut pending = Vec::new();
    for row in rows {
        let (object_id, envelopes, state) =
            row.map_err(|error| map_sqlite(error, "a sweep row could not be read"))?;
        let object_id = crate::row::id(&object_id, "the object id is malformed")?;
        pending.push(Pending {
            object_id,
            erased: envelopes == 0 && state == i64::from(ObjectState::Tombstoned.value()),
            containers: containers_of(db, &object_id)?,
        });
    }
    Ok(pending)
}

/// The opaque container identifiers of one object, derived assets first.
///
/// §14.1 unlinks the derived-asset containers at step 3 and the original at
/// step 4, so the order this returns is the order the caller unlinks in.
fn containers_of(db: &CatalogDb, object_id: &Id) -> Result<Vec<Id>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare(
            "SELECT container_path_id FROM object_streams
              WHERE object_id = ?1
              ORDER BY (stream_kind = 1), stream_kind",
        )
        .map_err(|error| map_sqlite(error, "the container query could not be prepared"))?;
    let rows = statement
        .query_map([object_id.as_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|error| map_sqlite(error, "the containers could not be read"))?;
    let mut containers = Vec::new();
    for row in rows {
        let bytes = row.map_err(|error| map_sqlite(error, "a container row could not be read"))?;
        containers.push(crate::row::id(
            &bytes,
            "the container path id is malformed",
        )?);
    }
    Ok(containers)
}

/// Whether a container found in the committed namespace should be deleted.
///
/// §14.1 last bullet: a container with no object row and no `ImportTransaction`
/// row is deleted. The import-temporary case belongs to
/// `docs/format/OBJECT_CONTAINER_V1.md` §14.4 and is not this decision.
pub fn is_orphan_container(db: &CatalogDb, container_path_id: &Id) -> Result<bool> {
    let key = container_path_id.as_bytes().as_slice();
    let streams: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM object_streams WHERE container_path_id = ?1",
            [key],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the streams could not be read"))?;
    let imports: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM import_transactions WHERE temp_path_id = ?1",
            [key],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the journal could not be read"))?;
    Ok(streams == 0 && imports == 0)
}

/// Whether a file in the temporary container namespace is dead.
///
/// `OBJECT_CONTAINER_V1.md` §14.4: a temporary container with no journal record
/// is dead. It is the [`is_orphan_container`] rule with one exception: a
/// received object download, from the own vault's sync or from a shared
/// collection, is staged under the object's identifier with no journal record.
/// Both receive plans give the host an object only after they write its
/// `object_receive_dispatch` ticket, so a download can exist only for an
/// object with a ticket. Such a download is kept, so that it can resume. A
/// shared object with sharing log rows is kept as well.
///
/// # Errors
///
/// Returns the engine's error when a row cannot be read.
pub fn is_orphan_temporary(db: &CatalogDb, temp_path_id: &Id) -> Result<bool> {
    if !is_orphan_container(db, temp_path_id)? {
        return Ok(false);
    }
    let received: i64 = db
        .connection()
        .query_row(
            "SELECT (SELECT count(*) FROM object_receive_dispatch WHERE object_id = ?1)
                  + (SELECT count(*) FROM sharing_object_operations WHERE object_id = ?1)",
            [temp_path_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the received objects could not be read"))?;
    Ok(received == 0)
}

/// Removes one object from the search index.
fn unindex_search(transaction: &Transaction<'_>, object_id: &Id) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM content_index WHERE object_id=?1",
            [object_id.as_bytes().as_slice()],
        )
        .map_err(|e| map_sqlite(e, "the content text could not be erased"))?;
    transaction
        .execute(
            "DELETE FROM object_search WHERE rowid = ?1",
            [crate::store::row_key(object_id)],
        )
        .map_err(|error| map_sqlite(error, "the search row could not be removed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::db::{CatalogKey, CatalogLocation};
    use crate::model::{
        COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE, Collection, MetadataRevision,
        Object, Stream,
    };
    use crate::query::{ObjectQuery, Scope, page};
    use crate::schema::open_at_current_version;
    use crate::store;
    use crate::trash;
    use chur_core::ChurStatus;
    use chur_crypto::{Key, Nonce, random};
    use chur_format::constants::{IntegritySummary, MediaClass, StreamKind};
    use chur_format::envelope::ObjectKeyEnvelope;

    struct Vault {
        db: CatalogDb,
        collection: Id,
    }

    fn envelope(collection_id: Id, object_id: Id) -> Vec<u8> {
        ObjectKeyEnvelope::seal(
            &random::secret::<32>().expect("collection key"),
            random::id().expect("vault id"),
            collection_id,
            1,
            object_id,
            1,
            Nonce::random().expect("nonce"),
            &random::secret::<32>().expect("object key"),
        )
        .expect("object envelope")
        .encode()
    }

    fn vault() -> Vault {
        let root: Key = random::secret::<32>().expect("root");
        let vault_id = random::id().expect("id");
        let key = CatalogKey::derive(&root, &vault_id).expect("key");
        vault_at(&CatalogLocation::Memory, &key)
    }

    fn vault_at(location: &CatalogLocation<'_>, key: &CatalogKey) -> Vault {
        let mut db = CatalogDb::open(location, key).expect("open");
        open_at_current_version(&mut db, 1).expect("schema");
        let collection = random::id().expect("id");
        store::put_collection(
            &mut db,
            &Collection {
                collection_id: collection,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
        )
        .expect("collection");
        Vault { db, collection }
    }

    fn import(vault: &mut Vault) -> (Id, Id) {
        let object_id = random::id().expect("id");
        let stream_id = random::id().expect("id");
        let container = random::id().expect("id");
        store::activate_object(
            &mut vault.db,
            &store::ObjectActivation {
                object: Object {
                    object_id,
                    object_generation: 1,
                    collection_id: vault.collection,
                    primary_stream_id: stream_id,
                    media_kind: MediaClass::Image,
                    capture_time_ms: 1_000,
                    import_time_ms: 1_001,
                    capture_time_substituted: false,
                    plaintext_size: 4_096,
                    width: 100,
                    height: 100,
                    duration_ms: 0,
                    favorite: false,
                    state: ObjectState::Active,
                    integrity_summary: IntegritySummary::Unverified,
                    thumbnail_ready: false,
                    active_metadata_revision: 1,
                },
                stream: Stream {
                    stream_id,
                    object_id,
                    stream_kind: StreamKind::Original,
                    stream_revision: 1,
                    source_content_revision: 0,
                    container_path_id: container,
                    container_version: 1,
                    suite_id: 1,
                    ciphertext_size: 4_200,
                    plaintext_size: 4_096,
                    chunk_size: 262_144,
                    complete_verified_ms: None,
                    final_commitment: [0u8; 32],
                },
                envelope: envelope(vault.collection, object_id),
                envelope_generation: 1,
                metadata: MetadataRevision {
                    object_id,
                    revision: 1,
                    active: true,
                    record: vec![0u8; 32],
                    original_filename: Some(String::from("holiday.jpg")),
                    caption: None,
                    content_type: String::from("image/jpeg"),
                    capture_time_ms: Some(1_000),
                    width: 100,
                    height: 100,
                    duration_ms: 0,
                },
            },
        )
        .expect("activate");
        (object_id, container)
    }

    fn listed(db: &CatalogDb) -> usize {
        page(db, &ObjectQuery::timeline())
            .expect("page")
            .objects
            .len()
    }

    fn searchable(db: &CatalogDb) -> usize {
        page(
            db,
            &ObjectQuery {
                scope: Scope::Search,
                terms: Some(String::from("holiday")),
                ..ObjectQuery::timeline()
            },
        )
        .expect("page")
        .objects
        .len()
    }

    fn rejection<T>(outcome: Result<T>) -> ChurStatus {
        let Err(error) = outcome else {
            panic!("deletion accepted something the specification forbids");
        };
        error.status()
    }

    #[test]
    fn a_forward_clock_jump_cannot_expire_a_fresh_trash_entry() {
        use crate::trusted_time;
        use std::time::{Duration, Instant};
        let mut vault = vault();
        let (id, _) = import(&mut vault);
        let base = Instant::now();
        let start = 1_700_000_000_000;
        let month = 30 * 24 * 60 * 60 * 1000;
        let trusted = trusted_time::advance(&mut vault.db, start, base).expect("start");
        trash::set(&mut vault.db, &[id], false, trusted).expect("trash");
        // The device clock jumps a month ahead; the process measured five seconds.
        let jumped =
            trusted_time::advance(&mut vault.db, start + month, base + Duration::from_secs(5))
                .expect("jump");
        assert!(
            trash::pending(&vault.db, Some(jumped))
                .expect("pending")
                .is_empty()
        );
        // Real time passes: the entry stays through day 29 and expires on day 30.
        for day in 1..=30u64 {
            let at = base + Duration::from_secs(5 + day * 24 * 60 * 60);
            let now = trusted_time::advance(&mut vault.db, start + month, at).expect("sweep");
            assert_eq!(
                trash::pending(&vault.db, Some(now)).expect("pending").len(),
                usize::from(day == 30),
                "day {day}"
            );
        }
    }

    #[test]
    fn trash_hides_then_restores_an_object_without_losing_its_key() {
        let mut vault = vault();
        let (id, _) = import(&mut vault);
        trash::set(&mut vault.db, &[id], false, 1_000).expect("trash");
        assert_eq!(listed(&vault.db), 0);
        assert_eq!(searchable(&vault.db), 0);
        assert_eq!(
            page(
                &vault.db,
                &ObjectQuery {
                    scope: Scope::Trash,
                    ..ObjectQuery::timeline()
                }
            )
            .expect("trash page")
            .objects
            .len(),
            1
        );
        assert!(store::active_envelope(&vault.db, &id).is_ok());
        assert!(
            trash::pending(&vault.db, Some(1_000 + trash::RETENTION_MS - 1))
                .expect("early expiry")
                .is_empty()
        );
        assert_eq!(
            trash::pending(&vault.db, Some(1_000 + trash::RETENTION_MS)).expect("expiry"),
            vec![id]
        );
        assert_eq!(
            rejection(trash::set(
                &mut vault.db,
                &[id],
                true,
                1_000 + trash::RETENTION_MS
            )),
            ChurStatus::NotFound
        );
        trash::set(&mut vault.db, &[id], true, 2_000).expect("restore");
        assert_eq!(listed(&vault.db), 1);
        assert_eq!(searchable(&vault.db), 1);
        assert!(trash::pending(&vault.db, None).expect("pending").is_empty());
    }

    #[test]
    fn trash_selection_is_atomic_and_permanent_deletion_removes_its_entry() {
        let mut vault = vault();
        let (id, _) = import(&mut vault);
        let unknown = random::id().expect("id");
        assert_eq!(
            rejection(trash::set(&mut vault.db, &[id, unknown], false, 1)),
            ChurStatus::NotFound
        );
        assert_eq!(listed(&vault.db), 1);
        assert!(trash::pending(&vault.db, None).expect("pending").is_empty());
        trash::set(&mut vault.db, &[id], false, 1).expect("trash");
        begin(&mut vault.db, &id).expect("purge");
        assert!(trash::pending(&vault.db, None).expect("pending").is_empty());
        erase(&mut vault.db, &id, 2).expect("erase");
        assert_eq!(
            rejection(store::active_envelope(&vault.db, &id)),
            ChurStatus::NotFound
        );
    }

    #[test]
    fn published_history_remains_valid_without_retaining_a_deleted_object_key() {
        use crate::{sharing, sharing_publication, sync_keys, sync_receive};
        use chur_format::envelope::CollectionKeyEnvelope;
        use chur_sync_protocol::payload::{OperationPayload, PayloadBody};

        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        let (neighbor_id, _) = import(&mut vault);
        let root = Key::new([71; 32]);
        let vault_id = Id::new([72; 16]).expect("vault id");
        let collection_key = Key::new([73; 32]);
        let content_key = Key::new([74; 32]);
        let envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            vault_id,
            vault.collection,
            1,
            object_id,
            1,
            Nonce::new([75; 24]),
            &content_key,
        )
        .expect("object envelope");
        vault
            .db
            .connection()
            .execute(
                "UPDATE object_key_envelopes SET body = ?2 WHERE object_id = ?1",
                params![object_id.as_bytes().as_slice(), envelope.encode()],
            )
            .expect("replace envelope");
        let neighbor_envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            vault_id,
            vault.collection,
            1,
            neighbor_id,
            1,
            Nonce::new([78; 24]),
            &Key::new([79; 32]),
        )
        .expect("neighbor envelope");
        vault
            .db
            .connection()
            .execute(
                "UPDATE object_key_envelopes SET body = ?2 WHERE object_id = ?1",
                params![
                    neighbor_id.as_bytes().as_slice(),
                    neighbor_envelope.encode()
                ],
            )
            .expect("replace neighbor envelope");
        vault
            .db
            .connection()
            .execute(
                "UPDATE object_streams SET final_commitment = ?2 WHERE object_id = ?1",
                params![object_id.as_bytes().as_slice(), [76u8; 32].as_slice()],
            )
            .expect("committed original");
        let collection = store::collection(&vault.db, &vault.collection).expect("collection");
        let collection_envelope = CollectionKeyEnvelope::seal(
            &root,
            vault_id,
            vault.collection,
            1,
            1,
            Nonce::new([77; 24]),
            &collection_key,
        )
        .expect("collection envelope");
        store::put_collection_with_envelope(
            &mut vault.db,
            &collection,
            1,
            &collection_envelope.encode(),
        )
        .expect("retain collection key");
        sync_receive::provision_local_identity(&mut vault.db, &root, vault_id).expect("identity");
        sharing::provision(&mut vault.db, vault_id, vault.collection, 1).expect("sharing");
        let candidate = sharing_publication::candidate(&vault.db, &vault.collection, &object_id)
            .expect("candidate");
        let publication = sharing_publication::publish_page(
            &mut vault.db,
            &root,
            vault_id,
            vault.collection,
            &[candidate],
        )
        .expect("publish")
        .remove(0);
        let retained_record = publication.commit_operation.encode();
        let keys = sync_keys::key_directory(&vault.db, &root, vault_id).expect("keys");
        let payload =
            OperationPayload::open_for_collection_operation(&publication.commit_operation, &keys)
                .expect("retained publication opens");
        let PayloadBody::CommitObject {
            object_key_commitment,
            ..
        } = payload.body()
        else {
            panic!("not an object commit");
        };
        assert_eq!(
            *object_key_commitment,
            chur_sync_protocol::object_grant::object_key_commitment(
                &vault.collection,
                &object_id,
                &content_key
            )
        );
        assert!(
            !payload
                .encode()
                .windows(ObjectKeyEnvelope::LEN)
                .any(|window| window == envelope.encode())
        );
        begin(&mut vault.db, &object_id).expect("begin published deletion");
        erase_with_sync(&mut vault.db, &root, vault_id, &object_id, 2)
            .expect("erase published key");
        finish(&mut vault.db, &object_id).expect("collect published object");
        discard_tombstone(&mut vault.db, &object_id).expect("retain required tombstone");
        assert_eq!(
            rejection(store::active_envelope(&vault.db, &object_id)),
            ChurStatus::NotFound
        );
        assert_eq!(
            store::active_envelope(&vault.db, &neighbor_id).expect("neighbor key"),
            neighbor_envelope.encode()
        );
        assert_eq!(
            crate::object_grants::ensure_not_deleted(&vault.db, &vault.collection, &object_id)
                .expect_err("local tombstone")
                .status(),
            ChurStatus::NotFound
        );
        let membership = crate::sync_membership::load(&vault.db)
            .expect("membership")
            .expect("present");
        let state = sharing::load(&vault.db, &vault.collection)
            .expect("sharing")
            .expect("present");
        let memberships = std::collections::BTreeMap::from([(vault_id, membership)]);
        crate::sharing_log::load(
            &vault.db,
            vault.collection,
            1,
            *publication.commit_operation.key_selector(),
            &keys,
            &memberships,
            &state,
        )
        .expect("signed chain still replays");
        assert_eq!(publication.commit_operation.encode(), retained_record);
        let (device, _) = crate::sync_keys::local_identity(
            &vault.db,
            &root,
            memberships.get(&vault_id).expect("membership"),
        )
        .expect("identity")
        .expect("present");
        let outbound = crate::sharing_log::outbound_after(&vault.db, &vault_id, &device, 0)
            .expect("durable outbox");
        assert_eq!(
            outbound.len(),
            3,
            "create, commit and deletion survive object garbage collection"
        );
        let tombstone = chur_sync_protocol::collection_operation::CollectionOperation::decode(
            &outbound[2].record,
        )
        .expect("signed tombstone");
        assert!(
            matches!(OperationPayload::open_for_collection_operation(&tombstone, &keys).expect("open tombstone").body(),
            PayloadBody::PurgeObject { object_id: deleted, .. } if *deleted == object_id)
        );
        assert!(
            crate::sharing_log::outbound_after(&vault.db, &vault_id, &device, outbound[2].cursor)
                .expect("ack cursor")
                .is_empty()
        );
        assert!(
            crate::sharing_log::outbound_after(
                &vault.db,
                &vault_id,
                &Id::new([90; 16]).expect("other device"),
                0
            )
            .expect("other device cursor")
            .is_empty()
        );
    }

    #[test]
    fn blocked_erasure_retries_after_restart_and_keeps_neighbor_keys() {
        let directory =
            std::env::temp_dir().join(format!("chur-erase-{}", random::id().expect("id").to_hex()));
        std::fs::create_dir_all(&directory).expect("directory");
        let path = directory.join("catalog.db");
        let root = Key::new([81; 32]);
        let vault_id = Id::new([82; 16]).expect("vault id");
        let key = CatalogKey::derive(&root, &vault_id).expect("catalog key");
        let mut vault = vault_at(&CatalogLocation::File(&path), &key);
        let (object_id, _) = import(&mut vault);
        let (neighbor_id, _) = import(&mut vault);
        let neighbor_envelope =
            store::active_envelope(&vault.db, &neighbor_id).expect("neighbor key");
        begin(&mut vault.db, &object_id).expect("begin");
        let reader = CatalogDb::open(&CatalogLocation::File(&path), &key).expect("reader");
        reader
            .connection()
            .execute_batch("BEGIN; SELECT body FROM object_key_envelopes;")
            .expect("retain snapshot with the old envelope");
        vault
            .db
            .connection()
            .execute_batch("PRAGMA busy_timeout = 0;")
            .expect("do not wait");
        assert_eq!(
            rejection(erase(&mut vault.db, &object_id, 2)),
            ChurStatus::IoFailure
        );
        assert_eq!(
            store::object(&vault.db, &object_id).expect("object").state,
            ObjectState::Deleting
        );
        assert_eq!(
            sweep(&vault.db).expect("sweep")[0].rollforward(),
            Rollforward::Erase
        );
        assert_eq!(
            rejection(finish(&mut vault.db, &object_id)),
            ChurStatus::Conflict
        );
        reader
            .connection()
            .execute_batch("ROLLBACK;")
            .expect("release old snapshot");
        reader.close().expect("close reader");
        vault.db.close().expect("restart");
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &key).expect("reopen");
        assert_eq!(
            sweep(&db).expect("recovery")[0].rollforward(),
            Rollforward::Erase
        );
        erase(&mut db, &object_id, 3).expect("erase after restart");
        assert_eq!(
            sweep(&db).expect("sweep")[0].rollforward(),
            Rollforward::Collect
        );
        assert_eq!(
            store::active_envelope(&db, &neighbor_id).expect("neighbor key"),
            neighbor_envelope
        );
        assert_eq!(
            rejection(store::active_envelope(&db, &object_id)),
            ChurStatus::NotFound
        );
        finish(&mut db, &object_id).expect("finish");
        db.close().expect("close");
        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn an_absent_envelope_before_the_wal_barrier_still_requires_erasure() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        vault
            .db
            .connection()
            .execute(
                "DELETE FROM object_key_envelopes WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .expect("simulate interrupted erasure");
        assert_eq!(
            sweep(&vault.db).expect("sweep")[0].rollforward(),
            Rollforward::Erase
        );
        erase(&mut vault.db, &object_id, 3).expect("complete barrier");
        assert_eq!(
            sweep(&vault.db).expect("sweep")[0].rollforward(),
            Rollforward::Collect
        );
    }

    #[test]
    fn corrupt_objects_can_be_erased_without_returning_to_active() {
        let mut vault = vault();
        let (object_id, container) = import(&mut vault);
        let (neighbor, _) = import(&mut vault);
        let neighbor_key = store::active_envelope(&vault.db, &neighbor).expect("neighbor key");
        store::mark_corrupt(&mut vault.db, &object_id).expect("verified corruption");
        assert_eq!(listed(&vault.db), 1);
        begin(&mut vault.db, &object_id).expect("corrupt media can be permanently deleted");
        erase(&mut vault.db, &object_id, 10).expect("destroy corrupt object key");
        assert_eq!(
            sweep(&vault.db).expect("garbage collection")[0].containers,
            vec![container]
        );
        finish(&mut vault.db, &object_id).expect("collect corrupt object");
        assert_eq!(
            rejection(store::active_envelope(&vault.db, &object_id)),
            ChurStatus::NotFound
        );
        assert_eq!(
            rejection(store::object(&vault.db, &object_id)),
            ChurStatus::NotFound
        );
        assert_eq!(
            store::active_envelope(&vault.db, &neighbor).expect("neighbor key"),
            neighbor_key
        );
    }

    #[test]
    fn step_one_stops_the_object_being_listable_and_searchable() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        assert_eq!(listed(&vault.db), 1);
        assert_eq!(searchable(&vault.db), 1);
        begin(&mut vault.db, &object_id).expect("begin");
        assert_eq!(listed(&vault.db), 0);
        assert_eq!(searchable(&vault.db), 0);
        assert_eq!(
            store::object(&vault.db, &object_id).expect("object").state,
            ObjectState::Deleting
        );
    }

    #[test]
    fn step_two_destroys_every_envelope_and_writes_the_tombstone() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        erase(&mut vault.db, &object_id, 4_242).expect("erase");
        assert_eq!(
            rejection(store::active_envelope(&vault.db, &object_id)),
            ChurStatus::NotFound,
            "an envelope survived the erasure moment"
        );
        let authored: i64 = vault
            .db
            .connection()
            .query_row(
                "SELECT authored_ms FROM tombstones WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("tombstone");
        assert_eq!(authored, 4_242);
        assert_eq!(
            store::object(&vault.db, &object_id).expect("object").state,
            ObjectState::Tombstoned
        );
    }

    #[test]
    fn the_whole_sequence_leaves_only_the_tombstone() {
        let mut vault = vault();
        let (object_id, container) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        erase(&mut vault.db, &object_id, 1).expect("erase");
        let pending = sweep(&vault.db).expect("sweep");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].containers, vec![container]);
        assert_eq!(pending[0].rollforward(), Rollforward::Collect);
        finish(&mut vault.db, &object_id).expect("finish");

        assert_eq!(
            rejection(store::object(&vault.db, &object_id)),
            ChurStatus::NotFound
        );
        assert!(sweep(&vault.db).expect("sweep").is_empty());
        let tombstones: i64 = vault
            .db
            .connection()
            .query_row("SELECT count(*) FROM tombstones", [], |row| row.get(0))
            .expect("count");
        assert_eq!(tombstones, 1, "the tombstone was discarded too early");
        for table in [
            "object_streams",
            "metadata_revisions",
            "object_key_envelopes",
            "sync_object_envelope_epochs",
            "derived_assets",
        ] {
            let rows: i64 = vault
                .db
                .connection()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count");
            assert_eq!(rows, 0, "{table} kept a row of a purged object");
        }
    }

    #[test]
    fn recovery_from_step_one_rolls_forward_and_never_back() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        let pending = sweep(&vault.db).expect("sweep");
        assert_eq!(
            pending[0].rollforward(),
            Rollforward::Erase,
            "envelopes are present, so step 2 never committed"
        );
        assert!(!pending[0].erased);
        erase(&mut vault.db, &object_id, 1).expect("run step 2 now");
        assert_eq!(
            sweep(&vault.db).expect("sweep")[0].rollforward(),
            Rollforward::Collect
        );
    }

    #[test]
    fn an_object_whose_envelopes_are_gone_never_returns_to_active() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        erase(&mut vault.db, &object_id, 1).expect("erase");
        // Nothing offers a path back, and the one function that sets ACTIVE is
        // activation, which inserts rather than updates.
        assert_eq!(
            rejection(begin(&mut vault.db, &object_id)),
            ChurStatus::NotFound
        );
        assert_eq!(
            rejection(store::set_favorite(&mut vault.db, &object_id, true, 1)),
            ChurStatus::NotFound
        );
    }

    #[test]
    fn every_garbage_collection_step_is_idempotent() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        erase(&mut vault.db, &object_id, 1).expect("erase");
        erase(&mut vault.db, &object_id, 2).expect("erase again");
        finish(&mut vault.db, &object_id).expect("finish");
        finish(&mut vault.db, &object_id).expect("finish again");
        discard_tombstone(&mut vault.db, &object_id).expect("discard");
        discard_tombstone(&mut vault.db, &object_id).expect("discard again");
        let tombstones: i64 = vault
            .db
            .connection()
            .query_row("SELECT count(*) FROM tombstones", [], |row| row.get(0))
            .expect("count");
        assert_eq!(tombstones, 0);
    }

    #[test]
    fn a_tombstone_is_not_discarded_while_its_object_row_exists() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        begin(&mut vault.db, &object_id).expect("begin");
        erase(&mut vault.db, &object_id, 1).expect("erase");
        assert_eq!(
            rejection(discard_tombstone(&mut vault.db, &object_id)),
            ChurStatus::Conflict
        );
    }

    #[test]
    fn a_sweep_returns_the_derived_containers_before_the_original() {
        let mut vault = vault();
        let (object_id, original) = import(&mut vault);
        let mut thumbnail = store::streams(&vault.db, &object_id).expect("streams")[0].clone();
        thumbnail.stream_id = random::id().expect("id");
        thumbnail.stream_kind = StreamKind::ThumbnailSmall;
        thumbnail.source_content_revision = 1;
        thumbnail.container_path_id = random::id().expect("id");
        let derived = thumbnail.container_path_id;
        store::put_derived_asset(
            &mut vault.db,
            &crate::model::DerivedAsset {
                object_id,
                kind: StreamKind::ThumbnailSmall,
                source_content_revision: 1,
                asset_revision: 1,
                generator_profile: 1,
                stream_id: thumbnail.stream_id,
            },
            &thumbnail,
        )
        .expect("thumbnail");
        begin(&mut vault.db, &object_id).expect("begin");
        let pending = sweep(&vault.db).expect("sweep");
        assert_eq!(
            pending[0].containers,
            vec![derived, original],
            "§14.1 unlinks the derived containers at step 3 and the original at step 4"
        );
    }

    #[test]
    fn a_temporary_container_is_dead_only_without_a_row() {
        let mut vault = vault();
        let (_, container) = import(&mut vault);
        assert!(!is_orphan_temporary(&vault.db, &container).expect("active"));
        assert!(is_orphan_temporary(&vault.db, &random::id().expect("id")).expect("orphan"));

        // A partial download of an object that a receive plan handed out, as
        // the own vault's sync plan does for each object it returns, has no
        // journal record and no stream yet. It stays resumable.
        let pending = random::id().expect("id");
        assert!(is_orphan_temporary(&vault.db, &pending).expect("before the plan"));
        crate::receive_queue::dispatched(&mut vault.db, &vault.collection, &[pending])
            .expect("plan");
        assert!(!is_orphan_temporary(&vault.db, &pending).expect("planned download"));
    }

    #[test]
    fn a_container_with_no_row_and_no_journal_record_is_an_orphan() {
        let mut vault = vault();
        let (_, container) = import(&mut vault);
        assert!(!is_orphan_container(&vault.db, &container).expect("check"));
        let stranger = random::id().expect("id");
        assert!(is_orphan_container(&vault.db, &stranger).expect("check"));

        let mut journal = crate::journal::ImportTransaction {
            transaction_id: random::id().expect("id"),
            temp_path_id: stranger,
            object_id: random::id().expect("id"),
            stream_id: random::id().expect("id"),
            stream_kind: StreamKind::Original,
            stream_revision: 1,
            envelope_generation: 1,
            envelope_body: Some(vec![0u8; 142]),
            nonce_prefix: [0u8; 16],
            chunk_size: 262_144,
            manifest_length: 117,
            reserved_index: None,
            expected_length: None,
            source_seekable: true,
            stage: crate::journal::Stage::Opening,
            opened_ms: 1,
        };
        crate::journal::open(&mut vault.db, &journal).expect("open");
        assert!(
            !is_orphan_container(&vault.db, &stranger).expect("check"),
            "a container an import owns is not an orphan"
        );
        journal.temp_path_id = stranger;
    }

    #[test]
    fn a_deleting_object_is_returned_by_no_query_scope() {
        let mut vault = vault();
        let (object_id, _) = import(&mut vault);
        store::set_favorite(&mut vault.db, &object_id, true, 1).expect("favourite");
        begin(&mut vault.db, &object_id).expect("begin");
        for scope in [Scope::Timeline, Scope::Favorites, Scope::Quarantine] {
            let result = page(
                &vault.db,
                &ObjectQuery {
                    scope,
                    ..ObjectQuery::timeline()
                },
            )
            .expect("page");
            assert!(result.objects.is_empty());
        }
    }
}
