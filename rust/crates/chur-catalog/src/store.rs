//! Reading and writing the catalog entities.
//!
//! Every function here is either one statement or one transaction. The
//! transactions are the atomic boundaries `docs/format/CATALOG_SCHEMA_V1.md`
//! §17 requires by name, and each one says which boundary it is.
//!
//! The policy bounds of §21 are enforced here rather than in the schema. SQLite
//! can express a per-row constraint but not "at most 1000000 objects", and a
//! bound checked in the same transaction as the insert cannot be raced by a
//! second writer, because §8.1 of `docs/interop/FFI_CONTRACT.md` serializes
//! catalog writes behind one mutex per session.

use chur_core::{Id, Result, bail, ensure, err, limits::catalog as limits};
use chur_format::{
    constants::{IntegritySummary, ObjectState, StreamKind},
    envelope::ObjectKeyEnvelope,
};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::HashSet;

use crate::db::{CatalogDb, as_sqlite_integer, from_sqlite_integer, map_sqlite};
use crate::model::{
    Album, Collection, DerivedAsset, ENVELOPE_STATUS_ACTIVE, MetadataRevision, Object, Stream, Tag,
};
use crate::schema::bump_generation;

/// Everything one transaction needs to activate a newly imported object.
///
/// It is one type rather than eight arguments because §17 makes the object
/// commit, its envelope, its stream, and its metadata revision a single atomic
/// boundary: a caller that could pass them separately could also commit them
/// separately.
pub struct ObjectActivation {
    /// The object row.
    pub object: Object,
    /// The original stream.
    pub stream: Stream,
    /// The encoded `ObjectKeyEnvelopeV1` that wraps this object's key.
    pub envelope: Vec<u8>,
    /// The generation of that envelope.
    pub envelope_generation: u64,
    /// The first metadata revision.
    pub metadata: MetadataRevision,
}

/// Inserts the collection every object of a single-vault install belongs to.
///
/// It is idempotent on the collection identifier, so provisioning may run it
/// again after an interrupted first run.
pub fn put_collection(db: &mut CatalogDb, collection: &Collection) -> Result<()> {
    db.transaction(|transaction| put_collection_in(transaction, collection))
}

/// Writes a collection and its first key envelope in one transaction, §4 and §17.
pub fn put_collection_with_envelope(
    db: &mut CatalogDb,
    collection: &Collection,
    envelope_generation: u64,
    envelope: &[u8],
) -> Result<()> {
    db.transaction(|transaction| {
        project_collection_with_envelope(transaction, collection, envelope_generation, envelope)
    })
}

pub(crate) fn project_collection_with_envelope(
    transaction: &Transaction<'_>,
    collection: &Collection,
    envelope_generation: u64,
    envelope: &[u8],
) -> Result<()> {
    let epoch = as_sqlite_integer(
        collection.current_epoch,
        "the collection epoch is too large",
    )?;
    let generation =
        as_sqlite_integer(envelope_generation, "the envelope generation is too large")?;
    put_collection_in(transaction, collection)?;
    let existing = transaction
        .query_row(
            "SELECT body FROM collection_key_envelopes
                  WHERE collection_id = ?1 AND collection_epoch = ?2 AND generation = ?3",
            params![
                collection.collection_id.as_bytes().as_slice(),
                epoch,
                generation,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "a catalog row could not be read"))?;
    if let Some(existing) = existing {
        ensure!(
            existing == envelope,
            Conflict,
            "the collection envelope generation already has another value"
        );
        return Ok(());
    }
    let active: i64 = transaction
        .query_row(
            "SELECT count(*) FROM collection_key_envelopes
                  WHERE collection_id = ?1 AND collection_epoch = ?2 AND status = 1",
            params![collection.collection_id.as_bytes().as_slice(), epoch],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the collection envelopes could not be counted"))?;
    let active = from_sqlite_integer(active, "a catalog count is negative")?;
    ensure!(
        active < u64::from(limits::COLLECTION_ENVELOPES_ACTIVE_MAX),
        ResourceLimitExceeded,
        "the epoch holds the §21 maximum of active collection envelopes"
    );
    transaction
        .execute(
            "INSERT INTO collection_key_envelopes
                     (collection_id, collection_epoch, generation, status, body)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(collection_id, collection_epoch, generation) DO NOTHING",
            params![
                collection.collection_id.as_bytes().as_slice(),
                epoch,
                generation,
                i64::from(ENVELOPE_STATUS_ACTIVE),
                envelope,
            ],
        )
        .map_err(|error| map_sqlite(error, "the collection envelope could not be written"))?;
    Ok(())
}

fn put_collection_in(transaction: &Transaction<'_>, collection: &Collection) -> Result<()> {
    let present = count(transaction, "SELECT count(*) FROM collections")?;
    let already: i64 = transaction
        .query_row(
            "SELECT count(*) FROM collections WHERE collection_id = ?1",
            [collection.collection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the collection could not be read"))?;
    if already == 0 {
        ensure!(
            present < limits::COLLECTIONS_MAX,
            ResourceLimitExceeded,
            "the vault holds the §21 maximum of collections"
        );
    }
    transaction
        .execute(
            "INSERT INTO collections
                 (collection_id, current_epoch, policy_type, created_revision, status)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(collection_id) DO UPDATE SET
                 current_epoch = excluded.current_epoch,
                 status = excluded.status",
            params![
                collection.collection_id.as_bytes().as_slice(),
                as_sqlite_integer(
                    collection.current_epoch,
                    "the collection epoch is too large"
                )?,
                i64::from(collection.policy_type),
                as_sqlite_integer(
                    collection.created_revision,
                    "the collection revision is too large"
                )?,
                i64::from(collection.status),
            ],
        )
        .map_err(|error| map_sqlite(error, "the collection could not be written"))?;
    Ok(())
}

/// The active key envelope of one collection epoch, §4.
pub fn active_collection_envelope(
    db: &CatalogDb,
    collection_id: &Id,
    epoch: u64,
) -> Result<Vec<u8>> {
    db.connection()
        .query_row(
            "SELECT body FROM collection_key_envelopes
              WHERE collection_id = ?1 AND collection_epoch = ?2 AND status = ?3
              ORDER BY generation DESC LIMIT 1",
            params![
                collection_id.as_bytes().as_slice(),
                as_sqlite_integer(epoch, "the collection epoch is too large")?,
                i64::from(ENVELOPE_STATUS_ACTIVE),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| map_sqlite(error, "the collection envelope could not be read"))
}

/// The collection a single-vault install seals every object under, §3.
///
/// It returns `None` rather than failing when the vault has none yet, because
/// a vault created but never imported into is a legitimate state.
pub fn default_collection(db: &CatalogDb) -> Result<Option<Id>> {
    let bytes: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT collection_id FROM collections
              WHERE policy_type = ?1 AND status = ?2
              ORDER BY created_revision, collection_id LIMIT 1",
            params![
                i64::from(crate::model::COLLECTION_POLICY_VAULT_DEFAULT),
                i64::from(crate::model::COLLECTION_STATUS_ACTIVE),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "a catalog row could not be read"))?;
    bytes
        .map(|value| crate::row::id(&value, "the collection id is malformed"))
        .transpose()
}

/// Reads one collection.
pub fn collection(db: &CatalogDb, collection_id: &Id) -> Result<Collection> {
    db.connection()
        .query_row(
            "SELECT current_epoch, policy_type, created_revision, status
               FROM collections WHERE collection_id = ?1",
            [collection_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(|error| map_sqlite(error, "the collection could not be read"))
        .and_then(|(epoch, policy, revision, status)| {
            Ok(Collection {
                collection_id: *collection_id,
                current_epoch: from_sqlite_integer(epoch, "the collection epoch is negative")?,
                policy_type: byte(policy, "the collection policy is out of range")?,
                created_revision: from_sqlite_integer(
                    revision,
                    "the collection revision is negative",
                )?,
                status: byte(status, "the collection status is out of range")?,
            })
        })
}

/// Commits an imported object, its key envelope, its stream, and its first
/// metadata revision in one transaction.
///
/// This is the "object commit plus envelope/catalog activation" boundary of
/// §17. Nothing here touches the filesystem: the container is already renamed
/// into the committed namespace by `docs/format/OBJECT_CONTAINER_V1.md` §14
/// before this runs, so a crash leaves a container with no row, which §14.1 of
/// the catalog specification sweeps.
pub fn activate_object(db: &mut CatalogDb, activation: &ObjectActivation) -> Result<()> {
    check_activation(activation)?;
    db.transaction(|transaction| activate_in(transaction, activation))
}

/// Activates a re-encrypted copy and retires the object it replaces, in one
/// transaction.
///
/// `docs/adr/0069-re-encrypt-objects-after-revocation.md`: the copy has a fresh
/// object key and object identifier. It takes the album memberships and tags
/// of the retired object, its display assets, metadata revisions, import
/// time, extracted text, and Trash state, and the retired object enters step 1
/// of the §14.1 deletion in the same commit. A crash therefore leaves either the old object
/// alone or the new object with a deletion that the unlock sweep rolls
/// forward, never two listable copies.
pub fn activate_replacement(
    db: &mut CatalogDb,
    activation: &ObjectActivation,
    assets: &[(DerivedAsset, Stream)],
    retired: &Id,
    now_ms: u64,
) -> Result<()> {
    check_activation(activation)?;
    ensure!(
        assets
            .iter()
            .all(|(asset, _)| asset.object_id == activation.object.object_id),
        InvalidInput,
        "a display asset names another object"
    );
    let retired = *retired;
    let replacement = activation.object.object_id;
    ensure!(
        retired != replacement,
        InvalidInput,
        "an object cannot replace itself"
    );
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| {
        let (collection, state, import_time, active_revision): (Vec<u8>, i64, i64, i64) =
            transaction
                .query_row(
                    "SELECT collection_id, state, import_time_ms, active_metadata_revision
                       FROM objects WHERE object_id = ?1 AND state IN (?2, ?3)",
                    params![
                        retired.as_bytes().as_slice(),
                        i64::from(ObjectState::Active.value()),
                        i64::from(ObjectState::Trashed.value())
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| map_sqlite(error, "the replaced object could not be read"))?
                .ok_or_else(|| err!(NotFound, "the replaced object is not active or trashed"))?;
        ensure!(
            collection.as_slice() == activation.object.collection_id.as_bytes().as_slice(),
            InvalidInput,
            "a replacement belongs to the collection of the object it replaces"
        );
        activate_in(transaction, activation)?;
        for (asset, stream) in assets {
            put_derived_asset_in(transaction, asset, stream)?;
        }
        let albums = {
            let mut statement = transaction
                .prepare(
                    "SELECT album_id FROM album_memberships WHERE object_id = ?1 ORDER BY album_id",
                )
                .map_err(|error| map_sqlite(error, "album memberships could not be prepared"))?;
            let rows = statement
                .query_map([retired.as_bytes().as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|error| map_sqlite(error, "album memberships could not be read"))?;
            let mut albums = Vec::new();
            for row in rows {
                let bytes = row
                    .map_err(|error| map_sqlite(error, "an album membership could not be read"))?;
                albums.push(crate::row::id(&bytes, "an album id is malformed")?);
            }
            albums
        };
        for album in &albums {
            set_album_membership_in(transaction, album, &replacement, true, now_ms)?;
        }
        transaction
            .execute(
                "INSERT INTO object_tags (tag_id, object_id, capture_time_ms)
                 SELECT t.tag_id, ?2, o.capture_time_ms
                   FROM object_tags t JOIN objects o ON o.object_id = ?2
                  WHERE t.object_id = ?1
                 ON CONFLICT(tag_id, object_id) DO NOTHING",
                params![
                    retired.as_bytes().as_slice(),
                    replacement.as_bytes().as_slice()
                ],
            )
            .map_err(|error| map_sqlite(error, "the tags could not be copied"))?;
        // Every metadata revision, the import time, the extracted text, and
        // the resume position carry over; none is sealed under the object key.
        let new_id = replacement.as_bytes().as_slice();
        let old_id = retired.as_bytes().as_slice();
        for (statement, context) in [
            (
                "DELETE FROM metadata_revisions WHERE object_id = ?2",
                "the first metadata revision could not be replaced",
            ),
            (
                "INSERT INTO metadata_revisions
                     (object_id, revision, active, record, original_filename, caption,
                      content_type, capture_time_ms, width, height, duration_ms)
                 SELECT ?2, revision, active, record, original_filename, caption,
                        content_type, capture_time_ms, width, height, duration_ms
                   FROM metadata_revisions WHERE object_id = ?1",
                "the metadata revisions could not be copied",
            ),
            (
                "INSERT INTO content_index
                     (object_id, primary_stream_id, engine_version, status, body)
                 SELECT ?2, (SELECT primary_stream_id FROM objects WHERE object_id = ?2),
                        engine_version, status, body
                   FROM content_index WHERE object_id = ?1",
                "the extracted text could not be copied",
            ),
            (
                // A resume position binds the object generation and the
                // original's revision; the copy is generation 1 with a first
                // original, and a stale position is not carried.
                "INSERT INTO playback_positions
                     (object_id, object_generation, source_content_revision,
                      position_ms, duration_ms)
                 SELECT ?2, 1, 1, p.position_ms, p.duration_ms
                   FROM playback_positions p
                   JOIN objects o ON o.object_id = p.object_id
                   JOIN object_streams s ON s.stream_id = o.primary_stream_id
                  WHERE p.object_id = ?1
                    AND p.object_generation = o.object_generation
                    AND p.source_content_revision = s.stream_revision
                    AND p.duration_ms = o.duration_ms",
                "the resume position could not be copied",
            ),
        ] {
            transaction
                .execute(statement, params![old_id, new_id])
                .map_err(|error| map_sqlite(error, context))?;
        }
        transaction
            .execute(
                "UPDATE objects SET import_time_ms = ?2, active_metadata_revision = ?3
                  WHERE object_id = ?1",
                params![new_id, import_time, active_revision],
            )
            .map_err(|error| map_sqlite(error, "the import time could not be kept"))?;
        if state == i64::from(ObjectState::Trashed.value()) {
            // A trashed object stays in Trash with its own deadline.
            transaction
                .execute(
                    "INSERT INTO trash_entries (object_id, deleted_ms, expires_ms)
                     SELECT ?2, deleted_ms, expires_ms FROM trash_entries WHERE object_id = ?1",
                    params![old_id, new_id],
                )
                .map_err(|error| map_sqlite(error, "the trash entry could not be copied"))?;
            transaction
                .execute(
                    "UPDATE objects SET state = ?2 WHERE object_id = ?1",
                    params![new_id, i64::from(ObjectState::Trashed.value())],
                )
                .map_err(|error| map_sqlite(error, "the copy could not enter Trash"))?;
            transaction
                .execute(
                    "DELETE FROM object_search WHERE rowid = ?1",
                    [row_key(&replacement)],
                )
                .map_err(|error| map_sqlite(error, "the search row could not be removed"))?;
        } else {
            reindex_search(transaction, &replacement)?;
        }
        crate::deletion::begin_in(transaction, &retired)
    })
}

fn check_activation(activation: &ObjectActivation) -> Result<()> {
    activation.object.check()?;
    activation.stream.check()?;
    activation.metadata.check()?;
    ensure!(
        activation.object.object_id == activation.stream.object_id
            && activation.object.object_id == activation.metadata.object_id,
        InvalidInput,
        "the activation names more than one object"
    );
    ensure!(
        activation.object.primary_stream_id == activation.stream.stream_id,
        InvalidInput,
        "the primary stream is not the stream being activated"
    );
    ensure!(
        activation.stream.stream_kind == StreamKind::Original,
        InvalidInput,
        "an activation commits the original stream"
    );
    ensure!(
        activation.metadata.active,
        InvalidInput,
        "the first metadata revision is the active one"
    );
    Ok(())
}

fn activate_in(transaction: &Transaction<'_>, activation: &ObjectActivation) -> Result<()> {
    {
        let objects = count(transaction, "SELECT count(*) FROM objects")?;
        ensure!(
            objects < limits::OBJECTS_MAX,
            ResourceLimitExceeded,
            "the vault holds the §21 maximum of objects"
        );
        insert_object_row(transaction, &activation.object)?;
        if activation.object.favorite {
            transaction
                .execute(
                    "INSERT INTO favorites(object_id,capture_time_ms,added_ms) VALUES(?1,?2,?3)",
                    params![
                        activation.object.object_id.as_bytes().as_slice(),
                        as_sqlite_integer(
                            activation.object.capture_time_ms,
                            "the favorite time is out of range"
                        )?,
                        as_sqlite_integer(
                            activation.object.import_time_ms,
                            "the import time is out of range"
                        )?
                    ],
                )
                .map_err(|error| {
                    map_sqlite(error, "the favorite projection could not be activated")
                })?;
        }
        insert_stream_row(transaction, &activation.stream)?;
        insert_envelope_row(
            transaction,
            &activation.object.object_id,
            activation.envelope_generation,
            ENVELOPE_STATUS_ACTIVE,
            &activation.envelope,
        )?;
        insert_metadata_row(transaction, &activation.metadata)?;
        reindex_search(transaction, &activation.object.object_id)?;
        crate::object_grants::remove_pending(
            transaction,
            &activation.object.collection_id,
            &activation.object.object_id,
        )?;
        bump_generation(transaction)
    }
}

fn insert_object_row(transaction: &Transaction<'_>, object: &Object) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO objects (
                 object_id, object_generation, collection_id, primary_stream_id, media_kind,
                 capture_time_ms, import_time_ms, capture_time_substituted, plaintext_size,
                 width, height, duration_ms, favorite, state, integrity_summary,
                 thumbnail_ready, active_metadata_revision, search_key
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                object.object_id.as_bytes().as_slice(),
                as_sqlite_integer(
                    object.object_generation,
                    "the object generation is too large"
                )?,
                object.collection_id.as_bytes().as_slice(),
                object.primary_stream_id.as_bytes().as_slice(),
                i64::from(object.media_kind.value()),
                as_sqlite_integer(object.capture_time_ms, "the capture time is out of range")?,
                as_sqlite_integer(object.import_time_ms, "the import time is out of range")?,
                i64::from(object.capture_time_substituted),
                as_sqlite_integer(object.plaintext_size, "the plaintext size is out of range")?,
                i64::from(object.width),
                i64::from(object.height),
                as_sqlite_integer(object.duration_ms, "the duration is out of range")?,
                i64::from(object.favorite),
                i64::from(object.state.value()),
                i64::from(object.integrity_summary.value()),
                i64::from(object.thumbnail_ready),
                i64::from(object.active_metadata_revision),
                row_key(&object.object_id),
            ],
        )
        .map_err(|error| map_sqlite(error, "the object row could not be written"))?;
    Ok(())
}

fn insert_stream_row(transaction: &Transaction<'_>, stream: &Stream) -> Result<()> {
    let streams: u64 = count_with(
        transaction,
        "SELECT count(*) FROM object_streams WHERE object_id = ?1",
        [stream.object_id.as_bytes().as_slice()],
    )?;
    ensure!(
        streams < u64::from(limits::STREAMS_PER_OBJECT_MAX),
        ResourceLimitExceeded,
        "the object holds the §21 maximum of streams"
    );
    transaction
        .execute(
            "INSERT INTO object_streams (
                 stream_id, object_id, stream_kind, stream_revision, source_content_revision,
                 container_path_id, container_version, suite_id, ciphertext_size,
                 plaintext_size, chunk_size, complete_verified_ms, final_commitment
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                stream.stream_id.as_bytes().as_slice(),
                stream.object_id.as_bytes().as_slice(),
                i64::from(stream.stream_kind.value()),
                i64::from(stream.stream_revision),
                i64::from(stream.source_content_revision),
                stream.container_path_id.as_bytes().as_slice(),
                i64::from(stream.container_version),
                i64::from(stream.suite_id),
                as_sqlite_integer(
                    stream.ciphertext_size,
                    "the ciphertext size is out of range"
                )?,
                as_sqlite_integer(stream.plaintext_size, "the plaintext size is out of range")?,
                i64::from(stream.chunk_size),
                stream
                    .complete_verified_ms
                    .map(|value| as_sqlite_integer(value, "the verification time is out of range"))
                    .transpose()?,
                stream.final_commitment.as_slice(),
            ],
        )
        .map_err(|error| map_sqlite(error, "the stream row could not be written"))?;
    Ok(())
}

pub(crate) fn insert_envelope_row(
    transaction: &Transaction<'_>,
    object_id: &Id,
    generation: u64,
    status: u8,
    body: &[u8],
) -> Result<()> {
    let projection = if status == ENVELOPE_STATUS_ACTIVE {
        let envelope = ObjectKeyEnvelope::decode(body)?;
        ensure!(
            envelope.object_id() == object_id && envelope.envelope_generation() == generation,
            InvalidInput,
            "the object envelope contradicts its catalog row"
        );
        let collection_bytes: Vec<u8> = transaction
            .query_row(
                "SELECT collection_id FROM objects WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "the object's collection could not be read"))?;
        let collection_id = crate::row::id(&collection_bytes, "the collection id is malformed")?;
        ensure!(
            envelope.collection_id() == &collection_id,
            InvalidInput,
            "the object envelope names another collection"
        );
        Some((collection_id, envelope.collection_epoch()))
    } else {
        None
    };
    let total: u64 = count_with(
        transaction,
        "SELECT count(*) FROM object_key_envelopes WHERE object_id = ?1",
        [object_id.as_bytes().as_slice()],
    )?;
    ensure!(
        total < u64::from(limits::OBJECT_ENVELOPES_MAX),
        ResourceLimitExceeded,
        "the object holds the §21 maximum of key envelopes"
    );
    if status == ENVELOPE_STATUS_ACTIVE {
        let active: u64 = count_with(
            transaction,
            "SELECT count(*) FROM object_key_envelopes WHERE object_id = ?1 AND status = 1",
            [object_id.as_bytes().as_slice()],
        )?;
        ensure!(
            active < u64::from(limits::OBJECT_ENVELOPES_ACTIVE_MAX),
            ResourceLimitExceeded,
            "the object holds the §21 maximum of active key envelopes"
        );
    }
    transaction
        .execute(
            "INSERT INTO object_key_envelopes (object_id, generation, status, body)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                object_id.as_bytes().as_slice(),
                as_sqlite_integer(generation, "the envelope generation is too large")?,
                i64::from(status),
                body,
            ],
        )
        .map_err(|error| map_sqlite(error, "the key envelope could not be written"))?;
    if let Some((collection_id, collection_epoch)) = projection {
        transaction
            .execute(
                "INSERT INTO sync_object_envelope_epochs
                     (object_id, collection_id, collection_epoch, envelope_generation)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(object_id) DO UPDATE SET
                     collection_id = excluded.collection_id,
                     collection_epoch = excluded.collection_epoch,
                     envelope_generation = excluded.envelope_generation
                   WHERE excluded.envelope_generation
                       > sync_object_envelope_epochs.envelope_generation",
                params![
                    object_id.as_bytes().as_slice(),
                    collection_id.as_bytes().as_slice(),
                    as_sqlite_integer(
                        collection_epoch,
                        "the envelope collection epoch is too large"
                    )?,
                    as_sqlite_integer(generation, "the envelope generation is too large")?,
                ],
            )
            .map_err(|error| map_sqlite(error, "the envelope epoch could not be projected"))?;
    }
    Ok(())
}

fn insert_metadata_row(transaction: &Transaction<'_>, revision: &MetadataRevision) -> Result<()> {
    let present: u64 = count_with(
        transaction,
        "SELECT count(*) FROM metadata_revisions WHERE object_id = ?1",
        [revision.object_id.as_bytes().as_slice()],
    )?;
    ensure!(
        present < u64::from(limits::METADATA_REVISIONS_MAX),
        ResourceLimitExceeded,
        "the object holds the §21 maximum of metadata revisions"
    );
    if revision.active {
        transaction
            .execute(
                "UPDATE metadata_revisions SET active = 0 WHERE object_id = ?1",
                [revision.object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the previous revision could not be retired"))?;
    }
    transaction
        .execute(
            "INSERT INTO metadata_revisions (
                 object_id, revision, active, record, original_filename, caption,
                 content_type, capture_time_ms, width, height, duration_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                revision.object_id.as_bytes().as_slice(),
                i64::from(revision.revision),
                i64::from(revision.active),
                revision.record.as_slice(),
                revision.original_filename.as_deref(),
                revision.caption.as_deref(),
                revision.content_type.as_str(),
                revision
                    .capture_time_ms
                    .map(|value| as_sqlite_integer(value, "the capture time is out of range"))
                    .transpose()?,
                i64::from(revision.width),
                i64::from(revision.height),
                as_sqlite_integer(revision.duration_ms, "the duration is out of range")?,
            ],
        )
        .map_err(|error| map_sqlite(error, "the metadata revision could not be written"))?;
    Ok(())
}

/// Activates a new metadata revision, §17.
///
/// The revision, the object's projection columns, and the search index are
/// rewritten together, which is what §16.3 means by the duplicated
/// `capture_time_ms` not being able to drift and what §16.4 means by an index
/// that never outlives the revision it describes.
pub fn activate_metadata_revision(db: &mut CatalogDb, revision: &MetadataRevision) -> Result<()> {
    revision.check()?;
    ensure!(
        revision.active,
        InvalidInput,
        "an activation writes the active revision"
    );
    let object_id = revision.object_id;
    db.transaction(|transaction| {
        insert_metadata_row(transaction, revision)?;
        let capture = revision
            .capture_time_ms
            .map(|value| as_sqlite_integer(value, "the capture time is out of range"))
            .transpose()?;
        transaction
            .execute(
                "UPDATE objects
                    SET active_metadata_revision = ?2,
                        width = ?3, height = ?4, duration_ms = ?5,
                        capture_time_ms = COALESCE(?6, capture_time_ms),
                        capture_time_substituted = CASE WHEN ?6 IS NULL THEN 1 ELSE 0 END
                  WHERE object_id = ?1",
                params![
                    object_id.as_bytes().as_slice(),
                    i64::from(revision.revision),
                    i64::from(revision.width),
                    i64::from(revision.height),
                    as_sqlite_integer(revision.duration_ms, "the duration is out of range")?,
                    capture,
                ],
            )
            .map_err(|error| map_sqlite(error, "the object projection could not be rewritten"))?;
        // §16.3: the duplicated sort key is rewritten in the same transaction.
        transaction
            .execute(
                "UPDATE album_memberships
                    SET capture_time_ms = (SELECT capture_time_ms FROM objects WHERE object_id = ?1)
                  WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "an album sort key could not be rewritten"))?;
        transaction
            .execute(
                "UPDATE favorites
                    SET capture_time_ms = (SELECT capture_time_ms FROM objects WHERE object_id = ?1)
                  WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "a favourite sort key could not be rewritten"))?;
        transaction
            .execute(
                "UPDATE object_tags
                    SET capture_time_ms = (SELECT capture_time_ms FROM objects WHERE object_id = ?1)
                  WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "a tag sort key could not be rewritten"))?;
        reindex_search(transaction, &object_id)?;
        bump_generation(transaction)
    })
}

/// Records a derived asset and its stream, §10 and §17.
pub fn put_derived_asset(db: &mut CatalogDb, asset: &DerivedAsset, stream: &Stream) -> Result<()> {
    asset.check()?;
    stream.check()?;
    ensure!(
        asset.stream_id == stream.stream_id && asset.object_id == stream.object_id,
        InvalidInput,
        "the asset and its stream name different subjects"
    );
    db.transaction(|transaction| {
        put_derived_asset_in(transaction, asset, stream)?;
        bump_generation(transaction)
    })
}

/// Inserts one derived asset and its stream inside a caller's transaction.
fn put_derived_asset_in(
    transaction: &Transaction<'_>,
    asset: &DerivedAsset,
    stream: &Stream,
) -> Result<()> {
    asset.check()?;
    stream.check()?;
    ensure!(
        asset.stream_id == stream.stream_id && asset.object_id == stream.object_id,
        InvalidInput,
        "the asset and its stream name different subjects"
    );
    let thumbnail = asset.kind == StreamKind::ThumbnailSmall;
    {
        insert_stream_row(transaction, stream)?;
        transaction
            .execute(
                "INSERT INTO derived_assets (
                     object_id, kind, source_content_revision, asset_revision,
                     generator_profile, stream_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(object_id, kind, source_content_revision) DO UPDATE SET
                     asset_revision = excluded.asset_revision,
                     generator_profile = excluded.generator_profile,
                     stream_id = excluded.stream_id",
                params![
                    asset.object_id.as_bytes().as_slice(),
                    i64::from(asset.kind.value()),
                    i64::from(asset.source_content_revision),
                    i64::from(asset.asset_revision),
                    i64::from(asset.generator_profile),
                    asset.stream_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|error| map_sqlite(error, "the derived asset could not be written"))?;
        if thumbnail {
            transaction
                .execute(
                    "UPDATE objects SET thumbnail_ready = 1 WHERE object_id = ?1",
                    [asset.object_id.as_bytes().as_slice()],
                )
                .map_err(|error| map_sqlite(error, "the thumbnail flag could not be set"))?;
        }
        Ok(())
    }
}

/// Sets or clears the favourite flag, §9.
pub fn set_favorite(db: &mut CatalogDb, object_id: &Id, favorite: bool, now_ms: u64) -> Result<()> {
    let added = as_sqlite_integer(now_ms, "the time is out of range")?;
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE objects SET favorite = ?2 WHERE object_id = ?1 AND state = 1",
                params![object_id.as_bytes().as_slice(), i64::from(favorite)],
            )
            .map_err(|error| map_sqlite(error, "the favourite flag could not be set"))?;
        ensure!(changed == 1, NotFound, "no listable object carries that id");
        if favorite {
            transaction
                .execute(
                    "INSERT INTO favorites (object_id, capture_time_ms, added_ms)
                     SELECT object_id, capture_time_ms, ?2 FROM objects WHERE object_id = ?1
                     ON CONFLICT(object_id) DO NOTHING",
                    params![object_id.as_bytes().as_slice(), added],
                )
                .map_err(|error| map_sqlite(error, "the favourite row could not be written"))?;
        } else {
            transaction
                .execute(
                    "DELETE FROM favorites WHERE object_id = ?1",
                    [object_id.as_bytes().as_slice()],
                )
                .map_err(|error| map_sqlite(error, "the favourite row could not be removed"))?;
        }
        bump_generation(transaction)
    })
}

/// Changes the favourite state of a selection as one catalog operation.
pub fn set_favorites(
    db: &mut CatalogDb,
    object_ids: &[Id],
    favorite: bool,
    now_ms: u64,
) -> Result<()> {
    ensure!(
        !object_ids.is_empty() && object_ids.len() as u64 <= limits::OBJECTS_MAX,
        InvalidInput,
        "the selection size is outside the object bound"
    );
    let mut distinct = HashSet::with_capacity(object_ids.len());
    ensure!(
        object_ids.iter().all(|id| distinct.insert(*id)),
        InvalidInput,
        "the selection repeats an object"
    );
    let added = as_sqlite_integer(now_ms, "the time is out of range")?;
    db.transaction(|transaction| {
        for id in object_ids {
            ensure!(
                count_with(
                    transaction,
                    "SELECT count(*) FROM objects WHERE object_id = ?1 AND state = 1",
                    [id.as_bytes().as_slice()]
                )? == 1,
                NotFound,
                "the selection contains no listable object"
            );
        }
        for id in object_ids {
            transaction
                .execute(
                    "UPDATE objects SET favorite = ?2 WHERE object_id = ?1",
                    params![id.as_bytes().as_slice(), i64::from(favorite)],
                )
                .map_err(|error| map_sqlite(error, "the favourite flag could not be set"))?;
            if favorite {
                transaction
                    .execute(
                        "INSERT INTO favorites (object_id, capture_time_ms, added_ms)
                     SELECT object_id, capture_time_ms, ?2 FROM objects WHERE object_id = ?1
                     ON CONFLICT(object_id) DO NOTHING",
                        params![id.as_bytes().as_slice(), added],
                    )
                    .map_err(|error| map_sqlite(error, "the favourite row could not be written"))?;
            } else {
                transaction
                    .execute(
                        "DELETE FROM favorites WHERE object_id = ?1",
                        [id.as_bytes().as_slice()],
                    )
                    .map_err(|error| map_sqlite(error, "the favourite row could not be removed"))?;
            }
        }
        bump_generation(transaction)
    })
}

/// Records a verification verdict, §5.1 and §13.
///
/// Proven corruption is a lifecycle change rather than a verdict, so it is
/// [`mark_corrupt`] and not a value this function accepts.
pub fn set_integrity_summary(
    db: &mut CatalogDb,
    object_id: &Id,
    summary: IntegritySummary,
    now_ms: u64,
) -> Result<()> {
    let checked = as_sqlite_integer(now_ms, "the time is out of range")?;
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE objects SET integrity_summary = ?2 WHERE object_id = ?1 AND state = 1",
                params![object_id.as_bytes().as_slice(), i64::from(summary.value())],
            )
            .map_err(|error| map_sqlite(error, "the integrity summary could not be set"))?;
        ensure!(changed == 1, NotFound, "no active object carries that id");
        if summary == IntegritySummary::CompleteVerified {
            transaction
                .execute(
                    "UPDATE object_streams SET complete_verified_ms = ?2 WHERE object_id = ?1",
                    params![object_id.as_bytes().as_slice(), checked],
                )
                .map_err(|error| map_sqlite(error, "the verification time could not be set"))?;
        }
        bump_generation(transaction)
    })
}

/// Moves an object to the terminal `CORRUPT` lifecycle state, §5.1.
///
/// The transition is one-way and this is the only function that performs it.
pub fn mark_corrupt(db: &mut CatalogDb, object_id: &Id) -> Result<()> {
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE objects SET state = ?2, integrity_summary = ?3
                  WHERE object_id = ?1 AND state = ?4",
                params![
                    object_id.as_bytes().as_slice(),
                    i64::from(ObjectState::Corrupt.value()),
                    i64::from(IntegritySummary::Unverified.value()),
                    i64::from(ObjectState::Active.value()),
                ],
            )
            .map_err(|error| map_sqlite(error, "the object could not be marked corrupt"))?;
        ensure!(changed == 1, NotFound, "no active object carries that id");
        bump_generation(transaction)
    })
}

/// Whether the catalog already holds the object row.
///
/// §14.4 reconciliation reads this before it treats an open journal record as
/// dead: a process that died between the activation and the journal close
/// left a finished import behind, and abandoning that record would destroy
/// the container of an object the catalog has already activated.
pub fn object_present(db: &CatalogDb, object_id: &Id) -> Result<bool> {
    let present: Option<i64> = db
        .connection()
        .query_row(
            "SELECT 1 FROM objects WHERE object_id = ?1",
            [object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "the object row could not be read"))?;
    Ok(present.is_some())
}

/// Whether an import identity is committed, permanently deleted, or reserved by a live import.
pub fn object_id_reserved(db: &CatalogDb, object_id: &Id) -> Result<bool> {
    db.connection()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM objects WHERE object_id = ?1)
                 OR EXISTS(SELECT 1 FROM tombstones WHERE object_id = ?1)
                 OR EXISTS(SELECT 1 FROM import_transactions WHERE object_id = ?1 AND stage <> 4)",
            [object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the import identity could not be checked"))
}

/// Lists original objects for verification, including quarantined and known corrupt rows.
/// Trashed and deleted objects are outside the active-library integrity scan.
pub fn integrity_scan_targets(db: &CatalogDb) -> Result<Vec<Id>> {
    let mut statement = db
        .connection()
        .prepare("SELECT object_id FROM objects WHERE state IN (?1, ?2) ORDER BY object_id")
        .map_err(|e| map_sqlite(e, "the integrity inventory could not be prepared"))?;
    let rows = statement
        .query_map(
            [ObjectState::Active.value(), ObjectState::Corrupt.value()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| map_sqlite(e, "the integrity inventory could not be read"))?;
    rows.map(|row| {
        let bytes = row.map_err(|e| map_sqlite(e, "the integrity object could not be read"))?;
        crate::row::id(&bytes, "the integrity object ID is malformed")
    })
    .collect()
}

/// Reads one object row.
pub fn object(db: &CatalogDb, object_id: &Id) -> Result<Object> {
    db.connection()
        .query_row(
            "SELECT object_generation, collection_id, primary_stream_id, media_kind,
                    capture_time_ms, import_time_ms, capture_time_substituted, plaintext_size,
                    width, height, duration_ms, favorite, state, integrity_summary,
                    thumbnail_ready, active_metadata_revision
               FROM objects WHERE object_id = ?1",
            [object_id.as_bytes().as_slice()],
            |row| crate::row::object(object_id, row),
        )
        .map_err(|error| map_sqlite(error, "the object could not be read"))?
}

/// Reads the streams of one object, in kind order.
pub fn streams(db: &CatalogDb, object_id: &Id) -> Result<Vec<Stream>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare(
            "SELECT stream_id, stream_kind, stream_revision, source_content_revision,
                    container_path_id, container_version, suite_id, ciphertext_size,
                    plaintext_size, chunk_size, complete_verified_ms, final_commitment
               FROM object_streams WHERE object_id = ?1 ORDER BY stream_kind",
        )
        .map_err(|error| map_sqlite(error, "the stream query could not be prepared"))?;
    let rows = statement
        .query_map([object_id.as_bytes().as_slice()], |row| {
            crate::row::stream(object_id, row)
        })
        .map_err(|error| map_sqlite(error, "the streams could not be read"))?;
    let mut streams = Vec::new();
    for row in rows {
        streams.push(row.map_err(|error| map_sqlite(error, "a stream row could not be read"))??);
    }
    Ok(streams)
}

/// Visits every stream of the vault in the total order of
/// `docs/format/BACKUP_FORMAT_V1.md` §7.1.
///
/// The order is ascending `object_id`, then ascending `stream_id`, then
/// ascending `stream_revision`. Those three keys are unique together, so the
/// order is total and two conforming writers that back up the same content emit
/// the same sequence.
///
/// It visits rather than collects. A vault holds up to a million objects under
/// `docs/format/CATALOG_SCHEMA_V1.md` §21, and a vector of that many stream rows
/// is hundreds of megabytes: a backup that materialized its own inventory would
/// scale memory with the vault, which is what
/// `docs/assurance/PERFORMANCE_BUDGETS.md` §4 forbids.
pub fn for_each_stream_ordered(
    db: &CatalogDb,
    mut visit: impl FnMut(&Id, &Stream) -> Result<()>,
) -> Result<()> {
    let connection = db.connection();
    // The stream columns keep the order `row::stream` reads, and `object_id`
    // follows them, so one mapper serves this walk and the per-object query.
    let mut statement = connection
        .prepare(
            "SELECT stream_id, stream_kind, stream_revision, source_content_revision,
                    container_path_id, container_version, suite_id, ciphertext_size,
                    plaintext_size, chunk_size, complete_verified_ms, final_commitment,
                    object_id
               FROM object_streams ORDER BY object_id, stream_id, stream_revision",
        )
        .map_err(|error| map_sqlite(error, "the stream walk could not be prepared"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite(error, "the streams could not be walked"))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "a stream row could not be read"))?
    {
        let object_bytes: Vec<u8> = row
            .get(12)
            .map_err(|error| map_sqlite(error, "a stream row carried no object"))?;
        let object_id = crate::row::id(&object_bytes, "a stream row's object id is malformed")?;
        let stream = crate::row::stream(&object_id, row)
            .map_err(|error| map_sqlite(error, "a stream row could not be read"))??;
        visit(&object_id, &stream)?;
    }
    Ok(())
}

/// Reads the active key envelope of one object, §7.
pub fn active_envelope(db: &CatalogDb, object_id: &Id) -> Result<Vec<u8>> {
    db.connection()
        .query_row(
            "SELECT body FROM object_key_envelopes
              WHERE object_id = ?1 AND status = ?2
              ORDER BY generation DESC LIMIT 1",
            params![
                object_id.as_bytes().as_slice(),
                i64::from(ENVELOPE_STATUS_ACTIVE)
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| map_sqlite(error, "the object key envelope could not be read"))
}

/// Reads the active metadata revision of one object, §8.
pub fn active_metadata(db: &CatalogDb, object_id: &Id) -> Result<MetadataRevision> {
    db.connection()
        .query_row(
            "SELECT revision, record, original_filename, caption, content_type,
                    capture_time_ms, width, height, duration_ms
               FROM metadata_revisions WHERE object_id = ?1 AND active = 1",
            [object_id.as_bytes().as_slice()],
            |row| crate::row::metadata(object_id, row),
        )
        .map_err(|error| map_sqlite(error, "the metadata revision could not be read"))?
}

/// Creates an album, §9.
pub fn put_album(db: &mut CatalogDb, album: &Album) -> Result<()> {
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| put_album_in(transaction, album))
}

pub(crate) fn put_album_in(transaction: &Transaction<'_>, album: &Album) -> Result<()> {
    album.check()?;
    let created = as_sqlite_integer(album.created_ms, "the time is out of range")?;
    let revision = as_sqlite_integer(album.revision, "the revision is too large")?;
    let present = count(transaction, "SELECT count(*) FROM albums")?;
    let already: i64 = transaction
        .query_row(
            "SELECT count(*) FROM albums WHERE album_id = ?1",
            [album.album_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the album could not be read"))?;
    if already == 0 {
        ensure!(
            present < limits::ALBUMS_MAX,
            ResourceLimitExceeded,
            "the vault holds the §21 maximum of albums"
        );
    }
    transaction
        .execute(
            "INSERT INTO albums (album_id, name, created_ms, revision, sort_position)
             VALUES (?1, ?2, ?3, ?4,
                 (SELECT coalesce(max(sort_position) + 1, 0) FROM albums
                   WHERE parent_album_id IS NULL))
             ON CONFLICT(album_id) DO UPDATE SET
                 name = excluded.name, revision = excluded.revision",
            params![
                album.album_id.as_bytes().as_slice(),
                album.name.as_str(),
                created,
                revision,
            ],
        )
        .map_err(|error| map_sqlite(error, "the album could not be written"))?;
    bump_generation(transaction)
}

/// One logical album with its user-controlled place in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumListing {
    /// Stable logical album.
    pub album: Album,
    /// Number of live media objects directly in this album.
    pub member_count: u64,
    /// Parent, absent at the root.
    pub parent_id: Option<Id>,
    /// Order among siblings.
    pub position: u64,
}

/// The name of one existing album, without enumerating the entire library.
pub fn album_name(db: &CatalogDb, album_id: &Id) -> Result<Option<String>> {
    db.connection()
        .query_row(
            "SELECT name FROM albums WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "the album name could not be read"))
}

/// Every album, with its membership count and tree position, §9.
pub fn albums(db: &CatalogDb) -> Result<Vec<AlbumListing>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare(
            "SELECT a.album_id, a.name, a.created_ms, a.revision,
                    (SELECT count(*) FROM album_memberships m
                      JOIN objects o ON o.object_id = m.object_id
                     WHERE m.album_id = a.album_id AND o.state = 1
                       AND o.integrity_summary <> ?1)
                    , a.parent_album_id, a.sort_position
               FROM albums a ORDER BY a.parent_album_id, a.sort_position, a.album_id",
        )
        .map_err(|error| map_sqlite(error, "the album query could not be prepared"))?;
    let rows = statement
        .query_map([i64::from(IntegritySummary::Quarantined.value())], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "the albums could not be read"))?;
    let mut albums = Vec::new();
    for row in rows {
        let (id, name, created, revision, members, parent, position) =
            row.map_err(|error| map_sqlite(error, "an album row could not be read"))?;
        albums.push(AlbumListing {
            album: Album {
                album_id: crate::row::id(&id, "the album id is malformed")?,
                name,
                created_ms: from_sqlite_integer(created, "the album time is negative")?,
                revision: from_sqlite_integer(revision, "the album revision is negative")?,
            },
            member_count: from_sqlite_integer(members, "an album count is negative")?,
            parent_id: parent
                .map(|id| crate::row::id(&id, "the parent id is malformed"))
                .transpose()?,
            position: from_sqlite_integer(position, "the album position is negative")?,
        });
    }
    Ok(albums)
}

/// Every tag in name order, for the private picker.
pub fn tags(db: &CatalogDb) -> Result<Vec<Tag>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare("SELECT tag_id, name, created_ms FROM tags ORDER BY name, tag_id")
        .map_err(|error| map_sqlite(error, "the tag query could not be prepared"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "the tags could not be read"))?;
    let mut tags = Vec::new();
    for row in rows {
        let (id, name, created) =
            row.map_err(|error| map_sqlite(error, "a tag row could not be read"))?;
        tags.push(Tag {
            tag_id: crate::row::id(&id, "the tag id is malformed")?,
            name,
            created_ms: from_sqlite_integer(created, "the tag time is negative")?,
        });
    }
    Ok(tags)
}

/// The tags on one object, in name order, §9.
pub fn object_tags(db: &CatalogDb, object_id: &Id) -> Result<Vec<Tag>> {
    let connection = db.connection();
    let mut statement = connection
        .prepare(
            "SELECT t.tag_id, t.name, t.created_ms
               FROM object_tags o JOIN tags t ON t.tag_id = o.tag_id
              WHERE o.object_id = ?1 ORDER BY t.name, t.tag_id",
        )
        .map_err(|error| map_sqlite(error, "the tag query could not be prepared"))?;
    let rows = statement
        .query_map([object_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "the tags could not be read"))?;
    let mut tags = Vec::new();
    for row in rows {
        let (id, name, created) =
            row.map_err(|error| map_sqlite(error, "a tag row could not be read"))?;
        tags.push(Tag {
            tag_id: crate::row::id(&id, "the tag id is malformed")?,
            name,
            created_ms: from_sqlite_integer(created, "the tag time is negative")?,
        });
    }
    Ok(tags)
}

fn mark_pending_album_add(transaction: &Transaction<'_>, album: &Id, object: &Id) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO own_sync_pending_album_memberships (album_id, object_id)
        VALUES (?1, ?2) ON CONFLICT(album_id, object_id) DO NOTHING",
            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "pending album membership could not be written"))?;
    Ok(())
}

pub(crate) fn clear_pending_album_add(
    transaction: &Transaction<'_>,
    album: &Id,
    object: &Id,
) -> Result<()> {
    transaction
        .execute(
            "DELETE FROM own_sync_pending_album_memberships WHERE album_id = ?1 AND object_id = ?2",
            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "pending album membership could not be cleared"))?;
    Ok(())
}

/// Adds or removes an album membership, §9.
pub fn set_album_membership(
    db: &mut CatalogDb,
    album_id: &Id,
    object_id: &Id,
    member: bool,
    now_ms: u64,
) -> Result<()> {
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| {
        set_album_membership_in(transaction, album_id, object_id, member, now_ms)
    })
}

pub(crate) fn set_album_membership_in(
    transaction: &Transaction<'_>,
    album_id: &Id,
    object_id: &Id,
    member: bool,
    now_ms: u64,
) -> Result<()> {
    let added = as_sqlite_integer(now_ms, "the time is out of range")?;
    if member {
        let present: u64 = count_with(
            transaction,
            "SELECT count(*) FROM album_memberships WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
        )?;
        let already = count_with(
            transaction,
            "SELECT count(*) FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
            [
                album_id.as_bytes().as_slice(),
                object_id.as_bytes().as_slice(),
            ],
        )?;
        ensure!(
            already == 1 || present < limits::ALBUM_MEMBERSHIPS_MAX,
            ResourceLimitExceeded,
            "the album holds the §21 maximum of memberships"
        );
        let changed = transaction
            .execute(
                "INSERT INTO album_memberships
                     (album_id, object_id, capture_time_ms, added_ms, revision, sort_position)
                 SELECT ?1, object_id, capture_time_ms, ?3, 1,
                     (SELECT coalesce(max(sort_position) + 1, 0)
                        FROM album_memberships WHERE album_id = ?1)
                   FROM objects WHERE object_id = ?2 AND state = 1
                 ON CONFLICT(album_id, object_id) DO NOTHING",
                params![
                    album_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                    added,
                ],
            )
            .map_err(|error| map_sqlite(error, "the membership could not be written"))?;
        if changed == 1 {
            mark_pending_album_add(transaction, album_id, object_id)?;
        }
        ensure!(
            changed == 1
                || count_with::<_, [&[u8]; 2]>(
                    transaction,
                    "SELECT count(*) FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
                    [
                        album_id.as_bytes().as_slice(),
                        object_id.as_bytes().as_slice()
                    ],
                )? == 1,
            NotFound,
            "no listable object carries that id"
        );
    } else {
        clear_pending_album_add(transaction, album_id, object_id)?;
        transaction
            .execute(
                "DELETE FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
                params![
                    album_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice()
                ],
            )
            .map_err(|error| map_sqlite(error, "the membership could not be removed"))?;
    }
    transaction
        .execute(
            "UPDATE albums SET revision = revision + 1 WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "the album revision could not advance"))?;
    bump_generation(transaction)
}

/// Removes a selection from one album in one catalog transaction.
/// The objects and their other album memberships stay in the catalog.
///
/// # Errors
///
/// Returns `InvalidInput` for an empty, repeated, or oversized selection,
/// `NotFound` for an absent album, or `Conflict` for a stale membership.
/// Database failures roll back the complete selection.
pub fn remove_album_members(db: &mut CatalogDb, album_id: &Id, object_ids: &[Id]) -> Result<()> {
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| remove_album_members_in(transaction, album_id, object_ids))
}

pub(crate) fn remove_album_members_in(
    transaction: &Transaction<'_>,
    album_id: &Id,
    object_ids: &[Id],
) -> Result<()> {
    ensure!(
        !object_ids.is_empty() && object_ids.len() as u64 <= limits::ALBUM_MEMBERSHIPS_MAX,
        InvalidInput,
        "the selection size is outside the album bound"
    );
    let mut distinct = HashSet::with_capacity(object_ids.len());
    ensure!(
        object_ids.iter().all(|id| distinct.insert(*id)),
        InvalidInput,
        "the selection repeats an object"
    );
    ensure!(
        count_with(
            transaction,
            "SELECT count(*) FROM albums WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()]
        )? == 1,
        NotFound,
        "the source album does not exist"
    );
    for object_id in object_ids {
        clear_pending_album_add(transaction, album_id, object_id)?;
        let changed = transaction
            .execute(
                "DELETE FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
                params![
                    album_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice()
                ],
            )
            .map_err(|error| map_sqlite(error, "the selected membership could not be removed"))?;
        ensure!(
            changed == 1,
            Conflict,
            "the selection is no longer in the source album"
        );
    }
    transaction
        .execute(
            "UPDATE albums SET revision = revision + 1 WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "the source album revision could not advance"))?;
    bump_generation(transaction)
}

/// Destination for one atomic selection placement.
pub enum AlbumDestination<'a> {
    /// Use an existing album.
    Existing(&'a Id),
    /// Create a new album under the optional parent before placing the objects.
    New(&'a Album, Option<&'a Id>),
}

/// Adds a selection to an album, or moves it from one album, in one catalog transaction.
/// Creating the destination is part of the same transaction.
pub fn place_album_members(
    db: &mut CatalogDb,
    destination: AlbumDestination<'_>,
    source: Option<&Id>,
    object_ids: &[Id],
    move_members: bool,
    now_ms: u64,
) -> Result<Id> {
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| {
        place_album_members_in(
            transaction,
            destination,
            source,
            object_ids,
            move_members,
            now_ms,
        )
    })
}

pub(crate) fn place_album_members_in(
    transaction: &Transaction<'_>,
    destination: AlbumDestination<'_>,
    source: Option<&Id>,
    object_ids: &[Id],
    move_members: bool,
    now_ms: u64,
) -> Result<Id> {
    ensure!(
        !object_ids.is_empty() && object_ids.len() as u64 <= limits::ALBUM_MEMBERSHIPS_MAX,
        InvalidInput,
        "the selection size is outside the album bound"
    );
    ensure!(
        !move_members || source.is_some(),
        InvalidInput,
        "a move needs a source album"
    );
    let moving_source = if move_members { source } else { None };
    let mut distinct = HashSet::with_capacity(object_ids.len());
    ensure!(
        object_ids.iter().all(|id| distinct.insert(*id)),
        InvalidInput,
        "the selection repeats an object"
    );
    if let AlbumDestination::New(album, _) = &destination {
        album.check()?;
    }
    let added = as_sqlite_integer(now_ms, "the time is out of range")?;
    let target = match destination {
        AlbumDestination::Existing(id) => {
            ensure!(
                count_with(
                    transaction,
                    "SELECT count(*) FROM albums WHERE album_id = ?1",
                    [id.as_bytes().as_slice()]
                )? == 1,
                NotFound,
                "the target album does not exist"
            );
            *id
        }
        AlbumDestination::New(album, parent) => {
            ensure!(
                count(transaction, "SELECT count(*) FROM albums")? < limits::ALBUMS_MAX,
                ResourceLimitExceeded,
                "the vault holds the maximum of albums"
            );
            if let Some(parent) = parent {
                ensure!(
                    count_with(
                        transaction,
                        "SELECT count(*) FROM albums WHERE album_id = ?1",
                        [parent.as_bytes().as_slice()]
                    )? == 1,
                    NotFound,
                    "the parent album does not exist"
                );
            }
            transaction.execute(
                "INSERT INTO albums (album_id, name, created_ms, revision, parent_album_id, sort_position)
                 VALUES (?1, ?2, ?3, ?4, ?5,
                   (SELECT coalesce(max(sort_position) + 1, 0) FROM albums WHERE parent_album_id IS ?5))",
                params![
                    album.album_id.as_bytes().as_slice(), album.name.as_str(),
                    as_sqlite_integer(album.created_ms, "the creation time is out of range")?,
                    as_sqlite_integer(album.revision, "the revision is out of range")?,
                    parent.map(|id| id.as_bytes().as_slice()),
                ],
            ).map_err(|error| map_sqlite(error, "the target album could not be created"))?;
            album.album_id
        }
    };
    if let Some(source) = moving_source {
        ensure!(
            count_with(
                transaction,
                "SELECT count(*) FROM albums WHERE album_id = ?1",
                [source.as_bytes().as_slice()]
            )? == 1,
            NotFound,
            "the source album does not exist"
        );
    }
    let mut missing = 0u64;
    for id in object_ids {
        ensure!(
            count_with(
                transaction,
                "SELECT count(*) FROM objects WHERE object_id = ?1 AND state = 1",
                [id.as_bytes().as_slice()]
            )? == 1,
            NotFound,
            "the selection contains no listable object"
        );
        if let Some(source) = moving_source {
            ensure!(
                count_with(
                    transaction,
                    "SELECT count(*) FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
                    [source.as_bytes().as_slice(), id.as_bytes().as_slice()]
                )? == 1,
                Conflict,
                "the selection is no longer in the source album"
            );
        }
        if count_with(
            transaction,
            "SELECT count(*) FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
            [target.as_bytes().as_slice(), id.as_bytes().as_slice()],
        )? == 0
        {
            missing += 1;
        }
    }
    let present = count_with(
        transaction,
        "SELECT count(*) FROM album_memberships WHERE album_id = ?1",
        [target.as_bytes().as_slice()],
    )?;
    ensure!(
        present + missing <= limits::ALBUM_MEMBERSHIPS_MAX,
        ResourceLimitExceeded,
        "the target album would exceed its membership bound"
    );
    for id in object_ids {
        let changed = transaction
            .execute(
                "INSERT INTO album_memberships
                (album_id, object_id, capture_time_ms, added_ms, revision, sort_position)
             SELECT ?1, object_id, capture_time_ms, ?3, 1,
                (SELECT coalesce(max(sort_position) + 1, 0)
                 FROM album_memberships WHERE album_id = ?1)
               FROM objects WHERE object_id = ?2 AND state = 1
             ON CONFLICT(album_id, object_id) DO NOTHING",
                params![
                    target.as_bytes().as_slice(),
                    id.as_bytes().as_slice(),
                    added
                ],
            )
            .map_err(|error| map_sqlite(error, "the selected object could not be placed"))?;
        if changed == 1 {
            mark_pending_album_add(transaction, &target, id)?;
        }
    }
    if let Some(source) = moving_source
        && *source != target
    {
        for id in object_ids {
            clear_pending_album_add(transaction, source, id)?;
            transaction
                .execute(
                    "DELETE FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
                    params![source.as_bytes().as_slice(), id.as_bytes().as_slice()],
                )
                .map_err(|error| map_sqlite(error, "the source membership could not be removed"))?;
        }
        transaction
            .execute(
                "UPDATE albums SET revision = revision + 1 WHERE album_id = ?1",
                [source.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the source album revision could not advance"))?;
    }
    transaction
        .execute(
            "UPDATE albums SET revision = revision + 1 WHERE album_id = ?1",
            [target.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "the target album revision could not advance"))?;
    bump_generation(transaction)?;
    Ok(target)
}

/// Changes only an album's label; its identifier, descendants, and members stay put.
pub fn rename_album(db: &mut CatalogDb, album_id: &Id, name: &str) -> Result<()> {
    crate::own_sync::mark_albums_dirty(db);
    db.transaction(|transaction| rename_album_in(transaction, album_id, name))
}

pub(crate) fn rename_album_in(
    transaction: &Transaction<'_>,
    album_id: &Id,
    name: &str,
) -> Result<()> {
    Album {
        album_id: *album_id,
        name: name.to_owned(),
        created_ms: 0,
        revision: 1,
    }
    .check()?;
    let changed = transaction
        .execute(
            "UPDATE albums SET name = ?2, revision = revision + 1 WHERE album_id = ?1",
            params![album_id.as_bytes().as_slice(), name],
        )
        .map_err(|error| map_sqlite(error, "the album could not be renamed"))?;
    ensure!(changed == 1, NotFound, "no album carries that id");
    bump_generation(transaction)
}

/// Deletes a subtree of logical albums, retaining every media object.
pub fn delete_album(db: &mut CatalogDb, album_id: &Id) -> Result<()> {
    db.transaction(|transaction| {
        let present = count_with(
            transaction,
            "SELECT count(*) FROM albums WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
        )?;
        ensure!(present == 1, NotFound, "no album carries that id");
        for table in ["album_memberships", "albums"] {
            let sql = format!(
                "WITH RECURSIVE subtree(id) AS (
                    SELECT album_id FROM albums WHERE album_id = ?1
                    UNION ALL
                    SELECT a.album_id FROM albums a JOIN subtree s ON a.parent_album_id = s.id
                 ) DELETE FROM {table} WHERE album_id IN (SELECT id FROM subtree)",
            );
            transaction
                .execute(&sql, [album_id.as_bytes().as_slice()])
                .map_err(|error| map_sqlite(error, "the album subtree could not be removed"))?;
        }
        bump_generation(transaction)
    })
}

/// Moves an album to a parent and a place before one of that parent's children.
/// A missing `before` appends it. Cycles and cross-parent targets are refused.
pub fn move_album(
    db: &mut CatalogDb,
    album_id: &Id,
    parent_id: Option<&Id>,
    before: Option<&Id>,
) -> Result<()> {
    ensure!(
        before != Some(album_id),
        InvalidInput,
        "an album cannot precede itself"
    );
    ensure!(
        parent_id != Some(album_id),
        InvalidInput,
        "an album cannot contain itself"
    );
    db.transaction(|transaction| {
        let present = count_with(
            transaction,
            "SELECT count(*) FROM albums WHERE album_id = ?1",
            [album_id.as_bytes().as_slice()],
        )?;
        ensure!(present == 1, NotFound, "no album carries that id");
        if let Some(parent) = parent_id {
            let mut cursor = Some(*parent);
            for _ in 0..=limits::ALBUMS_MAX {
                let Some(id) = cursor else { break };
                ensure!(
                    id != *album_id,
                    InvalidInput,
                    "the move would create an album cycle"
                );
                let row: Option<Option<Vec<u8>>> = transaction
                    .query_row(
                        "SELECT parent_album_id FROM albums WHERE album_id = ?1",
                        [id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| map_sqlite(error, "the parent could not be read"))?;
                let Some(next) = row else {
                    bail!(NotFound, "no parent album carries that id")
                };
                cursor = next
                    .map(|bytes| crate::row::id(&bytes, "the parent id is malformed"))
                    .transpose()?;
            }
            ensure!(
                cursor.is_none(),
                CatalogCorrupt,
                "the album hierarchy contains a cycle"
            );
        }
        let parent_bytes = parent_id.map(|id| id.as_bytes().to_vec());
        let mut siblings = Vec::new();
        let mut statement = transaction
            .prepare(
                "SELECT album_id FROM albums WHERE parent_album_id IS ?1
             AND album_id <> ?2 ORDER BY sort_position, album_id",
            )
            .map_err(|error| map_sqlite(error, "the sibling query could not be prepared"))?;
        let rows = statement
            .query_map(
                params![parent_bytes, album_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|error| map_sqlite(error, "the siblings could not be read"))?;
        for row in rows {
            siblings.push(crate::row::id(
                &row.map_err(|error| map_sqlite(error, "a sibling row is malformed"))?,
                "the sibling id is malformed",
            )?);
        }
        drop(statement);
        let at = match before {
            Some(id) => siblings
                .iter()
                .position(|candidate| candidate == id)
                .ok_or_else(|| chur_core::err!(InvalidInput, "the target is not a sibling"))?,
            None => siblings.len(),
        };
        siblings.insert(at, *album_id);
        for (index, id) in siblings.iter().enumerate() {
            transaction
                .execute(
                    "UPDATE albums SET parent_album_id = ?2, sort_position = ?3,
                    revision = revision + 1 WHERE album_id = ?1",
                    params![
                        id.as_bytes().as_slice(),
                        parent_id.map(|id| id.as_bytes().as_slice()),
                        as_sqlite_integer(index as u64, "the position is out of range")?
                    ],
                )
                .map_err(|error| map_sqlite(error, "the album position could not be written"))?;
        }
        bump_generation(transaction)
    })
}

/// Reorders a member inside one album without changing its membership.
pub fn move_album_member(
    db: &mut CatalogDb,
    album_id: &Id,
    object_id: &Id,
    before: Option<&Id>,
) -> Result<()> {
    db.transaction(|transaction| {
        let mut members = Vec::new();
        let mut statement = transaction
            .prepare(
                "SELECT object_id FROM album_memberships WHERE album_id = ?1
             ORDER BY sort_position, object_id",
            )
            .map_err(|error| map_sqlite(error, "the album order could not be prepared"))?;
        let rows = statement
            .query_map([album_id.as_bytes().as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|error| map_sqlite(error, "the album order could not be read"))?;
        for row in rows {
            members.push(crate::row::id(
                &row.map_err(|error| map_sqlite(error, "a membership row is malformed"))?,
                "the member id is malformed",
            )?);
        }
        drop(statement);
        let old = members
            .iter()
            .position(|id| id == object_id)
            .ok_or_else(|| chur_core::err!(NotFound, "the object is not in this album"))?;
        members.remove(old);
        let at = match before {
            Some(id) if id == object_id => old.min(members.len()),
            Some(id) => members
                .iter()
                .position(|candidate| candidate == id)
                .ok_or_else(|| chur_core::err!(InvalidInput, "the target is not in this album"))?,
            None => members.len(),
        };
        members.insert(at, *object_id);
        for (index, id) in members.iter().enumerate() {
            transaction
                .execute(
                    "UPDATE album_memberships SET sort_position = ?3, revision = revision + 1
                 WHERE album_id = ?1 AND object_id = ?2",
                    params![
                        album_id.as_bytes().as_slice(),
                        id.as_bytes().as_slice(),
                        as_sqlite_integer(index as u64, "the position is out of range")?
                    ],
                )
                .map_err(|error| map_sqlite(error, "the member position could not be written"))?;
        }
        bump_generation(transaction)
    })
}

/// Creates a tag, §9.
pub fn put_tag(db: &mut CatalogDb, tag: &Tag) -> Result<()> {
    tag.check()?;
    let created = as_sqlite_integer(tag.created_ms, "the time is out of range")?;
    db.transaction(|transaction| {
        let present = count(transaction, "SELECT count(*) FROM tags")?;
        let already: i64 = transaction
            .query_row(
                "SELECT count(*) FROM tags WHERE tag_id = ?1",
                [tag.tag_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "the tag could not be read"))?;
        if already == 0 {
            ensure!(
                present < limits::TAGS_MAX,
                ResourceLimitExceeded,
                "the vault holds the §21 maximum of tags"
            );
        }
        transaction
            .execute(
                "INSERT INTO tags (tag_id, name, created_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(tag_id) DO UPDATE SET name = excluded.name",
                params![tag.tag_id.as_bytes().as_slice(), tag.name.as_str(), created],
            )
            .map_err(|error| map_sqlite(error, "the tag could not be written"))?;
        bump_generation(transaction)
    })
}

/// Renames a tag and refreshes every affected search projection atomically.
pub fn rename_tag(db: &mut CatalogDb, tag_id: &Id, name: &str) -> Result<()> {
    Tag {
        tag_id: *tag_id,
        name: name.to_owned(),
        created_ms: 0,
    }
    .check()?;
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE tags SET name = ?2 WHERE tag_id = ?1",
                params![tag_id.as_bytes().as_slice(), name],
            )
            .map_err(|error| map_sqlite(error, "the tag could not be renamed"))?;
        ensure!(changed == 1, NotFound, "the tag does not exist");
        let ids = tag_member_ids(transaction, tag_id)?;
        for id in &ids {
            reindex_search(transaction, id)?;
        }
        bump_generation(transaction)
    })
}

/// Deletes a tag, removes its memberships, and refreshes search in one transaction.
pub fn delete_tag(db: &mut CatalogDb, tag_id: &Id) -> Result<()> {
    db.transaction(|transaction| {
        let ids = tag_member_ids(transaction, tag_id)?;
        transaction
            .execute(
                "DELETE FROM object_tags WHERE tag_id = ?1",
                [tag_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the tag memberships could not be removed"))?;
        let changed = transaction
            .execute(
                "DELETE FROM tags WHERE tag_id = ?1",
                [tag_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the tag could not be deleted"))?;
        ensure!(changed == 1, NotFound, "the tag does not exist");
        for id in &ids {
            reindex_search(transaction, id)?;
        }
        bump_generation(transaction)
    })
}

fn tag_member_ids(transaction: &Transaction<'_>, tag_id: &Id) -> Result<Vec<Id>> {
    let mut statement = transaction
        .prepare("SELECT object_id FROM object_tags WHERE tag_id = ?1")
        .map_err(|error| map_sqlite(error, "the tag members could not be read"))?;
    let rows = statement
        .query_map([tag_id.as_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|error| map_sqlite(error, "the tag members could not be read"))?;
    rows.map(|row| {
        let bytes = row.map_err(|error| map_sqlite(error, "a tag member could not be read"))?;
        Id::from_slice(&bytes)
    })
    .collect()
}

/// Uses an existing tag or creates one together with its selected memberships.
pub fn apply_tag_selection(
    db: &mut CatalogDb,
    tag_id: Option<&Id>,
    new_tag: Option<&Tag>,
    object_ids: &[Id],
    tagged: bool,
) -> Result<Id> {
    ensure!(
        !object_ids.is_empty() && object_ids.len() as u64 <= limits::OBJECTS_MAX,
        InvalidInput,
        "the selection size is outside the object bound"
    );
    ensure!(
        tag_id.is_some() != new_tag.is_some() && (tagged || new_tag.is_none()),
        InvalidInput,
        "the tag target is invalid"
    );
    let mut distinct = HashSet::with_capacity(object_ids.len());
    ensure!(
        object_ids.iter().all(|id| distinct.insert(*id)),
        InvalidInput,
        "the selection repeats an object"
    );
    if let Some(tag) = new_tag {
        tag.check()?;
    }
    db.transaction(|transaction| {
        let id = if let Some(tag) = new_tag {
            ensure!(
                count(transaction, "SELECT count(*) FROM tags")? < limits::TAGS_MAX,
                ResourceLimitExceeded,
                "the vault holds the maximum of tags"
            );
            transaction
                .execute(
                    "INSERT INTO tags (tag_id, name, created_ms) VALUES (?1, ?2, ?3)",
                    params![
                        tag.tag_id.as_bytes().as_slice(),
                        tag.name.as_str(),
                        as_sqlite_integer(tag.created_ms, "the tag time is out of range")?
                    ],
                )
                .map_err(|error| map_sqlite(error, "the tag could not be created"))?;
            tag.tag_id
        } else if let Some(id) = tag_id {
            *id
        } else {
            bail!(InvalidInput, "the tag target is missing");
        };
        ensure!(
            count_with(
                transaction,
                "SELECT count(*) FROM tags WHERE tag_id = ?1",
                [id.as_bytes().as_slice()]
            )? == 1,
            NotFound,
            "the tag does not exist"
        );
        for object_id in object_ids {
            ensure!(
                count_with(
                    transaction,
                    "SELECT count(*) FROM objects WHERE object_id = ?1 AND state = 1",
                    [object_id.as_bytes().as_slice()]
                )? == 1,
                NotFound,
                "the selection contains no listable object"
            );
            if tagged {
                let already = count_with(
                    transaction,
                    "SELECT count(*) FROM object_tags WHERE tag_id = ?1 AND object_id = ?2",
                    [id.as_bytes().as_slice(), object_id.as_bytes().as_slice()],
                )?;
                if already == 0 {
                    ensure!(
                        count_with(
                            transaction,
                            "SELECT count(*) FROM object_tags WHERE object_id = ?1",
                            [object_id.as_bytes().as_slice()]
                        )? < u64::from(limits::TAGS_PER_OBJECT_MAX),
                        ResourceLimitExceeded,
                        "the object holds the maximum of tags"
                    );
                }
            }
        }
        for object_id in object_ids {
            if tagged {
                transaction
                    .execute(
                        "INSERT INTO object_tags (tag_id, object_id, capture_time_ms)
                     SELECT ?1, object_id, capture_time_ms FROM objects WHERE object_id = ?2
                     ON CONFLICT(tag_id, object_id) DO NOTHING",
                        params![id.as_bytes().as_slice(), object_id.as_bytes().as_slice()],
                    )
                    .map_err(|error| map_sqlite(error, "the tag could not be applied"))?;
            } else {
                transaction
                    .execute(
                        "DELETE FROM object_tags WHERE tag_id = ?1 AND object_id = ?2",
                        params![id.as_bytes().as_slice(), object_id.as_bytes().as_slice()],
                    )
                    .map_err(|error| map_sqlite(error, "the tag could not be removed"))?;
            }
            reindex_search(transaction, object_id)?;
        }
        bump_generation(transaction)?;
        Ok(id)
    })
}

/// Adds or removes a tag on one object, §9.
///
/// The search index is rewritten in the same transaction, which is the second
/// half of the §16.4 rule that an index never outlives the row it describes.
pub fn set_object_tag(db: &mut CatalogDb, tag_id: &Id, object_id: &Id, tagged: bool) -> Result<()> {
    let object_id = *object_id;
    db.transaction(|transaction| {
        if tagged {
            let present: u64 = count_with(
                transaction,
                "SELECT count(*) FROM object_tags WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
            )?;
            ensure!(
                present < u64::from(limits::TAGS_PER_OBJECT_MAX),
                ResourceLimitExceeded,
                "the object holds the §21 maximum of tags"
            );
            transaction
                .execute(
                    "INSERT INTO object_tags (tag_id, object_id, capture_time_ms)
                     SELECT ?1, object_id, capture_time_ms FROM objects
                      WHERE object_id = ?2 AND state = 1
                     ON CONFLICT(tag_id, object_id) DO NOTHING",
                    params![
                        tag_id.as_bytes().as_slice(),
                        object_id.as_bytes().as_slice()
                    ],
                )
                .map_err(|error| map_sqlite(error, "the tag could not be applied"))?;
        } else {
            transaction
                .execute(
                    "DELETE FROM object_tags WHERE tag_id = ?1 AND object_id = ?2",
                    params![
                        tag_id.as_bytes().as_slice(),
                        object_id.as_bytes().as_slice()
                    ],
                )
                .map_err(|error| map_sqlite(error, "the tag could not be removed"))?;
        }
        reindex_search(transaction, &object_id)?;
        bump_generation(transaction)
    })
}

/// Rewrites one object's row in the FTS5 index, §16.4.
///
/// The index is external-content, so the catalog writes it explicitly. The
/// delete-then-insert pair is how FTS5 replaces a row of such a table: an
/// `INSERT` with the `delete` command supplies the old column values, and
/// storing them would duplicate the source of truth, so the row is deleted by
/// its identifier through the `delete-all`-free path of a rowid delete.
pub(crate) fn reindex_search(transaction: &Transaction<'_>, object_id: &Id) -> Result<()> {
    let rowid = search_rowid(transaction, object_id)?;
    let Some(rowid) = rowid else {
        // The object row is gone, so nothing describes it any more.
        transaction
            .execute(
                "DELETE FROM object_search WHERE rowid = ?1",
                [row_key(object_id)],
            )
            .map_err(|error| map_sqlite(error, "the search row could not be removed"))?;
        return Ok(());
    };
    transaction
        .execute("DELETE FROM object_search WHERE rowid = ?1", [rowid])
        .map_err(|error| map_sqlite(error, "the search row could not be replaced"))?;
    transaction
        .execute(
            "INSERT INTO object_search (rowid, filename, caption, tag_names, content_body)
             SELECT ?1,
                    COALESCE(m.original_filename, ''),
                    COALESCE(m.caption, ''),
                    COALESCE((SELECT group_concat(t.name, ' ')
                                FROM object_tags o JOIN tags t ON t.tag_id = o.tag_id
                               WHERE o.object_id = ?2), ''),
                    COALESCE((SELECT c.body FROM content_index c JOIN objects source ON source.object_id=c.object_id AND source.primary_stream_id=c.primary_stream_id WHERE c.object_id=?2),'')
               FROM metadata_revisions m
              WHERE m.object_id = ?2 AND m.active = 1",
            params![rowid, object_id.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "the search row could not be written"))?;
    Ok(())
}

/// The FTS5 rowid of one object, or `None` when the object row is gone.
fn search_rowid(transaction: &Transaction<'_>, object_id: &Id) -> Result<Option<i64>> {
    let present: i64 = transaction
        .query_row(
            "SELECT count(*) FROM objects WHERE object_id = ?1",
            [object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the object could not be read"))?;
    Ok((present == 1).then(|| row_key(object_id)))
}

/// The stable FTS5 rowid of an object.
///
/// FTS5 keys on an `INTEGER` rowid, and an object is keyed on 16 opaque bytes,
/// so a mapping is unavoidable. The first eight bytes of the identifier are
/// used, big-endian, with the sign bit cleared so the value is positive. The
/// identifier is CSPRNG output, so a collision needs about 2^31 objects in one
/// vault by the birthday bound and the vault holds at most 10^6 under §21. The
/// `objects.search_key` column carries the same value under a `UNIQUE`
/// constraint, so the case the bound makes improbable is still refused rather
/// than served as a wrong page.
pub(crate) fn row_key(object_id: &Id) -> i64 {
    let bytes = object_id.as_bytes();
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[..8]);
    #[expect(
        clippy::cast_possible_wrap,
        reason = "the sign bit is cleared, so the value is a positive i64"
    )]
    let value = (u64::from_be_bytes(head) & 0x7fff_ffff_ffff_ffff) as i64;
    value
}

fn count(transaction: &Transaction<'_>, sql: &str) -> Result<u64> {
    let value: i64 = transaction
        .query_row(sql, [], |row| row.get(0))
        .map_err(|error| map_sqlite(error, "a catalog count could not be read"))?;
    from_sqlite_integer(value, "a catalog count is negative")
}

fn count_with<P, I>(transaction: &Transaction<'_>, sql: &str, params: I) -> Result<u64>
where
    I: IntoIterator<Item = P>,
    P: rusqlite::ToSql,
{
    let value: i64 = transaction
        .query_row(sql, rusqlite::params_from_iter(params), |row| row.get(0))
        .map_err(|error| map_sqlite(error, "a catalog count could not be read"))?;
    from_sqlite_integer(value, "a catalog count is negative")
}

fn byte(value: i64, context: &'static str) -> Result<u8> {
    u8::try_from(value)
        .map_err(|_| chur_core::Error::new(chur_core::ChurStatus::CatalogCorrupt, context))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::db::{CatalogKey, CatalogLocation};
    use crate::model::{COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE};
    use crate::schema::open_at_current_version;
    use chur_core::ChurStatus;
    use chur_crypto::{Key, Nonce, random};
    use chur_format::constants::MediaClass;

    #[test]
    fn tag_selection_and_management_keep_search_and_refusals_atomic() {
        let mut fixture = fixture();
        let first = activation(&fixture, 10, "one.jpg");
        let second = activation(&fixture, 11, "two.jpg");
        let ids = [first.object.object_id, second.object.object_id];
        activate_object(&mut fixture.db, &first).expect("first");
        activate_object(&mut fixture.db, &second).expect("second");
        let tag = Tag {
            tag_id: random::id().expect("tag"),
            name: "Amber".into(),
            created_ms: 1,
        };
        assert_eq!(
            rejection(apply_tag_selection(
                &mut fixture.db,
                None,
                Some(&tag),
                &[ids[0], random::id().expect("missing")],
                true
            )),
            ChurStatus::NotFound
        );
        assert!(tags(&fixture.db).expect("tags").is_empty());
        apply_tag_selection(&mut fixture.db, None, Some(&tag), &ids, true)
            .expect("create and apply");
        assert_eq!(
            object_tags(&fixture.db, &ids[0]).expect("first tags").len(),
            1
        );
        assert_eq!(
            object_tags(&fixture.db, &ids[1])
                .expect("second tags")
                .len(),
            1
        );
        rename_tag(&mut fixture.db, &tag.tag_id, "Copper").expect("rename");
        assert_eq!(
            object_tags(&fixture.db, &ids[0]).expect("renamed tags")[0].name,
            "Copper"
        );
        apply_tag_selection(&mut fixture.db, Some(&tag.tag_id), None, &[ids[1]], false)
            .expect("remove one");
        assert!(
            object_tags(&fixture.db, &ids[1])
                .expect("removed tags")
                .is_empty()
        );
        delete_tag(&mut fixture.db, &tag.tag_id).expect("delete");
        assert!(
            object_tags(&fixture.db, &ids[0])
                .expect("deleted tags")
                .is_empty()
        );
        assert!(tags(&fixture.db).expect("tags").is_empty());
    }

    #[test]
    fn favourite_selection_refuses_missing_objects_without_partial_update() {
        let mut fixture = fixture();
        let first = activation(&fixture, 10, "one.jpg");
        let id = first.object.object_id;
        activate_object(&mut fixture.db, &first).expect("first");
        assert_eq!(
            rejection(set_favorites(
                &mut fixture.db,
                &[id, random::id().expect("missing")],
                true,
                2
            )),
            ChurStatus::NotFound
        );
        assert!(!object(&fixture.db, &id).expect("object").favorite);
        set_favorites(&mut fixture.db, &[id], true, 3).expect("favorite");
        assert!(object(&fixture.db, &id).expect("object").favorite);
        set_favorites(&mut fixture.db, &[id], false, 4).expect("unfavorite");
        assert!(!object(&fixture.db, &id).expect("object").favorite);
    }

    #[test]
    fn nested_album_move_refuses_a_cycle_and_delete_keeps_media() {
        let mut fixture = fixture();
        let media = activation(&fixture, 10, "image.jpg");
        let object_id = media.object.object_id;
        activate_object(&mut fixture.db, &media).expect("import");
        let root = random::id().expect("root");
        let child = random::id().expect("child");
        for (id, name) in [(root, "Root"), (child, "Child")] {
            put_album(
                &mut fixture.db,
                &Album {
                    album_id: id,
                    name: name.to_owned(),
                    created_ms: 1,
                    revision: 1,
                },
            )
            .expect("album");
        }
        set_album_membership(&mut fixture.db, &child, &object_id, true, 2).expect("member");
        move_album(&mut fixture.db, &child, Some(&root), None).expect("nest");
        assert_eq!(
            rejection(move_album(&mut fixture.db, &root, Some(&child), None)),
            ChurStatus::InvalidInput
        );
        let listed = albums(&fixture.db).expect("albums");
        assert_eq!(
            listed
                .iter()
                .find(|row| row.album.album_id == child)
                .unwrap()
                .parent_id,
            Some(root)
        );
        delete_album(&mut fixture.db, &root).expect("delete tree");
        assert!(albums(&fixture.db).expect("albums").is_empty());
        assert_eq!(
            object(&fixture.db, &object_id).expect("media").object_id,
            object_id
        );
    }

    #[test]
    fn renaming_and_reordering_albums_preserves_membership() {
        let mut fixture = fixture();
        let first = random::id().expect("first");
        let second = random::id().expect("second");
        for (id, name) in [(first, "First"), (second, "Second")] {
            put_album(
                &mut fixture.db,
                &Album {
                    album_id: id,
                    name: name.to_owned(),
                    created_ms: 1,
                    revision: 1,
                },
            )
            .expect("album");
        }
        rename_album(&mut fixture.db, &second, "Renamed").expect("rename");
        move_album(&mut fixture.db, &second, None, Some(&first)).expect("reorder");
        let listed = albums(&fixture.db).expect("albums");
        assert_eq!(listed[0].album.album_id, second);
        assert_eq!(listed[0].album.name, "Renamed");
        assert_eq!(listed[1].album.album_id, first);
    }

    #[test]
    fn album_member_count_matches_visible_album_page_after_quarantine() {
        let mut fixture = fixture();
        let first = activation(&fixture, 10, "first.jpg");
        let held = activation(&fixture, 11, "held.jpg");
        activate_object(&mut fixture.db, &first).expect("first");
        activate_object(&mut fixture.db, &held).expect("held");
        let album = Album {
            album_id: random::id().expect("album id"),
            name: "Visible".into(),
            created_ms: 1,
            revision: 1,
        };
        put_album(&mut fixture.db, &album).expect("album");
        for id in [first.object.object_id, held.object.object_id] {
            set_album_membership(&mut fixture.db, &album.album_id, &id, true, 1)
                .expect("membership");
        }
        set_integrity_summary(
            &mut fixture.db,
            &held.object.object_id,
            IntegritySummary::Quarantined,
            2,
        )
        .expect("quarantine");
        let page = crate::query::page(
            &fixture.db,
            &crate::query::ObjectQuery {
                scope: crate::query::Scope::Album(album.album_id),
                ..crate::query::ObjectQuery::timeline()
            },
        )
        .expect("album page");
        assert_eq!(page.objects.len(), 1);
        assert_eq!(albums(&fixture.db).expect("albums")[0].member_count, 1);
    }

    #[test]
    fn existing_album_membership_is_idempotent_at_the_membership_limit() {
        let mut fixture = fixture();
        let first = activation(&fixture, 10, "first.jpg");
        activate_object(&mut fixture.db, &first).expect("first");
        let album = Album {
            album_id: random::id().expect("album id"),
            name: "Full".into(),
            created_ms: 1,
            revision: 1,
        };
        put_album(&mut fixture.db, &album).expect("album");
        // Populate the real SQLCipher schema in one transaction. Foreign key
        // checks stay enabled; the calls under test enforce the production bound.
        fixture
            .db
            .transaction(|tx| {
                tx.execute(
                    "WITH RECURSIVE sequence(n) AS (
                    VALUES(1) UNION ALL SELECT n+1 FROM sequence WHERE n < ?1
                 ) INSERT INTO objects SELECT randomblob(16), object_generation,
                    collection_id, randomblob(16), media_kind, capture_time_ms,
                    import_time_ms, capture_time_substituted, plaintext_size, width,
                    height, duration_ms, favorite, state, integrity_summary,
                    thumbnail_ready, active_metadata_revision, n
                   FROM sequence CROSS JOIN objects WHERE object_id = ?2",
                    params![
                        i64::try_from(limits::ALBUM_MEMBERSHIPS_MAX - 1).expect("limit"),
                        first.object.object_id.as_bytes().as_slice()
                    ],
                )
                .expect("populate objects");
                tx.execute(
                    "INSERT INTO album_memberships
                    (album_id, object_id, capture_time_ms, added_ms, revision, sort_position)
                 SELECT ?1, object_id, capture_time_ms, 1, 1, row_number() OVER ()
                   FROM objects",
                    [album.album_id.as_bytes().as_slice()],
                )
                .expect("fill album");
                Ok(())
            })
            .expect("fixture transaction");
        assert_eq!(
            albums(&fixture.db).expect("full album")[0].member_count,
            limits::ALBUM_MEMBERSHIPS_MAX
        );
        set_album_membership(
            &mut fixture.db,
            &album.album_id,
            &first.object.object_id,
            true,
            2,
        )
        .expect("existing member at limit");
        let extra = activation(&fixture, 12, "extra.jpg");
        activate_object(&mut fixture.db, &extra).expect("extra object");
        assert_eq!(
            rejection(set_album_membership(
                &mut fixture.db,
                &album.album_id,
                &extra.object.object_id,
                true,
                2
            )),
            ChurStatus::ResourceLimitExceeded
        );
        assert_eq!(
            albums(&fixture.db).expect("album remains full")[0].member_count,
            limits::ALBUM_MEMBERSHIPS_MAX
        );
    }

    fn album_with_two_members(fixture: &mut Fixture) -> (Id, [Id; 2]) {
        let first = activation(fixture, 10, "first.jpg");
        let second = activation(fixture, 11, "second.jpg");
        let ids = [first.object.object_id, second.object.object_id];
        activate_object(&mut fixture.db, &first).expect("first");
        activate_object(&mut fixture.db, &second).expect("second");
        let album = Album {
            album_id: random::id().expect("album id"),
            name: "Selection".into(),
            created_ms: 1,
            revision: 1,
        };
        put_album(&mut fixture.db, &album).expect("album");
        place_album_members(
            &mut fixture.db,
            AlbumDestination::Existing(&album.album_id),
            None,
            &ids,
            false,
            1,
        )
        .expect("selection");
        (album.album_id, ids)
    }

    #[test]
    fn removing_album_selection_advances_revision_and_generation_once() {
        let mut fixture = fixture();
        let (album, ids) = album_with_two_members(&mut fixture);
        let before = albums(&fixture.db).expect("before")[0].clone();
        let generation = crate::schema::generation(&fixture.db).expect("generation");
        remove_album_members(&mut fixture.db, &album, &ids).expect("remove selection");
        let after = albums(&fixture.db).expect("after")[0].clone();
        assert_eq!(after.member_count, 0);
        assert_eq!(after.album.revision, before.album.revision + 1);
        assert_eq!(
            crate::schema::generation(&fixture.db).expect("generation"),
            generation + 1
        );
        for id in ids {
            assert_eq!(
                object(&fixture.db, &id).expect("object query").object_id,
                id
            );
        }
    }

    #[test]
    fn removing_album_selection_rolls_back_on_a_stale_membership() {
        let mut fixture = fixture();
        let (album, ids) = album_with_two_members(&mut fixture);
        let before = albums(&fixture.db).expect("before");
        let generation = crate::schema::generation(&fixture.db).expect("generation");
        let absent = random::id().expect("absent id");
        assert_eq!(
            rejection(remove_album_members(
                &mut fixture.db,
                &album,
                &[ids[0], absent]
            )),
            ChurStatus::Conflict
        );
        assert_eq!(albums(&fixture.db).expect("unchanged"), before);
        assert_eq!(
            crate::schema::generation(&fixture.db).expect("generation"),
            generation
        );
        for selection in [vec![], vec![ids[0], ids[0]]] {
            assert_eq!(
                rejection(remove_album_members(&mut fixture.db, &album, &selection)),
                ChurStatus::InvalidInput
            );
        }
        assert_eq!(
            rejection(remove_album_members(&mut fixture.db, &absent, &ids)),
            ChurStatus::NotFound
        );
    }

    #[test]
    fn removing_album_selection_rolls_back_after_a_database_write_failure() {
        let mut fixture = fixture();
        let (album, ids) = album_with_two_members(&mut fixture);
        let before = albums(&fixture.db).expect("before");
        let generation = crate::schema::generation(&fixture.db).expect("generation");
        fixture
            .db
            .connection()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_second_membership_delete
             BEFORE DELETE ON album_memberships
             WHEN OLD.object_id = (SELECT object_id FROM objects WHERE capture_time_ms = 11)
             BEGIN SELECT RAISE(ABORT, 'membership write failed'); END;",
            )
            .expect("inject real database failure");
        remove_album_members(&mut fixture.db, &album, &ids)
            .expect_err("second delete must fail after first delete");
        assert_eq!(albums(&fixture.db).expect("unchanged"), before);
        assert_eq!(
            crate::schema::generation(&fixture.db).expect("generation"),
            generation
        );
        fixture
            .db
            .connection()
            .execute_batch("DROP TRIGGER reject_second_membership_delete")
            .expect("clear database failure");
        remove_album_members(&mut fixture.db, &album, &ids)
            .expect("both memberships survived rollback");
        assert_eq!(albums(&fixture.db).expect("removed")[0].member_count, 0);
    }

    #[test]
    fn selection_move_is_atomic_and_add_keeps_the_source() {
        let mut fixture = fixture();
        let first = activation(&fixture, 10, "first.jpg");
        let second = activation(&fixture, 11, "second.jpg");
        let ids = [first.object.object_id, second.object.object_id];
        activate_object(&mut fixture.db, &first).expect("first");
        activate_object(&mut fixture.db, &second).expect("second");
        let source = random::id().expect("source");
        let target = random::id().expect("target");
        for (id, name) in [(source, "Source"), (target, "Target")] {
            put_album(
                &mut fixture.db,
                &Album {
                    album_id: id,
                    name: name.to_owned(),
                    created_ms: 1,
                    revision: 1,
                },
            )
            .expect("album");
        }
        set_album_membership(&mut fixture.db, &source, &ids[0], true, 2).expect("source member");
        assert_eq!(
            rejection(place_album_members(
                &mut fixture.db,
                AlbumDestination::Existing(&target),
                Some(&source),
                &ids,
                true,
                3
            )),
            ChurStatus::Conflict,
        );
        let members = |db: &CatalogDb, album: Id| -> u64 {
            db.connection()
                .query_row(
                    "SELECT count(*) FROM album_memberships WHERE album_id = ?1",
                    [album.as_bytes().as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count") as u64
        };
        assert_eq!(members(&fixture.db, target), 0);
        assert_eq!(members(&fixture.db, source), 1);
        place_album_members(
            &mut fixture.db,
            AlbumDestination::Existing(&target),
            Some(&source),
            &ids,
            false,
            3,
        )
        .expect("add selection");
        assert_eq!(members(&fixture.db, target), 2);
        assert_eq!(members(&fixture.db, source), 1);
        set_album_membership(&mut fixture.db, &source, &ids[1], true, 4)
            .expect("second source member");
        place_album_members(
            &mut fixture.db,
            AlbumDestination::Existing(&target),
            Some(&source),
            &ids,
            true,
            5,
        )
        .expect("move selection");
        assert_eq!(members(&fixture.db, target), 2);
        assert_eq!(members(&fixture.db, source), 0);
    }

    #[test]
    fn creating_nested_destination_rolls_back_with_invalid_selection() {
        let mut fixture = fixture();
        let parent = random::id().expect("parent");
        put_album(
            &mut fixture.db,
            &Album {
                album_id: parent,
                name: "Parent".to_owned(),
                created_ms: 1,
                revision: 1,
            },
        )
        .expect("parent");
        let child = Album {
            album_id: random::id().expect("child"),
            name: "Child".to_owned(),
            created_ms: 2,
            revision: 1,
        };
        assert_eq!(
            rejection(place_album_members(
                &mut fixture.db,
                AlbumDestination::New(&child, Some(&parent)),
                None,
                &[random::id().expect("missing object")],
                false,
                3
            )),
            ChurStatus::NotFound,
        );
        assert_eq!(albums(&fixture.db).expect("albums").len(), 1);
        let media = activation(&fixture, 10, "image.jpg");
        let object_id = media.object.object_id;
        activate_object(&mut fixture.db, &media).expect("import");
        place_album_members(
            &mut fixture.db,
            AlbumDestination::New(&child, Some(&parent)),
            None,
            &[object_id],
            false,
            4,
        )
        .expect("create and add");
        let listing = albums(&fixture.db).expect("albums");
        assert_eq!(
            listing
                .iter()
                .find(|row| row.album.album_id == child.album_id)
                .expect("child")
                .parent_id,
            Some(parent)
        );
    }

    struct Fixture {
        db: CatalogDb,
        collection: Id,
    }

    fn envelope(collection_id: Id, object_id: Id, generation: u64) -> Vec<u8> {
        ObjectKeyEnvelope::seal(
            &random::secret::<32>().expect("collection key"),
            random::id().expect("vault id"),
            collection_id,
            1,
            object_id,
            generation,
            Nonce::random().expect("nonce"),
            &random::secret::<32>().expect("object key"),
        )
        .expect("object envelope")
        .encode()
    }

    fn fixture() -> Fixture {
        let root: Key = random::secret::<32>().expect("root");
        let vault = random::id().expect("id");
        let key = CatalogKey::derive(&root, &vault).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("open");
        open_at_current_version(&mut db, 1_700_000_000_000).expect("schema");
        let collection = random::id().expect("id");
        put_collection(
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
        Fixture { db, collection }
    }

    fn activation(fixture: &Fixture, capture_ms: u64, filename: &str) -> ObjectActivation {
        let object_id = random::id().expect("id");
        let stream_id = random::id().expect("id");
        ObjectActivation {
            object: Object {
                object_id,
                object_generation: 1,
                collection_id: fixture.collection,
                primary_stream_id: stream_id,
                media_kind: MediaClass::Image,
                capture_time_ms: capture_ms,
                import_time_ms: capture_ms + 1,
                capture_time_substituted: false,
                plaintext_size: 4_096,
                width: 4_000,
                height: 3_000,
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
                container_path_id: random::id().expect("id"),
                container_version: 1,
                suite_id: 1,
                ciphertext_size: 4_200,
                plaintext_size: 4_096,
                chunk_size: 262_144,
                complete_verified_ms: None,
                final_commitment: [7u8; 32],
            },
            envelope: envelope(fixture.collection, object_id, 1),
            envelope_generation: 1,
            metadata: MetadataRevision {
                object_id,
                revision: 1,
                active: true,
                record: vec![1u8; 64],
                original_filename: Some(String::from(filename)),
                caption: None,
                content_type: String::from("image/jpeg"),
                capture_time_ms: Some(capture_ms),
                width: 4_000,
                height: 3_000,
                duration_ms: 0,
            },
        }
    }

    fn rejection<T>(outcome: Result<T>) -> ChurStatus {
        let Err(error) = outcome else {
            panic!("the catalog accepted something the specification forbids");
        };
        error.status()
    }

    #[test]
    fn collection_and_first_envelope_commit_atomically_and_replay_exactly() {
        let root = Key::new([1; 32]);
        let vault = Id::new([2; 16]).expect("vault");
        let key = CatalogKey::derive(&root, &vault).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("open");
        open_at_current_version(&mut db, 1).expect("schema");
        let collection = Collection {
            collection_id: Id::new([3; 16]).expect("collection"),
            current_epoch: 1,
            policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: COLLECTION_STATUS_ACTIVE,
        };
        db.connection()
            .execute_batch(
                "CREATE TRIGGER reject_collection_envelope
                 BEFORE INSERT ON collection_key_envelopes
                 BEGIN SELECT RAISE(ABORT, 'test rejection'); END;",
            )
            .expect("trigger");
        assert!(put_collection_with_envelope(&mut db, &collection, 1, &[4]).is_err());
        assert_eq!(
            db.connection()
                .query_row("SELECT count(*) FROM collections", [], |row| row
                    .get::<_, i64>(0))
                .expect("collection count"),
            0
        );

        db.connection()
            .execute_batch("DROP TRIGGER reject_collection_envelope")
            .expect("drop trigger");
        put_collection_with_envelope(&mut db, &collection, 1, &[4]).expect("store");
        put_collection_with_envelope(&mut db, &collection, 1, &[4]).expect("exact replay");
        assert_eq!(
            rejection(put_collection_with_envelope(&mut db, &collection, 1, &[5],)),
            ChurStatus::Conflict
        );
        assert_eq!(
            active_collection_envelope(&db, &collection.collection_id, 1).expect("envelope"),
            vec![4]
        );
    }

    #[test]
    fn an_activation_commits_the_object_stream_envelope_and_revision_together() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1_700_000_000_000, "holiday.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");

        let stored = object(&fixture.db, &object_id).expect("object");
        assert_eq!(stored, activation.object);
        assert_eq!(streams(&fixture.db, &object_id).expect("streams").len(), 1);
        assert_eq!(
            active_envelope(&fixture.db, &object_id).expect("envelope"),
            activation.envelope
        );
        let projection: (i64, i64) = fixture
            .db
            .connection()
            .query_row(
                "SELECT collection_epoch, envelope_generation
                   FROM sync_object_envelope_epochs WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("envelope projection");
        assert_eq!(projection, (1, 1));
        assert_eq!(
            active_metadata(&fixture.db, &object_id)
                .expect("metadata")
                .original_filename
                .as_deref(),
            Some("holiday.jpg")
        );
    }

    #[test]
    fn an_activation_that_names_two_objects_is_refused() {
        let mut fixture = fixture();
        let mut activation = activation(&fixture, 1, "a.jpg");
        activation.metadata.object_id = random::id().expect("id");
        assert_eq!(
            rejection(activate_object(&mut fixture.db, &activation)),
            ChurStatus::InvalidInput
        );
    }

    #[test]
    fn an_activation_rolls_back_whole_when_one_row_fails() {
        let mut fixture = fixture();
        let mut activation = activation(&fixture, 1, "a.jpg");
        // A collection the vault does not hold fails the foreign key, which is
        // the last statement of the transaction to run.
        activation.object.collection_id = random::id().expect("id");
        assert!(activate_object(&mut fixture.db, &activation).is_err());
        assert_eq!(
            rejection(object(&fixture.db, &activation.object.object_id)),
            ChurStatus::NotFound
        );
        let orphans: i64 = fixture
            .db
            .connection()
            .query_row("SELECT count(*) FROM object_streams", [], |row| row.get(0))
            .expect("count");
        assert_eq!(orphans, 0, "a stream survived a failed activation");
    }

    #[test]
    fn the_favourite_scope_and_its_sort_key_follow_the_flag() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1_700_000_000_000, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        set_favorite(&mut fixture.db, &object_id, true, 5).expect("favourite");
        let stored: i64 = fixture
            .db
            .connection()
            .query_row(
                "SELECT capture_time_ms FROM favorites WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("row");
        assert_eq!(stored, 1_700_000_000_000);
        assert!(object(&fixture.db, &object_id).expect("object").favorite);
        set_favorite(&mut fixture.db, &object_id, false, 6).expect("unfavourite");
        let rows: i64 = fixture
            .db
            .connection()
            .query_row("SELECT count(*) FROM favorites", [], |row| row.get(0))
            .expect("count");
        assert_eq!(rows, 0);
    }

    #[test]
    fn a_new_revision_rewrites_every_duplicated_sort_key() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1_000, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        set_favorite(&mut fixture.db, &object_id, true, 1).expect("favourite");
        let album_id = random::id().expect("id");
        put_album(
            &mut fixture.db,
            &Album {
                album_id,
                name: String::from("Holiday"),
                created_ms: 1,
                revision: 1,
            },
        )
        .expect("album");
        set_album_membership(&mut fixture.db, &album_id, &object_id, true, 1).expect("member");

        let mut revision = activation.metadata.clone();
        revision.revision = 2;
        revision.capture_time_ms = Some(9_000);
        revision.caption = Some(String::from("a caption"));
        activate_metadata_revision(&mut fixture.db, &revision).expect("activate revision");

        assert_eq!(
            object(&fixture.db, &object_id)
                .expect("object")
                .capture_time_ms,
            9_000
        );
        for table in ["favorites", "album_memberships"] {
            let stored: i64 = fixture
                .db
                .connection()
                .query_row(
                    &format!("SELECT capture_time_ms FROM {table} WHERE object_id = ?1"),
                    [object_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("row");
            assert_eq!(stored, 9_000, "{table} kept a stale sort key");
        }
    }

    #[test]
    fn an_absent_capture_time_marks_the_row_substituted() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1_000, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        let mut revision = activation.metadata.clone();
        revision.revision = 2;
        revision.capture_time_ms = None;
        activate_metadata_revision(&mut fixture.db, &revision).expect("activate revision");
        let stored = object(&fixture.db, &object_id).expect("object");
        assert!(stored.capture_time_substituted);
        assert_eq!(stored.capture_time_ms, 1_000, "the earlier time is kept");
    }

    #[test]
    fn corruption_is_a_lifecycle_change_and_is_terminal() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        mark_corrupt(&mut fixture.db, &object_id).expect("mark");
        assert_eq!(
            object(&fixture.db, &object_id).expect("object").state,
            ObjectState::Corrupt
        );
        assert_eq!(
            rejection(mark_corrupt(&mut fixture.db, &object_id)),
            ChurStatus::NotFound
        );
        assert_eq!(
            rejection(set_integrity_summary(
                &mut fixture.db,
                &object_id,
                IntegritySummary::CompleteVerified,
                1
            )),
            ChurStatus::NotFound,
            "a corrupt object still accepted a verification verdict"
        );
    }

    /// A stored all-zero `object_id` is a malformed row, which `row` reports as
    /// `CATALOG_CORRUPT`. `Id::new` alone would report `INVALID_INPUT`, the
    /// status of a bad caller argument, to a backup that passed no argument.
    #[test]
    fn a_reserved_object_id_in_the_stream_walk_is_catalog_corrupt() {
        let Fixture { db, .. } = fixture();
        db.connection()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO object_streams VALUES (
                     x'01010101010101010101010101010101', zeroblob(16), 0, 1, 0,
                     x'02020202020202020202020202020202', 1, 1, 0, 0, 65536, NULL,
                     zeroblob(32));",
            )
            .expect("zero object id row");
        assert_eq!(
            rejection(for_each_stream_ordered(&db, |_, _| Ok(()))),
            ChurStatus::CatalogCorrupt
        );
    }

    #[test]
    fn complete_verification_stamps_every_stream() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        set_integrity_summary(
            &mut fixture.db,
            &object_id,
            IntegritySummary::CompleteVerified,
            4_242,
        )
        .expect("verify");
        let stream = &streams(&fixture.db, &object_id).expect("streams")[0];
        assert_eq!(stream.complete_verified_ms, Some(4_242));
    }

    #[test]
    fn a_derived_asset_sets_the_thumbnail_flag_only_for_the_small_thumbnail() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        let mut stream = activation.stream.clone();
        stream.stream_id = random::id().expect("id");
        stream.stream_kind = StreamKind::GridPreview;
        stream.source_content_revision = 1;
        put_derived_asset(
            &mut fixture.db,
            &DerivedAsset {
                object_id,
                kind: StreamKind::GridPreview,
                source_content_revision: 1,
                asset_revision: 1,
                generator_profile: 1,
                stream_id: stream.stream_id,
            },
            &stream,
        )
        .expect("preview");
        assert!(
            !object(&fixture.db, &object_id)
                .expect("object")
                .thumbnail_ready
        );

        let mut thumbnail = stream.clone();
        thumbnail.stream_id = random::id().expect("id");
        thumbnail.stream_kind = StreamKind::ThumbnailSmall;
        put_derived_asset(
            &mut fixture.db,
            &DerivedAsset {
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
        assert!(
            object(&fixture.db, &object_id)
                .expect("object")
                .thumbnail_ready
        );
    }

    #[test]
    fn the_active_envelope_bound_of_section_21_is_enforced() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        for generation in 2..=4 {
            fixture
                .db
                .transaction(|transaction| {
                    insert_envelope_row(
                        transaction,
                        &object_id,
                        generation,
                        ENVELOPE_STATUS_ACTIVE,
                        &envelope(fixture.collection, object_id, generation),
                    )
                })
                .expect("an envelope inside the bound");
        }
        let outcome = fixture.db.transaction(|transaction| {
            insert_envelope_row(
                transaction,
                &object_id,
                5,
                ENVELOPE_STATUS_ACTIVE,
                &envelope(fixture.collection, object_id, 5),
            )
        });
        assert_eq!(rejection(outcome), ChurStatus::ResourceLimitExceeded);
    }

    #[test]
    fn the_tags_per_object_bound_of_section_21_is_enforced() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "a.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");
        let mut ids = Vec::new();
        for index in 0..129 {
            let tag_id = random::id().expect("id");
            put_tag(
                &mut fixture.db,
                &Tag {
                    tag_id,
                    name: format!("tag-{index}"),
                    created_ms: 1,
                },
            )
            .expect("tag");
            ids.push(tag_id);
        }
        for tag_id in ids.iter().take(128) {
            set_object_tag(&mut fixture.db, tag_id, &object_id, true).expect("tag the object");
        }
        assert_eq!(
            rejection(set_object_tag(&mut fixture.db, &ids[128], &object_id, true)),
            ChurStatus::ResourceLimitExceeded
        );
    }

    #[test]
    fn the_search_index_follows_the_filename_the_caption_and_the_tags() {
        let mut fixture = fixture();
        let activation = activation(&fixture, 1, "Bäckerei.jpg");
        let object_id = activation.object.object_id;
        activate_object(&mut fixture.db, &activation).expect("activate");

        let hits = |query: &str, db: &CatalogDb| -> i64 {
            db.connection()
                .query_row(
                    "SELECT count(*) FROM object_search WHERE object_search MATCH ?1",
                    [query],
                    |row| row.get(0),
                )
                .expect("search")
        };
        assert_eq!(hits("backerei", &fixture.db), 1, "diacritics are folded");
        assert_eq!(hits("holiday", &fixture.db), 0);

        let tag_id = random::id().expect("id");
        put_tag(
            &mut fixture.db,
            &Tag {
                tag_id,
                name: String::from("holiday"),
                created_ms: 1,
            },
        )
        .expect("tag");
        set_object_tag(&mut fixture.db, &tag_id, &object_id, true).expect("apply");
        assert_eq!(hits("holiday", &fixture.db), 1, "a tag is indexed");

        let mut revision = activation.metadata.clone();
        revision.revision = 2;
        revision.caption = Some(String::from("Kaffee und Kuchen"));
        activate_metadata_revision(&mut fixture.db, &revision).expect("revision");
        assert_eq!(hits("kuchen", &fixture.db), 1, "a caption is indexed");
        assert_eq!(
            hits("holiday", &fixture.db),
            1,
            "the tag survived a revision"
        );

        set_object_tag(&mut fixture.db, &tag_id, &object_id, false).expect("untag");
        assert_eq!(
            hits("holiday", &fixture.db),
            0,
            "a removed tag is unindexed"
        );
    }

    #[test]
    fn every_write_that_changes_a_page_advances_the_generation() {
        let mut fixture = fixture();
        let start = crate::schema::generation(&fixture.db).expect("generation");
        let activation = activation(&fixture, 1, "a.jpg");
        activate_object(&mut fixture.db, &activation).expect("activate");
        assert_eq!(
            crate::schema::generation(&fixture.db).expect("generation"),
            start + 1
        );
        set_favorite(&mut fixture.db, &activation.object.object_id, true, 1).expect("favourite");
        assert_eq!(
            crate::schema::generation(&fixture.db).expect("generation"),
            start + 2
        );
    }

    #[test]
    fn a_membership_of_an_absent_object_is_not_found() {
        let mut fixture = fixture();
        let album_id = random::id().expect("id");
        put_album(
            &mut fixture.db,
            &Album {
                album_id,
                name: String::from("Holiday"),
                created_ms: 1,
                revision: 1,
            },
        )
        .expect("album");
        assert_eq!(
            rejection(set_album_membership(
                &mut fixture.db,
                &album_id,
                &random::id().expect("id"),
                true,
                1
            )),
            ChurStatus::NotFound
        );
    }
}
