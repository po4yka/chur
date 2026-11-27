//! Durable collection epoch rotation and eager object-key rewrap.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::{
    constants::ObjectState,
    envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope},
};
use chur_sync_protocol::{
    rotation::{CollectionEpochState, RewrapOutcome},
    state::MembershipState,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    db::{CatalogDb, as_sqlite_integer, from_sqlite_integer, map_sqlite},
    model::{ENVELOPE_STATUS_ACTIVE, ENVELOPE_STATUS_SUPERSEDED},
    store::insert_envelope_row,
};

/// Verified current state of one collection's epoch rotation.
pub struct CollectionRotation {
    state: CollectionEpochState,
    complete: bool,
}

type RotationRow = (i64, Vec<u8>, i64, i64, Vec<u8>, i64);

impl CollectionRotation {
    /// Smallest active object still wrapped by the previous epoch.
    #[must_use]
    pub fn next_missing_object(&self) -> Option<&Id> {
        self.state.next_missing_object()
    }

    /// Current envelope for one active object.
    #[must_use]
    pub fn envelope(&self, object_id: &Id) -> Option<&ObjectKeyEnvelope> {
        self.state.envelope(object_id)
    }

    /// Whether no rewrap remains for the active or latest rotation.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Loads and authenticates one collection's envelope and rotation projections.
pub fn load(
    db: &CatalogDb,
    vault_id: Id,
    collection_id: Id,
    membership: &MembershipState,
    root: &Key,
) -> Result<CollectionRotation> {
    load_connection(db.connection(), vault_id, collection_id, membership, root)
}

/// Projects a validated `CreateCollectionEpoch` payload inside its operation transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are authenticated operation fields and unlocked key state"
)]
pub fn project_begin(
    transaction: &Transaction<'_>,
    vault_id: Id,
    collection_id: Id,
    membership: &MembershipState,
    owner_device_id: Id,
    membership_generation: u64,
    accepted_at_ms: u64,
    collection_envelope: CollectionKeyEnvelope,
    root: &Key,
) -> Result<()> {
    let mut rotation = load_connection(transaction, vault_id, collection_id, membership, root)?;
    ensure!(
        rotation.complete,
        Conflict,
        "collection rotation is already active"
    );
    rotation.state.begin_rotation(
        membership,
        owner_device_id,
        membership_generation,
        accepted_at_ms,
        collection_envelope,
        root,
    )?;
    let target_epoch = rotation.state.current_epoch();
    let envelope = rotation
        .state
        .collection_envelope()
        .ok_or_else(|| Error::new(ChurStatus::InternalFailure, "rotation has no envelope"))?;
    let changed = transaction
        .execute(
            "UPDATE collections SET current_epoch = ?1
              WHERE collection_id = ?2 AND current_epoch = ?3",
            params![
                as_sqlite_integer(target_epoch, "the target epoch is too large")?,
                collection_id.as_bytes().as_slice(),
                as_sqlite_integer(target_epoch - 1, "the previous epoch is too large")?,
            ],
        )
        .map_err(|error| map_sqlite(error, "the collection epoch could not be advanced"))?;
    ensure!(
        changed == 1,
        CatalogCorrupt,
        "the collection epoch projection moved concurrently"
    );
    transaction
        .execute(
            "INSERT INTO collection_key_envelopes
                 (collection_id, collection_epoch, generation, status, body)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                collection_id.as_bytes().as_slice(),
                as_sqlite_integer(target_epoch, "the target epoch is too large")?,
                as_sqlite_integer(
                    envelope.envelope_generation(),
                    "the collection envelope generation is too large"
                )?,
                i64::from(ENVELOPE_STATUS_ACTIVE),
                envelope.encode(),
            ],
        )
        .map_err(|error| map_sqlite(error, "the collection envelope could not be written"))?;
    let complete = rotation.state.is_complete();
    let changed = transaction
        .execute(
            "INSERT INTO sync_rotations
                 (collection_id, target_epoch, owner_device_id, membership_generation,
                  accepted_at_ms, collection_envelope, completed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(collection_id) DO UPDATE SET
                 target_epoch = excluded.target_epoch,
                 owner_device_id = excluded.owner_device_id,
                 membership_generation = excluded.membership_generation,
                 accepted_at_ms = excluded.accepted_at_ms,
                 collection_envelope = excluded.collection_envelope,
                 completed = excluded.completed
               WHERE sync_rotations.completed = 1",
            params![
                collection_id.as_bytes().as_slice(),
                as_sqlite_integer(target_epoch, "the target epoch is too large")?,
                owner_device_id.as_bytes().as_slice(),
                as_sqlite_integer(
                    membership_generation,
                    "the rotation membership generation is too large"
                )?,
                as_sqlite_integer(accepted_at_ms, "the rotation time is too large")?,
                envelope.encode(),
                i64::from(complete),
            ],
        )
        .map_err(|error| map_sqlite(error, "the rotation could not be written"))?;
    ensure!(
        changed == 1,
        Conflict,
        "collection rotation is already active"
    );
    Ok(())
}

/// Projects one authenticated target-epoch object envelope inside its operation transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are authenticated operation fields and unlocked key state"
)]
pub fn project_rewrap(
    transaction: &Transaction<'_>,
    vault_id: Id,
    collection_id: Id,
    membership: &MembershipState,
    worker_device_id: &Id,
    now_ms: u64,
    previous_collection_key: &Key,
    current_collection_key: &Key,
    envelope: ObjectKeyEnvelope,
    root: &Key,
) -> Result<RewrapOutcome> {
    let mut rotation = load_connection(transaction, vault_id, collection_id, membership, root)?;
    ensure!(
        !rotation.complete,
        Conflict,
        "collection has no active rotation"
    );
    let object_id = *envelope.object_id();
    let generation = envelope.envelope_generation();
    let outcome = rotation.state.apply_rewrap(
        membership,
        worker_device_id,
        now_ms,
        previous_collection_key,
        current_collection_key,
        envelope,
    )?;
    if outcome == RewrapOutcome::AlreadyApplied {
        return Ok(outcome);
    }
    let body = rotation
        .state
        .envelope(&object_id)
        .ok_or_else(|| Error::new(ChurStatus::InternalFailure, "rewrap has no envelope"))?
        .encode();
    // The old envelope wraps the object key under an epoch the removed member
    // holds. It is deleted, not kept as a superseded row, in the transaction
    // that commits its replacement; `secure_delete` overwrites the cell, and
    // the caller truncates the WAL when the rotation completes.
    let active: i64 = transaction
        .query_row(
            "SELECT count(*) FROM object_key_envelopes WHERE object_id = ?1 AND status = ?2",
            params![
                object_id.as_bytes().as_slice(),
                i64::from(ENVELOPE_STATUS_ACTIVE)
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "old object envelopes could not be counted"))?;
    ensure!(
        active != 0,
        CatalogCorrupt,
        "an active object has no active key envelope"
    );
    transaction
        .execute(
            "DELETE FROM object_key_envelopes WHERE object_id = ?1",
            [object_id.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "old object envelopes could not be destroyed"))?;
    insert_envelope_row(
        transaction,
        &object_id,
        generation,
        ENVELOPE_STATUS_ACTIVE,
        &body,
    )?;
    if rotation.state.is_complete() {
        let changed = transaction
            .execute(
                "UPDATE sync_rotations SET completed = 1
                  WHERE collection_id = ?1 AND completed = 0",
                [collection_id.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "the rotation could not be completed"))?;
        ensure!(
            changed == 1,
            CatalogCorrupt,
            "the active rotation row is absent"
        );
        // A catalog written before superseded envelopes were deleted can still
        // hold them. None of them is read, so the completed walk removes them.
        transaction
            .execute(
                "DELETE FROM object_key_envelopes
                  WHERE status = ?1
                    AND object_id IN (SELECT object_id FROM objects WHERE collection_id = ?2)",
                params![
                    i64::from(ENVELOPE_STATUS_SUPERSEDED),
                    collection_id.as_bytes().as_slice()
                ],
            )
            .map_err(|error| {
                map_sqlite(error, "superseded object envelopes could not be destroyed")
            })?;
    }
    Ok(outcome)
}

/// Whether the latest rotation of one collection has completed.
pub fn is_completed(connection: &Connection, collection_id: &Id) -> Result<bool> {
    let completed: Option<i64> = connection
        .query_row(
            "SELECT completed FROM sync_rotations WHERE collection_id = ?1",
            [collection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "the collection rotation could not be read"))?;
    Ok(completed == Some(1))
}

/// The objects whose key a member removed by a completed rotation may hold.
///
/// A rewrap advances the envelope generation and keeps the object key, so an
/// envelope above generation 1 names a key that predates a rotation. A
/// trashed object is not rewrapped, so its envelope stays under an earlier
/// epoch. Only the device that owns the rotation re-encrypts, so two devices
/// never replace the same object. Received shared collections are not listed:
/// their source vault re-encrypts them. ADR-0069 records the policy.
///
/// The smallest objects come first, so a large object that needs a whole
/// session does not hold back the rest.
pub fn reencryption_candidates(db: &CatalogDb, root: &Key) -> Result<Vec<Id>> {
    reencryption_query(db, root, &[ObjectState::Active, ObjectState::Trashed])
}

/// The number of objects still to re-encrypt, and of objects that cannot be
/// re-encrypted because their original does not authenticate.
pub fn reencryption_counts(db: &CatalogDb, root: &Key) -> Result<(u64, u64)> {
    let pending = reencryption_candidates(db, root)?.len();
    let corrupt = reencryption_query(db, root, &[ObjectState::Corrupt])?.len();
    let count = |value: usize| {
        u64::try_from(value)
            .map_err(|_| Error::new(ChurStatus::InternalFailure, "the count is too large"))
    };
    Ok((count(pending)?, count(corrupt)?))
}

fn reencryption_query(db: &CatalogDb, root: &Key, states: &[ObjectState]) -> Result<Vec<Id>> {
    let Some(membership) = crate::sync_membership::load(db)? else {
        return Ok(Vec::new());
    };
    let Some((device_id, _)) = crate::sync_keys::local_identity(db, root, &membership)? else {
        return Ok(Vec::new());
    };
    let mut statement = db
        .connection()
        .prepare(
            "SELECT o.object_id, o.state
               FROM objects o
               JOIN collections c ON c.collection_id = o.collection_id
               JOIN sync_rotations r ON r.collection_id = o.collection_id
               JOIN sync_object_envelope_epochs p ON p.object_id = o.object_id
              WHERE c.policy_type = ?1
                AND r.completed = 1
                AND r.owner_device_id = ?2
                AND (p.envelope_generation > 1 OR p.collection_epoch < c.current_epoch)
              ORDER BY o.plaintext_size, o.object_id",
        )
        .map_err(|error| map_sqlite(error, "re-encryption candidates could not be prepared"))?;
    let rows = statement
        .query_map(
            params![
                i64::from(crate::model::COLLECTION_POLICY_VAULT_DEFAULT),
                device_id.as_bytes().as_slice(),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|error| map_sqlite(error, "re-encryption candidates could not be read"))?;
    let mut ids = Vec::new();
    for row in rows {
        let (bytes, state) =
            row.map_err(|error| map_sqlite(error, "a re-encryption candidate could not be read"))?;
        if states
            .iter()
            .any(|wanted| i64::from(wanted.value()) == state)
        {
            ids.push(crate::row::id(
                &bytes,
                "a re-encryption candidate id is malformed",
            )?);
        }
    }
    Ok(ids)
}

fn load_connection(
    connection: &Connection,
    vault_id: Id,
    collection_id: Id,
    membership: &MembershipState,
    root: &Key,
) -> Result<CollectionRotation> {
    ensure!(
        membership.vault_id() == &vault_id,
        AuthenticationFailed,
        "rotation membership belongs to another vault"
    );
    let current_epoch: i64 = connection
        .query_row(
            "SELECT current_epoch FROM collections WHERE collection_id = ?1",
            [collection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the collection epoch could not be read"))?;
    let current_epoch = from_sqlite_integer(current_epoch, "the collection epoch is negative")?;
    let envelopes = active_object_envelopes(connection, vault_id, collection_id)?;
    let row: Option<RotationRow> = connection
        .query_row(
            "SELECT target_epoch, owner_device_id, membership_generation,
                    accepted_at_ms, collection_envelope, completed
               FROM sync_rotations WHERE collection_id = ?1",
            [collection_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite(error, "the collection rotation could not be read"))?;
    let Some((target, owner, generation, accepted_at, envelope, completed)) = row else {
        return Ok(CollectionRotation {
            state: CollectionEpochState::new(vault_id, collection_id, current_epoch, envelopes)
                .map_err(corrupt_rotation)?,
            complete: true,
        });
    };
    let target = from_sqlite_integer(target, "the target epoch is negative")?;
    ensure!(
        target == current_epoch,
        CatalogCorrupt,
        "the rotation target contradicts the collection epoch"
    );
    let mut state = CollectionEpochState::restore_active(
        vault_id,
        collection_id,
        target,
        envelopes,
        crate::row::id(&owner, "the rotation owner is malformed")?,
        from_sqlite_integer(generation, "the rotation membership generation is negative")?,
        from_sqlite_integer(accepted_at, "the rotation time is negative")?,
        CollectionKeyEnvelope::decode(&envelope).map_err(corrupt_rotation)?,
        membership,
        root,
    )
    .map_err(corrupt_rotation)?;
    let complete = completed == 1;
    if complete {
        state.finish_rotation().map_err(corrupt_rotation)?;
    }
    Ok(CollectionRotation { state, complete })
}

fn active_object_envelopes(
    connection: &Connection,
    vault_id: Id,
    collection_id: Id,
) -> Result<Vec<ObjectKeyEnvelope>> {
    let mut statement = connection
        .prepare(
            "SELECT p.object_id, p.collection_epoch, p.envelope_generation, e.body
               FROM sync_object_envelope_epochs p
               JOIN objects o ON o.object_id = p.object_id
               JOIN object_key_envelopes e
                 ON e.object_id = p.object_id
                AND e.generation = p.envelope_generation
                AND e.status = 1
              WHERE p.collection_id = ?1 AND o.state = ?2
              ORDER BY p.object_id",
        )
        .map_err(|error| map_sqlite(error, "active object envelopes could not be prepared"))?;
    let rows = statement
        .query_map(
            params![
                collection_id.as_bytes().as_slice(),
                i64::from(ObjectState::Active.value())
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .map_err(|error| map_sqlite(error, "active object envelopes could not be read"))?;
    let mut envelopes = Vec::new();
    for row in rows {
        let (object, epoch, generation, body) =
            row.map_err(|error| map_sqlite(error, "an active object envelope could not be read"))?;
        let object_id = crate::row::id(&object, "an object envelope id is malformed")?;
        let epoch = from_sqlite_integer(epoch, "an object envelope epoch is negative")?;
        let generation =
            from_sqlite_integer(generation, "an object envelope generation is negative")?;
        let envelope = ObjectKeyEnvelope::decode(&body).map_err(corrupt_rotation)?;
        ensure!(
            envelope.vault_id() == &vault_id
                && envelope.collection_id() == &collection_id
                && envelope.object_id() == &object_id
                && envelope.collection_epoch() == epoch
                && envelope.envelope_generation() == generation,
            CatalogCorrupt,
            "an object envelope contradicts its projection"
        );
        envelopes.push(envelope);
    }
    let expected: i64 = connection
        .query_row(
            "SELECT count(*) FROM objects WHERE collection_id = ?1 AND state = ?2",
            params![
                collection_id.as_bytes().as_slice(),
                i64::from(ObjectState::Active.value())
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "active objects could not be counted"))?;
    ensure!(
        from_sqlite_integer(expected, "the active object count is negative")?
            == u64::try_from(envelopes.len()).map_err(|_| {
                Error::new(ChurStatus::CatalogCorrupt, "the object count is too large")
            })?,
        CatalogCorrupt,
        "an active object has no current envelope projection"
    );
    Ok(envelopes)
}

fn corrupt_rotation(_: Error) -> Error {
    Error::new(
        ChurStatus::CatalogCorrupt,
        "stored collection rotation does not authenticate",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use chur_core::Id;
    use chur_crypto::{Key, Nonce};
    use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
    use chur_sync_protocol::{
        membership::EnrollmentRecord, operation::DeviceSigningKey, state::MembershipState,
    };

    use super::*;
    use crate::{
        db::{CatalogDb, CatalogKey, CatalogLocation},
        schema::open_at_current_version,
        sync_membership,
    };

    struct Fixture {
        db: CatalogDb,
        membership: MembershipState,
        root: Key,
        old_key: Key,
        new_key: Key,
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn setup() -> Fixture {
        let root = Key::new([1; 32]);
        let old_key = Key::new([2; 32]);
        let new_key = Key::new([3; 32]);
        let catalog_key = CatalogKey::derive(&root, &id(1)).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
        open_at_current_version(&mut db, 1).expect("schema");
        let signing_key = DeviceSigningKey::from_seed([4; 32]);
        let enrollment =
            EnrollmentRecord::initial(id(1), id(2), signing_key.verifying_key(), [5; 32])
                .expect("enrollment")
                .sign(&signing_key);
        let membership = sync_membership::provision(&mut db, &enrollment).expect("membership");
        db.transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO collections VALUES (?1, 1, 1, 1, 1)",
                    [id(10).as_bytes().as_slice()],
                )
                .expect("collection");
            for object in [30u8, 10, 20] {
                let envelope = ObjectKeyEnvelope::seal(
                    &old_key,
                    id(1),
                    id(10),
                    1,
                    id(object),
                    1,
                    Nonce::new([object; 24]),
                    &Key::new([object; 32]),
                )
                .expect("old envelope");
                transaction
                    .execute(
                        "INSERT INTO objects VALUES (
                             ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, ?4
                         )",
                        rusqlite::params![
                            id(object).as_bytes().as_slice(),
                            id(10).as_bytes().as_slice(),
                            id(object + 40).as_bytes().as_slice(),
                            i64::from(object),
                        ],
                    )
                    .expect("object");
                transaction
                    .execute(
                        "INSERT INTO object_key_envelopes VALUES (?1, 1, 1, ?2)",
                        rusqlite::params![id(object).as_bytes().as_slice(), envelope.encode()],
                    )
                    .expect("envelope");
                transaction
                    .execute(
                        "INSERT INTO sync_object_envelope_epochs VALUES (?1, ?2, 1, 1)",
                        rusqlite::params![
                            id(object).as_bytes().as_slice(),
                            id(10).as_bytes().as_slice(),
                        ],
                    )
                    .expect("projection");
            }
            Ok(())
        })
        .expect("objects");
        Fixture {
            db,
            membership,
            root,
            old_key,
            new_key,
        }
    }

    fn destination(fixture: &Fixture, envelope: &ObjectKeyEnvelope) -> ObjectKeyEnvelope {
        envelope
            .rewrap(
                &fixture.old_key,
                &fixture.new_key,
                id(10),
                2,
                2,
                Nonce::new([9; 24]),
            )
            .expect("rewrap")
    }

    #[test]
    fn rotation_resumes_at_the_smallest_hole_and_completes_atomically() {
        let mut fixture = setup();
        let rotation = load(
            &fixture.db,
            id(1),
            id(10),
            &fixture.membership,
            &fixture.root,
        )
        .expect("load");
        assert!(rotation.is_complete());
        let collection = CollectionKeyEnvelope::seal(
            &fixture.root,
            id(1),
            id(10),
            2,
            2,
            Nonce::new([8; 24]),
            &fixture.new_key,
        )
        .expect("collection envelope");
        fixture
            .db
            .transaction(|transaction| {
                project_begin(
                    transaction,
                    id(1),
                    id(10),
                    &fixture.membership,
                    id(2),
                    1,
                    1_000,
                    collection,
                    &fixture.root,
                )
            })
            .expect("begin");
        let rotation = load(
            &fixture.db,
            id(1),
            id(10),
            &fixture.membership,
            &fixture.root,
        )
        .expect("begun");
        assert_eq!(rotation.next_missing_object(), Some(&id(10)));

        let last = rotation.envelope(&id(30)).expect("last").clone();
        let last = destination(&fixture, &last);
        fixture
            .db
            .transaction(|transaction| {
                project_rewrap(
                    transaction,
                    id(1),
                    id(10),
                    &fixture.membership,
                    &id(2),
                    1_000,
                    &fixture.old_key,
                    &fixture.new_key,
                    last,
                    &fixture.root,
                )
                .map(|_| ())
            })
            .expect("last first");
        let mut rotation = load(
            &fixture.db,
            id(1),
            id(10),
            &fixture.membership,
            &fixture.root,
        )
        .expect("reopen");
        assert_eq!(rotation.next_missing_object(), Some(&id(10)));
        let envelopes = |db: &CatalogDb, sql: &str| -> i64 {
            db.connection()
                .query_row(sql, [], |row| row.get(0))
                .expect("envelope count")
        };
        // The rewrap deleted the old-epoch envelope instead of keeping it.
        assert_eq!(
            envelopes(
                &fixture.db,
                "SELECT count(*) FROM object_key_envelopes
                  WHERE object_id = x'1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e'"
            ),
            1
        );
        // A superseded row left by an earlier version goes when the walk completes.
        fixture
            .db
            .transaction(|transaction| {
                transaction
                    .execute(
                        "INSERT INTO object_key_envelopes VALUES (?1, 9, 2, x'00')",
                        [id(30).as_bytes().as_slice()],
                    )
                    .map_err(|error| map_sqlite(error, "legacy row"))?;
                Ok(())
            })
            .expect("legacy superseded row");

        for object in [10, 20] {
            let old = rotation.envelope(&id(object)).expect("old").clone();
            let destination = destination(&fixture, &old);
            fixture
                .db
                .transaction(|transaction| {
                    project_rewrap(
                        transaction,
                        id(1),
                        id(10),
                        &fixture.membership,
                        &id(2),
                        1_000,
                        &fixture.old_key,
                        &fixture.new_key,
                        destination,
                        &fixture.root,
                    )
                    .map(|_| ())
                })
                .expect("rewrap");
            rotation = load(
                &fixture.db,
                id(1),
                id(10),
                &fixture.membership,
                &fixture.root,
            )
            .expect("reload");
        }
        assert!(rotation.is_complete());
        assert_eq!(
            envelopes(&fixture.db, "SELECT count(*) FROM object_key_envelopes"),
            3
        );
        assert_eq!(
            envelopes(
                &fixture.db,
                "SELECT count(*) FROM object_key_envelopes WHERE status <> 1 OR generation <> 2"
            ),
            0
        );
        assert!(is_completed(fixture.db.connection(), &id(10)).expect("completed"));
        let completed: i64 = fixture
            .db
            .connection()
            .query_row("SELECT completed FROM sync_rotations", [], |row| row.get(0))
            .expect("completed");
        assert_eq!(completed, 1);
        assert!(
            load(
                &fixture.db,
                id(1),
                id(10),
                &fixture.membership,
                &fixture.root,
            )
            .expect("completed reopen")
            .is_complete()
        );
    }
}
