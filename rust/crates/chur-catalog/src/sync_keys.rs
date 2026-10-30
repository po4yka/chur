//! Rebuilds the unlocked sync key directory from catalog key envelopes.

use crate::CatalogDb;
use crate::db::{as_sqlite_integer, from_sqlite_integer, map_sqlite};
use crate::model::ENVELOPE_STATUS_ACTIVE;
use crate::schema::bump_generation;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::envelope::CollectionKeyEnvelope;
use chur_sync_protocol::{
    KeyDirectory, KeyDomain,
    identity::{DeviceIdentity, DeviceIdentityEnvelope},
    state::{DeviceStatus, MembershipState},
};
use rusqlite::{OptionalExtension, Transaction, params};

/// Stores the only local private device identity as a portable recovery envelope.
pub fn store_portable_identity_envelope(
    db: &mut CatalogDb,
    root: &Key,
    membership: &MembershipState,
    envelope: &DeviceIdentityEnvelope,
) -> Result<()> {
    ensure!(
        envelope.is_recovery_only(),
        InvalidInput,
        "portable identity is not recovery-only"
    );
    store_identity_envelope(db, root, membership, envelope)
}

/// Stores the ordinary local identity used for signing and grant opening.
pub fn store_local_identity_envelope(
    db: &mut CatalogDb,
    root: &Key,
    membership: &MembershipState,
    envelope: &DeviceIdentityEnvelope,
) -> Result<()> {
    ensure!(
        !envelope.is_recovery_only(),
        InvalidInput,
        "local identity has recovery-only purpose"
    );
    store_identity_envelope(db, root, membership, envelope)
}

fn store_identity_envelope(
    db: &mut CatalogDb,
    root: &Key,
    membership: &MembershipState,
    envelope: &DeviceIdentityEnvelope,
) -> Result<()> {
    validate_identity_envelope(root, membership, envelope, ChurStatus::AuthenticationFailed)?;
    let device_id = envelope.device_id();
    let generation = as_sqlite_integer(
        envelope.identity_generation(),
        "the identity generation is too large",
    )?;
    let body = envelope.encode();
    db.transaction(|transaction| {
        let latest: Option<(i64, i64, i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT identity_generation, active, recovery_only, body
                   FROM sync_identity_envelopes WHERE device_id = ?1
                   ORDER BY identity_generation DESC LIMIT 1",
                [device_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| map_sqlite(error, "identity envelopes could not be read"))?;
        if latest.as_ref().is_some_and(|row| {
            row.0 == generation
                && row.1 == 1
                && crate::row::flag(row.2, "the identity purpose is not a boolean")
                    == Ok(envelope.is_recovery_only())
                && row.3 == body
        }) {
            return Ok(());
        }
        let expected = match latest {
            Some(row) => row.0.checked_add(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "the stored identity generation has no successor",
                )
            })?,
            None => 1,
        };
        ensure!(
            generation == expected,
            Conflict,
            "identity generation does not advance the stored device identity"
        );
        transaction
            .execute(
                "UPDATE sync_identity_envelopes SET active = 0 WHERE active = 1",
                [],
            )
            .map_err(|error| map_sqlite(error, "the previous identity could not be retired"))?;
        transaction
            .execute(
                "INSERT INTO sync_identity_envelopes
                     (device_id, identity_generation, active, recovery_only, body)
                 VALUES (?1, ?2, 1, ?3, ?4)",
                params![
                    device_id.as_bytes().as_slice(),
                    generation,
                    i64::from(envelope.is_recovery_only()),
                    body
                ],
            )
            .map_err(|error| map_sqlite(error, "the private identity could not be stored"))?;
        bump_generation(transaction)
    })
}

pub(crate) fn project_local_identity(
    transaction: &Transaction<'_>,
    envelope: &DeviceIdentityEnvelope,
) -> Result<()> {
    ensure!(
        !envelope.is_recovery_only(),
        InvalidInput,
        "local identity has recovery-only purpose"
    );
    transaction
        .execute(
            "INSERT INTO sync_identity_envelopes
                 (device_id, identity_generation, active, recovery_only, body)
             VALUES (?1, ?2, 1, 0, ?3)",
            params![
                envelope.device_id().as_bytes().as_slice(),
                as_sqlite_integer(
                    envelope.identity_generation(),
                    "the identity generation is too large"
                )?,
                envelope.encode()
            ],
        )
        .map_err(|error| map_sqlite(error, "the local identity could not be stored"))?;
    Ok(())
}

/// Prepares the private identity in an isolated backup catalog snapshot.
///
/// The caller must pass a disposable catalog copy, never the live catalog.
/// It replaces all private identity rows with one recovery-only envelope and
/// seals a checkpoint over the current heads before converting an ordinary
/// signer. An already recovered identity retains its authenticated checkpoint.
///
/// # Errors
///
/// Returns catalog or authentication errors for an invalid stored identity,
/// and [`ChurStatus::VaultIncomplete`] when a recovery checkpoint is stale.
pub fn prepare_backup_identity(
    snapshot: &mut CatalogDb,
    root: &Key,
    membership: &MembershipState,
    now_ms: u64,
) -> Result<Option<DeviceIdentityEnvelope>> {
    let Some(stored) = active_identity_envelope(snapshot, root, membership)? else {
        return Ok(None);
    };
    let mut log = crate::sync_log::load(snapshot, membership)?;
    let portable = if stored.is_recovery_only() {
        ensure!(
            log.own_checkpoint_covers_current_heads(snapshot, membership)?,
            VaultIncomplete,
            "the recovered sync identity has no current own checkpoint"
        );
        stored
    } else {
        let identity = stored.open_for_local(root).map_err(corrupt_identity)?;
        log.issue_own_checkpoint(
            snapshot,
            membership,
            stored.device_id(),
            identity.signing_key(),
            now_ms,
        )?;
        DeviceIdentityEnvelope::seal_for_recovery(
            root,
            *stored.vault_id(),
            *stored.device_id(),
            stored.identity_generation(),
            chur_crypto::Nonce::random()?,
            &identity,
        )?
    };
    let checkpoint_record: Vec<u8> = snapshot
        .connection()
        .query_row(
            "SELECT checkpoint.record FROM sync_checkpoints AS checkpoint
          JOIN sync_state AS state ON checkpoint.commitment = state.latest_own_checkpoint_commitment
         WHERE state.only_row = 1 AND checkpoint.own = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the snapshot checkpoint could not be read"))?;
    let checkpoint = chur_sync_protocol::checkpoint::Checkpoint::decode(&checkpoint_record)
        .map_err(corrupt_identity)?;
    ensure!(
        checkpoint.issuer_device_id() == portable.device_id(),
        CatalogCorrupt,
        "the recovery checkpoint belongs to another device"
    );
    snapshot.transaction(|transaction| {
        // The snapshot already contains these exact accepted heads. Persist
        // them as explicit recovery floors as well as signed checkpoint evidence.
        for head in checkpoint.heads() {
            transaction.execute(
                "UPDATE sync_heads SET floor_sequence = ?1, floor_digest = ?2 WHERE device_id = ?3",
                params![as_sqlite_integer(head.device_sequence(), "the recovery floor is too large")?,
                    head.operation_digest().as_slice(), head.device_id().as_bytes().as_slice()],
            ).map_err(|error| map_sqlite(error, "the snapshot recovery floor could not be stored"))?;
        }
        transaction.execute("DELETE FROM device_pairing_pending", [])
            .map_err(|error| map_sqlite(error, "pending pairing state could not be excluded from backup"))?;
        transaction.execute("DELETE FROM device_pairing_approvals", [])
            .map_err(|error| map_sqlite(error, "pairing approvals could not be excluded from backup"))?;
        transaction.execute("DELETE FROM sync_identity_envelopes", [])
            .map_err(|error| map_sqlite(error, "snapshot identities could not be removed"))?;
        transaction.execute(
            "INSERT INTO sync_identity_envelopes
                 (device_id, identity_generation, active, recovery_only, body)
             VALUES (?1, ?2, 1, 1, ?3)",
            params![portable.device_id().as_bytes().as_slice(),
                as_sqlite_integer(portable.identity_generation(), "the identity generation is too large")?,
                portable.encode()],
        ).map_err(|error| map_sqlite(error, "the snapshot recovery identity could not be stored"))?;
        bump_generation(transaction)
    })?;
    Ok(Some(portable))
}

/// Loads and authenticates the local portable recovery identity, when present.
pub fn portable_identity_envelope(
    db: &CatalogDb,
    root: &Key,
    membership: &MembershipState,
) -> Result<Option<DeviceIdentityEnvelope>> {
    let envelope = active_identity_envelope(db, root, membership)?;
    ensure!(
        envelope
            .as_ref()
            .is_none_or(DeviceIdentityEnvelope::is_recovery_only),
        CatalogCorrupt,
        "the active identity is not recovery-only"
    );
    Ok(envelope)
}

/// Whether the active identity is a restored recovery-only identity.
pub fn is_recovery_only(db: &CatalogDb, root: &Key, membership: &MembershipState) -> Result<bool> {
    Ok(active_identity_envelope(db, root, membership)?
        .is_some_and(|envelope| envelope.is_recovery_only()))
}

/// Loads and authenticates the ordinary local identity, when present.
pub fn local_identity(
    db: &CatalogDb,
    root: &Key,
    membership: &MembershipState,
) -> Result<Option<(Id, DeviceIdentity)>> {
    let Some(envelope) = active_identity_envelope(db, root, membership)? else {
        return Ok(None);
    };
    ensure!(
        !envelope.is_recovery_only(),
        CatalogCorrupt,
        "the active identity is recovery-only"
    );
    let device_id = *envelope.device_id();
    let identity = envelope.open_for_local(root).map_err(corrupt_identity)?;
    Ok(Some((device_id, identity)))
}

fn active_identity_envelope(
    db: &CatalogDb,
    root: &Key,
    membership: &MembershipState,
) -> Result<Option<DeviceIdentityEnvelope>> {
    let mut statement = db
        .connection()
        .prepare(
            "SELECT device_id, identity_generation, recovery_only, body
               FROM sync_identity_envelopes WHERE active = 1 ORDER BY device_id",
        )
        .map_err(|error| map_sqlite(error, "the active identity could not be prepared"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite(error, "the active identity could not be read"))?;
    let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "the active identity could not be read"))?
    else {
        return Ok(None);
    };
    let device_bytes: Vec<u8> = row
        .get(0)
        .map_err(|error| map_sqlite(error, "the identity device could not be read"))?;
    let generation: i64 = row
        .get(1)
        .map_err(|error| map_sqlite(error, "the identity generation could not be read"))?;
    let recovery_only: i64 = row
        .get(2)
        .map_err(|error| map_sqlite(error, "the identity purpose could not be read"))?;
    let body: Vec<u8> = row
        .get(3)
        .map_err(|error| map_sqlite(error, "the identity body could not be read"))?;
    ensure!(
        rows.next()
            .map_err(|error| map_sqlite(error, "the active identity could not be read"))?
            .is_none(),
        CatalogCorrupt,
        "the catalog carries multiple active private identities"
    );
    let device_id = crate::row::id(&device_bytes, "the identity device id is malformed")?;
    let generation = from_sqlite_integer(generation, "the identity generation is negative")?;
    let recovery_only = crate::row::flag(recovery_only, "the identity purpose is not a boolean")?;
    let envelope = DeviceIdentityEnvelope::decode(&body).map_err(corrupt_identity)?;
    ensure!(
        envelope.device_id() == &device_id
            && envelope.identity_generation() == generation
            && envelope.is_recovery_only() == recovery_only,
        CatalogCorrupt,
        "the private identity contradicts its catalog row"
    );
    ensure!(
        membership.is_active(envelope.device_id()),
        AuthenticationFailed,
        "the local device identity has been revoked"
    );
    validate_identity_envelope(root, membership, &envelope, ChurStatus::CatalogCorrupt)?;
    Ok(Some(envelope))
}

fn validate_identity_envelope(
    root: &Key,
    membership: &MembershipState,
    envelope: &DeviceIdentityEnvelope,
    status: ChurStatus,
) -> Result<()> {
    let member = membership
        .device(envelope.device_id())
        .ok_or_else(|| Error::new(status, "the portable identity device is not enrolled"))?;
    if envelope.vault_id() != membership.vault_id() || member.status() != DeviceStatus::Active {
        return Err(Error::new(
            status,
            "the portable identity is not an active identity of this vault",
        ));
    }
    let (signing_public_key, hpke_public_key) = if envelope.is_recovery_only() {
        let identity = envelope
            .open_for_recovery(root)
            .map_err(|_| Error::new(status, "the private identity does not authenticate"))?;
        (identity.signing_public_key(), identity.hpke_public_key())
    } else {
        let identity = envelope
            .open_for_local(root)
            .map_err(|_| Error::new(status, "the private identity does not authenticate"))?;
        (identity.signing_public_key(), identity.hpke_public_key())
    };
    if signing_public_key != *member.signing_public_key()
        || hpke_public_key != *member.hpke_public_key()
    {
        return Err(Error::new(
            status,
            "the private identity keys contradict membership",
        ));
    }
    Ok(())
}

fn corrupt_identity(_: Error) -> Error {
    Error::new(
        ChurStatus::CatalogCorrupt,
        "the portable identity envelope is invalid",
    )
}

/// Derives root and retained collection-epoch routing for one unlocked vault.
pub fn key_directory(db: &CatalogDb, root: &Key, vault_id: Id) -> Result<KeyDirectory> {
    let mut directory = KeyDirectory::new(root, &vault_id)?;
    let mut statement = db
        .connection()
        .prepare(
            "SELECT collection_id, collection_epoch, generation, body
               FROM collection_key_envelopes WHERE status = ?1
               ORDER BY collection_id, collection_epoch, generation DESC",
        )
        .map_err(|error| map_sqlite(error, "collection envelopes could not be prepared"))?;
    let rows = statement
        .query_map([i64::from(ENVELOPE_STATUS_ACTIVE)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "collection envelopes could not be read"))?;
    let mut previous = None;
    for row in rows {
        let (collection, epoch, generation, body) =
            row.map_err(|error| map_sqlite(error, "a collection envelope could not be read"))?;
        let collection_id = crate::row::id(&collection, "a collection id is malformed")?;
        let epoch = from_sqlite_integer(epoch, "a collection epoch is negative")?;
        let generation = from_sqlite_integer(generation, "an envelope generation is negative")?;
        ensure!(
            previous != Some((collection_id, epoch)),
            CatalogCorrupt,
            "a collection epoch has multiple active envelopes"
        );
        previous = Some((collection_id, epoch));
        let envelope = CollectionKeyEnvelope::decode(&body).map_err(corrupt_envelope)?;
        ensure!(
            envelope.vault_id() == &vault_id
                && envelope.collection_id() == &collection_id
                && envelope.collection_epoch() == epoch
                && envelope.envelope_generation() == generation,
            CatalogCorrupt,
            "a collection envelope contradicts its catalog row"
        );
        let collection_key = envelope.open(root).map_err(corrupt_envelope)?;
        directory.insert(KeyDomain::collection(
            &collection_key,
            &collection_id,
            epoch,
        )?)?;
    }
    Ok(directory)
}

fn corrupt_envelope(_: Error) -> Error {
    Error::new(
        ChurStatus::CatalogCorrupt,
        "a collection key envelope is invalid",
    )
}

pub(crate) fn collection_key(
    db: &CatalogDb,
    root: &Key,
    vault_id: Id,
    collection_id: Id,
    epoch: u64,
) -> Result<Key> {
    let body = crate::store::active_collection_envelope(db, &collection_id, epoch)?;
    let envelope = CollectionKeyEnvelope::decode(&body).map_err(corrupt_envelope)?;
    ensure!(
        envelope.vault_id() == &vault_id
            && envelope.collection_id() == &collection_id
            && envelope.collection_epoch() == epoch,
        CatalogCorrupt,
        "a collection envelope contradicts its lookup key"
    );
    envelope.open(root).map_err(corrupt_envelope)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{
        db::{CatalogKey, CatalogLocation},
        schema::open_at_current_version,
        sync_membership,
    };
    use chur_crypto::Nonce;
    use chur_sync_protocol::{identity::DeviceIdentity, membership::EnrollmentRecord};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    #[test]
    fn backup_snapshot_keeps_one_recovery_identity_and_no_retired_signers() {
        let root = Key::new([21; 32]);
        let vault_id = id(22);
        let key = CatalogKey::derive(&root, &vault_id).expect("catalog key");
        let mut snapshot = CatalogDb::open(&CatalogLocation::Memory, &key).expect("catalog");
        open_at_current_version(&mut snapshot, 1).expect("schema");
        crate::sync_receive::provision_local_identity(&mut snapshot, &root, vault_id)
            .expect("production identity");
        let membership = sync_membership::load(&snapshot)
            .expect("membership")
            .expect("present");
        let (device_id, identity) = local_identity(&snapshot, &root, &membership)
            .expect("identity")
            .expect("present");
        let replacement = DeviceIdentityEnvelope::seal_for_local(
            &root,
            vault_id,
            device_id,
            2,
            Nonce::new([23; 24]),
            &identity,
        )
        .expect("generation two");
        store_local_identity_envelope(&mut snapshot, &root, &membership, &replacement)
            .expect("retire generation one");
        let portable = prepare_backup_identity(&mut snapshot, &root, &membership, 2)
            .expect("backup identity")
            .expect("present");
        assert!(portable.is_recovery_only());
        assert_eq!(portable.identity_generation(), 2);
        let rows: (i64, i64) = snapshot
            .connection()
            .query_row(
                "SELECT count(*), sum(recovery_only) FROM sync_identity_envelopes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("identity rows");
        assert_eq!(rows, (1, 1));
        let restored = portable_identity_envelope(&snapshot, &root, &membership)
            .expect("portable identity")
            .expect("present");
        assert_eq!(restored.encode(), portable.encode());
    }

    #[test]
    fn portable_identity_round_trips_through_the_catalog() {
        let root = Key::new([1; 32]);
        let key = CatalogKey::derive(&root, &id(2)).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("catalog");
        open_at_current_version(&mut db, 1).expect("schema");
        let identity = DeviceIdentity::from_seeds([3; 32], [4; 32]);
        let enrollment = EnrollmentRecord::initial(
            id(2),
            id(5),
            identity.signing_public_key(),
            identity.hpke_public_key(),
        )
        .expect("enrollment")
        .sign(identity.signing_key());
        let membership = sync_membership::provision(&mut db, &enrollment).expect("membership");
        let envelope = DeviceIdentityEnvelope::seal_for_recovery(
            &root,
            id(2),
            id(5),
            1,
            Nonce::new([6; 24]),
            &identity,
        )
        .expect("envelope");

        let wrong_identity = DeviceIdentity::from_seeds([7; 32], [8; 32]);
        let wrong_envelope = DeviceIdentityEnvelope::seal_for_recovery(
            &root,
            id(2),
            id(5),
            1,
            Nonce::new([9; 24]),
            &wrong_identity,
        )
        .expect("wrong envelope");
        let error = store_portable_identity_envelope(&mut db, &root, &membership, &wrong_envelope)
            .expect_err("membership key substitution must fail");
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);

        store_portable_identity_envelope(&mut db, &root, &membership, &envelope).expect("store");
        let generation = crate::schema::generation(&db).expect("generation");
        store_portable_identity_envelope(&mut db, &root, &membership, &envelope)
            .expect("idempotent store");
        assert_eq!(
            crate::schema::generation(&db).expect("same generation"),
            generation
        );
        let restored = portable_identity_envelope(&db, &root, &membership)
            .expect("load")
            .expect("present");
        assert_eq!(restored.encode(), envelope.encode());
    }

    #[test]
    fn local_identity_round_trips_without_exposing_seed_bytes() {
        let root = Key::new([11; 32]);
        let key = CatalogKey::derive(&root, &id(12)).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("catalog");
        open_at_current_version(&mut db, 1).expect("schema");
        let identity = DeviceIdentity::from_seeds([13; 32], [14; 32]);
        let enrollment = EnrollmentRecord::initial(
            id(12),
            id(15),
            identity.signing_public_key(),
            identity.hpke_public_key(),
        )
        .expect("enrollment")
        .sign(identity.signing_key());
        let membership = sync_membership::provision(&mut db, &enrollment).expect("membership");
        let envelope = DeviceIdentityEnvelope::seal_for_local(
            &root,
            id(12),
            id(15),
            1,
            Nonce::new([16; 24]),
            &identity,
        )
        .expect("envelope");

        store_local_identity_envelope(&mut db, &root, &membership, &envelope).expect("store");
        let (device_id, restored) = local_identity(&db, &root, &membership)
            .expect("load")
            .expect("present");
        assert_eq!(device_id, id(15));
        assert_eq!(restored.signing_public_key(), identity.signing_public_key());
        assert_eq!(restored.hpke_public_key(), identity.hpke_public_key());
        let error = match portable_identity_envelope(&db, &root, &membership) {
            Ok(_) => panic!("local identity entered recovery mode"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::CatalogCorrupt);
    }
}
