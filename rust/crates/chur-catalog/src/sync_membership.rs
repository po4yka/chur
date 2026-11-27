//! Durable device membership in catalog v2.
//!
//! `chur-sync-protocol` remains the only validator. This module replays its
//! canonical records when opening and writes the accepted record plus every
//! projection in one SQLCipher transaction.

use std::collections::BTreeSet;

use chur_core::{ChurStatus, Error, Id, Result, bail, ensure};
use chur_crypto::Commitment;
use chur_sync_protocol::{
    membership::{EnrollmentRecord, RevocationRecord},
    state::{DeviceStatus, MembershipState},
};
use rusqlite::{Transaction, params};

use crate::{
    db::{CatalogDb, as_sqlite_integer, from_sqlite_integer, map_sqlite},
    schema::bump_generation,
};

const ENROLLMENT: i64 = 1;
const REVOCATION: i64 = 2;
const ACTIVE: i64 = 1;
const REVOKED: i64 = 2;

/// Replays and verifies the accepted membership chain and its projections.
pub fn load(db: &CatalogDb) -> Result<Option<MembershipState>> {
    let state_count: i64 = db
        .connection()
        .query_row("SELECT count(*) FROM sync_state", [], |row| row.get(0))
        .map_err(|error| map_sqlite(error, "sync state could not be counted"))?;
    if state_count == 0 {
        let partial: i64 = db
            .connection()
            .query_row(
                "SELECT
                    (SELECT count(*) FROM sync_membership_records) +
                    (SELECT count(*) FROM sync_devices) +
                    (SELECT count(*) FROM sync_signing_keys) +
                    (SELECT count(*) FROM sync_identity_envelopes)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "sync membership could not be inspected"))?;
        ensure!(
            partial == 0,
            CatalogCorrupt,
            "sync membership exists without sync state"
        );
        return Ok(None);
    }
    ensure!(
        state_count == 1,
        CatalogCorrupt,
        "the catalog carries more than one sync state"
    );

    let (stored_generation, stored_commitment): (i64, Vec<u8>) = db
        .connection()
        .query_row(
            "SELECT membership_generation, membership_commitment FROM sync_state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| map_sqlite(error, "sync state could not be read"))?;
    let stored_generation =
        from_sqlite_integer(stored_generation, "the membership generation is negative")?;
    let stored_commitment = commitment(&stored_commitment, "the membership head is malformed")?;
    let state = replay_chain(db, None)?;
    ensure!(
        state.generation() == stored_generation && state.commitment() == &stored_commitment,
        CatalogCorrupt,
        "sync state contradicts the membership chain"
    );
    validate_device_projections(db, &state)?;
    Ok(Some(state))
}

/// Replays the local chain up to one earlier accepted generation.
///
/// A sharing record names the issuer generation it was authored at. A sibling
/// that has since accepted another enrollment or revocation verifies it against
/// that historical state, as `sharing_service` does for external issuers.
pub(crate) fn load_at_generation(db: &CatalogDb, generation: u64) -> Result<MembershipState> {
    ensure!(
        generation != 0,
        AuthenticationFailed,
        "issuer membership generation is absent"
    );
    let state = replay_chain(db, Some(generation))?;
    ensure!(
        state.generation() == generation,
        AuthenticationFailed,
        "issuer membership generation is absent"
    );
    Ok(state)
}

fn replay_chain(db: &CatalogDb, through: Option<u64>) -> Result<MembershipState> {
    let mut statement = db
        .connection()
        .prepare(
            "SELECT membership_generation, record_kind, device_id, commitment, record
               FROM sync_membership_records ORDER BY membership_generation",
        )
        .map_err(|error| map_sqlite(error, "membership records could not be prepared"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite(error, "membership records could not be read"))?;
    let mut state: Option<MembershipState> = None;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "a membership record could not be read"))?
    {
        let generation: i64 = row
            .get(0)
            .map_err(|error| map_sqlite(error, "a membership generation could not be read"))?;
        let kind: i64 = row
            .get(1)
            .map_err(|error| map_sqlite(error, "a membership kind could not be read"))?;
        let device_bytes: Vec<u8> = row
            .get(2)
            .map_err(|error| map_sqlite(error, "a membership device could not be read"))?;
        let commitment_bytes: Vec<u8> = row
            .get(3)
            .map_err(|error| map_sqlite(error, "a membership commitment could not be read"))?;
        let record: Vec<u8> = row
            .get(4)
            .map_err(|error| map_sqlite(error, "a membership record could not be read"))?;
        let generation = from_sqlite_integer(generation, "a membership generation is negative")?;
        if through.is_some_and(|limit| generation > limit) {
            break;
        }
        let device_id = crate::row::id(&device_bytes, "a membership device id is malformed")?;
        let stored = commitment(&commitment_bytes, "a membership commitment is malformed")?;

        match kind {
            ENROLLMENT => {
                let enrollment = EnrollmentRecord::decode(&record).map_err(corrupt_membership)?;
                ensure!(
                    enrollment.membership_generation() == generation
                        && enrollment.device_id() == &device_id
                        && enrollment.commitment() == stored,
                    CatalogCorrupt,
                    "an enrollment contradicts its catalog row"
                );
                if let Some(current) = state.as_mut() {
                    current
                        .accept_enrollment(
                            &enrollment,
                            enrollment.issuer_device_id(),
                            enrollment.created_sequence(),
                        )
                        .map_err(corrupt_membership)?;
                } else {
                    state =
                        Some(MembershipState::bootstrap(&enrollment).map_err(corrupt_membership)?);
                }
            }
            REVOCATION => {
                let revocation = RevocationRecord::decode(&record).map_err(corrupt_membership)?;
                ensure!(
                    revocation.membership_generation() == generation
                        && revocation.revoked_device_id() == &device_id
                        && revocation.commitment() == stored,
                    CatalogCorrupt,
                    "a revocation contradicts its catalog row"
                );
                state
                    .as_mut()
                    .ok_or_else(|| {
                        Error::new(
                            ChurStatus::CatalogCorrupt,
                            "the membership chain starts with a revocation",
                        )
                    })?
                    .accept_revocation(&revocation, revocation.issuer_device_id())
                    .map_err(corrupt_membership)?;
            }
            _ => bail!(CatalogCorrupt, "a membership record kind is unallocated"),
        }
    }
    state.ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "sync state has no membership chain",
        )
    })
}

/// Authenticated historical key pairs for one local device, in generation order.
/// The full membership chain is replayed before these rows are used as evidence.
pub(crate) fn device_key_history(
    db: &CatalogDb,
    device_id: &Id,
) -> Result<Vec<([u8; 32], [u8; 32])>> {
    let state = load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "local membership history is absent",
        )
    })?;
    ensure!(
        state.device(device_id).is_some(),
        AuthenticationFailed,
        "local device is not enrolled"
    );
    let mut statement = db
        .connection()
        .prepare("SELECT record FROM sync_membership_records WHERE record_kind = ?1 ORDER BY membership_generation")
        .map_err(|error| map_sqlite(error, "local key history could not be prepared"))?;
    let mut rows = statement
        .query([ENROLLMENT])
        .map_err(|error| map_sqlite(error, "local key history could not be read"))?;
    let mut history = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "local key history could not be read"))?
    {
        let bytes: Vec<u8> = row
            .get(0)
            .map_err(|error| map_sqlite(error, "local enrollment could not be read"))?;
        let record = EnrollmentRecord::decode(&bytes).map_err(corrupt_membership)?;
        if record.device_id() == device_id {
            history.push((*record.signing_public_key(), *record.hpke_public_key()));
        }
    }
    ensure!(
        history.last().is_some_and(|(signing, hpke)| {
            state.device(device_id).is_some_and(|device| {
                signing == device.signing_public_key() && hpke == device.hpke_public_key()
            })
        }),
        CatalogCorrupt,
        "local key history contradicts current membership"
    );
    Ok(history)
}

/// Creates generation-one membership and every required projection atomically.
pub fn provision(db: &mut CatalogDb, enrollment: &EnrollmentRecord) -> Result<MembershipState> {
    db.transaction(|transaction| {
        let state = project_provision(transaction, enrollment)?;
        bump_generation(transaction)?;
        Ok(state)
    })
}

/// Loads the latest authenticated enrollment for one device.
pub fn enrollment_for_device(db: &CatalogDb, device_id: &Id) -> Result<EnrollmentRecord> {
    let record: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT record FROM sync_membership_records
              WHERE device_id = ?1 AND record_kind = ?2
              ORDER BY membership_generation DESC LIMIT 1",
            params![device_id.as_bytes().as_slice(), ENROLLMENT],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the device enrollment could not be read"))?;
    let enrollment = EnrollmentRecord::decode(&record).map_err(corrupt_membership)?;
    ensure!(
        enrollment.device_id() == device_id,
        CatalogCorrupt,
        "the device enrollment contradicts its lookup key"
    );
    Ok(enrollment)
}

pub(crate) fn project_provision(
    transaction: &Transaction<'_>,
    enrollment: &EnrollmentRecord,
) -> Result<MembershipState> {
    let state = MembershipState::bootstrap(enrollment)?;
    let present: i64 = transaction
        .query_row("SELECT count(*) FROM sync_state", [], |row| row.get(0))
        .map_err(|error| map_sqlite(error, "sync state could not be counted"))?;
    ensure!(
        present == 0,
        Conflict,
        "sync membership is already provisioned"
    );
    let head = enrollment.commitment();
    insert_membership_record(
        transaction,
        enrollment.membership_generation(),
        ENROLLMENT,
        enrollment.device_id(),
        &head,
        &enrollment.encode(),
    )?;
    upsert_active_device(transaction, enrollment)?;
    transaction
        .execute(
            "INSERT INTO sync_state
                 (only_row, membership_generation, membership_commitment,
                  latest_own_checkpoint_commitment)
             VALUES (1, ?1, ?2, NULL)",
            params![
                as_sqlite_integer(
                    enrollment.membership_generation(),
                    "the membership generation is too large"
                )?,
                head.as_slice(),
            ],
        )
        .map_err(|error| map_sqlite(error, "sync state could not be provisioned"))?;
    Ok(state)
}

/// Accepts one validated successor enrollment and updates key history atomically.
pub fn accept_enrollment(
    db: &mut CatalogDb,
    enrollment: &EnrollmentRecord,
    outer_device_id: &Id,
    outer_sequence: u64,
) -> Result<MembershipState> {
    let state = load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::VaultIncomplete,
            "sync membership is not provisioned",
        )
    })?;
    db.transaction(|transaction| {
        let candidate = project_enrollment(
            transaction,
            &state,
            enrollment,
            outer_device_id,
            outer_sequence,
        )?;
        bump_generation(transaction)?;
        Ok(candidate)
    })
}

/// Projects one validated successor enrollment inside its operation transaction.
pub fn project_enrollment(
    transaction: &Transaction<'_>,
    current: &MembershipState,
    enrollment: &EnrollmentRecord,
    outer_device_id: &Id,
    outer_sequence: u64,
) -> Result<MembershipState> {
    let previous_generation = current.generation();
    let previous_commitment = *current.commitment();
    let mut candidate = current.clone();
    candidate.accept_enrollment(enrollment, outer_device_id, outer_sequence)?;
    let head = enrollment.commitment();
    insert_membership_record(
        transaction,
        enrollment.membership_generation(),
        ENROLLMENT,
        enrollment.device_id(),
        &head,
        &enrollment.encode(),
    )?;
    upsert_active_device(transaction, enrollment)?;
    advance_head(
        transaction,
        previous_generation,
        &previous_commitment,
        enrollment.membership_generation(),
        &head,
    )?;
    Ok(candidate)
}

/// Accepts one validated device revocation and pins its final branch atomically.
pub fn accept_revocation(
    db: &mut CatalogDb,
    revocation: &RevocationRecord,
    outer_device_id: &Id,
) -> Result<MembershipState> {
    let state = load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::VaultIncomplete,
            "sync membership is not provisioned",
        )
    })?;
    db.transaction(|transaction| {
        let candidate = project_revocation(transaction, &state, revocation, outer_device_id)?;
        bump_generation(transaction)?;
        Ok(candidate)
    })
}

/// Projects one validated revocation inside its operation transaction.
pub fn project_revocation(
    transaction: &Transaction<'_>,
    current: &MembershipState,
    revocation: &RevocationRecord,
    outer_device_id: &Id,
) -> Result<MembershipState> {
    project_revocation_state(transaction, current, revocation, outer_device_id, true)
}

/// A received signed revocation describes the issuer's accepted prefix, not
/// the receiver's possibly later local history.
pub(crate) fn project_received_revocation(
    transaction: &Transaction<'_>,
    current: &MembershipState,
    revocation: &RevocationRecord,
    outer: &chur_sync_protocol::operation::Operation,
) -> Result<MembershipState> {
    ensure!(
        revocation.final_accepted_device_sequence() != 0
            || outer
                .observed_heads()
                .iter()
                .all(|head| head.device_id() != revocation.revoked_device_id()),
        AuthenticationFailed,
        "genesis revocation observes its target's authored history"
    );
    project_revocation_state(transaction, current, revocation, outer.device_id(), false)
}

fn project_revocation_state(
    transaction: &Transaction<'_>,
    current: &MembershipState,
    revocation: &RevocationRecord,
    outer_device_id: &Id,
    local_author: bool,
) -> Result<MembershipState> {
    if local_author && revocation.final_accepted_device_sequence() == 0 {
        let authored: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_heads WHERE device_id = ?1 AND (accepted_sequence > 0 OR floor_sequence > 0))",
            [revocation.revoked_device_id().as_bytes().as_slice()], |row| row.get(0),
        ).map_err(|error| map_sqlite(error, "revocation genesis could not be verified"))?;
        ensure!(
            !authored,
            AuthenticationFailed,
            "genesis revocation names an authored device"
        );
    }
    let previous_generation = current.generation();
    let previous_commitment = *current.commitment();
    let mut candidate = current.clone();
    candidate.accept_revocation(revocation, outer_device_id)?;
    let head = revocation.commitment();
    insert_membership_record(
        transaction,
        revocation.membership_generation(),
        REVOCATION,
        revocation.revoked_device_id(),
        &head,
        &revocation.encode(),
    )?;
    let changed = transaction
        .execute(
            "UPDATE sync_devices
                SET status = ?2, membership_generation = ?3,
                    revoked_sequence = ?4, revoked_digest = ?5
              WHERE device_id = ?1 AND status = ?6",
            params![
                revocation.revoked_device_id().as_bytes().as_slice(),
                REVOKED,
                as_sqlite_integer(
                    revocation.membership_generation(),
                    "the membership generation is too large"
                )?,
                as_sqlite_integer(
                    revocation.final_accepted_device_sequence(),
                    "the revocation sequence is too large"
                )?,
                revocation.final_accepted_operation_digest().as_slice(),
                ACTIVE,
            ],
        )
        .map_err(|error| map_sqlite(error, "the revoked device could not be updated"))?;
    ensure!(
        changed == 1,
        Conflict,
        "the revocation projection changed concurrently"
    );
    advance_head(
        transaction,
        previous_generation,
        &previous_commitment,
        revocation.membership_generation(),
        &head,
    )?;
    Ok(candidate)
}

fn insert_membership_record(
    transaction: &Transaction<'_>,
    generation: u64,
    kind: i64,
    device_id: &Id,
    commitment: &Commitment,
    record: &[u8],
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO sync_membership_records
                 (membership_generation, record_kind, device_id, commitment, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                as_sqlite_integer(generation, "the membership generation is too large")?,
                kind,
                device_id.as_bytes().as_slice(),
                commitment.as_slice(),
                record,
            ],
        )
        .map_err(|error| map_sqlite(error, "the membership record could not be written"))?;
    Ok(())
}

fn upsert_active_device(
    transaction: &Transaction<'_>,
    enrollment: &EnrollmentRecord,
) -> Result<()> {
    let generation = as_sqlite_integer(
        enrollment.membership_generation(),
        "the membership generation is too large",
    )?;
    transaction
        .execute(
            "INSERT INTO sync_devices
                 (device_id, signing_public_key, hpke_public_key, status,
                  membership_generation, revoked_sequence, revoked_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)
             ON CONFLICT(device_id) DO UPDATE SET
                 signing_public_key = excluded.signing_public_key,
                 hpke_public_key = excluded.hpke_public_key,
                 status = excluded.status,
                 membership_generation = excluded.membership_generation,
                 revoked_sequence = NULL,
                 revoked_digest = NULL",
            params![
                enrollment.device_id().as_bytes().as_slice(),
                enrollment.signing_public_key().as_slice(),
                enrollment.hpke_public_key().as_slice(),
                ACTIVE,
                generation,
            ],
        )
        .map_err(|error| map_sqlite(error, "the device projection could not be written"))?;
    transaction
        .execute(
            "INSERT INTO sync_signing_keys
                 (device_id, membership_generation, public_key)
             VALUES (?1, ?2, ?3)",
            params![
                enrollment.device_id().as_bytes().as_slice(),
                generation,
                enrollment.signing_public_key().as_slice(),
            ],
        )
        .map_err(|error| map_sqlite(error, "the signing key history could not be written"))?;
    Ok(())
}

fn advance_head(
    transaction: &Transaction<'_>,
    previous_generation: u64,
    previous_commitment: &Commitment,
    generation: u64,
    commitment: &Commitment,
) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE sync_state
                SET membership_generation = ?1, membership_commitment = ?2
              WHERE only_row = 1
                AND membership_generation = ?3 AND membership_commitment = ?4",
            params![
                as_sqlite_integer(generation, "the membership generation is too large")?,
                commitment.as_slice(),
                as_sqlite_integer(
                    previous_generation,
                    "the previous membership generation is too large"
                )?,
                previous_commitment.as_slice(),
            ],
        )
        .map_err(|error| map_sqlite(error, "the membership head could not be advanced"))?;
    ensure!(
        changed == 1,
        Conflict,
        "the membership head changed concurrently"
    );
    Ok(())
}

fn validate_device_projections(db: &CatalogDb, state: &MembershipState) -> Result<()> {
    let mut statement = db
        .connection()
        .prepare(
            "SELECT device_id, signing_public_key, hpke_public_key, status,
                    membership_generation, revoked_sequence, revoked_digest
               FROM sync_devices ORDER BY device_id",
        )
        .map_err(|error| map_sqlite(error, "device projections could not be prepared"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite(error, "device projections could not be read"))?;
    let mut count = 0u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "a device projection could not be read"))?
    {
        let device_bytes: Vec<u8> = row
            .get(0)
            .map_err(|error| map_sqlite(error, "a device id could not be read"))?;
        let signing: Vec<u8> = row
            .get(1)
            .map_err(|error| map_sqlite(error, "a signing key could not be read"))?;
        let hpke: Vec<u8> = row
            .get(2)
            .map_err(|error| map_sqlite(error, "an HPKE key could not be read"))?;
        let status: i64 = row
            .get(3)
            .map_err(|error| map_sqlite(error, "a device status could not be read"))?;
        let generation: i64 = row
            .get(4)
            .map_err(|error| map_sqlite(error, "a device generation could not be read"))?;
        let revoked_sequence: Option<i64> = row
            .get(5)
            .map_err(|error| map_sqlite(error, "a revocation sequence could not be read"))?;
        let revoked_digest: Option<Vec<u8>> = row
            .get(6)
            .map_err(|error| map_sqlite(error, "a revocation digest could not be read"))?;
        let device_id = crate::row::id(&device_bytes, "a device id is malformed")?;
        let membership = state.device(&device_id).ok_or_else(|| {
            Error::new(
                ChurStatus::CatalogCorrupt,
                "a device projection is absent from membership",
            )
        })?;
        ensure!(
            signing.as_slice() == membership.signing_public_key()
                && hpke.as_slice() == membership.hpke_public_key(),
            CatalogCorrupt,
            "a device projection carries the wrong public keys"
        );
        match (
            status,
            revoked_sequence,
            revoked_digest,
            membership.status(),
        ) {
            (ACTIVE, None, None, DeviceStatus::Active) => {}
            (
                REVOKED,
                Some(sequence),
                Some(digest),
                DeviceStatus::Revoked {
                    sequence: expected_sequence,
                    digest: expected_digest,
                },
            ) => ensure!(
                from_sqlite_integer(sequence, "a revocation sequence is negative")?
                    == expected_sequence
                    && commitment(&digest, "a revocation digest is malformed")? == expected_digest,
                CatalogCorrupt,
                "a device revocation projection contradicts membership"
            ),
            _ => bail!(CatalogCorrupt, "a device status projection is malformed"),
        }
        let generation = from_sqlite_integer(generation, "a device generation is negative")?;
        let projection_source_exists: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_membership_records
                  WHERE membership_generation = ?1 AND record_kind = ?2 AND device_id = ?3",
                params![
                    as_sqlite_integer(generation, "a device generation is too large")?,
                    if status == ACTIVE {
                        ENROLLMENT
                    } else {
                        REVOCATION
                    },
                    device_id.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "a device enrollment could not be checked"))?;
        ensure!(
            projection_source_exists == 1,
            CatalogCorrupt,
            "a device projection has no matching membership record"
        );

        let expected_keys: BTreeSet<[u8; 32]> = membership.signing_public_keys().copied().collect();
        let mut key_statement = db
            .connection()
            .prepare("SELECT public_key FROM sync_signing_keys WHERE device_id = ?1")
            .map_err(|error| map_sqlite(error, "signing key history could not be prepared"))?;
        let keys = key_statement
            .query_map([device_id.as_bytes().as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|error| map_sqlite(error, "signing key history could not be read"))?;
        let mut stored_keys = BTreeSet::new();
        for key in keys {
            let key = key.map_err(|error| map_sqlite(error, "a signing key could not be read"))?;
            let key: [u8; 32] = key.try_into().map_err(|_| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "a signing key has the wrong length",
                )
            })?;
            stored_keys.insert(key);
        }
        ensure!(
            stored_keys == expected_keys,
            CatalogCorrupt,
            "signing key history contradicts membership"
        );
        count += 1;
    }
    let expected_count: i64 = db
        .connection()
        .query_row(
            "SELECT count(DISTINCT device_id) FROM sync_membership_records WHERE record_kind = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "enrolled devices could not be counted"))?;
    ensure!(
        count == from_sqlite_integer(expected_count, "the device count is negative")?,
        CatalogCorrupt,
        "the device projection count contradicts membership"
    );
    Ok(())
}

fn commitment(bytes: &[u8], context: &'static str) -> Result<Commitment> {
    bytes
        .try_into()
        .map_err(|_| Error::new(ChurStatus::CatalogCorrupt, context))
}

fn corrupt_membership(_: Error) -> Error {
    Error::new(
        ChurStatus::CatalogCorrupt,
        "stored membership does not authenticate",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{
        db::{CatalogKey, CatalogLocation},
        schema::open_at_current_version,
    };
    use chur_crypto::{Key, random};
    use chur_sync_protocol::operation::DeviceSigningKey;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn catalog() -> CatalogDb {
        let root: Key = random::secret::<32>().expect("root");
        let key = CatalogKey::derive(&root, &id(1)).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("catalog");
        open_at_current_version(&mut db, 1).expect("schema");
        db
    }

    #[test]
    fn membership_replays_key_rotation_and_revocation_after_reopen() {
        let mut db = catalog();
        let first_key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), first_key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&first_key);
        provision(&mut db, &initial).expect("provision");

        let peer_key = DeviceSigningKey::from_seed([4; 32]);
        let peer = EnrollmentRecord::new(
            id(1),
            id(5),
            peer_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [7; 32],
        )
        .expect("peer")
        .sign(&first_key);
        accept_enrollment(&mut db, &peer, &id(2), 2).expect("enroll peer");

        let rotated_key = DeviceSigningKey::from_seed([8; 32]);
        let rotation = EnrollmentRecord::new(
            id(1),
            id(2),
            rotated_key.verifying_key(),
            [9; 32],
            3,
            id(2),
            3,
            peer.commitment(),
            [10; 32],
        )
        .expect("rotation")
        .sign(&first_key);
        accept_enrollment(&mut db, &rotation, &id(2), 3).expect("rotate key");

        let revocation =
            RevocationRecord::new(id(1), id(5), 1, [11; 32], 4, id(2), rotation.commitment())
                .expect("revocation")
                .sign(&rotated_key);
        accept_revocation(&mut db, &revocation, &id(2)).expect("revoke peer");

        let state = load(&db).expect("load").expect("membership");
        assert_eq!(state.generation(), 4);
        assert!(!state.is_active(&id(5)));
        let keys: BTreeSet<_> = state
            .device(&id(2))
            .expect("issuer")
            .signing_public_keys()
            .copied()
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([first_key.verifying_key(), rotated_key.verifying_key()])
        );
    }

    #[test]
    fn rejected_successor_changes_no_durable_membership_row() {
        let mut db = catalog();
        let key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&key);
        provision(&mut db, &initial).expect("provision");
        let peer_key = DeviceSigningKey::from_seed([4; 32]);
        let stale = EnrollmentRecord::new(
            id(1),
            id(5),
            peer_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            [9; 32],
            [7; 32],
        )
        .expect("stale")
        .sign(&key);
        assert!(accept_enrollment(&mut db, &stale, &id(2), 2).is_err());
        let rows: i64 = db
            .connection()
            .query_row("SELECT count(*) FROM sync_membership_records", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(rows, 1);
        assert_eq!(
            load(&db).expect("load").expect("membership").generation(),
            1
        );
    }

    #[test]
    fn a_tampered_device_projection_fails_closed() {
        let mut db = catalog();
        let key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&key);
        provision(&mut db, &initial).expect("provision");
        db.connection()
            .execute(
                "UPDATE sync_devices SET signing_public_key = ?1 WHERE device_id = ?2",
                params![[9u8; 32], id(2).as_bytes().as_slice()],
            )
            .expect("tamper");
        let Err(error) = load(&db) else {
            panic!("the corrupt projection loaded");
        };
        assert_eq!(error.status(), ChurStatus::CatalogCorrupt);
    }
}
