//! Disposable object-key requests and mutable local key custody.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Key, Nonce, random};
use chur_format::envelope::ObjectKeyEnvelope;
use chur_sync_protocol::{
    grant::PermissionProfile,
    object_grant::{ObjectKeyGrant, ObjectPrekey, object_key_commitment},
    state::DeviceStatus,
};
use rusqlite::{OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

use crate::db::map_sqlite;
use crate::{
    CatalogDb, sharing, sharing_publication, sharing_receive, sharing_service, store, sync_keys,
    sync_membership,
};

/// Requests the key of an authenticated pending object. A deleted object can
/// never cause another request, even when its server replays the creation log.
pub fn request(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    collection_id: Id,
    object_id: Id,
) -> Result<ObjectPrekey> {
    ensure_not_deleted(db, &collection_id, &object_id)?;
    let object = sharing_receive::pending_object_for_collection(
        db,
        root,
        local_vault_id,
        collection_id,
        object_id,
    )?;
    let membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "recipient membership is absent",
        )
    })?;
    ensure!(
        membership.vault_id() == &local_vault_id,
        AuthenticationFailed,
        "recipient vault differs"
    );
    let (device_id, identity) = sync_keys::local_identity(db, root, &membership)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "recipient identity is absent"))?;
    let stored: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT record FROM object_key_requests WHERE object_id = ?1 AND collection_id = ?2
         UNION ALL SELECT request_record FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2 LIMIT 1",
            params![object_id.as_bytes().as_slice(), collection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "object key request could not be read"))?;
    if let Some(bytes) = stored {
        let prekey = ObjectPrekey::decode(&bytes)?;
        ensure!(
            prekey.collection_id() == &collection_id && prekey.object_id() == &object_id,
            AuthenticationFailed,
            "stored object request belongs to another collection or object"
        );
        ensure!(
            prekey.object_generation() == object.object_generation
                && prekey.container_commitment() == &object.container_commitment,
            Conflict,
            "object changed after its key request"
        );
        ensure!(
            prekey.recipient_vault_id() == &local_vault_id,
            CatalogCorrupt,
            "stored prekey belongs to another vault"
        );
        if prekey.recipient_device_id() == &device_id {
            return Ok(prekey);
        }
        match pending_envelope(db, &collection_id, &object_id) {
            Ok(_) => return Ok(prekey),
            Err(error) if error.status() == ChurStatus::NotFound => {}
            Err(error) => return Err(error),
        }
        // A restored backup can retain an unaccepted request addressed to the
        // former device. After approved pairing, only a fresh request signed
        // by the new ordinary identity may be sent. Keep ready envelopes.
        db.transaction(|tx| {
            tx.execute(
                "DELETE FROM object_key_requests WHERE object_id = ?1 AND collection_id = ?2",
                params![
                    object_id.as_bytes().as_slice(),
                    collection_id.as_bytes().as_slice()
                ],
            )
            .map_err(|error| {
                map_sqlite(error, "the previous device prekey could not be retired")
            })?;
            Ok(())
        })?;
        db.checkpoint()?;
    }
    let private = random::secret::<32>()?;
    let prekey = ObjectPrekey::sign(
        random::id()?,
        collection_id,
        object_id,
        object.object_generation,
        object.container_commitment,
        local_vault_id,
        device_id,
        1,
        &private,
        identity.signing_key(),
    )?;
    db.transaction(|tx| {
        tx.execute(
            "INSERT INTO object_key_requests VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                object_id.as_bytes().as_slice(),
                collection_id.as_bytes().as_slice(),
                prekey.prekey_id().as_bytes().as_slice(),
                private.expose().as_slice(),
                prekey.encode()
            ],
        )
        .map_err(|error| map_sqlite(error, "object key request could not be stored"))?;
        Ok(())
    })?;
    Ok(prekey)
}

/// Delivers a key only for the exact active object requested by an authorized
/// recipient. Public grants can be retained without retaining a decryption key.
pub fn issue(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    prekey: &ObjectPrekey,
) -> Result<ObjectKeyGrant> {
    ensure_not_deleted(db, prekey.collection_id(), prekey.object_id())?;
    if prekey.recipient_vault_id() == &source_vault_id {
        ensure!(
            crate::own_sync::is_local_collection(db, prekey.collection_id())?,
            AuthenticationFailed,
            "own device request names an external collection"
        );
        let membership = sync_membership::load(db)?
            .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "own membership is absent"))?;
        ensure!(
            membership.vault_id() == &source_vault_id,
            AuthenticationFailed,
            "own source vault differs"
        );
        let recipient = membership
            .device(prekey.recipient_device_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "own request device is not enrolled",
                )
            })?;
        ensure!(
            recipient.status() == DeviceStatus::Active,
            AuthenticationFailed,
            "own request device is revoked"
        );
        prekey.verify(recipient.signing_public_key())?;
    } else {
        sharing_publication::ensure_ready(db, root, source_vault_id, *prekey.collection_id())?;
        let state = sharing::load(db, prekey.collection_id())?
            .ok_or_else(|| Error::new(ChurStatus::NotFound, "shared collection is absent"))?;
        ensure!(
            state.source_vault_id() == &source_vault_id
                && state.is_authorized(
                    prekey.recipient_vault_id(),
                    prekey.recipient_device_id(),
                    PermissionProfile::Read
                ),
            AuthenticationFailed,
            "object key request recipient is not authorized"
        );
        let member = state
            .member(prekey.recipient_vault_id(), prekey.recipient_device_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "request recipient is absent",
                )
            })?;
        prekey.verify(member.signing_public_key())?;
    }
    let candidate = sharing_publication::candidate(db, prekey.collection_id(), prekey.object_id())?;
    ensure!(
        candidate.object_generation == prekey.object_generation()
            && &candidate.container_commitment == prekey.container_commitment(),
        AuthenticationFailed,
        "object key request names another committed object"
    );
    let membership = sync_membership::load(db)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "source membership is absent"))?;
    let (device_id, identity) = sync_keys::local_identity(db, root, &membership)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "source identity is absent"))?;
    let previous: Option<(Vec<u8>, Vec<u8>)> = db.connection().query_row(
        "SELECT request_record, grant_record FROM issued_object_key_grants WHERE prekey_id = ?1",
        [prekey.prekey_id().as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(|error| map_sqlite(error, "issued object grant could not be read"))?;
    if let Some((request, grant)) = previous {
        ensure!(
            request == prekey.encode(),
            AuthenticationFailed,
            "prekey identity was reused"
        );
        let grant = ObjectKeyGrant::decode(&grant)?;
        ensure!(
            grant.source_vault_id() == &source_vault_id && grant.prekey_id() == prekey.prekey_id(),
            CatalogCorrupt,
            "cached object grant has another binding"
        );
        if membership.is_active(grant.source_device_id())
            && membership
                .device(grant.source_device_id())
                .is_some_and(|sender| grant.verify(sender.signing_public_key()).is_ok())
        {
            return Ok(grant);
        }
        // An authorized sibling reissues a public response whose old signer
        // was revoked or rotated. The recipient's disposable request survives.
    }
    let envelope = ObjectKeyEnvelope::decode(&store::active_envelope(db, prekey.object_id())?)?;
    let collection_key = sync_keys::collection_key(
        db,
        root,
        source_vault_id,
        *prekey.collection_id(),
        envelope.collection_epoch(),
    )?;
    let key = envelope.open(&collection_key)?;
    let grant = ObjectKeyGrant::seal(
        random::id()?,
        source_vault_id,
        device_id,
        candidate.object_id,
        candidate.object_generation,
        candidate.container_commitment,
        prekey,
        &key,
        identity.signing_key(),
    )?;
    db.transaction(|tx| {
        tx.execute(
            "DELETE FROM issued_object_key_grants WHERE prekey_id = ?1",
            [prekey.prekey_id().as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "stale public object grant could not be retired"))?;
        // This is a public response cache, not key custody or chain state.
        // Eviction is safe because a retry can issue another equivalent grant.
        tx.execute(
            "DELETE FROM issued_object_key_grants WHERE rowid IN (
            SELECT rowid FROM issued_object_key_grants ORDER BY rowid
            LIMIT max(0, (SELECT count(*) FROM issued_object_key_grants) - 4095))",
            [],
        )
        .map_err(|error| map_sqlite(error, "object grant cache could not be bounded"))?;
        tx.execute(
            "INSERT INTO issued_object_key_grants VALUES (?1, ?2, ?3, ?4)",
            params![
                prekey.prekey_id().as_bytes().as_slice(),
                candidate.object_id.as_bytes().as_slice(),
                prekey.encode(),
                grant.encode()
            ],
        )
        .map_err(|error| map_sqlite(error, "object key grant could not be stored"))?;
        Ok(())
    })?;
    Ok(grant)
}

/// Accepts a grant once, stores a local envelope, and destroys its disposable
/// private key before success. A restart or duplicate grant does not need it.
pub fn accept(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    issuers: &[sharing_service::IssuerEvidence<'_>],
    grant: &ObjectKeyGrant,
) -> Result<()> {
    ensure_not_deleted(db, grant.collection_id(), grant.object_id())?;
    let membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "recipient membership is absent",
        )
    })?;
    ensure!(
        membership.vault_id() == &local_vault_id,
        AuthenticationFailed,
        "recipient vault differs"
    );
    let (device_id, _) = sync_keys::local_identity(db, root, &membership)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "recipient identity is absent"))?;
    ensure!(
        grant.recipient_vault_id() == &local_vault_id && grant.recipient_device_id() == &device_id,
        AuthenticationFailed,
        "object grant addresses another recipient"
    );
    let source = if grant.source_vault_id() == &local_vault_id {
        ensure!(
            crate::own_sync::is_local_collection(db, grant.collection_id())?,
            AuthenticationFailed,
            "own grant names an external collection"
        );
        membership.clone()
    } else {
        let state = sharing::load(db, grant.collection_id())?
            .ok_or_else(|| Error::new(ChurStatus::NotFound, "shared collection is absent"))?;
        ensure!(
            grant.source_vault_id() == state.source_vault_id()
                && state.is_authorized(&local_vault_id, &device_id, PermissionProfile::Read),
            AuthenticationFailed,
            "object grant addresses another collection member"
        );
        let (states, _) = sharing_service::authenticate_issuers(issuers)?;
        let (generation, state) = states
            .get(grant.source_vault_id())
            .and_then(|history| history.last_key_value())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "object grant source membership is absent",
                )
            })?;
        sharing_service::ensure_not_below_accepted_issuer(
            db,
            grant.source_vault_id(),
            *generation,
        )?;
        state.clone()
    };
    let sender = source.device(grant.source_device_id()).ok_or_else(|| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "object grant sender is unknown",
        )
    })?;
    ensure!(
        sender.status() == DeviceStatus::Active,
        AuthenticationFailed,
        "object grant sender is revoked"
    );
    grant.verify(sender.signing_public_key())?;
    if store::object_present(db, grant.object_id())? {
        let object = store::object(db, grant.object_id())?;
        ensure!(
            object.state == chur_format::constants::ObjectState::Active,
            NotFound,
            "object is not active"
        );
        ensure!(
            object.collection_id == *grant.collection_id()
                && object.object_generation == grant.object_generation(),
            AuthenticationFailed,
            "object grant differs from the active object"
        );
        let candidate =
            sharing_publication::candidate(db, grant.collection_id(), grant.object_id())?;
        ensure!(
            &candidate.container_commitment == grant.container_commitment(),
            AuthenticationFailed,
            "object grant differs from the active container"
        );
        let envelope = ObjectKeyEnvelope::decode(&store::active_envelope(db, grant.object_id())?)?;
        ensure!(
            envelope.vault_id() == &local_vault_id
                && envelope.collection_id() == grant.collection_id()
                && envelope.object_id() == grant.object_id(),
            AuthenticationFailed,
            "active object envelope has another binding"
        );
        let collection_key = sync_keys::collection_key(
            db,
            root,
            local_vault_id,
            *grant.collection_id(),
            envelope.collection_epoch(),
        )?;
        let key = envelope.open(&collection_key)?;
        ensure!(
            &object_key_commitment(grant.collection_id(), grant.object_id(), &key)
                == grant.object_key_commitment(),
            AuthenticationFailed,
            "object grant differs from the protected active key"
        );
        return db.checkpoint();
    }
    let expected = sharing_receive::pending_object_for_collection(
        db,
        root,
        local_vault_id,
        *grant.collection_id(),
        *grant.object_id(),
    )?;
    ensure!(
        expected.object_generation == grant.object_generation()
            && &expected.container_commitment == grant.container_commitment()
            && &expected.object_key_commitment == grant.object_key_commitment(),
        AuthenticationFailed,
        "object grant differs from the authenticated commit"
    );
    let previous: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT grant_record FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2",
            params![grant.object_id().as_bytes().as_slice(), grant.collection_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "pending object key could not be read"))?;
    if let Some(previous) = previous {
        let previous = ObjectKeyGrant::decode(&previous)?;
        ensure!(
            previous.prekey_id() == grant.prekey_id(),
            AuthenticationFailed,
            "object has a different pending request"
        );
        // The signature and accepted commit were checked above. A response
        // reissued after public-cache eviction can have a new HPKE nonce.
        return db.checkpoint();
    }
    let (record, private): (Vec<u8>, Vec<u8>) = db.connection().query_row(
        "SELECT record, private_key FROM object_key_requests WHERE object_id = ?1 AND prekey_id = ?2 AND collection_id = ?3",
        params![grant.object_id().as_bytes().as_slice(), grant.prekey_id().as_bytes().as_slice(), grant.collection_id().as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|error| map_sqlite(error, "object grant has no live key request"))?;
    let private = Zeroizing::new(private);
    ensure!(
        private.len() == 32,
        CatalogCorrupt,
        "object prekey secret is malformed"
    );
    let mut secret = Key::zeroed();
    secret.expose_mut().copy_from_slice(&private);
    let prekey = ObjectPrekey::decode(&record)?;
    let key = grant.open(&prekey, &secret, sender.signing_public_key())?;
    ensure!(
        object_key_commitment(grant.collection_id(), grant.object_id(), &key)
            == expected.object_key_commitment,
        AuthenticationFailed,
        "object key commitment differs"
    );
    let collection = store::collection(db, grant.collection_id())?;
    let collection_key = sync_keys::collection_key(
        db,
        root,
        local_vault_id,
        *grant.collection_id(),
        collection.current_epoch,
    )?;
    let envelope = ObjectKeyEnvelope::seal(
        &collection_key,
        local_vault_id,
        *grant.collection_id(),
        collection.current_epoch,
        *grant.object_id(),
        1,
        Nonce::random()?,
        &key,
    )?;
    db.transaction(|tx| {
        tx.execute(
            "INSERT INTO pending_object_keys VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                grant.object_id().as_bytes().as_slice(),
                grant.collection_id().as_bytes().as_slice(),
                record,
                grant.encode(),
                envelope.encode()
            ],
        )
        .map_err(|error| map_sqlite(error, "pending object key could not be stored"))?;
        tx.execute(
            "DELETE FROM object_key_requests WHERE object_id = ?1 AND collection_id = ?2",
            params![
                grant.object_id().as_bytes().as_slice(),
                grant.collection_id().as_bytes().as_slice()
            ],
        )
        .map_err(|error| map_sqlite(error, "object prekey could not be destroyed"))?;
        Ok(())
    })?;
    db.checkpoint()
}

/// Reads the local key custody row required by container activation.
pub fn pending_envelope(
    db: &CatalogDb,
    collection_id: &Id,
    object_id: &Id,
) -> Result<ObjectKeyEnvelope> {
    let bytes: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT envelope FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2",
            params![
                object_id.as_bytes().as_slice(),
                collection_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "object key grant has not arrived"))?;
    let envelope = ObjectKeyEnvelope::decode(&bytes)?;
    ensure!(
        envelope.collection_id() == collection_id && envelope.object_id() == object_id,
        CatalogCorrupt,
        "pending object envelope has another custody binding"
    );
    ensure_not_deleted(db, collection_id, object_id)?;
    Ok(envelope)
}

/// Removes temporary local key custody after atomic object activation.
pub fn remove_pending(tx: &Transaction<'_>, collection_id: &Id, object_id: &Id) -> Result<()> {
    tx.execute(
        "DELETE FROM pending_object_keys WHERE object_id = ?1 AND collection_id = ?2",
        params![
            object_id.as_bytes().as_slice(),
            collection_id.as_bytes().as_slice()
        ],
    )
    .map_err(|error| map_sqlite(error, "pending object key could not be removed"))?;
    Ok(())
}

/// Returns a stable not-found verdict for locally erased objects.
pub(crate) fn ensure_not_deleted(db: &CatalogDb, collection_id: &Id, object_id: &Id) -> Result<()> {
    let deleted: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM tombstones WHERE object_id = ?1 AND collection_id = ?2",
            params![
                object_id.as_bytes().as_slice(),
                collection_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "local object tombstone could not be read"))?;
    ensure!(
        deleted == 0,
        NotFound,
        "object was permanently deleted on this device"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        db::{CatalogKey, CatalogLocation},
        model::{COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE, Collection},
        schema,
        sharing_log::DurableCollectionOperationLog,
        sync_log, sync_receive,
    };
    use chur_format::envelope::CollectionKeyEnvelope;
    use chur_sync_protocol::{
        KeyDomain,
        collection_operation::CollectionOperation,
        operation::Operation,
        payload::{OperationPayload, PayloadBody},
    };
    fn id(value: u8) -> Id {
        Id::new([value; 16]).expect("id")
    }
    #[test]
    fn unavailable_requests_do_not_starve_later_keys_or_evict_asynchronous_replies() {
        recipient_key_fixture(false, false, false);
    }
    #[test]
    fn active_object_rejects_wrong_signed_grant_before_idempotent_acknowledgment() {
        recipient_key_fixture(true, false, false);
    }
    #[test]
    fn a_foreign_collection_purge_cannot_erase_pending_keys_or_block_later_arrival() {
        recipient_key_fixture(false, true, false);
    }
    #[test]
    fn a_foreign_request_created_first_cannot_block_another_collections_key_custody() {
        recipient_key_fixture(false, true, true);
    }
    fn recipient_key_fixture(check_active: bool, check_scope: bool, foreign_first: bool) {
        let source_vault = id(21);
        let collection = id(22);
        let source_root = Key::new([23; 32]);
        let mut source = CatalogDb::open(
            &CatalogLocation::Memory,
            &CatalogKey::derive(&source_root, &source_vault).expect("source key"),
        )
        .expect("source");
        schema::open_at_current_version(&mut source, 1).expect("source schema");
        let (source_enrollment, _) =
            sync_receive::provision_local_identity(&mut source, &source_root, source_vault)
                .expect("source identity");
        let metadata_key = Key::new([24; 32]);
        let envelope = CollectionKeyEnvelope::seal(
            &source_root,
            source_vault,
            collection,
            1,
            1,
            Nonce::new([25; 24]),
            &metadata_key,
        )
        .expect("collection envelope");
        store::put_collection_with_envelope(
            &mut source,
            &Collection {
                collection_id: collection,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &envelope.encode(),
        )
        .expect("source collection");
        let recipient_vault = id(26);
        let recipient_root = Key::new([27; 32]);
        let mut recipient = CatalogDb::open(
            &CatalogLocation::Memory,
            &CatalogKey::derive(&recipient_root, &recipient_vault).expect("recipient key"),
        )
        .expect("recipient");
        schema::open_at_current_version(&mut recipient, 1).expect("recipient schema");
        let (recipient_enrollment, _) = sync_receive::provision_local_identity(
            &mut recipient,
            &recipient_root,
            recipient_vault,
        )
        .expect("recipient identity");
        let prepared = sharing_service::prepare_share(
            &mut source,
            &source_root,
            source_vault,
            collection,
            &recipient_enrollment,
            PermissionProfile::Read,
            true,
        )
        .expect("authorized share");
        // A Contribute member whose modified client signs records recipients must skip.
        let member_vault = id(43);
        let member_root = Key::new([41; 32]);
        let mut member_db = CatalogDb::open(
            &CatalogLocation::Memory,
            &CatalogKey::derive(&member_root, &member_vault).expect("member key"),
        )
        .expect("member");
        schema::open_at_current_version(&mut member_db, 1).expect("member schema");
        let (member_enrollment, _) =
            sync_receive::provision_local_identity(&mut member_db, &member_root, member_vault)
                .expect("member identity");
        let member_membership = sync_membership::load(&member_db)
            .expect("membership")
            .expect("present");
        let (_, member_identity) =
            sync_keys::local_identity(&member_db, &member_root, &member_membership)
                .expect("member identity")
                .expect("present");
        let member_share = (!check_scope).then(|| {
            sharing_service::prepare_share(
                &mut source,
                &source_root,
                source_vault,
                collection,
                &member_enrollment,
                PermissionProfile::Contribute,
                true,
            )
            .expect("member share")
        });
        let records = sync_log::records_after(&source, source_enrollment.device_id(), 0)
            .expect("source evidence")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        let membership_records = [sharing_service::IssuerMembershipRecord::Enrollment(
            source_enrollment.clone(),
        )];
        let member_records = [sharing_service::IssuerMembershipRecord::Enrollment(
            member_enrollment.clone(),
        )];
        let member_evidence = sync_log::records_after(&member_db, member_enrollment.device_id(), 0)
            .expect("member evidence")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        let mut issuers = vec![sharing_service::IssuerEvidence {
            membership: &membership_records,
            operations: &records,
        }];
        let mut changes = vec![(
            prepared.membership().clone(),
            prepared.membership_operation().clone(),
        )];
        if let Some(share) = &member_share {
            issuers.push(sharing_service::IssuerEvidence {
                membership: &member_records,
                operations: &member_evidence,
            });
            changes.push((
                share.membership().clone(),
                share.membership_operation().clone(),
            ));
        }
        let source_membership = sync_membership::load(&source)
            .expect("membership")
            .expect("present");
        let (_, identity) = sync_keys::local_identity(&source, &source_root, &source_membership)
            .expect("source identity")
            .expect("present");
        let shared = sharing::load(&source, &collection)
            .expect("state")
            .expect("present");
        let domain = KeyDomain::collection(&metadata_key, &collection, 1).expect("domain");
        let mut log = DurableCollectionOperationLog::provision(
            &mut source,
            collection,
            1,
            *domain.selector(),
        )
        .expect("collection log");
        let mut commits = Vec::new();
        let mut objects = Vec::new();
        for marker in 1..=66u8 {
            let object = random::id().expect("object");
            let content = Key::new([marker; 32]);
            for body in [
                PayloadBody::CreateObject {
                    object_id: object,
                    object_generation: 1,
                    store_id: object,
                    stream_id: object,
                    metadata_fields: vec![],
                },
                PayloadBody::CommitObject {
                    object_id: object,
                    object_generation: 1,
                    store_id: object,
                    container_length: 1024,
                    container_commitment: [marker; 32],
                    object_key_commitment: object_key_commitment(&collection, &object, &content),
                },
            ] {
                commits.push(
                    log.author(
                        &mut source,
                        random::id().expect("operation id"),
                        source_vault,
                        *source_enrollment.device_id(),
                        domain.operation_key(),
                        Nonce::random().expect("nonce"),
                        &OperationPayload::new(collection, 1, body).expect("payload"),
                        identity.signing_key(),
                        &source_membership,
                        &source_membership,
                        &shared,
                    )
                    .expect("signed committed object"),
                );
            }
            objects.push((object, content));
        }
        // The rejected record stalls its device chain, so only a variant without later records from that device injects it.
        let rejected_id = random::id().expect("operation id");
        if !check_scope {
            // A modified client signs a second creation for an existing object.
            // Recipients must skip it, not fail the page. This test signs it
            // with the source device; the foreign-issuer cases are unit tests in sharing_log.
            source
                .transaction(|transaction| {
                    transaction
                        .execute("DROP INDEX sharing_object_single_create_commit", [])
                        .map_err(|error| crate::db::map_sqlite(error, "index drop"))
                })
                .expect("attacker client has no unique index");
            commits.push(
                log.author(
                    &mut source,
                    rejected_id,
                    source_vault,
                    *source_enrollment.device_id(),
                    domain.operation_key(),
                    Nonce::random().expect("nonce"),
                    &OperationPayload::new(
                        collection,
                        1,
                        PayloadBody::CreateObject {
                            object_id: objects[0].0,
                            object_generation: 1,
                            store_id: objects[0].0,
                            stream_id: objects[0].0,
                            metadata_fields: vec![],
                        },
                    )
                    .expect("payload"),
                    identity.signing_key(),
                    &source_membership,
                    &source_membership,
                    &shared,
                )
                .expect("signed repeated creation"),
            );
        }
        // The member signs a purge, which only the source may author, a payload for another
        // collection, and a payload version this build cannot read. All reach `receive` after the
        // source records and must not fail the page, whatever status each failure carries.
        let member_ids = [
            random::id().expect("operation id"),
            random::id().expect("operation id"),
            random::id().expect("operation id"),
        ];
        if member_share.is_some() {
            let plaintexts = [
                OperationPayload::new(
                    collection,
                    1,
                    PayloadBody::PurgeObject {
                        object_id: objects[0].0,
                        object_generation: 1,
                        authored_at_ms: 1,
                    },
                )
                .expect("payload")
                .encode(),
                OperationPayload::new(
                    id(99),
                    1,
                    PayloadBody::SetFavorite {
                        object_id: objects[0].0,
                        favorite: true,
                        removed_tokens: vec![],
                    },
                )
                .expect("payload")
                .encode(),
                vec![0xFF; 64],
            ];
            for (operation_id, payload) in member_ids.iter().zip(plaintexts) {
                commits.push(
                    CollectionOperation::seal(
                        *operation_id,
                        member_vault,
                        *member_enrollment.device_id(),
                        1,
                        [0; 32],
                        vec![],
                        *domain.selector(),
                        domain.operation_key(),
                        Nonce::random().expect("nonce"),
                        &payload,
                    )
                    .expect("member record")
                    .sign(member_identity.signing_key()),
                );
            }
        }
        let plan = sharing_receive::receive(
            &mut recipient,
            &recipient_root,
            recipient_vault,
            &issuers,
            &changes,
            prepared.grant(),
            prepared.grant_operation(),
            &commits,
        )
        .expect("authenticated collection receive");
        assert_eq!(plan.objects.len(), 66);
        assert_eq!(plan.pending_operations, 0);
        assert_eq!(plan.rejected_operations, if check_scope { 0 } else { 4 });
        for rejected in std::iter::once(rejected_id).chain(member_ids) {
            let stored: i64 = recipient
                .connection()
                .query_row(
                    "SELECT count(*) FROM sharing_operations WHERE operation_id = ?1",
                    [rejected.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("rejected row count");
            assert_eq!(stored, 0);
        }
        if member_share.is_some() {
            // A record sealed for a key this device does not hold yet is not the issuer's fault,
            // so it fails the page for the source and for a member alike.
            let payload = OperationPayload::new(
                collection,
                1,
                PayloadBody::SetFavorite {
                    object_id: objects[0].0,
                    favorite: true,
                    removed_tokens: vec![],
                },
            )
            .expect("payload")
            .encode();
            for (vault, device, signer) in [
                (
                    source_vault,
                    *source_enrollment.device_id(),
                    identity.signing_key(),
                ),
                (
                    member_vault,
                    *member_enrollment.device_id(),
                    member_identity.signing_key(),
                ),
            ] {
                let unkeyed = CollectionOperation::seal(
                    random::id().expect("operation id"),
                    vault,
                    device,
                    1,
                    [0; 32],
                    vec![],
                    random::id().expect("selector"),
                    domain.operation_key(),
                    Nonce::random().expect("nonce"),
                    &payload,
                )
                .expect("record for an unheld key")
                .sign(signer);
                let error = sharing_receive::receive(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    &issuers,
                    &changes,
                    prepared.grant(),
                    prepared.grant_operation(),
                    std::slice::from_ref(&unkeyed),
                )
                .err()
                .expect("an unheld key selector fails the page");
                assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
            }
        }
        let mut requests = std::collections::BTreeMap::new();
        for (index, (object, _)) in objects.iter().enumerate() {
            if foreign_first && index == 2 {
                continue;
            }
            requests.insert(
                index,
                request(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    collection,
                    *object,
                )
                .expect("every authenticated object can request its own key"),
            );
        }
        for index in [65usize, 0] {
            let (object, content) = &objects[index];
            let grant = ObjectKeyGrant::seal(
                random::id().expect("grant id"),
                source_vault,
                *source_enrollment.device_id(),
                *object,
                1,
                [index as u8 + 1; 32],
                &requests[&index],
                content,
                identity.signing_key(),
            )
            .expect("asynchronous signed grant");
            accept(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                &issuers,
                &grant,
            )
            .expect("grant acceptance");
            assert_eq!(
                pending_envelope(&recipient, &collection, object)
                    .expect("accepted local key")
                    .open(&metadata_key)
                    .expect("local envelope")
                    .expose(),
                content.expose()
            );
        }
        assert_eq!(
            request(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                collection,
                objects[1].0
            )
            .expect("unavailable neighbor retained")
            .encode(),
            requests[&1].encode()
        );
        let private_count: i64 = recipient
            .connection()
            .query_row("SELECT count(*) FROM object_key_requests", [], |row| {
                row.get(0)
            })
            .expect("pending count");
        assert_eq!(
            private_count,
            if foreign_first { 63 } else { 64 },
            "only accepted replies consume their own private keys"
        );
        if check_scope {
            // Both collections have real source-signed membership, metadata grants,
            // and causally valid content logs. The adversarial source controls the
            // object IDs of its own collection, not custody in another collection.
            let foreign = id(90);
            let foreign_key = Key::new([91; 32]);
            let envelope = CollectionKeyEnvelope::seal(
                &source_root,
                source_vault,
                foreign,
                1,
                1,
                Nonce::random().expect("nonce"),
                &foreign_key,
            )
            .expect("foreign envelope");
            store::put_collection_with_envelope(
                &mut source,
                &Collection {
                    collection_id: foreign,
                    current_epoch: 1,
                    policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                    created_revision: 1,
                    status: COLLECTION_STATUS_ACTIVE,
                },
                1,
                &envelope.encode(),
            )
            .expect("foreign collection");
            let share = sharing_service::prepare_share(
                &mut source,
                &source_root,
                source_vault,
                foreign,
                &recipient_enrollment,
                PermissionProfile::Read,
                true,
            )
            .expect("foreign authenticated share");
            let foreign_state = sharing::load(&source, &foreign)
                .expect("state")
                .expect("present");
            let domain = KeyDomain::collection(&foreign_key, &foreign, 1).expect("domain");
            let mut foreign_log = DurableCollectionOperationLog::provision(
                &mut source,
                foreign,
                1,
                *domain.selector(),
            )
            .expect("foreign log");
            let future = random::id().expect("future object");
            let mut foreign_keys =
                sync_keys::key_directory(&source, &source_root, source_vault).expect("source keys");
            foreign_keys
                .insert(KeyDomain::collection(&foreign_key, &foreign, 1).expect("domain"))
                .expect("foreign domain");
            let mut malicious = Vec::new();
            for object in [objects[1].0, objects[0].0, future] {
                for body in [
                    PayloadBody::CreateObject {
                        object_id: object,
                        object_generation: 1,
                        store_id: object,
                        stream_id: object,
                        metadata_fields: vec![],
                    },
                    PayloadBody::PurgeObject {
                        object_id: object,
                        object_generation: 1,
                        authored_at_ms: 10,
                    },
                ] {
                    malicious.push(
                        foreign_log
                            .author_with_keys(
                                &mut source,
                                &foreign_keys,
                                random::id().expect("operation"),
                                source_vault,
                                *source_enrollment.device_id(),
                                domain.operation_key(),
                                Nonce::random().expect("nonce"),
                                &OperationPayload::new(foreign, 1, body).expect("payload"),
                                identity.signing_key(),
                                &source_membership,
                                &source_membership,
                                &foreign_state,
                            )
                            .expect("valid foreign signed lifecycle"),
                    );
                }
            }
            // A second valid foreign create/commit copies a victim's public
            // container binding. It must not reuse or rotate the victim request.
            {
                let index = 2;
                let (object, content) = &objects[index];
                for body in [
                    PayloadBody::CreateObject {
                        object_id: *object,
                        object_generation: 1,
                        store_id: *object,
                        stream_id: *object,
                        metadata_fields: vec![],
                    },
                    PayloadBody::CommitObject {
                        object_id: *object,
                        object_generation: 1,
                        store_id: *object,
                        container_length: 1024,
                        container_commitment: [index as u8 + 1; 32],
                        object_key_commitment: object_key_commitment(&foreign, object, content),
                    },
                ] {
                    malicious.push(
                        foreign_log
                            .author_with_keys(
                                &mut source,
                                &foreign_keys,
                                random::id().expect("operation"),
                                source_vault,
                                *source_enrollment.device_id(),
                                domain.operation_key(),
                                Nonce::random().expect("nonce"),
                                &OperationPayload::new(foreign, 1, body).expect("payload"),
                                identity.signing_key(),
                                &source_membership,
                                &source_membership,
                                &foreign_state,
                            )
                            .expect("valid foreign copied commit"),
                    );
                }
            }
            let proof = sync_log::records_after(&source, source_enrollment.device_id(), 0)
                .expect("evidence")
                .iter()
                .map(|b| Operation::decode(b).expect("operation"))
                .collect::<Vec<_>>();
            let evidence = [sharing_service::IssuerEvidence {
                membership: &membership_records,
                operations: &proof,
            }];
            sharing_receive::receive(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                &evidence,
                &[(
                    share.membership().clone(),
                    share.membership_operation().clone(),
                )],
                share.grant(),
                share.grant_operation(),
                &malicious,
            )
            .expect("foreign purge accepted only in its own scope");
            let foreign_request = request(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                foreign,
                objects[2].0,
            )
            .expect("foreign collection owns an independent disposable request");
            let foreign_grant = ObjectKeyGrant::seal(
                random::id().expect("foreign grant"),
                source_vault,
                *source_enrollment.device_id(),
                objects[2].0,
                1,
                [3; 32],
                &foreign_request,
                &objects[2].1,
                identity.signing_key(),
            )
            .expect("foreign signed key grant");
            if !foreign_first {
                accept(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    &evidence,
                    &foreign_grant,
                )
                .expect("foreign pending envelope has independent custody");
            }
            let legitimate_request = request(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                collection,
                objects[2].0,
            )
            .expect("foreign request created first cannot deny legitimate collection custody");
            if foreign_first {
                requests.insert(2, legitimate_request.clone());
            }
            assert_ne!(foreign_request.prekey_id(), legitimate_request.prekey_id());
            assert_eq!(foreign_request.collection_id(), &foreign);
            assert_eq!(legitimate_request.collection_id(), &collection);
            let legitimate_grant = ObjectKeyGrant::seal(
                random::id().expect("legitimate grant"),
                source_vault,
                *source_enrollment.device_id(),
                objects[2].0,
                1,
                [3; 32],
                &legitimate_request,
                &objects[2].1,
                identity.signing_key(),
            )
            .expect("legitimate signed key grant");
            accept(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                &evidence,
                &legitimate_grant,
            )
            .expect("both collection custody rows can accept their own grants");
            if foreign_first {
                assert_eq!(
                    request(
                        &mut recipient,
                        &recipient_root,
                        recipient_vault,
                        foreign,
                        objects[2].0
                    )
                    .expect("legitimate grant preserves foreign private request")
                    .encode(),
                    foreign_request.encode()
                );
                accept(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    &evidence,
                    &foreign_grant,
                )
                .expect("the original foreign private prekey can still decrypt its reply");
            }
            for (scope, metadata) in [(foreign, &foreign_key), (collection, &metadata_key)] {
                assert_eq!(
                    pending_envelope(&recipient, &scope, &objects[2].0)
                        .expect("scoped envelope")
                        .open(metadata)
                        .expect("independent key")
                        .expose(),
                    objects[2].1.expose()
                );
            }
            assert_eq!(
                request(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    collection,
                    objects[2].0
                )
                .expect("victim request unchanged")
                .encode(),
                requests[&2].encode()
            );
            recipient
                .transaction(|tx| remove_pending(tx, &collection, &objects[2].0))
                .expect("remove only legitimate temporary key");
            assert!(
                pending_envelope(&recipient, &foreign, &objects[2].0).is_ok(),
                "removing one collection must keep its neighbor key"
            );
            assert_eq!(
                request(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    collection,
                    objects[1].0
                )
                .expect("victim private key survives")
                .encode(),
                requests[&1].encode()
            );
            assert_eq!(
                pending_envelope(&recipient, &collection, &objects[0].0)
                    .expect("victim accepted envelope survives")
                    .open(&metadata_key)
                    .expect("victim content key")
                    .expose(),
                objects[0].1.expose()
            );
            let content = Key::new([92; 32]);
            let mut arrival = Vec::new();
            for body in [
                PayloadBody::CreateObject {
                    object_id: future,
                    object_generation: 1,
                    store_id: future,
                    stream_id: future,
                    metadata_fields: vec![],
                },
                PayloadBody::CommitObject {
                    object_id: future,
                    object_generation: 1,
                    store_id: future,
                    container_length: 1024,
                    container_commitment: [92; 32],
                    object_key_commitment: object_key_commitment(&collection, &future, &content),
                },
            ] {
                arrival.push(
                    log.author(
                        &mut source,
                        random::id().expect("operation"),
                        source_vault,
                        *source_enrollment.device_id(),
                        KeyDomain::collection(&metadata_key, &collection, 1)
                            .expect("domain")
                            .operation_key(),
                        Nonce::random().expect("nonce"),
                        &OperationPayload::new(collection, 1, body).expect("payload"),
                        identity.signing_key(),
                        &source_membership,
                        &source_membership,
                        &shared,
                    )
                    .expect("legitimate later arrival"),
                );
            }
            sharing_receive::receive(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                &evidence,
                &changes,
                prepared.grant(),
                prepared.grant_operation(),
                &arrival,
            )
            .expect("later victim collection remains receivable");
            request(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                collection,
                future,
            )
            .expect("foreign preemptive purge does not block victim request");
            return;
        }
        if check_active {
            use crate::model::{MetadataRevision, Object, Stream};
            use chur_format::constants::{IntegritySummary, MediaClass, ObjectState, StreamKind};
            let (object, content) = &objects[65];
            let local =
                pending_envelope(&recipient, &collection, object).expect("accepted local key");
            store::activate_object(
                &mut recipient,
                &store::ObjectActivation {
                    object: Object {
                        object_id: *object,
                        object_generation: 1,
                        collection_id: collection,
                        primary_stream_id: *object,
                        media_kind: MediaClass::Image,
                        capture_time_ms: 1,
                        import_time_ms: 1,
                        capture_time_substituted: false,
                        plaintext_size: 16,
                        width: 1,
                        height: 1,
                        duration_ms: 0,
                        favorite: false,
                        state: ObjectState::Active,
                        integrity_summary: IntegritySummary::CompleteVerified,
                        thumbnail_ready: false,
                        active_metadata_revision: 1,
                    },
                    stream: Stream {
                        stream_id: *object,
                        object_id: *object,
                        stream_kind: StreamKind::Original,
                        stream_revision: 1,
                        source_content_revision: 0,
                        container_path_id: *object,
                        container_version: 1,
                        suite_id: 1,
                        ciphertext_size: 1024,
                        plaintext_size: 16,
                        chunk_size: 262144,
                        complete_verified_ms: Some(1),
                        final_commitment: [66; 32],
                    },
                    envelope: local.encode(),
                    envelope_generation: local.envelope_generation(),
                    metadata: MetadataRevision {
                        object_id: *object,
                        revision: 1,
                        active: true,
                        record: vec![1],
                        original_filename: None,
                        caption: None,
                        content_type: "image/jpeg".into(),
                        capture_time_ms: Some(1),
                        width: 1,
                        height: 1,
                        duration_ms: 0,
                    },
                },
            )
            .expect("activate healthy protected object");
            let bad = ObjectKeyGrant::seal(
                random::id().expect("bad grant id"),
                source_vault,
                *source_enrollment.device_id(),
                *object,
                1,
                [66; 32],
                &requests[&65],
                &Key::new([201; 32]),
                identity.signing_key(),
            )
            .expect("authorized source signs a wrong object key");
            assert_eq!(
                accept(
                    &mut recipient,
                    &recipient_root,
                    recipient_vault,
                    &issuers,
                    &bad
                )
                .err()
                .map(|error| error.status()),
                Some(ChurStatus::AuthenticationFailed),
                "active media must not success-ack a mismatching key commitment"
            );
            let recipient_membership = sync_membership::load(&recipient)
                .expect("recipient membership")
                .expect("present");
            let (recipient_device, recipient_identity) =
                sync_keys::local_identity(&recipient, &recipient_root, &recipient_membership)
                    .expect("recipient identity")
                    .expect("present");
            for (generation, commitment) in [(2, [66; 32]), (1, [202; 32])] {
                let alternate = ObjectPrekey::sign(
                    random::id().expect("alternate request"),
                    collection,
                    *object,
                    generation,
                    commitment,
                    recipient_vault,
                    recipient_device,
                    1,
                    &Key::new([203; 32]),
                    recipient_identity.signing_key(),
                )
                .expect("bound alternate request");
                let malformed = ObjectKeyGrant::seal(
                    random::id().expect("alternate grant"),
                    source_vault,
                    *source_enrollment.device_id(),
                    *object,
                    generation,
                    commitment,
                    &alternate,
                    content,
                    identity.signing_key(),
                )
                .expect("authorized source signs incorrect binding");
                assert_eq!(
                    accept(
                        &mut recipient,
                        &recipient_root,
                        recipient_vault,
                        &issuers,
                        &malformed
                    )
                    .err()
                    .map(|error| error.status()),
                    Some(ChurStatus::AuthenticationFailed),
                    "an active original rejects another generation or container"
                );
            }
            let healthy = ObjectKeyGrant::seal(
                random::id().expect("healthy grant id"),
                source_vault,
                *source_enrollment.device_id(),
                *object,
                1,
                [66; 32],
                &requests[&65],
                content,
                identity.signing_key(),
            )
            .expect("healthy retry");
            accept(
                &mut recipient,
                &recipient_root,
                recipient_vault,
                &issuers,
                &healthy,
            )
            .expect("valid active grant retry");
            assert_eq!(
                store::active_envelope(&recipient, object).expect("protected key remains"),
                local.encode()
            );
            assert!(
                pending_envelope(&recipient, &collection, object).is_err(),
                "active retry must not recreate a private request or pending key"
            );
        }
    }
}
