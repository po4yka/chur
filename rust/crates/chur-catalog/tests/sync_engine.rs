//! Locked staging to unlocked catalog acceptance.

#![allow(clippy::expect_used)]

use chur_catalog::db::{CatalogKey, CatalogLocation};
use chur_catalog::model::{COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE, Collection};
use chur_catalog::paths::VaultRoot;
use chur_catalog::sync_engine::{self, StagedKind};
use chur_catalog::{
    CatalogDb, schema, store, sync_log, sync_membership, sync_receive, sync_staging::LockedStaging,
};
use chur_core::Id;
use chur_crypto::{Key, Nonce, random};
use chur_sync_protocol::KeyDomain;
use chur_sync_protocol::membership::{EnrollmentRecord, RevocationRecord};
use chur_sync_protocol::operation::{DeviceSigningKey, Operation};
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("id")
}

#[test]
fn unlocked_processing_removes_validated_records_and_reports_rejections() {
    let vault_id = id(1);
    let root = Key::new([2; 32]);
    let catalog_key = CatalogKey::derive(&root, &vault_id).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let signing_key = DeviceSigningKey::from_seed([3; 32]);
    let enrollment =
        EnrollmentRecord::initial(vault_id, id(4), signing_key.verifying_key(), [5; 32])
            .expect("enrollment")
            .sign(&signing_key);
    let (membership, mut log, operation) =
        sync_receive::provision_initial_membership(&mut db, &root, &signing_key, &enrollment)
            .expect("provision");
    let checkpoint = log
        .issue_own_checkpoint(&mut db, &membership, &id(4), &signing_key, 7)
        .expect("checkpoint");
    let path = std::env::temp_dir().join(format!(
        "chur-sync-engine-{}",
        random::id().expect("random id").to_hex()
    ));
    let vault_root = VaultRoot::new(&path);
    sync_engine::stage_inbound(
        &vault_root,
        vault_id,
        StagedKind::Operation,
        8,
        &operation.encode(),
    )
    .expect("stage operation");
    sync_engine::stage_inbound(
        &vault_root,
        vault_id,
        StagedKind::Checkpoint,
        9,
        &checkpoint.encode(),
    )
    .expect("stage checkpoint");
    sync_engine::stage_inbound(
        &vault_root,
        vault_id,
        StagedKind::Operation,
        10,
        b"malformed",
    )
    .expect("stage malformed");
    let mut staging = LockedStaging::open(vault_root.sync_inbox(&vault_id)).expect("staging");

    let report =
        sync_engine::process_staged(&mut db, &root, vault_id, &mut staging, 10).expect("process");

    assert_eq!(report.duplicates, 2);
    assert_eq!(report.rejected, 1);
    assert_eq!(
        report.first_rejection,
        Some(chur_core::ChurStatus::UnsupportedVersion)
    );
    assert_eq!(staging.len(10).expect("remaining"), 0);
    std::fs::remove_dir_all(path).expect("cleanup");
}

/// `ROLLBACK_PROTECTION.md` §4: junk staged ahead of a forked record cannot
/// hide the verdict.
///
/// Records are processed by staging time, so the malformed record is rejected
/// first. The engine then freezes the chain and drops the forked record, so the
/// report of this pass is the only place the fork can surface.
#[test]
fn a_fork_verdict_outranks_an_earlier_rejection() {
    let vault_id = id(1);
    let root = Key::new([2; 32]);
    let catalog_key = CatalogKey::derive(&root, &vault_id).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let signing_key = DeviceSigningKey::from_seed([3; 32]);
    let enrollment =
        EnrollmentRecord::initial(vault_id, id(4), signing_key.verifying_key(), [5; 32])
            .expect("enrollment")
            .sign(&signing_key);
    let (_, _, accepted) =
        sync_receive::provision_initial_membership(&mut db, &root, &signing_key, &enrollment)
            .expect("provision");

    let collection_id = id(30);
    let collection_key = Key::new([31; 32]);
    let envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &root,
        vault_id,
        collection_id,
        1,
        1,
        Nonce::new([32; 24]),
        &collection_key,
    )
    .expect("envelope");
    store::put_collection_with_envelope(
        &mut db,
        &Collection {
            collection_id,
            current_epoch: 1,
            policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: COLLECTION_STATUS_ACTIVE,
        },
        1,
        &envelope.encode(),
    )
    .expect("collection");
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateAlbum {
            album_id: id(20),
            name: "fork".to_owned(),
        },
    )
    .expect("payload")
    .encode();
    // A second signed record at the sequence the device already used.
    let fork = Operation::seal(
        id(21),
        vault_id,
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([21; 24]),
        &payload,
    )
    .expect("fork")
    .sign(&signing_key);

    let path = std::env::temp_dir().join(format!(
        "chur-sync-engine-{}",
        random::id().expect("random id").to_hex()
    ));
    let vault_root = VaultRoot::new(&path);
    for (staged_at_ms, record) in [
        (7, b"malformed".to_vec()),
        (8, accepted.encode()),
        (9, fork.encode()),
    ] {
        sync_engine::stage_inbound(
            &vault_root,
            vault_id,
            StagedKind::Operation,
            staged_at_ms,
            &record,
        )
        .expect("stage");
    }
    let mut staging = LockedStaging::open(vault_root.sync_inbox(&vault_id)).expect("staging");

    let report =
        sync_engine::process_staged(&mut db, &root, vault_id, &mut staging, 10).expect("process");

    assert_eq!(report.duplicates, 1);
    assert_eq!(report.rejected, 2);
    assert_eq!(
        report.first_rejection,
        Some(chur_core::ChurStatus::SyncChainFork)
    );
    std::fs::remove_dir_all(path).expect("cleanup");
}

/// `REVOCATION.md` §7: a lagging receiver still takes a revoked peer's tail.
///
/// The receiver holds no operation of the peer, so nothing places the first
/// operation on the branch the revocation point pins until the operation at the
/// point has been offered. The inbox retains both across passes, which is the
/// only reason the tail is not held for ever.
#[test]
fn a_revoked_peer_tail_applies_from_the_retained_inbox() {
    let vault_id = id(1);
    let root = Key::new([2; 32]);
    let catalog_key = CatalogKey::derive(&root, &vault_id).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let owner_key = DeviceSigningKey::from_seed([3; 32]);
    let initial = EnrollmentRecord::initial(vault_id, id(4), owner_key.verifying_key(), [5; 32])
        .expect("enrollment")
        .sign(&owner_key);
    let (membership, _, _) =
        sync_receive::provision_initial_membership(&mut db, &root, &owner_key, &initial)
            .expect("provision");

    let peer_key = DeviceSigningKey::from_seed([11; 32]);
    let enrollment = EnrollmentRecord::new(
        vault_id,
        id(6),
        peer_key.verifying_key(),
        [12; 32],
        2,
        id(4),
        2,
        *membership.commitment(),
        [13; 32],
    )
    .expect("peer enrollment")
    .sign(&owner_key);
    sync_membership::accept_enrollment(&mut db, &enrollment, &id(4), 2).expect("enrol peer");

    let collection_id = id(30);
    let collection_key = Key::new([31; 32]);
    let envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &root,
        vault_id,
        collection_id,
        1,
        1,
        Nonce::new([32; 24]),
        &collection_key,
    )
    .expect("envelope");
    store::put_collection_with_envelope(
        &mut db,
        &Collection {
            collection_id,
            current_epoch: 1,
            policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: COLLECTION_STATUS_ACTIVE,
        },
        1,
        &envelope.encode(),
    )
    .expect("collection");
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let album = |album_id: Id, name: &str| {
        OperationPayload::new(
            collection_id,
            1,
            PayloadBody::CreateAlbum {
                album_id,
                name: name.to_owned(),
            },
        )
        .expect("payload")
        .encode()
    };
    let first = Operation::seal(
        id(21),
        vault_id,
        id(6),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([21; 24]),
        &album(id(20), "one"),
    )
    .expect("first")
    .sign(&peer_key);
    let second = Operation::seal(
        id(23),
        vault_id,
        id(6),
        2,
        first.digest(),
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([23; 24]),
        &album(id(22), "two"),
    )
    .expect("second")
    .sign(&peer_key);
    let revocation = RevocationRecord::new(
        vault_id,
        id(6),
        2,
        second.digest(),
        3,
        id(4),
        enrollment.commitment(),
    )
    .expect("revocation")
    .sign(&owner_key);
    let membership =
        sync_membership::accept_revocation(&mut db, &revocation, &id(4)).expect("revoke peer");

    let path = std::env::temp_dir().join(format!(
        "chur-sync-engine-{}",
        random::id().expect("random id").to_hex()
    ));
    let vault_root = VaultRoot::new(&path);
    for (staged_at_ms, operation) in [(8, &first), (9, &second)] {
        sync_engine::stage_inbound(
            &vault_root,
            vault_id,
            StagedKind::Operation,
            staged_at_ms,
            &operation.encode(),
        )
        .expect("stage");
    }
    let mut staging = LockedStaging::open(vault_root.sync_inbox(&vault_id)).expect("staging");

    let report =
        sync_engine::process_staged(&mut db, &root, vault_id, &mut staging, 10).expect("process");

    assert_eq!(report.applied, 2);
    assert_eq!(report.pending, 0);
    assert_eq!(staging.len(10).expect("remaining"), 0);
    assert_eq!(
        sync_log::load(&db, &membership).expect("log").head(&id(6)),
        Some((2, second.digest()))
    );
    std::fs::remove_dir_all(path).expect("cleanup");
}
