//! Atomic acceptance of encrypted membership operations.

#![allow(clippy::expect_used)]

use chur_catalog::db::{CatalogKey, CatalogLocation};
use chur_catalog::model::{COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE, Collection};
use chur_catalog::{
    CatalogDb, schema, sharing, store, sync_keys, sync_log, sync_membership, sync_receive,
};
use chur_core::Id;
use chur_crypto::{Key, Nonce};
use chur_sync_protocol::collection_membership::{
    CollectionMembershipAction, CollectionMembershipRecord,
};
use chur_sync_protocol::grant::{CollectionGrant, PermissionProfile};
use chur_sync_protocol::materialization::MaterializedState;
use chur_sync_protocol::membership::EnrollmentRecord;
use chur_sync_protocol::operation::{DeviceSigningKey, Operation};
use chur_sync_protocol::operation_log::ApplyOutcome;
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};
use chur_sync_protocol::{KeyDirectory, KeyDomain};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("id")
}

struct Fixture {
    db: CatalogDb,
    root: Key,
    issuer: DeviceSigningKey,
    membership: chur_sync_protocol::state::MembershipState,
}

fn setup() -> Fixture {
    let root = Key::new([1; 32]);
    let catalog_key = CatalogKey::derive(&root, &id(2)).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let issuer = DeviceSigningKey::from_seed([3; 32]);
    let initial = EnrollmentRecord::initial(id(2), id(4), issuer.verifying_key(), [5; 32])
        .expect("initial")
        .sign(&issuer);
    let membership = sync_membership::provision(&mut db, &initial).expect("membership");
    Fixture {
        db,
        root,
        issuer,
        membership,
    }
}

#[test]
fn initial_membership_and_outer_operation_provision_together() {
    let root = Key::new([50; 32]);
    let catalog_key = CatalogKey::derive(&root, &id(51)).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let signing_key = DeviceSigningKey::from_seed([52; 32]);
    let enrollment =
        EnrollmentRecord::initial(id(51), id(53), signing_key.verifying_key(), [54; 32])
            .expect("initial")
            .sign(&signing_key);

    let (membership, log, operation) =
        sync_receive::provision_initial_membership(&mut db, &root, &signing_key, &enrollment)
            .expect("provision");
    assert_eq!(operation.device_sequence(), 1);
    assert_eq!(log.head(&id(53)), Some((1, operation.digest())));
    assert_eq!(membership.generation(), 1);
    assert_eq!(
        sync_membership::load(&db)
            .expect("membership")
            .expect("present")
            .generation(),
        1
    );
    assert_eq!(
        sync_log::load(&db, &membership).expect("log").head(&id(53)),
        Some((1, operation.digest()))
    );
}

#[test]
fn failed_initial_provision_writes_no_outer_operation() {
    let root = Key::new([55; 32]);
    let catalog_key = CatalogKey::derive(&root, &id(56)).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let signing_key = DeviceSigningKey::from_seed([57; 32]);
    let enrollment =
        EnrollmentRecord::initial(id(56), id(58), signing_key.verifying_key(), [59; 32])
            .expect("initial")
            .sign(&signing_key);
    sync_membership::provision(&mut db, &enrollment).expect("membership only");

    assert!(
        sync_receive::provision_initial_membership(&mut db, &root, &signing_key, &enrollment,)
            .is_err()
    );
    let membership = sync_membership::load(&db)
        .expect("membership")
        .expect("present");
    assert!(
        sync_log::load(&db, &membership)
            .expect("log")
            .head(&id(58))
            .is_none()
    );
}

#[test]
fn sharing_membership_and_log_head_commit_together() {
    let mut fixture = setup();
    let collection_id = id(80);
    let collection_key = Key::new([81; 32]);
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let mut sharing_state =
        sharing::provision(&mut fixture.db, id(2), collection_id, 1).expect("sharing state");
    let recipient = DeviceSigningKey::from_seed([82; 32]);
    let record = CollectionMembershipRecord::new(
        id(2),
        collection_id,
        1,
        [0; 32],
        CollectionMembershipAction::Upsert(PermissionProfile::Read),
        id(83),
        id(84),
        recipient.verifying_key(),
        [85; 32],
        1,
        id(2),
        id(4),
        1,
        1,
    )
    .expect("membership record")
    .sign(&fixture.issuer);
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");

    let operation = sync_receive::author_sharing_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut sharing_state,
        &domain,
        id(86),
        id(4),
        &fixture.issuer,
        PayloadBody::ChangeCollectionMembership(record.clone()),
    )
    .expect("author sharing membership");

    assert_eq!(operation.device_sequence(), 1);
    assert_eq!(sharing_state.commitment(), &record.commitment());
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));
    assert_eq!(
        sharing::load(&fixture.db, &collection_id)
            .expect("load")
            .expect("sharing state")
            .commitment(),
        &record.commitment()
    );

    let grant_id = id(87);
    let grant = CollectionGrant::seal(
        grant_id,
        id(2),
        collection_id,
        1,
        1,
        id(83),
        id(84),
        &[85; 32],
        id(4),
        PermissionProfile::Read,
        1,
        2,
        &collection_key,
        &fixture.issuer,
    )
    .expect("grant");
    let grant_operation = sync_receive::author_sharing_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut sharing_state,
        &domain,
        grant_id,
        id(4),
        &fixture.issuer,
        PayloadBody::IssueCollectionGrant(grant.clone()),
    )
    .expect("author grant");
    assert_eq!(grant_operation.device_sequence(), 2);
    assert_eq!(log.head(&id(4)), Some((2, grant_operation.digest())));
    assert!(
        sharing::load_grants(&fixture.db, &collection_id).is_ok_and(|stored| stored == [grant])
    );

    let wrong_key = DeviceSigningKey::from_seed([88; 32]);
    let invalid = CollectionMembershipRecord::new(
        id(2),
        collection_id,
        2,
        *sharing_state.commitment(),
        CollectionMembershipAction::Upsert(PermissionProfile::Contribute),
        id(83),
        id(84),
        recipient.verifying_key(),
        [85; 32],
        1,
        id(2),
        id(4),
        1,
        3,
    )
    .expect("invalid membership")
    .sign(&wrong_key);
    assert!(
        sync_receive::author_sharing_operation(
            &mut fixture.db,
            &mut log,
            &fixture.membership,
            &mut sharing_state,
            &domain,
            id(89),
            id(4),
            &fixture.issuer,
            PayloadBody::ChangeCollectionMembership(invalid),
        )
        .is_err()
    );
    assert_eq!(log.head(&id(4)), Some((2, grant_operation.digest())));
    assert_eq!(sharing_state.generation(), 1);
}

#[test]
fn locally_authored_enrollment_and_revocation_commit_with_their_log_heads() {
    let root = Key::new([60; 32]);
    let vault = id(61);
    let owner_id = id(62);
    let owner = DeviceSigningKey::from_seed([63; 32]);
    let catalog_key = CatalogKey::derive(&root, &vault).expect("catalog key");
    let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
    schema::open_at_current_version(&mut db, 1).expect("schema");
    let initial = EnrollmentRecord::initial(vault, owner_id, owner.verifying_key(), [64; 32])
        .expect("initial")
        .sign(&owner);
    let (mut membership, mut log, _) =
        sync_receive::provision_initial_membership(&mut db, &root, &owner, &initial)
            .expect("provision");
    let checkpoint = log
        .issue_own_checkpoint(&mut db, &membership, &owner_id, &owner, 1)
        .expect("checkpoint");
    let root_domain = KeyDomain::root(&root, &vault).expect("root domain");
    let peer_id = id(65);
    let peer = DeviceSigningKey::from_seed([66; 32]);
    let wrong_checkpoint = EnrollmentRecord::new(
        vault,
        peer_id,
        peer.verifying_key(),
        [67; 32],
        2,
        owner_id,
        2,
        *membership.commitment(),
        [99; 32],
    )
    .expect("wrong checkpoint enrollment")
    .sign(&owner);
    assert!(
        sync_receive::author_membership_operation(
            &mut db,
            &mut log,
            &mut membership,
            &root_domain,
            owner_id,
            &owner,
            PayloadBody::AddDevice(wrong_checkpoint),
        )
        .is_err()
    );
    assert_eq!(membership.generation(), 1);
    assert_eq!(log.head(&owner_id).map(|head| head.0), Some(1));
    let enrollment = EnrollmentRecord::new(
        vault,
        peer_id,
        peer.verifying_key(),
        [67; 32],
        2,
        owner_id,
        2,
        *membership.commitment(),
        checkpoint.commitment(),
    )
    .expect("enrollment")
    .sign(&owner);
    let enrollment_operation = sync_receive::author_membership_operation(
        &mut db,
        &mut log,
        &mut membership,
        &root_domain,
        owner_id,
        &owner,
        PayloadBody::AddDevice(enrollment),
    )
    .expect("author enrollment");
    assert_eq!(enrollment_operation.device_sequence(), 2);
    assert_eq!(membership.generation(), 2);

    let collection_id = id(68);
    let collection_key = Key::new([69; 32]);
    let collection_domain =
        KeyDomain::collection(&collection_key, &collection_id, 1).expect("collection domain");
    let mut state = MaterializedState::new();
    let peer_operation = sync_receive::author_content_operation(
        &mut db,
        &mut log,
        &membership,
        &mut state,
        &collection_domain,
        peer_id,
        &peer,
        &OperationPayload::new(
            collection_id,
            1,
            PayloadBody::CreateAlbum {
                album_id: id(70),
                name: "Private".to_owned(),
            },
        )
        .expect("album payload"),
    )
    .expect("peer operation");
    let revocation = chur_sync_protocol::membership::RevocationRecord::new(
        vault,
        peer_id,
        peer_operation.device_sequence(),
        peer_operation.digest(),
        3,
        owner_id,
        *membership.commitment(),
    )
    .expect("revocation")
    .sign(&owner);
    let wrong_revocation = chur_sync_protocol::membership::RevocationRecord::new(
        vault,
        peer_id,
        peer_operation.device_sequence(),
        [99; 32],
        3,
        owner_id,
        *membership.commitment(),
    )
    .expect("wrong revocation")
    .sign(&owner);
    assert!(
        sync_receive::author_membership_operation(
            &mut db,
            &mut log,
            &mut membership,
            &root_domain,
            owner_id,
            &owner,
            PayloadBody::RevokeDevice(wrong_revocation),
        )
        .is_err()
    );
    assert_eq!(membership.generation(), 2);
    assert_eq!(log.head(&owner_id).map(|head| head.0), Some(2));
    let revocation_operation = sync_receive::author_membership_operation(
        &mut db,
        &mut log,
        &mut membership,
        &root_domain,
        owner_id,
        &owner,
        PayloadBody::RevokeDevice(revocation),
    )
    .expect("author revocation");

    assert_eq!(revocation_operation.device_sequence(), 3);
    assert_eq!(membership.generation(), 3);
    assert!(matches!(
        membership.device(&peer_id).map(|device| device.status()),
        Some(chur_sync_protocol::state::DeviceStatus::Revoked { .. })
    ));
    let reloaded = sync_membership::load(&db)
        .expect("reload membership")
        .expect("membership");
    assert_eq!(reloaded.generation(), 3);
    assert_eq!(
        sync_log::load(&db, &reloaded)
            .expect("reload log")
            .head(&owner_id),
        Some((3, revocation_operation.digest()))
    );
}

fn enrollment_operation(fixture: &Fixture, enrollment: EnrollmentRecord) -> Operation {
    let domain = KeyDomain::root(&fixture.root, &id(2)).expect("root domain");
    let payload =
        OperationPayload::new(id(2), 0, PayloadBody::AddDevice(enrollment)).expect("payload");
    Operation::seal(
        id(6),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([7; 24]),
        &payload.encode(),
    )
    .expect("operation")
    .sign(&fixture.issuer)
}

#[test]
fn membership_and_log_head_commit_together() {
    let mut fixture = setup();
    let peer = DeviceSigningKey::from_seed([8; 32]);
    let enrollment = EnrollmentRecord::new(
        id(2),
        id(9),
        peer.verifying_key(),
        [10; 32],
        1,
        id(4),
        2,
        *fixture.membership.commitment(),
        [11; 32],
    )
    .expect("enrollment")
    .sign(&fixture.issuer);
    let operation = enrollment_operation(&fixture, enrollment);
    let keys = KeyDirectory::new(&fixture.root, &id(2)).expect("keys");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");

    assert_eq!(
        sync_receive::accept_membership_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &keys,
            &operation.encode(),
        )
        .expect("accept"),
        ApplyOutcome::Applied
    );
    assert_eq!(fixture.membership.generation(), 2);
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));
    assert_eq!(
        sync_membership::load(&fixture.db)
            .expect("reload")
            .expect("membership")
            .generation(),
        2
    );
}

#[test]
fn invalid_nested_membership_rolls_back_the_log_head() {
    let mut fixture = setup();
    let peer = DeviceSigningKey::from_seed([12; 32]);
    let wrong_issuer = DeviceSigningKey::from_seed([13; 32]);
    let enrollment = EnrollmentRecord::new(
        id(2),
        id(14),
        peer.verifying_key(),
        [15; 32],
        1,
        id(4),
        2,
        *fixture.membership.commitment(),
        [16; 32],
    )
    .expect("enrollment")
    .sign(&wrong_issuer);
    let operation = enrollment_operation(&fixture, enrollment);
    let keys = KeyDirectory::new(&fixture.root, &id(2)).expect("keys");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");

    assert!(
        sync_receive::accept_membership_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &keys,
            &operation.encode(),
        )
        .is_err()
    );
    assert_eq!(fixture.membership.generation(), 1);
    assert!(log.head(&id(4)).is_none());
    assert!(
        sync_log::load(&fixture.db, &fixture.membership)
            .expect("reload")
            .head(&id(4))
            .is_none()
    );
}

#[test]
fn collection_epoch_and_log_head_commit_together() {
    let mut fixture = setup();
    let collection_id = id(17);
    let old_key = Key::new([18; 32]);
    let new_key = Key::new([19; 32]);
    let old_envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection_id,
        1,
        1,
        Nonce::new([20; 24]),
        &old_key,
    )
    .expect("old envelope");
    store::put_collection_with_envelope(
        &mut fixture.db,
        &Collection {
            collection_id,
            current_epoch: 1,
            policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: COLLECTION_STATUS_ACTIVE,
        },
        1,
        &old_envelope.encode(),
    )
    .expect("collection");
    sharing::provision(&mut fixture.db, id(2), collection_id, 1).expect("sharing");
    let new_envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection_id,
        2,
        2,
        Nonce::new([21; 24]),
        &new_key,
    )
    .expect("new envelope");
    let payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateCollectionEpoch {
            previous_collection_epoch: 1,
            membership_generation: 1,
            collection_key_envelope: new_envelope,
        },
    )
    .expect("payload");
    let old_domain = KeyDomain::collection(&old_key, &collection_id, 1).expect("old domain");
    let operation = Operation::seal(
        id(22),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *old_domain.selector(),
        old_domain.operation_key(),
        Nonce::new([23; 24]),
        &payload.encode(),
    )
    .expect("operation")
    .sign(&fixture.issuer);
    let mut keys = sync_keys::key_directory(&fixture.db, &fixture.root, id(2)).expect("keys");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");

    assert_eq!(
        sync_receive::accept_rotation_operation(
            &mut fixture.db,
            &mut log,
            &fixture.membership,
            &mut keys,
            &fixture.root,
            1_000,
            &operation.encode(),
        )
        .expect("accept"),
        ApplyOutcome::Applied
    );
    assert_eq!(
        store::collection(&fixture.db, &collection_id)
            .expect("collection")
            .current_epoch,
        2
    );
    assert_eq!(
        sharing::load(&fixture.db, &collection_id)
            .expect("sharing")
            .expect("sharing state")
            .collection_epoch(),
        2
    );
    let new_domain = KeyDomain::collection(&new_key, &collection_id, 2).expect("new domain");
    assert!(keys.operation_key(new_domain.selector()).is_ok());
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));
}

#[test]
fn a_membership_record_carries_a_source_rotation_the_recipient_never_observed() {
    let mut fixture = setup();
    let collection_id = id(17);
    sharing::provision(&mut fixture.db, id(2), collection_id, 1).expect("sharing");
    // The source rotated to epoch 2 through a `CreateCollectionEpoch`
    // operation that travels in the source vault's own log; an external
    // recipient only ever sees the collection stream, so the next membership
    // record is what tells it the epoch moved.
    let new_key = Key::new([19; 32]);
    let new_domain = KeyDomain::collection(&new_key, &collection_id, 2).expect("new domain");
    let record = CollectionMembershipRecord::new(
        id(2),
        collection_id,
        1,
        [0; 32],
        CollectionMembershipAction::Upsert(PermissionProfile::Read),
        id(7),
        id(8),
        [9; 32],
        [10; 32],
        2,
        id(2),
        id(4),
        fixture.membership.generation(),
        1,
    )
    .expect("record")
    .sign(&fixture.issuer);
    let payload = OperationPayload::new(
        collection_id,
        2,
        PayloadBody::ChangeCollectionMembership(record),
    )
    .expect("payload");
    let operation = Operation::seal(
        id(31),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *new_domain.selector(),
        new_domain.operation_key(),
        Nonce::new([32; 24]),
        &payload.encode(),
    )
    .expect("operation")
    .sign(&fixture.issuer);
    let mut keys = KeyDirectory::new(&fixture.root, &id(2)).expect("keys");
    keys.check_insert(&new_domain).expect("check the epoch key");
    keys.insert(new_domain).expect("insert the epoch key");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut materialized = MaterializedState::new();

    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut materialized,
            &mut keys,
            &fixture.root,
            1_000,
            &operation.encode(),
        )
        .expect("accept"),
        ApplyOutcome::Applied
    );
    let state = sharing::load(&fixture.db, &collection_id)
        .expect("sharing")
        .expect("sharing state");
    assert_eq!(state.collection_epoch(), 2);
    assert_eq!(state.generation(), 1);
}

#[test]
fn locally_authored_rotation_rewraps_the_collection_and_commits_log_heads() {
    let mut fixture = setup();
    let collection_id = id(71);
    let object_id = id(72);
    let old_key = Key::new([73; 32]);
    let new_key = Key::new([74; 32]);
    let object_key = Key::new([75; 32]);
    let old_collection_envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection_id,
        1,
        1,
        Nonce::new([76; 24]),
        &old_key,
    )
    .expect("old collection envelope");
    store::put_collection_with_envelope(
        &mut fixture.db,
        &Collection {
            collection_id,
            current_epoch: 1,
            policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: COLLECTION_STATUS_ACTIVE,
        },
        1,
        &old_collection_envelope.encode(),
    )
    .expect("collection");
    let old_object_envelope = chur_format::envelope::ObjectKeyEnvelope::seal(
        &old_key,
        id(2),
        collection_id,
        1,
        object_id,
        1,
        Nonce::new([77; 24]),
        &object_key,
    )
    .expect("old object envelope");
    fixture
        .db
        .transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO objects VALUES (
                         ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 72
                     )",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                        id(78).as_bytes().as_slice(),
                    ],
                )
                .expect("object");
            transaction
                .execute(
                    "INSERT INTO object_key_envelopes VALUES (?1, 1, 1, ?2)",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        old_object_envelope.encode()
                    ],
                )
                .expect("object envelope");
            transaction
                .execute(
                    "INSERT INTO sync_object_envelope_epochs VALUES (?1, ?2, 1, 1)",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                    ],
                )
                .expect("envelope projection");
            Ok(())
        })
        .expect("object state");
    let new_collection_envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection_id,
        2,
        2,
        Nonce::new([79; 24]),
        &new_key,
    )
    .expect("new collection envelope");
    let old_domain = KeyDomain::collection(&old_key, &collection_id, 1).expect("old domain");
    let mut keys = sync_keys::key_directory(&fixture.db, &fixture.root, id(2)).expect("keys");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let begin = sync_receive::author_rotation_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut keys,
        &fixture.root,
        &old_domain,
        id(4),
        &fixture.issuer,
        1_000,
        &OperationPayload::new(
            collection_id,
            1,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch: 1,
                membership_generation: 1,
                collection_key_envelope: new_collection_envelope,
            },
        )
        .expect("begin payload"),
    )
    .expect("author begin");
    assert_eq!(begin.device_sequence(), 1);
    assert_eq!(log.head(&id(4)), Some((1, begin.digest())));

    let new_domain = KeyDomain::collection(&new_key, &collection_id, 2).expect("new domain");
    let rewrap = sync_receive::author_rotation_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut keys,
        &fixture.root,
        &new_domain,
        id(4),
        &fixture.issuer,
        1_001,
        &OperationPayload::new(
            collection_id,
            2,
            PayloadBody::RewrapObjectKey {
                object_id,
                object_key_commitment: chur_sync_protocol::object_grant::object_key_commitment(
                    &collection_id,
                    &object_id,
                    &object_key,
                ),
            },
        )
        .expect("rewrap payload"),
    )
    .expect("author rewrap");

    assert_eq!(rewrap.device_sequence(), 2);
    assert_eq!(log.head(&id(4)), Some((2, rewrap.digest())));
    let rotation = chur_catalog::sync_rotation::load(
        &fixture.db,
        id(2),
        collection_id,
        &fixture.membership,
        &fixture.root,
    )
    .expect("rotation");
    assert!(rotation.is_complete());
    assert!(
        rotation
            .envelope(&object_id)
            .expect("current envelope")
            .open(&new_key)
            .expect("object key")
            == object_key
    );
}

#[test]
fn accepted_content_state_rebuilds_after_restart() {
    let mut fixture = setup();
    let collection_id = id(24);
    let collection_key = Key::new([25; 32]);
    let envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection_id,
        1,
        1,
        Nonce::new([26; 24]),
        &collection_key,
    )
    .expect("envelope");
    store::put_collection_with_envelope(
        &mut fixture.db,
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
    let create = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateObject {
            object_id: id(27),
            object_generation: 1,
            store_id: id(28),
            stream_id: id(33),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let create_operation = Operation::seal(
        id(29),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([30; 24]),
        &create.encode(),
    )
    .expect("create operation")
    .sign(&fixture.issuer);
    let favorite = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::SetFavorite {
            object_id: id(27),
            favorite: true,
            removed_tokens: Vec::new(),
        },
    )
    .expect("favorite");
    let favorite_operation = Operation::seal(
        id(31),
        id(2),
        id(4),
        2,
        create_operation.digest(),
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([32; 24]),
        &favorite.encode(),
    )
    .expect("favorite operation")
    .sign(&fixture.issuer);
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    log.accept_with(
        &mut fixture.db,
        &create_operation,
        &fixture.membership,
        |_| Ok(()),
    )
    .expect("create");
    log.accept_with(
        &mut fixture.db,
        &favorite_operation,
        &fixture.membership,
        |_| Ok(()),
    )
    .expect("favorite");
    let keys = sync_keys::key_directory(&fixture.db, &fixture.root, id(2)).expect("keys");

    let restored = sync_receive::load_materialized_state(&fixture.db, &keys).expect("state");
    assert!(restored.is_favorite(&id(27)));
    assert!(!restored.is_presentable(&id(27)));
}

#[test]
fn missing_content_cause_does_not_advance_the_log() {
    let mut fixture = setup();
    let collection_id = id(33);
    let collection_key = Key::new([34; 32]);
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let create_payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateObject {
            object_id: id(35),
            object_generation: 1,
            store_id: id(36),
            stream_id: id(43),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create payload");
    let create = Operation::seal(
        id(37),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([38; 24]),
        &create_payload.encode(),
    )
    .expect("create")
    .sign(&fixture.issuer);
    let favorite_payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::SetFavorite {
            object_id: id(35),
            favorite: true,
            removed_tokens: Vec::new(),
        },
    )
    .expect("favorite payload");
    let pending = Operation::seal(
        id(39),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([40; 24]),
        &favorite_payload.encode(),
    )
    .expect("pending")
    .sign(&fixture.issuer);
    let favorite = Operation::seal(
        id(41),
        id(2),
        id(4),
        2,
        create.digest(),
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([42; 24]),
        &favorite_payload.encode(),
    )
    .expect("favorite")
    .sign(&fixture.issuer);
    let mut keys = KeyDirectory::new(&fixture.root, &id(2)).expect("keys");
    keys.insert(domain).expect("domain");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut state = MaterializedState::new();

    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut state,
            &mut keys,
            &fixture.root,
            1,
            &pending.encode(),
        )
        .expect("pending cause"),
        ApplyOutcome::PendingCause
    );
    assert!(log.head(&id(4)).is_none());
    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut state,
            &mut keys,
            &fixture.root,
            1,
            &create.encode(),
        )
        .expect("create"),
        ApplyOutcome::Applied
    );
    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut state,
            &mut keys,
            &fixture.root,
            1,
            &favorite.encode(),
        )
        .expect("favorite"),
        ApplyOutcome::Applied
    );
    assert!(state.is_favorite(&id(35)));
    assert_eq!(log.head(&id(4)), Some((2, favorite.digest())));
}

#[test]
fn locally_authored_content_and_head_commit_together() {
    let mut fixture = setup();
    let collection_id = id(44);
    let collection_key = Key::new([45; 32]);
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let create = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateObject {
            object_id: id(46),
            object_generation: 1,
            store_id: id(47),
            stream_id: id(48),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut state = MaterializedState::new();

    let operation = sync_receive::author_content_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut state,
        &domain,
        id(4),
        &fixture.issuer,
        &create,
    )
    .expect("author create");
    assert_eq!(operation.device_sequence(), 1);
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));
    assert_eq!(
        sync_log::load(&fixture.db, &fixture.membership)
            .expect("reload")
            .head(&id(4)),
        Some((1, operation.digest()))
    );

    let invalid = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::SetFavorite {
            object_id: id(49),
            favorite: true,
            removed_tokens: Vec::new(),
        },
    )
    .expect("invalid favorite");
    assert!(
        sync_receive::author_content_operation(
            &mut fixture.db,
            &mut log,
            &fixture.membership,
            &mut state,
            &domain,
            id(4),
            &fixture.issuer,
            &invalid,
        )
        .is_err()
    );
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));
}

/// A peer device of the source vault receives sharing records like any other.
///
/// `COLLECTION_OPERATION_LOG.md` §1 keeps kinds 0x11 and 0x12 out of the
/// collection stream and `COLLECTION_MEMBERSHIP.md` §5 puts the membership
/// record on kind 0x11 of the identity-vault log, so `accept_operation` is the
/// only channel that can carry them to a sibling. It used to refuse both with
/// `InvalidInput`, which `sync_engine` classifies as a rejection: the record
/// left the inbox and the sibling's view of that device's chain stopped there.
///
/// The absence of a `sharing::provision` call is the point. A peer holds no
/// sharing rows until the first record arrives, so acceptance has to write them
/// itself, inside the operation's own transaction.
#[test]
fn inbound_sharing_membership_routes_through_accept_operation() {
    let mut fixture = setup();
    let collection_id = id(90);
    let collection_key = Key::new([91; 32]);
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let mut keys = KeyDirectory::new(&fixture.root, &id(2)).expect("keys");
    keys.insert(KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain"))
        .expect("insert domain");

    let recipient = DeviceSigningKey::from_seed([92; 32]);
    let record = CollectionMembershipRecord::new(
        id(2),
        collection_id,
        1,
        [0; 32],
        CollectionMembershipAction::Upsert(PermissionProfile::Read),
        id(93),
        id(94),
        recipient.verifying_key(),
        [95; 32],
        1,
        id(2),
        id(4),
        1,
        1,
    )
    .expect("membership record")
    .sign(&fixture.issuer);
    let payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::ChangeCollectionMembership(record.clone()),
    )
    .expect("payload");
    let operation = Operation::seal(
        id(96),
        id(2),
        id(4),
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([97; 24]),
        &payload.encode(),
    )
    .expect("operation")
    .sign(&fixture.issuer);

    // The receiver accepts an unrelated enrollment first, so it is a generation
    // ahead of the one the record was authored at. That used to be a permanent
    // `AuthenticationFailed` rejection.
    let peer = DeviceSigningKey::from_seed([98; 32]);
    let enrollment = EnrollmentRecord::new(
        id(2),
        id(99),
        peer.verifying_key(),
        [100; 32],
        3,
        id(4),
        2,
        *fixture.membership.commitment(),
        [101; 32],
    )
    .expect("enrollment")
    .sign(&fixture.issuer);
    fixture.membership =
        sync_membership::accept_enrollment(&mut fixture.db, &enrollment, &id(4), 3)
            .expect("later enrollment");
    assert_eq!(fixture.membership.generation(), 2);

    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut state = MaterializedState::new();
    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut state,
            &mut keys,
            &fixture.root,
            1,
            &operation.encode(),
        )
        .expect("inbound sharing membership"),
        ApplyOutcome::Applied
    );
    assert_eq!(
        sharing::load(&fixture.db, &collection_id)
            .expect("load")
            .expect("sharing state")
            .commitment(),
        &record.commitment()
    );
    assert_eq!(log.head(&id(4)), Some((1, operation.digest())));

    // The grant arm names its sender generation separately; it is the same
    // generation-one state, so the sibling accepts it at generation two too.
    let grant = CollectionGrant::seal(
        id(102),
        id(2),
        collection_id,
        1,
        1,
        id(93),
        id(94),
        &[95; 32],
        id(4),
        PermissionProfile::Read,
        1,
        2,
        &collection_key,
        &fixture.issuer,
    )
    .expect("grant");
    let grant_payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::IssueCollectionGrant(grant.clone()),
    )
    .expect("grant payload");
    let grant_operation = Operation::seal(
        id(102),
        id(2),
        id(4),
        2,
        operation.digest(),
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::new([103; 24]),
        &grant_payload.encode(),
    )
    .expect("grant operation")
    .sign(&fixture.issuer);
    assert_eq!(
        sync_receive::accept_operation(
            &mut fixture.db,
            &mut log,
            &mut fixture.membership,
            &mut state,
            &mut keys,
            &fixture.root,
            1,
            &grant_operation.encode(),
        )
        .expect("inbound sharing grant"),
        ApplyOutcome::Applied
    );
    assert!(
        sharing::load_grants(&fixture.db, &collection_id).is_ok_and(|stored| stored == [grant])
    );
}

#[test]
fn root_declarations_discover_future_collections_and_epochs_without_key_substitution() {
    use chur_format::envelope::CollectionKeyEnvelope;
    let mut fixture = setup();
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut keys = KeyDirectory::new(&fixture.root, &id(2)).expect("root directory");
    let mut state = MaterializedState::new();
    let root_domain = KeyDomain::root(&fixture.root, &id(2)).expect("root domain");
    let mut previous = [0; 32];
    for (sequence, collection, epoch, marker) in [
        (1, id(90), 1, 91),
        (2, id(92), 1, 93),
        (3, id(90), 2, 94),
        (4, id(90), 1, 91),
    ] {
        let envelope = CollectionKeyEnvelope::seal(
            &fixture.root,
            id(2),
            collection,
            epoch,
            epoch,
            Nonce::new([marker; 24]),
            &Key::new([marker; 32]),
        )
        .expect("metadata envelope");
        let payload = OperationPayload::new(
            id(2),
            0,
            PayloadBody::DeclareCollection {
                collection_key_envelope: envelope,
            },
        )
        .expect("root declaration");
        let operation = Operation::seal(
            id(150 + sequence as u8),
            id(2),
            id(4),
            sequence,
            previous,
            vec![],
            *root_domain.selector(),
            root_domain.operation_key(),
            Nonce::new([marker + 1; 24]),
            &payload.encode(),
        )
        .expect("signed declaration")
        .sign(&fixture.issuer);
        assert_eq!(
            sync_receive::accept_operation(
                &mut fixture.db,
                &mut log,
                &mut fixture.membership,
                &mut state,
                &mut keys,
                &fixture.root,
                1,
                &operation.encode()
            )
            .expect("declaration accepted"),
            ApplyOutcome::Applied
        );
        previous = operation.digest();
        let domain = KeyDomain::collection(&Key::new([marker; 32]), &collection, epoch)
            .expect("declared domain");
        assert!(keys.contains_selector(domain.selector()));
    }
    assert_eq!(
        store::collection(&fixture.db, &id(90))
            .expect("future epoch")
            .current_epoch,
        2
    );
    assert_eq!(
        store::collection(&fixture.db, &id(92))
            .expect("future collection")
            .current_epoch,
        1
    );
    for envelope_vault in [id(2), id(99)] {
        let envelope = CollectionKeyEnvelope::seal(
            &fixture.root,
            envelope_vault,
            id(90),
            2,
            2,
            Nonce::new([98; 24]),
            &Key::new([99; 32]),
        )
        .expect("substitution envelope");
        let payload = OperationPayload::new(
            id(2),
            0,
            PayloadBody::DeclareCollection {
                collection_key_envelope: envelope,
            },
        )
        .expect("declaration");
        let operation = Operation::seal(
            id(100),
            id(2),
            id(4),
            5,
            previous,
            vec![],
            *root_domain.selector(),
            root_domain.operation_key(),
            Nonce::new([101; 24]),
            &payload.encode(),
        )
        .expect("record")
        .sign(&fixture.issuer);
        assert_eq!(
            sync_receive::accept_operation(
                &mut fixture.db,
                &mut log,
                &mut fixture.membership,
                &mut state,
                &mut keys,
                &fixture.root,
                2,
                &operation.encode()
            )
            .expect_err("key or vault substitution rejected")
            .status(),
            chur_core::ChurStatus::AuthenticationFailed
        );
        assert_eq!(log.head(&id(4)), Some((4, previous)));
    }
}

#[test]
fn rotation_accepts_waiting_keys_pending_envelopes_and_permanent_tombstones() {
    use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
    use chur_sync_protocol::object_grant::{ObjectKeyGrant, ObjectPrekey, object_key_commitment};
    let mut fixture = setup();
    let collection = id(110);
    let old = Key::new([111; 32]);
    let next = Key::new([112; 32]);
    let envelope = CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection,
        1,
        1,
        Nonce::new([113; 24]),
        &old,
    )
    .expect("old envelope");
    store::put_collection_with_envelope(
        &mut fixture.db,
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
    .expect("collection");
    let mut keys = sync_keys::key_directory(&fixture.db, &fixture.root, id(2)).expect("keys");
    let mut log = sync_log::load(&fixture.db, &fixture.membership).expect("log");
    let mut state = MaterializedState::new();
    let old_domain = KeyDomain::collection(&old, &collection, 1).expect("old domain");
    for object in [id(115), id(116), id(117)] {
        let content = Key::new([object.as_bytes()[0]; 32]);
        for body in [
            PayloadBody::CreateObject {
                object_id: object,
                object_generation: 1,
                store_id: object,
                stream_id: id(118),
                metadata_fields: vec![],
            },
            PayloadBody::CommitObject {
                object_id: object,
                object_generation: 1,
                store_id: object,
                container_length: 1024,
                container_commitment: [119; 32],
                object_key_commitment: object_key_commitment(&collection, &object, &content),
            },
        ] {
            sync_receive::author_content_operation(
                &mut fixture.db,
                &mut log,
                &fixture.membership,
                &mut state,
                &old_domain,
                id(4),
                &fixture.issuer,
                &OperationPayload::new(collection, 1, body).expect("content payload"),
            )
            .expect("accepted commit cause");
        }
    }
    let private = Key::new([120; 32]);
    for object in [id(115), id(116)] {
        let content = Key::new([object.as_bytes()[0]; 32]);
        let request = ObjectPrekey::sign(
            object,
            collection,
            object,
            1,
            [119; 32],
            id(2),
            id(4),
            1,
            &private,
            &fixture.issuer,
        )
        .expect("request");
        fixture
            .db
            .transaction(|tx| {
                if object == id(115) {
                    let grant = ObjectKeyGrant::seal(
                        id(121),
                        id(2),
                        id(4),
                        object,
                        1,
                        [119; 32],
                        &request,
                        &content,
                        &fixture.issuer,
                    )
                    .expect("grant");
                    let envelope = ObjectKeyEnvelope::seal(
                        &old,
                        id(2),
                        collection,
                        1,
                        object,
                        1,
                        Nonce::new([122; 24]),
                        &content,
                    )
                    .expect("pending envelope");
                    tx.execute(
                        "INSERT INTO pending_object_keys VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            object.as_bytes().as_slice(),
                            collection.as_bytes().as_slice(),
                            request.encode(),
                            grant.encode(),
                            envelope.encode()
                        ],
                    )
                    .expect("accepted pending projection");
                } else {
                    tx.execute(
                        "INSERT INTO object_key_requests VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            object.as_bytes().as_slice(),
                            collection.as_bytes().as_slice(),
                            request.prekey_id().as_bytes().as_slice(),
                            private.expose().as_slice(),
                            request.encode()
                        ],
                    )
                    .expect("waiting private prekey");
                }
                Ok(())
            })
            .expect("pending state");
    }
    fixture
        .db
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO tombstones VALUES (?1, ?2, 1, 1)",
                rusqlite::params![
                    collection.as_bytes().as_slice(),
                    id(117).as_bytes().as_slice()
                ],
            )
            .expect("permanent tombstone");
            Ok(())
        })
        .expect("tombstone");
    let envelope = CollectionKeyEnvelope::seal(
        &fixture.root,
        id(2),
        collection,
        2,
        2,
        Nonce::new([123; 24]),
        &next,
    )
    .expect("new metadata key");
    sync_receive::author_rotation_operation(
        &mut fixture.db,
        &mut log,
        &fixture.membership,
        &mut keys,
        &fixture.root,
        &old_domain,
        id(4),
        &fixture.issuer,
        10,
        &OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch: 1,
                membership_generation: 1,
                collection_key_envelope: envelope,
            },
        )
        .expect("rotation"),
    )
    .expect("rotation accepted");
    let new_domain = KeyDomain::collection(&next, &collection, 2).expect("new domain");
    for object in [id(115), id(116), id(117)] {
        let content = Key::new([object.as_bytes()[0]; 32]);
        sync_receive::author_rotation_operation(
            &mut fixture.db,
            &mut log,
            &fixture.membership,
            &mut keys,
            &fixture.root,
            &new_domain,
            id(4),
            &fixture.issuer,
            11,
            &OperationPayload::new(
                collection,
                2,
                PayloadBody::RewrapObjectKey {
                    object_id: object,
                    object_key_commitment: object_key_commitment(&collection, &object, &content),
                },
            )
            .expect("rewrap"),
        )
        .expect("missing local media cannot block key-free rewrap");
    }
    assert_eq!(log.head(&id(4)).expect("advanced head").0, 10);
    let pending = chur_catalog::object_grants::pending_envelope(&fixture.db, &collection, &id(115))
        .expect("rewrapped pending key");
    assert_eq!(pending.collection_epoch(), 2);
    assert_eq!(
        pending.open(&next).expect("current metadata key").expose(),
        Key::new([115; 32]).expose()
    );
    assert!(store::active_envelope(&fixture.db, &id(116)).is_err());
    assert!(
        chur_catalog::object_grants::pending_envelope(&fixture.db, &collection, &id(117)).is_err()
    );
}
