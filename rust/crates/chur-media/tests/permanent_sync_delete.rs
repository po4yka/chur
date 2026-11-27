//! Permanent source deletion destroys content keys on an enrolled sibling.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use chur_catalog::{
    deletion, device_pairing, own_sync,
    paths::VaultRoot,
    sharing_publication, sync_engine, sync_keys, sync_log, sync_membership, sync_receive,
    sync_staging::LockedStaging,
    vault::{self, Session},
};
use chur_core::{ChurStatus, Id};
use chur_crypto::{Key, random};
use chur_format::constants::StreamKind;
use chur_media::{
    backup, export,
    import::{self, CanonicalMedia, SourceCapability},
    keys,
    progress::Uninterrupted,
    store, sync_download,
};
use std::io::Cursor;
use zeroize::Zeroizing;
const PASSWORD: &[u8] = b"permanent sibling deletion password";
const NOW: u64 = 1_700_000_000_000;
fn root() -> VaultRoot {
    let path = std::env::temp_dir().join(format!(
        "chur-permanent-sync-{}",
        random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    VaultRoot::new(path)
}
#[track_caller]
fn relay(source: &Session, target: &mut Session, secret: &Key, device: &Id) {
    let vault = source.vault_id();
    for record in sync_log::records_after(source.catalog_ref().unwrap(), device, 0).unwrap() {
        sync_engine::stage_inbound(
            target.root_dir(),
            vault,
            sync_engine::StagedKind::Operation,
            NOW + 10,
            &record,
        )
        .unwrap();
    }
    let mut staging = LockedStaging::open(target.root_dir().sync_inbox(&vault)).unwrap();
    let result = sync_engine::process_staged(
        target.catalog().unwrap(),
        secret,
        vault,
        &mut staging,
        NOW + 10,
    )
    .unwrap();
    assert_eq!(result.rejected, 0);
    assert_eq!(result.pending, 0);
}
fn finish(session: &mut Session, secret: &Key) {
    let vault = session.vault_id();
    let store_id = session.object_store_id();
    for pending in deletion::sweep(session.catalog_ref().unwrap()).unwrap() {
        if !pending.erased {
            deletion::erase_with_sync(
                session.catalog().unwrap(),
                secret,
                vault,
                &pending.object_id,
                NOW + 20,
            )
            .unwrap();
        }
        for id in pending.containers {
            store::unlink_container(session.root_dir(), &store_id, &id).unwrap();
        }
        deletion::finish(session.catalog().unwrap(), &pending.object_id).unwrap();
        deletion::discard_tombstone(session.catalog().unwrap(), &pending.object_id).unwrap();
    }
    session.catalog().unwrap().checkpoint().unwrap();
}
fn import(session: &mut Session, value: &[u8]) -> Id {
    import::import_bytes(
        session,
        SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(value.len() as u64),
            content_type_hint: "application/octet-stream".into(),
            original_filename: Some("private.bin".into()),
            capture_time_ms: None,
        },
        CanonicalMedia::opaque(),
        "application/octet-stream",
        &Zeroizing::new(value.to_vec()),
        NOW + 8,
    )
    .unwrap()
}
fn import_ocr_text(session: &mut Session, value: &[u8]) -> Id {
    import::import_bytes(
        session,
        SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(value.len() as u64),
            content_type_hint: "text/plain".into(),
            original_filename: Some("private.bin".into()),
            capture_time_ms: None,
        },
        CanonicalMedia::opaque(),
        "text/plain",
        &Zeroizing::new(value.to_vec()),
        NOW + 8,
    )
    .unwrap()
}

fn index_ocr(session: &mut Session, object: Id, text: &str) -> Id {
    let stream = chur_catalog::store::object(session.catalog_ref().unwrap(), &object)
        .unwrap()
        .primary_stream_id;
    chur_catalog::content_index::put(session.catalog().unwrap(), &object, &stream, 1, 1, text)
        .unwrap();
    stream
}

fn assert_purged_ocr_and_healthy_neighbor(
    session: &mut Session,
    removed: Id,
    neighbor: Id,
    old_stream: Id,
) {
    session
        .catalog()
        .unwrap()
        .transaction(|tx| {
            let rows: i64 = tx
                .query_row(
                    "SELECT count(*) FROM content_index WHERE object_id = ?1",
                    [removed.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0);
            tx.execute_batch(
                "CREATE VIRTUAL TABLE temp.ocr_vocab USING fts5vocab(main, object_search, row)",
            )
            .unwrap();
            let terms: i64 = tx
                .query_row(
                    "SELECT count(*) FROM temp.ocr_vocab WHERE term = 'remotepurgedocrcanary'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                terms, 0,
                "remote purge must remove OCR from the actual FTS vocabulary"
            );
            tx.execute_batch("DROP TABLE temp.ocr_vocab").unwrap();
            Ok(())
        })
        .unwrap();
    assert_eq!(
        chur_catalog::content_index::put(
            session.catalog().unwrap(),
            &removed,
            &old_stream,
            1,
            1,
            "remotepurgedocrcanary"
        )
        .unwrap_err()
        .status(),
        ChurStatus::NotFound
    );
    let query = chur_catalog::query::ObjectQuery {
        scope: chur_catalog::query::Scope::Search,
        terms: Some("remotepreservedocrneighbor".into()),
        ..chur_catalog::query::ObjectQuery::timeline()
    };
    let hits = chur_catalog::query::page(session.catalog_ref().unwrap(), &query)
        .unwrap()
        .objects;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].object_id, neighbor);
}

fn rotate(source: &mut Session, secret: &Key, collection: Id, objects: &[Id]) {
    use chur_sync_protocol::{
        KeyDomain,
        payload::{OperationPayload, PayloadBody},
    };
    let vault = source.vault_id();
    let membership = sync_membership::load(source.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    let (device, identity) =
        sync_keys::local_identity(source.catalog_ref().unwrap(), secret, &membership)
            .unwrap()
            .unwrap();
    let old = keys::collection_key(source, &collection, 1).unwrap();
    let next = random::secret::<32>().unwrap();
    let envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        secret,
        vault,
        collection,
        2,
        2,
        chur_crypto::Nonce::random().unwrap(),
        &next,
    )
    .unwrap();
    let domain = KeyDomain::collection(&old, &collection, 1).unwrap();
    let mut directory =
        sync_keys::key_directory(source.catalog_ref().unwrap(), secret, vault).unwrap();
    let mut log = sync_log::load(source.catalog_ref().unwrap(), &membership).unwrap();
    sync_receive::author_rotation_operation(
        source.catalog().unwrap(),
        &mut log,
        &membership,
        &mut directory,
        secret,
        &domain,
        device,
        identity.signing_key(),
        NOW + 12,
        &OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch: 1,
                membership_generation: membership.generation(),
                collection_key_envelope: envelope,
            },
        )
        .unwrap(),
    )
    .unwrap();
    let domain = KeyDomain::collection(&next, &collection, 2).unwrap();
    for object in objects {
        let content = keys::object_key(source, object).unwrap();
        sync_receive::author_rotation_operation(
            source.catalog().unwrap(),
            &mut log,
            &membership,
            &mut directory,
            secret,
            &domain,
            device,
            identity.signing_key(),
            NOW + 13,
            &OperationPayload::new(
                collection,
                2,
                PayloadBody::RewrapObjectKey {
                    object_id: *object,
                    object_key_commitment: chur_sync_protocol::object_grant::object_key_commitment(
                        &collection,
                        object,
                        &content,
                    ),
                },
            )
            .unwrap(),
        )
        .unwrap();
    }
}
fn foreign_collection_event(
    target: &mut Session,
    secret: &Key,
    object: Id,
    target_device: Id,
    first_enrollment: &chur_sync_protocol::membership::EnrollmentRecord,
    mut terminal: chur_sync_protocol::payload::PayloadBody,
    content_key: Option<&Key>,
) -> (Id, Option<chur_catalog::sharing_receive::SharedObject>) {
    use chur_catalog::{
        sharing, sharing_log::DurableCollectionOperationLog, sharing_receive, sharing_service,
    };
    use chur_sync_protocol::{
        KeyDomain,
        grant::PermissionProfile,
        operation::Operation,
        payload::{OperationPayload, PayloadBody},
    };
    let target_vault = target.vault_id();
    let second =
        sync_membership::enrollment_for_device(target.catalog_ref().unwrap(), &target_device)
            .unwrap();
    let membership_records = [
        sharing_service::IssuerMembershipRecord::Enrollment(first_enrollment.clone()),
        sharing_service::IssuerMembershipRecord::Enrollment(second),
    ];
    let mut own_records = Vec::new();
    for device in [*first_enrollment.device_id(), target_device] {
        own_records.extend(
            sync_log::records_after(target.catalog_ref().unwrap(), &device, 0)
                .unwrap()
                .iter()
                .map(|bytes| Operation::decode(bytes).unwrap()),
        );
    }
    let attacker_root = root();
    let mut attacker = vault::create(&attacker_root, PASSWORD, NOW)
        .unwrap()
        .activate()
        .unwrap();
    let attacker_secret = attacker.root_secret().unwrap().duplicate();
    let attacker_vault = attacker.vault_id();
    let (enrollment, _) = sync_receive::provision_local_identity(
        attacker.catalog().unwrap(),
        &attacker_secret,
        attacker_vault,
    )
    .unwrap();
    let seed_object = import(&mut attacker, b"foreign source original");
    let collection = chur_catalog::store::object(attacker.catalog_ref().unwrap(), &seed_object)
        .unwrap()
        .collection_id;
    let share = sharing_service::prepare_share_for_device(
        attacker.catalog().unwrap(),
        &attacker_secret,
        attacker_vault,
        collection,
        sharing_service::IssuerEvidence {
            membership: &membership_records,
            operations: &own_records,
        },
        target_device,
        PermissionProfile::Read,
        true,
    )
    .unwrap();
    let membership = sync_membership::load(attacker.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    let (_, identity) = sync_keys::local_identity(
        attacker.catalog_ref().unwrap(),
        &attacker_secret,
        &membership,
    )
    .unwrap()
    .unwrap();
    let state = sharing::load(attacker.catalog_ref().unwrap(), &collection)
        .unwrap()
        .unwrap();
    let metadata_key = keys::collection_key(&attacker, &collection, 1).unwrap();
    let domain = KeyDomain::collection(&metadata_key, &collection, 1).unwrap();
    let directory = sync_keys::key_directory(
        attacker.catalog_ref().unwrap(),
        &attacker_secret,
        attacker_vault,
    )
    .unwrap();
    let mut log = DurableCollectionOperationLog::provision(
        attacker.catalog().unwrap(),
        collection,
        1,
        *domain.selector(),
    )
    .unwrap();
    if let (
        Some(content),
        PayloadBody::CommitObject {
            object_key_commitment,
            ..
        },
    ) = (content_key, &mut terminal)
    {
        *object_key_commitment =
            chur_sync_protocol::object_grant::object_key_commitment(&collection, &object, content);
    }
    let mut events = Vec::new();
    for body in [
        PayloadBody::CreateObject {
            object_id: object,
            object_generation: 1,
            store_id: object,
            stream_id: object,
            metadata_fields: vec![],
        },
        terminal,
    ] {
        events.push(
            log.author_with_keys(
                attacker.catalog().unwrap(),
                &directory,
                random::id().unwrap(),
                attacker_vault,
                *enrollment.device_id(),
                domain.operation_key(),
                chur_crypto::Nonce::random().unwrap(),
                &OperationPayload::new(collection, 1, body).unwrap(),
                identity.signing_key(),
                &membership,
                &membership,
                &state,
            )
            .unwrap(),
        );
    }
    let proofs =
        sync_log::records_after(attacker.catalog_ref().unwrap(), enrollment.device_id(), 0)
            .unwrap()
            .iter()
            .map(|bytes| Operation::decode(bytes).unwrap())
            .collect::<Vec<_>>();
    let attacker_device = *enrollment.device_id();
    let records = [sharing_service::IssuerMembershipRecord::Enrollment(
        enrollment,
    )];
    let mut plan = sharing_receive::receive(
        target.catalog().unwrap(),
        secret,
        target_vault,
        &[sharing_service::IssuerEvidence {
            membership: &records,
            operations: &proofs,
        }],
        &[(
            share.membership().clone(),
            share.membership_operation().clone(),
        )],
        share.grant(),
        share.grant_operation(),
        &events,
    )
    .unwrap();
    if let Some(content) = content_key {
        let prekey = chur_catalog::object_grants::request(
            target.catalog().unwrap(),
            secret,
            target_vault,
            collection,
            object,
        )
        .unwrap();
        let grant = chur_sync_protocol::object_grant::ObjectKeyGrant::seal(
            random::id().unwrap(),
            attacker_vault,
            attacker_device,
            object,
            1,
            plan.objects[0].container_commitment,
            &prekey,
            content,
            identity.signing_key(),
        )
        .unwrap();
        chur_catalog::object_grants::accept(
            target.catalog().unwrap(),
            secret,
            target_vault,
            &[sharing_service::IssuerEvidence {
                membership: &records,
                operations: &proofs,
            }],
            &grant,
        )
        .unwrap();
    }
    (collection, plan.objects.pop())
}
fn foreign_purge_preserves_active_original(
    target: &mut Session,
    secret: &Key,
    object: Id,
    target_device: Id,
    first_enrollment: &chur_sync_protocol::membership::EnrollmentRecord,
) {
    use chur_catalog::query;
    let query = query::ObjectQuery {
        scope: query::Scope::Search,
        terms: Some("private".into()),
        ..query::ObjectQuery::timeline()
    };
    assert!(
        query::page(target.catalog_ref().unwrap(), &query)
            .unwrap()
            .objects
            .iter()
            .any(|row| row.object_id == object)
    );
    let original_key = keys::object_key(target, &object).unwrap();
    let original = chur_catalog::store::object(target.catalog_ref().unwrap(), &object).unwrap();
    foreign_collection_event(
        target,
        secret,
        object,
        target_device,
        first_enrollment,
        chur_sync_protocol::payload::PayloadBody::PurgeObject {
            object_id: object,
            object_generation: 1,
            authored_at_ms: NOW,
        },
        None,
    );
    finish(target, secret);
    assert_eq!(
        chur_catalog::store::object(target.catalog_ref().unwrap(), &object).unwrap(),
        original
    );
    assert_eq!(
        keys::object_key(target, &object).unwrap().expose(),
        original_key.expose()
    );
    assert!(
        query::page(target.catalog_ref().unwrap(), &query)
            .unwrap()
            .objects
            .iter()
            .any(|row| row.object_id == object)
    );
    let mut bytes = Vec::new();
    export::export_stream(
        target,
        &object,
        StreamKind::Original,
        &mut bytes,
        &mut Uninterrupted,
    )
    .unwrap();
    assert_eq!(bytes, b"neighbor remains readable");
}
#[test]
fn source_purge_relay_erases_sibling_after_restart_and_backup_without_damaging_neighbor() {
    let source_root = root();
    let mut source = vault::create(&source_root, PASSWORD, NOW)
        .unwrap()
        .activate()
        .unwrap();
    let secret = source.root_secret().unwrap().duplicate();
    let vault = source.vault_id();
    let (source_enrollment, _) =
        sync_receive::provision_local_identity(source.catalog().unwrap(), &secret, vault).unwrap();
    let mut baseline = Cursor::new(Vec::new());
    backup::create(&mut source, &mut baseline, NOW, &mut Uninterrupted).unwrap();
    let target_root = root();
    backup::restore(&target_root, &mut baseline, PASSWORD, &mut Uninterrupted).unwrap();
    let mut target = vault::unlock_with_password(&target_root, PASSWORD, NOW + 1).unwrap();
    let request =
        device_pairing::prepare_request(target.catalog().unwrap(), &secret, vault).unwrap();
    let approval =
        device_pairing::approve(source.catalog().unwrap(), &secret, vault, &request, NOW + 2)
            .unwrap();
    device_pairing::accept_start(
        target.catalog().unwrap(),
        &secret,
        vault,
        &approval.approval,
    )
    .unwrap();
    relay(&source, &mut target, &secret, source_enrollment.device_id());
    let target_device =
        device_pairing::finalize(target.catalog().unwrap(), &secret, vault, NOW + 4).unwrap();
    let removed = import_ocr_text(&mut source, b"removed private original");
    let neighbor = import_ocr_text(&mut source, b"neighbor remains readable");
    let source_ocr_stream = index_ocr(&mut source, removed, "remotepurgedocrcanary");
    index_ocr(&mut source, neighbor, "remotepreservedocrneighbor");
    let pending_removed = import(&mut source, b"pending original never activated");
    let pending_sealed = import(&mut source, b"accepted pending key without container");
    let collection = chur_catalog::store::object(source.catalog_ref().unwrap(), &removed)
        .unwrap()
        .collection_id;
    for object in [removed, neighbor, pending_removed, pending_sealed] {
        let item =
            sharing_publication::candidate(source.catalog_ref().unwrap(), &collection, &object)
                .unwrap();
        own_sync::publish(
            source.catalog().unwrap(),
            &secret,
            vault,
            collection,
            &[item],
        )
        .unwrap();
    }
    relay(&source, &mut target, &secret, source_enrollment.device_id());
    let plan =
        own_sync::pending_for_collection(target.catalog().unwrap(), &secret, vault, collection)
            .unwrap();
    assert_eq!(plan.objects.len(), 4);
    // The untrusted collection receives its own valid pending object and
    // disposable request before this device asks for the legitimate original.
    let malicious_key = Key::new([88; 32]);
    let malicious_identity = chur_format::container::StreamIdentity {
        object_id: neighbor,
        stream_id: neighbor,
        stream_kind: StreamKind::Original,
        stream_revision: 1,
    };
    let manifest = chur_format::container::CanonicalManifest::new(
        malicious_identity,
        None,
        1_048_576,
        [89; 16],
        1,
        chur_format::container::MediaProperties::opaque(),
    )
    .unwrap();
    let mut writer = chur_format::container::ContainerWriter::start(
        Vec::new(),
        &malicious_key,
        manifest,
        chur_crypto::Nonce::new([90; 24]),
    )
    .unwrap();
    writer
        .write_chunk(b"attacker's separately authenticated original")
        .unwrap();
    let malicious_bytes = writer.finish(chur_crypto::Nonce::new([91; 24]), 1).unwrap();
    let malicious_commit = *chur_format::container::ContainerReader::open(
        &malicious_bytes,
        &malicious_key,
        &malicious_identity,
    )
    .unwrap()
    .read_final_commit()
    .unwrap()
    .ordered_chunk_commitment();
    let (foreign, stale) = foreign_collection_event(
        &mut target,
        &secret,
        neighbor,
        target_device,
        &source_enrollment,
        chur_sync_protocol::payload::PayloadBody::CommitObject {
            object_id: neighbor,
            object_generation: 1,
            store_id: neighbor,
            container_length: malicious_bytes.len() as u64,
            container_commitment: malicious_commit,
            object_key_commitment: [88; 32],
        },
        Some(&malicious_key),
    );
    let stale = stale.unwrap();
    let foreign_request = chur_catalog::object_grants::request(
        target.catalog().unwrap(),
        &secret,
        vault,
        foreign,
        neighbor,
    )
    .unwrap();
    let foreign_envelope = chur_catalog::object_grants::pending_envelope(
        target.catalog_ref().unwrap(),
        &foreign,
        &neighbor,
    )
    .unwrap()
    .encode();
    let mut retained_grants = Vec::new();
    for object in plan.objects {
        let prekey = chur_catalog::object_grants::request(
            target.catalog().unwrap(),
            &secret,
            vault,
            collection,
            object.object_id,
        )
        .unwrap();
        let grant =
            chur_catalog::object_grants::issue(source.catalog().unwrap(), &secret, vault, &prekey)
                .unwrap();
        retained_grants.push(grant.clone());
        if object.object_id == pending_removed {
            continue;
        }
        chur_catalog::object_grants::accept(target.catalog().unwrap(), &secret, vault, &[], &grant)
            .unwrap();
        if object.object_id == pending_sealed {
            continue;
        }
        let bytes = store::read_container(
            source.root_dir(),
            &source.object_store_id(),
            &object.store_id,
        )
        .unwrap();
        let expected = sync_download::Expectation::new(
            object.object_id,
            object.stream_id,
            object.container_length,
            object.container_commitment,
        )
        .unwrap();
        sync_download::append_range(
            target.root_dir(),
            &target.object_store_id(),
            &object.object_id,
            0,
            &bytes,
            &expected,
        )
        .unwrap();
        sync_download::activate_shared(&mut target, &object, NOW + 11).unwrap();
    }
    // Recognition is local: the receiver indexes its own authenticated source.
    let target_ocr_stream = index_ocr(&mut target, removed, "remotepurgedocrcanary");
    index_ocr(&mut target, neighbor, "remotepreservedocrneighbor");
    let active_before =
        chur_catalog::store::object(target.catalog_ref().unwrap(), &neighbor).unwrap();
    let committed_before =
        store::read_container(target.root_dir(), &target.object_store_id(), &neighbor).unwrap();
    let expected = sync_download::Expectation::new(
        neighbor,
        stale.stream_id,
        stale.container_length,
        stale.container_commitment,
    )
    .unwrap();
    sync_download::append_range(
        target.root_dir(),
        &target.object_store_id(),
        &neighbor,
        0,
        &malicious_bytes,
        &expected,
    )
    .unwrap();
    assert!(
        sync_download::activate_shared(&mut target, &stale, NOW + 12).is_err(),
        "stale foreign plan cannot rebind an active global object ID"
    );
    assert!(
        store::read_container(target.root_dir(), &target.object_store_id(), &neighbor).unwrap()
            == committed_before,
        "failed foreign activation must preserve the already healthy original ciphertext"
    );
    assert_eq!(
        chur_catalog::object_grants::pending_envelope(
            target.catalog_ref().unwrap(),
            &foreign,
            &neighbor
        )
        .unwrap()
        .encode(),
        foreign_envelope,
        "foreign pending key custody remains unchanged after the collision"
    );
    assert_eq!(
        chur_catalog::store::object(target.catalog_ref().unwrap(), &neighbor).unwrap(),
        active_before
    );
    assert_eq!(
        active_before.state,
        chur_format::constants::ObjectState::Active
    );
    // The existing global-ID policy rejects a foreign active collision explicitly.
    for _ in 0..2 {
        assert_eq!(
            chur_catalog::sharing_receive::pending_for_collection(
                target.catalog().unwrap(),
                &secret,
                vault,
                foreign
            )
            .err()
            .unwrap()
            .status(),
            ChurStatus::Conflict
        );
        assert_eq!(
            chur_catalog::sharing_receive::pending_object_for_collection(
                target.catalog().unwrap(),
                &secret,
                vault,
                foreign,
                neighbor
            )
            .err()
            .unwrap()
            .status(),
            ChurStatus::NotFound
        );
    }
    let mut received = Vec::new();
    export::export_stream(
        &target,
        &neighbor,
        StreamKind::Original,
        &mut received,
        &mut Uninterrupted,
    )
    .unwrap();
    assert_eq!(received, b"neighbor remains readable");
    assert!(keys::object_key(&target, &removed).is_ok());
    foreign_purge_preserves_active_original(
        &mut target,
        &secret,
        neighbor,
        *request.device_id(),
        &source_enrollment,
    );
    rotate(
        &mut source,
        &secret,
        collection,
        &[removed, neighbor, pending_removed, pending_sealed],
    );
    // Rotation must not block on the sibling's missing pending container/key.
    let later = import(&mut source, b"new epoch original");
    let item =
        sharing_publication::candidate(source.catalog_ref().unwrap(), &collection, &later).unwrap();
    own_sync::publish(
        source.catalog().unwrap(),
        &secret,
        vault,
        collection,
        &[item],
    )
    .unwrap();
    relay(&source, &mut target, &secret, source_enrollment.device_id());
    assert_eq!(
        chur_catalog::store::collection(target.catalog_ref().unwrap(), &collection)
            .unwrap()
            .current_epoch,
        2
    );
    let pending =
        own_sync::pending_for_collection(target.catalog().unwrap(), &secret, vault, collection)
            .unwrap();
    assert_eq!(pending.objects.len(), 3);
    // The new-epoch original remains pending until it has its own bound grant.
    deletion::begin(source.catalog().unwrap(), &removed).unwrap();
    deletion::begin(source.catalog().unwrap(), &pending_removed).unwrap();
    deletion::begin(source.catalog().unwrap(), &pending_sealed).unwrap();
    finish(&mut source, &secret);
    assert_purged_ocr_and_healthy_neighbor(&mut source, removed, neighbor, source_ocr_stream);
    assert!(keys::object_key(&source, &removed).is_err());
    relay(&source, &mut target, &secret, source_enrollment.device_id());
    // The native acceptance transaction removes keys before it advances the head.
    assert!(keys::object_key(&target, &removed).is_err());
    assert!(
        chur_catalog::object_grants::pending_envelope(
            target.catalog_ref().unwrap(),
            &collection,
            &pending_removed
        )
        .is_err()
    );
    finish(&mut target, &secret);
    drop(target);
    let mut target = vault::unlock_with_password(&target_root, PASSWORD, NOW + 30).unwrap();
    assert_purged_ocr_and_healthy_neighbor(&mut target, removed, neighbor, target_ocr_stream);
    assert!(keys::object_key(&target, &removed).is_err());
    assert_eq!(
        chur_catalog::object_grants::request(
            target.catalog().unwrap(),
            &secret,
            vault,
            collection,
            removed
        )
        .err()
        .unwrap()
        .status(),
        ChurStatus::NotFound
    );
    for grant in retained_grants.iter().filter(|grant| {
        grant.object_id() == &removed
            || grant.object_id() == &pending_removed
            || grant.object_id() == &pending_sealed
    }) {
        assert_eq!(
            chur_catalog::object_grants::accept(
                target.catalog().unwrap(),
                &secret,
                vault,
                &[],
                grant
            )
            .unwrap_err()
            .status(),
            ChurStatus::NotFound
        );
    }
    let mut plaintext = Vec::new();
    export::export_stream(
        &target,
        &neighbor,
        StreamKind::Original,
        &mut plaintext,
        &mut Uninterrupted,
    )
    .unwrap();
    assert_eq!(plaintext, b"neighbor remains readable");
    let membership = sync_membership::load(target.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        sync_keys::local_identity(target.catalog_ref().unwrap(), &secret, &membership)
            .unwrap()
            .unwrap()
            .0,
        *request.device_id()
    );
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut target, &mut package, NOW + 31, &mut Uninterrupted).unwrap();
    let restored_root = root();
    backup::restore(&restored_root, &mut package, PASSWORD, &mut Uninterrupted).unwrap();
    let mut restored = vault::unlock_with_password(&restored_root, PASSWORD, NOW + 32).unwrap();
    assert_purged_ocr_and_healthy_neighbor(&mut restored, removed, neighbor, target_ocr_stream);
    assert!(keys::object_key(&restored, &removed).is_err());
    let mut bytes = Vec::new();
    export::export_stream(
        &restored,
        &neighbor,
        StreamKind::Original,
        &mut bytes,
        &mut Uninterrupted,
    )
    .unwrap();
    assert_eq!(bytes, b"neighbor remains readable");
    // Active object IDs stay globally unique. A second collection cannot
    // rebind this active ID, but its pending private request must survive it.
    assert_eq!(
        chur_catalog::object_grants::request(
            target.catalog().unwrap(),
            &secret,
            vault,
            foreign,
            neighbor
        )
        .err()
        .unwrap()
        .status(),
        ChurStatus::NotFound
    );
    deletion::begin(target.catalog().unwrap(), &neighbor).unwrap();
    finish(&mut target, &secret);
    assert_eq!(
        chur_catalog::object_grants::request(
            target.catalog().unwrap(),
            &secret,
            vault,
            foreign,
            neighbor
        )
        .unwrap()
        .encode(),
        foreign_request.encode(),
        "activation and erasure in one collection must preserve the other collection's original private request"
    );
}
