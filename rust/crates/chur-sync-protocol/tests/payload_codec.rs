//! Cross-kind checks for the canonical encrypted operation payload.

#![allow(clippy::expect_used, clippy::panic)]

use chur_core::{ChurStatus, Id};
use chur_crypto::{Key, Nonce};
use chur_format::envelope::CollectionKeyEnvelope;
use chur_sync_protocol::collection_membership::{
    CollectionMembershipAction, CollectionMembershipRecord,
};
use chur_sync_protocol::collection_operation::CollectionOperation;
use chur_sync_protocol::grant::{CollectionGrant, PermissionProfile};
use chur_sync_protocol::identity::DeviceIdentity;
use chur_sync_protocol::membership::{EnrollmentRecord, RevocationRecord};
use chur_sync_protocol::operation::{DeviceSigningKey, Operation};
use chur_sync_protocol::payload::{MetadataField, MetadataFieldId, OperationPayload, PayloadBody};
use chur_sync_protocol::{KeyDirectory, KeyDomain};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("non-zero identifier")
}

#[test]
fn sharing_records_round_trip_as_bounded_payload_kinds() {
    let source_key = DeviceSigningKey::from_seed([1; 32]);
    let recipient = DeviceIdentity::from_seeds([2; 32], [3; 32]);
    let membership = CollectionMembershipRecord::new(
        id(4),
        id(5),
        1,
        [0; 32],
        CollectionMembershipAction::Upsert(PermissionProfile::Read),
        id(6),
        id(7),
        recipient.signing_public_key(),
        recipient.hpke_public_key(),
        7,
        id(4),
        id(8),
        1,
        9,
    )
    .expect("membership")
    .sign(&source_key);
    let grant = CollectionGrant::seal(
        id(10),
        id(4),
        id(5),
        7,
        1,
        id(6),
        id(7),
        &recipient.hpke_public_key(),
        id(8),
        PermissionProfile::Read,
        1,
        11,
        &Key::new([12; 32]),
        &source_key,
    )
    .expect("grant");

    let payloads = [
        PayloadBody::ChangeCollectionMembership(membership),
        PayloadBody::IssueCollectionGrant(grant),
    ]
    .map(|body| OperationPayload::new(id(5), 7, body).expect("payload"));
    for payload in &payloads {
        assert!(OperationPayload::decode(&payload.encode()).is_ok_and(|value| &value == payload));
    }

    let membership_operation = Operation::new(
        id(13),
        id(4),
        id(8),
        9,
        [1; 32],
        Vec::new(),
        id(14),
        [vec![15; 24], vec![16; 16]].concat(),
        [0; 64],
    )
    .expect("membership operation");
    payloads[0]
        .validate_for_operation(&membership_operation, &id(5), 7)
        .expect("membership binding");
    let grant_operation = Operation::new(
        id(10),
        id(4),
        id(8),
        11,
        [1; 32],
        Vec::new(),
        id(14),
        [vec![15; 24], vec![16; 16]].concat(),
        [0; 64],
    )
    .expect("grant operation");
    payloads[1]
        .validate_for_operation(&grant_operation, &id(5), 7)
        .expect("grant binding");
}

#[test]
fn a_collection_operation_accepts_only_content_payload_kinds() {
    let collection = id(1);
    let collection_key = Key::new([2; 32]);
    let domain = KeyDomain::collection(&collection_key, &collection, 7).expect("domain");
    let selector = *domain.selector();
    let mut keys = KeyDirectory::new(&Key::new([3; 32]), &id(4)).expect("directory");
    keys.insert(domain).expect("insert domain");
    let payload = OperationPayload::new(
        collection,
        7,
        PayloadBody::CreateAlbum {
            album_id: id(5),
            name: "Shared".to_owned(),
        },
    )
    .expect("payload");
    let operation = CollectionOperation::seal(
        id(6),
        id(7),
        id(8),
        1,
        [0; 32],
        Vec::new(),
        selector,
        keys.operation_key(&selector).expect("operation key"),
        Nonce::new([9; 24]),
        &payload.encode(),
    )
    .expect("operation");

    assert!(
        OperationPayload::open_for_collection_operation(&operation, &keys)
            .is_ok_and(|opened| opened == payload)
    );

    let identity = DeviceIdentity::from_seeds([10; 32], [11; 32]);
    let enrollment = EnrollmentRecord::initial(
        id(7),
        id(8),
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )
    .expect("enrollment")
    .sign(&DeviceSigningKey::from_seed([10; 32]));
    let forbidden =
        OperationPayload::new(id(7), 0, PayloadBody::AddDevice(enrollment)).expect("root payload");
    assert_eq!(
        forbidden
            .validate_for_collection_operation(&id(7), 0)
            .expect_err("identity payload must be rejected")
            .status(),
        ChurStatus::AuthenticationFailed
    );
}

#[test]
fn every_allocated_payload_kind_has_one_canonical_round_trip() {
    let vault = id(1);
    let collection = id(2);
    let object = id(3);
    let collection_envelope = CollectionKeyEnvelope::seal(
        &Key::new([4; 32]),
        vault,
        collection,
        8,
        1,
        Nonce::new([5; 24]),
        &Key::new([6; 32]),
    )
    .expect("collection envelope");
    let signing_key = DeviceSigningKey::from_seed([7; 32]);
    let enrollment = EnrollmentRecord::initial(vault, id(8), signing_key.verifying_key(), [9; 32])
        .expect("enrollment")
        .sign(&signing_key);
    let revocation = RevocationRecord::new(vault, id(10), 4, [11; 32], 2, id(8), [12; 32])
        .expect("revocation")
        .sign(&signing_key);
    let caption =
        MetadataField::new(MetadataFieldId::Caption, b"private".to_vec()).expect("caption");
    let rating = MetadataField::new(MetadataFieldId::Rating, vec![5]).expect("rating");
    let payloads = vec![
        OperationPayload::new(
            collection,
            7,
            PayloadBody::CreateObject {
                object_id: object,
                object_generation: 1,
                store_id: id(13),
                stream_id: id(20),
                metadata_fields: vec![caption.clone(), rating],
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::CommitObject {
                object_id: object,
                object_generation: 1,
                store_id: id(13),
                container_length: 100,
                container_commitment: [14; 32],
                object_key_commitment: [3; 32],
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::UpdateMetadata {
                object_id: object,
                object_generation: 1,
                field: caption,
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::CreateAlbum {
                album_id: id(15),
                name: "Private".to_owned(),
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::RenameAlbum {
                album_id: id(15),
                name: "Renamed".to_owned(),
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::AddAlbumMembership {
                album_id: id(15),
                object_id: object,
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::RemoveAlbumMembership {
                album_id: id(15),
                object_id: object,
                removed_tokens: vec![id(16)],
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::SetFavorite {
                object_id: object,
                favorite: true,
                removed_tokens: Vec::new(),
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::AddTag {
                tag_id: id(17),
                object_id: object,
                name: "tag".to_owned(),
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::RemoveTag {
                tag_id: id(17),
                object_id: object,
                removed_tokens: vec![id(18)],
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::DeleteObject {
                object_id: object,
                object_generation: 1,
                authored_at_ms: 1_787_990_400_000,
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::RestoreObject {
                object_id: object,
                tombstone_operation_id: id(19),
                new_object_generation: 2,
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::PurgeObject {
                object_id: object,
                object_generation: 1,
                authored_at_ms: 1_787_990_400_000,
            },
        ),
        OperationPayload::new(vault, 0, PayloadBody::DeviceReady),
        OperationPayload::new(
            vault,
            0,
            PayloadBody::DeclareCollection {
                collection_key_envelope: collection_envelope.clone(),
            },
        ),
        OperationPayload::new(vault, 0, PayloadBody::AddDevice(enrollment)),
        OperationPayload::new(vault, 0, PayloadBody::RevokeDevice(revocation)),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch: 7,
                membership_generation: 2,
                collection_key_envelope: collection_envelope,
            },
        ),
        OperationPayload::new(
            collection,
            7,
            PayloadBody::RewrapObjectKey {
                object_id: object,
                object_key_commitment: [3; 32],
            },
        ),
    ];

    for payload in payloads {
        let payload = payload.expect("valid payload");
        let encoded = payload.encode();
        assert!(OperationPayload::decode(&encoded).expect("decode") == payload);
    }
}

#[test]
fn parser_and_semantic_non_canonical_forms_fail_closed() {
    let payload = OperationPayload::new(
        id(1),
        7,
        PayloadBody::CreateAlbum {
            album_id: id(2),
            name: "Private".to_owned(),
        },
    )
    .expect("payload");
    let mut unknown = payload.encode();
    unknown[2] = 0xff;
    assert_eq!(
        OperationPayload::decode(&unknown)
            .err()
            .expect("unknown kind")
            .status(),
        ChurStatus::UnsupportedVersion
    );
    let mut trailing = payload.encode();
    trailing.push(0);
    assert_eq!(
        OperationPayload::decode(&trailing)
            .err()
            .expect("trailing byte")
            .status(),
        ChurStatus::NonCanonicalEncoding
    );
    assert!(
        OperationPayload::new(
            id(1),
            7,
            PayloadBody::RemoveTag {
                tag_id: id(2),
                object_id: id(3),
                removed_tokens: vec![id(5), id(4)],
            },
        )
        .is_err()
    );
    assert!(
        OperationPayload::new(
            id(1),
            7,
            PayloadBody::SetFavorite {
                object_id: id(3),
                favorite: false,
                removed_tokens: Vec::new(),
            },
        )
        .is_err()
    );
    assert!(MetadataField::new(MetadataFieldId::MediaType, b"Image/JPEG".to_vec()).is_err());
}

#[test]
fn key_free_records_must_match_the_authenticated_outer_domain() {
    let vault = id(1);
    let collection = id(2);
    let object = id(3);
    let payload = OperationPayload::new(
        collection,
        7,
        PayloadBody::RewrapObjectKey {
            object_id: object,
            object_key_commitment: [3; 32],
        },
    )
    .expect("payload");
    let operation = Operation::new(
        id(4),
        vault,
        id(5),
        1,
        [0; 32],
        Vec::new(),
        id(6),
        [vec![7; 24], vec![8; 16]].concat(),
        [0; 64],
    )
    .expect("operation");

    assert_eq!(
        payload
            .validate_for_operation(&operation, &id(9), 7)
            .expect_err("wrong collection domain")
            .status(),
        ChurStatus::AuthenticationFailed
    );
}
