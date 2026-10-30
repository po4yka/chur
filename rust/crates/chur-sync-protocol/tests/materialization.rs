//! Aggregate convergence behavior for decrypted operation payloads.

#![allow(clippy::expect_used)]

use chur_core::Id;
use chur_crypto::{Key, Nonce};
use chur_sync_protocol::convergence::MergeOutcome;
use chur_sync_protocol::materialization::MaterializedState;
use chur_sync_protocol::operation::{DeviceSigningKey, ObservedHead, Operation};
use chur_sync_protocol::payload::{MetadataField, MetadataFieldId, OperationPayload, PayloadBody};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("id")
}

fn operation(
    key: &DeviceSigningKey,
    marker: u8,
    device_id: Id,
    sequence: u64,
    previous: [u8; 32],
    observed: Vec<ObservedHead>,
    payload: &OperationPayload,
) -> Operation {
    Operation::seal(
        id(marker),
        id(1),
        device_id,
        sequence,
        previous,
        observed,
        id(9),
        &Key::new([8; 32]),
        Nonce::new([marker; 24]),
        &payload.encode(),
    )
    .expect("operation")
    .sign(key)
}

#[test]
fn object_metadata_albums_and_favorites_share_one_state() {
    let key = DeviceSigningKey::from_seed([2; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateObject {
            object_id: id(11),
            object_generation: 1,
            store_id: id(12),
            stream_id: id(18),
            metadata_fields: vec![
                MetadataField::new(MetadataFieldId::Caption, b"First".to_vec()).expect("field"),
            ],
        },
    )
    .expect("create");
    let create_operation = operation(&key, 20, id(2), 1, [0; 32], Vec::new(), &create);
    let album = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateAlbum {
            album_id: id(13),
            name: "Trips".to_owned(),
        },
    )
    .expect("album");
    let album_operation = operation(
        &key,
        21,
        id(2),
        2,
        create_operation.digest(),
        Vec::new(),
        &album,
    );
    let membership = OperationPayload::new(
        id(10),
        1,
        PayloadBody::AddAlbumMembership {
            album_id: id(13),
            object_id: id(11),
        },
    )
    .expect("membership");
    let membership_operation = operation(
        &key,
        22,
        id(2),
        3,
        album_operation.digest(),
        Vec::new(),
        &membership,
    );
    let favorite = OperationPayload::new(
        id(10),
        1,
        PayloadBody::SetFavorite {
            object_id: id(11),
            favorite: true,
            removed_tokens: Vec::new(),
        },
    )
    .expect("favorite");
    let favorite_operation = operation(
        &key,
        23,
        id(2),
        4,
        membership_operation.digest(),
        Vec::new(),
        &favorite,
    );
    let mut state = MaterializedState::new();

    state.apply(&create_operation, &create).expect("create");
    state.apply(&album_operation, &album).expect("album");
    state
        .apply(&membership_operation, &membership)
        .expect("membership");
    state
        .apply(&favorite_operation, &favorite)
        .expect("favorite");

    assert_eq!(
        state.metadata(&id(11), MetadataFieldId::Caption),
        Some(b"First".as_slice())
    );
    assert_eq!(state.album_name(&id(13)), Some("Trips"));
    assert!(state.album_contains(&id(13), &id(11)));
    assert!(state.is_favorite(&id(11)));
    assert!(!state.is_presentable(&id(11)));
}

#[test]
fn remove_waits_for_its_observed_add() {
    let key_a = DeviceSigningKey::from_seed([3; 32]);
    let key_b = DeviceSigningKey::from_seed([4; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateObject {
            object_id: id(30),
            object_generation: 1,
            store_id: id(31),
            stream_id: id(29),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let create_operation = operation(&key_a, 32, id(2), 1, [0; 32], Vec::new(), &create);
    let add = OperationPayload::new(
        id(10),
        1,
        PayloadBody::SetFavorite {
            object_id: id(30),
            favorite: true,
            removed_tokens: Vec::new(),
        },
    )
    .expect("add");
    let add_operation = operation(
        &key_a,
        33,
        id(2),
        2,
        create_operation.digest(),
        Vec::new(),
        &add,
    );
    let remove = OperationPayload::new(
        id(10),
        1,
        PayloadBody::SetFavorite {
            object_id: id(30),
            favorite: false,
            removed_tokens: vec![*add_operation.operation_id()],
        },
    )
    .expect("remove");
    let remove_operation = operation(
        &key_b,
        34,
        id(3),
        1,
        [0; 32],
        vec![ObservedHead::new(id(2), 2)],
        &remove,
    );
    let mut state = MaterializedState::new();
    state.apply(&create_operation, &create).expect("create");

    assert_eq!(
        state.apply(&remove_operation, &remove).expect("pending"),
        MergeOutcome::PendingCause
    );
    state.apply(&add_operation, &add).expect("add");
    state.apply(&remove_operation, &remove).expect("remove");
    assert!(!state.is_favorite(&id(30)));
}

#[test]
fn a_commit_and_edit_of_an_older_generation_land_in_both_arrival_orders() {
    let key_a = DeviceSigningKey::from_seed([2; 32]);
    let key_b = DeviceSigningKey::from_seed([3; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateObject {
            object_id: id(60),
            object_generation: 1,
            store_id: id(61),
            stream_id: id(62),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let create_operation = operation(&key_a, 63, id(2), 1, [0; 32], Vec::new(), &create);
    let edit = OperationPayload::new(
        id(10),
        1,
        PayloadBody::UpdateMetadata {
            object_id: id(60),
            object_generation: 1,
            field: MetadataField::new(MetadataFieldId::Caption, b"Edited".to_vec()).expect("field"),
        },
    )
    .expect("edit");
    let edit_operation = operation(
        &key_a,
        64,
        id(2),
        2,
        create_operation.digest(),
        Vec::new(),
        &edit,
    );
    let commit = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CommitObject {
            object_id: id(60),
            object_generation: 1,
            store_id: id(61),
            container_length: 100,
            container_commitment: [47; 32],
            object_key_commitment: [46; 32],
        },
    )
    .expect("commit");
    let commit_operation = operation(
        &key_a,
        65,
        id(2),
        3,
        edit_operation.digest(),
        Vec::new(),
        &commit,
    );
    let delete = OperationPayload::new(
        id(10),
        1,
        PayloadBody::DeleteObject {
            object_id: id(60),
            object_generation: 1,
            authored_at_ms: 1,
        },
    )
    .expect("delete");
    let delete_operation = operation(
        &key_b,
        66,
        id(3),
        1,
        [0; 32],
        vec![ObservedHead::new(id(2), 1)],
        &delete,
    );
    let restore = OperationPayload::new(
        id(10),
        1,
        PayloadBody::RestoreObject {
            object_id: id(60),
            tombstone_operation_id: *delete_operation.operation_id(),
            new_object_generation: 2,
        },
    )
    .expect("restore");
    let restore_operation = operation(
        &key_b,
        67,
        id(3),
        2,
        delete_operation.digest(),
        vec![ObservedHead::new(id(2), 1)],
        &restore,
    );

    // The edit and the commit are concurrent with the delete-and-restore pair
    // on the second device. Whichever order the operations arrive in, the
    // retained state must end up the same: gating the older generation as
    // Obsolete silently dropped them whenever the restore replayed first.
    let mut ordered = MaterializedState::new();
    for (op, payload) in [
        (&create_operation, &create),
        (&edit_operation, &edit),
        (&commit_operation, &commit),
        (&delete_operation, &delete),
        (&restore_operation, &restore),
    ] {
        ordered.apply(op, payload).expect("ordered apply");
    }
    let mut permuted = MaterializedState::new();
    for (op, payload) in [
        (&create_operation, &create),
        (&delete_operation, &delete),
        (&restore_operation, &restore),
        (&edit_operation, &edit),
        (&commit_operation, &commit),
    ] {
        permuted.apply(op, payload).expect("permuted apply");
    }

    for state in [&ordered, &permuted] {
        assert_eq!(
            state.metadata(&id(60), MetadataFieldId::Caption),
            Some(b"Edited".as_slice())
        );
        assert!(state.committed_object(&id(60)).is_some());
        assert!(state.is_presentable(&id(60)));
    }
}

#[test]
fn committed_object_keeps_the_stream_identity_needed_for_download() {
    let key = DeviceSigningKey::from_seed([5; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateObject {
            object_id: id(40),
            object_generation: 1,
            store_id: id(41),
            stream_id: id(42),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let create_operation = operation(&key, 43, id(2), 1, [0; 32], Vec::new(), &create);
    let commit = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CommitObject {
            object_id: id(40),
            object_generation: 1,
            store_id: id(41),
            container_length: 100,
            container_commitment: [47; 32],
            object_key_commitment: [46; 32],
        },
    )
    .expect("commit");
    let commit_operation = operation(
        &key,
        48,
        id(2),
        2,
        create_operation.digest(),
        Vec::new(),
        &commit,
    );
    let mut state = MaterializedState::new();
    state.apply(&create_operation, &create).expect("create");
    state.apply(&commit_operation, &commit).expect("commit");

    assert_eq!(
        state
            .committed_object(&id(40))
            .expect("committed")
            .stream_id(),
        &id(42)
    );
}

#[test]
fn concurrent_matching_album_creations_share_one_initial_value_in_every_order() {
    let key = DeviceSigningKey::from_seed([2; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateAlbum {
            album_id: id(13),
            name: "Legacy".into(),
        },
    )
    .expect("create payload");
    let first = operation(&key, 40, id(2), 1, [0; 32], vec![], &create);
    let second = operation(&key, 41, id(3), 1, [0; 32], vec![], &create);
    let rename = OperationPayload::new(
        id(10),
        1,
        PayloadBody::RenameAlbum {
            album_id: id(13),
            name: "Explicit rename".into(),
        },
    )
    .expect("rename payload");
    let renamed = operation(&key, 42, id(2), 2, first.digest(), vec![], &rename);
    let records = [(&first, &create), (&second, &create), (&renamed, &rename)];
    for order in [[0, 1, 2], [1, 0, 2], [0, 2, 1], [1, 2, 0]] {
        let mut state = MaterializedState::new();
        for index in order {
            let (op, payload) = records[index];
            assert_eq!(
                state
                    .apply(op, payload)
                    .expect("concurrent creation or rename"),
                MergeOutcome::Applied
            );
        }
        assert_eq!(state.album_name(&id(13)), Some("Explicit rename"));
        assert_eq!(
            state.apply(&first, &create).expect("exact replay"),
            MergeOutcome::Duplicate
        );
    }
}

#[test]
fn album_creation_rejects_conflicting_name_collection_and_causal_identifier_reuse() {
    let key = DeviceSigningKey::from_seed([2; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateAlbum {
            album_id: id(13),
            name: "Legacy".into(),
        },
    )
    .expect("create payload");
    let first = operation(&key, 40, id(2), 1, [0; 32], vec![], &create);
    let mut state = MaterializedState::new();
    state.apply(&first, &create).expect("initial creation");
    let different_name = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateAlbum {
            album_id: id(13),
            name: "Different".into(),
        },
    )
    .expect("different name payload");
    let different_collection = OperationPayload::new(
        id(14),
        1,
        PayloadBody::CreateAlbum {
            album_id: id(13),
            name: "Legacy".into(),
        },
    )
    .expect("different collection payload");
    let name_reuse = operation(&key, 41, id(3), 1, [0; 32], vec![], &different_name);
    let collection_reuse = operation(&key, 42, id(3), 1, [0; 32], vec![], &different_collection);
    let causal_reuse = operation(&key, 43, id(2), 2, first.digest(), vec![], &create);
    for (op, payload) in [
        (&name_reuse, &different_name),
        (&collection_reuse, &different_collection),
        (&causal_reuse, &create),
    ] {
        assert_eq!(
            state
                .apply(op, payload)
                .expect_err("reused ID rejected")
                .status(),
            chur_core::ChurStatus::AuthenticationFailed
        );
    }
    assert_eq!(state.album_name(&id(13)), Some("Legacy"));
}

#[test]
fn a_rejected_tag_leaves_no_partial_state_behind() {
    let key = DeviceSigningKey::from_seed([2; 32]);
    let create = OperationPayload::new(
        id(10),
        1,
        PayloadBody::CreateObject {
            object_id: id(11),
            object_generation: 1,
            store_id: id(12),
            stream_id: id(18),
            metadata_fields: Vec::new(),
        },
    )
    .expect("create");
    let create_operation = operation(&key, 20, id(2), 1, [0; 32], Vec::new(), &create);
    let tag = |tag_id: u8, name: &str| {
        OperationPayload::new(
            id(10),
            1,
            PayloadBody::AddTag {
                tag_id: id(tag_id),
                object_id: id(11),
                name: name.to_owned(),
            },
        )
        .expect("tag")
    };
    let first = tag(30, "Trips");
    let first_operation = operation(
        &key,
        24,
        id(2),
        2,
        create_operation.digest(),
        Vec::new(),
        &first,
    );
    // Same operation identifier, different content: the set refuses it after
    // the tag name register would already have taken the new name.
    let reused = tag(31, "Other");
    let reused_operation = operation(
        &key,
        24,
        id(2),
        3,
        first_operation.digest(),
        Vec::new(),
        &reused,
    );
    let mut state = MaterializedState::new();
    state.apply(&create_operation, &create).expect("create");
    state.apply(&first_operation, &first).expect("first tag");

    state
        .apply(&reused_operation, &reused)
        .expect_err("reused operation identifier");

    assert_eq!(state.tag_name(&id(30)), Some("Trips"));
    assert_eq!(state.tag_name(&id(31)), None);
}
