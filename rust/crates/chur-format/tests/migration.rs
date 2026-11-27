//! The migration harness.
//!
//! `docs/assurance/MIGRATION_POLICY.md` §1 versions ten domains independently
//! and §2 states the rules that hold before any second version exists:
//!
//! - a reader fails closed on an unknown critical version or suite;
//! - accepted v1 bytes are never reinterpreted without a new version;
//! - a writer emits only the current approved version.
//!
//! Apart from the bucket-padded object container of ADR-0066, which a reader
//! takes beside v1 rather than migrating to, v1 is the only version of every
//! format, so this harness cannot migrate anything. What it can do, and what it does, is prove that each domain's
//! reader refuses a version it does not know, and refuses it as an unsupported
//! artifact rather than as a damaged one. That distinction is the whole of the
//! migration contract today: a future reader finds `UNSUPPORTED_VERSION` and
//! knows a migration exists, where `OBJECT_CORRUPT` would tell it to restore
//! from backup.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use chur_core::Id;
use chur_core::status::ChurStatus;
use chur_crypto::aead::Nonce;
use chur_crypto::secret::Key;
use chur_format::constants::{MediaClass, SlotType, StreamKind, VaultState};
use chur_format::container::{
    CanonicalManifest, Layout, MediaProperties, NONCE_PREFIX_LEN, StreamIdentity, encode_container,
};
use chur_format::descriptor::{
    CatalogDescriptor, KeySlotDescriptor, ObjectStoreDescriptor, VaultDescriptor,
};
use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
use chur_format::slot::{PasswordSlotBody, RecoverySlotBody, SlotBinding};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn key(byte: u8) -> Key {
    Key::new([byte; 32])
}

fn nonce(byte: u8) -> Nonce {
    Nonce::new([byte; 24])
}

/// Raises the `u16` at `offset` to 3, a value no namespace allocates, so the
/// reader must fail closed. Container version 2 is allocated by ADR-0066.
fn bumped_u16(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset..offset + 2].copy_from_slice(&3u16.to_be_bytes());
    out
}

#[test]
fn a_container_from_a_later_version_is_unsupported_not_corrupt() {
    let manifest = CanonicalManifest::new(
        StreamIdentity {
            object_id: id(0x33),
            stream_id: id(0x34),
            stream_kind: StreamKind::Original,
            stream_revision: 1,
        },
        None,
        65_536,
        [0x35; NONCE_PREFIX_LEN],
        1,
        MediaProperties::new(MediaClass::Opaque, 0, 0, 0).unwrap(),
    )
    .unwrap();
    let bytes = encode_container(
        &key(0x77),
        manifest,
        nonce(0x36),
        b"payload",
        nonce(0x37),
        1,
    )
    .unwrap();

    // container_version, canonical_encoding_profile, chunk_record_profile.
    for offset in [0x08usize, 0x0a, 0x18] {
        assert_eq!(
            Layout::parse(&bumped_u16(&bytes, offset))
                .unwrap_err()
                .status(),
            ChurStatus::UnsupportedVersion,
            "offset {offset:#x}"
        );
    }
    // suite_id has its own code, because a suite change is not a version change.
    assert_eq!(
        Layout::parse(&bumped_u16(&bytes, 0x0c))
            .unwrap_err()
            .status(),
        ChurStatus::UnsupportedSuite
    );
}

#[test]
fn both_key_envelopes_from_a_later_version_are_unsupported() {
    let collection = CollectionKeyEnvelope::seal(
        &key(0x5a),
        id(0x11),
        id(0x22),
        1,
        1,
        nonce(0x33),
        &key(0x44),
    )
    .unwrap()
    .encode();
    let object = ObjectKeyEnvelope::seal(
        &key(0x44),
        id(0x11),
        id(0x22),
        1,
        id(0x33),
        1,
        nonce(0x66),
        &key(0x77),
    )
    .unwrap()
    .encode();

    for offset in [0x00usize, 0x02] {
        assert_eq!(
            CollectionKeyEnvelope::decode(&bumped_u16(&collection, offset))
                .unwrap_err()
                .status(),
            ChurStatus::UnsupportedVersion
        );
        assert_eq!(
            ObjectKeyEnvelope::decode(&bumped_u16(&object, offset))
                .unwrap_err()
                .status(),
            ChurStatus::UnsupportedVersion
        );
    }
    assert_eq!(
        CollectionKeyEnvelope::decode(&bumped_u16(&collection, 0x04))
            .unwrap_err()
            .status(),
        ChurStatus::UnsupportedSuite
    );
    assert_eq!(
        ObjectKeyEnvelope::decode(&bumped_u16(&object, 0x04))
            .unwrap_err()
            .status(),
        ChurStatus::UnsupportedSuite
    );
}

#[test]
fn a_descriptor_from_a_later_version_is_unsupported_before_any_credential() {
    let descriptor = VaultDescriptor {
        vault_id: id(0x11),
        descriptor_generation: 1,
        state: VaultState::Active,
        catalog: CatalogDescriptor {
            catalog_format_version: chur_format::constants::CATALOG_FORMAT_VERSION_V1,
            opaque_catalog_path_id: id(0x12),
            catalog_generation: 1,
            catalog_header_commitment: [0x13; 32],
        },
        object_store: ObjectStoreDescriptor::v1(id(0x14)),
        key_slots: vec![
            KeySlotDescriptor::v1(id(0x55), SlotType::Password, 1, vec![0xaa; 16]).unwrap(),
        ],
        migration: None,
    };
    let bytes = descriptor.encode(&key(0x5a)).unwrap();

    // descriptor_version, canonical_encoding_profile, crypto_policy_id.
    for offset in [0x08usize, 0x0a, 0x0c] {
        let raised = bumped_u16(&bytes, offset);
        assert_eq!(
            VaultDescriptor::parse(&raised).unwrap_err().status(),
            ChurStatus::UnsupportedVersion,
            "offset {offset:#x}"
        );
        // §8 step 2 runs before a credential, so the same code appears even
        // when a candidate root is offered.
        assert_eq!(
            VaultDescriptor::authenticate(&raised, Some(&key(0x5a)))
                .unwrap_err()
                .status(),
            ChurStatus::UnsupportedVersion
        );
    }
}

#[test]
fn a_slot_body_from_a_later_profile_is_unsupported() {
    let binding = SlotBinding::v1(id(0x11), id(0x55), SlotType::Password, 1);
    let params = chur_crypto::password::Argon2Params::validated(65_536, 3, 1).unwrap();
    let password = PasswordSlotBody::seal(
        &binding,
        b"password",
        vec![0x77; 16],
        params,
        nonce(0x88),
        &key(0x5a),
    )
    .unwrap()
    .encode();
    assert_eq!(
        PasswordSlotBody::decode(&bumped_u16(&password, 0))
            .unwrap_err()
            .status(),
        ChurStatus::UnsupportedVersion
    );

    let recovery_binding = SlotBinding::v1(id(0x11), id(0x56), SlotType::Recovery, 1);
    let recovery = RecoverySlotBody::seal(&recovery_binding, &key(0x99), nonce(0xaa), &key(0x5a))
        .unwrap()
        .encode();
    assert_eq!(
        RecoverySlotBody::decode(&bumped_u16(&recovery, 0))
            .unwrap_err()
            .status(),
        ChurStatus::UnsupportedVersion
    );
}

#[test]
fn a_writer_emits_only_the_current_approved_version() {
    // §2: writers emit only current approved versions. Every encoder writes the
    // v1 constants without offering a parameter that could select another.
    let collection = CollectionKeyEnvelope::seal(
        &key(0x5a),
        id(0x11),
        id(0x22),
        1,
        1,
        nonce(0x33),
        &key(0x44),
    )
    .unwrap()
    .encode();
    assert_eq!(&collection[0..6], &[0, 1, 0, 1, 0, 1]);

    let descriptor = VaultDescriptor {
        vault_id: id(0x11),
        descriptor_generation: 1,
        state: VaultState::Active,
        catalog: CatalogDescriptor {
            catalog_format_version: chur_format::constants::CATALOG_FORMAT_VERSION_V1,
            opaque_catalog_path_id: id(0x12),
            catalog_generation: 1,
            catalog_header_commitment: [0x13; 32],
        },
        object_store: ObjectStoreDescriptor::v1(id(0x14)),
        key_slots: vec![
            KeySlotDescriptor::v1(id(0x55), SlotType::Password, 1, vec![0xaa; 16]).unwrap(),
        ],
        migration: None,
    }
    .encode(&key(0x5a))
    .unwrap();
    assert_eq!(&descriptor[0x08..0x0e], &[0, 1, 0, 1, 0, 1]);
}

#[test]
fn accepted_v1_bytes_decode_to_the_same_values_they_encoded() {
    // §2: never reinterpret accepted v1 bytes without a new version. A decode
    // that reproduces its own input is the mechanical half of that rule.
    let manifest = CanonicalManifest::new(
        StreamIdentity {
            object_id: id(0x33),
            stream_id: id(0x34),
            stream_kind: StreamKind::GridPreview,
            stream_revision: 4,
        },
        Some(2),
        262_144,
        [0x35; NONCE_PREFIX_LEN],
        7,
        MediaProperties::new(MediaClass::Video, 1920, 1080, 12_345).unwrap(),
    )
    .unwrap();
    let encoded = manifest.encode();
    let decoded = CanonicalManifest::decode(&encoded).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.encode(), encoded);
}
