//! The deterministic v1 vector set.
//!
//! Every value here is a fixed test-only constant. `docs/format/TEST_VECTORS.md`
//! §3 permits deterministic keys, salts, nonces, passwords, and recovery
//! secrets inside `test-vectors/` and requires them to be clearly marked:
//!
//! ```text
//! TEST-ONLY — NEVER USE FOR REAL VAULTS
//! ```
//!
//! No production API selects deterministic randomness. This module builds its
//! bytes explicitly instead of replacing `chur_crypto::random`, so the
//! generator and a release build share no code path that could substitute one
//! for the other.

use serde_json::json;

use chur_core::limits::{ID_LEN, KEY_LEN, NONCE_LEN};
use chur_core::{ChurStatus, Error, Id, Result};
use chur_crypto::aead::Nonce;
use chur_crypto::commit;
use chur_crypto::kdf::{self, Context, ContextShape, Label};
use chur_crypto::password::{self, Argon2Params};
use chur_crypto::recovery;
use chur_crypto::secret::Key;
use chur_crypto::tuple::{Tuple, tag};
use chur_format::codec::Writer;
use chur_format::constants::{MediaClass, SlotType, StreamKind, VaultState};
use chur_format::container::{
    CanonicalManifest, ContainerReader, ContainerVersion, MediaProperties, NONCE_PREFIX_LEN,
    PaddingDeviation, PublicPreamble, StreamIdentity, encode_container_with_version,
    encode_deviant_container, padded_length,
};
use chur_format::descriptor::{
    CatalogDescriptor, KeySlotDescriptor, MigrationDescriptor, ObjectStoreDescriptor,
    VaultDescriptor,
};
use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
use chur_format::slot::{
    AndroidKeystoreSlotBody, AppleKeychainSlotBody, PasswordSlotBody, RecoverySlotBody, SlotBinding,
};
use chur_sync_protocol::checkpoint::{
    Checkpoint, CheckpointHead, UNCOMPACTED_CATALOG_STATE_COMMITMENT, collection_epoch_commitment,
};
use chur_sync_protocol::collection_membership::{
    CollectionMembershipAction, CollectionMembershipRecord,
};
use chur_sync_protocol::collection_operation::{CollectionObservedHead, CollectionOperation};
use chur_sync_protocol::grant::{CollectionGrant, PermissionProfile, hpke_key_id, signing_key_id};
use chur_sync_protocol::identity::DeviceIdentity;
use chur_sync_protocol::membership::{EnrollmentRecord, RevocationRecord};
use chur_sync_protocol::object_grant::{ObjectKeyGrant, ObjectPrekey, object_key_commitment};
use chur_sync_protocol::operation::{DeviceSigningKey, ObservedHead, Operation};
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};

use crate::manifest::{Vector, VectorBuilder, hex_of, number};

/// The marker every generated `README` and manifest note carries.
pub const TEST_ONLY: &str = "TEST-ONLY — NEVER USE FOR REAL VAULTS";

/// A fixed identifier built from one repeated byte.
fn id(byte: u8) -> Result<Id> {
    Id::new([byte; ID_LEN])
}

/// A fixed key built from one repeated byte.
fn key(byte: u8) -> Key {
    Key::new([byte; KEY_LEN])
}

/// A fixed nonce built from one repeated byte.
fn nonce(byte: u8) -> Nonce {
    Nonce::new([byte; NONCE_LEN])
}

fn expect_rejection<T>(result: Result<T>, expected: ChurStatus) -> Result<()> {
    match result {
        Err(error) if error.status() == expected => Ok(()),
        _ => Err(Error::new(
            ChurStatus::InternalFailure,
            "a generated negative vector did not fail as declared",
        )),
    }
}

/// A repeatable plaintext pattern of the given length.
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

/// The chunk size every container vector uses: the v1 minimum, 64 KiB.
const VECTOR_CHUNK_SIZE: u32 = 65_536;

/// Builds the whole vector set, sorted by `vector_id`.
///
/// # Errors
///
/// Returns an error when a construction the vectors exercise fails, which for
/// fixed inputs means the library is broken rather than the input.
pub fn build_all() -> Result<Vec<Vector>> {
    let mut vectors = Vec::new();
    canonical_encoding(&mut vectors)?;
    key_derivations(&mut vectors)?;
    password_slots(&mut vectors)?;
    recovery_slots(&mut vectors)?;
    platform_slots(&mut vectors)?;
    vault_descriptors(&mut vectors)?;
    collection_envelopes(&mut vectors)?;
    object_key_envelopes(&mut vectors)?;
    object_containers(&mut vectors)?;
    backup_packages(&mut vectors)?;
    sync_protocol(&mut vectors)?;
    disposable_object_keys(&mut vectors)?;
    sharing_protocol(&mut vectors)?;
    vectors.sort_by(|left, right| left.entry.vector_id.cmp(&right.entry.vector_id));
    Ok(vectors)
}

const ENCODING_SPEC: &str = "docs/format/CANONICAL_ENCODING_V1.md";
const CONTAINER_SPEC: &str = "docs/format/OBJECT_CONTAINER_V1.md";
const DESCRIPTOR_SPEC: &str = "docs/format/VAULT_DESCRIPTOR_V1.md";
const SLOT_SPEC: &str = "docs/format/KEY_SLOT_BODIES_V1.md";
const HIERARCHY_SPEC: &str = "docs/security/KEY_HIERARCHY.md";
const COLLECTION_ENVELOPE_SPEC: &str = "docs/format/COLLECTION_KEY_ENVELOPE_V1.md";
const OBJECT_ENVELOPE_SPEC: &str = "docs/format/OBJECT_KEY_ENVELOPE_V1.md";
const RECOVERY_SPEC: &str = "docs/security/RECOVERY.md";
const BACKUP_SPEC: &str = "docs/format/BACKUP_FORMAT_V1.md";
const OPERATION_SPEC: &str = "docs/sync/OPERATION_LOG.md";
const IDENTITY_SPEC: &str = "docs/sync/DEVICE_IDENTITY.md";
const ROLLBACK_SPEC: &str = "docs/sync/ROLLBACK_PROTECTION.md";
const GRANT_SPEC: &str = "docs/sync/COLLECTION_GRANTS.md";
const COLLECTION_MEMBERSHIP_SPEC: &str = "docs/sync/COLLECTION_MEMBERSHIP.md";
const COLLECTION_OPERATION_SPEC: &str = "docs/sync/COLLECTION_OPERATION_LOG.md";

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

fn canonical_encoding(out: &mut Vec<Vector>) -> Result<()> {
    let mut writer = Writer::new();
    writer
        .u8(0)
        .u8(u8::MAX)
        .u16(0)
        .u16(u16::MAX)
        .u32(0)
        .u32(u32::MAX)
        .u64(0)
        .u64(u64::MAX)
        .bool(false)
        .bool(true)
        .presence(false)
        .presence(true);
    let boundaries = writer.finish();
    out.push(
        VectorBuilder::accept(
            "canonical-encoding",
            "canonical-encoding-v1-primitive-boundaries",
            ENCODING_SPEC,
            "2",
            "Every fixed-width primitive at both bounds, then a boolean and an optional presence byte in both states.",
        )
        .input("field_order", json!([
            "u8 minimum", "u8 maximum", "u16 minimum", "u16 maximum",
            "u32 minimum", "u32 maximum", "u64 minimum", "u64 maximum",
            "boolean false", "boolean true", "optional absent", "optional present"
        ]))
        .expect_bytes("encoded", &boundaries)
        .expect("encoded_length", json!(boundaries.len()))
        .build(),
    );

    let mut writer = Writer::new();
    writer.variable(b"")?.variable(b"chur")?;
    let variable = writer.finish();
    out.push(
        VectorBuilder::accept(
            "canonical-encoding",
            "canonical-encoding-v1-empty-and-short-variable-elements",
            ENCODING_SPEC,
            "2",
            "A zero-length variable element carries its u32 length and no bytes; a short one follows it.",
        )
        .input("elements", json!(["", "chur"]))
        .expect_bytes("encoded", &variable)
        .build(),
    );

    out.push(
        VectorBuilder::accept(
            "canonical-encoding",
            "canonical-encoding-v1-maximum-identifier",
            ENCODING_SPEC,
            "8",
            "The all-ones identifier is a valid 16-byte value; only the all-zero value is reserved.",
        )
        .input_bytes("identifier", &[0xff; ID_LEN])
        .expect("accepted", json!(true))
        .build(),
    );

    let example = Tuple::new(b"CHUR\0EXAMPLE\0TUPLE\0V1")
        .u16(0x0001)
        .id(&id(0xaa)?)
        .string("label")?
        .finish();
    out.push(
        VectorBuilder::accept(
            "canonical-encoding",
            "canonical-encoding-v1-illustrative-tuple",
            ENCODING_SPEC,
            "7.1",
            "The worked tuple example: a bare tag, a u16, a 16-byte fixed element, then a u32-prefixed string.",
        )
        .input("domain_tag", json!(hex_of(b"CHUR\0EXAMPLE\0TUPLE\0V1")))
        .input("suite_id", json!(1))
        .input_bytes("object_id", &[0xaa; ID_LEN])
        .input("label", json!("label"))
        .expect_bytes("encoded", &example)
        .expect("encoded_length", json!(example.len()))
        .note("The tag is unregistered and illustrative; no record uses it.")
        .build(),
    );

    out.push(
        VectorBuilder::reject(
            "canonical-encoding",
            "canonical-encoding-v1-all-zero-identifier",
            ENCODING_SPEC,
            "8",
            "The all-zero identifier is reserved as invalid.",
            "INVALID_INPUT",
        )
        .input_bytes("identifier", &[0x00; ID_LEN])
        .build(),
    );
    out.push(
        VectorBuilder::reject(
            "canonical-encoding",
            "canonical-encoding-v1-boolean-byte-two",
            ENCODING_SPEC,
            "11",
            "A boolean byte other than 0x00 or 0x01 is not canonical.",
            "NON_CANONICAL_ENCODING",
        )
        .input_bytes("encoded", &[0x02])
        .build(),
    );
    out.push(
        VectorBuilder::reject(
            "canonical-encoding",
            "canonical-encoding-v1-invalid-utf8-string",
            ENCODING_SPEC,
            "3",
            "A string element that is not valid UTF-8 is rejected.",
            "NON_CANONICAL_ENCODING",
        )
        .input_bytes("encoded", &[0x00, 0x00, 0x00, 0x02, 0xff, 0xfe])
        .build(),
    );
    out.push(
        VectorBuilder::reject(
            "canonical-encoding",
            "canonical-encoding-v1-declared-length-over-the-limit",
            ENCODING_SPEC,
            "10",
            "A declared element length above the parser limit allocates nothing.",
            "RESOURCE_LIMIT_EXCEEDED",
        )
        .input_bytes("encoded", &[0xee, 0x6b, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00])
        .input("parser_limit", json!(64))
        .build(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Key derivations
// ---------------------------------------------------------------------------

fn label_slug(label: Label) -> String {
    label.as_str().replace('/', "-").replace("chur-v1-", "")
}

fn sample_context(shape: ContextShape) -> Result<Context> {
    Ok(match shape {
        ContextShape::Vault => Context::vault(&id(0x11)?),
        ContextShape::CollectionEnvelope => Context::collection_envelope(&id(0x11)?, &id(0x22)?, 1),
        ContextShape::ObjectEnvelope => Context::object_envelope(&id(0x22)?, 1, &id(0x33)?),
        ContextShape::CollectionMetadata => Context::collection_metadata(&id(0x22)?, 1),
        ContextShape::ContainerStream => {
            Context::container_stream(&id(0x33)?, &id(0x44)?, StreamKind::Original.value(), 1)
        }
        ContextShape::DerivedAsset => {
            Context::derived_asset(&id(0x33)?, StreamKind::ThumbnailSmall.value(), 1, 1)
        }
        ContextShape::ObjectMetadata => Context::object_metadata(&id(0x33)?, 1),
        ContextShape::Slot => Context::slot(&id(0x11)?, &id(0x55)?, 1),
        ContextShape::PeerSession => Context::peer_session(&[0x66; 32], 1),
        ContextShape::PeerTranscript => Context::peer_transcript(&[0x66; 32]),
    })
}

fn key_derivations(out: &mut Vec<Vector>) -> Result<()> {
    let input_key = [0x99u8; KEY_LEN];
    for label in Label::ALL {
        let context = sample_context(label.shape())?;
        let info = kdf::info(*label, &context)?;
        let derived = kdf::derive(&input_key, *label, &context)?;
        out.push(
            VectorBuilder::accept(
                "key-derivation",
                &format!("key-derivation-v1-{}", label_slug(*label)),
                HIERARCHY_SPEC,
                "3",
                &format!(
                    "HKDF-SHA-256 under `{}` with its registered context.",
                    label.as_str()
                ),
            )
            .input_bytes("input_key", &input_key)
            .input("label", json!(label.as_str()))
            .input_bytes("context_elements", context.elements())
            .expect_bytes("info", &info)
            .expect("info_length", json!(info.len()))
            .expect_bytes("derived_key", derived.expose())
            .note(TEST_ONLY)
            .build(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key slots
// ---------------------------------------------------------------------------

fn password_binding() -> Result<SlotBinding> {
    Ok(SlotBinding::v1(id(0x11)?, id(0x55)?, SlotType::Password, 1))
}

fn password_slots(out: &mut Vec<Vector>) -> Result<()> {
    let binding = password_binding()?;
    let params = Argon2Params::v1_default();
    let salt = vec![0x77u8; 16];
    let password = "correct horse battery staple";
    let body = PasswordSlotBody::seal(
        &binding,
        password.as_bytes(),
        salt.clone(),
        params,
        nonce(0x88),
        &key(0x5a),
    )?;
    let aad = PasswordSlotBody::aad(&binding, params, &salt)?;
    out.push(
        VectorBuilder::accept(
            "password-slot",
            "password-slot-v1-frozen-floor-profile",
            SLOT_SPEC,
            "3",
            "A password slot at the frozen Argon2id floor: 65536 KiB, 3 iterations, parallelism 1, 16-byte salt.",
        )
        .input("password", json!(password))
        .input_bytes("password_bytes", password.as_bytes())
        .input_bytes("salt", &salt)
        .input_bytes("slot_nonce", nonce(0x88).as_bytes())
        .input_bytes("vault_root_secret", key(0x5a).expose())
        .input("memory_kib", json!(params.memory_kib()))
        .input("iterations", json!(params.iterations()))
        .input("parallelism", json!(params.parallelism()))
        .expect_bytes("slot_aad", &aad)
        .expect("slot_aad_length", json!(aad.len()))
        .expect_single_fixture("slot_body", &body.encode())
        .expect("slot_body_length", json!(body.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    // The composed and decomposed spellings of one accented character are
    // different passwords, because profile 0x0001 applies no normalization.
    let composed = "é";
    let decomposed = "e\u{0301}";
    let composed_kek = password::derive_kek(composed.as_bytes(), &salt, params)?;
    let decomposed_kek = password::derive_kek(decomposed.as_bytes(), &salt, params)?;
    out.push(
        VectorBuilder::accept(
            "password-slot",
            "password-slot-v1-unicode-combining-no-normalization",
            "docs/security/PASSWORD_PROFILE.md",
            "3",
            "Profile 0x0001 applies no normalization, so U+00E9 and U+0065 U+0301 are different passwords.",
        )
        .input_bytes("composed_password_bytes", composed.as_bytes())
        .input_bytes("decomposed_password_bytes", decomposed.as_bytes())
        .input_bytes("salt", &salt)
        .expect_bytes("composed_password_kek", composed_kek.expose())
        .expect_bytes("decomposed_password_kek", decomposed_kek.expose())
        .expect("keys_differ", json!(true))
        .note(TEST_ONLY)
        .build(),
    );

    let mut lowered = body.encode();
    lowered[4..8].copy_from_slice(&1024u32.to_be_bytes());
    out.push(
        VectorBuilder::reject(
            "password-slot",
            "password-slot-v1-memory-below-the-floor",
            SLOT_SPEC,
            "8",
            "A memory cost under the frozen floor is refused before Argon2 allocates anything.",
            "RESOURCE_LIMIT_EXCEEDED",
        )
        .input_bytes("slot_body", &lowered)
        .build(),
    );

    let mut trailing = body.encode();
    trailing.push(0x00);
    out.push(
        VectorBuilder::reject(
            "password-slot",
            "password-slot-v1-trailing-byte",
            SLOT_SPEC,
            "8",
            "A body length that exceeds what its own fields imply is rejected.",
            "NON_CANONICAL_ENCODING",
        )
        .input_bytes("slot_body", &trailing)
        .build(),
    );
    Ok(())
}

fn recovery_slots(out: &mut Vec<Vector>) -> Result<()> {
    let binding = SlotBinding::v1(id(0x11)?, id(0x56)?, SlotType::Recovery, 1);
    let recovery_secret = key(0x99);
    let body = RecoverySlotBody::seal(&binding, &recovery_secret, nonce(0xaa), &key(0x5a))?;
    let aad = RecoverySlotBody::aad(&binding);
    out.push(
        VectorBuilder::accept(
            "recovery-slot",
            "recovery-slot-v1-generation-one",
            SLOT_SPEC,
            "4",
            "A recovery slot: no salt, no password KDF, RecoveryKEK derived from the 32-byte secret.",
        )
        .input_bytes("recovery_secret", recovery_secret.expose())
        .input_bytes("slot_nonce", nonce(0xaa).as_bytes())
        .input_bytes("vault_root_secret", key(0x5a).expose())
        .expect_bytes("slot_aad", &aad)
        .expect("slot_aad_length", json!(aad.len()))
        .expect_single_fixture("slot_body", &body.encode())
        .expect("slot_body_length", json!(body.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let phrase = recovery::to_phrase(&recovery_secret);
    let denormalized = format!("  {}  ", phrase.to_uppercase().replace(' ', "\u{00a0} "));
    out.push(
        VectorBuilder::accept(
            "recovery-slot",
            "recovery-slot-v1-phrase-round-trip",
            RECOVERY_SPEC,
            "2",
            "32 bytes to 24 BIP-39 English words and back, and one denormalized re-entry that normalizes to the same words.",
        )
        .input_bytes("recovery_secret", recovery_secret.expose())
        .input("denormalized_re_entry", json!(denormalized))
        .expect("phrase", json!(phrase.as_str()))
        .expect("word_count", json!(recovery::WORD_COUNT))
        .expect("qr_payload", json!(recovery::to_qr_payload(&recovery_secret).as_str()))
        .expect("normalized_re_entry", json!(recovery::normalize(&denormalized)))
        .note(TEST_ONLY)
        .build(),
    );

    let words: Vec<&str> = recovery::encode(&recovery_secret);
    let mut broken = words.clone();
    broken[23] = if words[23] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    out.push(
        VectorBuilder::reject(
            "recovery-slot",
            "recovery-slot-v1-checksum-mismatch",
            RECOVERY_SPEC,
            "2",
            "A phrase whose last word changes fails the BIP-39 checksum and no slot unwrap is attempted.",
            "INVALID_INPUT",
        )
        .input("phrase", json!(broken.join(" ")))
        .build(),
    );

    let mut short = words.clone();
    short.truncate(23);
    out.push(
        VectorBuilder::reject(
            "recovery-slot",
            "recovery-slot-v1-twenty-three-words",
            RECOVERY_SPEC,
            "2",
            "A v1 recovery phrase is exactly 24 words.",
            "INVALID_INPUT",
        )
        .input("phrase", json!(short.join(" ")))
        .build(),
    );
    Ok(())
}

fn platform_slots(out: &mut Vec<Vector>) -> Result<()> {
    let keychain_binding = SlotBinding::v1(id(0x11)?, id(0x57)?, SlotType::AppleKeychain, 1);
    let device_unlock_secret = key(0xbb);
    let body = AppleKeychainSlotBody::seal(
        &keychain_binding,
        &device_unlock_secret,
        id(0xcc)?,
        nonce(0xdd),
        &key(0x5a),
    )?;
    let aad = AppleKeychainSlotBody::aad(&keychain_binding);
    let kek = AppleKeychainSlotBody::kek(&device_unlock_secret, &keychain_binding)?;
    out.push(
        VectorBuilder::accept(
            "keychain-slot",
            "keychain-slot-v1-device-unlock-secret",
            SLOT_SPEC,
            "6",
            "The Keychain family: a device-held secret, AppleDeviceKEK derived in Rust, and the root wrapped there.",
        )
        .input_bytes("device_unlock_secret", device_unlock_secret.expose())
        .input_bytes("keychain_item_id", id(0xcc)?.as_bytes())
        .input_bytes("slot_nonce", nonce(0xdd).as_bytes())
        .input_bytes("vault_root_secret", key(0x5a).expose())
        .expect_bytes("apple_device_kek", kek.expose())
        .expect_bytes("slot_aad", &aad)
        .expect("slot_aad_length", json!(aad.len()))
        .expect_single_fixture("slot_body", &body.encode())
        .note(TEST_ONLY)
        .build(),
    );

    let keystore_binding = SlotBinding::v1(id(0x11)?, id(0x58)?, SlotType::AndroidKeystore, 1);
    let alias = vec![0xeeu8; 16];
    let keystore_aad = AndroidKeystoreSlotBody::aad(&keystore_binding, &alias)?;
    let keystore_body =
        AndroidKeystoreSlotBody::new(&keystore_binding, alias.clone(), [0x0f; 12], [0x01; 48])?;
    out.push(
        VectorBuilder::accept(
            "keystore-slot",
            "keystore-slot-v1-sixteen-byte-alias",
            SLOT_SPEC,
            "5",
            "The Android family's body framing and the AAD the platform cipher receives.",
        )
        .input_bytes("alias", &alias)
        .input_bytes("gcm_nonce", &[0x0f; 12])
        .input_bytes("wrapped_root_secret", &[0x01; 48])
        .expect_bytes("slot_aad", &keystore_aad)
        .expect("slot_aad_length", json!(keystore_aad.len()))
        .expect_single_fixture("slot_body", &keystore_body.encode())
        .note(
            "The wrapped bytes are a fixed placeholder: this family's AEAD runs in the platform \
             Keystore, so no Rust implementation reproduces them. TEST-ONLY — NEVER USE FOR REAL VAULTS",
        )
        .build(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Vault descriptors
// ---------------------------------------------------------------------------

fn minimal_descriptor() -> Result<VaultDescriptor> {
    Ok(VaultDescriptor {
        vault_id: id(0x11)?,
        descriptor_generation: 1,
        state: VaultState::Active,
        catalog: CatalogDescriptor {
            catalog_format_version: chur_format::constants::CATALOG_FORMAT_VERSION_V1,
            opaque_catalog_path_id: id(0x12)?,
            catalog_generation: 1,
            catalog_header_commitment: [0x13; 32],
        },
        object_store: ObjectStoreDescriptor::v1(id(0x14)?),
        key_slots: vec![KeySlotDescriptor::v1(
            id(0x55)?,
            SlotType::Password,
            1,
            vec![0xaa; 16],
        )?],
        migration: None,
    })
}

fn vault_descriptors(out: &mut Vec<Vector>) -> Result<()> {
    let root = key(0x5a);
    let descriptor = minimal_descriptor()?;
    let encoded = descriptor.encode(&root)?;
    out.push(
        VectorBuilder::accept(
            "vault-descriptor",
            "vault-descriptor-v1-minimal-password-slot",
            DESCRIPTOR_SPEC,
            "13",
            "The smallest v1 descriptor: the head, one password slot with a 16-byte body, no migration, and the tag.",
        )
        .input_bytes("vault_root_secret", root.expose())
        .input_bytes("vault_id", id(0x11)?.as_bytes())
        .input("descriptor_generation", json!(1))
        .input("state", json!("ACTIVE"))
        .expect_single_fixture("descriptor", &encoded)
        .expect("descriptor_length", json!(encoded.len()))
        .expect_bytes("descriptor_auth_tag", &encoded[encoded.len() - 32..])
        .decoded("key_slot_count", json!(1))
        .note(TEST_ONLY)
        .build(),
    );

    let mut migrating = minimal_descriptor()?;
    migrating.state = VaultState::Migrating;
    migrating.descriptor_generation = 2;
    migrating.migration = Some(MigrationDescriptor {
        from_descriptor_version: 1,
        to_descriptor_version: 1,
        from_catalog_format_version: 1,
        to_catalog_format_version: 1,
        migration_generation: 1,
        checkpoint_id: id(0x15)?,
    });
    let migrating_bytes = migrating.encode(&root)?;
    out.push(
        VectorBuilder::accept(
            "vault-descriptor",
            "vault-descriptor-v1-migrating-state",
            DESCRIPTOR_SPEC,
            "2.2",
            "MIGRATING carries the 32-byte migration descriptor, so the encoding is 33 bytes longer than the minimum.",
        )
        .input_bytes("vault_root_secret", root.expose())
        .input("state", json!("MIGRATING"))
        .expect_single_fixture("descriptor", &migrating_bytes)
        .expect("descriptor_length", json!(migrating_bytes.len()))
        .note(TEST_ONLY)
        .build(),
    );

    let mut wrong_magic = encoded.clone();
    wrong_magic[4] = b'X';
    out.push(
        VectorBuilder::reject(
            "vault-descriptor",
            "vault-descriptor-v1-wrong-magic",
            DESCRIPTOR_SPEC,
            "2.1",
            "A magic that differs in one byte is rejected before any credential is used.",
            "VAULT_CORRUPT",
        )
        .input_bytes("descriptor", &wrong_magic)
        .build(),
    );

    let mut short_tag = encoded.clone();
    short_tag.truncate(encoded.len() - 1);
    out.push(
        VectorBuilder::reject(
            "vault-descriptor",
            "vault-descriptor-v1-truncated-tag",
            DESCRIPTOR_SPEC,
            "8",
            "A descriptor whose declared length does not match its bytes fails step 1.",
            "VAULT_CORRUPT",
        )
        .input_bytes("descriptor", &short_tag)
        .build(),
    );

    let mut wrong_root = minimal_descriptor()?;
    wrong_root.descriptor_generation = 1;
    out.push(
        VectorBuilder::reject(
            "vault-descriptor",
            "vault-descriptor-v1-wrong-candidate-root",
            DESCRIPTOR_SPEC,
            "8",
            "A structurally valid descriptor under a wrong root is AUTHENTICATION_FAILED, never VAULT_CORRUPT.",
            "AUTHENTICATION_FAILED",
        )
        .input_bytes("descriptor", &encoded)
        .input_bytes("candidate_root", key(0x5b).expose())
        .note(TEST_ONLY)
        .build(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Key envelopes
// ---------------------------------------------------------------------------

fn collection_envelopes(out: &mut Vec<Vector>) -> Result<()> {
    let root = key(0x5a);
    let collection_key = key(0x44);
    let envelope = CollectionKeyEnvelope::seal(
        &root,
        id(0x11)?,
        id(0x22)?,
        1,
        1,
        nonce(0x33),
        &collection_key,
    )?;
    let encoded = envelope.encode();
    let wrapping = CollectionKeyEnvelope::wrapping_key(&root, &id(0x11)?, &id(0x22)?, 1)?;
    out.push(
        VectorBuilder::accept(
            "collection-envelope",
            "collection-envelope-v1-epoch-one-generation-one",
            COLLECTION_ENVELOPE_SPEC,
            "1",
            "A collection key wrapped under the root-derived envelope key for epoch 1, generation 1.",
        )
        .input_bytes("vault_root_secret", root.expose())
        .input_bytes("security_collection_key", collection_key.expose())
        .input_bytes("vault_id", id(0x11)?.as_bytes())
        .input_bytes("collection_id", id(0x22)?.as_bytes())
        .input("collection_epoch", number(1))
        .input("envelope_generation", number(1))
        .input_bytes("nonce", nonce(0x33).as_bytes())
        .expect_bytes("collection_envelope_key", wrapping.expose())
        .expect_bytes("aad", &envelope.aad())
        .expect("aad_length", json!(envelope.aad().len()))
        .expect_single_fixture("envelope", &encoded)
        .expect("envelope_length", json!(encoded.len()))
        .note(TEST_ONLY)
        .build(),
    );

    let mut foreign = encoded.clone();
    foreign[0x06] = 0x12;
    out.push(
        VectorBuilder::reject(
            "collection-envelope",
            "collection-envelope-v1-foreign-vault-identity",
            COLLECTION_ENVELOPE_SPEC,
            "3",
            "Changing the vault identity changes both the wrapping key and the AAD, so the envelope does not open.",
            "OBJECT_CORRUPT",
        )
        .input_bytes("envelope", &foreign)
        .input_bytes("vault_root_secret", root.expose())
        .note(TEST_ONLY)
        .build(),
    );
    Ok(())
}

fn object_key_envelopes(out: &mut Vec<Vector>) -> Result<()> {
    let collection_key = key(0x44);
    let object_key = key(0x77);
    let envelope = ObjectKeyEnvelope::seal(
        &collection_key,
        id(0x11)?,
        id(0x22)?,
        1,
        id(0x33)?,
        1,
        nonce(0x66),
        &object_key,
    )?;
    let encoded = envelope.encode();
    let wrapping = ObjectKeyEnvelope::wrapping_key(&collection_key, &id(0x22)?, 1, &id(0x33)?)?;
    out.push(
        VectorBuilder::accept(
            "object-key-envelope",
            "object-key-envelope-v1-epoch-one-generation-one",
            OBJECT_ENVELOPE_SPEC,
            "1",
            "An object key wrapped under the collection-derived envelope key for epoch 1, generation 1.",
        )
        .input_bytes("security_collection_key", collection_key.expose())
        .input_bytes("object_key", object_key.expose())
        .input_bytes("vault_id", id(0x11)?.as_bytes())
        .input_bytes("collection_id", id(0x22)?.as_bytes())
        .input("collection_epoch", number(1))
        .input_bytes("object_id", id(0x33)?.as_bytes())
        .input("envelope_generation", number(1))
        .input_bytes("nonce", nonce(0x66).as_bytes())
        .expect_bytes("object_envelope_key", wrapping.expose())
        .expect_bytes("aad", &envelope.aad())
        .expect("aad_length", json!(envelope.aad().len()))
        .expect_single_fixture("envelope", &encoded)
        .expect("envelope_length", json!(encoded.len()))
        .note(TEST_ONLY)
        .build(),
    );

    let mut unsupported = encoded.clone();
    unsupported[5] = 0x02;
    out.push(
        VectorBuilder::reject(
            "object-key-envelope",
            "object-key-envelope-v1-unsupported-suite",
            OBJECT_ENVELOPE_SPEC,
            "1",
            "An unsupported suite identifier is refused before the AEAD runs.",
            "UNSUPPORTED_SUITE",
        )
        .input_bytes("envelope", &unsupported)
        .build(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Object containers
// ---------------------------------------------------------------------------

fn container_identity() -> Result<StreamIdentity> {
    Ok(StreamIdentity {
        object_id: id(0x33)?,
        stream_id: id(0x34)?,
        stream_kind: StreamKind::Original,
        stream_revision: 1,
    })
}

fn container_manifest() -> Result<CanonicalManifest> {
    CanonicalManifest::new(
        container_identity()?,
        None,
        VECTOR_CHUNK_SIZE,
        [0x35; NONCE_PREFIX_LEN],
        1,
        MediaProperties::new(MediaClass::Image, 4032, 3024, 0)?,
    )
}

fn container_case(
    out: &mut Vec<Vector>,
    vector_id: &str,
    section: &str,
    purpose: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    container_case_with_version(
        out,
        vector_id,
        CONTAINER_SPEC,
        section,
        purpose,
        plaintext,
        ContainerVersion::V1,
    )
}

fn container_case_with_version(
    out: &mut Vec<Vector>,
    vector_id: &str,
    spec: &str,
    section: &str,
    purpose: &str,
    plaintext: &[u8],
    version: ContainerVersion,
) -> Result<Vec<u8>> {
    let object_key = key(0x77);
    let encoded = encode_container_with_version(
        &object_key,
        container_manifest()?,
        nonce(0x36),
        plaintext,
        nonce(0x37),
        1,
        version,
    )?;
    let preamble = PublicPreamble::decode(&encoded[..PublicPreamble::LEN])?;
    let stored = if version.is_padded() {
        padded_length(plaintext.len() as u64)
    } else {
        plaintext.len() as u64
    };
    let chunk_count = stored.div_ceil(u64::from(VECTOR_CHUNK_SIZE));
    let mut builder = VectorBuilder::accept("object", vector_id, spec, section, purpose);
    if version.is_padded() {
        builder = builder
            .input("container_version", json!(version.value()))
            .decoded("stored_length", number(stored));
    }
    out.push(
        builder
            .input_bytes("object_key", object_key.expose())
            .input_bytes("object_id", id(0x33)?.as_bytes())
            .input_bytes("stream_id", id(0x34)?.as_bytes())
            .input("stream_kind", json!(StreamKind::Original.value()))
            .input("stream_revision", json!(1))
            .input("chunk_size", json!(VECTOR_CHUNK_SIZE))
            .input_bytes("nonce_prefix", &[0x35; NONCE_PREFIX_LEN])
            .input_bytes("manifest_nonce", nonce(0x36).as_bytes())
            .input_bytes("commit_nonce", nonce(0x37).as_bytes())
            .input("plaintext_length", number(plaintext.len() as u64))
            .input("plaintext_pattern", json!("byte i equals i modulo 251"))
            .expect_single_fixture("container", &encoded)
            .expect("container_length", number(encoded.len() as u64))
            .expect(
                "manifest_record_length",
                json!(preamble.manifest_record_length()),
            )
            .decoded("chunk_count", number(chunk_count))
            .decoded("total_plaintext_length", number(plaintext.len() as u64))
            .note(TEST_ONLY)
            .build(),
    );
    Ok(encoded)
}

fn object_containers(out: &mut Vec<Vector>) -> Result<()> {
    container_case(
        out,
        "object-v1-zero-byte",
        "13",
        "A zero-byte stream: no chunk records, and the ordered commitment is the hash of its domain tag alone.",
        b"",
    )?;
    let one_chunk = container_case(
        out,
        "object-v1-one-partial-chunk",
        "13",
        "One chunk shorter than the chunk size, which is therefore also the last chunk.",
        &pattern(1000),
    )?;
    container_case(
        out,
        "object-v1-exact-multiple-of-chunk-size",
        "13",
        "An exact multiple of the chunk size writes no zero-length trailing record.",
        &pattern(2 * VECTOR_CHUNK_SIZE as usize),
    )?;
    container_case(
        out,
        "object-v1-two-chunks-partial-final",
        "8",
        "Two chunks and a short third, the canonical chunking every reader recomputes.",
        &pattern(2 * VECTOR_CHUNK_SIZE as usize + 17),
    )?;

    out.push(
        VectorBuilder::accept(
            "object",
            "object-v1-zero-chunk-ordered-commitment",
            CONTAINER_SPEC,
            "10",
            "The ordered chunk commitment of a zero-chunk object is BLAKE3-256 of the domain tag alone.",
        )
        .input("domain_tag", json!(hex_of(tag::OBJECT_ORDERED_COMMITMENT)))
        .expect_bytes(
            "ordered_chunk_commitment",
            &commit::commit(tag::OBJECT_ORDERED_COMMITMENT, &[]),
        )
        .build(),
    );

    let truncated = &one_chunk[..one_chunk.len() - (32 + 144)];
    out.push(
        VectorBuilder::reject(
            "object",
            "object-v1-missing-final-commit",
            CONTAINER_SPEC,
            "15",
            "A container whose chunk records authenticate but whose final commit is absent is incomplete, not corrupt.",
            "OBJECT_INCOMPLETE",
        )
        .input_bytes("container", truncated)
        .input_bytes("object_key", key(0x77).expose())
        .note(TEST_ONLY)
        .build(),
    );

    let mut trailing = one_chunk.clone();
    trailing.push(0x00);
    out.push(
        VectorBuilder::reject(
            "object",
            "object-v1-trailing-byte-after-final-commit",
            CONTAINER_SPEC,
            "11",
            "No bytes may follow the final commit record.",
            "OBJECT_CORRUPT",
        )
        .input_bytes("container", &trailing)
        .build(),
    );

    let mut reserved = one_chunk.clone();
    reserved[0x1a] = 0x01;
    out.push(
        VectorBuilder::reject(
            "object",
            "object-v1-non-zero-preamble-reserved",
            CONTAINER_SPEC,
            "3",
            "A fixed preamble field holding any other value is OBJECT_CORRUPT and is never ignored.",
            "OBJECT_CORRUPT",
        )
        .input_bytes("container", &reserved)
        .build(),
    );

    let mut forged = one_chunk.clone();
    let first_chunk = PublicPreamble::LEN
        + one_chunk[0x14..0x18]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
    forged[first_chunk + 12..first_chunk + 16].copy_from_slice(&99u32.to_be_bytes());
    out.push(
        VectorBuilder::reject(
            "object",
            "object-v1-forged-chunk-plaintext-length",
            CONTAINER_SPEC,
            "8",
            "A chunk header whose ciphertext length is not the plaintext length plus one tag is rejected without a key.",
            "OBJECT_CORRUPT",
        )
        .input_bytes("container", &forged)
        .build(),
    );

    let mut wrong_suite = one_chunk;
    wrong_suite[0x0d] = 0x02;
    out.push(
        VectorBuilder::reject(
            "object",
            "object-v1-unsupported-suite",
            CONTAINER_SPEC,
            "3",
            "An unknown suite fails as UNSUPPORTED_SUITE rather than as corruption.",
            "UNSUPPORTED_SUITE",
        )
        .input_bytes("container", &wrong_suite)
        .build(),
    );
    padded_containers(out)
}

/// The bucket-padded container of ADR-0066.
fn padded_containers(out: &mut Vec<Vector>) -> Result<()> {
    container_case_with_version(
        out,
        "object-v2-one-padded-chunk",
        CONTAINER_SPEC,
        "18",
        "A 1000-byte object stored in the 4096-byte bucket: one record whose zero padding follows the object.",
        &pattern(1000),
        ContainerVersion::V2,
    )?;
    container_case_with_version(
        out,
        "object-v2-padding-only-record",
        CONTAINER_SPEC,
        "18",
        "One byte past the chunk size: the 131072-byte bucket fills a padded first chunk and a padding-only second record.",
        &pattern(VECTOR_CHUNK_SIZE as usize + 1),
        ContainerVersion::V2,
    )?;

    let cases = [
        (
            "object-v2-non-zero-padding-byte",
            "A padding byte other than zero is refused even though its record authenticates.",
            PaddingDeviation::PaddingByte(0x01),
        ),
        (
            "object-v2-padding-short-of-bucket",
            "A stream that stops one byte before the bucket of its object length is refused.",
            PaddingDeviation::ShortOfBucket,
        ),
        (
            "object-v2-padding-past-bucket",
            "A stream that carries one byte past the bucket of its object length is refused.",
            PaddingDeviation::PastBucket,
        ),
    ];
    for (vector_id, purpose, deviation) in cases {
        let container = encode_deviant_container(
            &key(0x77),
            container_manifest()?,
            nonce(0x36),
            &pattern(1000),
            nonce(0x37),
            deviation,
        )?;
        expect_rejection(
            ContainerReader::open(&container, &key(0x77), &container_identity()?)
                .and_then(|reader| reader.verify_complete()),
            ChurStatus::ObjectCorrupt,
        )?;
        out.push(
            VectorBuilder::reject(
                "object",
                vector_id,
                CONTAINER_SPEC,
                "18",
                purpose,
                "OBJECT_CORRUPT",
            )
            .input_bytes("container", &container)
            .input_bytes("object_key", key(0x77).expose())
            .input_bytes("object_id", id(0x33)?.as_bytes())
            .input_bytes("stream_id", id(0x34)?.as_bytes())
            .input("stream_kind", json!(StreamKind::Original.value()))
            .input("stream_revision", json!(1))
            .note(TEST_ONLY)
            .build(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Backup package
// ---------------------------------------------------------------------------

/// The deterministic structures of `BACKUP_FORMAT_V1.md`.
///
/// A whole package is not a vector and cannot be. §2 has it carry the encrypted
/// catalog, which is a SQLCipher file with a random salt, so two runs over one
/// vault produce two packages that differ in bytes and mean the same thing.
/// What is deterministic is every structure the format defines itself: the
/// public preamble, the record header, the two inventory entries, the ordered
/// inventory commitment, and the two sealed records under a fixed key and
/// nonce. Those are the bytes a second implementation has to reproduce, and
/// they are what these vectors carry.
fn backup_packages(out: &mut Vec<Vector>) -> Result<()> {
    use chur_format::backup::{
        BackupManifest, FinalBackupCommit, InventoryCommitter, PublicPreamble as BackupPreamble,
        RecordHeader, RecordType, SlotInventoryEntry, StreamInventoryEntry, manifest_key,
    };
    use chur_format::constants::BACKUP_VERSION_V1;

    let vault_id = id(0x11)?;
    let backup_id = id(0x22)?;
    let root = key(0x61);
    let manifest_key = manifest_key(&root, &vault_id)?;

    let preamble = BackupPreamble::new(BACKUP_VERSION_V1, 6)?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-public-preamble",
            BACKUP_SPEC,
            "2.1",
            "The 32-byte public preamble, whose only variable field is the record count.",
        )
        .input("record_count", number(6))
        .expect_bytes("preamble", &preamble.encode())
        .expect("preamble_length", number(32))
        .build(),
    );

    let header = RecordHeader {
        record_type: RecordType::Container,
        payload_length: 262_253,
    };
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-record-header",
            BACKUP_SPEC,
            "2.2",
            "One package record header: type, version, reserved, and a u64 payload length.",
        )
        .input("record_type", json!(RecordType::Container as u8))
        .input("payload_length", number(262_253))
        .expect_bytes("header", &header.encode())
        .expect("header_length", number(12))
        .build(),
    );

    let stream_entry = StreamInventoryEntry {
        object_id: id(0x41)?,
        stream_id: id(0x42)?,
        stream_kind: StreamKind::Original,
        stream_revision: 1,
        ciphertext_length: 262_144,
        manifest_commitment: [0x43; 32],
        ordered_chunk_commitment: [0x44; 32],
    };
    let slot_entry = SlotInventoryEntry {
        slot_id: id(0x45)?,
        slot_type: 0x01,
        slot_generation: 1,
    };
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-inventory-entries",
            BACKUP_SPEC,
            "7.1",
            "One stream inventory entry and one slot inventory entry, at their canonical lengths.",
        )
        .input_bytes("object_id", id(0x41)?.as_bytes())
        .input_bytes("stream_id", id(0x42)?.as_bytes())
        .input("stream_kind", json!(StreamKind::Original.value()))
        .input("stream_revision", json!(1))
        .input("ciphertext_length", number(262_144))
        .input_bytes("manifest_commitment", &[0x43; 32])
        .input_bytes("ordered_chunk_commitment", &[0x44; 32])
        .input_bytes("slot_id", id(0x45)?.as_bytes())
        .input("slot_type", json!(1))
        .input("slot_generation", json!(1))
        .expect_bytes("stream_entry", &stream_entry.encode())
        .expect("stream_entry_length", number(109))
        .expect_bytes("slot_entry", &slot_entry.encode())
        .expect("slot_entry_length", number(25))
        .build(),
    );

    let mut committer = InventoryCommitter::new();
    committer.add_stream(&stream_entry)?;
    committer.add_slot(&slot_entry)?;
    let inventory_commitment = committer.finish();
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-inventory-commitment",
            BACKUP_SPEC,
            "7.2",
            "The ordered inventory commitment over one stream entry then one slot entry, with no count prefix and no separator.",
        )
        .input("domain_tag", json!(hex_of(tag::BACKUP_INVENTORY_COMMITMENT)))
        .input_bytes("stream_entry", &stream_entry.encode())
        .input_bytes("slot_entry", &slot_entry.encode())
        .expect_bytes("inventory_commitment", &inventory_commitment)
        .build(),
    );

    let empty = InventoryCommitter::new();
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-empty-inventory-commitment",
            BACKUP_SPEC,
            "7.2",
            "For an empty inventory the commitment is BLAKE3-256 of the domain tag alone.",
        )
        .input(
            "domain_tag",
            json!(hex_of(tag::BACKUP_INVENTORY_COMMITMENT)),
        )
        .expect_bytes("inventory_commitment", &empty.finish())
        .build(),
    );

    let manifest = BackupManifest {
        backup_id,
        backup_version: BACKUP_VERSION_V1,
        vault_id,
        created_time_ms: 1_700_000_000_000,
        base_backup_id: None,
        catalog_generation: 7,
        catalog_format_version: 1,
        stream_entry_count: 1,
        slot_entry_count: 1,
        inventory_commitment,
        free_space_required: 67_371_008,
    };
    let manifest_record = manifest.seal(&manifest_key, &nonce(0x31))?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-manifest",
            BACKUP_SPEC,
            "4",
            "The manifest plaintext and the sealed record, under a key derived from the root and the vault identity alone.",
        )
        .input_bytes("root_secret", root.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", backup_id.as_bytes())
        .input_bytes("manifest_nonce", nonce(0x31).as_bytes())
        .input("created_time_ms", number(1_700_000_000_000))
        .input("catalog_generation", number(7))
        .expect_bytes("backup_manifest_key", manifest_key.expose())
        .expect_bytes("manifest_plaintext", &manifest.encode())
        .expect("manifest_plaintext_length", number(117))
        .expect_bytes("manifest_record", &manifest_record)
        .note(TEST_ONLY)
        .build(),
    );

    let commit = FinalBackupCommit {
        backup_id,
        record_count: 6,
        stream_entry_count: 1,
        slot_entry_count: 1,
        inventory_commitment,
        records: None,
    };
    let commit_record = commit.seal(&manifest_key, &vault_id, &nonce(0x32))?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v1-final-commit",
            BACKUP_SPEC,
            "7",
            "The final backup commit, sealed under the manifest key and a different domain tag, so neither record opens as the other.",
        )
        .input_bytes("root_secret", root.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", backup_id.as_bytes())
        .input_bytes("commit_nonce", nonce(0x32).as_bytes())
        .input("record_count", number(6))
        .expect_bytes("commit_plaintext", &commit.encode())
        .expect("commit_plaintext_length", number(64))
        .expect_bytes("commit_record", &commit_record)
        .note(TEST_ONLY)
        .build(),
    );

    // Negative vectors, §5: every fixed field is checked rather than ignored.
    let mut wrong_magic = preamble.encode();
    wrong_magic[7] = b'2';
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-wrong-magic",
            BACKUP_SPEC,
            "2.3",
            "Eight bytes that are neither CHURBAK1 nor an age header are not a Chur backup.",
            "VAULT_CORRUPT",
        )
        .input_bytes("preamble", &wrong_magic)
        .build(),
    );

    // A historical v1 vector: 0x0002 was unallocated when it was frozen, and
    // `TEST_VECTORS.md` §8 keeps its bytes. ADR-0068 allocates 0x0002, and
    // `backup-v2-unsupported-version` records the rule a current reader keeps.
    let mut wrong_version = preamble.encode();
    wrong_version[9] = 0x02;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-unsupported-version",
            BACKUP_SPEC,
            "2.1",
            "An unknown backup version fails as UNSUPPORTED_VERSION rather than as corruption.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("preamble", &wrong_version)
        .note(
            "Superseded: ADR-0068 allocates backup_version 0x0002, which a current reader accepts.",
        )
        .superseded_by("backup-v2-unsupported-version")
        .build(),
    );

    let mut wrong_suite = preamble.encode();
    wrong_suite[13] = 0x02;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-unsupported-suite",
            BACKUP_SPEC,
            "2.1",
            "Suite 0x0002 is the Android Keystore wrap and is invalid as a package suite.",
            "UNSUPPORTED_SUITE",
        )
        .input_bytes("preamble", &wrong_suite)
        .build(),
    );

    let mut non_zero_reserved = preamble.encode();
    non_zero_reserved[23] = 0x01;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-non-zero-reserved",
            BACKUP_SPEC,
            "2.1",
            "A fixed preamble field holding any other value is VAULT_CORRUPT and is never ignored.",
            "VAULT_CORRUPT",
        )
        .input_bytes("preamble", &non_zero_reserved)
        .build(),
    );

    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-record-count-below-minimum",
            BACKUP_SPEC,
            "13",
            "A package holds at least the encrypted backup manifest and the final backup commit.",
            "RESOURCE_LIMIT_EXCEEDED",
        )
        .input("record_count", number(1))
        .build(),
    );

    let mut unallocated = header.encode();
    unallocated[0] = 0x08;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-unallocated-record-type",
            BACKUP_SPEC,
            "2.2",
            "An unallocated record type is a parse failure, never an ignorable record.",
            "VAULT_CORRUPT",
        )
        .input_bytes("header", &unallocated)
        .build(),
    );

    let mut wrong_record_version = header.encode();
    wrong_record_version[1] = 0x02;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-unsupported-record-version",
            BACKUP_SPEC,
            "2.2",
            "Every v1 package record carries record_version 0x01.",
            "VAULT_CORRUPT",
        )
        .input_bytes("header", &wrong_record_version)
        .build(),
    );

    // §4: the manifest repeats the preamble's backup version, and a restore
    // rejects the package when the two differ.
    let mut contradicts = manifest.encode();
    contradicts[17] = 0x02;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-manifest-contradicts-the-preamble",
            BACKUP_SPEC,
            "4",
            "The manifest repeats the public preamble's backup version; a restore rejects a package where the two differ.",
            "VAULT_CORRUPT",
        )
        .input_bytes("manifest_plaintext", &contradicts)
        .build(),
    );

    // The final commit is sealed under the same key and a different tag, so it
    // does not open as a manifest.
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v1-final-commit-does-not-open-as-a-manifest",
            BACKUP_SPEC,
            "4",
            "Two records of one package share a key and differ only in their domain tag, so neither opens as the other.",
            "VAULT_CORRUPT",
        )
        .input_bytes("manifest_key", manifest_key.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("record", &commit_record)
        .note(TEST_ONLY)
        .build(),
    );
    backup_packages_v2(out)
}

const BACKUP_V2_SPEC: &str = "docs/format/BACKUP_FORMAT_V2.md";

/// One fixed chunk sequence for the export-stream vectors.
struct VectorChunks(std::vec::IntoIter<Vec<u8>>);

impl chur_format::catalog_export::ChunkSource for VectorChunks {
    fn next_chunk(&mut self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        Ok(self.0.next().map(zeroize::Zeroizing::new))
    }
}

/// Parses a whole one-table export stream, for the negative vectors.
fn parse_export(stream: &[u8]) -> Result<()> {
    use chur_format::catalog_export::ExportReader;
    let (mut reader, header) = ExportReader::new(VectorChunks(vec![stream.to_vec()].into_iter()))?;
    for _ in 0..header.table_count {
        let table = reader.table()?;
        for _ in 0..table.row_count * table.columns.len() as u64 {
            reader.value()?;
        }
    }
    reader.finish()
}

/// The version 2 package of ADR-0068: the catalog export stream and its
/// sealed records, the record commitment, and the version 2 final commit.
fn backup_packages_v2(out: &mut Vec<Vector>) -> Result<()> {
    use chur_format::backup::{
        BackupManifest, CatalogExportPosition, FinalBackupCommit, PublicPreamble as BackupPreamble,
        RecordCommitter, RecordSeal, RecordType, manifest_key, open_catalog_export,
        seal_catalog_export,
    };
    use chur_format::catalog_export::{ExportHeader, ExportWriter, TableHeader};
    use chur_format::constants::BACKUP_VERSION_V2;

    let vault_id = id(0x11)?;
    let backup_id = id(0x22)?;
    let root = key(0x61);
    let manifest_key = manifest_key(&root, &vault_id)?;

    let preamble = BackupPreamble::new(BACKUP_VERSION_V2, 7)?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v2-public-preamble",
            BACKUP_V2_SPEC,
            "2",
            "The version 2 preamble differs from version 1 only in backup_version.",
        )
        .input("backup_version", json!(BACKUP_VERSION_V2))
        .input("record_count", number(7))
        .expect_bytes("preamble", &preamble.encode())
        .build(),
    );

    let mut stream = Vec::new();
    let mut writer = ExportWriter::new(
        |chunk: &[u8], _| {
            stream.extend_from_slice(chunk);
            Ok(())
        },
        &ExportHeader {
            catalog_format_version: 15,
            catalog_generation: 3,
            table_count: 1,
        },
    )?;
    writer.table(&TableHeader {
        name: "tags".into(),
        columns: vec![
            "tag_id".into(),
            "name".into(),
            "created_ms".into(),
            "note".into(),
        ],
        row_count: 1,
    })?;
    writer.blob(&[0x51; 16])?;
    writer.text(b"beach")?;
    writer.integer(1_700_000_000_000)?;
    writer.null()?;
    writer.finish()?;
    parse_export(&stream)?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v2-catalog-export-stream",
            BACKUP_V2_SPEC,
            "3",
            "A CatalogExportV1 stream of one table with one row holding a blob, a text, an integer, and a NULL.",
        )
        .input("catalog_format_version", json!(15))
        .input("catalog_generation", number(3))
        .input("table_name", json!("tags"))
        .input("columns", json!(["tag_id", "name", "created_ms", "note"]))
        .input_bytes("tag_id", &[0x51; 16])
        .input("name", json!("beach"))
        .input("created_ms", number(1_700_000_000_000))
        .expect_bytes("stream", &stream)
        .build(),
    );

    let at = CatalogExportPosition {
        vault_id,
        backup_id,
        record_index: 2,
        chunk_index: 0,
        is_final: true,
    };
    let export_record = seal_catalog_export(&manifest_key, &nonce(0x35), &at, &stream)?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v2-catalog-export-record",
            BACKUP_V2_SPEC,
            "4",
            "The stream sealed as the only catalog export record, at record index 2, under the manifest key.",
        )
        .input_bytes("root_secret", root.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", backup_id.as_bytes())
        .input("record_index", number(2))
        .input("chunk_index", json!(0))
        .input("is_final", json!(true))
        .input_bytes("record_nonce", nonce(0x35).as_bytes())
        .input_bytes("stream", &stream)
        .expect_bytes("aad", &at.aad())
        .expect_bytes("record", &export_record)
        .note(TEST_ONLY)
        .build(),
    );

    // The non-container records of a seven-record package: the manifest, the
    // descriptor, the catalog export, one container (not committed here), the
    // identity envelope, and the final commit.
    let manifest = BackupManifest {
        backup_id,
        backup_version: BACKUP_VERSION_V2,
        vault_id,
        created_time_ms: 1_700_000_000_000,
        base_backup_id: None,
        catalog_generation: 3,
        catalog_format_version: 15,
        stream_entry_count: 1,
        slot_entry_count: 1,
        inventory_commitment: [0x5a; 32],
        free_space_required: 67_371_008,
    };
    let manifest_record = manifest.seal(&manifest_key, &nonce(0x36))?;
    let descriptor_record = pattern(96);
    let envelope_record = pattern(48);
    let commitment_of = |descriptor: &[u8]| {
        let mut records = RecordCommitter::new();
        records.add(0, RecordType::Manifest, &manifest_record);
        records.add(1, RecordType::Descriptor, descriptor);
        records.add(2, RecordType::CatalogExport, &export_record);
        records.add(4, RecordType::Envelope, &envelope_record);
        records.finish()
    };
    let record_commitment = commitment_of(&descriptor_record);
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v2-record-commitment",
            BACKUP_V2_SPEC,
            "5",
            "The record commitment over the manifest, descriptor, catalog export, and envelope records at indexes 0, 1, 2, and 4.",
        )
        .input("domain_tag", json!(hex_of(tag::BACKUP_RECORD_COMMITMENT)))
        .input_bytes("manifest_record", &manifest_record)
        .input_bytes("descriptor_record", &descriptor_record)
        .input_bytes("catalog_export_record", &export_record)
        .input_bytes("envelope_record", &envelope_record)
        .expect_bytes("record_commitment", &record_commitment)
        .note(TEST_ONLY)
        .build(),
    );

    let commit = FinalBackupCommit {
        backup_id,
        record_count: 7,
        stream_entry_count: 1,
        slot_entry_count: 1,
        inventory_commitment: [0x5a; 32],
        records: Some(RecordSeal {
            catalog_export_record_count: 1,
            record_commitment,
        }),
    };
    let commit_record = commit.seal(&manifest_key, &vault_id, &nonce(0x37))?;
    out.push(
        VectorBuilder::accept(
            "backup",
            "backup-v2-final-commit",
            BACKUP_V2_SPEC,
            "6",
            "The version 2 final commit: the version 1 fields, the catalog export record count, and the record commitment.",
        )
        .input_bytes("root_secret", root.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", backup_id.as_bytes())
        .input_bytes("commit_nonce", nonce(0x37).as_bytes())
        .expect_bytes("commit_plaintext", &commit.encode())
        .expect("commit_plaintext_length", number(100))
        .expect_bytes("commit_record", &commit_record)
        .note(TEST_ONLY)
        .build(),
    );

    // Negative vectors. Each is checked here to fail as it declares.
    let spliced_at = CatalogExportPosition {
        backup_id: id(0x23)?,
        ..at
    };
    expect_rejection(
        open_catalog_export(&export_record, &manifest_key, &spliced_at),
        ChurStatus::VaultCorrupt,
    )?;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v2-catalog-export-spliced-from-another-backup",
            BACKUP_V2_SPEC,
            "4",
            "A catalog export record sealed for one backup does not open in another backup of the same vault.",
            "VAULT_CORRUPT",
        )
        .input_bytes("manifest_key", manifest_key.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", id(0x23)?.as_bytes())
        .input("record_index", number(2))
        .input("chunk_index", json!(0))
        .input("is_final", json!(true))
        .input_bytes("record", &export_record)
        .note(TEST_ONLY)
        .build(),
    );

    let moved_at = CatalogExportPosition {
        record_index: 3,
        chunk_index: 1,
        ..at
    };
    expect_rejection(
        open_catalog_export(&export_record, &manifest_key, &moved_at),
        ChurStatus::VaultCorrupt,
    )?;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v2-catalog-export-reordered",
            BACKUP_V2_SPEC,
            "4",
            "A catalog export record moved to another record and chunk index does not open there.",
            "VAULT_CORRUPT",
        )
        .input_bytes("manifest_key", manifest_key.expose())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("backup_id", backup_id.as_bytes())
        .input("record_index", number(3))
        .input("chunk_index", json!(1))
        .input("is_final", json!(true))
        .input_bytes("record", &export_record)
        .note(TEST_ONLY)
        .build(),
    );

    let truncated = &stream[..stream.len() - 1];
    expect_rejection(parse_export(truncated), ChurStatus::VaultCorrupt)?;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v2-catalog-export-truncated",
            BACKUP_V2_SPEC,
            "3",
            "An export stream that ends inside its last value is refused rather than imported short.",
            "VAULT_CORRUPT",
        )
        .input_bytes("stream", truncated)
        .build(),
    );

    let mut altered = descriptor_record.clone();
    altered[95] ^= 0x01;
    let altered_commitment = commitment_of(&altered);
    let compare = |value: &[u8; 32]| -> Result<()> {
        if value == &record_commitment {
            Ok(())
        } else {
            Err(Error::new(
                ChurStatus::VaultCorrupt,
                "the record commitment does not match",
            ))
        }
    };
    compare(&record_commitment)?;
    expect_rejection(compare(&altered_commitment), ChurStatus::VaultCorrupt)?;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v2-descriptor-altered",
            BACKUP_V2_SPEC,
            "5",
            "One changed descriptor byte changes the record commitment, so it no longer matches the value the final commit seals.",
            "VAULT_CORRUPT",
        )
        .input_bytes("manifest_record", &manifest_record)
        .input_bytes("descriptor_record", &altered)
        .input_bytes("catalog_export_record", &export_record)
        .input_bytes("envelope_record", &envelope_record)
        .input_bytes("sealed_record_commitment", &record_commitment)
        .input_bytes("recomputed_record_commitment", &altered_commitment)
        .note(TEST_ONLY)
        .build(),
    );

    let mut unsupported = preamble.encode();
    unsupported[9] = 0x03;
    expect_rejection(
        BackupPreamble::decode(&unsupported),
        ChurStatus::UnsupportedVersion,
    )?;
    out.push(
        VectorBuilder::reject(
            "backup",
            "backup-v2-unsupported-version",
            BACKUP_V2_SPEC,
            "2",
            "Version 0x0003 is unallocated and fails as UNSUPPORTED_VERSION.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("preamble", &unsupported)
        .build(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Sync protocol
// ---------------------------------------------------------------------------

fn sync_protocol(out: &mut Vec<Vector>) -> Result<()> {
    let vault_id = id(0x11)?;
    let owner_device_id = id(0x21)?;
    let peer_device_id = id(0x22)?;
    let owner_seed = [0x81; 32];
    let peer_seed = [0x82; 32];
    let owner_key = DeviceSigningKey::from_seed(owner_seed);
    let peer_key = DeviceSigningKey::from_seed(peer_seed);
    let owner_hpke_public_key = [0x83; 32];
    let peer_hpke_public_key = [0x84; 32];

    let initial = EnrollmentRecord::initial(
        vault_id,
        owner_device_id,
        owner_key.verifying_key(),
        owner_hpke_public_key,
    )?
    .sign(&owner_key);
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-initial-enrollment",
            IDENTITY_SPEC,
            "4",
            "Generation-one self-enrollment fixes the device suites, capability, signature, and membership-chain commitment.",
        )
        .input_bytes("device_signing_seed", &owner_seed)
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("device_id", owner_device_id.as_bytes())
        .input_bytes("hpke_public_key", &owner_hpke_public_key)
        .expect_bytes("signing_public_key", &owner_key.verifying_key())
        .expect_bytes("record", &initial.encode())
        .expect_bytes("membership_commitment", &initial.commitment())
        .expect("record_length", json!(initial.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let payload_key = key(0x85);
    let operation_nonce = nonce(0x86);
    let payload = b"sync-vector-payload";
    let operation = Operation::seal(
        id(0x31)?,
        vault_id,
        owner_device_id,
        1,
        [0; 32],
        Vec::<ObservedHead>::new(),
        id(0x32)?,
        &payload_key,
        operation_nonce,
        payload,
    )?
    .sign(&owner_key);
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-signed-record",
            OPERATION_SPEC,
            "4",
            "One genesis operation fixes payload encryption, canonical signing bytes, and the per-device chain digest.",
        )
        .input_bytes("device_signing_seed", &owner_seed)
        .input_bytes("payload_key", payload_key.expose())
        .input_bytes("nonce", operation_nonce.as_bytes())
        .input_bytes("operation_id", operation.operation_id().as_bytes())
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("device_id", owner_device_id.as_bytes())
        .input("device_sequence", number(operation.device_sequence()))
        .input_bytes("previous_operation_hash", operation.previous_operation_hash())
        .input("observed_heads", json!([]))
        .input_bytes("key_selector", operation.key_selector().as_bytes())
        .input_bytes("payload_plaintext", payload)
        .expect_bytes("signing_public_key", &owner_key.verifying_key())
        .expect_bytes("record", &operation.encode())
        .expect_bytes("operation_digest", &operation.digest())
        .expect("record_length", json!(operation.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let epochs = [(id(0x41)?, 3), (id(0x42)?, 9)];
    let epochs_commitment = collection_epoch_commitment(&epochs)?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-collection-epoch-commitment",
            ROLLBACK_SPEC,
            "6.1",
            "Two sorted current collection epochs fix the ordered checkpoint commitment input.",
        )
        .input_bytes("domain_tag", tag::SYNC_COLLECTION_EPOCHS)
        .input(
            "entries",
            json!([
                {"collection_id": hex_of(epochs[0].0.as_bytes()), "current_epoch": 3},
                {"collection_id": hex_of(epochs[1].0.as_bytes()), "current_epoch": 9}
            ]),
        )
        .expect_bytes("collection_epoch_commitment", &epochs_commitment)
        .build(),
    );

    let checkpoint = Checkpoint::new(
        vault_id,
        owner_device_id,
        operation.device_sequence(),
        initial.membership_generation(),
        initial.commitment(),
        vec![CheckpointHead::new(
            owner_device_id,
            operation.device_sequence(),
            operation.digest(),
        )],
        epochs_commitment,
        UNCOMPACTED_CATALOG_STATE_COMMITMENT,
    )?
    .sign(&owner_key);
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-checkpoint",
            ROLLBACK_SPEC,
            "6",
            "A signed uncompacted checkpoint binds membership, exact device heads, and current collection epochs.",
        )
        .input_bytes("device_signing_seed", &owner_seed)
        .input_bytes("vault_id", vault_id.as_bytes())
        .input_bytes("issuer_device_id", owner_device_id.as_bytes())
        .input("issuer_device_sequence", number(operation.device_sequence()))
        .input("membership_generation", number(initial.membership_generation()))
        .input_bytes("membership_commitment", &initial.commitment())
        .input_bytes("operation_digest", &operation.digest())
        .input_bytes("collection_epoch_commitment", &epochs_commitment)
        .input_bytes(
            "catalog_state_commitment",
            &UNCOMPACTED_CATALOG_STATE_COMMITMENT,
        )
        .expect_bytes("record", &checkpoint.encode())
        .expect_bytes("checkpoint_commitment", &checkpoint.commitment())
        .expect("record_length", json!(checkpoint.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let successor = EnrollmentRecord::new(
        vault_id,
        peer_device_id,
        peer_key.verifying_key(),
        peer_hpke_public_key,
        2,
        owner_device_id,
        2,
        initial.commitment(),
        checkpoint.commitment(),
    )?
    .sign(&owner_key);
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-successor-enrollment",
            IDENTITY_SPEC,
            "4",
            "A later enrollment binds the new keys to the prior membership head and the issuer's bootstrap checkpoint.",
        )
        .input_bytes("issuer_signing_seed", &owner_seed)
        .input_bytes("device_id", peer_device_id.as_bytes())
        .input_bytes("signing_public_key", &peer_key.verifying_key())
        .input_bytes("hpke_public_key", &peer_hpke_public_key)
        .input("created_sequence", number(2))
        .input("membership_generation", number(2))
        .input_bytes("previous_membership_commitment", &initial.commitment())
        .input_bytes("bootstrap_checkpoint_commitment", &checkpoint.commitment())
        .expect_bytes("record", &successor.encode())
        .expect_bytes("membership_commitment", &successor.commitment())
        .expect("record_length", json!(successor.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let peer_final_digest = [0x87; 32];
    let revocation = RevocationRecord::new(
        vault_id,
        peer_device_id,
        1,
        peer_final_digest,
        3,
        owner_device_id,
        successor.commitment(),
    )?
    .sign(&owner_key);
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-revocation",
            IDENTITY_SPEC,
            "9",
            "Device revocation pins the final accepted branch and advances the membership chain.",
        )
        .input_bytes("issuer_signing_seed", &owner_seed)
        .input_bytes("revoked_device_id", peer_device_id.as_bytes())
        .input("final_accepted_device_sequence", number(1))
        .input_bytes("final_accepted_operation_digest", &peer_final_digest)
        .input("membership_generation", number(3))
        .input_bytes("previous_membership_commitment", &successor.commitment())
        .expect_bytes("record", &revocation.encode())
        .expect_bytes("membership_commitment", &revocation.commitment())
        .expect("record_length", json!(revocation.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );

    let mut version_two = operation.encode();
    version_two[1] = 2;
    expect_rejection(
        Operation::decode(&version_two),
        ChurStatus::UnsupportedVersion,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-version-two",
            OPERATION_SPEC,
            "2",
            "A v1 reader rejects an unallocated sync protocol version.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("record", &version_two)
        .build(),
    );

    let operation_bytes = operation.encode();
    let truncated = &operation_bytes[..operation_bytes.len() - 1];
    expect_rejection(
        Operation::decode(truncated),
        ChurStatus::NonCanonicalEncoding,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-truncated-signature",
            OPERATION_SPEC,
            "2",
            "A record with a truncated signature is not canonical.",
            "NON_CANONICAL_ENCODING",
        )
        .input_bytes("record", truncated)
        .build(),
    );

    let mut modified_signature = operation_bytes;
    let last = modified_signature.len() - 1;
    modified_signature[last] ^= 1;
    let modified = Operation::decode(&modified_signature)?;
    expect_rejection(
        modified.verify_signature(&owner_key.verifying_key()),
        ChurStatus::AuthenticationFailed,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-modified-signature",
            OPERATION_SPEC,
            "7",
            "A modified Ed25519 signature does not authenticate the canonical operation.",
            "AUTHENTICATION_FAILED",
        )
        .input_bytes("signing_public_key", &owner_key.verifying_key())
        .input_bytes("record", &modified_signature)
        .build(),
    );

    let mut hpke_suite_two = initial.encode();
    hpke_suite_two[69] = 2;
    expect_rejection(
        EnrollmentRecord::decode(&hpke_suite_two),
        ChurStatus::UnsupportedVersion,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-hpke-suite-two",
            IDENTITY_SPEC,
            "4",
            "Enrollment rejects an unallocated HPKE suite before accepting device keys.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("record", &hpke_suite_two)
        .build(),
    );

    let mut compacted_checkpoint = checkpoint.encode();
    let catalog_commitment = compacted_checkpoint.len() - 64 - 32;
    compacted_checkpoint[catalog_commitment] = 1;
    expect_rejection(
        Checkpoint::decode(&compacted_checkpoint),
        ChurStatus::UnsupportedVersion,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-compacted-checkpoint",
            ROLLBACK_SPEC,
            "6.1",
            "Sync v1 rejects a checkpoint that claims an unsupported compacted catalog state.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("record", &compacted_checkpoint)
        .build(),
    );

    let mut self_issued_revocation = revocation.encode();
    self_issued_revocation.copy_within(82..98, 18);
    expect_rejection(
        RevocationRecord::decode(&self_issued_revocation),
        ChurStatus::NonCanonicalEncoding,
    )?;
    out.push(
        VectorBuilder::reject(
            "operation",
            "operation-v1-self-issued-revocation",
            IDENTITY_SPEC,
            "9",
            "A device cannot issue its own revocation record.",
            "NON_CANONICAL_ENCODING",
        )
        .input_bytes("record", &self_issued_revocation)
        .build(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Collection sharing
// ---------------------------------------------------------------------------

fn sharing_protocol(out: &mut Vec<Vector>) -> Result<()> {
    let source_vault_id = id(0x91)?;
    let collection_id = id(0x92)?;
    let sender_device_id = id(0x93)?;
    let recipient_vault_id = id(0x94)?;
    let recipient_device_id = id(0x95)?;
    let sender = DeviceSigningKey::from_seed([0x96; 32]);
    let recipient = DeviceIdentity::from_seeds([0x97; 32], [0x98; 32]);
    let membership = CollectionMembershipRecord::new(
        source_vault_id,
        collection_id,
        1,
        [0; 32],
        CollectionMembershipAction::Upsert(PermissionProfile::Contribute),
        recipient_vault_id,
        recipient_device_id,
        recipient.signing_public_key(),
        recipient.hpke_public_key(),
        1,
        source_vault_id,
        sender_device_id,
        1,
        1,
    )?
    .sign(&sender);
    out.push(
        VectorBuilder::accept(
            "collection-membership",
            "collection-membership-v1-upsert",
            COLLECTION_MEMBERSHIP_SPEC,
            "1",
            "One signed generation-one recipient-device membership entry.",
        )
        .input_bytes("sender_signing_seed", &[0x96; 32])
        .input_bytes(
            "recipient_signing_public_key",
            &recipient.signing_public_key(),
        )
        .input_bytes("recipient_hpke_public_key", &recipient.hpke_public_key())
        .expect_bytes("record", &membership.encode())
        .expect_bytes("membership_commitment", &membership.commitment())
        .expect("record_length", json!(CollectionMembershipRecord::LEN))
        .build(),
    );

    let operation_key = key(0x9c);
    let operation_plaintext = b"deterministic shared collection payload";
    let collection_operation = CollectionOperation::seal(
        id(0x9d)?,
        source_vault_id,
        sender_device_id,
        1,
        [0; 32],
        vec![CollectionObservedHead::new(
            recipient_vault_id,
            recipient_device_id,
            3,
        )],
        id(0x9e)?,
        &operation_key,
        nonce(0x9f),
        operation_plaintext,
    )?
    .sign(&sender);
    collection_operation.verify_signature(&sender.verifying_key())?;
    let opened = collection_operation.open_payload(&operation_key)?;
    if opened.as_slice() != operation_plaintext {
        return Err(Error::new(
            ChurStatus::InternalFailure,
            "collection operation vector opened the wrong payload",
        ));
    }
    out.push(
        VectorBuilder::accept(
            "collection-operation",
            "collection-operation-v1-signed-encrypted",
            COLLECTION_OPERATION_SPEC,
            "1",
            "One byte-exact signed and encrypted cross-vault collection operation.",
        )
        .input_bytes("issuer_signing_seed", &[0x96; 32])
        .input_bytes("operation_key", operation_key.expose())
        .input_bytes("nonce", &[0x9f; NONCE_LEN])
        .input_bytes("plaintext", operation_plaintext)
        .expect_bytes("record", &collection_operation.encode())
        .expect_bytes("operation_digest", &collection_operation.digest())
        .expect_bytes("opened_plaintext", &opened)
        .expect("record_length", json!(collection_operation.encode().len()))
        .build(),
    );

    let collection_key = key(0x99);
    let ephemeral_ikm = [0x9a; 32];
    let grant = CollectionGrant::seal_for_test_vector(
        id(0x9b)?,
        source_vault_id,
        collection_id,
        1,
        1,
        recipient_vault_id,
        recipient_device_id,
        &recipient.hpke_public_key(),
        sender_device_id,
        PermissionProfile::Contribute,
        1,
        2,
        &collection_key,
        &sender,
        ephemeral_ikm,
    )?;
    let opened = grant.open_collection_key(
        &recipient_vault_id,
        &recipient_device_id,
        &recipient,
        &sender.verifying_key(),
    )?;
    if opened != collection_key {
        return Err(Error::new(
            ChurStatus::InternalFailure,
            "sharing vector opened the wrong collection key",
        ));
    }
    out.push(
        VectorBuilder::accept(
            "collection-grant",
            "collection-grant-v1-signed-hpke",
            GRANT_SPEC,
            "2",
            "One byte-exact signed RFC 9180 grant opens only to the bound recipient device.",
        )
        .input_bytes("collection_key", collection_key.expose())
        .input_bytes("ephemeral_ikm", &ephemeral_ikm)
        .input_bytes("recipient_hpke_public_key", &recipient.hpke_public_key())
        .input_bytes("sender_signing_seed", &[0x96; 32])
        .expect_bytes(
            "recipient_hpke_key_id",
            &hpke_key_id(
                &recipient_vault_id,
                &recipient_device_id,
                &recipient.hpke_public_key(),
            ),
        )
        .expect_bytes(
            "sender_signing_key_id",
            &signing_key_id(&source_vault_id, &sender_device_id, &sender.verifying_key()),
        )
        .expect_bytes("record", &grant.encode())
        .expect_bytes("opened_collection_key", opened.expose())
        .expect("record_length", json!(CollectionGrant::LEN))
        .build(),
    );

    let mut modified_signature = grant.encode();
    modified_signature[CollectionGrant::LEN - 1] ^= 1;
    let modified = CollectionGrant::decode(&modified_signature)?;
    expect_rejection(
        modified.open_collection_key(
            &recipient_vault_id,
            &recipient_device_id,
            &recipient,
            &sender.verifying_key(),
        ),
        ChurStatus::AuthenticationFailed,
    )?;
    out.push(
        VectorBuilder::reject(
            "collection-grant",
            "collection-grant-v1-modified-signature",
            GRANT_SPEC,
            "4",
            "A modified sender signature cannot authenticate the HPKE grant.",
            "AUTHENTICATION_FAILED",
        )
        .input_bytes("recipient_signing_seed", &[0x97; 32])
        .input_bytes("recipient_hpke_secret", &[0x98; 32])
        .input_bytes("sender_signing_public_key", &sender.verifying_key())
        .input_bytes("record", &modified_signature)
        .build(),
    );

    let mut unknown_profile = grant.encode();
    unknown_profile[3] = 2;
    expect_rejection(
        CollectionGrant::decode(&unknown_profile),
        ChurStatus::UnsupportedVersion,
    )?;
    out.push(
        VectorBuilder::reject(
            "collection-grant",
            "collection-grant-v1-unknown-hpke-profile",
            GRANT_SPEC,
            "1",
            "A reader rejects an unallocated HPKE profile before opening a key.",
            "UNSUPPORTED_VERSION",
        )
        .input_bytes("record", &unknown_profile)
        .build(),
    );
    Ok(())
}

fn disposable_object_keys(out: &mut Vec<Vector>) -> Result<()> {
    let recipient = DeviceSigningKey::from_seed([0xa1; 32]);
    let sender = DeviceSigningKey::from_seed([0xa2; 32]);
    let collection = id(0xa3)?;
    let object = id(0xa4)?;
    let private = key(0xa5);
    let content = key(0xa6);
    let request = ObjectPrekey::sign(
        id(0xa7)?,
        collection,
        object,
        1,
        [0xa8; 32],
        id(0xa9)?,
        id(0xaa)?,
        1,
        &private,
        &recipient,
    )?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-object-key-request",
            "docs/sync/OBJECT_KEY_GRANTS.md",
            "1",
            "One signed disposable key request binds the recipient to one committed object.",
        )
        .input_bytes("recipient_signing_seed", &[0xa1; 32])
        .input_bytes("disposable_private_key", private.expose())
        .expect_bytes("record", &request.encode())
        .expect("record_length", json!(request.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );
    let grant = ObjectKeyGrant::seal_for_test_vector(
        id(0xab)?,
        id(0xac)?,
        id(0xad)?,
        object,
        1,
        [0xa8; 32],
        &request,
        &content,
        &sender,
        [0xae; 32],
    )?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-object-key-grant",
            "docs/sync/OBJECT_KEY_GRANTS.md",
            "2",
            "One signed HPKE grant opens only with the object's disposable private key.",
        )
        .input_bytes("source_signing_seed", &[0xa2; 32])
        .input_bytes("ephemeral_ikm", &[0xae; 32])
        .input_bytes("object_key", content.expose())
        .input_bytes("request", &request.encode())
        .expect_bytes("record", &grant.encode())
        .expect("record_length", json!(grant.encode().len()))
        .expect_bytes(
            "opened_key",
            grant
                .open(&request, &private, &sender.verifying_key())?
                .expose(),
        )
        .note(TEST_ONLY)
        .build(),
    );
    for (vector_id, body) in [
        (
            "operation-v1-key-free-object-commit",
            PayloadBody::CommitObject {
                object_id: object,
                object_generation: 1,
                store_id: id(0xaf)?,
                container_length: 1024,
                container_commitment: [0xa8; 32],
                object_key_commitment: object_key_commitment(&collection, &object, &content),
            },
        ),
        (
            "operation-v1-key-free-object-rewrap",
            PayloadBody::RewrapObjectKey {
                object_id: object,
                object_key_commitment: object_key_commitment(&collection, &object, &content),
            },
        ),
    ] {
        let payload = OperationPayload::new(collection, 1, body)?;
        out.push(VectorBuilder::accept("operation", vector_id, "docs/sync/OPERATION_PAYLOAD_V1.md", "2",
            "The signed payload contains a key commitment and no recoverable object-key envelope.")
            .input_bytes("object_key", content.expose()).expect_bytes("record", &payload.encode())
            .expect("record_length", json!(payload.encode().len())).note(TEST_ONLY).build());
    }
    let ready = OperationPayload::new(id(0xac)?, 0, PayloadBody::DeviceReady)?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-device-ready",
            "docs/sync/OPERATION_PAYLOAD_V1.md",
            "2",
            "An enrolled new device starts its ordinary chain without a content mutation.",
        )
        .expect_bytes("record", &ready.encode())
        .expect("record_length", json!(ready.encode().len()))
        .build(),
    );
    let purge = OperationPayload::new(
        collection,
        1,
        PayloadBody::PurgeObject {
            object_id: object,
            object_generation: 1,
            authored_at_ms: 1787990400000,
        },
    )?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-permanent-object-purge",
            "docs/sync/OPERATION_PAYLOAD_V1.md",
            "2",
            "A terminal purge names the committed object and contains no key.",
        )
        .expect_bytes("record", &purge.encode())
        .expect("record_length", json!(purge.encode().len()))
        .build(),
    );
    let envelope = CollectionKeyEnvelope::seal(
        &key(0xb0),
        id(0xac)?,
        collection,
        1,
        1,
        Nonce::new([0xb1; 24]),
        &key(0xb2),
    )?;
    let declaration = OperationPayload::new(
        id(0xac)?,
        0,
        PayloadBody::DeclareCollection {
            collection_key_envelope: envelope,
        },
    )?;
    out.push(
        VectorBuilder::accept(
            "operation",
            "operation-v1-declare-collection",
            "docs/sync/OPERATION_PAYLOAD_V1.md",
            "2",
            "An own-vault declaration carries a root-wrapped metadata key and no content key.",
        )
        .input_bytes("root_key", key(0xb0).expose())
        .input_bytes("collection_metadata_key", key(0xb2).expose())
        .expect_bytes("record", &declaration.encode())
        .expect("record_length", json!(declaration.encode().len()))
        .note(TEST_ONLY)
        .build(),
    );
    Ok(())
}
