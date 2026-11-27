//! Domain tags and the canonical tuple encoder.
//!
//! `docs/format/CANONICAL_ENCODING_V1.md` §7 makes a domain tag a bare ASCII
//! byte constant with no length prefix, no terminator, and no trailing NUL, and
//! §7.1 makes `CanonicalTuple(tag, element, ...)` a §4 structure whose first
//! field is that tag and which adds no framing of its own: no element count, no
//! schema-version field, no separator, and no terminator.
//!
//! Tuple bytes are produced, never parsed. They are AEAD additional
//! authenticated data, HKDF `info`, or hash input, so a mismatch surfaces as an
//! authentication failure rather than as a decode error. There is deliberately
//! no reader in this module.

use chur_core::Id;
use chur_core::status::ChurStatus;
use chur_core::{Error, Result};

/// A registered domain tag, as its exact bytes.
///
/// Every value is allocated in `docs/format/CANONICAL_ENCODING_V1.md` §15.5.
/// The `\0` bytes are separators inside the constant itself.
pub mod tag {
    /// HKDF `info` tuple for every derivation.
    pub const KDF_INFO: &[u8] = b"CHUR\0KDF\0INFO\0V1";
    /// Password key-slot AAD.
    pub const SLOT_PASSWORD: &[u8] = b"CHUR\0SLOT\0PASSWORD\0V1";
    /// Recovery key-slot AAD.
    pub const SLOT_RECOVERY: &[u8] = b"CHUR\0SLOT\0RECOVERY\0V1";
    /// Android Keystore key-slot AAD.
    pub const SLOT_ANDROID_KEYSTORE: &[u8] = b"CHUR\0SLOT\0ANDROID-KEYSTORE\0V1";
    /// Apple Keychain key-slot AAD.
    pub const SLOT_APPLE_KEYCHAIN: &[u8] = b"CHUR\0SLOT\0APPLE-KEYCHAIN\0V1";
    /// Collection-key envelope AAD.
    pub const COLLECTION_KEY_ENVELOPE: &[u8] = b"CHUR\0COLLECTION\0KEY-ENVELOPE\0V1";
    /// Object-key envelope AAD.
    pub const OBJECT_KEY_ENVELOPE: &[u8] = b"CHUR\0OBJECT\0KEY-ENVELOPE\0V1";
    /// Object-bound disposable key request signature.
    pub const OBJECT_PREKEY_SIGNATURE: &[u8] = b"CHUR\0OBJECT-PREKEY\0SIGNATURE\0V1";
    /// Disposable object-key grant signature.
    pub const OBJECT_KEY_GRANT_SIGNATURE: &[u8] = b"CHUR\0OBJECT-KEY-GRANT\0SIGNATURE\0V1";
    /// Disposable object-key grant HPKE context.
    pub const OBJECT_KEY_GRANT_HPKE: &[u8] = b"CHUR\0OBJECT-KEY-GRANT\0HPKE\0V1";
    /// Key-free content-key commitment.
    pub const OBJECT_KEY_COMMITMENT: &[u8] = b"CHUR\0OBJECT-KEY\0COMMITMENT\0V1";
    /// Encrypted manifest AAD.
    pub const OBJECT_MANIFEST_AAD: &[u8] = b"CHUR\0OBJECT\0MANIFEST-AAD\0V1";
    /// Manifest commitment.
    pub const OBJECT_MANIFEST_COMMITMENT: &[u8] = b"CHUR\0OBJECT\0MANIFEST-COMMITMENT\0V1";
    /// Chunk AAD.
    pub const OBJECT_CHUNK_AAD: &[u8] = b"CHUR\0OBJECT\0CHUNK-AAD\0V1";
    /// Ordered chunk commitment.
    pub const OBJECT_ORDERED_COMMITMENT: &[u8] = b"CHUR\0OBJECT\0ORDERED-COMMITMENT\0V1";
    /// Final-commit AAD.
    pub const OBJECT_FINAL_COMMIT_AAD: &[u8] = b"CHUR\0OBJECT\0FINAL-COMMIT-AAD\0V1";
    /// Vault-descriptor authentication tag.
    pub const VAULT_DESCRIPTOR_AUTH: &[u8] = b"CHUR\0VAULT\0DESCRIPTOR-AUTH\0V1";
    /// §15.5: catalog header commitment, `VAULT_DESCRIPTOR_V1.md` §5.
    pub const CATALOG_HEADER_COMMITMENT: &[u8] = b"CHUR\0CATALOG\0HEADER-COMMITMENT\0V1";
    /// Ordered backup inventory commitment.
    pub const BACKUP_INVENTORY_COMMITMENT: &[u8] = b"CHUR\0BACKUP\0INVENTORY-COMMITMENT\0V1";
    /// Backup manifest AAD, `BACKUP_FORMAT_V1.md` §4.
    pub const BACKUP_MANIFEST_AAD: &[u8] = b"CHUR\0BACKUP\0MANIFEST-AAD\0V1";
    /// Final backup commit AAD, `BACKUP_FORMAT_V1.md` §7.
    pub const BACKUP_FINAL_COMMIT_AAD: &[u8] = b"CHUR\0BACKUP\0FINAL-COMMIT-AAD\0V1";
    /// Catalog export record AAD, ADR-0068.
    pub const BACKUP_CATALOG_EXPORT_AAD: &[u8] = b"CHUR\0BACKUP\0CATALOG-EXPORT-AAD\0V1";
    /// Commitment over every non-container package record, ADR-0068.
    pub const BACKUP_RECORD_COMMITMENT: &[u8] = b"CHUR\0BACKUP\0RECORD-COMMITMENT\0V1";
    /// Operation digest and per-device chain hash.
    pub const SYNC_OPERATION_CHAIN: &[u8] = b"CHUR\0SYNC\0OPERATION-CHAIN\0V1";
    /// Operation payload AAD and Ed25519 signature input.
    pub const SYNC_OPERATION: &[u8] = b"CHUR\0SYNC\0OPERATION\0V1";
    /// Checkpoint record signature.
    pub const SYNC_CHECKPOINT: &[u8] = b"CHUR\0SYNC\0CHECKPOINT\0V1";
    /// Checkpoint commitment used by enrollment and recovery.
    pub const SYNC_CHECKPOINT_COMMITMENT: &[u8] = b"CHUR\0SYNC\0CHECKPOINT-COMMITMENT\0V1";
    /// Ordered current collection-epoch commitment.
    pub const SYNC_COLLECTION_EPOCHS: &[u8] = b"CHUR\0SYNC\0COLLECTION-EPOCHS\0V1";
    /// Device-enrollment record signature.
    pub const SYNC_ENROLLMENT: &[u8] = b"CHUR\0SYNC\0ENROLLMENT\0V1";
    /// Device-revocation record signature.
    pub const SYNC_REVOCATION: &[u8] = b"CHUR\0SYNC\0REVOCATION\0V1";
    /// Membership-chain commitment.
    pub const SYNC_MEMBERSHIP_CHAIN: &[u8] = b"CHUR\0SYNC\0MEMBERSHIP-CHAIN\0V1";
    /// Opaque server deletion authorization signature.
    pub const SYNC_SERVER_DELETE: &[u8] = b"CHUR\0SYNC\0SERVER-DELETE\0V1";
    /// Keyed restored-root possession proof.
    pub const PAIRING_ROOT_PROOF: &[u8] = b"CHUR\0PAIRING\0ROOT-PROOF\0V1";
    /// Fresh own-device request signature.
    pub const PAIRING_REQUEST_SIGNATURE: &[u8] = b"CHUR\0PAIRING\0REQUEST-SIGNATURE\0V1";
    /// Complete own-device request commitment.
    pub const PAIRING_REQUEST_DIGEST: &[u8] = b"CHUR\0PAIRING\0REQUEST-DIGEST\0V1";
    /// Authorized own-device approval signature.
    pub const PAIRING_APPROVAL_SIGNATURE: &[u8] = b"CHUR\0PAIRING\0APPROVAL-SIGNATURE\0V1";
    /// Own-device approval HPKE info and AAD.
    pub const PAIRING_APPROVAL_HPKE: &[u8] = b"CHUR\0PAIRING\0APPROVAL-HPKE\0V1";
    /// Device verification fingerprint.
    pub const IDENTITY_FINGERPRINT: &[u8] = b"CHUR\0IDENTITY\0FINGERPRINT\0V1";
    /// Signing public-key identifier.
    pub const IDENTITY_SIGNING_KEY_ID: &[u8] = b"CHUR\0IDENTITY\0SIGNING-KEY-ID\0V1";
    /// HPKE public-key identifier.
    pub const IDENTITY_HPKE_KEY_ID: &[u8] = b"CHUR\0IDENTITY\0HPKE-KEY-ID\0V1";
    /// Collection-grant HPKE `info`.
    pub const SHARING_GRANT_HPKE_INFO: &[u8] = b"CHUR\0SHARING\0GRANT-HPKE-INFO\0V1";
    /// Collection-grant HPKE AAD.
    pub const SHARING_GRANT_HPKE_AAD: &[u8] = b"CHUR\0SHARING\0GRANT-HPKE-AAD\0V1";
    /// Collection-grant Ed25519 signature.
    pub const SHARING_COLLECTION_GRANT: &[u8] = b"CHUR\0SHARING\0COLLECTION-GRANT\0V1";
    /// Signs one collection membership change.
    pub const SHARING_COLLECTION_MEMBERSHIP: &[u8] = b"CHUR\0SHARING\0COLLECTION-MEMBERSHIP\0V1";
    /// Commits the ordered collection membership chain.
    pub const SHARING_MEMBERSHIP_CHAIN: &[u8] = b"CHUR\0SHARING\0MEMBERSHIP-CHAIN\0V1";
    /// Shared-collection operation payload AAD.
    pub const SHARING_COLLECTION_OPERATION_AAD: &[u8] =
        b"CHUR\0SHARING\0COLLECTION-OPERATION-AAD\0V1";
    /// Shared-collection operation signature input.
    pub const SHARING_COLLECTION_OPERATION: &[u8] = b"CHUR\0SHARING\0COLLECTION-OPERATION\0V1";
    /// Shared-collection operation chain digest.
    pub const SHARING_COLLECTION_OPERATION_CHAIN: &[u8] =
        b"CHUR\0SHARING\0COLLECTION-OPERATION-CHAIN\0V1";
    /// Portable device-identity envelope AAD.
    pub const DEVICE_IDENTITY_ENVELOPE: &[u8] = b"CHUR\0IDENTITY\0ENVELOPE\0V1";

    /// Every tag this build allocates, for the prefix-free check of §7.
    pub const ALL: &[&[u8]] = &[
        KDF_INFO,
        SLOT_PASSWORD,
        SLOT_RECOVERY,
        SLOT_ANDROID_KEYSTORE,
        SLOT_APPLE_KEYCHAIN,
        COLLECTION_KEY_ENVELOPE,
        OBJECT_KEY_ENVELOPE,
        OBJECT_PREKEY_SIGNATURE,
        OBJECT_KEY_GRANT_SIGNATURE,
        OBJECT_KEY_GRANT_HPKE,
        OBJECT_KEY_COMMITMENT,
        OBJECT_MANIFEST_AAD,
        OBJECT_MANIFEST_COMMITMENT,
        OBJECT_CHUNK_AAD,
        OBJECT_ORDERED_COMMITMENT,
        OBJECT_FINAL_COMMIT_AAD,
        VAULT_DESCRIPTOR_AUTH,
        CATALOG_HEADER_COMMITMENT,
        BACKUP_INVENTORY_COMMITMENT,
        BACKUP_MANIFEST_AAD,
        BACKUP_FINAL_COMMIT_AAD,
        BACKUP_CATALOG_EXPORT_AAD,
        BACKUP_RECORD_COMMITMENT,
        SYNC_OPERATION,
        SYNC_OPERATION_CHAIN,
        SYNC_CHECKPOINT,
        SYNC_CHECKPOINT_COMMITMENT,
        SYNC_COLLECTION_EPOCHS,
        SYNC_ENROLLMENT,
        SYNC_REVOCATION,
        SYNC_MEMBERSHIP_CHAIN,
        SYNC_SERVER_DELETE,
        PAIRING_ROOT_PROOF,
        PAIRING_REQUEST_SIGNATURE,
        PAIRING_REQUEST_DIGEST,
        PAIRING_APPROVAL_SIGNATURE,
        PAIRING_APPROVAL_HPKE,
        IDENTITY_FINGERPRINT,
        IDENTITY_SIGNING_KEY_ID,
        IDENTITY_HPKE_KEY_ID,
        SHARING_GRANT_HPKE_INFO,
        SHARING_GRANT_HPKE_AAD,
        SHARING_COLLECTION_GRANT,
        SHARING_COLLECTION_MEMBERSHIP,
        SHARING_MEMBERSHIP_CHAIN,
        SHARING_COLLECTION_OPERATION_AAD,
        SHARING_COLLECTION_OPERATION,
        SHARING_COLLECTION_OPERATION_CHAIN,
        DEVICE_IDENTITY_ENVELOPE,
    ];
}

/// Builds the bytes of one canonical tuple.
///
/// Construction takes the domain tag, and every method appends one element by
/// the rule its declared type carries in
/// `docs/format/CANONICAL_ENCODING_V1.md` §2. A fixed-length element carries no
/// prefix; a variable-length element carries its own `u32` length.
#[derive(Clone)]
pub struct Tuple {
    bytes: Vec<u8>,
}

impl Tuple {
    /// Starts a tuple with its registered domain tag.
    ///
    /// The tag is written as its exact bytes: no length prefix, no terminator.
    #[must_use]
    pub fn new(tag: &'static [u8]) -> Self {
        let mut bytes = Vec::with_capacity(tag.len() + 64);
        bytes.extend_from_slice(tag);
        Self { bytes }
    }

    /// Appends a `u8`.
    #[must_use]
    pub fn u8(mut self, value: u8) -> Self {
        self.bytes.push(value);
        self
    }

    /// Appends a big-endian `u16`.
    #[must_use]
    pub fn u16(mut self, value: u16) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a big-endian `u32`.
    #[must_use]
    pub fn u32(mut self, value: u32) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a big-endian `u64`.
    #[must_use]
    pub fn u64(mut self, value: u64) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a boolean as `0x00` or `0x01`.
    #[must_use]
    pub fn bool(self, value: bool) -> Self {
        self.u8(u8::from(value))
    }

    /// Appends a fixed-length byte element, with no length prefix.
    ///
    /// The element's width is fixed by the owning specification, so the caller
    /// passes exactly that many bytes.
    #[must_use]
    pub fn fixed(mut self, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// Appends an opaque 16-byte identifier as a fixed-length element.
    #[must_use]
    pub fn id(self, value: &Id) -> Self {
        self.fixed(value.as_bytes())
    }

    /// Appends a variable-length byte element: a `u32` length then the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::ResourceLimitExceeded`] when the value is longer
    /// than a `u32` can express, which no v1 element is.
    pub fn variable(mut self, value: &[u8]) -> Result<Self> {
        let length = u32::try_from(value.len()).map_err(|_| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "variable tuple element exceeds the u32 length prefix",
            )
        })?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(self)
    }

    /// Appends a UTF-8 string element: a `u32` byte length then the bytes.
    ///
    /// The length counts encoded bytes, not characters, and no normalization is
    /// applied, per `docs/format/CANONICAL_ENCODING_V1.md` §3.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::ResourceLimitExceeded`] when the encoded string is
    /// longer than a `u32` can express.
    pub fn string(self, value: &str) -> Result<Self> {
        self.variable(value.as_bytes())
    }

    /// The encoded tuple.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// The number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has been written, which no tuple with a tag satisfies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_tag_has_the_registered_shape() {
        for entry in tag::ALL {
            assert!(entry.starts_with(b"CHUR\0"), "tag does not start with CHUR");
            assert!(entry.ends_with(b"\0V1"), "tag does not end with a version");
            assert!(!entry.ends_with(b"\0"), "tag carries a trailing NUL");
            assert_eq!(
                entry.iter().filter(|byte| **byte == 0).count(),
                3,
                "a tag has exactly three separators"
            );
            assert!(entry.iter().all(u8::is_ascii), "tag is not ASCII");
        }
    }

    #[test]
    fn the_sync_operation_tag_matches_the_registry() {
        assert_eq!(tag::SYNC_OPERATION, b"CHUR\0SYNC\0OPERATION\0V1");
    }

    #[test]
    fn no_tag_is_a_byte_prefix_of_another() {
        for (index, left) in tag::ALL.iter().enumerate() {
            for (other, right) in tag::ALL.iter().enumerate() {
                if index == other {
                    continue;
                }
                assert!(
                    !right.starts_with(left),
                    "one allocated tag is a prefix of another"
                );
            }
        }
    }

    #[test]
    fn the_documented_tag_lengths_hold() {
        // Every length a specification states in prose, asserted against bytes.
        assert_eq!(tag::KDF_INFO.len(), 16);
        assert_eq!(tag::SLOT_PASSWORD.len(), 21);
        assert_eq!(tag::SLOT_RECOVERY.len(), 21);
        assert_eq!(tag::SLOT_ANDROID_KEYSTORE.len(), 29);
        assert_eq!(tag::SLOT_APPLE_KEYCHAIN.len(), 27);
        assert_eq!(tag::COLLECTION_KEY_ENVELOPE.len(), 31);
        assert_eq!(tag::OBJECT_KEY_ENVELOPE.len(), 27);
        assert_eq!(tag::OBJECT_MANIFEST_AAD.len(), 27);
        assert_eq!(tag::OBJECT_MANIFEST_COMMITMENT.len(), 34);
        assert_eq!(tag::OBJECT_CHUNK_AAD.len(), 24);
        assert_eq!(tag::OBJECT_ORDERED_COMMITMENT.len(), 33);
        assert_eq!(tag::OBJECT_FINAL_COMMIT_AAD.len(), 31);
    }

    #[test]
    fn a_tuple_adds_no_framing_of_its_own() {
        let encoded = Tuple::new(tag::OBJECT_CHUNK_AAD).u16(1).u16(1).finish();
        let mut expected = tag::OBJECT_CHUNK_AAD.to_vec();
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn the_illustrative_tuple_of_the_encoding_profile_encodes_as_documented() {
        // CANONICAL_ENCODING_V1.md §7.1 works one example through: a 21-byte
        // tag, a u16, a 16-byte fixed element, then a u32-prefixed string.
        let object_id = Id::new([0xaa; 16]).unwrap();
        let encoded = Tuple::new(b"CHUR\0EXAMPLE\0TUPLE\0V1")
            .u16(0x0001)
            .id(&object_id)
            .string("label")
            .unwrap()
            .finish();
        assert_eq!(encoded.len(), 21 + 2 + 16 + 4 + 5);
        assert_eq!(&encoded[..21], b"CHUR\0EXAMPLE\0TUPLE\0V1");
        assert_eq!(&encoded[21..23], &[0x00, 0x01]);
        assert_eq!(&encoded[39..43], &[0x00, 0x00, 0x00, 0x05]);
        assert_eq!(&encoded[43..], b"label");
    }

    #[test]
    fn a_variable_element_carries_its_own_length() {
        let encoded = Tuple::new(tag::SLOT_PASSWORD)
            .variable(&[0xde, 0xad])
            .unwrap()
            .finish();
        assert_eq!(
            &encoded[tag::SLOT_PASSWORD.len()..],
            &[0, 0, 0, 2, 0xde, 0xad]
        );
    }

    #[test]
    fn a_boolean_is_one_byte() {
        assert_eq!(
            Tuple::new(tag::KDF_INFO).bool(true).finish().last(),
            Some(&1)
        );
        assert_eq!(
            Tuple::new(tag::KDF_INFO).bool(false).finish().last(),
            Some(&0)
        );
    }
}
