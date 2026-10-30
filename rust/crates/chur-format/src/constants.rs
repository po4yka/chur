//! The v1 constant registry.
//!
//! `docs/format/CANONICAL_ENCODING_V1.md` §15 allocates the values shared
//! across Chur formats: file magics, version numbers, encoding profile and
//! policy identifiers, suite identifiers, record types, and enumerated
//! discriminants. This module is that registry as Rust.
//!
//! Widths are uniform: format-level version, profile, policy, and suite
//! identifiers are `u16`; per-record type and version bytes and enumerated
//! discriminants are `u8`. `0x0000` and `0x00` are never allocated and are
//! invalid in every namespace, and every unallocated value is unsupported: a
//! reader rejects it rather than ignoring or forwarding it.

use chur_core::limits::MAGIC_LEN;

/// §15.1: the `ChurObjectV1` container magic.
pub const MAGIC_OBJECT: [u8; MAGIC_LEN] = *b"CHUROBJ1";
/// §15.1: the `VaultDescriptorV1` magic.
pub const MAGIC_VAULT: [u8; MAGIC_LEN] = *b"CHURVLT1";
/// §15.1: the `BackupPackageV1` magic.
pub const MAGIC_BACKUP: [u8; MAGIC_LEN] = *b"CHURBAK1";

/// §15.2: the only v1 cryptographic suite.
///
/// XChaCha20-Poly1305 for AEAD, BLAKE3-256 for commitments, HKDF-SHA-256 for
/// key derivation.
pub const SUITE_V1: u16 = 0x0001;
/// §15.2: canonical encoding profile v1.
pub const ENCODING_PROFILE_V1: u16 = 0x0001;
/// §15.2: `container_version` of `ChurObjectV1`.
pub const CONTAINER_VERSION_V1: u16 = 0x0001;
/// §15.2: `container_version` of the bucket-padded container of ADR-0066.
pub const CONTAINER_VERSION_V2: u16 = 0x0002;
/// §15.2: `record_version` of every container record.
pub const RECORD_VERSION_V1: u8 = 0x01;
/// §15.2: `descriptor_version` of `VaultDescriptorV1`.
pub const DESCRIPTOR_VERSION_V1: u16 = 0x0001;
/// §15.2: `format_version` of both key envelopes.
pub const ENVELOPE_FORMAT_VERSION_V1: u16 = 0x0001;
/// §15.2: `backup_version` of `BackupPackageV1`.
pub const BACKUP_VERSION_V1: u16 = 0x0001;
/// §15.2: `backup_version` of the package with a portable catalog export and a
/// record commitment, ADR-0068.
pub const BACKUP_VERSION_V2: u16 = 0x0002;
/// §15.2: `export_version` of `CatalogExportV1`, ADR-0068.
pub const CATALOG_EXPORT_VERSION_V1: u16 = 0x0001;
/// §15.2: `catalog_format_version` of the private catalog.
pub const CATALOG_FORMAT_VERSION_V1: u16 = 0x0001;
/// §15.2: private catalog v2 with durable encrypted-sync state.
pub const CATALOG_FORMAT_VERSION_V2: u16 = 0x0002;
/// §15.2: private catalog v3 with durable collection-sharing state.
pub const CATALOG_FORMAT_VERSION_V3: u16 = 0x0003;
/// §15.2: private catalog v4 with durable collection-operation streams.
pub const CATALOG_FORMAT_VERSION_V4: u16 = 0x0004;
/// §15.2: private catalog v5 with the durable grant-acceptance freeze.
pub const CATALOG_FORMAT_VERSION_V5: u16 = 0x0005;
/// §15.2: private catalog v6 with an indexed shared-object projection.
pub const CATALOG_FORMAT_VERSION_V6: u16 = 0x0006;
/// §15.2: private catalog v7 with nested, ordered logical albums.
pub const CATALOG_FORMAT_VERSION_V7: u16 = 0x0007;
/// §15.2: private catalog v8 with recoverable trash and retention deadlines.
pub const CATALOG_FORMAT_VERSION_V8: u16 = 0x0008;
/// Local private notes.
pub const CATALOG_FORMAT_VERSION_V9: u16 = 0x0009;
/// Local encrypted document and image content index.
pub const CATALOG_FORMAT_VERSION_V10: u16 = 0x000a;
/// §15.2: private catalog v11 with durable pending album membership additions.
pub const CATALOG_FORMAT_VERSION_V11: u16 = 0x000b;
/// Explicit private note body format.
pub const CATALOG_FORMAT_VERSION_V12: u16 = 0x000c;
/// Bounded note-owned encrypted attachments.
pub const CATALOG_FORMAT_VERSION_V13: u16 = 0x000d;
/// Encrypted note organization and retained revisions.
pub const CATALOG_FORMAT_VERSION_V14: u16 = 0x000e;
/// Private catalog without persisted network endpoints or transport credentials.
pub const CATALOG_FORMAT_VERSION_V15: u16 = 0x000f;
/// Private catalog supporting encrypted compatible-video derivative streams.
pub const CATALOG_FORMAT_VERSION_V16: u16 = 0x0010;
/// Encrypted local playback positions and video storyboard capability.
pub const CATALOG_FORMAT_VERSION_V17: u16 = 0x0011;
/// Persisted trusted-time high-water mark for trash and note retention.
pub const CATALOG_FORMAT_VERSION_V18: u16 = 0x0012;
/// §15.2: `object_store_format_version`.
pub const OBJECT_STORE_FORMAT_VERSION_V1: u16 = 0x0001;
/// §15.2: `slot_version` of the v1 key-slot families.
pub const SLOT_VERSION_V1: u16 = 0x0001;
/// §15.2: `chunk_record_profile`, the framing of container §8.
pub const CHUNK_RECORD_PROFILE_V1: u16 = 0x0001;
/// §15.2: `commitment_profile`, the constructions of container §5 and §10.
pub const COMMITMENT_PROFILE_V1: u16 = 0x0001;
/// §15.2: `crypto_policy_id`, suite `0x0001` for every vault-level record.
pub const CRYPTO_POLICY_V1: u16 = 0x0001;
/// §15.2: `naming_profile_id`, opaque random store identifiers.
pub const NAMING_PROFILE_V1: u16 = 0x0001;
/// §15.2: `password_profile_id`, strict UTF-8 with no normalization.
pub const PASSWORD_PROFILE_V1: u16 = 0x0001;
/// §15.2: `recovery_profile_id`, a 32-byte secret as 24 BIP-39 English words.
pub const RECOVERY_PROFILE_V1: u16 = 0x0001;
/// §15.2: `keystore_profile_id`, a non-exportable AES-256-GCM Keystore key.
pub const KEYSTORE_PROFILE_V1: u16 = 0x0001;
/// §15.2: `keychain_profile_id`, a Keychain-held `DeviceUnlockSecret`.
pub const KEYCHAIN_PROFILE_V1: u16 = 0x0001;

/// The `flags` value every v1 record that carries one holds.
pub const FLAGS_V1: u16 = 0x0000;
/// The `reserved` value every v1 record that carries one holds.
pub const RESERVED_V1: u16 = 0x0000;

macro_rules! discriminant_enum {
    (
        $(#[$outer:meta])*
        $name:ident : $repr:ty {
            $( $(#[$meta:meta])* $variant:ident = $value:literal; )+
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        #[repr($repr)]
        pub enum $name {
            $( $(#[$meta])* $variant = $value, )+
        }

        impl $name {
            /// Every allocated value, in registry order.
            pub const ALL: &'static [$name] = &[ $( $name::$variant, )+ ];

            /// The encoded discriminant.
            #[must_use]
            pub const fn value(self) -> $repr {
                self as $repr
            }

            /// The variant a discriminant denotes, or `None` when the value is
            /// unallocated.
            ///
            /// An unallocated value is never ignored or forwarded. The caller
            /// converts `None` into the rejection its own record defines.
            #[must_use]
            pub const fn from_value(value: $repr) -> Option<$name> {
                match value {
                    $( $value => Some($name::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

discriminant_enum! {
    /// §15.3: `record_type` inside a `ChurObjectV1` container.
    ///
    /// The value is scoped to the format that carries it: the magic selects the
    /// namespace, and the same byte names a different record in another file.
    ContainerRecordType: u8 {
        /// `ChunkRecordV1`, the 20-byte header of container §8.
        Chunk = 0x01;
        /// `FinalCommitRecordV1`, the 32-byte header of container §11.
        FinalCommit = 0x02;
    }
}

discriminant_enum! {
    /// §15.4: `state` of the vault descriptor.
    VaultState: u8 {
        /// Setup started and has not committed.
        Initializing = 0x01;
        /// The only ordinary openable state.
        Active = 0x02;
        /// A migration is in progress.
        Migrating = 0x03;
        /// A recovery flow is in progress.
        Recovering = 0x04;
        /// Deletion is in progress.
        Deleting = 0x05;
    }
}

discriminant_enum! {
    /// §15.4: `slot_type` of a key-slot descriptor.
    SlotType: u8 {
        /// `PasswordSlotV1`.
        Password = 0x01;
        /// `AndroidKeystoreSlotV1`.
        AndroidKeystore = 0x02;
        /// `AppleKeychainSlotV1`.
        AppleKeychain = 0x03;
        /// `RecoverySlotV1`.
        Recovery = 0x04;
        /// `PeerDeviceSlotV1`, allocated for the future family. It parses and is
        /// never accepted as an unlock method in v1.
        PeerDevice = 0x05;
    }
}

discriminant_enum! {
    /// §15.4: `stream_kind` of the object manifest.
    StreamKind: u8 {
        /// The imported bytes as received. The only kind with no
        /// `source_content_revision`.
        Original = 0x01;
        /// Small thumbnail.
        ThumbnailSmall = 0x02;
        /// Grid preview.
        GridPreview = 0x03;
        /// Screen preview.
        ScreenPreview = 0x04;
        /// Video poster frame.
        VideoPoster = 0x05;
        /// Audio waveform.
        AudioWaveform = 0x06;
        /// OCR text layer.
        OcrText = 0x07;
        /// Face record.
        FaceRecord = 0x08;
        /// Embedding record.
        EmbeddingRecord = 0x09;
        /// An explicit H.264/AAC SDR viewing copy of a video original.
        CompatibleVideo = 0x0a;
        /// Twelve SDR seek thumbnails in a four-by-three JPEG atlas.
        VideoStoryboard = 0x0b;
    }
}

impl StreamKind {
    /// Whether this kind is derived from an original.
    ///
    /// Container §5 makes `source_content_revision` present exactly when the
    /// kind is not [`StreamKind::Original`], so one logical stream has exactly
    /// one manifest encoding.
    #[must_use]
    pub const fn is_derived(self) -> bool {
        !matches!(self, StreamKind::Original)
    }
}

discriminant_enum! {
    /// §15.4: `media_class` of the manifest media properties.
    MediaClass: u8 {
        /// Still image.
        Image = 0x01;
        /// Video.
        Video = 0x02;
        /// Audio.
        Audio = 0x03;
        /// No decodable media dimensions.
        Opaque = 0x04;
    }
}

impl MediaClass {
    /// Whether `pixel_width` and `pixel_height` may be non-zero.
    #[must_use]
    pub const fn has_pixels(self) -> bool {
        matches!(self, MediaClass::Image | MediaClass::Video)
    }

    /// Whether `duration_ms` may be non-zero.
    #[must_use]
    pub const fn has_duration(self) -> bool {
        matches!(self, MediaClass::Video | MediaClass::Audio)
    }
}

discriminant_enum! {
    /// §15.4: `state` of the catalog object row, the lifecycle enum of
    /// `docs/format/CATALOG_SCHEMA_V1.md` §5.1.
    ///
    /// It is a second space from [`VaultState`] and shares no value with it,
    /// which is what makes a reader that confused a vault with an object fail
    /// rather than produce a plausible wrong answer.
    ObjectState: u8 {
        /// The container and final commit are durable and the object is listable.
        Active = 0x01;
        /// Deletion has started and the object is no longer listable, §14.1.
        Deleting = 0x02;
        /// Every object-key envelope is destroyed and a tombstone row exists.
        Tombstoned = 0x03;
        /// A check proved the object unusable and no repair path remains.
        Corrupt = 0x04;
        /// A signed shared-collection delete hides the object while retaining its key for restore.
        SharedDeleted = 0x05;
        /// Locally removed from ordinary scopes; keys and containers remain recoverable.
        Trashed = 0x06;
    }
}

discriminant_enum! {
    /// §15.4: `integrity_summary` of the catalog object row.
    ///
    /// The same vocabulary is what `chur_object_reader_verify_complete` writes
    /// through `out_state`, so the persisted column and the ABI return carry one
    /// set of values. Proven corruption is a lifecycle change and is not a
    /// member of this space.
    IntegritySummary: u8 {
        /// Never verified.
        Unverified = 0x01;
        /// Verification is running.
        Verifying = 0x02;
        /// One or more ranges authenticated.
        RangeVerified = 0x03;
        /// Manifest, every chunk, and the final commit authenticated.
        CompleteVerified = 0x04;
        /// Records are missing.
        Incomplete = 0x05;
        /// Held back from use pending investigation.
        Quarantined = 0x06;
        /// The reader does not support this artifact.
        Unsupported = 0x07;
        /// The artifact must migrate before use.
        MigrationRequired = 0x08;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_three_magics_are_pairwise_distinct_at_bytes_four_to_six() {
        let magics = [MAGIC_OBJECT, MAGIC_VAULT, MAGIC_BACKUP];
        for (index, left) in magics.iter().enumerate() {
            assert_eq!(&left[..4], b"CHUR");
            assert_eq!(left[7], b'1');
            for right in magics.iter().skip(index + 1) {
                assert_ne!(left[4], right[4], "byte 4 alone must separate all three");
                assert_ne!(left[5], right[5]);
                assert_ne!(left[6], right[6]);
            }
        }
    }

    #[test]
    fn zero_is_allocated_in_no_discriminant_namespace() {
        assert!(ContainerRecordType::from_value(0).is_none());
        assert!(VaultState::from_value(0).is_none());
        assert!(SlotType::from_value(0).is_none());
        assert!(StreamKind::from_value(0).is_none());
        assert!(MediaClass::from_value(0).is_none());
        assert!(IntegritySummary::from_value(0).is_none());
    }

    #[test]
    fn the_experiment_reserved_range_is_unallocated() {
        for value in 0xf0..=0xffu8 {
            assert!(ContainerRecordType::from_value(value).is_none());
            assert!(VaultState::from_value(value).is_none());
            assert!(SlotType::from_value(value).is_none());
            assert!(StreamKind::from_value(value).is_none());
            assert!(MediaClass::from_value(value).is_none());
            assert!(IntegritySummary::from_value(value).is_none());
        }
    }

    #[test]
    fn every_namespace_allocates_the_lowest_free_values_without_a_gap() {
        fn ascending<T: Copy>(all: &[T], value: impl Fn(T) -> u8) {
            for (index, entry) in all.iter().enumerate() {
                assert_eq!(value(*entry), u8::try_from(index + 1).unwrap());
            }
        }
        ascending(ContainerRecordType::ALL, ContainerRecordType::value);
        ascending(VaultState::ALL, VaultState::value);
        ascending(SlotType::ALL, SlotType::value);
        ascending(StreamKind::ALL, StreamKind::value);
        ascending(MediaClass::ALL, MediaClass::value);
        ascending(IntegritySummary::ALL, IntegritySummary::value);
    }

    #[test]
    fn only_the_original_stream_kind_is_not_derived() {
        for kind in StreamKind::ALL {
            assert_eq!(kind.is_derived(), *kind != StreamKind::Original);
        }
    }

    #[test]
    fn media_class_property_rules_match_the_manifest_field_list() {
        assert!(MediaClass::Image.has_pixels() && !MediaClass::Image.has_duration());
        assert!(MediaClass::Video.has_pixels() && MediaClass::Video.has_duration());
        assert!(!MediaClass::Audio.has_pixels() && MediaClass::Audio.has_duration());
        assert!(!MediaClass::Opaque.has_pixels() && !MediaClass::Opaque.has_duration());
    }
}
