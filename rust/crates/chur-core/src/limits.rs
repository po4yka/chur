//! Parser limits, gathered from the specification that owns each one.
//!
//! `docs/adr/0020-set-the-v1-parser-limits.md` requires every v1 parser to
//! reject an out-of-range declared value before it allocates or derives. The
//! constants live in one module so a bound cannot be written twice with two
//! values, and each carries the section that owns it.
//!
//! A constant here never invents a bound. If a value disagrees with its cited
//! section, the section is right and this module is a defect.

/// Length of every Chur identifier, `docs/format/CANONICAL_ENCODING_V1.md` §8.
pub const ID_LEN: usize = 16;

/// Length of every symmetric key in the v1 hierarchy.
pub const KEY_LEN: usize = 32;

/// Length of a BLAKE3-256 output.
pub const COMMITMENT_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;

/// Length of an AES-GCM nonce, used only by the Android Keystore slot.
pub const GCM_NONCE_LEN: usize = 12;

/// Length of a Poly1305 or GCM authentication tag.
pub const TAG_LEN: usize = 16;

/// Length of a wrapped 32-byte key: the key plus its tag.
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Eight-byte magic shared prefix, `docs/format/CANONICAL_ENCODING_V1.md` §15.1.
pub const MAGIC_LEN: usize = 8;

/// Limits of `docs/format/OBJECT_CONTAINER_V1.md` §16.
pub mod container {
    /// Exact length of `PublicPreambleV1`, §3.
    pub const PREAMBLE_LEN: usize = 28;
    /// Smallest accepted `manifest_record_length`, §3.
    pub const MANIFEST_RECORD_MIN: u32 = 40;
    /// Largest accepted `manifest_record_length`, §3.
    pub const MANIFEST_RECORD_MAX: u32 = 65_536;
    /// Exact length of `CanonicalManifest` for an original stream, §5.
    pub const CANONICAL_MANIFEST_ORIGINAL_LEN: usize = 85;
    /// Exact length of `CanonicalManifest` for a derived stream, §5.
    pub const CANONICAL_MANIFEST_DERIVED_LEN: usize = 89;
    /// Exact length of the `ChunkRecordV1` header, §8.
    pub const CHUNK_HEADER_LEN: usize = 20;
    /// Exact length of the `FinalCommitRecordV1` header, §11.
    pub const COMMIT_HEADER_LEN: usize = 32;
    /// Exact length of `CanonicalFinalCommit`, §11.
    pub const CANONICAL_FINAL_COMMIT_LEN: usize = 128;
    /// Smallest accepted `commit_ciphertext_length`, §11.
    pub const COMMIT_CIPHERTEXT_MIN: u32 = 16;
    /// Largest accepted `commit_ciphertext_length`, §11.
    pub const COMMIT_CIPHERTEXT_MAX: u32 = 4_096;
    /// Smallest accepted `chunk_size`, 64 KiB, §16.
    pub const CHUNK_SIZE_MIN: u32 = 65_536;
    /// Largest accepted `chunk_size`, 8 MiB, §16.
    pub const CHUNK_SIZE_MAX: u32 = 8_388_608;
    /// Required whole multiple of every `chunk_size`, §16.
    pub const CHUNK_SIZE_MULTIPLE: u32 = 4_096;
    /// Largest accepted `chunk_count`, §16.
    pub const CHUNK_COUNT_MAX: u64 = 1_048_576;
    /// Largest accepted `total_plaintext_length`, 1 TiB, §16.
    pub const TOTAL_PLAINTEXT_MAX: u64 = 1_099_511_627_776;
    /// Peak container buffer: one chunk plaintext plus one chunk ciphertext, §16.
    pub const MAX_BUFFER: usize = 16_777_232;
}

/// Limits of `docs/format/OBJECT_KEY_ENVELOPE_V1.md` §10 and
/// `docs/format/COLLECTION_KEY_ENVELOPE_V1.md` §9.
pub mod envelope {
    /// Exact length of `ObjectKeyEnvelopeV1`.
    pub const OBJECT_KEY_ENVELOPE_LEN: usize = 142;
    /// Exact length of `CollectionKeyEnvelopeV1`.
    pub const COLLECTION_KEY_ENVELOPE_LEN: usize = 126;
    /// Envelopes retained per object, `docs/format/CATALOG_SCHEMA_V1.md` §21.
    pub const MAX_PER_OBJECT: u32 = 64;
    /// Envelopes active at once per object.
    pub const MAX_ACTIVE_PER_OBJECT: u32 = 4;
    /// Envelopes per collection epoch.
    pub const MAX_PER_COLLECTION_EPOCH: u32 = 8;
    /// Collections per vault.
    pub const MAX_COLLECTIONS_PER_VAULT: u32 = 1_024;
}

/// Limits of `docs/format/VAULT_DESCRIPTOR_V1.md` §13.
pub mod descriptor {
    /// Exact length of the public head, §2.1.
    pub const HEAD_LEN: usize = 40;
    /// Smallest accepted `descriptor_length`.
    pub const LENGTH_MIN: u32 = 220;
    /// Largest accepted `descriptor_length`.
    pub const LENGTH_MAX: u32 = 65_536;
    /// Exact length of the catalog descriptor, §5.
    pub const CATALOG_DESCRIPTOR_LEN: usize = 60;
    /// Exact length of the object-store descriptor, §6.
    pub const OBJECT_STORE_DESCRIPTOR_LEN: usize = 24;
    /// Exact length of the key-slot descriptor header, §7.
    pub const SLOT_HEADER_LEN: usize = 34;
    /// Exact length of `MigrationDescriptorV1` when present, §2.2.
    pub const MIGRATION_DESCRIPTOR_LEN: usize = 32;
    /// Exact length of the trailing `descriptor_authentication` tag, §8.
    pub const AUTH_TAG_LEN: usize = 32;
    /// Smallest accepted key-slot count.
    pub const SLOT_COUNT_MIN: u32 = 1;
    /// Largest accepted key-slot count.
    pub const SLOT_COUNT_MAX: u32 = 16;
    /// Entries the vault registry holds, §11.
    pub const REGISTRY_MAX_ENTRIES: usize = 2;
}

/// Limits of `docs/format/KEY_SLOT_BODIES_V1.md` §8.
pub mod slot {
    /// Smallest accepted `slot_body_length`.
    pub const BODY_MIN: u32 = 16;
    /// Largest accepted `slot_body_length`.
    pub const BODY_MAX: u32 = 4_096;
    /// Largest accepted total of every slot body in one descriptor.
    pub const BODY_TOTAL_MAX: u32 = 16_384;
    /// Smallest accepted Argon2id salt length.
    pub const SALT_MIN: u32 = 16;
    /// Largest accepted Argon2id salt length.
    pub const SALT_MAX: u32 = 32;
    /// Salt length a v1 writer produces.
    pub const SALT_DEFAULT: u32 = 16;
    /// Smallest accepted Android Keystore alias length.
    pub const ALIAS_MIN: u32 = 16;
    /// Largest accepted Android Keystore alias length.
    pub const ALIAS_MAX: u32 = 64;
    /// Password slots one descriptor may declare,
    /// `docs/security/KEY_SLOTS.md` §11.
    pub const MAX_PASSWORD_SLOT_IDENTITIES: usize = 1;
    /// Argon2id derivations one password unlock attempt runs,
    /// `docs/security/KEY_SLOTS.md` §8.
    pub const PASSWORD_CANDIDATES_PER_ATTEMPT: usize = 2;
}

/// Password and Argon2id bounds, `docs/CRYPTOGRAPHY.md` §17 and §18.3 and
/// `docs/security/PASSWORD_PROFILE.md` §4.
pub mod password {
    /// Smallest accepted encoded password, `docs/CRYPTOGRAPHY.md` §17.
    ///
    /// It applies to every password a slot is opened with, so an existing
    /// slot with a short password still opens.
    pub const ENCODED_MIN: usize = 1;
    /// Fewest Unicode scalar values a new or changed password slot accepts,
    /// `docs/security/PASSWORD_PROFILE.md` §3. A 12-digit PIN meets it.
    pub const NEW_MIN_CHARS: usize = 12;
    /// Largest accepted encoded password, `docs/CRYPTOGRAPHY.md` §17.
    pub const ENCODED_MAX: usize = 1_024;
    /// Frozen memory floor in KiB, also the v1 default, `PASSWORD_PROFILE.md` §4.
    pub const MEMORY_FLOOR_KIB: u32 = 65_536;
    /// Largest memory cost a v1 parser accepts, in KiB, `CRYPTOGRAPHY.md` §18.3.
    pub const MEMORY_MAX_KIB: u32 = 524_288;
    /// Frozen iteration floor, also the v1 default.
    pub const ITERATIONS_FLOOR: u32 = 3;
    /// Largest iteration count a v1 parser accepts.
    pub const ITERATIONS_MAX: u32 = 10;
    /// Smallest accepted parallelism, also the v1 default.
    pub const PARALLELISM_MIN: u32 = 1;
    /// Largest accepted parallelism.
    pub const PARALLELISM_MAX: u32 = 4;
    /// Required Argon2 output length.
    pub const OUTPUT_LEN: usize = 32;
}

/// Catalog policy bounds, `docs/format/CATALOG_SCHEMA_V1.md` §21.
///
/// These are catalog policy rather than encoded field widths, so raising one is
/// a `catalog_format_version` change only when it changes a stored width.
pub mod catalog {
    /// Largest number of media objects in one vault.
    pub const OBJECTS_MAX: u64 = 1_000_000;
    /// Largest number of streams on one object: one original and 15 derived.
    pub const STREAMS_PER_OBJECT_MAX: u32 = 16;
    /// Largest number of derived streams on one object.
    pub const DERIVED_STREAMS_PER_OBJECT_MAX: u32 = STREAMS_PER_OBJECT_MAX - 1;
    /// Largest number of security collections in one vault.
    pub const COLLECTIONS_MAX: u64 = 1_024;
    /// Largest number of object-key envelopes on one object.
    pub const OBJECT_ENVELOPES_MAX: u32 = 64;
    /// Largest number of object-key envelopes active at once on one object.
    pub const OBJECT_ENVELOPES_ACTIVE_MAX: u32 = 4;
    /// Largest number of collection-key envelopes in one collection epoch.
    pub const COLLECTION_ENVELOPES_MAX: u32 = 8;
    /// Largest number of collection-key envelopes active at once in one epoch.
    pub const COLLECTION_ENVELOPES_ACTIVE_MAX: u32 = 1;
    /// Largest number of albums in one vault.
    pub const ALBUMS_MAX: u64 = 10_000;
    /// Largest number of memberships in one album.
    pub const ALBUM_MEMBERSHIPS_MAX: u64 = 100_000;
    /// Largest number of tags in one vault.
    pub const TAGS_MAX: u64 = 10_000;
    /// Largest number of tags on one object.
    pub const TAGS_PER_OBJECT_MAX: u32 = 128;
    /// Largest number of metadata revisions on one object.
    pub const METADATA_REVISIONS_MAX: u32 = 1_024;
    /// Largest number of concurrent import transactions.
    pub const IMPORT_TRANSACTIONS_MAX: u32 = 128;

    /// Smallest accepted page `limit`, `docs/format/CATALOG_SCHEMA_V1.md` §16.2.
    pub const QUERY_LIMIT_MIN: u32 = 1;
    /// Largest accepted page `limit`, §16.2.
    pub const QUERY_LIMIT_MAX: u32 = 500;
    /// Page `limit` a caller that names none receives, §16.2.
    pub const QUERY_LIMIT_DEFAULT: u32 = 200;
    /// Exact length of `ObjectProjectionV1`, §16.1.
    pub const PROJECTION_LEN: usize = 16 + 16 + 2 + 8 + 8 + 1 + 8 + 4 + 4 + 8 + 1 + 1 + 1 + 1;
    /// Exact length of an encoded page cursor, §16.2.
    ///
    /// It is the ordering key, a sort value and an object ID, plus the sort and
    /// scope the cursor was issued under, which is what makes a cursor carried
    /// into a different scope detectable rather than silently valid.
    pub const CURSOR_LEN: usize = 8 + super::ID_LEN + 1 + 1 + super::ID_LEN;

    /// Longest album name the catalog accepts, in bytes,
    /// `docs/format/CATALOG_SCHEMA_V1.md` §21. The sync protocol's canonical
    /// payloads bound an album name at 4096 bytes, so the catalog accepts the
    /// same bound and a replicated name always fits.
    pub const ALBUM_NAME_MAX: usize = 4_096;
    /// Longest tag name the catalog accepts, in bytes,
    /// `docs/format/CATALOG_SCHEMA_V1.md` §21; the sync payload bound again.
    pub const TAG_NAME_MAX: usize = 4_096;
    /// Longest search query the catalog accepts, in bytes,
    /// `docs/format/CATALOG_SCHEMA_V1.md` §21.
    pub const SEARCH_TERMS_MAX: usize = 512;
}

/// Media pipeline bounds, `docs/interop/MEDIA_PIPELINE.md` §12.
/// The portable backup package, `docs/format/BACKUP_FORMAT_V1.md` §13.
pub mod backup {
    /// Fewest records one package holds: the manifest and the final commit.
    pub const RECORD_COUNT_MIN: u64 = 2;
    /// Most records one package holds.
    pub const RECORD_COUNT_MAX: u64 = 1_048_576;
    /// Most records one version 2 package holds: the v1 bound plus the most
    /// catalog export records, ADR-0068.
    pub const RECORD_COUNT_MAX_V2: u64 = RECORD_COUNT_MAX + CATALOG_EXPORT_RECORDS_MAX;
    /// Most catalog export records one version 2 package carries.
    pub const CATALOG_EXPORT_RECORDS_MAX: u64 = 65_536;
    /// The plaintext of every catalog export record but the last, 1 MiB.
    pub const CATALOG_EXPORT_CHUNK_LEN: usize = 1_048_576;
    /// Largest catalog export record payload: nonce, full chunk, and tag.
    pub const CATALOG_EXPORT_PAYLOAD_MAX: u64 =
        (super::NONCE_LEN + CATALOG_EXPORT_CHUNK_LEN + super::TAG_LEN) as u64;
    /// Most tables one catalog export carries.
    pub const CATALOG_EXPORT_TABLES_MAX: u32 = 256;
    /// Most columns one exported table carries.
    pub const CATALOG_EXPORT_COLUMNS_MAX: u16 = 64;
    /// Longest table or column name in a catalog export, in bytes.
    pub const CATALOG_EXPORT_NAME_MAX: u32 = 64;
    /// Longest text or blob value in a catalog export, 16 MiB.
    pub const CATALOG_EXPORT_VALUE_MAX: u32 = 16_777_216;
    /// Most text and blob bytes one exported row holds together, 32 MiB.
    ///
    /// The largest catalog value is an 8 MiB note attachment, so the bound
    /// leaves room for every row the schema admits and stops a forged stream
    /// from making one row of 64 columns hold 1 GiB.
    pub const CATALOG_EXPORT_ROW_MAX: u64 = 33_554_432;
    /// Most stream inventory entries one package carries.
    pub const STREAM_ENTRIES_MAX: usize = 1_048_576;
    /// Most slot inventory entries one package carries.
    pub const SLOT_ENTRIES_MAX: usize = 16;
    /// Largest backup manifest record payload, 16 MiB.
    pub const MANIFEST_PAYLOAD_MAX: usize = 16_777_216;
    /// Free space a restore requires beyond the package length, 64 MiB.
    pub const RESTORE_HEADROOM: u64 = 67_108_864;
}

/// Sync operation bounds, `docs/sync/OPERATION_LOG.md` §4 and §12.
pub mod sync {
    /// Active devices in one vault, so every active device can observe all others.
    pub const ACTIVE_DEVICES_MAX: usize = OBSERVED_HEADS_MAX + 1;
    /// Other-device heads one operation may observe.
    pub const OBSERVED_HEADS_MAX: usize = 31;
    /// Exact encoded length of one observed head.
    pub const OBSERVED_HEAD_LEN: usize = super::ID_LEN + 8;
    /// Cross-vault heads one collection operation may observe.
    pub const COLLECTION_OBSERVED_HEADS_MAX: usize = 287;
    /// Exact encoded length of one cross-vault observed head.
    pub const COLLECTION_OBSERVED_HEAD_LEN: usize = (super::ID_LEN * 2) + 8;
    /// Active external recipient devices in one collection.
    pub const COLLECTION_RECIPIENT_DEVICES_MAX: usize = 256;
    /// Device heads one signed checkpoint may carry, including its issuer.
    pub const CHECKPOINT_HEADS_MAX: usize = OBSERVED_HEADS_MAX + 1;
    /// Exact encoded length of one checkpoint head.
    pub const CHECKPOINT_HEAD_LEN: usize = super::ID_LEN + 8 + super::COMMITMENT_LEN;
    /// Smallest sealed payload: one nonce and one authentication tag.
    pub const ENCRYPTED_PAYLOAD_MIN: usize = super::NONCE_LEN + super::TAG_LEN;
    /// Largest logical operation plaintext, 1 MiB.
    pub const PAYLOAD_PLAINTEXT_MAX: usize = 1_048_576;
    /// Largest sealed payload field.
    pub const ENCRYPTED_PAYLOAD_MAX: usize =
        super::NONCE_LEN + PAYLOAD_PLAINTEXT_MAX + super::TAG_LEN;
    /// Operations accepted in one response.
    pub const RESPONSE_OPERATIONS_MAX: usize = 256;
    /// Operation bytes accepted in one response, 16 MiB.
    pub const RESPONSE_BYTES_MAX: usize = 16_777_216;
    /// Opaque records retained per locked vault.
    pub const STAGED_RECORDS_MAX: usize = 4_096;
    /// Opaque bytes retained per locked vault, 64 MiB.
    pub const STAGED_BYTES_MAX: u64 = 67_108_864;
    /// Local retention of one unacknowledged staged record, seven days.
    pub const STAGED_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
}

/// The media pipeline, `docs/interop/MEDIA_PIPELINE.md` §12.
pub mod media {
    /// Largest accepted still-image edge, in pixels.
    pub const IMAGE_EDGE_MAX: u32 = 16_384;
    /// Largest accepted still-image area, in pixels.
    pub const IMAGE_AREA_MAX: u64 = 67_108_864;
    /// Largest accepted video width, in pixels.
    pub const VIDEO_WIDTH_MAX: u32 = 7_680;
    /// Largest accepted video height, in pixels.
    pub const VIDEO_HEIGHT_MAX: u32 = 4_320;
    /// Largest accepted track count in one video.
    pub const VIDEO_TRACKS_MAX: u32 = 8;
    /// Largest accepted duration, four hours in milliseconds.
    pub const DURATION_MS_MAX: u64 = 14_400_000;
    /// Largest number of fields in one metadata revision.
    pub const METADATA_FIELDS_MAX: u32 = 128;
    /// Largest single metadata field value, in bytes.
    pub const METADATA_FIELD_VALUE_MAX: usize = 8_192;
    /// Largest whole metadata revision, in bytes.
    pub const METADATA_REVISION_MAX: usize = 65_536;
    /// Long-edge target of the small thumbnail, in pixels.
    pub const THUMBNAIL_SMALL_EDGE: u32 = 320;
    /// Long-edge target of the grid preview, in pixels.
    pub const GRID_PREVIEW_EDGE: u32 = 640;
    /// Long-edge target of the screen preview, in pixels.
    pub const SCREEN_PREVIEW_EDGE: u32 = 2_048;
    /// Long-edge target of the video poster frame, in pixels.
    pub const VIDEO_POSTER_EDGE: u32 = 2_048;
    /// Largest bucket count in one audio waveform record,
    /// `docs/interop/MEDIA_PIPELINE.md` §6.1.
    ///
    /// A four-hour recording at this count is one bucket every 3.5 seconds,
    /// which is finer than a scrubber can draw on any supported screen. The
    /// bound exists because §12 gives a waveform no pixel edge, so without it
    /// nothing would bound the record at all.
    pub const WAVEFORM_BUCKETS_MAX: usize = 4_096;
    /// Largest whole audio waveform record, in bytes.
    pub const WAVEFORM_BYTES_MAX: usize = 8 + WAVEFORM_BUCKETS_MAX;
    /// Largest total decode and import buffer in flight per import, 256 MiB.
    pub const IMPORT_BUFFER_MAX: u64 = 268_435_456;
    /// Wall-clock budget of one derivative generation, in milliseconds.
    pub const DERIVATIVE_TIMEOUT_MS: u64 = 30_000;
    /// Longest IANA media type the content-info record carries, without the
    /// terminator, `docs/interop/FFI_CONTRACT.md` §6.1.
    pub const CONTENT_TYPE_MAX: usize = 63;
}

/// Plaintext scratch caps, `docs/security/PLAINTEXT_LIFECYCLE.md` §5.
///
/// Every cap is checked before the first plaintext byte is written. Exceeding
/// one fails the operation; nothing is truncated and no entry is evicted.
pub mod scratch {
    /// Largest single scratch entry, 4 GiB.
    pub const ENTRY_MAX: u64 = 4 * 1_073_741_824;
    /// Largest number of scratch entries alive at once.
    pub const ENTRIES_MAX: u32 = 4;
    /// Largest total scratch directory, 8 GiB.
    pub const DIRECTORY_MAX: u64 = 8 * 1_073_741_824;
    /// Longest an entry survives while a consumer holds it, 30 minutes.
    pub const HOLD_MS_MAX: u64 = 1_800_000;
}

// Compile-time consistency checks. A limit that contradicts another limit is a
// defect in this module, not a runtime condition, so it fails the build.

// §16: the two §6 chunk-size candidates are inside the accepted range and are
// whole multiples of 4096.
const _: () = assert!(262_144 >= container::CHUNK_SIZE_MIN);
const _: () = assert!(262_144 <= container::CHUNK_SIZE_MAX);
const _: () = assert!(262_144 % container::CHUNK_SIZE_MULTIPLE == 0);
const _: () = assert!(1_048_576 >= container::CHUNK_SIZE_MIN);
const _: () = assert!(1_048_576 <= container::CHUNK_SIZE_MAX);
const _: () = assert!(1_048_576 % container::CHUNK_SIZE_MULTIPLE == 0);

// §16: the peak container buffer is one chunk plaintext plus one chunk
// ciphertext at the largest accepted chunk size.
const _: () =
    assert!(2 * container::CHUNK_SIZE_MAX as u64 + TAG_LEN as u64 == container::MAX_BUFFER as u64);

// §16: at the 1 MiB candidate, the maximum chunk count covers the maximum
// plaintext length exactly.
const _: () = assert!(container::CHUNK_COUNT_MAX * 1_048_576 == container::TOTAL_PLAINTEXT_MAX);

// `docs/format/VAULT_DESCRIPTOR_V1.md` §13: the smallest descriptor is the
// 40-byte head, a 148-byte body holding one key-slot descriptor whose body is
// the 16-byte minimum and an absent migration descriptor, and the 32-byte tag.
const SMALLEST_DESCRIPTOR_BODY: usize = 8
    + 1
    + descriptor::CATALOG_DESCRIPTOR_LEN
    + descriptor::OBJECT_STORE_DESCRIPTOR_LEN
    + 4
    + descriptor::SLOT_HEADER_LEN
    + slot::BODY_MIN as usize
    + 1;
const _: () = assert!(SMALLEST_DESCRIPTOR_BODY == 148);
const _: () = assert!(
    (descriptor::HEAD_LEN + SMALLEST_DESCRIPTOR_BODY + descriptor::AUTH_TAG_LEN) as u32
        == descriptor::LENGTH_MIN
);

// `docs/CRYPTOGRAPHY.md` §18.3: the frozen Argon2id floor is inside the bounds a
// v1 parser accepts, and the output length is one symmetric key.
const _: () = assert!(password::MEMORY_FLOOR_KIB <= password::MEMORY_MAX_KIB);
const _: () = assert!(password::ITERATIONS_FLOOR <= password::ITERATIONS_MAX);
const _: () = assert!(password::PARALLELISM_MIN <= password::PARALLELISM_MAX);
const _: () = assert!(password::OUTPUT_LEN == KEY_LEN);

// `docs/format/KEY_SLOT_BODIES_V1.md` §8: every family body fits the descriptor
// bound, and the salt a v1 writer produces is inside the accepted range.
const _: () = assert!(slot::SALT_DEFAULT >= slot::SALT_MIN);
const _: () = assert!(slot::SALT_DEFAULT <= slot::SALT_MAX);
const _: () = assert!(92 + slot::SALT_MAX <= slot::BODY_MAX);
const _: () = assert!(66 + slot::ALIAS_MAX <= slot::BODY_MAX);
const _: () = assert!(74 >= slot::BODY_MIN);
const _: () = assert!(90 >= slot::BODY_MIN);

// `docs/format/CATALOG_SCHEMA_V1.md` §16.1: the projection is the fixed 79-byte
// shape the FFI page buffer of `docs/interop/FFI_CONTRACT.md` §6.2 is sized on,
// and a full page fits a bounded buffer.
const _: () = assert!(catalog::PROJECTION_LEN == 79);
const _: () = assert!(catalog::CURSOR_LEN == 42);
const _: () = assert!(catalog::QUERY_LIMIT_DEFAULT <= catalog::QUERY_LIMIT_MAX);
const _: () = assert!(catalog::QUERY_LIMIT_MIN <= catalog::QUERY_LIMIT_DEFAULT);
const _: () = assert!(catalog::QUERY_LIMIT_MAX as usize * catalog::PROJECTION_LEN == 39_500);

// §21: one original plus the derived streams is the whole per-object budget, and
// the nine derived-asset kinds of §15.4 fit inside it.
const _: () =
    assert!(catalog::DERIVED_STREAMS_PER_OBJECT_MAX + 1 == catalog::STREAMS_PER_OBJECT_MAX);
const _: () = assert!(catalog::OBJECT_ENVELOPES_ACTIVE_MAX <= catalog::OBJECT_ENVELOPES_MAX);
const _: () =
    assert!(catalog::COLLECTION_ENVELOPES_ACTIVE_MAX <= catalog::COLLECTION_ENVELOPES_MAX);

// `docs/interop/MEDIA_PIPELINE.md` §12: the derivative long edges are ordered,
// and the largest still image a decoder is offered fits the area bound.
const _: () = assert!(media::THUMBNAIL_SMALL_EDGE < media::GRID_PREVIEW_EDGE);
const _: () = assert!(media::GRID_PREVIEW_EDGE < media::SCREEN_PREVIEW_EDGE);
const _: () = assert!(media::SCREEN_PREVIEW_EDGE <= media::IMAGE_EDGE_MAX);
const _: () =
    assert!(media::IMAGE_EDGE_MAX as u64 * media::IMAGE_EDGE_MAX as u64 > media::IMAGE_AREA_MAX);
const _: () = assert!(media::METADATA_REVISION_MAX <= container::MANIFEST_RECORD_MAX as usize);

// `docs/security/PLAINTEXT_LIFECYCLE.md` §5: the whole directory holds the
// maximum number of maximum-size entries, and one entry sits far below the
// 1 TiB object bound of `docs/format/OBJECT_CONTAINER_V1.md` §16, which is why
// a large object has no scratch path at all.
const _: () = assert!(scratch::ENTRY_MAX * scratch::ENTRIES_MAX as u64 >= scratch::DIRECTORY_MAX);
const _: () = assert!(scratch::ENTRY_MAX < container::TOTAL_PLAINTEXT_MAX);
