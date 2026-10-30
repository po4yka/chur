# Canonical Encoding v1

> **Status:** Proposed normative binary profile; §15 allocates the v1 constant values, and domain tags for records whose AAD is not yet frozen remain outstanding

Canonical encoding ensures that authenticated, signed, hashed, or key-derived structures have exactly one byte representation. General serializer defaults are not protocol definitions.

## 1. Scope

This profile applies to:

- key-slot AAD and descriptors;
- vault descriptors;
- collection and object-key envelopes;
- object manifests, chunk AAD, and final commits;
- backup manifests;
- sync operations, signatures, and collection grants;
- deterministic test vectors.

It does not require UI/domain models to use the same in-memory representation.

## 2. Primitive rules

| Type | Encoding |
| --- | --- |
| `u8` | one byte |
| `u16` | unsigned, fixed-width, big-endian |
| `u32` | unsigned, fixed-width, big-endian |
| `u64` | unsigned, fixed-width, big-endian |
| boolean | one byte: `0x00` false, `0x01` true |
| fixed bytes | exact declared length, no prefix |
| variable bytes | `u32` length followed by bytes |
| UTF-8 string | `u32` byte length followed by strict UTF-8 |
| enum | fixed-width numeric discriminant defined by owning spec |
| optional | one presence byte: `0x00` absent and nothing follows, `0x01` present and the value follows |
| list | `u32` count followed by elements in order |

Signed integers and floating-point values are forbidden in v1 cryptographic records unless a focused specification defines their canonical representation.

## 3. Strings

- strict UTF-8 only;
- no implicit Unicode normalization;
- no NUL termination;
- length counts encoded bytes, not characters;
- invalid UTF-8 is rejected;
- application text fields may define separate normalization/search behavior after decryption;
- protocol labels are fixed ASCII byte constants.

## 4. Structures

A structure is encoded as fields in the exact order listed by its owning versioned specification. Field names are not encoded unless the specification explicitly defines tagged extensibility.

Example conceptual encoding, illustrative and not a registered record:

```text
ExampleRecordV1 =
    format_version:u16
    suite_id:u16
    object_id:bytes[16]
    envelope_generation:u64
```

The element list of a registered authenticated structure is written by the specification that owns the record, never here. The object-key envelope AAD is [`OBJECT_KEY_ENVELOPE_V1.md`](OBJECT_KEY_ENVELOPE_V1.md) §3 and the collection-key envelope AAD is [`COLLECTION_KEY_ENVELOPE_V1.md`](COLLECTION_KEY_ENVELOPE_V1.md) §3.

Concatenation without a schema is forbidden. The decoder must know the exact structure/version before parsing.

## 5. Maps and unordered collections

Maps are forbidden in signed/AAD structures by default. A specification that requires a map must define:

- allowed key type;
- canonical key-byte ordering;
- duplicate-key rejection;
- maximum count;
- whether unknown keys are rejected.

Sets are encoded as sorted unique lists. The default comparator is ascending lexicographic byte order over the canonical encoding of each element, comparing byte by byte and treating the shorter sequence as smaller when it is a prefix of the longer one. A specification may name a different comparator only by defining it in full; it may not leave one implied. Duplicate elements are rejected as non-canonical.

## 6. Tagged extension records

If a future structure uses tagged fields:

```text
field_tag:u16
field_length:u32
field_value:bytes
```

Rules:

- fields sorted by strictly increasing tag;
- duplicate tags rejected;
- required tags explicitly listed;
- unknown critical tags rejected;
- unknown non-critical tags may be preserved only if the owning spec permits forwarding;
- length must fit parser limits before allocation;
- canonical re-encoding must reproduce the same bytes.

Core v1 security records should prefer fixed schemas over extensible tagged maps.

## 7. Domain tags and canonical tuples

Every authenticated or signed record begins logically with a unique fixed domain tag, for example:

```text
CHUR\x00SLOT\x00PASSWORD\x00V1
CHUR\x00OBJECT\x00CHUNK-AAD\x00V1
CHUR\x00SYNC\x00OPERATION\x00V1
```

A domain tag is a bare ASCII byte constant. It is encoded as its exact registered bytes, with no length prefix, no terminator, and no trailing NUL. It is a fixed-bytes value under §2, not a UTF-8 string under §3; the `\x00` bytes shown above are separators inside the constant itself.

Exact tags are allocated in §15.5 and included in test vectors. A tag must never be reused for a different structure, and no registered tag may be a byte prefix of another registered tag. A version suffix past `V9` must not extend an existing tag, because `V1` is a byte prefix of `V10`.

### 7.1 Canonical tuples

`CanonicalTuple(tag, element, ...)`, as written in [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), is not a separate construct. It names a §4 structure whose first field is a domain tag, and it adds no framing of its own: no element count, no separate schema-version field, no separator between elements, and no terminator. The version suffix in the tag is the tuple's schema version.

Each element after the tag is one primitive from §2, encoded by the rule for its declared type. The specification that owns the record declares the element list in order, with the type and width of every element. A group of related values, such as the Argon2 public parameters of a password slot, is not one element; it is written as one element per value.

For an illustrative tuple, not a registered one:

```text
CanonicalTuple(
    "CHUR\x00EXAMPLE\x00TUPLE\x00V1",
    suite_id:u16,
    object_id:bytes[16],
    label:string
)
```

encodes as:

```text
43 48 55 52 00 45 58 41 4D 50 4C 45 00 54 55 50 4C 45 00 56 31  tag, 21 bytes, no prefix
2 bytes                                                          suite_id, big-endian
16 bytes                                                         object_id, no length prefix
4 bytes                                                          label byte length, u32 big-endian
label byte length bytes                                          label, strict UTF-8
```

A fixed-length element carries no prefix and a variable-length element carries its `u32` length, so the two are never confusable: the tag selects exactly one element list, and that list fixes the width of every fixed-length element and the position of every length prefix. Because no registered tag is a byte prefix of another, the tag is recoverable from the leading bytes, so two distinct tuples never encode to the same bytes.

One exception is defined: a tuple may delegate the rest of its element list to a registered label carried as its second field. The label is then a §2 UTF-8 string and its registry entry fixes the remaining elements. `CHUR\x00KDF\x00INFO\x00V1` is the only such tuple in v1, and its labels are registered in [`../security/KEY_HIERARCHY.md`](../security/KEY_HIERARCHY.md) §3. Tag plus label still selects exactly one element list, so the collision argument above holds unchanged.

Tuple bytes are produced, not parsed. They are AEAD additional authenticated data, HKDF `info`, or hash input, so a mismatch surfaces as an authentication failure rather than as a decode error. Nested tuples and nested structures are forbidden in v1 tuples.

A hash input that a byte-exact specification defines directly, such as the commitments in [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §5 and §10, is a domain tag followed by declared record bytes. It is not a canonical tuple and this subsection does not apply to it.

## 8. Identifiers

V1 identifiers are proposed as 16 random bytes, encoded exactly as bytes rather than textual UUID. Text rendering is presentation only and must not re-enter authenticated bytes.

Identifier all-zero value is reserved as invalid unless a focused spec says otherwise.

## 9. Time

Cryptographic records should avoid wall-clock time when monotonic counters or revisions suffice. When required, v1 uses:

```text
u64 whole milliseconds since Unix epoch UTC
```

Values are metadata, not trusted ordering proof. Negative times and timezone offsets are forbidden in canonical records.

## 10. Length and allocation limits

Each focused specification defines maximums. General decoder requirements:

- use checked arithmetic;
- validate count × element-size before allocation;
- reject trailing bytes unless explicitly permitted;
- reject truncated fields;
- reject lengths larger than remaining input;
- limit nesting depth;
- limit unknown extension bytes;
- never run Argon2 or allocate media buffers based on unchecked values.

## 11. Canonicality

A decoder for authenticated bytes must reject:

- alternate integer widths;
- leading padding;
- boolean values other than 0 or 1;
- optional presence bytes other than `0x00` or `0x01`;
- set elements that are out of comparator order;
- non-minimal or duplicate optional fields;
- unordered or duplicate tagged fields;
- invalid UTF-8;
- trailing bytes;
- unknown version/suite where policy disallows it;
- any representation that re-encodes differently.

## 12. Versioning

Encoding profile ID is carried by the containing artifact and holds `0x0001` for this profile, per §15. V1 bytes never change. A new rule requires a new profile/version and migration or dual-reader policy.

Do not add a field to a fixed v1 structure while retaining its version number.

## 13. Rust implementation

The canonical encoder/decoder should be a small Rust-owned crate or module with:

- no generic `serde` format as the authority;
- explicit read/write functions;
- bounded cursor operations;
- checked arithmetic;
- structured non-secret errors;
- property tests that decode→encode is identity for accepted bytes;
- fuzz tests that rejected bytes do not allocate beyond limits.

Kotlin and Swift consume Rust-produced records or vectors; they do not define alternate canonical encoders for private formats.

## 14. Required vectors

- each primitive boundary value;
- empty and maximum-length byte/string/list values;
- invalid UTF-8;
- truncated lengths and trailing bytes;
- duplicate/out-of-order tagged fields;
- all-zero/maximum identifiers;
- cross-platform examples for every owning format;
- non-canonical encodings that must be rejected.

## 15. Constant registry

This section allocates the constant values shared across Chur formats: file magics, version numbers, encoding profile and policy identifiers, suite identifiers, record types, and enumerated discriminants. It records which value is taken and by which format. The owning specification stays authoritative for layout and meaning, and where a byte-exact specification has already frozen a value, that document governs a conflict.

A constant that is local to one record and allocated from no shared namespace stays in its owning specification only. The object container's `flags`, `reserved`, and `public_header_length` are such constants and are not repeated here.

Widths are uniform across v1: format-level version, profile, policy, and suite identifiers are `u16`; per-record type and version bytes, and enumerated discriminants, are `u8`. All are unsigned big-endian per §2. One namespace is then validated the same way in every format.

### 15.1 File magics

A Chur file format begins at offset 0 with an eight-byte ASCII magic whose first four bytes are `CHUR`. The eighth byte is a generation digit that belongs to the magic; it does not replace the typed version field.

| Magic | Bytes | Format | Owner |
| --- | --- | --- | --- |
| `CHUROBJ1` | `43 48 55 52 4F 42 4A 31` | `ChurObjectV1` container | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §3 |
| `CHURVLT1` | `43 48 55 52 56 4C 54 31` | `VaultDescriptorV1` | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §2 |
| `CHURBAK1` | `43 48 55 52 42 41 4B 31` | `BackupPackageV1` | [`BACKUP_FORMAT_V1.md`](BACKUP_FORMAT_V1.md) §2 |

Pairwise distinctness rule: two magics are distinct when they differ in at least one of their eight byte positions. Every magic is exactly eight bytes, so no magic is a prefix of another, and eight bytes read from offset 0 either identify the format or reject the file. A candidate that differs from an allocated magic only in its generation digit is not allocated, because that digit marks a later generation of the same artifact rather than a different artifact.

The three allocated magics satisfy the rule. They share bytes 0 to 3 and byte 7, and differ at every one of bytes 4, 5, and 6:

| Offset | `CHUROBJ1` | `CHURVLT1` | `CHURBAK1` |
| --- | --- | --- | --- |
| 4 | `4F` | `56` | `42` |
| 5 | `42` | `4C` | `41` |
| 6 | `4A` | `54` | `4B` |

Each of the three pairs differs in three byte positions, and byte 4 alone separates all three.

### 15.2 Versions, profiles, and suites

`suite_id`, `catalog_crypto_suite`, and `wrap_suite_id` share one namespace:

| Value | Meaning |
| --- | --- |
| `0x0001` | XChaCha20-Poly1305 for AEAD, BLAKE3-256 for commitments, HKDF-SHA-256 for key derivation |
| `0x0002` | AES-256-GCM key wrapping performed by a platform keystore, valid only as `wrap_suite_id` of an `AndroidKeystoreSlotV1`, [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §5 |

`0x0002` names a wrapping operation rather than a whole suite: it fixes the AEAD of one key slot and nothing else. It is invalid as `suite_id` and as `catalog_crypto_suite`, because no Chur record outside that slot body is sealed by a platform keystore, and a reader that finds it in either field rejects the artifact as `UNSUPPORTED_SUITE`.

`canonical_encoding_profile` and `encoding_profile` share one namespace:

| Value | Meaning |
| --- | --- |
| `0x0001` | canonical encoding v1, §2 to §12 of this document |

Each format version field has its own namespace:

| Field | Value | Format | Owner |
| --- | --- | --- | --- |
| `container_version` | `0x0001` | `ChurObjectV1` | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §3 |
| `container_version` | `0x0002` | `ChurObjectV1` with bucket padding, [ADR-0066](../adr/0066-pad-object-containers-to-size-buckets.md) | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §18 |
| `record_version` | `0x01` | container chunk and final-commit records | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §8, §11 |
| `descriptor_version` | `0x0001` | `VaultDescriptorV1` | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §2 |
| `format_version` | `0x0001` | `ObjectKeyEnvelopeV1` | [`OBJECT_KEY_ENVELOPE_V1.md`](OBJECT_KEY_ENVELOPE_V1.md) §1 |
| `format_version` | `0x0001` | `CollectionKeyEnvelopeV1` | [`COLLECTION_KEY_ENVELOPE_V1.md`](COLLECTION_KEY_ENVELOPE_V1.md) §1 |
| `backup_version` | `0x0001` | `BackupPackageV1` | [`BACKUP_FORMAT_V1.md`](BACKUP_FORMAT_V1.md) §2.1 |
| `backup_version` | `0x0002` | `BackupPackageV1` with a portable catalog export and a record commitment, [ADR-0068](../adr/0068-carry-a-portable-catalog-export-in-backup-v2.md) | [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md) §2 |
| `export_version` | `0x0001` | `CatalogExportV1` | [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md) §3 |
| `catalog_format_version` | `0x0001` | private catalog schema v1 | [`CATALOG_SCHEMA_V1.md`](CATALOG_SCHEMA_V1.md) |
| `catalog_format_version` | `0x0002` | private catalog schema v2 with durable sync state | [`CATALOG_SCHEMA_V2.md`](CATALOG_SCHEMA_V2.md) |
| `catalog_format_version` | `0x0003` | private catalog schema v3 with durable collection-sharing state | [`CATALOG_SCHEMA_V3.md`](CATALOG_SCHEMA_V3.md) |
| `catalog_format_version` | `0x0004` | private catalog schema v4 with durable collection-operation streams | [`CATALOG_SCHEMA_V4.md`](CATALOG_SCHEMA_V4.md) |
| `catalog_format_version` | `0x0005` | private catalog schema v5 with the durable grant-acceptance freeze | [`CATALOG_SCHEMA_V5.md`](CATALOG_SCHEMA_V5.md) |
| `catalog_format_version` | `0x0006` | private catalog schema v6 with an accepted object-operation index | [`CATALOG_SCHEMA_V6.md`](CATALOG_SCHEMA_V6.md) |
| `catalog_format_version` | `0x0007` | private catalog schema v7 with album hierarchy and manual order | [`CATALOG_SCHEMA_V7.md`](CATALOG_SCHEMA_V7.md) |
| `catalog_format_version` | `0x0008` | private catalog schema v8 with recoverable trash | [`CATALOG_SCHEMA_V8.md`](CATALOG_SCHEMA_V8.md) |
| `catalog_format_version` | `0x0009` | private catalog schema v9 with local private notes | [`CATALOG_SCHEMA_V9.md`](CATALOG_SCHEMA_V9.md) |
| `catalog_format_version` | `0x000a` | private catalog schema v10 with encrypted content search | [`CATALOG_SCHEMA_V10.md`](CATALOG_SCHEMA_V10.md) |
| `catalog_format_version` | `0x000b` | private catalog schema v11 with pending album additions | [`CATALOG_SCHEMA_V11.md`](CATALOG_SCHEMA_V11.md) |
| `catalog_format_version` | `0x000c` | private catalog schema v12 with explicit note body format | [`CATALOG_SCHEMA_V12.md`](CATALOG_SCHEMA_V12.md) |
| `catalog_format_version` | `0x000d` | private catalog schema v13 with note-owned encrypted attachments | [`CATALOG_SCHEMA_V13.md`](CATALOG_SCHEMA_V13.md) |
| `catalog_format_version` | `0x000e` | private catalog schema v14 with encrypted note organization and recovery | [`CATALOG_SCHEMA_V14.md`](CATALOG_SCHEMA_V14.md) |
| `catalog_format_version` | `0x000f` | peer-only pairing without network credentials | [`CATALOG_SCHEMA_V15.md`](CATALOG_SCHEMA_V15.md) |
| `catalog_format_version` | `0x0010` | encrypted compatible-video derivative capability | [`CATALOG_SCHEMA_V16.md`](CATALOG_SCHEMA_V16.md) |
| `catalog_format_version` | `0x0011` | encrypted local video resume positions and storyboard capability | [`CATALOG_SCHEMA_V17.md`](CATALOG_SCHEMA_V17.md) |
| `catalog_format_version` | `0x0012` | trusted-time mark for trash and note retention | [`CATALOG_SCHEMA_V18.md`](CATALOG_SCHEMA_V18.md) |
| `object_store_format_version` | `0x0001` | object store layout v1 | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §6 |
| `slot_version` | `0x0001` | v1 key-slot families | [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §1 |

`container_version_floor` and `container_version_ceiling` carry values of the `container_version` namespace; a vault that supports only v1 containers records `0x0001` in both, and a vault that also holds bucket-padded containers records `0x0001` and `0x0002`.

Profile and policy identifiers:

| Field | Value | Meaning | Owner |
| --- | --- | --- | --- |
| `chunk_record_profile` | `0x0001` | chunk record framing of container §8 | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §8 |
| `commitment_profile` | `0x0001` | manifest and ordered chunk commitments of container §5 and §10 | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §5, §10 |
| `crypto_policy_id` | `0x0001` | v1 vault policy: suite `0x0001` for every vault-level record | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §2 |
| `naming_profile_id` | `0x0001` | opaque random store identifiers, no user-derived path names | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §6 |
| `password_profile_id` | `0x0001` | canonical password bytes: strict UTF-8, no normalization | [`../security/PASSWORD_PROFILE.md`](../security/PASSWORD_PROFILE.md) §3 |
| `recovery_profile_id` | `0x0001` | 32-byte recovery secret presented as 24 BIP-39 English words | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §4 |
| `keystore_profile_id` | `0x0001` | non-exportable AES-256-GCM Android Keystore wrapping key | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §5 |
| `keychain_profile_id` | `0x0001` | Keychain-held `DeviceUnlockSecret`, AEAD performed in Rust | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §6 |

Each profile identifier above has its own namespace, and each is `u16` per the width rule of §15.

### 15.3 Record types

`record_type` is scoped to the format that carries it. The same value names different records in different files, and the magic selects the namespace.

Object container, `ChurObjectV1`:

| Value | Record |
| --- | --- |
| `0x01` | `ChunkRecordV1` |
| `0x02` | `FinalCommitRecordV1` |

Backup package, `BackupPackageV1`, over the components of its package model:

| Value | Record |
| --- | --- |
| `0x01` | encrypted backup manifest |
| `0x02` | portable vault descriptor |
| `0x03` | encrypted canonical catalog export |
| `0x04` | object container entry |
| `0x05` | object-key or collection-key envelope entry |
| `0x06` | incremental operation segment |
| `0x07` | final backup commit |

An unallocated `record_type` is a parse failure, never an ignorable record.

### 15.4 Enumerated discriminants

`state` of the vault descriptor, in the order listed by [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §4:

| Value | State |
| --- | --- |
| `0x01` | `INITIALIZING` |
| `0x02` | `ACTIVE` |
| `0x03` | `MIGRATING` |
| `0x04` | `RECOVERING` |
| `0x05` | `DELETING` |

`slot_type`, in the order listed by [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §1:

| Value | Slot family |
| --- | --- |
| `0x01` | `PasswordSlotV1` |
| `0x02` | `AndroidKeystoreSlotV1` |
| `0x03` | `AppleKeychainSlotV1` |
| `0x04` | `RecoverySlotV1` |
| `0x05` | `PeerDeviceSlotV1`, allocated for the future family and not accepted as an unlock method in v1 |

`stream_kind` of the object manifest, [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §5, over the derived-asset kinds of [`../interop/MEDIA_PIPELINE.md`](../interop/MEDIA_PIPELINE.md) §6:

| Value | Stream |
| --- | --- |
| `0x01` | original, the imported bytes as received |
| `0x02` | small thumbnail |
| `0x03` | grid preview |
| `0x04` | screen preview |
| `0x05` | video poster frame |
| `0x06` | audio waveform |
| `0x07` | OCR text layer |
| `0x08` | face record |
| `0x09` | embedding record |
| `0x0a` | compatible video, encrypted H.264/AAC SDR MP4 |
| `0x0b` | video storyboard, encrypted 12-cell SDR JPEG grid |

`0x01` is the only kind whose `source_content_revision` is absent; every other kind is derived from an original. The animated preview of that section is future scope and takes the next free value in the change that freezes it.

`media_class` of the manifest media properties, [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §5.1:

| Value | Class |
| --- | --- |
| `0x01` | still image |
| `0x02` | video |
| `0x03` | audio |
| `0x04` | opaque, no decodable media dimensions |

`state` of the catalog object row, [`CATALOG_SCHEMA_V1.md`](CATALOG_SCHEMA_V1.md) §5.1, in the order listed there:

| Value | Lifecycle |
| --- | --- |
| `0x01` | `ACTIVE` |
| `0x02` | `DELETING` |
| `0x03` | `TOMBSTONED` |
| `0x04` | `CORRUPT` |
| `0x05` | `SHARED_DELETED` |
| `0x06` | `TRASHED` |

This is a second, independent space from the vault-descriptor `state` above. The two share three names and no values, which is deliberate: a vault and an object are different subjects, and a shared numbering would let a reader that confused them produce a plausible wrong answer instead of failing. The object row's value crosses the boundary in the `state` byte of the object projection, [`CATALOG_SCHEMA_V1.md`](CATALOG_SCHEMA_V1.md) §16.1, which is why it is registered here rather than left to the catalog.

`integrity_summary` of the catalog object row, [`CATALOG_SCHEMA_V1.md`](CATALOG_SCHEMA_V1.md) §5.1, in the order listed there:

| Value | Summary |
| --- | --- |
| `0x01` | `UNVERIFIED` |
| `0x02` | `VERIFYING` |
| `0x03` | `RANGE_VERIFIED` |
| `0x04` | `COMPLETE_VERIFIED` |
| `0x05` | `INCOMPLETE` |
| `0x06` | `QUARANTINED` |
| `0x07` | `UNSUPPORTED` |
| `0x08` | `MIGRATION_REQUIRED` |

These are also the values `chur_object_reader_verify_complete` writes through `out_state`, [`../interop/FFI_CONTRACT.md`](../interop/FFI_CONTRACT.md) §6.2, so the persisted column and the ABI return carry one vocabulary. Proven corruption is a lifecycle change rather than a verification verdict, so `CORRUPT` is a value of the object row's `state` and not of this space.

`operation_kind` of `OperationPayloadV1`, in the order frozen by
[`../sync/OPERATION_PAYLOAD_V1.md`](../sync/OPERATION_PAYLOAD_V1.md) §2:

| Value | Kind |
| --- | --- |
| `0x01` | `CreateObject` |
| `0x02` | `CommitObject` |
| `0x03` | `UpdateMetadata` |
| `0x04` | `CreateAlbum` |
| `0x05` | `RenameAlbum` |
| `0x06` | `AddAlbumMembership` |
| `0x07` | `RemoveAlbumMembership` |
| `0x08` | `SetFavorite` |
| `0x09` | `AddTag` |
| `0x0A` | `RemoveTag` |
| `0x0B` | `DeleteObject` |
| `0x0C` | `RestoreObject` |
| `0x0D` | `AddDevice` |
| `0x0E` | `RevokeDevice` |
| `0x0F` | `CreateCollectionEpoch` |
| `0x10` | `RewrapObjectKey` |

`field_id` of `MetadataFieldV1`, from
[`../sync/OPERATION_PAYLOAD_V1.md`](../sync/OPERATION_PAYLOAD_V1.md) §3:

| Value | Field |
| --- | --- |
| `0x0001` | original filename |
| `0x0002` | media type |
| `0x0003` | capture time |
| `0x0004` | caption |
| `0x0005` | rating |

`value_type` of a `CatalogExportV1` value, from [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md) §3:

| Value | Value |
| --- | --- |
| `0x01` | NULL |
| `0x02` | SQLite INTEGER, eight bytes of two's complement |
| `0x03` | strict UTF-8 text |
| `0x04` | blob |

### 15.5 Domain tags

A domain tag is a fixed ASCII byte constant written without a length prefix, per §3 and §7, of the form `CHUR\x00<AREA>\x00<PURPOSE>\x00V<n>`.

| Tag | Use | Owner |
| --- | --- | --- |
| `CHUR\x00KDF\x00INFO\x00V1` | HKDF `info` tuple for every derivation | [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13 |
| `CHUR\x00SLOT\x00PASSWORD\x00V1` | password key-slot AAD | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §3 |
| `CHUR\x00SLOT\x00RECOVERY\x00V1` | recovery key-slot AAD | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §4 |
| `CHUR\x00SLOT\x00ANDROID-KEYSTORE\x00V1` | Android Keystore key-slot AAD | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §5 |
| `CHUR\x00SLOT\x00APPLE-KEYCHAIN\x00V1` | Apple Keychain key-slot AAD | [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §6 |
| `CHUR\x00COLLECTION\x00KEY-ENVELOPE\x00V1` | collection-key envelope AAD | [`COLLECTION_KEY_ENVELOPE_V1.md`](COLLECTION_KEY_ENVELOPE_V1.md) §3 |
| `CHUR\x00OBJECT\x00KEY-ENVELOPE\x00V1` | object-key envelope AAD | [`OBJECT_KEY_ENVELOPE_V1.md`](OBJECT_KEY_ENVELOPE_V1.md) §3 |
| `CHUR\x00OBJECT-PREKEY\x00SIGNATURE\x00V1` | object-bound public key request signature | [`../sync/OBJECT_KEY_GRANTS.md`](../sync/OBJECT_KEY_GRANTS.md) section 1 |
| `CHUR\x00OBJECT-KEY-GRANT\x00SIGNATURE\x00V1` | disposable object-key grant signature | [`../sync/OBJECT_KEY_GRANTS.md`](../sync/OBJECT_KEY_GRANTS.md) section 2 |
| `CHUR\x00OBJECT-KEY-GRANT\x00HPKE\x00V1` | disposable object-key grant HPKE context | [`../sync/OBJECT_KEY_GRANTS.md`](../sync/OBJECT_KEY_GRANTS.md) section 2 |
| `CHUR\x00OBJECT-KEY\x00COMMITMENT\x00V1` | key-free content-key commitment | [`../sync/OBJECT_KEY_GRANTS.md`](../sync/OBJECT_KEY_GRANTS.md) section 2 |
| `CHUR\x00OBJECT\x00MANIFEST-AAD\x00V1` | encrypted manifest AAD | [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §32 |
| `CHUR\x00OBJECT\x00MANIFEST-COMMITMENT\x00V1` | manifest commitment | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §5 |
| `CHUR\x00OBJECT\x00CHUNK-AAD\x00V1` | chunk AAD | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §9 |
| `CHUR\x00OBJECT\x00ORDERED-COMMITMENT\x00V1` | ordered chunk commitment | [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §10 |
| `CHUR\x00OBJECT\x00FINAL-COMMIT-AAD\x00V1` | final-commit AAD | [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §38 |
| `CHUR\x00VAULT\x00DESCRIPTOR-AUTH\x00V1` | vault-descriptor authentication tag | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §8 |
| `CHUR\x00CATALOG\x00HEADER-COMMITMENT\x00V1` | catalog header commitment | [`VAULT_DESCRIPTOR_V1.md`](VAULT_DESCRIPTOR_V1.md) §5 |
| `CHUR\x00PRIVATE-NOTES\x00QUERY\x00V1` | local private-note cursor query fingerprint; not a keyed authorization token | [`CATALOG_SCHEMA_V9.md`](CATALOG_SCHEMA_V9.md) |
| `CHUR\x00BACKUP\x00INVENTORY-COMMITMENT\x00V1` | ordered backup inventory commitment | [`BACKUP_FORMAT_V1.md`](BACKUP_FORMAT_V1.md) §7.2 |
| `CHUR\x00BACKUP\x00MANIFEST-AAD\x00V1` | encrypted backup manifest AAD | [`BACKUP_FORMAT_V1.md`](BACKUP_FORMAT_V1.md) §4 |
| `CHUR\x00BACKUP\x00FINAL-COMMIT-AAD\x00V1` | final backup commit AAD | [`BACKUP_FORMAT_V1.md`](BACKUP_FORMAT_V1.md) §7 |
| `CHUR\x00BACKUP\x00CATALOG-EXPORT-AAD\x00V1` | catalog export record AAD | [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md) §4 |
| `CHUR\x00BACKUP\x00RECORD-COMMITMENT\x00V1` | commitment over every non-container backup record | [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md) §5 |
| `CHUR\x00SYNC\x00OPERATION\x00V1` | operation payload AAD and Ed25519 signature input | [`../sync/OPERATION_LOG.md`](../sync/OPERATION_LOG.md) §2, §6, §7 |
| `CHUR\x00SYNC\x00OPERATION-CHAIN\x00V1` | operation digest and per-device chain hash | [`../sync/OPERATION_LOG.md`](../sync/OPERATION_LOG.md) §4 |
| `CHUR\x00SYNC\x00CHECKPOINT\x00V1` | checkpoint record signature | [`../sync/ROLLBACK_PROTECTION.md`](../sync/ROLLBACK_PROTECTION.md) §6 |
| `CHUR\x00SYNC\x00CHECKPOINT-COMMITMENT\x00V1` | checkpoint commitment | [`../sync/ROLLBACK_PROTECTION.md`](../sync/ROLLBACK_PROTECTION.md) §6 |
| `CHUR\x00SYNC\x00COLLECTION-EPOCHS\x00V1` | ordered current collection-epoch commitment | [`../sync/ROLLBACK_PROTECTION.md`](../sync/ROLLBACK_PROTECTION.md) §6.1 |
| `CHUR\x00SYNC\x00ENROLLMENT\x00V1` | device-enrollment signature | [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §4 |
| `CHUR\x00SYNC\x00REVOCATION\x00V1` | device-revocation signature | [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §9 |
| `CHUR\x00SYNC\x00MEMBERSHIP-CHAIN\x00V1` | membership-state commitment | [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §4.1 |
| `CHUR\x00SYNC\x00SERVER-DELETE\x00V1` | opaque server deletion authorization signature | [`../sync/SYNC_PROTOCOL_V1.md`](../sync/SYNC_PROTOCOL_V1.md) §9.1 |
| `CHUR\x00PAIRING\x00ROOT-PROOF\x00V1` | keyed proof of the restored vault root | [`../sync/DEVICE_PAIRING.md`](../sync/DEVICE_PAIRING.md) |
| `CHUR\x00PAIRING\x00REQUEST-SIGNATURE\x00V1` | fresh device request signature | [`../sync/DEVICE_PAIRING.md`](../sync/DEVICE_PAIRING.md) |
| `CHUR\x00PAIRING\x00REQUEST-DIGEST\x00V1` | complete pairing request commitment | [`../sync/DEVICE_PAIRING.md`](../sync/DEVICE_PAIRING.md) |
| `CHUR\x00PAIRING\x00APPROVAL-SIGNATURE\x00V1` | authorized device approval signature | [`../sync/DEVICE_PAIRING.md`](../sync/DEVICE_PAIRING.md) |
| `CHUR\x00PAIRING\x00APPROVAL-HPKE\x00V1` | pairing HPKE info and AAD | [`../sync/DEVICE_PAIRING.md`](../sync/DEVICE_PAIRING.md) |
| `CHUR\x00IDENTITY\x00FINGERPRINT\x00V1` | device verification fingerprint | [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §5 |
| `CHUR\x00IDENTITY\x00SIGNING-KEY-ID\x00V1` | Ed25519 public-key identifier | [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §4 |
| `CHUR\x00IDENTITY\x00HPKE-KEY-ID\x00V1` | X25519 HPKE public-key identifier | [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §4 |
| `CHUR\x00SHARING\x00GRANT-HPKE-INFO\x00V1` | collection-grant HPKE `info` | [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §3 |
| `CHUR\x00SHARING\x00GRANT-HPKE-AAD\x00V1` | collection-grant HPKE AAD | [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §3 |
| `CHUR\x00SHARING\x00COLLECTION-GRANT\x00V1` | collection-grant Ed25519 signature | [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §4 |
| `CHUR\x00SHARING\x00COLLECTION-MEMBERSHIP\x00V1` | collection-membership Ed25519 signature | [`../sync/COLLECTION_MEMBERSHIP.md`](../sync/COLLECTION_MEMBERSHIP.md) §1 |
| `CHUR\x00SHARING\x00MEMBERSHIP-CHAIN\x00V1` | collection-membership chain commitment | [`../sync/COLLECTION_MEMBERSHIP.md`](../sync/COLLECTION_MEMBERSHIP.md) §1 |
| `CHUR\x00IDENTITY\x00ENVELOPE\x00V1` | portable device-identity envelope AAD | [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §6.1 |

No allocated tag is a byte prefix of another, as §7 requires; every tag above is checked pairwise by `chur-crypto`. Tags within one area differ at the first purpose byte or at a separator followed by a suffix; tags in different areas differ before the purpose.

The fingerprint tag reaches no persisted or wire bytes; it is the input to a string a person reads, so the ADR requirement of §15.6 does not apply to it. A tag for an authenticated record whose AAD is not yet frozen is otherwise allocated by a row here in the same change that freezes that record.

### 15.6 Allocation rule

- the change that freezes a record allocates the values it needs and adds the rows here in the same change; a value that reaches persisted or wire bytes also requires an ADR, per [`../adr/README.md`](../adr/README.md);
- allocate the lowest free value of the namespace;
- `0x0000` and `0x00` are never allocated and are invalid in every namespace, consistent with §8;
- `0xFF00` to `0xFFFF` and `0xF0` to `0xFF` are reserved for local experiments and never appear in a released build or a published vector;
- every other unallocated value is unsupported: a reader rejects it and does not ignore or forward it unless the owning specification defines safe forwarding;
- an allocated value is never reused for a different meaning, including after the format that used it is deprecated, superseded, or never shipped;
- correcting a mistaken allocation takes a new value; it never redefines an allocated one.
