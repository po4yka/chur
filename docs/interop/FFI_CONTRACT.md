# Rust–KMP FFI Contract

> **Status:** Proposed normative interop contract

The FFI boundary exposes coarse-grained vault operations without making Kotlin, Swift, JNI, Objective-C, UniFFI, or Gobley part of the private storage protocol.

## 1. Layers

```text
chur-core / crypto / format / catalog / media
    ↓ Rust-native APIs
chur-ffi   one stable C ABI, one process-global handle registry
    ├──────────────────────────────┐
    ↓                              ↓
KMP expect/actual adapter      platform shell data-plane adapter
    ↓                              (iOS AVAssetResourceLoader in v1)
features and platform shells
```

The handle registry is process-global and language-agnostic. A handle created through the control plane in one language is usable from the other, and lock invalidates it for both in one step. A platform shell adapter may call the data plane directly when this avoids repeated copies, but it never creates or owns a session: sessions are created and closed through the shared application layer, and exactly one Rust runtime exists in the process (§14).

Bindings are replaceable. The secure core has no dependency on binding-language types.

## 2. ABI versioning

The native library exports a handshake that answers every fact a platform gate checks before a vault opens. These functions are callable from any thread before runtime initialization and cannot fail:

```text
chur_abi_version_major()   -> uint32_t
chur_abi_version_minor()   -> uint32_t
chur_capabilities()        -> uint64_t
chur_object_format_min()   -> uint16_t
chur_object_format_max()   -> uint16_t
chur_key_slot_format_min() -> uint16_t
chur_key_slot_format_max() -> uint16_t
chur_build_flavor()        -> uint32_t
```

- native API version is the (major, minor) pair. The current library reports 7.3: §6.32 re-encryption after a revocation and the `UNLOCK_DELAYED` status of [`../ERROR_MODEL.md`](../ERROR_MODEL.md) are additive; local encrypted playback positions are additive; portable bounded JPEG XL decoding is additive; pairing control records are version 2 without service addresses or tokens, and `chur_peer_call` supplies ephemeral direct peer IO; §6.4 reads bounded text for every scope and binds cursors to the complete query filter; §6.25 adds attachment counts and bounded note-owned file operations while retaining explicit note format, and §6.30 retains the caller-persisted import and album identities introduced in published ABI 3.0; §6.19 changes the album-list record, §6.20 adds atomic album placement, §6.21 adds tag and favourite selection controls, §6.22 adds recoverable trash, §6.23 stages the recovery slot until its phrase is confirmed, §6.24 reads and acknowledges the sync fork state, §6.25 adds local private notes, §6.26 adds selective archives, §6.26.1 adds external-file encryption, §6.28 adds the encrypted content index, and §6.29 adds atomic album removal. Incoming OS sharing reuses the existing import surface. A different major value fails loading, reports `ABI_INCOMPATIBLE`, and the library is not called again in that process. A minor value below the one whose functions the host calls fails loading in the same way, so an older library is refused at the gate rather than at a missing symbol; a higher minor value is accepted. The bundled host requires 7.3. A major value of `0` is such a value: §11 makes it what a handshake export returns when its body panics, so a panicking library fails the gate;
- the object-format range is the inclusive `container_version` interval this build reads, using the values registered in [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §15;
- the key-slot range is the inclusive key-slot format interval;
- build flavor is a bitfield: bit 0 set means a release build, bit 1 set means debug assertions are compiled in, bit 2 set means test hooks are compiled in. A release application refuses a library with bit 1 or bit 2 set;
- required feature flags are capability bits.

`chur_capabilities()` returns a bitmask:

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `CHUR_CAP_DECOY_VAULT` | independent decoy identity supported |
| 1 | `CHUR_CAP_OBJECT_READER` | random-access authenticated reader available |
| 2 | `CHUR_CAP_SEQUENTIAL_READER` | sequential reader available |
| 3 | `CHUR_CAP_INTEGRITY_SCAN` | background integrity scan available |
| 4 | `CHUR_CAP_BACKUP_PACKAGE` | portable backup package import/export available |
| 5 | `CHUR_CAP_SYNC` | ciphertext sync available |
| 6 | `CHUR_CAP_CONCURRENT_READS` | one reader handle serves parallel reads (§8) |
| 7 | `CHUR_CAP_COLLECTION_SHARING` | local sharing identity and collection records available |
| 8 | `CHUR_CAP_SHARED_OBJECTS` | authenticated source publication and recipient object activation available |
| 9 | `CHUR_CAP_JPEG_XL` | bounded portable JPEG XL decoding available (§6.31) |
| 10-63 | reserved | zero in v1 |

An unknown set bit is ignored and never enables behavior. Minor and capability differences are negotiated only within explicitly compatible behavior; they never select cryptographic suites from untrusted input.

## 3. Handles

Opaque handles represent:

```text
RuntimeHandle
VaultSessionHandle
ObjectReaderHandle
JpegXlDecoderHandle
ImportHandle
ExportHandle
IntegrityScanHandle
```

Requirements:

- `chur_handle_t` is `uint64_t`: the low 32 bits index a typed registry slot, the high 32 bits carry that slot's generation counter. It is never a raw pointer and never a business ID; `0` is the null handle;
- explicit owner runtime/session for vault handles; the standalone JPEG XL decoder owns no vault authority and requires explicit host close;
- thread affinity and concurrency fixed per handle type by the table in §8, not per instance;
- close is idempotent for every handle type without exception: the first close releases the resources, and every later close of the same value returns success and does nothing. Close never returns `NOT_FOUND` or `SESSION_EXPIRED`; closing a value this process never issued returns `INVALID_INPUT`, which the generation counter makes distinguishable from a re-close;
- a handle value is never reissued: the generation counter of a slot increments on every allocation, so a stale value cannot alias a live handle for the life of the process;
- stale generation returns `SESSION_EXPIRED`;
- no handle revives after lock;
- handle registry bounded against leaks/DoS.

## 4. Session generation

Every opened vault session receives a monotonically changing in-process generation. Handles capture it. Locking:

1. marks session cancelling;
2. increments/invalidates generation;
3. zeroizes session secrets in place;
4. closes catalog;
5. cancels operations;
6. makes every old handle fail.

UI cleanup is not required for native invalidation.

## 5. Control plane

Suitable values:

- commands and bounded query parameters;
- opaque references;
- small projections;
- stable error codes;
- progress summaries;
- migration/integrity states;
- capability flags.

Control records must not contain keys, decrypted manifests, private paths, or arbitrarily large media bytes.

## 6. Data plane

Large data uses:

- platform file descriptors/seekable handles when safe;
- caller-provided direct/native buffers;
- `read_at(offset, destination)`;
- authenticated content information before the first range request;
- bounded sequential import/export;
- explicit byte counts;
- no whole-file `ByteArray`, `NSData`, or generated-binding list.

### 6.1 Content information

A range reader must publish content information before it answers the first request: Media3 needs a length and AVFoundation needs `contentInformationRequest` filled in. `chur_object_reader_content_info` supplies it from authenticated canonical metadata, never from the provider hint that [`MEDIA_PIPELINE.md`](MEDIA_PIPELINE.md) §3 classifies as untrusted:

```text
ChurContentInfoV1
    plaintext_size        u64        authenticated size from the final commit record
    content_type          char[64]   NUL-terminated lowercase IANA media type
    media_kind            u16        canonical metadata media-kind value
    byte_range_supported  u8         1 for a committed immutable object
    complete              u8         1 only after final-commit validation
```

- the content-type identifier space is IANA media types, at most 63 bytes plus the terminator, taken from the canonical metadata Rust validated at import. Android uses the value as the MIME type unchanged; iOS converts it with `UTType(mimeType:)`;
- content information is publishable only when the final commit record validates. Until then the call returns `OBJECT_INCOMPLETE` and the adapter fails the open or loading request instead of publishing a size, because a player that has been given a length treats a later failure as a transport error and retries indefinitely;
- a reader opened on an incomplete object may still serve `read_at` for resumable transfer and verification, but it must not be attached to a player.

### 6.2 Exported symbols

Every exported symbol is `chur_` followed by lower snake case. An operation on a handle takes the shape `chur_<subject>_<verb>`; the eight handshake accessors of §2 are named `chur_<fact>` for the value they return and are the only exceptions. Nothing else leaves the artifact: the Android link step applies a version script, the Apple link step an exported-symbols list, and a release check fails on any symbol outside this set. `chur_handle_t` is `uint64_t` with `0` as the null handle, and `chur_status_t` is the `int32_t` of [`../ERROR_MODEL.md`](../ERROR_MODEL.md).

The Phase-1 surface is frozen. Adding an export raises the minor ABI version; changing or removing one raises the major version. `chur.h`, checked in with the first `chur-ffi` export, is the deliverable both platform teams build against, and every binding derives from it.

The list below is the surface at ABI 1.0. §6.5 adds the exports Phase 1's own product scope requires and raises the minor version to 1; nothing in this list changed. The channel-less diagnostic of [ADR-0037](../adr/0037-contain-panics-in-channel-less-exports.md) is part of this surface as well, and the same minor-version rule covers it.

```c
/* handshake: any thread, before initialization, cannot fail (§2) */
uint32_t chur_abi_version_major(void);
uint32_t chur_abi_version_minor(void);
uint64_t chur_capabilities(void);
uint16_t chur_object_format_min(void);
uint16_t chur_object_format_max(void);
uint16_t chur_key_slot_format_min(void);
uint16_t chur_key_slot_format_max(void);
uint32_t chur_build_flavor(void);

/* status diagnostics: no handle, cannot fail (ADR-0037) */
bool chur_status_is_known(int32_t value);

/* runtime and session */
chur_status_t chur_runtime_open(const ChurRuntimeConfigV1 *config, chur_handle_t *out_runtime);
chur_status_t chur_runtime_close(chur_handle_t runtime);
chur_status_t chur_vault_unlock(chur_handle_t runtime, const ChurUnlockRequestV1 *request,
                                chur_handle_t *out_session);
chur_status_t chur_vault_lock(chur_handle_t session, uint32_t reason);
chur_status_t chur_session_close(chur_handle_t session);

/* catalog queries: a bounded projection written into a caller buffer */
chur_status_t chur_catalog_query(chur_handle_t session, const ChurQueryV1 *query,
                                 uint8_t *destination, size_t capacity, size_t *bytes_written);

/* operations */
chur_status_t chur_import_begin(chur_handle_t session, int32_t source_fd,
                                const ChurImportRequestV2 *request, chur_handle_t *out_import);
chur_status_t chur_export_begin(chur_handle_t session, const ChurObjectRefV1 *object,
                                int32_t destination_fd, chur_handle_t *out_export);
chur_status_t chur_integrity_scan_begin(chur_handle_t session, const ChurScanRequestV1 *request,
                                        chur_handle_t *out_scan);
chur_status_t chur_operation_poll(chur_handle_t operation, ChurProgressV1 *out_progress);
chur_status_t chur_operation_cancel(chur_handle_t operation);
chur_status_t chur_operation_close(chur_handle_t operation);

/* object reader */
chur_status_t chur_object_reader_open(chur_handle_t session, const ChurObjectRefV1 *object,
                                      uint32_t stream_kind, chur_handle_t *out_reader);
chur_status_t chur_object_reader_size(chur_handle_t reader, uint64_t *out_size);
chur_status_t chur_object_reader_content_info(chur_handle_t reader, ChurContentInfoV1 *out_info);
chur_status_t chur_object_reader_read_at(chur_handle_t reader, uint64_t offset, uint8_t *destination,
                                         size_t capacity, size_t *bytes_written);
chur_status_t chur_object_reader_verify_complete(chur_handle_t reader, uint32_t *out_state);
chur_status_t chur_object_reader_close(chur_handle_t reader);
```

Each target of an integrity scan begun by `chur_integrity_scan_begin` reaches an outcome: an `integrity_summary` verdict the catalog records, or proven corruption, which is a lifecycle change rather than a verification verdict (§6.4). No outcome ends the scan: it goes on to every remaining target, and its terminal status is `OBJECT_CORRUPT` when it proved at least one target corrupt, and `0` otherwise. A cancellation (§9), or a failure that reaches no outcome for a target (§11), ends the scan early with that status instead.

### 6.3 Range reads

`chur_object_reader_read_at` never mixes an error with a byte count: the status is the return value, the count is written through `bytes_written`.

- `bytes_written` is set on every call, including every failure, where it is set to `0`;
- on success `*bytes_written <= capacity`. A short read is permitted at any offset, not only near the end: the reader returns at most the authenticated bytes it already holds, so the caller must loop until it has the range it needs or observes `*bytes_written == 0`;
- `*bytes_written == 0` with a success status means end of authenticated plaintext, and occurs only when `offset == size`;
- `offset == size` returns success with `0` bytes;
- `offset > size` returns `INVALID_INPUT`, never a zero-length success, so a seek past the end stays distinguishable from end of stream;
- `capacity == 0` returns success with `0` bytes and touches nothing;
- on any failure status the whole destination buffer holds unspecified bytes. The caller must not use any prefix of it, and must not treat bytes written by an earlier successful call into the same buffer as still valid;
- `size` is the authenticated plaintext size from the final commit record, not a file length.

### 6.4 The catalog page encoding

`chur_catalog_query` writes one page into the caller's buffer as canonical bytes rather than as a C structure. A structure would carry the padding and alignment of whichever compiler built the host, and [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §13 reserves the definition of persisted and boundary bytes for Rust; a page whose layout depended on the host's compiler would not be one definition.

```text
ChurPageV1
    total_count           u64        rows the scope holds, not rows returned
    catalog_generation    u64        the generation the page was read at
    object_count          u32        projections that follow
    next_cursor_present   u8         0x00 or 0x01
    next_cursor           bytes[42]  the §16.2 cursor, zero bytes when absent
    objects               object_count × ObjectProjectionV1, §16.1
```

The header is 63 bytes and a projection is 79, so a page of `n` rows is `63 + 79n` bytes and a caller sizes its buffer from the `limit` it asked for. A buffer smaller than the page is `RESOURCE_LIMIT_EXCEEDED` and writes nothing: a truncated page would be indistinguishable from a short one, and the caller would treat the scope as exhausted.

`ChurQueryV1` is the request. It is a C structure because it is the caller's to build, and it carries no variable field except the search terms:

```text
ChurQueryV1
    scope                 uint8_t    1 timeline, 2 album, 3 favorites, 4 tag, 5 search, 6 quarantine, 7 trash
    sort                  uint8_t    0 or 1 capture_desc, 2 capture_asc, 3 import_desc, 4 album_manual
    kinds                 uint16_t   the §16.2 media-kind mask
    limit                 uint32_t   1 to 500, 0 for the default of 200
    scope_id              uint8_t[16]  the album or tag, zero bytes otherwise
    cursor_present        uint8_t    0 or 1
    cursor                uint8_t[42]  the §16.2 cursor
    terms                 const uint8_t *  UTF-8 search text, not NUL-terminated
    terms_length          uint32_t
```

`terms_length` bounds optional UTF-8 `terms` in every scope (512 bytes maximum); zero length clears the filter. Search requires nonblank text; Trash refuses it because its FTS entries have been erased. The pointer is not retained after the call. ABI 6 changes this formerly Search-only request field and the opaque cursor context; hosts from another major refuse at the handshake, and cursors from the prior contract are rejected. The C structure layout stays the same.

`chur_object_reader_verify_complete` writes through `out_state`, on success only, the `integrity_summary` value the scan reached: the enum of [`../format/CATALOG_SCHEMA_V1.md`](../format/CATALOG_SCHEMA_V1.md) §5.1, whose byte values are allocated in [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §15.4. Proven corruption is a lifecycle change rather than a verification verdict, so it returns `OBJECT_CORRUPT` and writes no state.

The control plane uses these same symbols through a thin KMP `expect`/`actual` adapter. No binding generator is part of the boundary ([ADR-0016](../adr/0016-freeze-the-v1-c-abi.md)).

### 6.5 The Phase-1 product surface, ABI 1.1

The list in §6.2 is the boundary a host needs to open a vault and read from it. It is not the boundary a host needs to *deliver* Phase 1, and the gap is not a matter of degree: with §6.2 alone an application cannot create a vault, so no vault ever exists to unlock; it cannot mark a favourite, create an album, delete an object, or read a thumbnail, so three of the four destinations of [`../../DESIGN.md`](../../DESIGN.md) §10 have nothing to show.

These exports close that gap. They are an addition, so they raise the minor ABI version to 1 and change nothing in §6.2. A host built against 1.0 still works: §2 negotiates a minor difference within explicitly compatible behaviour, and an export a host does not call costs it nothing.

```c
/* provisioning, PROVISIONING.md section 3 */
chur_status_t chur_vault_present(chur_handle_t runtime, uint8_t *out_present);
chur_status_t chur_vault_create_begin(chur_handle_t runtime,
                                      const ChurCreateRequestV1 *request,
                                      chur_handle_t *out_creation);
chur_status_t chur_vault_creation_add_recovery_slot(chur_handle_t creation,
                                                    uint8_t *destination,
                                                    size_t capacity,
                                                    size_t *bytes_written);
chur_status_t chur_vault_creation_activate(chur_handle_t creation,
                                           chur_handle_t *out_session);
chur_status_t chur_vault_creation_abandon(chur_handle_t creation);

/* key slots, KEY_SLOTS.md section 9 */
chur_status_t chur_vault_add_recovery_slot(chur_handle_t session, uint8_t *destination,
                                           size_t capacity, size_t *bytes_written);
chur_status_t chur_vault_recovery_begin(chur_handle_t session, uint8_t *destination,
                                        size_t capacity, size_t *bytes_written);
chur_status_t chur_vault_recovery_commit(chur_handle_t session);
chur_status_t chur_vault_add_device_slot(chur_handle_t session,
                                         const uint8_t *item_id,
                                         uint8_t *out_secret);
chur_status_t chur_vault_remove_slot(chur_handle_t session, const uint8_t *slot_id);
chur_status_t chur_vault_change_password(chur_handle_t session,
                                         const ChurUnlockRequestV1 *request);
chur_status_t chur_vault_slots(chur_handle_t session, uint8_t *destination,
                               size_t capacity, size_t *bytes_written);

/* library, DESIGN.md sections 11 to 13 */
chur_status_t chur_object_set_favorite(chur_handle_t session,
                                       const ChurObjectRefV1 *object,
                                       uint8_t favorite);
chur_status_t chur_object_delete(chur_handle_t session, const ChurObjectRefV1 *object);
chur_status_t chur_trash_set(chur_handle_t session, const uint8_t *object_ids,
                             uint32_t object_count, uint8_t restore);
chur_status_t chur_trash_empty(chur_handle_t session);
chur_status_t chur_trash_restore_all(chur_handle_t session);
chur_status_t chur_object_metadata(chur_handle_t session,
                                   const ChurObjectRefV1 *object,
                                   uint8_t *destination, size_t capacity,
                                   size_t *bytes_written);
chur_status_t chur_album_create(chur_handle_t session, const uint8_t *name,
                                uint32_t name_length, const uint8_t *requested_album_id,
                                uint8_t *out_album_id);
chur_status_t chur_album_set_membership(chur_handle_t session,
                                        const uint8_t *album_id,
                                        const ChurObjectRefV1 *object,
                                        uint8_t member);
chur_status_t chur_album_list(chur_handle_t session, uint8_t *destination,
                              size_t capacity, size_t *bytes_written);
chur_status_t chur_tag_create(chur_handle_t session, const uint8_t *name,
                              uint32_t name_length, uint8_t *out_tag_id);
chur_status_t chur_object_set_tag(chur_handle_t session, const uint8_t *tag_id,
                                  const ChurObjectRefV1 *object, uint8_t tagged);

/* derived assets, MEDIA_PIPELINE.md section 6 */
chur_status_t chur_derived_put(chur_handle_t session, const ChurObjectRefV1 *object,
                               uint32_t kind, uint32_t width, uint32_t height,
                               const uint8_t *bytes, uint32_t length);
chur_status_t chur_derived_read(chur_handle_t session, const ChurObjectRefV1 *object,
                                uint32_t kind, uint8_t *destination, size_t capacity,
                                size_t *bytes_written);
```

`ChurCreateRequestV1` is the password and the Argon2id profile a new vault is created with:

```text
ChurCreateRequestV1
    password          const uint8_t *
    password_length   uint32_t
    memory_kib        uint32_t   0 for the frozen v1 floor
    iterations        uint32_t   0 for the frozen v1 default
    parallelism       uint32_t   0 for the frozen v1 default
```

A creation handle is a fourth handle type. It exists because [`../security/PROVISIONING.md`](../security/PROVISIONING.md) §3 has a middle: the recovery slot is offered at step 5, after the password slot is verified at step 4 and before the descriptor reaches `ACTIVE` at step 6. A single create call would have to skip the offer or take a callback, and §10 admits no callback. Closing a creation handle without activating it abandons the creation, which §9 of [`../format/VAULT_DESCRIPTOR_V1.md`](../format/VAULT_DESCRIPTOR_V1.md) requires to leave nothing openable.

Two things cross that §12 would otherwise keep inside, and they cross differently.

`out_secret` is 32 bytes and is the `DeviceUnlockSecret` of [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §5. It must reach the platform keystore, which is exactly §12's "unavoidable for a key-slot operation", and it never reaches a screen: the host stores it and clears the buffer.

The recovery slot writes the *phrase* rather than the 32 canonical bytes. [`../security/RECOVERY.md`](../security/RECOVERY.md) §2 requires the user to see it, and the phrase is a presentation encoding, which [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §13 reserves for Rust; a host given the bytes would have to implement BIP-39 twice, once per platform, to show anything. It crosses as bounded UTF-8 bytes in a caller buffer, which is the same shape §12 already permits for a password entering Rust, and the host clears the buffer once the user has seen it. `CHUR_RECOVERY_PHRASE_MAX` is 216: twenty-four words of the English list, whose longest entry is eight characters, plus the separators.

Four list results are canonical bytes, for the reason §6.4 gives:

```text
ChurSlotListV1
    count             u32
    entries           count × { slot_id: bytes[16], slot_type: u8, slot_generation: u64 }

ChurAlbumListV2
    count             u32
    entries           count × { album_id: bytes[16], member_count: u64,
                                name_length: u16, name: bytes[name_length],
                                parent_album_id: bytes[16], sort_position: u64 }

ChurTagListV1
    count             u32
    entries           count × { tag_id: bytes[16], name_length: u16,
                                name: bytes[name_length] }

ChurObjectMetadataV1
    capture_time_ms            u64
    import_time_ms             u64
    capture_time_substituted   u8
    width                      u32
    height                     u32
    duration_ms                u64
    plaintext_size             u64
    content_type_length        u16
    content_type               bytes
    filename_length            u16
    filename                   bytes
    caption_length             u16
    caption                    bytes
    tag_count                  u16
    tags                       tag_count × { tag_id: bytes[16], name_length: u16, name: bytes }
```

`ChurObjectMetadataV1` is the only record in this contract that carries free-form private text, and §16.1 of [`../format/CATALOG_SCHEMA_V1.md`](../format/CATALOG_SCHEMA_V1.md) is why: a page of 200 rows must never carry 200 filenames, so the projection carries none and a detail screen fetches them for one object. A caller that asked for this record per row would be defeating that rule rather than using this one.

A buffer smaller than the record is `RESOURCE_LIMIT_EXCEEDED` and writes nothing, exactly as in §6.4.

### 6.6 The Android Keystore surface, ABI 1.2

The Android Keystore is the one key-slot family whose AEAD runs outside Rust. Its wrapping key is generated inside the Keystore and is non-exportable, which is the property that makes it worth having, and it means the cipher runs on the platform side. [`../format/KEY_SLOT_BODIES_V1.md`](../format/KEY_SLOT_BODIES_V1.md) §5 already records that in the format: `AndroidKeystoreSlotBodyV1` stores bytes Rust never produced and cannot open, and `wrap_suite_id` `0x0002` says so.

A cipher that runs on the platform side needs its plaintext there. These three exports are the consequence, and [ADR-0041](../adr/0041-the-android-keystore-slot-exchanges-root-bytes.md) is where the exception to §12 is argued rather than assumed. They are an addition, so they raise the minor ABI version to 2 and change nothing above.

```c
chur_status_t chur_vault_keystore_begin(chur_handle_t session,
                                        uint8_t *destination, size_t capacity,
                                        size_t *bytes_written);
chur_status_t chur_vault_keystore_commit(chur_handle_t session,
                                         const uint8_t *gcm_nonce,
                                         const uint8_t *wrapped_root_secret);
chur_status_t chur_vault_keystore_material(chur_handle_t runtime,
                                           uint8_t *destination, size_t capacity,
                                           size_t *bytes_written);
```

Enrollment is two calls with a platform operation between them:

1. `chur_vault_keystore_begin` allocates the slot id and the slot generation, because the §4 AAD binds both, and records the pending enrollment in the session. It writes nothing to the descriptor, so an enrollment the platform abandons leaves the vault exactly as it was. A second `begin` replaces the pending enrollment; a `commit` without one is `CONFLICT`. A `begin` in a session whose identity holds no device slot, while another registry entry holds one, is `PLATFORM_KEY_UNAVAILABLE` and releases no root: [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §8 admits one device-slot identity, and the Apple Keychain slot add follows the same rule;
2. the host asks the Keystore to encrypt the root under the AAD;
3. `chur_vault_keystore_commit` stores the nonce and the wrapped bytes, and the slot exists.

`chur_vault_keystore_material` takes a **runtime** handle rather than a session, because its result is what a caller needs *before* it can unlock. Nothing it returns is secret: every field is already stored in the clear in the descriptor. It returns one entry per enrolled slot across every identity the registry admits, in registry order, and names no identity: a caller tries each in turn, which is what [`../security/DECOY_VAULT.md`](../security/DECOY_VAULT.md) requires of a caller that must not learn which vault it opened. Every entry opens its own identity, so the order would choose the identity if two held a slot; the one-identity rule of `begin` above is what makes the first success the only one.

Unlock factor `4` carries the unwrapped root itself rather than a value a slot body opens, and is verified the way every other factor is: the descriptor authenticates under the root, so a wrong or substituted value is `AUTHENTICATION_FAILED` and not corruption. A descriptor with no Keystore slot is skipped.

Both records are canonical bytes in a caller buffer, as §6.4 has every list be:

```text
ChurKeystoreEnrollmentV1
    alias_length      u32
    alias             bytes[alias_length]
    aad_length        u32
    aad               bytes[aad_length]
    root_secret       bytes[32]

ChurKeystoreMaterialV1
    count             u32
    entries           count × { alias_length: u32, alias: bytes,
                                aad_length: u32, aad: bytes,
                                gcm_nonce: bytes[12],
                                wrapped_root_secret: bytes[48] }
```

`root_secret` is the one field in this contract that carries a vault root, and every holder clears it: Rust zeroizes the encoded record, and the caller overwrites the buffer as soon as the wrap returns. The same rule applies to the secret passed to `chur_vault_unlock` under factor `4`. A host that will not accept that window has a supported answer, which is not to enroll the slot: [`../security/PROVISIONING.md`](../security/PROVISIONING.md) §5 already makes a device slot never the only slot.

### 6.7 The portable backup surface, ABI 1.3

[`../format/BACKUP_FORMAT_V1.md`](../format/BACKUP_FORMAT_V1.md) §1 makes the package portable across Android, iOS, and the CLI, and its §7 and §8 are long-running work over the whole vault. Two exports carry them, and both return an operation handle driven by `chur_operation_poll`, `_cancel`, and `_close`, exactly as an import or an export is:

```c
chur_status_t chur_backup_create(chur_handle_t session, int32_t destination_fd,
                                 chur_handle_t *out_operation);
chur_status_t chur_backup_restore(chur_handle_t runtime, int32_t source_fd,
                                  const uint8_t *password, uint32_t password_length,
                                  chur_handle_t *out_operation);
```

`ChurProgressV1` gains two `kind` values, `4` for a backup and `5` for a restore. §10's rule is unchanged: a snapshot carries bounded non-private numbers, and a byte count is one.

Three things differ from the §6.2 operations and each follows from the format.

Both descriptors must be **seekable** as well as open. §7 writes the public preamble before the records and learns the record count only after the inventory pass, and §8 walks record headers before it reads a payload. A pipe is therefore neither a destination nor a source, and an application that uploads a package writes it to a file and uploads that file.

`chur_backup_restore` takes the **runtime** rather than a session. A restore installs an identity, so at the moment it runs there may be no session and no vault at all; §8 step 2 obtains the credential from the package's own portable descriptor. The operation belongs to the runtime, so §14's runtime close tears it down and §4's session lock does not, because there is no session to lock.

The password crosses the boundary as bytes and is **not retained**. §12 keeps credentials inside Rust: the bytes are copied into a zeroizing buffer before the call returns and the caller's pointer is not held.

A restore refuses when the registry already holds the two identities [`../format/VAULT_DESCRIPTOR_V1.md`](../format/VAULT_DESCRIPTOR_V1.md) §11 admits, and it installs nothing until the package authenticates whole.

### 6.8 The ciphertext sync inbox, ABI 1.4

The host can store downloaded opaque records while the vault is locked. Rust derives the local record name from the record bytes, bounds the inbox, and does not parse the record until unlock. The host passes the public random `vault_id`; it does not pass a private path or a key.

```c
chur_status_t chur_sync_stage(chur_handle_t runtime, const uint8_t vault_id[16],
                              uint8_t kind, uint64_t staged_at_ms,
                              const uint8_t *record, uint32_t record_length);
chur_status_t chur_sync_process(chur_handle_t session, uint64_t now_ms,
                                ChurSyncReportV1 *out_report);
chur_status_t chur_sync_heads(chur_handle_t session, uint8_t *destination,
                              size_t capacity, size_t *bytes_written);
```

Record kind `1` is an encrypted signed operation. Kind `2` is a signed checkpoint. `chur_sync_stage` is idempotent for identical bytes. It rejects one record above the 16 MiB response bound. The whole per-vault inbox remains bounded to the limits in [`../sync/SYNC_PROTOCOL_V1.md`](../sync/SYNC_PROTOCOL_V1.md) §7.

`chur_sync_heads` reads only authenticated active device membership and accepted operation heads from the unlocked catalog. It writes big-endian `version:u16=1`, `count:u32`, then at most 32 entries of `device_id:bytes[16]` and `accepted_sequence:u64`. A known device without an accepted operation has sequence zero. A locked session returns `VAULT_LOCKED`. The host saves these sequences as pull cursors after unlocked processing; download or staging counts never acknowledge a record.

`chur_sync_process` authenticates and decrypts operations under the unlocked session. It removes an applied record, an exact replay, and a record that full validation rejects. It retains an operation with a missing device sequence, causal predecessor, or collection key. The report contains applied, duplicate, pending, and rejected counts. `first_rejection` is zero or the first stable `chur_status_t`, except that `SYNC_CHAIN_FORK` or `SYNC_HEAD_ROLLBACK` replaces an earlier status of another kind: a server can stage any bytes beside a forked record, and the engine drops that record after it freezes the chain, so a first-record rule would let the server hide the verdict ([`../ERROR_MODEL.md`](../ERROR_MODEL.md) "Wire and persistence compatibility"). It contains no private text.

### 6.9 Sharing identity, ABI 1.5

`chur_sharing_identity` idempotently creates the vault's first ordinary device identity or returns the existing one. Ed25519 and X25519 private keys stay root-wrapped in the encrypted catalog and never cross the ABI. The same transaction commits the signed self-enrollment and its encrypted outer operation.

```c
chur_status_t chur_sharing_identity(chur_handle_t session,
                                    uint8_t *destination, size_t capacity,
                                    size_t *bytes_written);
```

The caller-owned result is a bounded public record: `version:u16 = 1`, `vault_id:bytes[16]`, `device_id:bytes[16]`, `signing_public_key:bytes[32]`, `hpke_public_key:bytes[32]`, then three `u32`-length-prefixed fields containing the 49-byte ASCII fingerprint, the 270-byte self-enrollment, and its canonical outer operation. Integers are big-endian. A retry returns identical bytes. A buffer that is too small receives no partial record and returns `RESOURCE_LIMIT_EXCEEDED`.

### 6.10 Share preparation, ABI 1.6

`chur_sharing_prepare` adds or updates one recipient and issues its HPKE collection-key grant. The input enrollment is the recipient's canonical 270-byte initial enrollment. `permissions` is the cumulative profile `1` (read), `3` (contribute), or `7` (manage members). `fingerprint_verified` is exactly `0` or `1`. Private identity and collection keys stay inside Rust.

```c
chur_status_t chur_sharing_prepare(chur_handle_t session,
                                   const uint8_t collection_id[16],
                                   const uint8_t *recipient_enrollment,
                                   uint32_t recipient_enrollment_length,
                                   uint8_t permissions,
                                   uint8_t fingerprint_verified,
                                   uint8_t *destination, size_t capacity,
                                   size_t *bytes_written);
```

The caller-owned output is `version:u16 = 1` followed by four `u32`-length-prefixed canonical fields: the collection membership record, its authenticated outer operation, the HPKE grant, and its authenticated outer operation. Integers are big-endian. A retry with the same accepted state returns identical bytes. A short buffer receives no partial record, sets `bytes_written` to zero, and returns `RESOURCE_LIMIT_EXCEEDED`.

### 6.11 Share acceptance, ABI 1.7

`chur_sharing_accept` receives relay records, authenticates every issuer membership and operation chain, opens the local device's HPKE grant, and atomically installs the shared collection, its root-wrapped key, membership, pins, and grant. Issuer operations are transient evidence and are not inserted into the recipient identity-vault log. Private keys and the opened collection key do not cross the ABI.

```c
chur_status_t chur_sharing_accept(chur_handle_t session,
                                  const uint8_t *bundle,
                                  uint32_t bundle_length);
```

The bundle is at most 16 MiB. It contains big-endian fields in this order:

```text
version:u16 = 1
issuer_count:u32
repeat issuer_count:
    membership_count:u32
    membership_records:membership_count * bytes<u32>
    operation_count:u32
    operations:operation_count * bytes<u32>
collection_membership_count:u32
collection_memberships:collection_membership_count * (
    membership_record:bytes<u32>, outer_operation:bytes<u32>)
grant:bytes<u32>
grant_outer_operation:bytes<u32>
```

There are at most 257 issuers and 4096 records in each counted list. Membership records are canonical `EnrollmentRecordV1` or `RevocationRecordV1`; every other record has its normative Phase 4 encoding. Counts, lengths, trailing bytes, gaps, causal predecessors, signatures, recipient bindings, selectors, payload pairs, epochs, permissions, and replay conflicts fail closed. Exact replay succeeds without advancing the catalog generation.

### 6.12 Share revocation, ABI 1.8

`chur_sharing_revoke` signs a recipient revocation, advances the collection epoch, eagerly rewraps active object keys, and issues current HPKE grants only to the remaining recipients. Revocation is forward-only: a removed recipient can retain old keys or plaintext. Private keys stay inside Rust.

```c
chur_status_t chur_sharing_revoke(chur_handle_t session,
                                  const uint8_t collection_id[16],
                                  const uint8_t recipient_vault_id[16],
                                  const uint8_t recipient_device_id[16],
                                  uint64_t accepted_at_ms,
                                  uint8_t *destination, size_t capacity,
                                  size_t *bytes_written);
```

The caller-owned output is at most 16 MiB and contains big-endian fields in this order:

```text
version:u16 = 1
revocation_membership:bytes<u32>
revocation_outer_operation:bytes<u32>
rotation_operation_count:u32
rotation_operations:rotation_operation_count * bytes<u32>
grant_count:u32
grants:grant_count * (grant:bytes<u32>, outer_operation:bytes<u32>)
rotation_complete:u8
```

Each counted list has at most 4096 records. One call authors at most 4096 rotation operations. If more rewrap work remains, it returns `rotation_complete = 0` and no grants; the caller uploads that batch and calls the function again. Current grants appear only with `rotation_complete = 1`. The flag is exactly `0` or `1`, and an exact retry creates no new record. The destination capacity must cover the 16 MiB response bound so buffer validation happens before durable state changes. A smaller buffer receives no partial record, sets `bytes_written` to zero, and returns `RESOURCE_LIMIT_EXCEEDED`.

### 6.13 Authenticated recipient devices, ABI 1.9

`chur_sharing_prepare_device` prepares the same output as §6.10, but it accepts a complete authenticated recipient identity-vault history and can address any active device in that vault. Rust validates the membership chain, operation chains, signatures, causal predecessors, revocation heads, and selected device before it pins keys or issues a grant. Kotlin does not parse recipient protocol records.

```c
chur_status_t chur_sharing_prepare_device(chur_handle_t session,
                                          const uint8_t collection_id[16],
                                          const uint8_t *recipient_evidence,
                                          uint32_t recipient_evidence_length,
                                          const uint8_t recipient_device_id[16],
                                          uint8_t permissions,
                                          uint8_t fingerprint_verified,
                                          uint8_t *destination, size_t capacity,
                                          size_t *bytes_written);
```

The evidence is at most 16 MiB and contains `version:u16 = 1`, `membership_count:u32`, that many `membership_record:bytes<u32>` values, `operation_count:u32`, and that many `operation:bytes<u32>` values. Each count is at most 4096. The membership list starts at generation one and includes every successor through the selected device's current membership. The output and retry rules are identical to §6.10. The initial-enrollment function remains for ABI compatibility and first-device invitations.

### 6.14 User-facing sharing discovery, ABI 1.10

`chur_sharing_overview` idempotently creates the default cryptographic collection if needed, then returns its identifier and all current or historical recipient devices. Its canonical output is `version:u16 = 1`, `collection_id:id`, `member_count:u32`, then each member in identifier order as `vault_id:id`, `device_id:id`, `permissions:u8`, `active:u8`, `fingerprint_verified:u8`, `fingerprint:bytes<u32>`. The count is at most 4096. The fingerprint is computed from the pinned public keys; both flags are exactly zero or one. A revoked recipient remains visible with `active = 0` so a pending key rotation can resume after restart.

`chur_sharing_inspect_enrollment` accepts exactly one canonical 270-byte initial enrollment and verifies its self-signature before returning `version:u16 = 1`, `vault_id:id`, `device_id:id`, `fingerprint:bytes<u32>`. The application compares the displayed fingerprint through an independent channel before preparing a grant. The enrollment and overview output contain public identity material only; neither function exposes a private key.

```c
chur_status_t chur_sharing_overview(chur_handle_t session,
                                    uint8_t *destination, size_t capacity,
                                    size_t *bytes_written);
chur_status_t chur_sharing_inspect_enrollment(const uint8_t *enrollment,
                                               uint32_t enrollment_length,
                                               uint8_t *destination, size_t capacity,
                                               size_t *bytes_written);
```

Both calls set `bytes_written` to zero on failure and reject a short destination without a partial write. The caller reserves 512 KiB for the overview and 128 bytes for one recipient preview.

### 6.15 Private tag picker, ABI 1.11

`chur_tag_list` returns `ChurTagListV1` in name and identifier order from the unlocked catalog. A short destination yields no partial record. Tag names remain private to the unlocked application surface.

```c
chur_status_t chur_tag_list(chur_handle_t session, uint8_t *destination,
                            size_t capacity, size_t *bytes_written);
```

### 6.16 Shared object transfer, ABI 1.12

`CHUR_CAP_SHARED_OBJECTS` covers source publication and recipient activation. The source page lists active originals in object ID order. It returns no signed content operations until `chur_sharing_author` verifies the uploaded object's store ID, length, and SHA-256 digest. The host uploads complete ciphertext and associates it with the source collection before it calls `chur_sharing_author` and sends its CreateObject and CommitObject records.

`chur_sharing_receive` accepts a bounded page of signed collection operations after it verifies the addressed share. Its plan contains only missing objects with accepted commits. The recipient downloads ciphertext into private staging with `chur_sharing_download_append`. `chur_sharing_download_finish` checks the object envelope, AEAD records, final commitment, and exact length before catalog activation. A retry can finish a verified container that was renamed before its catalog row committed. See `chur.h` for the exact pointer and length contract of each export.

### 6.17 Shared download resume, ABI 1.13

`chur_sharing_download_offset` reads the durable private staging length only for an object in the current authenticated receive plan. If staging is absent, a committed container with the signed length returns that length to recover a crash before catalog activation. A missing or oversized file returns offset zero. The host resumes at that offset, and `chur_sharing_download_finish` still verifies every ciphertext record and the signed final commitment before activation. If verification of resumed bytes fails, the host restarts the download at offset zero once.

### 6.18 Device-slot platform identifier, ABI 1.14

`chur_vault_platform_slot_identifier` returns the public platform name bound to one Android Keystore or Apple Keychain slot in the unlocked session. The result is the opaque Keystore alias or 16-byte Keychain item ID, never the platform key or device secret. The call refuses other slot families, missing slots, and an identifier shared by another slot. The host reads this name before removing the slot from the vault descriptor. After descriptor removal succeeds, it deletes the platform item by that name and reports a deletion failure to the caller. A crash between these two stores can leave an orphan platform item. It cannot open the vault without its descriptor slot.

### 6.19 Album organization, ABI 2.15

`ChurAlbumListV2` replaces `ChurAlbumListV1` and reports each album's parent and sibling position. A zero parent identifier means root. This wire change requires ABI major 2. If the caller's list buffer is too small, `chur_album_list` writes the required byte count to `bytes_written`, returns `RESOURCE_LIMIT_EXCEEDED`, and leaves the destination unchanged; the caller may allocate that exact size and retry.

`chur_album_rename` changes a name. `chur_album_delete` removes an album subtree and its memberships while retaining media objects. `chur_album_move` sets a parent and a position before a sibling, rejecting cycles and invalid targets. `chur_album_move_member` reorders one album's members. All-zero parent or before identifiers mean root or append, respectively. These mutations commit to the encrypted catalog and advance its generation. Query sort `4` reads an album's manual member order and is invalid for other scopes.

### 6.20 Atomic album placement, ABI 2.16

`chur_album_place_objects` accepts 1–100000 packed 16-byte object identifiers. A nonzero target identifies an existing album and requires an empty name and zero parent. A zero target creates a named album under the optional parent. A zero source and `move_members = 0` add the selection without removing other memberships. `move_members = 1` requires a source album and removes those memberships after placing every object in the target. Invalid, repeated, non-listable, or no-longer-in-source objects refuse the whole operation. Album creation, placement, source removal, revisions, and catalog generation commit in one SQLCipher transaction. On success, `out_album_id` receives the target identifier.

### 6.21 Tag management and selection edits, ABI 2.17

`chur_favorites_set` and `chur_tag_apply_selection` accept a nonempty, bounded array of packed 16-byte object identifiers. A zero tag id in `chur_tag_apply_selection` creates the named tag and requires `tagged = 1`; otherwise the existing tag is used and the name is empty. Both selection edits reject repeated or non-listable objects and commit once, without partial changes. `chur_tag_rename` and `chur_tag_delete` also update search projections in the same encrypted catalog transaction; deletion removes tag memberships while retaining media. Tag creation, rename, and deletion enforce the catalog name and count bounds.
When the caller's tag-list buffer is too small, `chur_tag_list` reports the required byte count and leaves that buffer unchanged so the host can retry.

### 6.22 Recoverable trash, ABI 2.18

`chur_trash_set` accepts a nonempty packed selection of 16-byte object identifiers and a strict boolean `restore`. The transaction moves all active objects to trash with a 30-day deadline on the trusted time of [catalog v18](../format/CATALOG_SCHEMA_V18.md), or restores all selected trashed objects. Invalid identifiers refuse the whole selection. Trash retains encrypted containers, key envelopes, metadata, tags, album memberships, and favourite flags. Scope 7 of `chur_catalog_query` lists trash newest first by deletion time; ordinary scopes and search hide it.

`chur_trash_restore_all` restores every unexpired entry in one transaction. `chur_object_delete` is the irreversible cryptographic erasure path. `chur_trash_empty` invokes it for every trash entry. Expired entries are purged on unlock and before catalog queries. An interrupted purge rolls forward at the next unlock. Final deletion may progress through several objects before an error; successful objects stay deleted and remaining entries stay in trash.

### 6.23 Staged recovery slot, ABI 2.19

[`../security/RECOVERY.md`](../security/RECOVERY.md) §8 commits a new recovery slot only after the user confirmed that the phrase was stored, and [`../security/PROVISIONING.md`](../security/PROVISIONING.md) §4 runs the presentation and confirmation "before the slot commits". `chur_vault_add_recovery_slot` commits before the host has shown anything, so a phrase lost on screen left a working slot that no one could use. `chur_vault_recovery_begin` seals a recovery slot, writes its phrase under the §6.5 rules, and holds the slot in the session without writing the descriptor; a second begin replaces the staged slot. `chur_vault_recovery_commit` writes the staged slot as one descriptor generation ([`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §9). The commit replaces every earlier recovery slot in the same descriptor generation. This is the RECOVERY.md §8 rotation: the replaced phrase stops opening the vault, and no descriptor generation carries neither phrase. A commit with nothing staged returns `CONFLICT`, and on a session that `chur_vault_lock` has locked it returns `VAULT_LOCKED`. Closing the session discards a staged slot, so a slot never committed is never written. `chur_vault_add_recovery_slot` is unchanged and serves callers with no presentation step. A creation needs neither call: its slot already waits in the creation handle, and the host calls `chur_vault_creation_activate` only after the phrase is confirmed.

### 6.24 Sync fork state, ABI 2.20

```c
chur_status_t chur_sync_fork_state(chur_handle_t session, uint64_t *out_detected,
                                   uint64_t *out_acknowledged);
chur_status_t chur_sync_fork_acknowledge(chur_handle_t session);
```

[`../sync/ROLLBACK_PROTECTION.md`](../sync/ROLLBACK_PROTECTION.md) §4 keeps a fork state per (vault, device) in the encrypted catalog until reconciliation or an accepted revocation clears it, and has the user told. `chur_sync_process` reports a fork only in the pass that found it (§6.8), so a host that restarted could not read the state again. `chur_sync_fork_state` writes how many device chains are `detected` and how many are `acknowledged`. `chur_sync_fork_acknowledge` moves every `detected` chain to `acknowledged` in one transaction, and changes nothing when none is detected. Neither call unfreezes a chain, returns evidence, or names a device, and both return `VAULT_LOCKED` on a locked session. A later record of a frozen chain is still refused as `SYNC_CHAIN_FORK` and leaves the state as it is, so a host tells a new fork from an acknowledged one by reading the state. A head rollback leaves no state here: the engine refuses the checkpoint and freezes no chain.

### 6.25 Local private notes, ABI 5.0

`chur_private_notes_query`, `chur_private_note_get`, `chur_private_note_save`, and `chur_private_note_change` take a session, a bounded request byte range, a writable destination, its capacity, and a `bytes_written` pointer. The destination capacity must be at least 1048576 bytes before any catalog mutation can begin. Requests are at most 1048576 bytes. Request and destination ranges must not overlap. Native temporary output is zeroized; the host must clear its output buffer after decoding.

All integers below are big endian. A string is a u32 byte count followed by UTF-8. Identifiers are 16 bytes. A note record contains identifier, revision u64, creation time u64, update time u64, deletion time u64 (`UINT64_MAX` means absent), pinned u8, format u8 (`0` plain text, `1` Markdown), attachment count u32, export byte count u64, title string, and body string. A summary uses the same encoding, with at most 160 Unicode scalar values in the body preview and the export size of the complete saved note.

| Call | Request | Successful output |
| --- | --- | --- |
| Query | Trash u8, limit u64, search string, cursor u32 length + bytes | Count u32, summary records, next cursor u32 length + bytes |
| Get | Identifier | Note record |
| Save | Identifier (all zero means create), expected revision u64, pinned u8, format u8, title string, body string | Committed note record |
| Change | Identifier, expected revision u64, action u8 | Committed note record, or zero bytes for purge |

ABI 5.0 adds attachment counts to the private-note record relative to published ABI 4.0, retaining explicit source format and caller-persisted transfer identities. This is an incompatible major-version change; every earlier-major host must refuse during the initial handshake, before exchanging payloads. Current hosts likewise reject earlier native majors. Hosts and native libraries must be released together. Unknown format values fail before any mutation. The discriminator is preserved by get/query/save/change, backups, restore, and selective encrypted archives.

Booleans are 0 or 1. Actions are 1 pin, 2 unpin, 3 trash, 4 restore, and 5 purge. Creation requires expected revision zero; updates require the current revision. Purge requires a trashed note. A stale revision fails without changing the note. See [catalog v9](../format/CATALOG_SCHEMA_V9.md) for input bounds, expiry, search, cursor bytes, and atomic index updates. These records do not enter media or sync/sharing operations.

`chur_private_note_export_begin(session, note_id, expected_revision, destination_fd, out_operation)` snapshots the saved revision and returns a normal operation handle. It duplicates the destination descriptor; ownership of the caller's descriptor stays with the caller. For format `0`, the exact output is UTF-8 title, two LF bytes, then UTF-8 body. For format `1`, it is the exact UTF-8 body with no prefix or suffix. The saved format and source belong to the same checked revision. The worker releases the session guard before destination writes, clears its plaintext buffer on completion, and uses the existing progress, cancellation, and close operations. Host publication requires successful completion and the same unlocked session generation. Cancel or lock discards an unpublished destination. Provider writes can still block as described for other descriptor exports. The selected destination or share receiver may retain plaintext after publication.

With attachments, export instead emits a UTF-8 `.churnote` JSON package:
`{"version":1,"title":"…","body":"…","format":"MARKDOWN|PLAIN_TEXT","attachments":[{"id":"32 lowercase hex","name":"basename","mimeType":"sniffed MIME","data":"standard padded Base64"}]}`.
The byte count is exact for the checked saved revision. Files and source are snapshotted together under the session guard. Notes without attachments retain the exact Markdown/plain-text behavior above.

`chur_private_note_attachment_export_begin(session, note_id, attachment_id, expected_revision, destination_fd, out_operation)` exports the exact original bytes of one note-owned file. It uses the same checked saved-revision snapshot, duplicated descriptor, unlocked-generation publication guard, cancellation and zeroization as complete-note export. Stale, purged, expired or locked notes fail before any provider write. Trash retains readable/exportable files until purge or expiry. No plaintext is returned through the control record or persisted in an intermediate cache.

`chur_private_note_attachments` uses the same pointer contract with a request limit of 16 MiB +512 KiB. All fields are big endian; strings and data are u32-length-prefixed. Commands:

| Command | Request after command u8 | Output |
| --- | --- | --- |
| 1 list | note ID | count u32, then attachment ID, filename string, MIME string, size u64 |
| 2 attach | note ID, expected revision u64, file | committed note record |
| 3 read | note ID, attachment ID | exact raw file bytes |
| 4 remove | note ID, expected revision u64, attachment ID | committed note record |
| 5 import | format u8, title/body strings, file count u32, files | new committed note record |

The same command entry point adds encrypted organization and history without changing the ABI 5 note record:

| Command | Request after command byte | Response |
| --- | --- | --- |
| `6` | `note_id:16` | organization |
| `7` | `note_id:16, expected_revision:u64, organization` | current note record |
| `8` | `note_id:16` | `count:u32`, then `revision:u64, updated_ms:u64, title:string, format:u8, attachment_count:u32` for each previous version, newest first |
| `9` | `note_id:16, expected_revision:u64, historical_revision:u64` | new current note record after atomic restoration |
| `10` | `note_id:16, historical_revision:u64, attachment_id:16` | original historical file bytes; requires 8 MiB output capacity |
| `11` | `note_id:16, historical_revision:u64` | historical note record (export size is source-only), organization, attachment metadata list using command 1 encoding |
| `12` | `trash:u8, limit:u64, terms:string, cursor:bytes, folder:string, tag:string` | existing note page encoding (count, records, cursor), then one organization per returned note in the same order |

Organization is `folder:string, tag_count:u32, tags:string[tag_count]`. Folder and tags are trimmed labels of at most 64 UTF-8 bytes without controls; folder may be empty, at most sixteen tags are sorted and deduplicated. Empty query folder/tag means any. Command 12 filters in SQL before pagination and binds both exact filters into its 65-byte cursor. Stored malformed or oversized metadata is rejected, including in authenticated archive catalogs. History keeps at most twenty prior versions and 64 MiB of deduplicated encrypted original file bytes per note. Command 9 commits the displaced state to history before recovering exact source/format, organization, and original files as a fresh CAS revision; Trash must be restored before a historical version can replace current content. Every command requires the unlocked session, rejects trailing bytes before mutation, and leaves caller output untouched on failure.

A file is attachment ID, filename string, MIME string, data bytes. Read requires an 8 MiB destination; other calls require at least 1 MiB before mutations. Maximum output capacity is 9 MiB. Native code independently validates 32 files, 8 MiB per file, 16 MiB total per note, basename-only filenames of at most 240 UTF-8 bytes, unique note-scoped IDs and byte-sniffed MIME. Import is one SQL transaction, including the note and all files. Attach/remove require an active note and its displayed revision; Trash retains readable files until purge/expiry. Outputs and temporary native copies are erased; hosts must erase file bytes after rendering or explicit export and must not persist private thumbnails. See [catalog v13](../format/CATALOG_SCHEMA_V13.md).

### 6.26 Selective encrypted archives, ABI 2.22

`chur_selective_export_begin` and `chur_selective_import_begin` take a session handle, request byte range and length, a host file descriptor, and an output operation handle. Export requires a writable destination; import requires a readable, seekable source. Native code duplicates the descriptor. The host keeps ownership of its own descriptor. Requests are at most 65536 bytes. The caller must supply a writable output handle and valid, non-overlapping request memory under the normal C pointer contract.

All integers are big endian. Both requests start with version u8 = 1 and a password field (u32 byte count, then UTF-8). The password follows the existing password profile and has at most 1024 bytes. Export then contains object count u32 + 16-byte identifiers, album count u32 + 16-byte identifiers, note count u32 + pairs of 16-byte identifier and expected revision u64, and maximum output bytes u64. Each explicit count is at most 1000. Import has no fields after the password. Unknown versions, extra bytes, invalid identifiers or revisions, and out-of-range fields fail closed. The host clears the encoded request after the call; native ownership uses zeroizing password storage.

Export resolves selected album subtrees and deduplicates original objects. At most 1000 albums and 10000 originals may be expanded. It validates saved note revisions and binds the plan to the source catalog generation. It copies content into a fresh temporary encrypted vault with independent keys and identifiers, then emits an ordinary CHURBAK1 package. No source descriptor, root, device identity, sync state, unrelated row, or original ciphertext is copied. Native output cannot exceed the supplied byte limit, including final package records, and is made durable before success.

Import restores and verifies the complete package in isolated encrypted staging before it adds anything to the open destination. It creates new identifiers and preserves existing entries. Each committed original with its display metadata, or complete note row, remains durable if a later step fails or cancellation stops the job. Tags, previews, and final album organization may remain incomplete, including newly created empty albums. The [product contract](../product/SELECTIVE_ENCRYPTED_EXPORT.md) specifies metadata selection, names, and the two ways to open an archive.

The operations belong to the open session. They use the existing poll/cancel/close surface. `processed` counts committed originals plus notes, not bytes; `total` is zero until the plan is known. Authentication and packaging do not replace item counts with byte counts. A terminal failure retains its completed-item count. Source readers use the normal deletion and lock revocation barrier. Selective catalog snapshots have a 4 GiB verification bound. SQLCipher page authentication runs as one stage, with cancellation before and after the scan; container verification and copying check cancellation between chunks. A blocked OS write has the existing descriptor-export limit. The host checks the session generation and successful completion before it publishes an export, and discards unpublished output on any refusal.
### 6.26.1 External file encryption, ABI 2.23

`chur_external_archive_begin(runtime, request, length, source_fds, source_count, destination_fd, out_operation)` creates a normal CHURBAK1 archive without an open session. It works with no installed vault or while the vault is locked. It never changes an installed catalog, descriptor, or object store. The archive has fresh vault keys and object identifiers; files are opaque originals. Existing restore and selective import read the result.

The request is at most 128 KiB. Its big-endian fields are version `u8 = 1`, password (`u32` byte count and at most 1024 canonical UTF-8 bytes), maximum output bytes `u64` (1 through `i64::MAX`), and file count `u32` (1 through 32). Each file has a UTF-8 basename (`u32` byte count, 1 through 1024 bytes), media-type hint (`u32` byte count, at most 255 bytes), and known-length flag `u8` (0 or 1), followed by length `u64` when 1. Names reject path separators, control characters, `.` and `..`. Empty or invalid media-type hints become `application/octet-stream`. Trailing fields and unknown versions fail closed. Known lengths and actual aggregate input have a 4 GiB bound. A changed declared length fails. Empty files are supported.

Native code duplicates every descriptor before returning. The host owns its descriptors and keeps their shared offsets exclusive until terminal. Sources need only support reads; a source may be a provider pipe. The writable, seekable destination must be empty at offset zero and must not refer to any source inode. Source bytes are never changed. Provider streams use the cancellable descriptor policy in §13. Android bridges provider files to pipes or stages encrypted archive output in private storage before publication. Cancellation is checked during stream readiness waits and between reads, encrypted chunks, and archive records. The host removes unpublished output on failure or cancellation and publishes only after terminal success. The source URI grant remains alive until terminal.

The operation belongs to the runtime and uses the existing poll, cancel, and close calls. Runtime close cancels and joins it; locking an unrelated session does not change it. Progress counts actual input bytes; the total is zero when a length is unknown, then becomes the completed aggregate at packaging. Packaging retains the byte count. The worker uses only bounded zeroizing plaintext memory and an isolated encrypted temporary vault under the trusted private runtime root. No plaintext scratch file is created. One external archive operation may hold the staging claim per runtime root. Cleanup validates its directory boundary and a process restart sweeps abandoned encrypted staging while an advisory claim prevents a second runtime from sweeping live work. Output bytes, including final package records, cannot exceed the caller's budget. Native code synchronizes the destination before success.

### 6.27 Own-device pairing and media transfer

These calls use the current ABI and require an unlocked session. All integers use big-endian order. A variable field is `length:u32 || bytes`; a string is a variable UTF-8 field. Pairing responses start with `version:u16 = 2`. Callers own all buffers. Root and private device keys never cross the boundary. The approval input is at most 16 MiB; larger inputs fail before parsing.

| Function | Input | Response after version |
| --- | --- | --- |
| `chur_device_pairing_prepare` | Empty | Variable request, fingerprint string |
| `chur_device_pairing_inspect` | Exact 210-byte request | Vault ID, new device ID, fingerprint string |
| `chur_device_pairing_approve` | Version 2, variable request, time `u64` | Variable checkpoint, enrollment, operation, encrypted approval |
| `chur_device_pairing_start` | Encrypted approval | Vault ID, device ID, variable enrollment, checkpoint |
| `chur_device_pairing_finish` | Time `u64` | Installed device ID |
| `chur_device_pairing_overview` | Empty | Count `u32`, then device ID, fingerprint string, active `u8`, current `u8`, retry-available `u8` per device |
| `chur_device_pairing_revoke` | Target device ID, time `u64` | Variable checkpoint, revocation, operation |
| `chur_device_pairing_checkpoint` | Time `u64` | Raw canonical signed checkpoint; no response version prefix |

IDs are 16 bytes. Boolean bytes are exactly zero or one. Retry-available means this catalog has a locally authored cached revocation; an inactive peer without it has no retry action. Approve and revoke persist retry artifacts with their catalog changes. Start authenticates the address-free approval before any peer connection. Finish installs an ordinary identity only after native verification accepts the approved membership and checkpoint ancestry. A restored recovery identity cannot sign enrollment. The UI transfers encrypted approval files, because membership proof histories can exceed a practical pasted-code limit.

Own-vault media calls use the same bounded control-buffer signature:

| Function | Input | Response |
| --- | --- | --- |
| `chur_own_sync_collections` | Empty | Version 1, count `u32`, local collection IDs |
| `chur_own_sync_operations` | Last acknowledged sequence `u64` | Version 1, count `u32`, then sequence `u64` and variable signed operation |
| `chur_own_sync_author` | Collection, object, store IDs; container length `u64`; SHA-256 (32 bytes) | Existing source-object page format |
| `chur_own_sync_plan` | Collection ID | Existing shared-receive-plan format |

Author verifies the immutable ciphertext before it creates key-free ordinary CreateObject and CommitObject operations. The host uploads the ciphertext before it publishes those operations, and persists its push cursor only after each relay acknowledgement. Receive uses the existing bounded download and full-container verification calls. Disposable object keys use authenticated current vault membership for same-vault delivery; an empty issuer bundle grants no cross-vault permission.

### 6.28 Local encrypted content index, ABI 2.24

`chur_content_index_candidates`, `chur_content_index_put`, and `chur_content_index_clear` use `(session, request, request_len, destination, capacity, written)`. They require an unlocked session. A caller provides a writable 1 MiB destination for every call, including calls with empty responses. Native code sets `written` to zero and checks output capacity and pointers before a mutation. Input is at most 262208 bytes. All integers below are big endian. IDs are 16 bytes. Strings use a `u32` UTF-8 byte count followed by bytes. Unknown versions, trailing bytes, invalid UTF-8, and unknown flags fail closed.

| Call | Request | Response |
| --- | --- | --- |
| Candidates | `version:u8=1`, `rebuild:u8` (0 or 1), `after_object_id:16 bytes`, `limit:u32` (1 through 100) | `version:u8=1`, `count:u32`, then object ID, primary stream ID, media class `u8`, original size `u64`, content-type string per item |
| Put | `version:u8=1`, object ID, expected primary stream ID, status `u8` (1 complete, 2 partial), engine version `u32=1`, text string | Empty |
| Clear | `version:u8=1` | Empty |

An all-zero candidate cursor starts the scan; all object and source IDs in responses are nonzero. Candidates use a stable ascending object-ID keyset, independent of catalog-generation changes made by indexing. A normal scan excludes current indexed sources; rebuild includes them. Complete and partial records both count as indexed. Supported originals are images and opaque files with image, PDF, text, JSON, or XML content types. Candidates exclude Trash, hidden/deleted objects, and quarantined objects. Put checks lifecycle, integrity, and the immutable original stream again within its write transaction; a stale source returns `CONFLICT`. Text rejects NUL and has a 256 KiB UTF-8 byte limit. No recognized text is returned by these calls. Clear removes content text, rebuilds metadata-only search, and completes the WAL checkpoint before success. These records are local derived state; they allocate no synchronization operation or archive field.

### 6.29 Atomic album removal, ABI 2.25

`chur_album_remove_objects(session, album_id, object_ids, object_count)` removes a selection from one album. `object_ids` contains 1 through 100000 distinct packed 16-byte identifiers. The album and every membership must exist. A stale membership returns `CONFLICT`; a malformed or repeated identifier returns `INVALID_INPUT`. One transaction removes all selected memberships and advances the album revision and catalog generation. A failed transaction keeps all memberships. Original files and membership in other albums remain intact. Synchronization records, when required, commit with the removal.

## 7. Buffer ownership

Each function specifies:

- allocating side;
- writable/readable range;
- alignment;
- maximum capacity;
- whether bytes remain valid after return;
- whether zeroization is required;
- whether concurrent reuse is allowed.

Default data-plane policy: caller allocates a bounded mutable buffer, Rust writes authenticated plaintext, validity ends when caller reuses/frees it. Rust never retains the pointer after return.

## 8. Threads and blocking

Native FFI calls are synchronous. v1 exposes no callback-based call (§10). KMP wraps blocking work on a dedicated I/O dispatcher. Rust may use internal workers but must not call arbitrary Kotlin/Swift code while holding secret locks.

Thread affinity is a property of the handle type, not of the creating thread. No handle is bound to the thread that created it:

| Handle | Callable from | Concurrent calls on one handle |
| --- | --- | --- |
| `RuntimeHandle` | any thread | serialized inside Rust |
| `VaultSessionHandle` | any thread | serialized per session |
| `ObjectReaderHandle` | any thread, explicitly including a thread other than its creator | serialized per reader in v1; parallel only when `CHUR_CAP_CONCURRENT_READS` is set, which requires benchmarks and correctness tests first |
| `ImportHandle` | any thread | one call at a time; a second concurrent call returns `CONFLICT` |
| `ExportHandle` | any thread | one call at a time; a second concurrent call returns `CONFLICT` |
| `IntegrityScanHandle` | any thread | one call at a time; a second concurrent call returns `CONFLICT` |

`chur_operation_cancel` and every `*_close` are exempt: they are callable from any thread at any time, including while another call on the same handle is in flight, and they never wait on that call. The registry lock is therefore per slot and is never held across user work, so a Media3 loader thread and an `AVAssetResourceLoader` queue may both drive a reader they did not create.

### 8.1 Vault-level concurrency

The table above bounds calls on one handle. These rules bound a vault, and no other document restates them:

- one process opens a vault. The runtime takes an exclusive advisory lock on the descriptor file for the life of the session; a second process that cannot take it returns `CONFLICT` and attempts no slot unwrap, so a split Android process or a second launch cannot corrupt the catalog;
- a vault directory whose descriptor is not installed yet, of a creation that waits for its recovery phrase or of a restore that is still writing, is held by the same kind of exclusive advisory lock, on a `lock` file inside the directory, until the install or the removal. The orphan sweep at runtime open ([`../security/PROVISIONING.md`](../security/PROVISIONING.md) §9) removes only a directory whose lock it can take, and it is best-effort: a directory it cannot remove never stops the runtime from opening;
- one runtime per process (§14), so a second iOS scene or a second Android task shares the one session rather than opening its own. There is no per-scene vault state;
- catalog writes are serialized by one writer mutex per session. Reads run on the writer's connection in v1, which is why every reader handle is serialized in the table above. A read pool is a later change gated on `CHUR_CAP_CONCURRENT_READS` and does not alter this contract, because callers must already tolerate serialized reads;
- at most one unlock is in flight per runtime. A `chur_vault_unlock` arriving while another is running returns `CONFLICT` before deriving anything, so a double-tapped unlock button never starts two derivations;
- the Argon2id semaphore is 1 for the whole process. No two Argon2id evaluations ever run at once, whatever requested them: one evaluation is the largest allocation the runtime makes, and two at once on a low-memory device is the fastest way to be killed by the platform;
- several import, export, and scan operations may run at once. The bound is the concurrent `ImportTransaction` limit of [`../format/CATALOG_SCHEMA_V1.md`](../format/CATALOG_SCHEMA_V1.md) §21;
- `ObjectReaderHandle` is therefore safe to call from a Media3 loader thread and from an `AVAssetResourceLoader` queue, including a thread that did not create it, with no lock added by the caller.

## 9. Cancellation

Long operations accept a cancellation handle/token or expose cancel functions. Lock cancellation has higher priority than ordinary caller cancellation.

Cancellation guarantees:

- no new plaintext after cancellation observed;
- partial ciphertext remains temp/journaled, not active;
- no progress snapshot advances after the terminal flag is set;
- exactly one terminal result;
- cancellation maps to `CANCELLED`, not corruption.

## 10. Progress reporting

v1 has no foreign callbacks. Rust never calls Kotlin, Swift, or Objective-C code, so there is no delivery thread, no re-entrancy rule, and no consumer-disappearance race to specify. The caller polls its own operation handle:

```text
chur_operation_poll(operation, out_progress) -> chur_status_t
```

- polling is synchronous and cheap: it takes the per-slot lock only long enough to copy a snapshot, and never waits on the operation;
- the caller polls on its own dispatcher or queue, at a rate it chooses, and republishes to the UI on the platform's main thread. The delivery thread is therefore the caller's, by construction;
- `ChurProgressV1` contains only bounded non-private numbers: operation kind, encrypted or plain bytes processed when safe (for an integrity scan or a re-encryption, the number of objects), total bytes if known, stage code, terminal flag, and the terminal status. A terminal successful import also carries the object identifier it activated;
- once the terminal flag is set the snapshot is frozen; every later poll returns the same terminal result until the handle is closed, so exactly one terminal result is observable;
- polling a stale-generation handle returns `SESSION_EXPIRED` rather than a partial snapshot;
- no filename, path, album, or real/decoy identity appears in progress. The one identifier this section admits is the object a terminal successful import activated: the caller that began the import needs it to attach the derivatives the media pipeline produces next, and it is an opaque value the caller's own object queries already return for that object.

A callback data plane would need a delivery-thread contract, a re-entrancy rule, and a release race against a disappearing consumer. Adding callbacks later is a minor-version addition behind a capability bit.

## 11. Errors

Every exported function that can fail returns `chur_status_t`, the `int32_t` status registered in [`../ERROR_MODEL.md`](../ERROR_MODEL.md), which owns every error name and value. `0` is success. Results never share the status channel: a byte count, a handle, or a projection is written through an out-parameter. Error strings are diagnostic-only and redacted, and this contract adds no code of its own.

An unrecognized value maps to `INTERNAL_FAILURE`.

The FFI artifacts build with `panic = "unwind"`; abort is not used. Every exported symbol wraps its whole body in `catch_unwind`, and one that returns `chur_status_t` converts a caught panic into `INTERNAL_FAILURE`.

The handshake exports of §2 have no status channel: they return a scalar and cannot fail. Each one instead returns a value the host already refuses, frozen by [ADR-0037](../adr/0037-contain-panics-in-channel-less-exports.md): `0` for either version component, an inclusive range whose minimum is `0xFFFF` and whose maximum is `0` for either format range, `0` for the capability mask, and `0` for the build flavor, which sets neither the release nor the debug bit. Containment is therefore visible to the host rather than silent, and no export is exempt. This is unconditional: every export, no "where applicable" exemption, verified by panic injection at each symbol. The panic payload is dropped inside the boundary and no payload text crosses it, the handle that owned the call is invalidated so a later call on it also fails, and a panic hook records a synthetic-reproduction diagnostic with no private values. Abort is rejected because it converts a contained, redactable failure into a process kill that skips session zeroization and removes the public shell along with the vault ([ADR-0016](../adr/0016-freeze-the-v1-c-abi.md)).

## 12. Secrets across FFI

Allowed only when unavoidable for a key-slot operation:

- bounded mutable byte buffers;
- exact length validation;
- no string conversion;
- no JSON/serialization;
- immediate best-effort clearing on foreign side;
- Rust secret wrapper on receipt;
- no callback echo.

Object/collection/root keys never return to application feature code.

## 13. File descriptor ownership

For each import/export call define whether Rust duplicates or consumes the descriptor. Preferred:

- platform opens descriptor;
- adapter passes it with explicit ownership flag;
- Rust duplicates when needed for asynchronous lifetime;
- original closes deterministically;
- non-seekable capability communicated explicitly;
- no integer descriptor persisted after operation.

Native stream endpoints must be app-owned. The Android broker mediates every provider descriptor, including provider pipes and sockets, because a provider that retains the same endpoint could change shared status flags. The app-owned pipes and sockets use nonblocking I/O. Native workers check cancellation at most every 50 ms while waiting for readiness; a stream with no progress for 30 seconds fails with `IO_FAILURE`. Cancellation returns `CANCELLED` and joins the worker before session cleanup completes. All owned operations receive cancellation before any worker is joined.

A duplicated descriptor shares status flags and offsets with the original. The host must not perform I/O or change flags through any duplicate until the operation ends. Native code sets `O_NONBLOCK` on streams and leaves it set; the host closes its descriptor on its own schedule. Seekable archive and backup APIs require regular files. On Android, native code rejects FUSE descriptors before metadata or I/O calls: the platform must bridge them through a pipe or stage them in app-private storage. It reads kernel proc mount records for this check because `fstat` and `fstatfs` can themselves call an untrusted provider. Regular-file syscalls and platform provider-open calls remain subject to OS filesystem latency; the stream cancellation bound does not cover them.

## 14. Packaging

Android loads ABI-specific native libraries through the application shell/JNI adapter. iOS links one Rust static library/XCFramework instance. Duplicate Rust runtimes in one process are forbidden unless an ADR proves safety.

## 15. Tests

- ABI mismatch and unknown capabilities;
- invalid/null/misaligned/oversized buffers;
- double close and leaked handle cleanup;
- lock during read/import/export/verify/migrate;
- panic injection;
- poll after the terminal result, after close, and after lock;
- file descriptor closed early/non-seekable;
- cancellation at every stage;
- no secret values in errors/logs;
- Android/iOS byte-equivalent behavior.

### Disposable object-key delivery

`chur_object_key_request`, `chur_object_key_issue`, and `chur_object_key_accept`
use the same buffer contract: `(session, input, input_length, destination,
capacity, bytes_written)`. Inputs are bounded to 16 MiB. The output count is
zero on failure. The caller checks output capacity before any key mutation.

- Request input is `collection_id[16] || object_id[16]`. A ready local key returns
  one zero byte. Otherwise the result is `0x01 || ObjectPrekey[226]`. The request
  must match an authenticated pending Commit and must have no local tombstone.
- Issue input is `ObjectPrekey[226]`. The result is `ObjectKeyGrant[346]`. The
  canonical source checks current recipient membership and the exact object
  generation and container commitment before it signs a grant.
- Accept input is `u32(package_length) || acceptance_package || u32(346) || grant`.
  The package supplies authenticated source membership evidence. On success the
  output is empty. Native acceptance stores a local encrypted object key and
  destroys the private prekey in one transaction, then checks the WAL erasure
  barrier. The transport acknowledges the grant only after this call succeeds.

The JNI names are `objectKeyRequest`, `objectKeyIssue`, and `objectKeyAccept`.
Collection-operation logs contain object-key commitments and no wrapped object
keys. Collection keys can decrypt metadata only.

### Open readers and permanent erasure

Permanent deletion revokes every reader for that object in the same physical vault. It waits for an in-flight read, removes its retained stream keys and cached plaintext, and completes the durable catalog erasure barrier before it reports success. Subsequent size, information, read, and verification calls return `SESSION_EXPIRED`. Reader close stays idempotent. Readers for other objects remain usable. Reader registration and deletion take a shared lifecycle mutex after the session lock. This covers different session handles for the same physical vault, so a reader cannot escape revocation between opening its key and publishing its handle. Ordinary reads do not take the lifecycle mutex. Close and owner teardown use the same barrier and clear a retained reader even if an in-flight call still owns its Arc. Once owner teardown starts, prepared child handles cannot be registered.


### 6.30 Caller-persisted transfer identities, ABI 3.0

`chur_import_begin` receives `ChurImportRequestV2`, whose first field is an optional pointer to 16 readable bytes naming a caller-generated random object ID. The ID is copied synchronously; it never borrows caller memory on the worker. A null pointer requests ordinary random allocation. A committed object, retained tombstone, or live journal reservation refuses reuse before any object key is created. Abandoned imports may be retried with the same ID and fresh keys/nonces. The committed catalog ID itself is the durable outcome record, so a desktop can resolve a lost response after reconnecting without creating another object.

`chur_album_create(session, name, name_length, requested_album_id, out_album_id)` similarly accepts an optional random ID. Replaying an existing matching ID/name returns the existing ID without resetting its placement or membership; conflicting metadata is `INVALID_INPUT`. The desktop records folder IDs before creation and reapplies parent placement on resume.

This is an incompatible native ABI change: the caller-persisted identity layout was introduced in ABI 3.0. Current bundled C/JNI/Kotlin/iOS callers use ABI 7.1, which retains this layout and adds private-note format; the host rejects every earlier major. The encrypted container, catalog and key-slot formats do not change. Desktop protocol version 2 requires these transfer identities and identifies the open vault during pairing; no version-1 control compatibility path is retained.

### Direct peer IO

`chur_peer_call` is a bounded input/output call owned by an unlocked session. Buffers remain caller-owned and no pointer is retained. The first input byte selects listen (1), connect (2), poll (3), queue frame (4), receive frame (5), close (6), flush (7), canonical device-history page (8), active-device check (9), locally retained pairing evidence (10), object key for the peer (11), or object ciphertext range for the peer (12). The input is capped at 4 MiB + 256 bytes. Receive requires capacity 4 MiB + 1; history requires 512 KiB; pairing evidence requires 8192 bytes; an object key requires 346 bytes; a ciphertext range requires 1 MiB; other commands have fixed small outputs. Capacity is checked before any mutation, so callers never replay IO for buffer sizing.

Listen takes a canonical string that contains the literal interface IP to bind. An empty body, an unspecified address, or a multicast address fails with `INVALID_INPUT`, so the listener never binds all interfaces. Listen returns `port:u16 || secret[32]`. Poll on a listener returns true only after a connection proves the invitation secret with its first frame, and that frame is the signed authentication record of the connector. Native code consumes the record; receive never returns it. Connect takes a canonical string containing a literal IP, a port `u16`, and a 32-byte invitation secret. Poll/flush return a canonical boolean byte. Queue takes one length-prefixed frame. Receive returns an availability byte and, when available, one fully authenticated plaintext frame. Close has no body. History takes `device_id[16] || after:u64 || until:u64` and returns `count:u32` followed by sequence `u64` and variable canonical record per entry. Check (9) with an empty body returns the 16-byte device ID that the signed handshake transcript authenticated; it requires capacity 16. Object key (11) takes one encoded object-key prekey and returns the 346-byte grant. The prekey must name the local vault and the authenticated device as its recipient, otherwise the call fails with `AUTHENTICATION_FAILED`. Range (12) takes `object_id[16] || offset:u64 || max_bytes:u32` and returns at most `max_bytes`, and at most 1 MiB, of the committed object ciphertext. The object must be in a local collection, as object key (11) also requires. The range is read from the same container handle whose manifest and final commit were authenticated. On a restored device with a pending approval, object key (11) checks the recipient against the local membership only. It therefore refuses a device that the local membership does not hold yet; this fails closed until pairing finishes. The earlier body of one device ID still works and succeeds only when that ID equals the authenticated device. Listen and connect load the local enrolled signer and the active member keys from the catalog, and fail with `RECOVERY_REQUIRED` when the device has no ordinary or approved identity. Poll returns true only after the remote device signature verifies; queue, receive, history, object key, and range fail or return nothing before that point. Each call that serves or accepts data checks the authenticated device again against the membership that is trusted at that time: a ready poll, queue, a receive that returns a frame, flush after authentication, history, check, object key, and range. A device revoked after the handshake fails that call with `AUTHENTICATION_FAILED`, and the connection closes. A transport or authentication failure closes the connection. A request-level failure of history, object key, or range after authentication, for example an absent or deleted object, an offset past the end, or a reused or stale key request, is returned and the connection stays open, so the caller can send an error response and continue. For a restored device with a verified pending approval, the trusted membership is the newer of the local membership and the approval authority. The peer wire protocol is version 2 (ADR-0067). A connector that receives a version-1 hello fails with `UNSUPPORTED_VERSION`. A listener refuses a connection with a version-1 hello as a failed connection; it reports `UNSUPPORTED_VERSION` only if the invitation then closes without a proven connection. All integer encodings are big-endian.

There is one ephemeral connection per session. Vault lock, session close, runtime close, and panic invalidation close it even if an app coroutine has not completed. Every call rechecks the unlocked session before IO. Android JNI and iOS cinterop map the same export. Pairing control records and the encrypted approval credential payload are version 2 and include no network endpoint or transport token.

Pairing-evidence command 10 has empty input and returns a presence byte followed, when present, by the current version-2 `DevicePairingCredentials` record. Native code revalidates the encrypted catalog approval before returning it. A finalized or absent approval returns only zero. No network connection is opened or recovered.


### 6.31 Portable JPEG XL decoding, ABI 7.1

`CHUR_CAP_JPEG_XL` enables `chur_jpeg_xl_open`, `chur_jpeg_xl_open_fd`,
`chur_jpeg_xl_render`, and `chur_jpeg_xl_close`, as declared in `chur.h`.
These additions keep major ABI 7 and all vault and sync formats unchanged.
A host checks ABI 7.1 and capability bit 9 before it calls the decoder.

The decoder accepts a borrowed authenticated direct buffer or a borrowed
seekable FD. It reads an FD from offset zero with positional IO, closes only
its duplicate, and does not change the caller's offset. It retains no caller
pointer. Android providers without positional IO use a bounded transient
direct buffer. No plaintext temporary file is required.

One typed generational handle owns each decoder. Calls on that handle,
including close, are serialized; work may run on any host worker thread.
A host closes the decoder when viewing stops, on cancellation, on vault lock,
and on memory pressure. Close is idempotent. The decoder has no session,
keys, storage authority, or access to other objects.

Open reports oriented source width, height, displayed frame count, and the
animation repeat count (zero means infinite). Render writes caller-owned
RGBA8 sRGB with straight alpha and reports the frame duration in milliseconds.
This is an SDR display path. It preserves source aspect ratio, never upscales,
and samples at a maximum edge of 1..4096. The host clears and releases each
output after it copies the pixels to a platform surface.

The source ceiling is 64 MiB encoded, 16384 per edge, 64 Mi pixels, 1024
displayed frames, and 4096 internal frames. Source dimensions are checked
before decoder initialization. Encoded and expanded ICC profile declarations
are each capped at 1 MiB; the retained header prefix is at most 2 MiB.
Ancillary container boxes are skipped before pixel decoding, including
compressed metadata. Decoder grid storage has a 256 MiB allocation tracker.
Other allocations remain bounded by input, ICC, prefix, and frame limits;
the tracker alone is not a process-wide memory limit.

Malformed or incomplete image payloads fail with fixed status codes. The
boundary contains panics and validates handles before access. It never
returns decoder error strings. Rust clears its 4 KiB IO and raster row
buffers. Upstream decoder grids have no secure wipe API: close releases them
but does not prove allocator zeroization. The host also releases the platform
image surface when the vault locks.


## Local video resume positions (ABI 7.2)

`chur_playback_position_get(session, object_ref, out_position_ms)` reads one
bounded scalar from the encrypted catalog. Absent or stale state returns zero.
The output is zeroed before handle or object validation. A null reference or
output returns `INVALID_INPUT`. An inactive or non-video object is refused.

`chur_playback_position_put(session, object_ref, position_ms, duration_ms)` writes
one observation. Both scalars are unsigned milliseconds; duration is 1 through
14,400,000 and position must not exceed the observed or canonical duration.
Zero clears the saved position. Object generation, original stream revision and
canonical duration bind the record to its source. No pointers are retained.
Calls hold the existing session mutex and fail when the session is locked.
Hosts negotiate minor version 2 before either call. The Kotlin repository also
requires the captured session generation before it reads or writes a position.
See [catalog v17](../format/CATALOG_SCHEMA_V17.md) for migration and deletion.

### 6.32 Re-encryption after a revocation, ABI 7.3

```c
chur_status_t chur_reencryption_begin(chur_handle_t session, chur_handle_t *out_operation);
chur_status_t chur_reencryption_counts(chur_handle_t session, uint64_t *out_pending,
                                       uint64_t *out_failed);
```

[ADR-0069](../adr/0069-re-encrypt-objects-after-revocation.md) and [`../sync/REVOCATION.md`](../sync/REVOCATION.md) §3.2 define the work. `chur_reencryption_begin` starts one pass as an operation of kind `CHUR_OPERATION_REENCRYPTION` (6). The host starts it after unlock, while the application is in the foreground, and polls, cancels, and closes it like any operation; a lock cancels it. `processed` and `total` count objects. The pass holds the session for one chunk or one catalog step at a time, so other calls on the session proceed while it runs. A pass ends with success when objects failed; `chur_reencryption_counts` then reports them in `out_failed`, with the objects still to re-encrypt in `out_pending`. Both counts are zero in an identity with no completed rotation that it owns. `chur_vault_unlock` does no re-encryption.

