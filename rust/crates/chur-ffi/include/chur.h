/*
 * chur.h - the stable C ABI of the Chur native library.
 *
 * This header is hand-written and is the authority for the C side of the
 * boundary. No binding generator produces it, and a generated header must not
 * become the canonical protocol definition (docs/interop/FFI_CONTRACT.md,
 * ADR-0016). A change here and a change in rust/crates/chur-ffi/src/lib.rs land
 * in the same commit.
 *
 * This header declares the Phase-1 surface: the ABI handshake of
 * FFI_CONTRACT.md section 2, the status vocabulary of docs/ERROR_MODEL.md, the
 * control plane and data plane of section 6.2, the product surface of section
 * 6.5, the Android Keystore surface of section 6.6, and the portable backup
 * surface of section 6.7, the sync inbox surface of section 6.8, and the
 * sharing identity surface of section 6.9, and the share preparation surface
 * of section 6.10, the share acceptance surface of section 6.11, and the
 * recipient revocation surface of section 6.12, and the authenticated
 * recipient-device surface of section 6.13, and the sharing discovery surface
 * of section 6.14, and the private tag list of section 6.15. Adding an export raises the minor
 * ABI version; changing or removing one raises the major. The library reports
 * 7.0. Pairing control payloads are version 2 and contain no service credentials.
 */

#ifndef CHUR_H
#define CHUR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Status
 *
 * The ABI representation of an error is int32_t. 0 is success and is not an
 * error code, every defined value is positive, 1-99 are permanently
 * unallocated, 700-899 and 1000 upward are reserved for future allocation, and
 * an unrecognized value maps to CHUR_INTERNAL_FAILURE. A code is added by
 * editing the table in docs/ERROR_MODEL.md in the same change that adds it
 * here.
 * ---------------------------------------------------------------------- */

typedef int32_t chur_status_t;

#define CHUR_OK 0

#define CHUR_AUTHENTICATION_FAILED 100
#define CHUR_PLATFORM_KEY_UNAVAILABLE 101
#define CHUR_PLATFORM_KEY_INVALIDATED 102
#define CHUR_RECOVERY_REQUIRED 103
#define CHUR_VAULT_LOCKED 104
#define CHUR_SESSION_EXPIRED 105
#define CHUR_PROTECTED_DATA_UNAVAILABLE 106
#define CHUR_KDF_MEMORY_UNAVAILABLE 107
#define CHUR_UNLOCK_DELAYED 108

#define CHUR_CANCELLED 200
#define CHUR_INVALID_INPUT 201
#define CHUR_RESOURCE_LIMIT_EXCEEDED 202
#define CHUR_PERMISSION_DENIED 203
#define CHUR_NOT_FOUND 204
#define CHUR_CONFLICT 205
#define CHUR_SYNC_CHAIN_FORK 206
#define CHUR_SYNC_HEAD_ROLLBACK 207

#define CHUR_UNSUPPORTED_VERSION 300
#define CHUR_UNSUPPORTED_SUITE 301
#define CHUR_NON_CANONICAL_ENCODING 302
#define CHUR_ABI_INCOMPATIBLE 303
#define CHUR_MIGRATION_REQUIRED 304
#define CHUR_MIGRATION_FAILED 305

#define CHUR_VAULT_INCOMPLETE 400
#define CHUR_VAULT_CORRUPT 401
#define CHUR_OBJECT_INCOMPLETE 402
#define CHUR_OBJECT_CORRUPT 403
#define CHUR_CATALOG_CORRUPT 404

#define CHUR_IO_FAILURE 500
#define CHUR_STORAGE_UNAVAILABLE 501
#define CHUR_SOURCE_NOT_SEEKABLE 502
#define CHUR_SOURCE_DOWNLOAD_REQUIRED 503

#define CHUR_NETWORK_FAILURE 600

#define CHUR_INTERNAL_FAILURE 900

/* -------------------------------------------------------------------------
 * Integrity states
 *
 * Range and complete-object verification are domain states, not errors. These
 * are the values chur_object_reader_verify_complete writes through out_state,
 * and the same values the catalog object row persists
 * (docs/format/CANONICAL_ENCODING_V1.md section 15.4). Proven corruption is a
 * lifecycle change and reaches a caller as CHUR_OBJECT_CORRUPT instead.
 * ---------------------------------------------------------------------- */

#define CHUR_INTEGRITY_UNVERIFIED 0x01
#define CHUR_INTEGRITY_VERIFYING 0x02
#define CHUR_INTEGRITY_RANGE_VERIFIED 0x03
#define CHUR_INTEGRITY_COMPLETE_VERIFIED 0x04
#define CHUR_INTEGRITY_INCOMPLETE 0x05
#define CHUR_INTEGRITY_QUARANTINED 0x06
#define CHUR_INTEGRITY_UNSUPPORTED 0x07
#define CHUR_INTEGRITY_MIGRATION_REQUIRED 0x08

/* -------------------------------------------------------------------------
 * Capability bits, returned by chur_capabilities().
 *
 * An unknown set bit is ignored and never enables behaviour. Bits 10 to 63 are
 * reserved and are zero in v1.
 * ---------------------------------------------------------------------- */

#define CHUR_CAP_DECOY_VAULT (UINT64_C(1) << 0)
#define CHUR_CAP_OBJECT_READER (UINT64_C(1) << 1)
#define CHUR_CAP_SEQUENTIAL_READER (UINT64_C(1) << 2)
#define CHUR_CAP_INTEGRITY_SCAN (UINT64_C(1) << 3)
#define CHUR_CAP_BACKUP_PACKAGE (UINT64_C(1) << 4)
#define CHUR_CAP_SYNC (UINT64_C(1) << 5)
#define CHUR_CAP_CONCURRENT_READS (UINT64_C(1) << 6)
#define CHUR_CAP_COLLECTION_SHARING (UINT64_C(1) << 7)
#define CHUR_CAP_SHARED_OBJECTS (UINT64_C(1) << 8)
#define CHUR_CAP_JPEG_XL (UINT64_C(1) << 9)

/* -------------------------------------------------------------------------
 * Build-flavor bits, returned by chur_build_flavor().
 *
 * A release application refuses a library with CHUR_FLAVOR_DEBUG_ASSERTIONS or
 * CHUR_FLAVOR_TEST_HOOKS or CHUR_FLAVOR_INTERNAL_PQ set.
 * ---------------------------------------------------------------------- */

#define CHUR_FLAVOR_RELEASE (UINT32_C(1) << 0)
#define CHUR_FLAVOR_DEBUG_ASSERTIONS (UINT32_C(1) << 1)
#define CHUR_FLAVOR_TEST_HOOKS (UINT32_C(1) << 2)
#define CHUR_FLAVOR_INTERNAL_PQ (UINT32_C(1) << 3)

/* -------------------------------------------------------------------------
 * Panic containment fallbacks
 *
 * FFI_CONTRACT.md section 11 has every export contain panics. A status-
 * returning export converts a caught panic into CHUR_INTERNAL_FAILURE. The
 * handshake exports below have no status channel, so ADR-0037 gives each one a
 * fallback the host already refuses: a major version that is not this ABI, an
 * inverted format range that contains no version, an empty capability mask, and
 * a flavor that is neither release nor debug. A host that reads one of these has
 * a library that panicked and must refuse it.
 * ---------------------------------------------------------------------- */

#define CHUR_PANIC_ABI_VERSION (UINT32_C(0))
#define CHUR_PANIC_FORMAT_MIN (UINT16_C(0xffff))
#define CHUR_PANIC_FORMAT_MAX (UINT16_C(0))
#define CHUR_PANIC_CAPABILITIES (UINT64_C(0))
#define CHUR_PANIC_BUILD_FLAVOR (UINT32_C(0))

/* -------------------------------------------------------------------------
 * Handshake
 *
 * Callable from any thread before runtime initialization. None of these can
 * fail, so none returns a status.
 * ---------------------------------------------------------------------- */

/*
 * None can fail. If a body panics, each returns the matching CHUR_PANIC_*
 * value above; chur_status_is_known returns false, which already fails closed.
 */
uint32_t chur_abi_version_major(void);
uint32_t chur_abi_version_minor(void);
uint64_t chur_capabilities(void);
uint16_t chur_object_format_min(void);
uint16_t chur_object_format_max(void);
uint16_t chur_key_slot_format_min(void);
uint16_t chur_key_slot_format_max(void);
uint32_t chur_build_flavor(void);

/*
 * Whether a status value is one this build allocates. A host uses it to tell a
 * genuine CHUR_INTERNAL_FAILURE from an unknown code it must fold into one.
 */
bool chur_status_is_known(int32_t value);

/* -------------------------------------------------------------------------
 * Handles
 *
 * chur_handle_t is uint64_t: the low 32 bits index a typed registry slot and
 * the high 32 bits carry that slot's generation. It is never a pointer and
 * never a business identifier. 0 is the null handle.
 *
 * Close is idempotent for every handle type: the first close releases the
 * resources and every later close of the same value returns CHUR_OK. Closing a
 * value this process never issued returns CHUR_INVALID_INPUT. A stale
 * generation returns CHUR_SESSION_EXPIRED, and no handle revives after a lock.
 * ---------------------------------------------------------------------- */

typedef uint64_t chur_handle_t;
typedef int32_t chur_status_t;

#define CHUR_NULL_HANDLE (UINT64_C(0))

/* Length of the page cursor of CATALOG_SCHEMA_V1.md section 16.2. */
#define CHUR_CURSOR_LEN 42
/* Length of ObjectProjectionV1 of CATALOG_SCHEMA_V1.md section 16.1. */
#define CHUR_PROJECTION_LEN 79
/* Length of the ChurPageV1 header of FFI_CONTRACT.md section 6.4. */
#define CHUR_PAGE_HEADER_LEN 63

/* Query scopes, CATALOG_SCHEMA_V1.md section 16.2. */
#define CHUR_SCOPE_TIMELINE 1
#define CHUR_SCOPE_ALBUM 2
#define CHUR_SCOPE_FAVORITES 3
#define CHUR_SCOPE_TAG 4
#define CHUR_SCOPE_SEARCH 5
#define CHUR_SCOPE_QUARANTINE 6
#define CHUR_SCOPE_TRASH 7

/* Query sorts, CATALOG_SCHEMA_V1.md section 16.2. */
#define CHUR_SORT_CAPTURE_DESC 1
#define CHUR_SORT_CAPTURE_ASC 2
#define CHUR_SORT_IMPORT_DESC 3
#define CHUR_SORT_ALBUM_MANUAL 4

/* Unlock factors, KEY_SLOTS.md section 1. */
#define CHUR_FACTOR_PASSWORD 1
#define CHUR_FACTOR_RECOVERY 2
#define CHUR_FACTOR_APPLE_KEYCHAIN 3
/* The Keystore performs the unwrap, so this factor's secret is the unwrapped
   root itself rather than a value a slot body opens. See ADR-0041. */
#define CHUR_FACTOR_ANDROID_KEYSTORE 4

/* Operation kinds and stages, FFI_CONTRACT.md section 10. */
#define CHUR_OPERATION_IMPORT 1
#define CHUR_OPERATION_EXPORT 2
#define CHUR_OPERATION_INTEGRITY_SCAN 3
#define CHUR_OPERATION_BACKUP 4
#define CHUR_OPERATION_RESTORE 5
#define CHUR_OPERATION_REENCRYPTION 6

#define CHUR_STAGE_STARTING 1
#define CHUR_STAGE_RUNNING 2
#define CHUR_STAGE_COMMITTING 3
#define CHUR_STAGE_TERMINAL 4

/* Lock reasons, passed to chur_vault_lock and reported nowhere private. */
#define CHUR_LOCK_REASON_USER 1
#define CHUR_LOCK_REASON_TIMEOUT 2
#define CHUR_LOCK_REASON_BACKGROUND 3
#define CHUR_LOCK_REASON_PANIC 4

/* -------------------------------------------------------------------------
 * Control-plane records
 *
 * The caller allocates and owns every structure below. Rust reads them during
 * the call and retains no pointer afterwards. A string field is UTF-8 and is
 * not NUL-terminated; its length field bounds it.
 * ---------------------------------------------------------------------- */

typedef struct ChurRuntimeConfigV1 {
  const uint8_t *root_path;
  uint32_t root_path_length;
} ChurRuntimeConfigV1;

typedef struct ChurUnlockRequestV1 {
  uint8_t factor;
  uint8_t reserved[3];
  const uint8_t *secret;
  uint32_t secret_length;
} ChurUnlockRequestV1;

typedef struct ChurQueryV1 {
  uint8_t scope;
  uint8_t sort;
  uint16_t kinds;
  uint32_t limit;
  uint8_t scope_id[16];
  uint8_t cursor_present;
  uint8_t cursor[CHUR_CURSOR_LEN];
  /* ABI 6: bounded UTF-8 filter; required in Search, forbidden in Trash. */
  const uint8_t *terms;
  uint32_t terms_length;
} ChurQueryV1;

typedef struct ChurObjectRefV1 {
  uint8_t object_id[16];
} ChurObjectRefV1;

typedef struct ChurImportRequestV2 {
  /* Optional 16-byte caller-persisted random object identity, or NULL. */
  const uint8_t *requested_object_id;
  uint8_t seekable;
  uint8_t known_length_present;
  uint8_t media_class;
  uint8_t reserved;
  uint32_t width;
  uint32_t height;
  uint64_t duration_ms;
  uint64_t known_length;
  uint64_t capture_time_ms;
  uint8_t capture_time_present;
  uint8_t reserved_two[7];
  const uint8_t *content_type;
  uint32_t content_type_length;
  const uint8_t *original_filename;
  uint32_t original_filename_length;
} ChurImportRequestV2;

typedef struct ChurScanRequestV1 {
  uint8_t single_object;
  uint8_t reserved[7];
  uint8_t object_id[16];
} ChurScanRequestV1;

typedef struct ChurProgressV1 {
  uint32_t kind;
  uint32_t stage;
  uint64_t processed;
  uint64_t total;
  uint8_t terminal;
  uint8_t reserved[3];
  int32_t status;
  uint8_t object_id[16];
} ChurProgressV1;

typedef struct ChurContentInfoV1 {
  uint64_t plaintext_size;
  uint8_t content_type[64];
  uint16_t media_kind;
  uint8_t byte_range_supported;
  uint8_t complete;
  uint8_t reserved[4];
} ChurContentInfoV1;

typedef struct ChurSyncReportV1 {
  uint64_t applied;
  uint64_t duplicates;
  uint64_t pending;
  uint64_t rejected;
  int32_t first_rejection;
  uint8_t reserved[4];
} ChurSyncReportV1;

/* -------------------------------------------------------------------------
 * Runtime and session
 * ---------------------------------------------------------------------- */

chur_status_t chur_runtime_open(const ChurRuntimeConfigV1 *config,
                                chur_handle_t *out_runtime);
chur_status_t chur_runtime_close(chur_handle_t runtime);
chur_status_t chur_vault_unlock(chur_handle_t runtime,
                                const ChurUnlockRequestV1 *request,
                                chur_handle_t *out_session);
chur_status_t chur_vault_lock(chur_handle_t session, uint32_t reason);
chur_status_t chur_session_close(chur_handle_t session);

/* Opaque locked staging and unlocked validation, FFI_CONTRACT.md section 6.8. */
#define CHUR_SYNC_RECORD_OPERATION 1
#define CHUR_SYNC_RECORD_CHECKPOINT 2
#define CHUR_SYNC_RECORD_OPERATION_PAGE 3
chur_status_t chur_sync_stage(chur_handle_t runtime, const uint8_t vault_id[16],
                              uint8_t kind, uint64_t staged_at_ms,
                              const uint8_t *record, uint32_t record_length);
chur_status_t chur_sync_process(chur_handle_t session, uint64_t now_ms,
                                ChurSyncReportV1 *out_report);
/* Authenticated active device heads: big-endian version:u16=1, count:u32,
 * then count*(device_id[16], accepted_sequence:u64), at most 32 entries. */
chur_status_t chur_sync_heads(chur_handle_t session, uint8_t *destination,
                              size_t capacity, size_t *bytes_written);

/* Own-device operation publication and verified media download plans. */
chur_status_t chur_own_sync_collections(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);

/* Bounded ephemeral direct peer IO, owned by an unlocked session. */
chur_status_t chur_peer_call(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_own_sync_operations(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_own_sync_plan(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_own_sync_author(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);

/* User-approved own-device pairing. Inputs and outputs are versioned bounded
 * control records. All methods require an unlocked session; identity private
 * keys and the root secret do not cross this boundary. */
chur_status_t chur_device_pairing_prepare(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_inspect(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_approve(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_start(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_finish(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_checkpoint(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_overview(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_device_pairing_revoke(chur_handle_t session, const uint8_t *input,
    uint32_t input_length, uint8_t *destination, size_t capacity, size_t *bytes_written);

/* ABI 2.20, FFI_CONTRACT.md section 6.24. ROLLBACK_PROTECTION.md section 4
 * keeps a fork state per device chain until it clears. State counts the chains
 * in each state; acknowledge moves every detected chain to acknowledged and
 * unfreezes none. Both return VAULT_LOCKED on a locked session. */
chur_status_t chur_sync_fork_state(chur_handle_t session, uint64_t *out_detected,
                                   uint64_t *out_acknowledged);
chur_status_t chur_sync_fork_acknowledge(chur_handle_t session);

/* Idempotent local identity provisioning, FFI_CONTRACT.md section 6.9. */
chur_status_t chur_sharing_identity(chur_handle_t session,
                                    uint8_t *destination, size_t capacity,
                                    size_t *bytes_written);

/* Default collection and current recipients, section 6.14. */
chur_status_t chur_sharing_overview(chur_handle_t session,
                                    uint8_t *destination, size_t capacity,
                                    size_t *bytes_written);

/* Authenticated initial recipient enrollment preview, section 6.14. */
chur_status_t chur_sharing_inspect_enrollment(const uint8_t *enrollment,
                                               uint32_t enrollment_length,
                                               uint8_t *destination, size_t capacity,
                                               size_t *bytes_written);

/* Recipient membership and HPKE grant preparation, section 6.10. */
chur_status_t chur_sharing_prepare(chur_handle_t session,
                                   const uint8_t collection_id[16],
                                   const uint8_t *recipient_enrollment,
                                   uint32_t recipient_enrollment_length,
                                   uint8_t permissions,
                                   uint8_t fingerprint_verified,
                                   uint8_t *destination, size_t capacity,
                                   size_t *bytes_written);

/* Authenticated multi-device recipient preparation, section 6.13. */
chur_status_t chur_sharing_prepare_device(chur_handle_t session,
                                          const uint8_t collection_id[16],
                                          const uint8_t *recipient_evidence,
                                          uint32_t recipient_evidence_length,
                                          const uint8_t recipient_device_id[16],
                                          uint8_t permissions,
                                          uint8_t fingerprint_verified,
                                          uint8_t *destination, size_t capacity,
                                          size_t *bytes_written);

/* Authenticated recipient share installation, section 6.11. */
chur_status_t chur_sharing_accept(chur_handle_t session,
                                  const uint8_t *bundle,
                                  uint32_t bundle_length);

/* Source objects in ascending ID order; zero cursor starts a 64-item page.
 * Record: version:u16, count:u32, then for each item two empty variable
 * records, object_id[16], store_id[16], length:u64, SHA-256[32]. */
chur_status_t chur_sharing_publication(chur_handle_t session,
                                       const uint8_t collection_id[16],
                                       const uint8_t after_object_id[16],
                                       uint8_t *destination, size_t capacity,
                                       size_t *bytes_written);

/* After upload, authors durable CreateObject and CommitObject for one object.
 * Returns one record in the same page format with both variables populated. */
chur_status_t chur_sharing_author(chur_handle_t session,
                                 const uint8_t collection_id[16],
                                 const uint8_t object_id[16],
                                 const uint8_t store_id[16],
                                 uint64_t expected_length,
                                 const uint8_t expected_sha256[32],
                                 uint8_t *destination, size_t capacity,
                                 size_t *bytes_written);

/* At most 1 MiB of committed original ciphertext and SHA-256 of that range. */
chur_status_t chur_sharing_object_read(chur_handle_t session,
                                      const uint8_t object_id[16],
                                      uint64_t offset, uint32_t max_bytes,
                                      uint8_t *destination, size_t capacity,
                                      size_t *bytes_written,
                                      uint8_t range_sha256[32]);

/* Authenticated recipient operation page and verified ciphertext activation. */
chur_status_t chur_object_key_request(chur_handle_t session,
    const uint8_t *input, uint32_t input_length,
    uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_object_key_issue(chur_handle_t session,
    const uint8_t *input, uint32_t input_length,
    uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_object_key_accept(chur_handle_t session,
    const uint8_t *input, uint32_t input_length,
    uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_sharing_outbound(chur_handle_t session, uint64_t after_cursor,
    uint8_t *destination, size_t capacity, size_t *bytes_written);
chur_status_t chur_sharing_receive(chur_handle_t session,
                                   const uint8_t *bundle, uint32_t bundle_length,
                                   const uint8_t *operations, uint32_t operations_length,
                                   uint8_t *destination, size_t capacity,
                                   size_t *bytes_written);
chur_status_t chur_sharing_download_offset(chur_handle_t session,
                                           const uint8_t collection_id[16],
                                           const uint8_t object_id[16],
                                           uint64_t *out_offset);
chur_status_t chur_sharing_download_append(chur_handle_t session,
                                           const uint8_t collection_id[16],
                                           const uint8_t object_id[16],
                                           uint64_t offset,
                                           const uint8_t *bytes, uint32_t length);
chur_status_t chur_sharing_download_finish(chur_handle_t session,
                                           const uint8_t collection_id[16],
                                           const uint8_t object_id[16],
                                           uint64_t now_ms);

/* Forward-only recipient revocation and key rotation, section 6.12. */
chur_status_t chur_sharing_revoke(chur_handle_t session,
                                  const uint8_t collection_id[16],
                                  const uint8_t recipient_vault_id[16],
                                  const uint8_t recipient_device_id[16],
                                  uint64_t accepted_at_ms,
                                  uint8_t *destination, size_t capacity,
                                  size_t *bytes_written);

/* -------------------------------------------------------------------------
 * Catalog queries
 *
 * The page is written into the caller's buffer as the canonical bytes of
 * FFI_CONTRACT.md section 6.4. bytes_written is set on every call, including
 * every failure, where it is set to 0. A buffer smaller than the page returns
 * CHUR_RESOURCE_LIMIT_EXCEEDED and writes nothing.
 * ---------------------------------------------------------------------- */

chur_status_t chur_catalog_query(chur_handle_t session, const ChurQueryV1 *query,
                                 uint8_t *destination, size_t capacity,
                                 size_t *bytes_written);

/* -------------------------------------------------------------------------
 * Operations
 *
 * An operation runs on an internal worker and the caller polls its own handle.
 * There is no callback, so there is no delivery thread and no re-entrancy rule.
 * chur_operation_cancel and every close are callable from any thread at any
 * time, including while another call on the same handle is in flight.
 *
 * Rust duplicates a descriptor it is given, so the caller closes its own on its
 * own schedule.
 * ---------------------------------------------------------------------- */

chur_status_t chur_import_begin(chur_handle_t session, int32_t source_fd,
                                const ChurImportRequestV2 *request,
                                chur_handle_t *out_import);
chur_status_t chur_export_begin(chur_handle_t session,
                                const ChurObjectRefV1 *object,
                                int32_t destination_fd,
                                chur_handle_t *out_export);
chur_status_t chur_integrity_scan_begin(chur_handle_t session,
                                        const ChurScanRequestV1 *request,
                                        chur_handle_t *out_scan);
chur_status_t chur_operation_poll(chur_handle_t operation,
                                  ChurProgressV1 *out_progress);
chur_status_t chur_operation_cancel(chur_handle_t operation);
chur_status_t chur_operation_close(chur_handle_t operation);

/* Re-encryption after a revocation, FFI_CONTRACT.md section 6.32, ABI 7.3. */
chur_status_t chur_reencryption_begin(chur_handle_t session,
                                      chur_handle_t *out_operation);
chur_status_t chur_reencryption_counts(chur_handle_t session,
                                       uint64_t *out_pending,
                                       uint64_t *out_failed);

/* -------------------------------------------------------------------------
 * Object reader
 *
 * chur_object_reader_read_at never mixes an error with a byte count. A short
 * read is permitted at any offset, so the caller loops until it has the range
 * it needs or observes *bytes_written == 0, which with a success status means
 * end of authenticated plaintext and occurs only when offset == size. An offset
 * above size returns CHUR_INVALID_INPUT, never a zero-length success. On any
 * failure the whole destination holds unspecified bytes.
 * ---------------------------------------------------------------------- */

chur_status_t chur_object_reader_open(chur_handle_t session,
                                      const ChurObjectRefV1 *object,
                                      uint32_t stream_kind,
                                      chur_handle_t *out_reader);
chur_status_t chur_object_reader_size(chur_handle_t reader, uint64_t *out_size);
/* ABI 7.2: local encrypted resume positions, in milliseconds. No pointer retained.
 * Get returns zero when no current position exists. Put validates an active video,
 * binds its original revision, and requires 0 <= position <= duration <= 4 hours. */
chur_status_t chur_playback_position_get(chur_handle_t session,
                                         const ChurObjectRefV1 *object,
                                         uint64_t *out_position_ms);
chur_status_t chur_playback_position_put(chur_handle_t session,
                                         const ChurObjectRefV1 *object,
                                         uint64_t position_ms, uint64_t duration_ms);
chur_status_t chur_object_reader_content_info(chur_handle_t reader,
                                              ChurContentInfoV1 *out_info);
chur_status_t chur_object_reader_read_at(chur_handle_t reader, uint64_t offset,
                                         uint8_t *destination, size_t capacity,
                                         size_t *bytes_written);
chur_status_t chur_object_reader_verify_complete(chur_handle_t reader,
                                                 uint32_t *out_state);
chur_status_t chur_object_reader_close(chur_handle_t reader);

/* -------------------------------------------------------------------------
 * The Phase-1 product surface, ABI 1.1, FFI_CONTRACT.md section 6.5.
 *
 * Section 6.2 is the boundary a host needs to open a vault and read from it.
 * These are the exports it needs to deliver Phase 1: without them no vault is
 * ever created, so none is ever unlocked, and three of the four destinations of
 * DESIGN.md section 10 have nothing to show.
 *
 * out_secret is 32 bytes and is the one place section 12's "allowed only when
 * unavoidable for a key-slot operation" applies here: a recovery secret must
 * reach the presentation of RECOVERY.md section 2, and a DeviceUnlockSecret
 * must reach the platform keystore. The host clears the buffer as soon as it is
 * done with it and never converts it to a string.
 * ---------------------------------------------------------------------- */

typedef struct ChurCreateRequestV1 {
  const uint8_t *password;
  uint32_t password_length;
  uint32_t memory_kib;
  uint32_t iterations;
  uint32_t parallelism;
} ChurCreateRequestV1;

/* Length of the device secret a slot operation hands back. */
#define CHUR_SECRET_LEN 32

/* The largest recovery phrase: 24 words of at most 8 characters, separated. */
#define CHUR_RECOVERY_PHRASE_MAX 216

chur_status_t chur_vault_present(chur_handle_t runtime, uint8_t *out_present);
chur_status_t chur_vault_create_begin(chur_handle_t runtime,
                                      const ChurCreateRequestV1 *request,
                                      chur_handle_t *out_creation);
/*
 * The recovery slot writes the phrase, not the 32 canonical bytes: the phrase
 * is a presentation encoding (RECOVERY.md section 2) and
 * CANONICAL_ENCODING_V1.md section 13 reserves every encoding for Rust, so a
 * host that received the bytes would have to implement BIP-39 twice. The bytes
 * are UTF-8 and are not NUL-terminated; the host clears the buffer once the
 * user has seen the phrase.
 */
chur_status_t chur_vault_creation_add_recovery_slot(chur_handle_t creation,
                                                    uint8_t *destination,
                                                    size_t capacity,
                                                    size_t *bytes_written);
chur_status_t chur_vault_creation_activate(chur_handle_t creation,
                                           chur_handle_t *out_session);
chur_status_t chur_vault_creation_abandon(chur_handle_t creation);

chur_status_t chur_vault_add_recovery_slot(chur_handle_t session,
                                           uint8_t *destination, size_t capacity,
                                           size_t *bytes_written);

/* ABI 2.19, FFI_CONTRACT.md section 6.23. RECOVERY.md section 8 commits a
 * recovery slot only after the user confirmed its phrase. Begin writes the
 * phrase as chur_vault_add_recovery_slot does and holds the sealed slot in the
 * session; commit writes it as one descriptor generation, which also removes
 * every earlier recovery slot. A slot never committed before the session
 * closes is never written. A commit with nothing staged returns CONFLICT, and
 * on a locked session VAULT_LOCKED. */
chur_status_t chur_vault_recovery_begin(chur_handle_t session,
                                        uint8_t *destination, size_t capacity,
                                        size_t *bytes_written);
chur_status_t chur_vault_recovery_commit(chur_handle_t session);
chur_status_t chur_vault_add_device_slot(chur_handle_t session,
                                         const uint8_t *item_id,
                                         uint8_t *out_secret);
chur_status_t chur_vault_remove_slot(chur_handle_t session,
                                     const uint8_t *slot_id);
chur_status_t chur_vault_change_password(chur_handle_t session,
                                         const ChurUnlockRequestV1 *request);
chur_status_t chur_vault_slots(chur_handle_t session, uint8_t *destination,
                               size_t capacity, size_t *bytes_written);

/* ABI 1.14. Returns the public platform identifier of a device slot in the
 * unlocked session: the 16-byte Apple Keychain item ID or the 16..64-byte
 * Android Keystore alias. Password and recovery slots have no identifier.
 * Call after looking up the slot family and before removing its descriptor.
 * The buffer is unchanged on failure and bytes_written is set to zero. */
chur_status_t chur_vault_platform_slot_identifier(
    chur_handle_t session, const uint8_t *slot_id, uint8_t *destination,
    size_t capacity, size_t *bytes_written);

/* -------------------------------------------------------------------------
 * The Android Keystore surface, ABI 1.2, FFI_CONTRACT.md section 6.6.
 *
 * This is the one key-slot family whose AEAD runs outside Rust: the Keystore
 * cipher performs it, so the enrollment is two calls with a platform operation
 * between them, and the unlock factor carries the unwrapped root. ADR-0041
 * records the exception and what the caller owes: the root_secret field of the
 * enrollment and the buffer passed to chur_vault_unlock must be overwritten as
 * soon as the platform call returns.
 *
 * chur_vault_keystore_material runs on a locked runtime, because its result is
 * what a caller needs before it can unlock. Nothing it returns is secret.
 *
 * Both records are canonical bytes in a caller buffer, as section 6.4 has every
 * list be: the enrollment is a length-prefixed alias, a length-prefixed AAD,
 * and 32 bytes of root secret; the material is a uint32 count followed by that
 * many entries of a length-prefixed alias, a length-prefixed AAD, a 12-byte
 * nonce, and a 48-byte wrapped root. Every integer is big-endian.
 * ---------------------------------------------------------------------- */

chur_status_t chur_vault_keystore_begin(chur_handle_t session,
                                        uint8_t *destination, size_t capacity,
                                        size_t *bytes_written);
chur_status_t chur_vault_keystore_commit(chur_handle_t session,
                                         const uint8_t *gcm_nonce,
                                         const uint8_t *wrapped_root_secret);
chur_status_t chur_vault_keystore_material(chur_handle_t runtime,
                                           uint8_t *destination, size_t capacity,
                                           size_t *bytes_written);

chur_status_t chur_object_set_favorite(chur_handle_t session,
                                       const ChurObjectRefV1 *object,
                                       uint8_t favorite);
chur_status_t chur_object_delete(chur_handle_t session,
                                 const ChurObjectRefV1 *object);
chur_status_t chur_trash_set(chur_handle_t session, const uint8_t *object_ids,
                             uint32_t object_count, uint8_t restore);
chur_status_t chur_trash_empty(chur_handle_t session);
chur_status_t chur_corrupt_empty(chur_handle_t session);
chur_status_t chur_trash_restore_all(chur_handle_t session);
chur_status_t chur_object_metadata(chur_handle_t session,
                                   const ChurObjectRefV1 *object,
                                   uint8_t *destination, size_t capacity,
                                   size_t *bytes_written);
chur_status_t chur_album_create(chur_handle_t session, const uint8_t *name,
                                uint32_t name_length, const uint8_t *requested_album_id,
                                uint8_t *out_album_id);
chur_status_t chur_album_rename(chur_handle_t session, const uint8_t *album_id,
                                const uint8_t *name, uint32_t name_length);
chur_status_t chur_album_delete(chur_handle_t session, const uint8_t *album_id);
/* All-zero parent means root; all-zero before means append. */
chur_status_t chur_album_move(chur_handle_t session, const uint8_t *album_id,
                              const uint8_t *parent_id, const uint8_t *before_id);
chur_status_t chur_album_move_member(chur_handle_t session, const uint8_t *album_id,
                                     const uint8_t *object_id, const uint8_t *before_id);
chur_status_t chur_album_set_membership(chur_handle_t session,
                                        const uint8_t *album_id,
                                        const ChurObjectRefV1 *object,
                                        uint8_t member);
/* Removes 1..100000 distinct packed 16-byte object IDs in one transaction.
 * Each ID must be a current member. Media objects remain in the library. */
chur_status_t chur_album_remove_objects(chur_handle_t session,
                                       const uint8_t *album_id,
                                       const uint8_t *object_ids, uint32_t object_count);
/* Zero target creates an album named by name under parent_id. Zero source means
 * add; move_members=1 requires a nonzero source. object_ids is count packed
 * 16-byte identifiers. The transaction returns the destination identifier. */
chur_status_t chur_album_place_objects(chur_handle_t session,
                                       const uint8_t *target_id,
                                       const uint8_t *name, uint32_t name_length,
                                       const uint8_t *parent_id,
                                       const uint8_t *source_id,
                                       const uint8_t *object_ids, uint32_t object_count,
                                       uint8_t move_members,
                                       uint8_t *out_album_id);
chur_status_t chur_album_list(chur_handle_t session, uint8_t *destination,
                              size_t capacity, size_t *bytes_written);
chur_status_t chur_tag_create(chur_handle_t session, const uint8_t *name,
                              uint32_t name_length, uint8_t *out_tag_id);
chur_status_t chur_tag_list(chur_handle_t session, uint8_t *destination,
                            size_t capacity, size_t *bytes_written);
chur_status_t chur_object_set_tag(chur_handle_t session, const uint8_t *tag_id,
                                  const ChurObjectRefV1 *object, uint8_t tagged);
/* object_ids is object_count packed 16-byte identifiers. Zero tag_id creates
 * name; an existing tag requires an empty name. Output receives the tag id. */
chur_status_t chur_favorites_set(chur_handle_t session,
                                const uint8_t *object_ids, uint32_t object_count,
                                uint8_t favorite);
chur_status_t chur_tag_apply_selection(chur_handle_t session,
                                      const uint8_t *tag_id,
                                      const uint8_t *name, uint32_t name_length,
                                      const uint8_t *object_ids, uint32_t object_count,
                                      uint8_t tagged, uint8_t *out_tag_id);
chur_status_t chur_tag_rename(chur_handle_t session, const uint8_t *tag_id,
                              const uint8_t *name, uint32_t name_length);
chur_status_t chur_tag_delete(chur_handle_t session, const uint8_t *tag_id);

chur_status_t chur_derived_put(chur_handle_t session,
                               const ChurObjectRefV1 *object, uint32_t kind,
                               uint32_t width, uint32_t height,
                               const uint8_t *bytes, uint32_t length);
chur_status_t chur_derived_read(chur_handle_t session,
                                const ChurObjectRefV1 *object, uint32_t kind,
                                uint8_t *destination, size_t capacity,
                                size_t *bytes_written);

/* -------------------------------------------------------------------------
 * The portable backup surface, ABI 1.3
 *
 * FFI_CONTRACT.md section 6.7. Both calls return an operation handle and are
 * driven with chur_operation_poll, _cancel, and _close, exactly as an import
 * or an export is.
 *
 * Both descriptors must be seekable. BACKUP_FORMAT_V1.md section 7 writes the
 * public preamble before the records and learns the record count only after
 * the inventory pass, and section 8 seeks over record headers before it reads
 * a payload, so a pipe is neither a destination nor a source.
 *
 * chur_backup_restore takes the runtime rather than a session: a restore
 * installs an identity, so at the moment it runs there may be no session and
 * no vault at all, and the credential comes from the package's own portable
 * descriptor. The credential can be a password or recovery phrase.
 * ---------------------------------------------------------------------- */

chur_status_t chur_backup_create(chur_handle_t session, int32_t destination_fd,
                                 chur_handle_t *out_operation);
chur_status_t chur_backup_restore(chur_handle_t runtime, int32_t source_fd,
                                  const uint8_t *password,
                                  uint32_t password_length,
                                  chur_handle_t *out_operation);

/* Private local notes, ABI 5.0 (breaking record layout). All records are bounded to 1 MiB.
 * Integer fields in the byte control records are big endian. No plaintext is retained by the ABI.
 * Query: trash:u8, limit:u64, terms:u32+UTF8, cursor:u32+bytes (0 or 65).
 * Save: id:16 (zero creates), expected_revision:u64, pinned:u8, format:u8 (plain0/markdown1), title:u32+UTF8, body:u32+UTF8.
 * Get: id:16. Change: id:16, expected_revision:u64, action:u8 (pin1/unpin2/trash3/restore4/purge5).
 * Note: id16, revision/created_ms/updated_ms/deleted_ms:u64 (UINT64_MAX absent), pinned:u8, format:u8 (plain0/markdown1),
 * attachment_count:u32, export_size:u64, title:u32+UTF8, body:u32+UTF8. Query replaces body with <=160 codepoints preview,
 * preceded by count:u32 and followed by cursor:u32+bytes. Purge returns zero bytes.
 * Export snapshots source and files: .churnote JSON when files exist; otherwise Markdown body or title+LF+LF+body.
 * Output capacity MUST be >=1048576; all pointers remain valid for this call.
 */
chur_status_t chur_private_notes_query(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_private_note_get(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_private_note_save(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_private_note_change(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
/* Attachments/workspace: requests <=16 MiB +512 KiB, byte reads <=8 MiB.
 * Commands 6 get organization, 7 CAS set organization, 8 list history, 9 CAS restore,
 * 10 read historical file, 11 historical detail, 12 folder/tag filtered page.
 * Organization: folder:string, count:u32, tags:string[count], <=16 tags, labels<=64 UTF8.
 * See FFI_CONTRACT 6.25 for exact additive command framing and retention guarantees. */
chur_status_t chur_private_note_attachments(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_private_note_export_begin(chur_handle_t session, const uint8_t *note_id, uint64_t expected_revision, int32_t destination_fd, chur_handle_t *out_operation);
/* Exports the exact bytes of one saved note-owned file; same snapshot/cancellation rules. */
chur_status_t chur_private_note_attachment_export_begin(chur_handle_t session, const uint8_t *note_id, const uint8_t *attachment_id, uint64_t expected_revision, int32_t destination_fd, chur_handle_t *out_operation);

/* ABI 2.24 local encrypted content index. Bounded record layout: FFI_CONTRACT section 6.28. */
chur_status_t chur_content_index_candidates(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_content_index_put(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);
chur_status_t chur_content_index_clear(chur_handle_t session, const uint8_t *request, size_t request_len, uint8_t *destination, size_t capacity, size_t *written);

/* ABI 2.23 external encrypted archives. Runtime-owned; no open vault required.
 * Request <= 128 KiB: u8=1, BE u32 password bytes <=1024, password,
 * BE u64 output limit, BE u32 count 1..32. Each file: BE u32 name bytes
 * 1..1024, UTF-8 basename, BE u32 MIME bytes <=255, MIME, u8 known (0/1),
 * optional BE u64 length. Actual aggregate input <=4 GiB. All descriptors are
 * duplicated before return; caller keeps ownership and an exclusive offset
 * lease until terminal. Inputs may be nonseekable; destination must be writable
 * and seekable. Existing operation poll/cancel/close applies. */
chur_status_t chur_external_archive_begin(chur_handle_t runtime, const uint8_t *request, uint32_t length, const int32_t *source_fds, uint32_t source_count, int32_t destination_fd, chur_handle_t *out_operation);

/* ABI 2.22 encrypted selective archives. Request v1 is BE: version:u8=1,
 * password:u32+bytes (1..1024), then export-only objectCount:u32+id16*,
 * albumCount:u32+id16*, noteCount:u32+(id16,revision:u64)*, maxOutputBytes:u64 (1..INT64_MAX). Each count<=1000;
 * expanded originals<=10000; selected albums<=1000; request<=65536.
 * Password and ids are copied during begin and never retained after the operation.
 * Owner session revokes the operation on lock. Progress is completed objects+notes,
 * never byte counts, including terminal cancellation/failure. Import verifies all
 * containers before any target write; completed imported items remain on failure.
 */
chur_status_t chur_selective_export_begin(chur_handle_t session, const uint8_t *request, uint32_t length, int32_t descriptor, chur_handle_t *out_operation);
chur_status_t chur_selective_import_begin(chur_handle_t session, const uint8_t *request, uint32_t length, int32_t descriptor, chur_handle_t *out_operation);

/* ABI 7.1: bounded portable JPEG XL. Input is borrowed; no pointer is retained.
 * Open FD borrows and duplicates the descriptor without changing its offset.
 * Decoder handles require close, including when the vault locks.
 * Source limit 64 MiB, 64M pixels, 1024 displayed frames; grid tracker 256 MiB.
 * Render max_edge is 1..4096; never upscales. RGBA8 sRGB, straight alpha.
 * Output size is floor(source dimension * min(1,max_edge / longest edge)),
 * each dimension at least one. Capacity must cover output width*height*4.
 */
typedef struct ChurJpegXlInfoV1 {
    uint32_t width;
    uint32_t height;
    uint32_t frame_count;
    uint32_t loop_count;
} ChurJpegXlInfoV1;
chur_status_t chur_jpeg_xl_open(const uint8_t *source, size_t length, chur_handle_t *out_handle, ChurJpegXlInfoV1 *out_info);
chur_status_t chur_jpeg_xl_open_fd(int32_t descriptor, chur_handle_t *out_handle, ChurJpegXlInfoV1 *out_info);
chur_status_t chur_jpeg_xl_render(chur_handle_t handle, uint32_t index, uint32_t max_edge, uint8_t *destination, size_t capacity, uint32_t *out_duration_ms);
chur_status_t chur_jpeg_xl_close(chur_handle_t handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CHUR_H */
