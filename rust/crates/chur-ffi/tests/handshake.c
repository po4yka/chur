/*
 * The C side of the FFI harness.
 *
 * docs/interop/FFI_CONTRACT.md section 2 says the handshake is what a platform
 * gate checks before a vault opens. This program is that gate, in C, linked
 * against the real static library, so the harness proves the symbols exist
 * with C linkage and the declared types rather than proving that Rust agrees
 * with Rust.
 *
 * It then drives the control plane and the data plane of section 6.2 the way a
 * host does: open a runtime, refuse a wrong credential, and prove that every
 * exported symbol links. Creating a vault is not on the boundary, so a full
 * round trip belongs to the Rust integration tests; what a C program can prove
 * and a Rust test cannot is that these symbols exist with these signatures.
 *
 * Build and run:
 *
 *   cargo build -p chur-ffi --release
 *   cc -I crates/chur-ffi/include crates/chur-ffi/tests/handshake.c \
 *      target/release/libchur_ffi.a -o handshake && ./handshake
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chur.h"

static int failures = 0;

static void check(int condition, const char *what) {
    if (condition) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

int main(void) {
    printf("chur ABI handshake\n");

    /*
     * A panicking export returns its CHUR_PANIC_* fallback, so these two
     * assertions are the host-side half of ADR-0037: the values are live rather
     * than contained failures.
     */
    check(chur_abi_version_major() != CHUR_PANIC_ABI_VERSION,
          "the version is computed, not a contained panic");
    check(chur_object_format_min() <= chur_object_format_max() &&
              chur_key_slot_format_min() <= chur_key_slot_format_max(),
          "neither format range is the empty panic fallback");

    check(chur_abi_version_major() == 7, "major ABI version is 7");
    check(chur_abi_version_minor() == 4,
          "minor ABI version is 4, including staged operation pages");

    check(chur_object_format_min() <= chur_object_format_max(),
          "object format range is ordered");
    check(chur_key_slot_format_min() <= chur_key_slot_format_max(),
          "key slot format range is ordered");
    check(chur_object_format_min() == 1 && chur_object_format_max() == 2,
          "object format range is 1..=2, v2 being the padded container of ADR-0066");
    check(chur_key_slot_format_min() == 1 && chur_key_slot_format_max() == 1,
          "key slot format range is 1..=1");

    uint64_t capabilities = chur_capabilities();
    check((capabilities & CHUR_CAP_OBJECT_READER) != 0,
          "the random-access reader is declared");
    check((capabilities & CHUR_CAP_SEQUENTIAL_READER) != 0,
          "the sequential reader is declared");
    check((capabilities & CHUR_CAP_INTEGRITY_SCAN) != 0,
          "the integrity scan is declared");
    check((capabilities & CHUR_CAP_BACKUP_PACKAGE) != 0,
          "the portable backup surface is declared");
    check((capabilities & CHUR_CAP_DECOY_VAULT) != 0,
          "the independent decoy identity is declared");
    check((capabilities & CHUR_CAP_SYNC) != 0,
          "the ciphertext sync inbox is declared");
    check((capabilities & CHUR_CAP_COLLECTION_SHARING) != 0,
          "the collection-sharing surface is declared");
    check((capabilities & CHUR_CAP_SHARED_OBJECTS) != 0,
          "shared object transfer is declared");
    check((capabilities & CHUR_CAP_CONCURRENT_READS) == 0,
          "no concurrent-reader capability is declared before its evidence exists");
    check((capabilities & ~(CHUR_CAP_DECOY_VAULT | CHUR_CAP_OBJECT_READER |
                            CHUR_CAP_SEQUENTIAL_READER | CHUR_CAP_INTEGRITY_SCAN |
                            CHUR_CAP_BACKUP_PACKAGE | CHUR_CAP_SYNC |
                            CHUR_CAP_CONCURRENT_READS |
                            CHUR_CAP_COLLECTION_SHARING | CHUR_CAP_SHARED_OBJECTS | CHUR_CAP_JPEG_XL)) == 0,
          "no reserved capability bit is set");

    uint32_t flavor = chur_build_flavor();
    check((flavor & CHUR_FLAVOR_TEST_HOOKS) == 0, "no test hooks are compiled in");
    check(((flavor & CHUR_FLAVOR_RELEASE) != 0) ^
              ((flavor & CHUR_FLAVOR_DEBUG_ASSERTIONS) != 0),
          "the build is release or debug, never both");

    check(chur_status_is_known(CHUR_AUTHENTICATION_FAILED),
          "an allocated status is known");
    check(!chur_status_is_known(CHUR_OK), "success is not an error code");
    check(!chur_status_is_known(42), "an unallocated value is unknown");
    check(!chur_status_is_known(-1), "a negative value is unknown");
    check(!chur_status_is_known(700), "the reserved 700 block is unallocated");

    /*
     * The control plane, called through C. A runtime over a directory that
     * holds no vault opens, refuses every credential with one external result,
     * and closes idempotently.
     */
    {
        const char *root = "./chur-abi-harness-root";
        ChurRuntimeConfigV1 config;
        chur_handle_t runtime = CHUR_NULL_HANDLE;
        chur_handle_t session = CHUR_NULL_HANDLE;
        ChurUnlockRequestV1 unlock;
        const char *password = "correct horse battery staple";
        ChurQueryV1 query;
        uint8_t page[CHUR_PAGE_HEADER_LEN];
        size_t written = 1;

        config.root_path = (const uint8_t *)root;
        config.root_path_length = (uint32_t)strlen(root);
        check(chur_runtime_open(&config, &runtime) == CHUR_OK,
              "the runtime opens over an empty root");
        check(runtime != CHUR_NULL_HANDLE, "a live handle is never the null handle");

        unlock.factor = CHUR_FACTOR_PASSWORD;
        unlock.reserved[0] = 0;
        unlock.reserved[1] = 0;
        unlock.reserved[2] = 0;
        unlock.secret = (const uint8_t *)password;
        unlock.secret_length = (uint32_t)strlen(password);
        check(chur_vault_unlock(runtime, &unlock, &session) ==
                  CHUR_AUTHENTICATION_FAILED,
              "an absent vault and a wrong credential are one external result");
        check(session == CHUR_NULL_HANDLE, "a failed unlock wrote no handle");

        /* A session handle that was never issued is refused, not dereferenced. */
        memset(&query, 0, sizeof(query));
        query.scope = CHUR_SCOPE_TIMELINE;
        query.sort = CHUR_SORT_CAPTURE_DESC;
        check(chur_catalog_query(CHUR_NULL_HANDLE, &query, page, sizeof(page),
                                 &written) == CHUR_INVALID_INPUT,
              "the null handle names nothing");
        check(written == 0, "a byte count is set on every call, including a failure");

        check(chur_runtime_close(runtime) == CHUR_OK, "the runtime closes");
        check(chur_runtime_close(runtime) == CHUR_OK, "close is idempotent");
        check(chur_runtime_close(CHUR_NULL_HANDLE) == CHUR_INVALID_INPUT,
              "closing the null handle is invalid input");
    }

    /*
     * Every remaining export is referenced so the link step proves it exists.
     * Taking the address is enough and calls nothing, which keeps the harness
     * a gate rather than a second integration suite.
     */
    {
        const void *surface[] = {
            (const void *)&chur_content_index_candidates,
            (const void *)&chur_content_index_put,
            (const void *)&chur_content_index_clear,
            (const void *)&chur_vault_lock,
            (const void *)&chur_session_close,
            (const void *)&chur_vault_platform_slot_identifier,
            (const void *)&chur_import_begin,
            (const void *)&chur_export_begin,
            (const void *)&chur_integrity_scan_begin,
            (const void *)&chur_operation_poll,
            (const void *)&chur_operation_cancel,
            (const void *)&chur_operation_close,
            (const void *)&chur_reencryption_begin,
            (const void *)&chur_reencryption_counts,
            (const void *)&chur_object_reader_open,
            (const void *)&chur_object_reader_size,
            (const void *)&chur_object_reader_content_info,
            (const void *)&chur_object_reader_read_at,
            (const void *)&chur_object_reader_verify_complete,
            (const void *)&chur_object_reader_close,
            (const void *)&chur_sharing_identity,
            (const void *)&chur_sharing_overview,
            (const void *)&chur_sharing_inspect_enrollment,
            (const void *)&chur_sharing_prepare,
            (const void *)&chur_sharing_prepare_device,
            (const void *)&chur_sharing_accept,
            (const void *)&chur_sharing_revoke,
            (const void *)&chur_sharing_download_offset,
        };
        size_t index;
        int all_present = 1;
        for (index = 0; index < sizeof(surface) / sizeof(surface[0]); index++) {
            if (surface[index] == NULL) {
                all_present = 0;
            }
        }
        check(all_present, "every section 6.2 and sharing export links");
    }

    if (failures != 0) {
        printf("\n%d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("\nall checks passed\n");
    return EXIT_SUCCESS;
}
