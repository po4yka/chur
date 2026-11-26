//! The control plane and the data plane driven through the real ABI.
//!
//! `docs/interop/FFI_CONTRACT.md` §15 names the tests this file owes: handle
//! misuse, invalid and null buffers, double close, leaked-handle cleanup, lock
//! during a read, poll after the terminal result and after close, a descriptor
//! closed early, cancellation, and no secret in an error.
//!
//! Every call goes through the exported symbol rather than through a Rust API,
//! so what is tested is the boundary and not the implementation behind it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// This file calls the exported symbols directly, which is the point: what is
// tested is the boundary and not the Rust API behind it. Every call satisfies
// the pointer contract the header states, and each one is visible at its call
// site rather than hidden behind a wrapper.
#![expect(
    unsafe_code,
    reason = "the tests drive the C ABI, which is unsafe to call by definition"
)]

use std::ffi::c_int;
use std::io::{Seek, Write};

use chur_core::ChurStatus;
use chur_ffi::api::*;
use chur_ffi::records::*;

const OK: i32 = 0;
const PASSWORD: &[u8] = b"correct horse battery staple";

fn status(value: i32) -> ChurStatus {
    ChurStatus::from_i32(value)
}

fn scratch() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-ffi-{}",
        chur_crypto::random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Opens a runtime over a fresh storage root.
fn open_runtime(root: &std::path::Path) -> u64 {
    let text = root.to_str().unwrap().as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: text.as_ptr(),
        root_path_length: text.len() as u32,
    };
    let mut handle = 0u64;
    let code = unsafe { chur_runtime_open(&config, &mut handle) };
    assert_eq!(code, OK, "the runtime did not open");
    assert_ne!(handle, 0, "a live handle is never the null handle");
    handle
}

/// Creates a vault through the Rust API, because §6.2 exposes no creation
/// export: `PROVISIONING.md` §3 is a product flow the shell drives, and the
/// boundary exposes only unlock.
fn create_vault(root: &std::path::Path) {
    let dir = chur_catalog::paths::VaultRoot::new(root.to_path_buf());
    drop(
        chur_catalog::vault::create(&dir, PASSWORD, 1_700_000_000_000)
            .expect("create")
            .activate()
            .expect("activate"),
    );
}

fn unlock(runtime: u64, secret: &[u8], factor: u8) -> (i32, u64) {
    let request = ChurUnlockRequestV1 {
        factor,
        reserved: [0; 3],
        secret: secret.as_ptr(),
        secret_length: secret.len() as u32,
    };
    let mut session = 0u64;
    let code = unsafe { chur_vault_unlock(runtime, &request, &mut session) };
    (code, session)
}

fn timeline_query() -> ChurQueryV1 {
    ChurQueryV1 {
        scope: 1,
        sort: 1,
        kinds: 0,
        limit: 0,
        scope_id: [0; 16],
        cursor_present: 0,
        cursor: [0; 42],
        terms: core::ptr::null(),
        terms_length: 0,
    }
}

/// Imports one object through the ABI and returns its identifier.
fn import(session: u64, bytes: &[u8]) -> [u8; 16] {
    import_at(session, bytes, 1_700_000_000_000)
}

/// Imports one object captured at `capture_time_ms` and returns its identifier.
///
/// The timeline sorts by capture time, newest first, so an object imported
/// later with an earlier capture time is the last row and the one returned.
fn import_at(session: u64, bytes: &[u8], capture_time_ms: u64) -> [u8; 16] {
    let mut file = tempfile();
    file.write_all(bytes).unwrap();
    file.rewind().unwrap();
    let fd = descriptor(&file);

    let content_type = b"image/jpeg";
    let filename = b"holiday.jpg";
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 1,
        known_length_present: 1,
        media_class: 1,
        reserved: 0,
        width: 4_000,
        height: 3_000,
        duration_ms: 0,
        known_length: bytes.len() as u64,
        capture_time_ms,
        capture_time_present: 1,
        reserved_two: [0; 7],
        content_type: content_type.as_ptr(),
        content_type_length: content_type.len() as u32,
        original_filename: filename.as_ptr(),
        original_filename_length: filename.len() as u32,
    };
    let mut operation = 0u64;
    assert_eq!(
        unsafe { chur_import_begin(session, fd, &request, &mut operation) },
        OK
    );
    let terminal = drain(operation);
    assert_eq!(terminal, OK, "the import failed");
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);

    let mut buffer = vec![0u8; 63 + 79 * 8];
    let mut written = 0usize;
    let query = timeline_query();
    assert_eq!(
        unsafe {
            chur_catalog_query(
                session,
                &query,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        },
        OK
    );
    let page = decode_page(&buffer[..written]).unwrap();
    *page.objects.last().unwrap().object_id.as_bytes()
}

/// Polls an operation until it is terminal and returns its ABI status.
///
/// The value is the `int32_t` and not a `ChurStatus`: success is `0`, which is
/// not a member of that enum, so folding it through `from_i32` would turn every
/// completed operation into `INTERNAL_FAILURE` and make a comparison of two
/// folded values pass.
fn drain(operation: u64) -> i32 {
    loop {
        let mut progress = zeroed_progress();
        assert_eq!(unsafe { chur_operation_poll(operation, &mut progress) }, OK);
        if progress.terminal == 1 {
            return progress.status;
        }
        std::thread::yield_now();
    }
}

fn zeroed_progress() -> ChurProgressV1 {
    ChurProgressV1 {
        kind: 0,
        stage: 0,
        processed: 0,
        total: 0,
        terminal: 0,
        reserved: [0; 3],
        status: 0,
        object_id: [0; 16],
    }
}

fn tempfile() -> std::fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-ffi-src-{}",
        chur_crypto::random::id().unwrap().to_hex()
    ));
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap()
}

#[cfg(unix)]
fn descriptor(file: &std::fs::File) -> c_int {
    use std::os::fd::AsRawFd;
    file.as_raw_fd()
}

// ---------------------------------------------------------------------------

#[test]
fn a_null_pointer_is_invalid_input_rather_than_a_crash() {
    let mut handle = 0u64;
    assert_eq!(
        status(unsafe { chur_runtime_open(core::ptr::null(), &mut handle) }),
        ChurStatus::InvalidInput
    );
    let root = scratch();
    let text = root.to_str().unwrap().as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: text.as_ptr(),
        root_path_length: text.len() as u32,
    };
    assert_eq!(
        status(unsafe { chur_runtime_open(&config, core::ptr::null_mut()) }),
        ChurStatus::InvalidInput
    );
    // A length with a null pointer is refused before anything is read.
    let broken = ChurRuntimeConfigV1 {
        root_path: core::ptr::null(),
        root_path_length: 8,
    };
    assert_eq!(
        status(unsafe { chur_runtime_open(&broken, &mut handle) }),
        ChurStatus::InvalidInput
    );
}

#[test]
fn the_null_handle_and_a_handle_never_issued_are_invalid_input() {
    for handle in [0u64, 0x0000_0001_ffff_ffff, u64::MAX] {
        assert_eq!(
            status(unsafe { chur_session_close(handle) }),
            ChurStatus::InvalidInput,
            "handle {handle:#x}"
        );
    }
}

#[test]
fn a_handle_of_another_type_is_refused() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut progress = zeroed_progress();
    // A runtime handle passed where an operation handle belongs.
    assert_eq!(
        status(unsafe { chur_operation_poll(runtime, &mut progress) }),
        ChurStatus::InvalidInput
    );
    let mut size = 0u64;
    assert_eq!(
        status(unsafe { chur_object_reader_size(runtime, &mut size) }),
        ChurStatus::InvalidInput
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn close_is_idempotent_and_never_reports_not_found() {
    let root = scratch();
    let runtime = open_runtime(&root);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    // §3: every later close of the same value returns success and does nothing.
    for _ in 0..3 {
        assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    }
}

#[test]
fn a_wrong_password_is_authentication_failed_and_carries_no_value() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (code, session) = unlock(runtime, b"wrong", 1);
    assert_eq!(status(code), ChurStatus::AuthenticationFailed);
    assert_eq!(session, 0, "a failed unlock wrote no handle");
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_unallocated_factor_is_invalid_input() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    assert_eq!(
        status(unlock(runtime, PASSWORD, 9).0),
        ChurStatus::InvalidInput
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_import_reads_back_through_the_reader() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (code, session) = unlock(runtime, PASSWORD, 1);
    assert_eq!(code, OK);

    let expected: Vec<u8> = (0..300_000u32).map(|value| (value % 251) as u8).collect();
    let object_id = import(session, &expected);

    let reference = ChurObjectRefV1 { object_id };
    let mut reader = 0u64;
    assert_eq!(
        unsafe { chur_object_reader_open(session, &reference, 1, &mut reader) },
        OK
    );
    let mut size = 0u64;
    assert_eq!(unsafe { chur_object_reader_size(reader, &mut size) }, OK);
    assert_eq!(size, expected.len() as u64);

    let mut info = ChurContentInfoV1 {
        plaintext_size: 0,
        content_type: [0; 64],
        media_kind: 0,
        byte_range_supported: 0,
        complete: 0,
        reserved: [0; 4],
    };
    assert_eq!(
        unsafe { chur_object_reader_content_info(reader, &mut info) },
        OK
    );
    assert_eq!(info.plaintext_size, expected.len() as u64);
    assert_eq!(info.byte_range_supported, 1);
    assert_eq!(info.complete, 1);
    let terminator = info
        .content_type
        .iter()
        .position(|byte| *byte == 0)
        .unwrap();
    assert_eq!(&info.content_type[..terminator], b"image/jpeg");

    let mut read = vec![0u8; expected.len()];
    let mut at = 0usize;
    while at < read.len() {
        let mut written = 0usize;
        let code = unsafe {
            chur_object_reader_read_at(
                reader,
                at as u64,
                read[at..].as_mut_ptr(),
                read.len() - at,
                &mut written,
            )
        };
        assert_eq!(code, OK);
        assert!(written > 0, "a short read returned zero before the end");
        at += written;
    }
    assert_eq!(read, expected);

    // §6.3: offset == size is a success with zero bytes; above it is INVALID_INPUT.
    let mut one = [0u8; 1];
    let mut written = 99usize;
    assert_eq!(
        unsafe { chur_object_reader_read_at(reader, size, one.as_mut_ptr(), 1, &mut written) },
        OK
    );
    assert_eq!(written, 0);
    written = 99;
    assert_eq!(
        status(unsafe {
            chur_object_reader_read_at(reader, size + 1, one.as_mut_ptr(), 1, &mut written)
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(written, 0, "§6.3 sets the count on every failure");

    let mut state = 0u32;
    assert_eq!(
        unsafe { chur_object_reader_verify_complete(reader, &mut state) },
        OK
    );
    assert_eq!(state, 4, "COMPLETE_VERIFIED");

    assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_query_buffer_smaller_than_the_page_writes_nothing() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    import(session, &[7u8; 4_096]);

    let query = timeline_query();
    let mut small = vec![0xaau8; 10];
    let mut written = 99usize;
    assert_eq!(
        status(unsafe {
            chur_catalog_query(
                session,
                &query,
                small.as_mut_ptr(),
                small.len(),
                &mut written,
            )
        }),
        ChurStatus::ResourceLimitExceeded
    );
    assert_eq!(written, 0);
    assert!(
        small.iter().all(|byte| *byte == 0xaa),
        "a refused page wrote into the buffer"
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn locking_invalidates_every_handle_the_session_owns() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let object_id = import(session, &[3u8; 8_192]);
    let reference = ChurObjectRefV1 { object_id };
    let mut reader = 0u64;
    assert_eq!(
        unsafe { chur_object_reader_open(session, &reference, 1, &mut reader) },
        OK
    );

    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);

    // §4: no handle revives after lock.
    let mut size = 0u64;
    assert_eq!(
        status(unsafe { chur_object_reader_size(reader, &mut size) }),
        ChurStatus::SessionExpired
    );
    // The session itself is locked rather than gone, and reports that.
    let query = timeline_query();
    let mut buffer = vec![0u8; 512];
    let mut written = 0usize;
    assert_eq!(
        status(unsafe {
            chur_catalog_query(
                session,
                &query,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        }),
        ChurStatus::VaultLocked
    );
    // Close after lock is still success, §3.
    assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn polling_after_the_terminal_result_returns_the_same_result() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);

    let mut file = tempfile();
    file.write_all(&[9u8; 4_096]).unwrap();
    file.rewind().unwrap();
    let content_type = b"image/jpeg";
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 1,
        known_length_present: 1,
        media_class: 1,
        reserved: 0,
        width: 100,
        height: 100,
        duration_ms: 0,
        known_length: 4_096,
        capture_time_ms: 0,
        capture_time_present: 0,
        reserved_two: [0; 7],
        content_type: content_type.as_ptr(),
        content_type_length: content_type.len() as u32,
        original_filename: core::ptr::null(),
        original_filename_length: 0,
    };
    let mut operation = 0u64;
    assert_eq!(
        unsafe { chur_import_begin(session, descriptor(&file), &request, &mut operation) },
        OK
    );
    let first = drain(operation);
    assert_eq!(first, OK, "the import failed");
    // §9: exactly one terminal result is observable, and the snapshot freezes.
    for _ in 0..5 {
        let mut progress = zeroed_progress();
        assert_eq!(unsafe { chur_operation_poll(operation, &mut progress) }, OK);
        assert_eq!(progress.terminal, 1);
        assert_eq!(progress.status, first);
        assert_eq!(progress.stage, 4);
    }
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    // §3: polling a closed handle is SESSION_EXPIRED, not a partial snapshot.
    let mut progress = zeroed_progress();
    assert_eq!(
        status(unsafe { chur_operation_poll(operation, &mut progress) }),
        ChurStatus::SessionExpired
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_import_from_a_closed_descriptor_fails_without_committing() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let content_type = b"image/jpeg";
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 0,
        known_length_present: 0,
        media_class: 1,
        reserved: 0,
        width: 0,
        height: 0,
        duration_ms: 0,
        known_length: 0,
        capture_time_ms: 0,
        capture_time_present: 0,
        reserved_two: [0; 7],
        content_type: content_type.as_ptr(),
        content_type_length: content_type.len() as u32,
        original_filename: core::ptr::null(),
        original_filename_length: 0,
    };
    let mut operation = 0u64;
    // §13: a descriptor that is not open is refused before any work.
    assert_eq!(
        status(unsafe { chur_import_begin(session, -1, &request, &mut operation) }),
        ChurStatus::InvalidInput
    );
    assert_eq!(operation, 0);

    // An empty source is a refusal that leaves nothing behind.
    let file = tempfile();
    assert_eq!(
        unsafe { chur_import_begin(session, descriptor(&file), &request, &mut operation) },
        OK
    );
    assert_eq!(status(drain(operation)), ChurStatus::InvalidInput);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);

    let query = timeline_query();
    let mut buffer = vec![0u8; 512];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            chur_catalog_query(
                session,
                &query,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        },
        OK
    );
    let page = decode_page(&buffer[..written]).unwrap();
    assert_eq!(page.total_count, 0);
    assert!(page.objects.is_empty());
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_export_writes_the_original_through_a_descriptor() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let expected: Vec<u8> = (0..70_000u32).map(|value| (value % 199) as u8).collect();
    let object_id = import(session, &expected);

    let destination = tempfile();
    let reference = ChurObjectRefV1 { object_id };
    let mut operation = 0u64;
    assert_eq!(
        unsafe {
            chur_export_begin(
                session,
                &reference,
                descriptor(&destination),
                &mut operation,
            )
        },
        OK
    );
    assert_eq!(drain(operation), OK);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);

    let mut written = destination;
    written.rewind().unwrap();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut written, &mut out).unwrap();
    assert_eq!(out, expected);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_integrity_scan_runs_over_every_object() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    import(session, &[1u8; 4_096]);
    import(session, &[2u8; 4_096]);

    let request = ChurScanRequestV1 {
        single_object: 0,
        reserved: [0; 7],
        object_id: [0; 16],
    };
    let mut operation = 0u64;
    assert_eq!(
        unsafe { chur_integrity_scan_begin(session, &request, &mut operation) },
        OK
    );
    assert_eq!(drain(operation), OK);
    let mut progress = zeroed_progress();
    assert_eq!(unsafe { chur_operation_poll(operation, &mut progress) }, OK);
    assert_eq!(progress.kind, 3);
    assert_eq!(progress.processed, 2);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

/// The one committed container, `vaults/<id>/objects/<xx>/<rest>`.
fn only_container(root: &std::path::Path) -> std::path::PathBuf {
    let only = |dir: std::path::PathBuf| -> std::path::PathBuf {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        entries.into_iter().next().unwrap()
    };
    only(only(only(root.join("vaults")).join("objects")))
}

/// Scans every object and returns the terminal status and `processed`.
fn scan_every_object(session: u64) -> (i32, u64) {
    let request = ChurScanRequestV1 {
        single_object: 0,
        reserved: [0; 7],
        object_id: [0; 16],
    };
    let mut operation = 0u64;
    assert_eq!(
        unsafe { chur_integrity_scan_begin(session, &request, &mut operation) },
        OK
    );
    let status = drain(operation);
    let mut progress = zeroed_progress();
    assert_eq!(unsafe { chur_operation_poll(operation, &mut progress) }, OK);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    (status, progress.processed)
}

/// The `integrity_summary` of every row the timeline shows.
fn timeline_summaries(session: u64) -> Vec<u8> {
    let mut buffer = vec![0u8; 63 + 79 * 8];
    let mut written = 0usize;
    let query = timeline_query();
    assert_eq!(
        unsafe {
            chur_catalog_query(
                session,
                &query,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        },
        OK
    );
    let page = decode_page(&buffer[..written]).unwrap();
    page.objects
        .iter()
        .map(|object| object.integrity_summary)
        .collect()
}

/// `docs/ERROR_MODEL.md` "Integrity states versus errors": proven corruption
/// reaches the caller as `OBJECT_CORRUPT`, and the scan still checks every
/// target before it reports.
///
/// The damaged object has the later capture time, so the timeline scans it
/// first on every run. A scan that stopped at it would leave the healthy object
/// unverified and `processed` short of two.
#[test]
fn a_scan_that_proves_corruption_checks_every_object_and_ends_object_corrupt() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let damaged: Vec<u8> = (0..70_000u32).map(|value| (value % 199) as u8).collect();
    let damaged_id = import_at(session, &damaged, 1_700_000_000_001);

    // The same flipped ciphertext bit as chur-media's
    // `a_flipped_ciphertext_bit_is_proven_corruption`.
    let path = only_container(&root);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    // Imported only now, so the container above was the only one.
    let healthy_id = import(session, &[2u8; 4_096]);

    let (status, processed) = scan_every_object(session);
    assert_eq!(status, ChurStatus::ObjectCorrupt.as_i32());
    assert_eq!(processed, 2, "every target was checked");
    assert_eq!(
        scan_every_object(session),
        (ChurStatus::ObjectCorrupt.as_i32(), 2)
    );

    // `docs/format/CATALOG_SCHEMA_V1.md` §16.2: the corrupt row is in no scope,
    // and the healthy one was verified rather than left behind.
    assert_eq!(
        timeline_summaries(session),
        [chur_format::constants::IntegritySummary::CompleteVerified.value()]
    );
    assert_eq!(chur_ffi::product::chur_corrupt_empty(session), OK);
    assert!(
        !path.exists(),
        "confirmed corrupt cleanup collects its ciphertext"
    );
    assert_eq!(
        chur_ffi::product::chur_corrupt_empty(session),
        OK,
        "cleanup is idempotent"
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    let directory = chur_catalog::paths::VaultRoot::new(&root);
    let mut reopened =
        chur_catalog::vault::unlock_with_password(&directory, PASSWORD, 1_700_000_000_010).unwrap();
    let damaged_id = chur_core::Id::new(damaged_id).unwrap();
    let healthy_id = chur_core::Id::new(healthy_id).unwrap();
    assert!(chur_media::keys::object_key(&reopened, &damaged_id).is_err());
    let mut healthy = chur_media::reader::open(
        &reopened,
        &healthy_id,
        chur_format::constants::StreamKind::Original,
    )
    .unwrap();
    assert_eq!(
        healthy.read_range(0, 4096).unwrap().as_slice(),
        &[2u8; 4096]
    );
    drop(healthy);
    let mut backup = std::io::Cursor::new(Vec::new());
    chur_media::backup::create(
        &mut reopened,
        &mut backup,
        1_700_000_000_011,
        &mut chur_media::progress::Uninterrupted,
    )
    .expect("backup succeeds after damaged media is explicitly erased");
}

/// `docs/interop/FFI_CONTRACT.md` §6.2: an outcome other than proven corruption
/// is an `integrity_summary` the catalog records, so a scan that proves nothing
/// corrupt checks every target and ends `0`.
///
/// The object whose container is gone has the later capture time, so the
/// timeline scans it first on every run. A scan that stopped at it would leave
/// the healthy object unverified and `processed` short of two.
#[test]
fn a_scan_that_quarantines_an_object_checks_every_object_and_ends_ok() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    import_at(session, &[1u8; 4_096], 1_700_000_000_001);
    std::fs::remove_file(only_container(&root)).unwrap();
    // Imported only now, so the container above was the only one.
    import(session, &[2u8; 4_096]);

    let (status, processed) = scan_every_object(session);
    assert_eq!(status, OK);
    assert_eq!(processed, 2, "every target was checked");

    // `docs/format/CATALOG_SCHEMA_V1.md` §16.2: the quarantined row appears
    // only in the quarantine scope, and the healthy one was verified.
    assert_eq!(
        timeline_summaries(session),
        [chur_format::constants::IntegritySummary::CompleteVerified.value()]
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn closing_the_runtime_releases_every_handle() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let object_id = import(session, &[5u8; 4_096]);
    let reference = ChurObjectRefV1 { object_id };
    let mut reader = 0u64;
    assert_eq!(
        unsafe { chur_object_reader_open(session, &reference, 1, &mut reader) },
        OK
    );

    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    // §15: no handle leaks. Every one now reports it is gone rather than
    // serving a stale session.
    let mut size = 0u64;
    assert_eq!(
        status(unsafe { chur_object_reader_size(reader, &mut size) }),
        ChurStatus::SessionExpired
    );
    let query = timeline_query();
    let mut buffer = vec![0u8; 512];
    let mut written = 0usize;
    assert_eq!(
        status(unsafe {
            chur_catalog_query(
                session,
                &query,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut written,
            )
        }),
        ChurStatus::SessionExpired
    );
}

#[test]
fn no_error_string_carries_a_value_the_caller_supplied() {
    // ERROR_MODEL.md: an error carries a stable code and a constant context.
    // The ABI returns only the code, so this asserts the property the code
    // itself has to hold: an invalid credential and an absent vault are one
    // external result.
    let empty = scratch();
    let runtime = open_runtime(&empty);
    let absent = unlock(runtime, PASSWORD, 1).0;
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);

    let populated = scratch();
    create_vault(&populated);
    let runtime = open_runtime(&populated);
    let wrong = unlock(runtime, b"a different password", 1).0;
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);

    assert_eq!(absent, wrong);
    assert_eq!(status(absent), ChurStatus::AuthenticationFailed);
}

#[test]
fn unlocking_reconciles_the_import_journal() {
    // `docs/format/OBJECT_CONTAINER_V1.md` §14.4: an import that a process
    // death interrupted holds a live `ContentKey` envelope and a partial
    // container until an unlock reconciles it. The CLI runs the reconciliation
    // at its own unlock, and Android and iOS reach a vault only through this
    // export, so the export owes the same property.
    let path = scratch();
    let root = chur_catalog::paths::VaultRoot::new(path.clone());
    let mut session = chur_catalog::vault::create(&root, PASSWORD, 1_700_000_000_000)
        .expect("create")
        .activate()
        .expect("activate");
    let store_id = session.object_store_id();
    let running = chur_media::import::begin(
        &mut session,
        chur_media::import::SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(4_096),
            content_type_hint: String::from("image/jpeg"),
            original_filename: Some(String::from("a.jpg")),
            capture_time_ms: Some(1_700_000_000_000),
        },
        chur_media::import::CanonicalMedia {
            media_class: chur_format::constants::MediaClass::Image,
            width: 1_200,
            height: 900,
            duration_ms: 0,
        },
        1_700_000_000_000,
    )
    .expect("begin");
    // The process died mid-import: no commit, no abandon, no lock.
    drop(running);
    let live = chur_catalog::journal::live(session.catalog_ref().unwrap()).unwrap();
    assert_eq!(live.len(), 1, "the interrupted import is live on disk");
    assert!(
        live[0].envelope_body.is_some(),
        "the envelope that opens the partial ciphertext is live"
    );
    let container = root.temporary_container(&store_id, &live[0].temp_path_id);
    assert!(container.exists(), "the partial container is durable");
    drop(session);

    let runtime = open_runtime(&path);
    let (code, opened) = unlock(runtime, PASSWORD, 1);
    assert_eq!(code, OK, "the vault did not unlock");
    assert_ne!(opened, 0);
    assert!(
        !container.exists(),
        "the unlock left the partial ciphertext on disk"
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);

    let reopened = chur_catalog::vault::unlock_with_password(&root, PASSWORD, 1_700_000_000_000)
        .expect("unlock");
    let catalog = reopened.catalog_ref().unwrap();
    assert!(
        chur_catalog::journal::live(catalog).unwrap().is_empty(),
        "the unlock left a live transaction and its envelope in the journal"
    );
    assert!(
        chur_catalog::journal::dead(catalog).unwrap().is_empty(),
        "a reconciled transaction leaves no record behind"
    );
}

#[test]
fn permanent_delete_invalidates_cached_and_uncached_readers_but_keeps_neighbor_open() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let removed = import_at(session, &vec![71; 600_000], 1_700_000_000_001);
    let neighbor = import_at(session, &[72; 4096], 1_700_000_000_000);
    let mut cached = 0;
    let mut cold = 0;
    let mut healthy = 0;
    for (id, reader) in [
        (removed, &mut cached),
        (removed, &mut cold),
        (neighbor, &mut healthy),
    ] {
        assert_eq!(
            unsafe {
                chur_object_reader_open(session, &ChurObjectRefV1 { object_id: id }, 1, reader)
            },
            OK
        );
    }
    let mut buffer = [0; 32];
    let mut written = 0;
    assert_eq!(
        unsafe {
            chur_object_reader_read_at(cached, 0, buffer.as_mut_ptr(), buffer.len(), &mut written)
        },
        OK
    );
    assert_eq!(buffer, [71; 32]);
    assert_eq!(
        unsafe {
            chur_ffi::product::chur_object_delete(session, &ChurObjectRefV1 { object_id: removed })
        },
        OK
    );
    for (reader, offset) in [(cached, 0), (cached, 262_144), (cold, 262_144)] {
        buffer.fill(0xa5);
        written = 99;
        assert_eq!(
            status(unsafe {
                chur_object_reader_read_at(
                    reader,
                    offset,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut written,
                )
            }),
            ChurStatus::SessionExpired
        );
        assert_eq!(written, 0);
        assert_eq!(buffer, [0xa5; 32]);
    }
    assert_eq!(
        unsafe {
            chur_object_reader_read_at(healthy, 0, buffer.as_mut_ptr(), buffer.len(), &mut written)
        },
        OK
    );
    assert_eq!(buffer, [72; 32]);
    for reader in [cached, cold, healthy] {
        assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
    }
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn creation_session_excludes_second_unlock_and_serializes_reader_deletion() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = ChurCreateRequestV1 {
        password: PASSWORD.as_ptr(),
        password_length: PASSWORD.len() as u32,
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    };
    let mut creation = 0;
    assert_eq!(
        unsafe { chur_ffi::product::chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut first = 0;
    assert_eq!(
        unsafe { chur_ffi::product::chur_vault_creation_activate(creation, &mut first) },
        OK
    );
    let object = import(first, &[73; 4096]);
    let second_runtime = open_runtime(&root);
    let (code, second) = unlock(second_runtime, PASSWORD, 1);
    assert_eq!(status(code), ChurStatus::Conflict);
    assert_eq!(
        second, 0,
        "an existing creation session must retain exclusive custody"
    );
    let mut initial = 0;
    assert_eq!(
        unsafe {
            chur_object_reader_open(
                first,
                &ChurObjectRefV1 { object_id: object },
                1,
                &mut initial,
            )
        },
        OK
    );
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let opened = std::thread::scope(|scope| {
        let read_start = start.clone();
        let opening = scope.spawn(move || {
            read_start.wait();
            let mut handles = vec![initial];
            for _ in 0..64 {
                let mut handle = 0;
                let code = unsafe {
                    chur_object_reader_open(
                        first,
                        &ChurObjectRefV1 { object_id: object },
                        1,
                        &mut handle,
                    )
                };
                if code == OK {
                    handles.push(handle);
                } else {
                    assert_eq!(status(code), ChurStatus::NotFound);
                }
            }
            handles
        });
        start.wait();
        assert_eq!(
            unsafe {
                chur_ffi::product::chur_object_delete(first, &ChurObjectRefV1 { object_id: object })
            },
            OK
        );
        opening.join().unwrap()
    });
    for reader in opened {
        let mut buffer = [0xa5; 16];
        let mut written = 99;
        assert_eq!(
            status(unsafe {
                chur_object_reader_read_at(
                    reader,
                    0,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut written,
                )
            }),
            ChurStatus::SessionExpired
        );
        assert_eq!(written, 0);
        assert_eq!(buffer, [0xa5; 16]);
        let mut size = 0;
        assert_eq!(
            status(unsafe { chur_object_reader_size(reader, &mut size) }),
            ChurStatus::SessionExpired
        );
        assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
        assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
    }
    assert_eq!(unsafe { chur_runtime_close(second_runtime) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[cfg(unix)]
fn provider_pipe() -> (std::fs::File, std::fs::File) {
    use std::os::fd::FromRawFd;
    let mut fds = [-1; 2];
    // SAFETY: fds contains two writable descriptor slots.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: pipe returned two distinct owned descriptors, each transferred once.
    (unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe {
        std::fs::File::from_raw_fd(fds[1])
    })
}

#[cfg(unix)]
fn pipe_import(session: u64, source: &std::fs::File) -> u64 {
    let mime = b"application/octet-stream";
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 0,
        known_length_present: 0,
        media_class: 4,
        reserved: 0,
        width: 0,
        height: 0,
        duration_ms: 0,
        known_length: 0,
        capture_time_ms: 0,
        capture_time_present: 0,
        reserved_two: [0; 7],
        content_type: mime.as_ptr(),
        content_type_length: mime.len() as u32,
        original_filename: core::ptr::null(),
        original_filename_length: 0,
    };
    let mut operation = 0;
    // SAFETY: source and request remain valid for this call; out is writable.
    assert_eq!(
        unsafe { chur_import_begin(session, descriptor(source), &request, &mut operation) },
        OK
    );
    operation
}

#[cfg(unix)]
fn wait_pipe_consumed(source: &std::fs::File) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut available: libc::c_int = 0;
        // SAFETY: the pipe is live and FIONREAD writes one initialized integer.
        assert_eq!(
            unsafe { libc::ioctl(descriptor(source), libc::FIONREAD, &mut available) },
            0
        );
        if available == 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "provider input was never consumed"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(unix)]
#[test]
fn stalled_provider_read_cancels_without_eof_and_discards_partial_import() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let (source, mut producer) = provider_pipe();
    producer.write_all(&[7; 1024]).unwrap();
    let operation = pipe_import(session, &source);
    wait_pipe_consumed(&source);
    assert_eq!(unsafe { chur_operation_cancel(operation) }, OK);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || send.send(drain(operation)).unwrap());
    let result = receive.recv_timeout(std::time::Duration::from_secs(3));
    // Release only after the timed result: old code needs EOF and fails the assertion.
    drop(producer);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), ChurStatus::Cancelled as i32);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    let mut output = vec![0; 65536];
    let mut length = 0;
    assert_eq!(
        unsafe {
            chur_catalog_query(
                session,
                &timeline_query(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
            )
        },
        OK
    );
    assert!(decode_page(&output[..length]).unwrap().objects.is_empty());
    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    // Open directly, without the FFI unlock's orphan sweep, to check rollback.
    let directory = chur_catalog::paths::VaultRoot::new(root.clone());
    let mut reopened = chur_catalog::vault::unlock_with_password(&directory, PASSWORD, 2).unwrap();
    assert!(
        chur_catalog::journal::live(reopened.catalog_ref().unwrap())
            .unwrap()
            .is_empty()
    );
    assert!(
        chur_catalog::journal::dead(reopened.catalog_ref().unwrap())
            .unwrap()
            .is_empty()
    );
    reopened.lock().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn locking_stalled_provider_write_cancels_all_workers_before_joining() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let object_id = import(session, &vec![7; 4 * 1024 * 1024]);
    // Reserve the lower operation slot, then put the blocked writer in a higher one.
    let scan_request = ChurScanRequestV1 {
        single_object: 0,
        reserved: [0; 7],
        object_id: [0; 16],
    };
    let mut spare = 0;
    assert_eq!(
        unsafe { chur_integrity_scan_begin(session, &scan_request, &mut spare) },
        OK
    );
    assert_eq!(drain(spare), OK);
    let (reader, writer) = provider_pipe();
    let mut exporting = 0;
    assert_eq!(
        unsafe {
            chur_export_begin(
                session,
                &ChurObjectRefV1 { object_id },
                descriptor(&writer),
                &mut exporting,
            )
        },
        OK
    );
    let mut ready = libc::pollfd {
        fd: descriptor(&reader),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: ready is a valid one-entry pollfd array and reader stays open.
    assert_eq!(unsafe { libc::poll(&mut ready, 1, 10_000) }, 1);
    assert_eq!(unsafe { chur_operation_close(spare) }, OK);
    let (input, producer) = provider_pipe();
    let queued = pipe_import(session, &input);
    let (send, receive) = std::sync::mpsc::channel();
    let worker =
        std::thread::spawn(move || send.send(unsafe { chur_vault_lock(session, 2) }).unwrap());
    let result = receive.recv_timeout(std::time::Duration::from_secs(3));
    // A failed old implementation is released before the test reports failure.
    drop(reader);
    drop(producer);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), OK);
    for operation in [queued, exporting] {
        assert_eq!(
            status(unsafe { chur_operation_poll(operation, &mut zeroed_progress()) }),
            ChurStatus::SessionExpired
        );
    }
    let mut output = [0; 128];
    let mut length = 0;
    assert_eq!(
        status(unsafe {
            chur_catalog_query(
                session,
                &timeline_query(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
            )
        }),
        ChurStatus::VaultLocked
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn stalled_provider_write_reports_cancelled_without_provider_drain() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let object_id = import(session, &vec![7; 4 * 1024 * 1024]);
    let (reader, writer) = provider_pipe();
    let mut exporting = 0;
    assert_eq!(
        unsafe {
            chur_export_begin(
                session,
                &ChurObjectRefV1 { object_id },
                descriptor(&writer),
                &mut exporting,
            )
        },
        OK
    );
    let mut ready = libc::pollfd {
        fd: descriptor(&reader),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: ready covers one valid pollfd; reader remains open for the call.
    assert_eq!(unsafe { libc::poll(&mut ready, 1, 10_000) }, 1);
    assert_eq!(unsafe { chur_operation_cancel(exporting) }, OK);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || send.send(drain(exporting)).unwrap());
    let result = receive.recv_timeout(std::time::Duration::from_secs(3));
    drop(reader);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), ChurStatus::Cancelled as i32);
    assert_eq!(unsafe { chur_operation_close(exporting) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn seekable_backup_apis_reject_provider_pipes_before_starting_workers() {
    let root = scratch();
    create_vault(&root);
    let runtime = open_runtime(&root);
    let (_, session) = unlock(runtime, PASSWORD, 1);
    let (reader, writer) = provider_pipe();
    let mut operation = 0;
    assert_eq!(
        status(unsafe {
            chur_ffi::product::chur_backup_create(session, descriptor(&writer), &mut operation)
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(
        status(unsafe {
            chur_ffi::product::chur_backup_restore(
                runtime,
                descriptor(&reader),
                PASSWORD.as_ptr(),
                PASSWORD.len() as u32,
                &mut operation,
            )
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(operation, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}
