//! The Phase-1 product surface of `docs/interop/FFI_CONTRACT.md` §6.5, driven
//! through the exported symbols.
//!
//! One test walks the whole product flow: create a vault, offer the recovery
//! slot, import, favourite, album, tag, read the detail record, store and read
//! a thumbnail, and delete. The other tests are the refusals each export owes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![expect(
    unsafe_code,
    reason = "the tests drive the C ABI, which is unsafe to call by definition"
)]

use std::io::{Seek, Write};

use chur_core::ChurStatus;
use chur_ffi::api::*;
use chur_ffi::product::*;
use chur_ffi::records::*;

const OK: i32 = 0;
const PASSWORD: &[u8] = b"correct horse battery staple";

fn status(value: i32) -> ChurStatus {
    ChurStatus::from_i32(value)
}

fn scratch() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-product-{}",
        chur_crypto::random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn open_runtime(root: &std::path::Path) -> u64 {
    let text = root.to_str().unwrap().as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: text.as_ptr(),
        root_path_length: text.len() as u32,
    };
    let mut handle = 0u64;
    assert_eq!(unsafe { chur_runtime_open(&config, &mut handle) }, OK);
    handle
}

fn create_request(password: &[u8]) -> ChurCreateRequestV1 {
    ChurCreateRequestV1 {
        password: password.as_ptr(),
        password_length: password.len() as u32,
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    }
}

fn tempfile() -> std::fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-product-src-{}",
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
fn descriptor(file: &std::fs::File) -> i32 {
    use std::os::fd::AsRawFd;
    file.as_raw_fd()
}

fn drain(operation: u64) -> i32 {
    loop {
        let mut progress = ChurProgressV1 {
            kind: 0,
            stage: 0,
            processed: 0,
            total: 0,
            terminal: 0,
            reserved: [0; 3],
            status: 0,
            object_id: [0; 16],
        };
        assert_eq!(unsafe { chur_operation_poll(operation, &mut progress) }, OK);
        if progress.terminal == 1 {
            return progress.status;
        }
        std::thread::yield_now();
    }
}

fn import(session: u64, bytes: &[u8], filename: &[u8]) -> [u8; 16] {
    import_with_id(session, bytes, filename, None)
}

fn import_with_id(
    session: u64,
    bytes: &[u8],
    filename: &[u8],
    requested: Option<[u8; 16]>,
) -> [u8; 16] {
    let mut file = tempfile();
    file.write_all(bytes).unwrap();
    file.rewind().unwrap();
    let content_type = b"image/jpeg";
    let request = ChurImportRequestV2 {
        requested_object_id: requested
            .as_ref()
            .map_or(core::ptr::null(), |id| id.as_ptr()),
        seekable: 1,
        known_length_present: 1,
        media_class: 1,
        reserved: 0,
        width: 1_200,
        height: 900,
        duration_ms: 0,
        known_length: bytes.len() as u64,
        capture_time_ms: 1_700_000_000_000,
        capture_time_present: 1,
        reserved_two: [0; 7],
        content_type: content_type.as_ptr(),
        content_type_length: content_type.len() as u32,
        original_filename: filename.as_ptr(),
        original_filename_length: filename.len() as u32,
    };
    let mut operation = 0u64;
    assert_eq!(
        unsafe { chur_import_begin(session, descriptor(&file), &request, &mut operation) },
        OK
    );
    assert_eq!(drain(operation), OK);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    latest_object(session)
}

#[cfg(unix)]
#[test]
fn an_unknown_length_pipe_imports_without_seeking() {
    use std::net::Shutdown;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let request = create_request(PASSWORD);
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );

    let (source, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&[0x5a; 4_096]).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    let content_type = b"audio/wav";
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 0,
        known_length_present: 0,
        media_class: 3,
        reserved: 0,
        width: 0,
        height: 0,
        duration_ms: 1_000,
        known_length: 0,
        capture_time_ms: 0,
        capture_time_present: 0,
        reserved_two: [0; 7],
        content_type: content_type.as_ptr(),
        content_type_length: content_type.len() as u32,
        original_filename: std::ptr::null(),
        original_filename_length: 0,
    };
    let mut operation = 0;
    assert_eq!(
        unsafe { chur_import_begin(session, source.as_raw_fd(), &request, &mut operation) },
        OK
    );
    assert_eq!(drain(operation), OK);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    assert_eq!(page(session, 1, [0; 16], b"").objects.len(), 1);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

fn page(session: u64, scope: u8, scope_id: [u8; 16], terms: &[u8]) -> DecodedPage {
    let query = ChurQueryV1 {
        scope,
        sort: 1,
        kinds: 0,
        limit: 0,
        scope_id,
        cursor_present: 0,
        cursor: [0; 42],
        terms: terms.as_ptr(),
        terms_length: terms.len() as u32,
    };
    let mut buffer = vec![0u8; 63 + 79 * 200];
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
    decode_page(&buffer[..written]).unwrap()
}

fn latest_object(session: u64) -> [u8; 16] {
    let page = page(session, 1, [0; 16], b"");
    *page.objects.first().unwrap().object_id.as_bytes()
}

#[test]
fn the_whole_product_flow_runs_through_the_boundary() {
    let root = scratch();
    let runtime = open_runtime(&root);

    // PROVISIONING §2: first launch finds no vault.
    let mut present = 9u8;
    assert_eq!(unsafe { chur_vault_present(runtime, &mut present) }, OK);
    assert_eq!(present, 0);

    // §3 steps 3 to 6, with the recovery offer of step 5 in its place.
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut phrase_bytes = vec![0u8; RECOVERY_PHRASE_MAX];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            chur_vault_creation_add_recovery_slot(
                creation,
                phrase_bytes.as_mut_ptr(),
                phrase_bytes.len(),
                &mut written,
            )
        },
        OK
    );
    let phrase = String::from_utf8(phrase_bytes[..written].to_vec()).expect("UTF-8");
    assert_eq!(phrase.split_whitespace().count(), 24, "a 24-word phrase");
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    assert_eq!(unsafe { chur_vault_present(runtime, &mut present) }, OK);
    assert_eq!(present, 1);

    // §6.5: the slot list carries the two slots and no body.
    let mut slots = vec![0u8; 1_024];
    assert_eq!(
        unsafe { chur_vault_slots(session, slots.as_mut_ptr(), slots.len(), &mut written) },
        OK
    );
    assert_eq!(written, 4 + 2 * 25, "two slots at 25 bytes each");

    // Import, then every library mutation the four destinations need.
    let bytes: Vec<u8> = (0..40_000u32).map(|value| (value % 253) as u8).collect();
    let object_id = import(session, &bytes, "Bäckerei.jpg".as_bytes());
    let reference = ChurObjectRefV1 { object_id };

    assert_eq!(
        unsafe { chur_object_set_favorite(session, &reference, 1) },
        OK
    );
    assert_eq!(page(session, 3, [0; 16], b"").objects.len(), 1);

    let name = b"Holiday";
    let mut album_id = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_album_create(
                session,
                name.as_ptr(),
                name.len() as u32,
                core::ptr::null(),
                album_id.as_mut_ptr(),
            )
        },
        OK
    );
    assert_eq!(
        unsafe { chur_album_set_membership(session, album_id.as_ptr(), &reference, 1) },
        OK
    );
    assert_eq!(page(session, 2, album_id, b"").objects.len(), 1);

    let mut albums = vec![0u8; 4_096];
    assert_eq!(
        unsafe { chur_album_list(session, albums.as_mut_ptr(), albums.len(), &mut written) },
        OK
    );
    let listed = decode_album_list(&albums[..written]).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Holiday");
    assert_eq!(listed[0].member_count, 1);
    assert_eq!(listed[0].parent_id, None);
    assert_eq!(listed[0].position, 0);

    let mut short = [0u8; 4];
    assert_eq!(
        status(unsafe { chur_album_list(session, short.as_mut_ptr(), short.len(), &mut written) }),
        ChurStatus::ResourceLimitExceeded
    );
    assert_eq!(written, 4 + 16 + 8 + 2 + name.len() + 16 + 8);
    let renamed = b"Journeys";
    assert_eq!(
        unsafe {
            chur_album_rename(
                session,
                album_id.as_ptr(),
                renamed.as_ptr(),
                renamed.len() as u32,
            )
        },
        OK
    );
    let mut child_id = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_album_create(
                session,
                b"Child".as_ptr(),
                5,
                core::ptr::null(),
                child_id.as_mut_ptr(),
            )
        },
        OK
    );
    let none = [0u8; 16];
    assert_eq!(
        unsafe { chur_album_move(session, child_id.as_ptr(), album_id.as_ptr(), none.as_ptr()) },
        OK
    );
    assert_eq!(
        status(unsafe {
            chur_album_move(session, album_id.as_ptr(), child_id.as_ptr(), none.as_ptr())
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(
        unsafe {
            chur_album_move_member(
                session,
                album_id.as_ptr(),
                object_id.as_ptr(),
                none.as_ptr(),
            )
        },
        OK
    );
    assert_eq!(unsafe { chur_album_delete(session, child_id.as_ptr()) }, OK);
    assert_eq!(page(session, 2, album_id, b"").objects.len(), 1);

    let zero = [0u8; 16];
    let mut nested = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_album_place_objects(
                session,
                zero.as_ptr(),
                b"Nested".as_ptr(),
                6,
                album_id.as_ptr(),
                zero.as_ptr(),
                object_id.as_ptr(),
                1,
                0,
                nested.as_mut_ptr(),
            )
        },
        OK,
    );
    assert_eq!(page(session, 2, nested, b"").objects.len(), 1);
    assert_eq!(page(session, 2, album_id, b"").objects.len(), 1);
    assert_eq!(
        unsafe {
            chur_album_place_objects(
                session,
                nested.as_ptr(),
                core::ptr::null(),
                0,
                zero.as_ptr(),
                album_id.as_ptr(),
                object_id.as_ptr(),
                1,
                1,
                nested.as_mut_ptr(),
            )
        },
        OK,
    );
    assert_eq!(page(session, 2, album_id, b"").objects.len(), 0);
    assert_eq!(
        unsafe {
            chur_album_place_objects(
                session,
                album_id.as_ptr(),
                core::ptr::null(),
                0,
                zero.as_ptr(),
                nested.as_ptr(),
                object_id.as_ptr(),
                1,
                1,
                album_id.as_mut_ptr(),
            )
        },
        OK,
    );
    assert_eq!(page(session, 2, album_id, b"").objects.len(), 1);

    let tag_name = "Sommer";
    let mut tag_id = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_tag_create(
                session,
                tag_name.as_ptr(),
                tag_name.len() as u32,
                tag_id.as_mut_ptr(),
            )
        },
        OK
    );
    assert_eq!(
        unsafe { chur_object_set_tag(session, tag_id.as_ptr(), &reference, 1) },
        OK
    );
    assert_eq!(page(session, 4, tag_id, b"").objects.len(), 1);
    // §16.4: a tag is indexed, and the tokenizer folds the diacritic.
    assert_eq!(page(session, 5, [0; 16], b"sommer").objects.len(), 1);
    assert_eq!(page(session, 5, [0; 16], b"backerei").objects.len(), 1);

    // §6.5: the detail record, which is the only record carrying private text.
    let mut detail = vec![0u8; 8_192];
    assert_eq!(
        unsafe {
            chur_object_metadata(
                session,
                &reference,
                detail.as_mut_ptr(),
                detail.len(),
                &mut written,
            )
        },
        OK
    );
    let metadata = decode_object_metadata(&detail[..written]).unwrap();
    assert_eq!(metadata.filename, "Bäckerei.jpg");
    assert_eq!(metadata.content_type, "image/jpeg");
    assert_eq!(metadata.plaintext_size, bytes.len() as u64);
    assert_eq!(metadata.width, 1_200);
    assert!(!metadata.capture_time_substituted);
    assert_eq!(metadata.tags.len(), 1);
    assert_eq!(metadata.tags[0].1, "Sommer");
    let mut tiny_tags = [0x5au8; 1];
    let mut tag_bytes = 0usize;
    assert_eq!(
        status(unsafe { chur_tag_list(session, tiny_tags.as_mut_ptr(), 1, &mut tag_bytes) }),
        ChurStatus::ResourceLimitExceeded
    );
    assert!(tag_bytes > tiny_tags.len());
    assert_eq!(tiny_tags, [0x5a]);

    assert_eq!(
        unsafe { chur_favorites_set(session, object_id.as_ptr(), 1, 0) },
        OK
    );
    assert_eq!(page(session, 3, [0; 16], b"").objects.len(), 0);
    assert_eq!(
        unsafe { chur_favorites_set(session, object_id.as_ptr(), 1, 1) },
        OK
    );
    assert_eq!(page(session, 3, [0; 16], b"").objects.len(), 1);
    let mut created_tag = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_tag_apply_selection(
                session,
                zero.as_ptr(),
                b"Travel".as_ptr(),
                6,
                object_id.as_ptr(),
                1,
                1,
                created_tag.as_mut_ptr(),
            )
        },
        OK
    );
    assert_eq!(page(session, 4, created_tag, b"").objects.len(), 1);
    assert_eq!(
        unsafe { chur_tag_rename(session, created_tag.as_ptr(), b"Trips".as_ptr(), 5) },
        OK
    );
    assert_eq!(page(session, 5, zero, b"trips").objects.len(), 1);
    assert_eq!(
        unsafe {
            chur_tag_apply_selection(
                session,
                created_tag.as_ptr(),
                core::ptr::null(),
                0,
                object_id.as_ptr(),
                1,
                0,
                created_tag.as_mut_ptr(),
            )
        },
        OK
    );
    assert_eq!(page(session, 4, created_tag, b"").objects.len(), 0);
    assert_eq!(
        unsafe { chur_tag_delete(session, created_tag.as_ptr()) },
        OK
    );
    assert_eq!(page(session, 5, zero, b"trips").objects.len(), 0);

    // MEDIA_PIPELINE §6: the platform hands over a thumbnail and reads it back.
    let thumbnail: Vec<u8> = (0..3_000u32).map(|value| (value % 97) as u8).collect();
    assert_eq!(
        unsafe {
            chur_derived_put(
                session,
                &reference,
                2,
                320,
                240,
                thumbnail.as_ptr(),
                thumbnail.len() as u32,
            )
        },
        OK
    );
    assert!(page(session, 1, [0; 16], b"").objects[0].thumbnail_ready);
    let mut read = vec![0u8; 8_192];
    assert_eq!(
        unsafe {
            chur_derived_read(
                session,
                &reference,
                2,
                read.as_mut_ptr(),
                read.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&read[..written], thumbnail.as_slice());

    // Trash keeps the key, preview, and organization until restore or purge.
    assert_eq!(
        unsafe { chur_trash_set(session, object_id.as_ptr(), 1, 0) },
        OK
    );
    assert!(page(session, 1, [0; 16], b"").objects.is_empty());
    assert!(page(session, 3, [0; 16], b"").objects.is_empty());
    assert_eq!(page(session, 7, [0; 16], b"").objects.len(), 1);
    assert_eq!(
        unsafe {
            chur_derived_read(
                session,
                &reference,
                2,
                read.as_mut_ptr(),
                read.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(
        unsafe { chur_trash_set(session, object_id.as_ptr(), 1, 1) },
        OK
    );
    assert_eq!(page(session, 1, [0; 16], b"").objects.len(), 1);
    assert_eq!(page(session, 3, [0; 16], b"").objects.len(), 1);
    assert!(page(session, 7, [0; 16], b"").objects.is_empty());
    assert_eq!(
        unsafe { chur_trash_set(session, object_id.as_ptr(), 1, 0) },
        OK
    );

    // Deletion runs the whole §14.1 transaction.
    assert_eq!(unsafe { chur_object_delete(session, &reference) }, OK);
    assert!(page(session, 7, [0; 16], b"").objects.is_empty());
    assert!(page(session, 1, [0; 16], b"").objects.is_empty());
    assert!(page(session, 3, [0; 16], b"").objects.is_empty());
    assert!(page(session, 5, [0; 16], b"backerei").objects.is_empty());
    assert_eq!(
        status(unsafe {
            chur_object_metadata(
                session,
                &reference,
                read.as_mut_ptr(),
                read.len(),
                &mut written,
            )
        }),
        ChurStatus::NotFound
    );

    // The recovery phrase from step 5 still opens the vault.
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    let runtime = open_runtime(&root);
    let unlock = ChurUnlockRequestV1 {
        factor: 2,
        reserved: [0; 3],
        secret: phrase.as_ptr(),
        secret_length: phrase.len() as u32,
    };
    let mut recovered = 0u64;
    assert_eq!(
        unsafe { chur_vault_unlock(runtime, &unlock, &mut recovered) },
        OK
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn an_abandoned_creation_leaves_no_vault() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut present = 9u8;
    assert_eq!(unsafe { chur_vault_present(runtime, &mut present) }, OK);
    assert_eq!(present, 0, "nothing is openable before activation");

    assert_eq!(unsafe { chur_vault_creation_abandon(creation) }, OK);
    assert_eq!(unsafe { chur_vault_present(runtime, &mut present) }, OK);
    assert_eq!(present, 0);

    // §3: the abandon closed the handle, so a later call on it is
    // SESSION_EXPIRED rather than a second creation. INVALID_INPUT is reserved
    // for a value this process never issued, and this one was issued.
    let mut session = 0u64;
    assert_eq!(
        status(unsafe { chur_vault_creation_activate(creation, &mut session) }),
        ChurStatus::SessionExpired
    );
    assert_eq!(session, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_creation_handle_activates_once() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut first = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut first) },
        OK
    );
    let mut second = 0u64;
    assert_eq!(
        status(unsafe { chur_vault_creation_activate(creation, &mut second) }),
        ChurStatus::SessionExpired
    );
    assert_eq!(second, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn the_last_portable_slot_cannot_be_removed_through_the_boundary() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );

    let mut slots = vec![0u8; 1_024];
    let mut written = 0usize;
    assert_eq!(
        unsafe { chur_vault_slots(session, slots.as_mut_ptr(), slots.len(), &mut written) },
        OK
    );
    // One slot: the password. Its identifier is the first 16 bytes after the
    // count.
    assert_eq!(written, 4 + 25);
    let slot_id: [u8; 16] = slots[4..20].try_into().unwrap();
    assert_eq!(
        status(unsafe { chur_vault_remove_slot(session, slot_id.as_ptr()) }),
        ChurStatus::Conflict,
        "KEY_SLOTS.md §9 keeps a verified recovery path through every update"
    );

    // A destination smaller than the contract's bound is refused before the
    // slot is committed: a caller that cannot receive the phrase must find
    // the descriptor as it was, and the successful call below proves the
    // refused one added nothing.
    let mut short = [0u8; 8];
    assert_eq!(
        status(unsafe {
            chur_vault_add_recovery_slot(session, short.as_mut_ptr(), short.len(), &mut written)
        }),
        ChurStatus::ResourceLimitExceeded
    );

    // With a recovery slot present it becomes removable.
    let mut phrase = vec![0u8; RECOVERY_PHRASE_MAX];
    assert_eq!(
        unsafe {
            chur_vault_add_recovery_slot(session, phrase.as_mut_ptr(), phrase.len(), &mut written)
        },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_remove_slot(session, slot_id.as_ptr()) },
        OK
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_device_slot_exposes_only_its_platform_item_id_until_removal() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    let item_id = [42u8; 16];
    let mut secret = [0u8; 32];
    assert_eq!(
        unsafe { chur_vault_add_device_slot(session, item_id.as_ptr(), secret.as_mut_ptr()) },
        OK
    );
    let mut slots = vec![0u8; 1_024];
    let mut written = 0usize;
    assert_eq!(
        unsafe { chur_vault_slots(session, slots.as_mut_ptr(), slots.len(), &mut written) },
        OK
    );
    let count = u32::from_be_bytes(slots[..4].try_into().unwrap()) as usize;
    let apple_slot: [u8; 16] = (0..count)
        .find_map(|index| {
            let start = 4 + index * 25;
            (slots[start + 16] == 3).then(|| slots[start..start + 16].try_into().unwrap())
        })
        .unwrap();
    let mut identifier = [0u8; 64];
    assert_eq!(
        unsafe {
            chur_vault_platform_slot_identifier(
                session,
                apple_slot.as_ptr(),
                identifier.as_mut_ptr(),
                identifier.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(written, 16);
    assert_eq!(&identifier[..written], &item_id);
    assert_ne!(&identifier[..written], &secret[..16]);
    assert_eq!(
        unsafe { chur_vault_remove_slot(session, apple_slot.as_ptr()) },
        OK
    );
    assert_eq!(
        status(unsafe {
            chur_vault_platform_slot_identifier(
                session,
                apple_slot.as_ptr(),
                identifier.as_mut_ptr(),
                identifier.len(),
                &mut written,
            )
        }),
        ChurStatus::NotFound
    );
    assert_eq!(written, 0);
    secret.fill(0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_password_change_takes_effect_and_retires_the_old_one() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );

    let replacement = b"a different password entirely";
    let change = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: replacement.as_ptr(),
        secret_length: replacement.len() as u32,
    };
    assert_eq!(unsafe { chur_vault_change_password(session, &change) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);

    let runtime = open_runtime(&root);
    let mut opened = 0u64;
    let old = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: PASSWORD.as_ptr(),
        secret_length: PASSWORD.len() as u32,
    };
    assert_eq!(
        status(unsafe { chur_vault_unlock(runtime, &old, &mut opened) }),
        ChurStatus::AuthenticationFailed
    );
    assert_eq!(
        unsafe { chur_vault_unlock(runtime, &change, &mut opened) },
        OK
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_boolean_argument_is_strictly_zero_or_one() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let object_id = import(session, &[1u8; 2_048], b"a.jpg");
    let reference = ChurObjectRefV1 { object_id };
    assert_eq!(
        status(unsafe { chur_object_set_favorite(session, &reference, 2) }),
        ChurStatus::NonCanonicalEncoding
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_derivative_above_its_long_edge_is_refused_at_the_boundary() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let object_id = import(session, &[1u8; 2_048], b"a.jpg");
    let reference = ChurObjectRefV1 { object_id };
    let bytes = [7u8; 64];
    assert_eq!(
        status(unsafe { chur_derived_put(session, &reference, 2, 321, 240, bytes.as_ptr(), 64) }),
        ChurStatus::ResourceLimitExceeded
    );
    // The original kind is not a derived asset.
    assert_eq!(
        status(unsafe { chur_derived_put(session, &reference, 1, 320, 240, bytes.as_ptr(), 64) }),
        ChurStatus::InvalidInput
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

/// A stand-in for the Keystore cipher, as in `chur-catalog`'s vault tests.
///
/// Rust neither performs nor verifies this AEAD, so what these tests check is
/// that the alias, the nonce, the wrapped bytes, and the AAD cross the boundary
/// unchanged and that the unwrapped root opens the vault.
fn keystore_wrap(aad: &[u8], root: &[u8; 32]) -> ([u8; 12], [u8; 48]) {
    let nonce = chur_crypto::random::array::<12>().unwrap();
    let mask = chur_crypto::commit::commit(b"chur/test/keystore-stand-in", &[&nonce, aad]);
    let mut wrapped = [0u8; 48];
    for (index, byte) in root.iter().enumerate() {
        wrapped[index] = byte ^ mask[index];
    }
    wrapped[32..].copy_from_slice(&mask[..16]);
    (nonce, wrapped)
}

fn keystore_unwrap(gcm_nonce: &[u8], aad: &[u8], wrapped: &[u8]) -> [u8; 32] {
    let mask = chur_crypto::commit::commit(b"chur/test/keystore-stand-in", &[gcm_nonce, aad]);
    assert_eq!(wrapped[32..], mask[..16]);
    let mut root = [0u8; 32];
    for (index, byte) in root.iter_mut().enumerate() {
        *byte = wrapped[index] ^ mask[index];
    }
    root
}

/// Reads a big-endian `u32` and the bytes it counts.
fn take_bounded<'a>(bytes: &'a [u8], at: &mut usize) -> &'a [u8] {
    let length = u32::from_be_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    let value = &bytes[*at..*at + length];
    *at += length;
    value
}

/// Enrolls a Keystore slot on an open session and returns the alias.
fn enroll_keystore(session: u64) -> Vec<u8> {
    let mut buffer = [0u8; 512];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            chur_vault_keystore_begin(session, buffer.as_mut_ptr(), buffer.len(), &mut written)
        },
        OK
    );
    let record = &buffer[..written];
    let mut at = 0usize;
    let alias = take_bounded(record, &mut at).to_vec();
    let aad = take_bounded(record, &mut at).to_vec();
    let root: [u8; 32] = record[at..at + 32].try_into().unwrap();
    let (nonce, wrapped) = keystore_wrap(&aad, &root);
    assert_eq!(
        unsafe { chur_vault_keystore_commit(session, nonce.as_ptr(), wrapped.as_ptr()) },
        OK
    );
    alias
}

/// Opens a session on a fresh vault.
fn fresh_session(runtime: u64) -> u64 {
    let request = create_request(PASSWORD);
    let mut creation = 0u64;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &request, &mut creation) },
        OK
    );
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    session
}

#[test]
fn the_keystore_slot_enrolls_and_unlocks_through_the_boundary() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    let alias = enroll_keystore(session);
    assert_eq!(alias.len(), 32);
    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    // The material is readable while the vault is locked, which is what a host
    // needs: it cannot ask the Keystore before it has the alias and the nonce.
    let mut buffer = [0u8; 512];
    let mut written = 0usize;
    assert_eq!(
        unsafe {
            chur_vault_keystore_material(runtime, buffer.as_mut_ptr(), buffer.len(), &mut written)
        },
        OK
    );
    let record = &buffer[..written];
    assert_eq!(u32::from_be_bytes(record[..4].try_into().unwrap()), 1);
    let mut at = 4usize;
    let stored_alias = take_bounded(record, &mut at).to_vec();
    let aad = take_bounded(record, &mut at).to_vec();
    let nonce = &record[at..at + 12];
    let wrapped = &record[at + 12..at + 60];
    assert_eq!(stored_alias, alias);

    let unwrapped = keystore_unwrap(nonce, &aad, wrapped);
    let unlock = ChurUnlockRequestV1 {
        factor: 4,
        reserved: [0; 3],
        secret: unwrapped.as_ptr(),
        secret_length: unwrapped.len() as u32,
    };
    let mut reopened = 0u64;
    assert_eq!(
        unsafe { chur_vault_unlock(runtime, &unlock, &mut reopened) },
        OK
    );
    assert_ne!(reopened, 0);
    assert_eq!(unsafe { chur_session_close(reopened) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_root_the_keystore_did_not_return_is_authentication_failed() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    enroll_keystore(session);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    let wrong = [7u8; 32];
    let unlock = ChurUnlockRequestV1 {
        factor: 4,
        reserved: [0; 3],
        secret: wrong.as_ptr(),
        secret_length: wrong.len() as u32,
    };
    let mut reopened = 0u64;
    assert_eq!(
        status(unsafe { chur_vault_unlock(runtime, &unlock, &mut reopened) }),
        ChurStatus::AuthenticationFailed
    );
    assert_eq!(reopened, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_commit_with_no_enrollment_is_refused() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    let nonce = [0u8; 12];
    let wrapped = [0u8; 48];
    assert_eq!(
        status(unsafe { chur_vault_keystore_commit(session, nonce.as_ptr(), wrapped.as_ptr()) }),
        ChurStatus::Conflict
    );
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn a_material_buffer_smaller_than_the_record_writes_nothing() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    enroll_keystore(session);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    let mut small = [0u8; 8];
    let mut written = 7usize;
    assert_eq!(
        status(unsafe {
            chur_vault_keystore_material(runtime, small.as_mut_ptr(), small.len(), &mut written)
        }),
        ChurStatus::ResourceLimitExceeded
    );
    assert_eq!(written, 0, "the count is set on every failure");
    assert_eq!(small, [0u8; 8], "a refused write leaves the buffer alone");
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
}

#[test]
fn private_note_output_preflight_cannot_commit_a_failed_create_or_change() {
    use chur_ffi::private_notes::*;
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &create_request(PASSWORD), &mut creation) },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let mut save = vec![0; 16];
    save.extend_from_slice(&0u64.to_be_bytes());
    save.push(0);
    save.push(1); // Markdown body format
    save.extend_from_slice(&1u32.to_be_bytes());
    save.push(b't');
    save.extend_from_slice(&1u32.to_be_bytes());
    save.push(b'b');
    let mut written = 999usize;
    assert_eq!(
        unsafe {
            chur_private_note_save(
                session,
                save.as_ptr(),
                save.len(),
                core::ptr::null_mut(),
                0,
                &mut written,
            )
        },
        ChurStatus::ResourceLimitExceeded as i32
    );
    assert_eq!(written, 0);
    assert_eq!(
        unsafe {
            chur_private_note_save(
                session,
                save.as_ptr(),
                save.len(),
                core::ptr::null_mut(),
                1048576,
                &mut written,
            )
        },
        ChurStatus::InvalidInput as i32
    );
    let mut query = vec![0];
    query.extend_from_slice(&50u64.to_be_bytes());
    query.extend_from_slice(&[0; 8]);
    let mut output = vec![0; 1048576];
    assert_eq!(
        unsafe {
            chur_private_notes_query(
                session,
                query.as_ptr(),
                query.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&output[..4], &[0; 4]);
    save[25] = 2; // Unknown format must not commit even with sufficient output capacity.
    assert_eq!(
        unsafe {
            chur_private_note_save(
                session,
                save.as_ptr(),
                save.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        ChurStatus::InvalidInput as i32
    );
    assert_eq!(written, 0);
    save[25] = 1;
    assert_eq!(
        unsafe {
            chur_private_note_save(
                session,
                save.as_ptr(),
                save.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        OK
    );
    let id = output[..16].to_vec();
    let mut change = id.clone();
    change.extend_from_slice(&1u64.to_be_bytes());
    change.push(3);
    assert_eq!(
        unsafe {
            chur_private_note_change(
                session,
                change.as_ptr(),
                change.len(),
                core::ptr::null_mut(),
                0,
                &mut written,
            )
        },
        ChurStatus::ResourceLimitExceeded as i32
    );
    assert_eq!(
        unsafe {
            chur_private_note_get(
                session,
                id.as_ptr(),
                id.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&output[16..24], &1u64.to_be_bytes());
    assert_eq!(&output[40..48], &u64::MAX.to_be_bytes());
    assert_eq!(
        unsafe {
            chur_private_notes_query(
                session,
                query.as_ptr(),
                query.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&output[..4], &1u32.to_be_bytes());
    output.fill(0);
    save.fill(0);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn content_index_records_validate_bounds_source_and_output_before_mutation() {
    use chur_ffi::content_index::*;
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &create_request(PASSWORD), &mut creation) },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let object = import(session, b"authenticated original", b"scan.jpg");
    let mut request = vec![1, 0];
    request.extend_from_slice(&[0; 16]);
    request.extend_from_slice(&100u32.to_be_bytes());
    let mut out = vec![0u8; 1_048_576];
    let mut written = 999;
    assert_eq!(
        unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&out[..5], &[1, 0, 0, 0, 1]);
    assert_eq!(&out[5..21], &object);
    let source = &out[21..37];
    let mut put = vec![1];
    put.extend_from_slice(&object);
    put.extend_from_slice(source);
    put.push(1);
    put.extend_from_slice(&1u32.to_be_bytes());
    let text = "Секретный OCR text";
    put.extend_from_slice(&(text.len() as u32).to_be_bytes());
    put.extend_from_slice(text.as_bytes());
    assert_eq!(
        status(unsafe {
            chur_content_index_put(
                session,
                put.as_ptr(),
                put.len(),
                core::ptr::null_mut(),
                0,
                &mut written,
            )
        }),
        ChurStatus::ResourceLimitExceeded
    );
    assert_eq!(written, 0);
    let mut trailing = put.clone();
    trailing.push(0);
    assert_eq!(
        status(unsafe {
            chur_content_index_put(
                session,
                trailing.as_ptr(),
                trailing.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::InvalidInput
    );
    let mut wrong = put.clone();
    wrong[17] ^= 1;
    assert_eq!(
        status(unsafe {
            chur_content_index_put(
                session,
                wrong.as_ptr(),
                wrong.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::Conflict
    );
    assert_eq!(
        unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&out[..5], &[1, 0, 0, 0, 1]);
    assert_eq!(
        unsafe {
            chur_content_index_put(
                session,
                put.as_ptr(),
                put.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(written, 0);
    assert_eq!(
        unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&out[..5], &[1, 0, 0, 0, 0]);
    assert_eq!(
        unsafe {
            chur_content_index_clear(
                session,
                [1u8].as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(
        unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    assert_eq!(&out[..5], &[1, 0, 0, 0, 1]);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(
        status(unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::SessionExpired
    );
    out.fill(0);
    put.fill(0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_content_controls_preserve_the_existing_index_and_authenticated_original() {
    use chur_ffi::content_index::*;
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &create_request(PASSWORD), &mut creation) },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let original = b"authenticated original survives malformed OCR records";
    let object = import(session, original, b"scan.jpg");
    let mut request = vec![1, 0];
    request.extend_from_slice(&[0; 16]);
    request.extend_from_slice(&100u32.to_be_bytes());
    let mut out = vec![0u8; 1_048_576];
    let mut written = 0;
    assert_eq!(
        unsafe {
            chur_content_index_candidates(
                session,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    let mut put = vec![1];
    put.extend_from_slice(&object);
    put.extend_from_slice(&out[21..37]);
    put.push(1);
    put.extend_from_slice(&1u32.to_be_bytes());
    let text = b"preservedocrboundarycanary";
    put.extend_from_slice(&(text.len() as u32).to_be_bytes());
    put.extend_from_slice(text);
    assert_eq!(
        unsafe {
            chur_content_index_put(
                session,
                put.as_ptr(),
                put.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        OK
    );
    // Close the C session before reading the encrypted storage through native
    // APIs. Search hits alone cannot detect a bad write of the same text, a
    // changed source/status, or a hidden row belonging to another object.
    let persisted = |session: &mut u64| {
        assert_eq!(unsafe { chur_session_close(*session) }, OK);
        let mut native = chur_catalog::vault::unlock_with_password(
            &chur_catalog::paths::VaultRoot::new(&root),
            PASSWORD,
            1_700_000_000_000,
        )
        .unwrap();
        let generation = chur_catalog::schema::generation(native.catalog_ref().unwrap()).unwrap();
        let contents = native.catalog().unwrap().transaction(|tx| {
            let rows = tx.prepare("SELECT object_id,primary_stream_id,engine_version,status,body FROM content_index ORDER BY object_id").unwrap()
                .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u32>(2)?, row.get::<_, u8>(3)?, row.get::<_, String>(4)?))).unwrap()
                .collect::<std::result::Result<Vec<_>, _>>().unwrap();
            tx.execute_batch("CREATE VIRTUAL TABLE temp.ocr_vocab USING fts5vocab(main, object_search, row)").unwrap();
            let terms = tx.prepare("SELECT term,doc,cnt FROM temp.ocr_vocab ORDER BY term").unwrap()
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))).unwrap()
                .collect::<std::result::Result<Vec<_>, _>>().unwrap();
            tx.execute_batch("DROP TABLE temp.ocr_vocab").unwrap();
            Ok((rows, terms))
        }).unwrap();
        native.lock().unwrap();
        drop(native);
        let unlock = ChurUnlockRequestV1 {
            factor: 1,
            reserved: [0; 3],
            secret: PASSWORD.as_ptr(),
            secret_length: PASSWORD.len() as u32,
        };
        assert_eq!(unsafe { chur_vault_unlock(runtime, &unlock, session) }, OK);
        (generation, contents)
    };
    let before = persisted(&mut session);
    assert_eq!(before.1.0.len(), 1);
    let mut malformed = Vec::new();
    for length in [0, 1, 16, 32, 33, 34, 37, 38, 41, put.len() - 1] {
        malformed.push(put[..length].to_vec());
    }
    for (offset, value) in [
        (0, 2),
        (33, 0),
        (33, 3),
        (37, 0),
        (37, 2),
        (42, 0xff),
        (42, 0),
    ] {
        let mut invalid = put.clone();
        invalid[offset] = value;
        malformed.push(invalid);
    }
    for invalid in &malformed {
        written = 999;
        assert_eq!(
            status(unsafe {
                chur_content_index_put(
                    session,
                    invalid.as_ptr(),
                    invalid.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            }),
            ChurStatus::InvalidInput
        );
        assert_eq!(written, 0);
        assert_eq!(persisted(&mut session), before);
        let hits = page(session, 5, [0; 16], text).objects;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].object_id.as_bytes(), &object);
    }
    let mut oversized = put.clone();
    oversized.resize(chur_catalog::content_index::TEXT_MAX + 65, 0);
    written = 999;
    assert_eq!(
        status(unsafe {
            chur_content_index_put(
                session,
                oversized.as_ptr(),
                oversized.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::ResourceLimitExceeded
    );
    assert_eq!(written, 0);
    assert_eq!(persisted(&mut session), before);
    for (offset, value) in [(1, 2), (21, 0), (21, 101)] {
        let mut invalid = request.clone();
        invalid[offset] = value;
        written = 999;
        assert_eq!(
            status(unsafe {
                chur_content_index_candidates(
                    session,
                    invalid.as_ptr(),
                    invalid.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            }),
            ChurStatus::InvalidInput
        );
        assert_eq!(written, 0);
        assert_eq!(persisted(&mut session), before);
    }
    written = 999;
    assert_eq!(
        status(unsafe {
            chur_content_index_clear(
                session,
                [1u8, 0].as_ptr(),
                2,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(written, 0);
    assert_eq!(persisted(&mut session), before);
    // A null count/output must be refused before the otherwise valid mutation.
    assert_eq!(
        status(unsafe {
            chur_content_index_clear(
                session,
                [1u8].as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                std::ptr::null_mut(),
            )
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(persisted(&mut session), before);
    written = 999;
    assert_eq!(
        status(unsafe {
            chur_content_index_clear(
                session,
                [1u8].as_ptr(),
                1,
                std::ptr::null_mut(),
                out.len(),
                &mut written,
            )
        }),
        ChurStatus::InvalidInput
    );
    assert_eq!(written, 0);
    assert_eq!(persisted(&mut session), before);
    let hits = page(session, 5, [0; 16], text).objects;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].object_id.as_bytes(), &object);
    let mut reader = 0;
    assert_eq!(
        unsafe {
            chur_object_reader_open(
                session,
                &ChurObjectRefV1 { object_id: object },
                1,
                &mut reader,
            )
        },
        OK
    );
    let mut size = 0;
    assert_eq!(unsafe { chur_object_reader_size(reader, &mut size) }, OK);
    assert_eq!(size, original.len() as u64);
    let mut bytes = vec![0; original.len()];
    assert_eq!(
        unsafe {
            chur_object_reader_read_at(reader, 0, bytes.as_mut_ptr(), bytes.len(), &mut written)
        },
        OK
    );
    assert_eq!(written, original.len());
    assert_eq!(bytes, original);
    assert_eq!(unsafe { chur_object_reader_close(reader) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    out.fill(0);
    put.fill(0);
    oversized.fill(0);
    for invalid in &mut malformed {
        invalid.fill(0);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn caller_persisted_import_and_album_identities_survive_retry() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &create_request(PASSWORD), &mut creation) },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let requested = [0x81; 16];
    assert_eq!(
        import_with_id(session, b"original", b"source.jpg", Some(requested)),
        requested
    );
    let mut output = [0; 16];
    let album_id = [0x82; 16];
    for _ in 0..2 {
        assert_eq!(
            unsafe {
                chur_album_create(
                    session,
                    b"Folder".as_ptr(),
                    6,
                    album_id.as_ptr(),
                    output.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(output, album_id);
    }
    assert_eq!(
        status(unsafe {
            chur_album_create(
                session,
                b"Other".as_ptr(),
                5,
                album_id.as_ptr(),
                output.as_mut_ptr(),
            )
        }),
        ChurStatus::InvalidInput
    );
    let mut encoded = vec![0; 16_384];
    let mut written = 0;
    assert_eq!(
        unsafe { chur_album_list(session, encoded.as_mut_ptr(), encoded.len(), &mut written) },
        OK
    );
    assert_eq!(u32::from_be_bytes(encoded[..4].try_into().unwrap()), 1);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn private_workspace_commands_are_bounded_cas_and_restore_saved_source() {
    use chur_ffi::private_notes::*;
    fn text(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    fn call(session: u64, request: &[u8], output: &mut [u8]) -> (i32, usize) {
        let mut written = usize::MAX;
        let status = unsafe {
            chur_private_note_attachments(
                session,
                request.as_ptr(),
                request.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        (status, written)
    }
    let root = scratch();
    let runtime = open_runtime(&root);
    let mut creation = 0;
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_create_begin(runtime, &create_request(PASSWORD), &mut creation) },
        OK
    );
    assert_eq!(
        unsafe { chur_vault_creation_activate(creation, &mut session) },
        OK
    );
    let mut save = vec![0; 16];
    save.extend_from_slice(&0u64.to_be_bytes());
    save.extend_from_slice(&[0, 1]);
    text(&mut save, "Title");
    text(&mut save, "# source");
    let mut output = vec![0u8; 1_048_576];
    let mut written = 0;
    assert_eq!(
        unsafe {
            chur_private_note_save(
                session,
                save.as_ptr(),
                save.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        },
        OK
    );
    let id = output[..16].to_vec();
    let mut set = vec![7];
    set.extend_from_slice(&id);
    set.extend_from_slice(&1u64.to_be_bytes());
    text(&mut set, "Work");
    set.extend_from_slice(&1u32.to_be_bytes());
    text(&mut set, "tag");
    let mut malformed = set.clone();
    malformed.push(0);
    output.fill(0x77);
    assert_eq!(
        call(session, &malformed, &mut output),
        (ChurStatus::InvalidInput as i32, 0)
    );
    assert!(output.iter().all(|b| *b == 0x77));
    let mut short = vec![0u8; 100];
    assert_eq!(
        call(session, &set, &mut short),
        (ChurStatus::ResourceLimitExceeded as i32, 0)
    );
    assert_eq!(call(session, &set, &mut output).0, OK);
    assert_eq!(&output[16..24], &2u64.to_be_bytes());
    assert_eq!(
        call(session, &set, &mut output),
        (ChurStatus::Conflict as i32, 0)
    );
    let mut history = vec![8];
    history.extend_from_slice(&id);
    let (status, size) = call(session, &history, &mut output);
    assert_eq!(status, OK);
    assert!(size > 4);
    assert_eq!(&output[..4], &1u32.to_be_bytes());
    assert_eq!(&output[4..12], &1u64.to_be_bytes());
    let mut detail = vec![11];
    detail.extend_from_slice(&id);
    detail.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(call(session, &detail, &mut output).0, OK);
    assert_eq!(&output[16..24], &1u64.to_be_bytes());
    let mut query = vec![12, 0];
    query.extend_from_slice(&1u64.to_be_bytes());
    text(&mut query, "");
    query.extend_from_slice(&0u32.to_be_bytes());
    text(&mut query, "Work");
    text(&mut query, "tag");
    assert_eq!(call(session, &query, &mut output).0, OK);
    assert_eq!(&output[..4], &1u32.to_be_bytes());
    let mut restore = vec![9];
    restore.extend_from_slice(&id);
    restore.extend_from_slice(&2u64.to_be_bytes());
    restore.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(call(session, &restore, &mut output).0, OK);
    assert_eq!(&output[16..24], &3u64.to_be_bytes());
    assert_eq!(call(session, &query, &mut output).0, OK);
    assert_eq!(&output[..4], &0u32.to_be_bytes());
    let mut get = vec![6];
    get.extend_from_slice(&id);
    assert_eq!(call(session, &get, &mut output), (OK, 8));
    assert_eq!(&output[..8], &[0; 8]);
    // A file above the 64 KiB control-plane bound still fits the 16 MiB request bound.
    let file = vec![0xA5u8; 100_000];
    let mut put = vec![2];
    put.extend_from_slice(&id);
    put.extend_from_slice(&3u64.to_be_bytes());
    put.extend_from_slice(&[0x55; 16]);
    text(&mut put, "big.bin");
    text(&mut put, "application/octet-stream");
    put.extend_from_slice(&(file.len() as u32).to_be_bytes());
    put.extend_from_slice(&file);
    assert_eq!(call(session, &put, &mut output).0, OK);
    let mut read = vec![3];
    read.extend_from_slice(&id);
    read.extend_from_slice(&[0x55; 16]);
    let mut big = vec![0u8; 8_388_608];
    assert_eq!(call(session, &read, &mut big), (OK, 100_000));
    assert_eq!(&big[..100_000], &file[..]);
    output.fill(0);
    save.fill(0);
    set.fill(0);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(
        call(session, &get, &mut output),
        (ChurStatus::SessionExpired as i32, 0)
    );
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

/// The one vault directory a fresh root holds.
fn only_vault_directory(root: &std::path::Path) -> std::path::PathBuf {
    let mut vaults = std::fs::read_dir(root.join("vaults"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(vaults.len(), 1);
    vaults.remove(0)
}

fn unlock_with_password(runtime: u64) -> u64 {
    let unlock = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: PASSWORD.as_ptr(),
        secret_length: PASSWORD.len() as u32,
    };
    let mut session = 0u64;
    assert_eq!(
        unsafe { chur_vault_unlock(runtime, &unlock, &mut session) },
        OK
    );
    session
}

/// A backup that is killed keeps its encrypted catalog snapshot in
/// `incoming/`. The next unlock removes it before the session is returned.
#[test]
fn an_unlock_removes_the_catalog_snapshot_a_killed_backup_left() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    let snapshot = only_vault_directory(&root)
        .join("incoming")
        .join(chur_media::backup::SNAPSHOT_DIRECTORY);
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(snapshot.join("catalog.db"), b"an abandoned catalog copy").unwrap();

    let session = unlock_with_password(runtime);
    assert!(!snapshot.exists());
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

/// `OBJECT_CONTAINER_V1.md` §14.4: a temporary container with no journal
/// record is dead. An import that dies after it writes the container and
/// before it writes the record leaves one; the next unlock deletes it, and
/// leaves an entry that is not a container name alone.
#[test]
fn an_unlock_deletes_a_temporary_container_with_no_journal_record() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    let incoming = only_vault_directory(&root).join("incoming");
    let orphan = incoming.join(chur_crypto::random::id().unwrap().to_hex());
    std::fs::write(&orphan, b"CHUROBJ1 and a manifest no record names").unwrap();
    let foreign = incoming.join("not-a-container");
    std::fs::write(&foreign, b"unknown").unwrap();

    let session = unlock_with_password(runtime);
    assert!(!orphan.exists());
    assert!(foreign.exists());
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

/// A failed startup sweep still runs the lock. The lock removes the whole
/// scratch directory, so the entry the sweep could not delete is gone, and
/// the next unlock succeeds rather than failing on the same entry again.
#[test]
fn a_failed_scratch_sweep_at_unlock_still_locks_the_session() {
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    assert_eq!(unsafe { chur_vault_lock(session, 1) }, OK);
    assert_eq!(unsafe { chur_session_close(session) }, OK);

    // `remove_file` cannot delete a directory, so the sweep fails on it.
    let stuck = only_vault_directory(&root).join("scratch").join("stuck");
    std::fs::create_dir_all(stuck.join("inner")).unwrap();
    let unlock = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: PASSWORD.as_ptr(),
        secret_length: PASSWORD.len() as u32,
    };
    let mut session = 0u64;
    assert_ne!(
        unsafe { chur_vault_unlock(runtime, &unlock, &mut session) },
        OK
    );
    assert_eq!(session, 0);
    assert!(!stuck.exists(), "the lock removes the scratch directory");

    let session = unlock_with_password(runtime);
    assert_eq!(unsafe { chur_session_close(session) }, OK);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, OK);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn encrypted_video_positions_cross_the_c_boundary_and_fail_closed_on_lock() {
    use chur_ffi::playback::{chur_playback_position_get, chur_playback_position_put};
    let root = scratch();
    let runtime = open_runtime(&root);
    let session = fresh_session(runtime);
    let bytes = include_bytes!("../../../../tests/media/hevc-main10/sdr10-hvc1.mp4");
    let mut file = tempfile();
    file.write_all(bytes).unwrap();
    file.rewind().unwrap();
    let request = ChurImportRequestV2 {
        requested_object_id: core::ptr::null(),
        seekable: 1,
        known_length_present: 1,
        media_class: 2,
        reserved: 0,
        width: 192,
        height: 96,
        duration_ms: 1250,
        known_length: bytes.len() as u64,
        capture_time_ms: 1_700_000_000_000,
        capture_time_present: 1,
        reserved_two: [0; 7],
        content_type: b"video/mp4".as_ptr(),
        content_type_length: 9,
        original_filename: b"video.mp4".as_ptr(),
        original_filename_length: 9,
    };
    let mut operation = 0;
    // SAFETY: all request fields and writable output live through each synchronous call.
    assert_eq!(
        unsafe { chur_import_begin(session, descriptor(&file), &request, &mut operation) },
        OK
    );
    assert_eq!(drain(operation), OK);
    assert_eq!(unsafe { chur_operation_close(operation) }, OK);
    let object = ChurObjectRefV1 {
        object_id: latest_object(session),
    };
    let mut position = u64::MAX;
    // SAFETY: the object reference and exclusive scalar output live for each call.
    unsafe {
        assert_eq!(
            chur_playback_position_get(session, &object, &mut position),
            OK
        );
        assert_eq!(position, 0);
        assert_eq!(chur_playback_position_put(session, &object, 500, 1250), OK);
        assert_eq!(
            chur_playback_position_get(session, &object, &mut position),
            OK
        );
        assert_eq!(position, 500);
        assert_eq!(
            status(chur_playback_position_put(session, &object, 1251, 1250)),
            ChurStatus::InvalidInput
        );
        assert_eq!(
            chur_playback_position_get(session, &object, &mut position),
            OK
        );
        assert_eq!(position, 500);
        assert_eq!(
            status(chur_playback_position_get(
                session,
                core::ptr::null(),
                &mut position
            )),
            ChurStatus::InvalidInput
        );
        assert_eq!(position, 0);
        assert_eq!(
            status(chur_playback_position_get(
                session,
                &object,
                core::ptr::null_mut()
            )),
            ChurStatus::InvalidInput
        );
        assert_eq!(chur_playback_position_put(session, &object, 0, 1250), OK);
        assert_eq!(
            chur_playback_position_get(session, &object, &mut position),
            OK
        );
        assert_eq!(position, 0);
        assert_eq!(chur_vault_lock(session, 1), OK);
        position = u64::MAX;
        assert_ne!(
            chur_playback_position_get(session, &object, &mut position),
            OK
        );
        assert_eq!(position, 0);
        assert_ne!(chur_playback_position_put(session, &object, 500, 1250), OK);
        assert_eq!(chur_session_close(session), OK);
        assert_eq!(chur_runtime_close(runtime), OK);
    }
    std::fs::remove_dir_all(root).unwrap();
}
