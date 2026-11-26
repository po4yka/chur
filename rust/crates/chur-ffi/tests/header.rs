//! The header-consistency harness.
//!
//! `include/chur.h` is hand-written and is the authority for the C side, so
//! nothing generates it and nothing checks it. This test is that check. It
//! parses the header and asserts three things against the Rust side:
//!
//! - every `chur_status_t` value in the header is a registered status, and
//!   every registered status appears in the header;
//! - every capability, build-flavor, and integrity constant matches;
//! - every function the header declares is exported by this crate, and no
//!   other, which is what freezes the §6.2 surface: an added export fails this
//!   test until the header declares it and the list below names it.
//!
//! `docs/ERROR_MODEL.md` requires a code to be added to the table and to the
//! FFI header in one change. A drift between them would otherwise surface as a
//! host mapping an allocated code to `INTERNAL_FAILURE`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use chur_core::ChurStatus;

const HEADER: &str = include_str!("../include/chur.h");

/// Every `#define NAME VALUE` whose name starts with `prefix`.
fn defines(prefix: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in HEADER.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let Some(name) = parts.next() else { continue };
        let Some(value) = parts.next() else { continue };
        if name.starts_with(prefix) {
            out.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    out
}

/// The name of every function the header declares.
///
/// A declaration may span several lines, so the comments are stripped and the
/// remainder is split on `;` rather than read line by line. A parser that only
/// saw single-line declarations would silently pass a header that declared a
/// wrapped function it did not export.
fn declared_functions() -> BTreeSet<String> {
    let mut source = String::with_capacity(HEADER.len());
    let mut rest = HEADER;
    while let Some(start) = rest.find("/*") {
        source.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("*/") else {
            break;
        };
        rest = &rest[start + end + 2..];
    }
    source.push_str(rest);

    // Preprocessor lines are removed before the split, not skipped after it: a
    // `#define` carries no `;`, so it would otherwise be glued to the
    // declaration that follows it and hide it.
    let source: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    let mut out = BTreeSet::new();
    for statement in source.split(';') {
        let statement: String = statement.split_whitespace().collect::<Vec<_>>().join(" ");
        if statement.starts_with("typedef") {
            continue;
        }
        let Some(open) = statement.find('(') else {
            continue;
        };
        let Some(name) = statement[..open].rsplit(' ').next() else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if name.starts_with("chur_") {
            out.insert(name.to_owned());
        }
    }
    out
}

/// The status names the header carries, mapped to their values.
fn header_statuses() -> BTreeMap<String, i32> {
    let mut out = BTreeMap::new();
    for (name, value) in defines("CHUR_") {
        // Capability, flavor, and integrity constants are not statuses.
        // Everything that is not a status: the capability, flavor, integrity,
        // and panic registries above, and the control-plane vocabulary of
        // §6.2. A new prefix must be listed here deliberately, so a constant
        // added without a decision fails this test rather than being read as a
        // status value.
        const NOT_STATUSES: &[&str] = &[
            "CHUR_CAP_",
            "CHUR_FLAVOR_",
            "CHUR_INTEGRITY_",
            "CHUR_PANIC_",
            "CHUR_SCOPE_",
            "CHUR_SORT_",
            "CHUR_FACTOR_",
            "CHUR_OPERATION_",
            "CHUR_STAGE_",
            "CHUR_SYNC_RECORD_",
            "CHUR_LOCK_REASON_",
        ];
        if NOT_STATUSES.iter().any(|prefix| name.starts_with(prefix))
            || matches!(
                name.as_str(),
                "CHUR_H"
                    | "CHUR_OK"
                    | "CHUR_NULL_HANDLE"
                    | "CHUR_CURSOR_LEN"
                    | "CHUR_PROJECTION_LEN"
                    | "CHUR_PAGE_HEADER_LEN"
                    | "CHUR_SECRET_LEN"
                    | "CHUR_RECOVERY_PHRASE_MAX"
            )
        {
            continue;
        }
        let Ok(parsed) = value.parse::<i32>() else {
            panic!("{name} is not a decimal status value: {value}");
        };
        out.insert(name, parsed);
    }
    out
}

#[test]
fn the_header_carries_every_registered_status_and_no_other() {
    let header = header_statuses();
    let expected: BTreeMap<String, i32> = ChurStatus::ALL
        .iter()
        .map(|status| (format!("CHUR_{}", status.name()), status.as_i32()))
        .collect();
    let header_names: BTreeSet<&String> = header.keys().collect();
    let expected_names: BTreeSet<&String> = expected.keys().collect();
    assert_eq!(
        header_names, expected_names,
        "the header and the ERROR_MODEL.md registry disagree about which codes exist"
    );
    for (name, value) in &expected {
        assert_eq!(header.get(name), Some(value), "{name} has the wrong value");
    }
    assert_eq!(header.len(), 34);
}

#[test]
fn success_is_zero_in_the_header() {
    assert_eq!(
        defines("CHUR_OK").get("CHUR_OK").map(String::as_str),
        Some("0")
    );
    assert_eq!(chur_ffi::CHUR_OK, 0);
}

#[test]
fn the_capability_bits_match() {
    let header = defines("CHUR_CAP_");
    let expected = [
        ("CHUR_CAP_DECOY_VAULT", chur_ffi::CHUR_CAP_DECOY_VAULT, 0),
        (
            "CHUR_CAP_OBJECT_READER",
            chur_ffi::CHUR_CAP_OBJECT_READER,
            1,
        ),
        (
            "CHUR_CAP_SEQUENTIAL_READER",
            chur_ffi::CHUR_CAP_SEQUENTIAL_READER,
            2,
        ),
        (
            "CHUR_CAP_INTEGRITY_SCAN",
            chur_ffi::CHUR_CAP_INTEGRITY_SCAN,
            3,
        ),
        (
            "CHUR_CAP_BACKUP_PACKAGE",
            chur_ffi::CHUR_CAP_BACKUP_PACKAGE,
            4,
        ),
        ("CHUR_CAP_SYNC", chur_ffi::CHUR_CAP_SYNC, 5),
        (
            "CHUR_CAP_CONCURRENT_READS",
            chur_ffi::CHUR_CAP_CONCURRENT_READS,
            6,
        ),
        (
            "CHUR_CAP_COLLECTION_SHARING",
            chur_ffi::CHUR_CAP_COLLECTION_SHARING,
            7,
        ),
        (
            "CHUR_CAP_SHARED_OBJECTS",
            chur_ffi::CHUR_CAP_SHARED_OBJECTS,
            8,
        ),
        ("CHUR_CAP_JPEG_XL", chur_ffi::CHUR_CAP_JPEG_XL, 9),
    ];
    assert_eq!(header.len(), expected.len());
    for (name, rust_value, bit) in expected {
        assert_eq!(rust_value, 1u64 << bit, "{name} is the wrong Rust bit");
        assert_eq!(
            header.get(name).map(String::as_str),
            Some(format!("(UINT64_C(1) << {bit})").as_str()),
            "{name} is the wrong header bit"
        );
    }
}

#[test]
fn the_build_flavor_bits_match() {
    let header = defines("CHUR_FLAVOR_");
    assert_eq!(header.len(), 4);
    for (name, rust_value, bit) in [
        ("CHUR_FLAVOR_RELEASE", chur_ffi::CHUR_FLAVOR_RELEASE, 0),
        (
            "CHUR_FLAVOR_INTERNAL_PQ",
            chur_ffi::CHUR_FLAVOR_INTERNAL_PQ,
            3,
        ),
        (
            "CHUR_FLAVOR_DEBUG_ASSERTIONS",
            chur_ffi::CHUR_FLAVOR_DEBUG_ASSERTIONS,
            1,
        ),
        (
            "CHUR_FLAVOR_TEST_HOOKS",
            chur_ffi::CHUR_FLAVOR_TEST_HOOKS,
            2,
        ),
    ] {
        assert_eq!(rust_value, 1u32 << bit, "{name} is the wrong Rust bit");
        assert_eq!(
            header.get(name).map(String::as_str),
            Some(format!("(UINT32_C(1) << {bit})").as_str())
        );
    }
}

#[test]
fn the_integrity_states_match_the_constant_registry() {
    let header = defines("CHUR_INTEGRITY_");
    let expected = chur_format::constants::IntegritySummary::ALL;
    assert_eq!(header.len(), expected.len());
    for state in expected {
        let name = format!(
            "CHUR_INTEGRITY_{}",
            match state {
                chur_format::constants::IntegritySummary::Unverified => "UNVERIFIED",
                chur_format::constants::IntegritySummary::Verifying => "VERIFYING",
                chur_format::constants::IntegritySummary::RangeVerified => "RANGE_VERIFIED",
                chur_format::constants::IntegritySummary::CompleteVerified => "COMPLETE_VERIFIED",
                chur_format::constants::IntegritySummary::Incomplete => "INCOMPLETE",
                chur_format::constants::IntegritySummary::Quarantined => "QUARANTINED",
                chur_format::constants::IntegritySummary::Unsupported => "UNSUPPORTED",
                chur_format::constants::IntegritySummary::MigrationRequired => "MIGRATION_REQUIRED",
                _ => panic!("an integrity state has no header name"),
            }
        );
        assert_eq!(
            header.get(&name).map(String::as_str),
            Some(format!("{:#04x}", state.value()).as_str()),
            "{name} disagrees with the registry"
        );
    }
}

#[test]
fn the_panic_fallbacks_match() {
    // ADR-0037. A drift here would let a host accept a value a panicking
    // library returned.
    let header = defines("CHUR_PANIC_");
    assert_eq!(header.len(), 5);
    for (name, expected) in [
        ("CHUR_PANIC_ABI_VERSION", "(UINT32_C(0))"),
        ("CHUR_PANIC_FORMAT_MIN", "(UINT16_C(0xffff))"),
        ("CHUR_PANIC_FORMAT_MAX", "(UINT16_C(0))"),
        ("CHUR_PANIC_CAPABILITIES", "(UINT64_C(0))"),
        ("CHUR_PANIC_BUILD_FLAVOR", "(UINT32_C(0))"),
    ] {
        assert_eq!(
            header.get(name).map(String::as_str),
            Some(expected),
            "{name}"
        );
    }
    assert_eq!(chur_ffi::PANIC_ABI_VERSION, 0);
    assert_eq!(chur_ffi::PANIC_FORMAT_MIN, 0xffff);
    assert_eq!(chur_ffi::PANIC_FORMAT_MAX, 0);
    assert_eq!(chur_ffi::PANIC_CAPABILITIES, 0);
    assert_eq!(chur_ffi::PANIC_BUILD_FLAVOR, 0);
}

#[test]
fn every_declared_function_is_exported() {
    let declared = declared_functions();
    let exported: BTreeSet<String> = [
        // §2, the handshake.
        "chur_abi_version_major",
        "chur_abi_version_minor",
        "chur_capabilities",
        "chur_object_format_min",
        "chur_object_format_max",
        "chur_key_slot_format_min",
        "chur_key_slot_format_max",
        "chur_build_flavor",
        "chur_status_is_known",
        // §6.2, the surface at ABI 1.0.
        "chur_runtime_open",
        "chur_runtime_close",
        "chur_vault_unlock",
        "chur_vault_lock",
        "chur_session_close",
        "chur_catalog_query",
        "chur_import_begin",
        "chur_export_begin",
        "chur_integrity_scan_begin",
        "chur_operation_poll",
        "chur_operation_cancel",
        "chur_operation_close",
        // §6.32, re-encryption after a revocation, ABI 7.2.
        "chur_reencryption_begin",
        "chur_reencryption_counts",
        "chur_object_reader_open",
        "chur_object_reader_size",
        "chur_object_reader_content_info",
        "chur_object_reader_read_at",
        "chur_object_reader_verify_complete",
        "chur_object_reader_close",
        // §6.5, the Phase-1 product surface added at ABI 1.1.
        "chur_vault_present",
        "chur_vault_create_begin",
        "chur_vault_creation_add_recovery_slot",
        "chur_vault_creation_activate",
        "chur_vault_creation_abandon",
        "chur_vault_add_recovery_slot",
        // §6.23, added at ABI 2.19.
        "chur_vault_recovery_begin",
        "chur_vault_recovery_commit",
        "chur_vault_add_device_slot",
        "chur_vault_remove_slot",
        "chur_vault_change_password",
        "chur_vault_slots",
        "chur_vault_platform_slot_identifier",
        "chur_object_set_favorite",
        "chur_favorites_set",
        "chur_object_delete",
        "chur_trash_set",
        "chur_corrupt_empty",
        "chur_trash_empty",
        "chur_trash_restore_all",
        "chur_object_metadata",
        "chur_album_create",
        "chur_album_rename",
        "chur_album_delete",
        "chur_album_move",
        "chur_album_move_member",
        "chur_album_set_membership",
        "chur_album_remove_objects",
        "chur_album_place_objects",
        "chur_album_list",
        "chur_external_archive_begin",
        "chur_selective_export_begin",
        "chur_selective_import_begin",
        "chur_private_notes_query",
        "chur_content_index_candidates",
        "chur_content_index_put",
        "chur_content_index_clear",
        "chur_private_note_get",
        "chur_private_note_save",
        "chur_private_note_change",
        "chur_private_note_attachments",
        "chur_private_note_export_begin",
        "chur_private_note_attachment_export_begin",
        "chur_tag_create",
        "chur_tag_list",
        "chur_object_set_tag",
        "chur_tag_apply_selection",
        "chur_tag_rename",
        "chur_tag_delete",
        "chur_derived_put",
        "chur_derived_read",
        "chur_backup_create",
        "chur_backup_restore",
        // §6.8, the Phase-3 sync inbox surface added at ABI 1.4.
        "chur_sync_stage",
        "chur_sync_process",
        "chur_sync_heads",
        "chur_device_pairing_prepare",
        "chur_device_pairing_inspect",
        "chur_device_pairing_approve",
        "chur_device_pairing_start",
        "chur_device_pairing_finish",
        "chur_device_pairing_checkpoint",
        "chur_device_pairing_overview",
        "chur_device_pairing_revoke",
        "chur_peer_call",
        "chur_own_sync_collections",
        "chur_own_sync_operations",
        "chur_own_sync_plan",
        "chur_own_sync_author",
        // §6.24, added at ABI 2.20.
        "chur_sync_fork_state",
        "chur_sync_fork_acknowledge",
        // §6.9, the collection-sharing identity surface added at ABI 1.5.
        "chur_sharing_identity",
        // §6.14, user-facing recipient discovery added at ABI 1.10.
        "chur_sharing_overview",
        "chur_sharing_inspect_enrollment",
        // §6.10, the share preparation surface added at ABI 1.6.
        "chur_sharing_prepare",
        // §6.13, authenticated recipient devices added at ABI 1.9.
        "chur_sharing_prepare_device",
        // §6.11, the share acceptance surface added at ABI 1.7.
        "chur_sharing_accept",
        "chur_sharing_publication",
        "chur_sharing_author",
        "chur_sharing_object_read",
        "chur_sharing_outbound",
        "chur_sharing_receive",
        "chur_object_key_request",
        "chur_object_key_issue",
        "chur_object_key_accept",
        "chur_sharing_download_offset",
        "chur_sharing_download_append",
        "chur_sharing_download_finish",
        // §6.12, the recipient revocation surface added at ABI 1.8.
        "chur_sharing_revoke",
        // §6.6, the Android Keystore surface added at ABI 1.2.
        "chur_playback_position_get",
        "chur_playback_position_put",
        "chur_jpeg_xl_open",
        "chur_jpeg_xl_open_fd",
        "chur_jpeg_xl_render",
        "chur_jpeg_xl_close",
        "chur_vault_keystore_begin",
        "chur_vault_keystore_commit",
        "chur_vault_keystore_material",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    assert_eq!(
        declared, exported,
        "the header declares a different function set than the crate exports"
    );

    // Calling each one proves the list above is not a stale copy.
    assert_eq!(chur_ffi::chur_abi_version_major(), 8);
    assert_eq!(chur_ffi::chur_abi_version_minor(), 4);
    assert_eq!(
        chur_ffi::chur_capabilities(),
        chur_ffi::CHUR_CAP_DECOY_VAULT
            | chur_ffi::CHUR_CAP_OBJECT_READER
            | chur_ffi::CHUR_CAP_SEQUENTIAL_READER
            | chur_ffi::CHUR_CAP_INTEGRITY_SCAN
            | chur_ffi::CHUR_CAP_BACKUP_PACKAGE
            | chur_ffi::CHUR_CAP_SYNC
            | chur_ffi::CHUR_CAP_COLLECTION_SHARING
            | chur_ffi::CHUR_CAP_SHARED_OBJECTS
            | chur_ffi::CHUR_CAP_JPEG_XL
    );
    assert_eq!(chur_ffi::chur_object_format_min(), 1);
    assert_eq!(chur_ffi::chur_object_format_max(), 2);
    assert_eq!(chur_ffi::chur_key_slot_format_min(), 1);
    assert_eq!(chur_ffi::chur_key_slot_format_max(), 1);
    assert_ne!(chur_ffi::chur_build_flavor(), 0);
    assert!(chur_ffi::chur_status_is_known(100));
}

#[test]
fn the_control_plane_vocabulary_matches_the_rust_side() {
    // §6.4 and §10 name these values, and a host reads them from the header.
    // A drift would make a query ask for a scope the library does not
    // implement, or a poll misread a stage.
    let lengths = defines("CHUR_");
    for (name, expected) in [
        ("CHUR_CURSOR_LEN", chur_core::limits::catalog::CURSOR_LEN),
        (
            "CHUR_PROJECTION_LEN",
            chur_core::limits::catalog::PROJECTION_LEN,
        ),
        ("CHUR_PAGE_HEADER_LEN", chur_ffi::records::PAGE_HEADER_LEN),
        ("CHUR_SECRET_LEN", chur_ffi::product::SECRET_LEN),
        (
            "CHUR_RECOVERY_PHRASE_MAX",
            chur_ffi::product::RECOVERY_PHRASE_MAX,
        ),
    ] {
        assert_eq!(
            lengths
                .get(name)
                .and_then(|value| value.parse::<usize>().ok()),
            Some(expected),
            "{name} disagrees with the Rust constant"
        );
    }

    // The scope and sort values are the ones records::query_from accepts. An
    // unallocated value is INVALID_INPUT, so the loop below also proves the
    // header declares no value the library refuses.
    let scope_id = [0u8; 16];
    for name in [
        "CHUR_SCOPE_TIMELINE",
        "CHUR_SCOPE_ALBUM",
        "CHUR_SCOPE_FAVORITES",
        "CHUR_SCOPE_TAG",
        "CHUR_SCOPE_SEARCH",
        "CHUR_SCOPE_QUARANTINE",
        "CHUR_SCOPE_TRASH",
    ] {
        let value: u8 = defines(name)[name].parse().expect("a decimal scope");
        // An album and a tag scope need a non-zero identifier, so those two are
        // checked with one; the rest ignore it.
        let id = if value == 2 || value == 4 {
            [1u8; 16]
        } else {
            scope_id
        };
        chur_ffi::records::query_from(value, 1, 0, 0, &id, None, Some(b"x"))
            .unwrap_or_else(|_| panic!("{name} is not a scope the library accepts"));
    }
    let manual: u8 = defines("CHUR_SORT_ALBUM_MANUAL")["CHUR_SORT_ALBUM_MANUAL"]
        .parse()
        .expect("a decimal sort");
    assert!(chur_ffi::records::query_from(2, manual, 0, 0, &[1u8; 16], None, None).is_ok());
    for name in [
        "CHUR_SORT_CAPTURE_DESC",
        "CHUR_SORT_CAPTURE_ASC",
        "CHUR_SORT_IMPORT_DESC",
    ] {
        let value: u8 = defines(name)[name].parse().expect("a decimal sort");
        chur_ffi::records::query_from(1, value, 0, 0, &scope_id, None, None)
            .unwrap_or_else(|_| panic!("{name} is not a sort the library accepts"));
    }
    // A value outside each space is refused, which is what makes the two lists
    // above exhaustive rather than merely correct.
    assert!(chur_ffi::records::query_from(8, 1, 0, 0, &scope_id, None, None).is_err());
    assert!(chur_ffi::records::query_from(1, 5, 0, 0, &scope_id, None, None).is_err());
}

#[test]
fn text_is_bounded_and_decoded_for_every_query_scope() {
    for scope in 1..=7 {
        let id = [1; 16];
        let query = chur_ffi::records::query_from(scope, 1, 0, 0, &id, None, Some(b"needle"))
            .expect("scope");
        assert_eq!(query.terms.as_deref(), Some("needle"));
        let malformed = chur_ffi::records::query_from(scope, 1, 0, 0, &id, None, Some(&[0xff]))
            .expect_err("UTF-8");
        assert_eq!(malformed.status(), chur_core::ChurStatus::InvalidInput);
        let long = chur_ffi::records::query_from(scope, 1, 0, 0, &id, None, Some(&[b'a'; 513]))
            .expect_err("bound");
        assert_eq!(long.status(), chur_core::ChurStatus::ResourceLimitExceeded);
    }
}
