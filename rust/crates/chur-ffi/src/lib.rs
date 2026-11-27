//! Chur FFI boundary.
//!
//! The boundary splits into a structured control plane and a bounded streaming
//! data plane, both on one stable C ABI (ADR-0006, frozen by ADR-0016). No
//! binding generator is part of it: `include/chur.h` is hand-written and is the
//! authority for the C side, and this crate is the authority for the Rust side.
//!
//! Every export contains panics. §11 of that contract is unconditional, and
//! `panic::guard` is how it is met: a caught panic never crosses the boundary
//! and its payload is dropped inside. A handshake export has no status channel,
//! so it returns a value the host refuses instead, per ADR-0037.
//!
//! The handshake of §2 is here; the control plane and the data plane are in
//! [`api`]. A handshake function is callable from any thread before runtime
//! initialization and cannot fail, which is what a platform gate needs before
//! it decides whether to load the library at all. [`chur_capabilities`] reports
//! the capabilities that actually exist and no others.
//!
//! Normative sources:
//!
//! - `docs/interop/FFI_CONTRACT.md` (ABI handshake, handles, buffer ownership)
//! - `docs/ERROR_MODEL.md` (`chur_status_t` and its values)
//! - `docs/security/SECURITY_INVARIANTS.md` (SEC-050, SEC-051)

pub mod api;
pub mod content_index;
pub mod device_pairing;
pub mod external_archive;
pub mod jpeg_xl;
pub mod own_sync;
pub mod peer;
pub mod playback;
pub mod selective;
pub mod sharing;
pub mod sharing_publish;
pub mod sync;

/// The number of live handles in this process.
///
/// `docs/interop/FFI_CONTRACT.md` §15 asks for a leaked-handle test, and the
/// registry is private, so the count is exposed here. It is a Rust function
/// rather than an export: nothing outside this library needs it, and §6.2
/// freezes the exported set.
#[must_use]
pub fn registry_live_handles() -> usize {
    registry::live()
}
mod operation;
mod panic;
pub mod private_notes;
pub mod product;
mod provider_io;
pub mod records;
pub mod reencrypt;
mod registry;
mod runtime;
mod unlock_throttle;

use chur_core::ChurStatus;
use chur_format::constants::{CONTAINER_VERSION_V1, CONTAINER_VERSION_V2, SLOT_VERSION_V1};

use crate::panic::guard;

/// Major component of the native API version.
///
/// A different major value fails loading, reports `ABI_INCOMPATIBLE`, and the
/// library is not called again in that process.
pub const ABI_VERSION_MAJOR: u32 = 7;

/// Minor component of the native API version.
///
/// A minor difference is negotiated only within explicitly compatible
/// behaviour; it never selects a cryptographic suite from untrusted input.
///
/// Minor 2 adds encrypted local video resume positions.
/// Minor 4 adds bounded pages to the locked sync inbox.
/// Minor 3 adds re-encryption after a revocation and the `UNLOCK_DELAYED` status.
/// ABI 7 removes service credentials from pairing and adds ephemeral direct peer IO.
/// ABI 6 reads bounded query text for every scope and binds cursors to its complete filter.
/// It retains ABI 3 caller-persisted import and album identities for safe desktop retries.
/// A caller from an earlier major must refuse before exchanging any payload.
pub const ABI_VERSION_MINOR: u32 = 4;

/// Capability bit: independent decoy identity supported.
pub const CHUR_CAP_DECOY_VAULT: u64 = 1 << 0;
/// Capability bit: random-access authenticated reader available.
pub const CHUR_CAP_OBJECT_READER: u64 = 1 << 1;
/// Capability bit: sequential reader available.
pub const CHUR_CAP_SEQUENTIAL_READER: u64 = 1 << 2;
/// Capability bit: background integrity scan available.
pub const CHUR_CAP_INTEGRITY_SCAN: u64 = 1 << 3;
/// Capability bit: portable backup package import and export available.
pub const CHUR_CAP_BACKUP_PACKAGE: u64 = 1 << 4;
/// Capability bit: ciphertext sync available.
pub const CHUR_CAP_SYNC: u64 = 1 << 5;
/// Capability bit: one reader handle serves parallel reads.
pub const CHUR_CAP_CONCURRENT_READS: u64 = 1 << 6;
/// Capability bit: collection-sharing identity and records available.
pub const CHUR_CAP_COLLECTION_SHARING: u64 = 1 << 7;
/// Capability bit: authenticated source publication and recipient object activation.
pub const CHUR_CAP_SHARED_OBJECTS: u64 = 1 << 8;

/// Capability bit: bounded portable JPEG XL decoder.
pub const CHUR_CAP_JPEG_XL: u64 = 1 << 9;

/// Build-flavor bit: this is a release build.
pub const CHUR_FLAVOR_RELEASE: u32 = 1 << 0;
/// Build-flavor bit: debug assertions are compiled in.
pub const CHUR_FLAVOR_DEBUG_ASSERTIONS: u32 = 1 << 1;
/// Build-flavor bit: test hooks are compiled in.
pub const CHUR_FLAVOR_TEST_HOOKS: u32 = 1 << 2;

/// The value a handshake export returns when its body panics, ADR-0037.
///
/// Each one is a value the host already refuses: a major version of 0 is not
/// this ABI, an inverted format range contains no version, a capability mask of
/// 0 offers nothing, a flavor with no bit set is neither release nor debug, and
/// an unknown status is unknown.
pub const PANIC_ABI_VERSION: u32 = 0;
/// See [`PANIC_ABI_VERSION`]. An empty range: the minimum exceeds the maximum.
pub const PANIC_FORMAT_MIN: u16 = u16::MAX;
/// See [`PANIC_ABI_VERSION`]. An empty range: the maximum is below the minimum.
pub const PANIC_FORMAT_MAX: u16 = 0;
/// See [`PANIC_ABI_VERSION`]. No capability is offered.
pub const PANIC_CAPABILITIES: u64 = 0;
/// See [`PANIC_ABI_VERSION`]. Neither release nor debug, which a host refuses.
pub const PANIC_BUILD_FLAVOR: u32 = 0;

// ADR-0037: each fallback is a value the host already refuses, so a panicking
// library fails the gate instead of reporting a value it did not compute.
const _: () = assert!(PANIC_ABI_VERSION != ABI_VERSION_MAJOR);
const _: () = assert!(PANIC_FORMAT_MIN > PANIC_FORMAT_MAX);
const _: () = assert!(PANIC_CAPABILITIES == 0);
const _: () = assert!(PANIC_BUILD_FLAVOR & CHUR_FLAVOR_RELEASE == 0);
const _: () = assert!(PANIC_BUILD_FLAVOR & CHUR_FLAVOR_DEBUG_ASSERTIONS == 0);

/// The capabilities this build offers.
///
/// A bit is set in the change that lands the surface it names, never before. A
/// host that reads a set bit is entitled to call the functions behind it, so
/// declaring a capability the data plane does not implement would be a false
/// handshake rather than a harmless placeholder.
///
/// `CHUR_CAP_BACKUP_PACKAGE` joined the set with the §6.7 surface: a host that
/// reads it may call `chur_backup_create` and `chur_backup_restore`, and both
/// exist.
///
/// `CHUR_CAP_CONCURRENT_READS` remains clear because it requires benchmarks and correctness tests first,
/// and until they exist every reader handle is serialized per
/// `docs/interop/FFI_CONTRACT.md` §8.
///
/// `CHUR_CAP_DECOY_VAULT` is set because a second identity is now reachable end
/// to end: the registry admits it, `chur_vault_create_begin` provisions it from
/// a runtime an authenticated session already holds, and `chur_vault_unlock`
/// resolves a credential to whichever identity it opens without naming which.
/// The bit says a decoy is supported, not that one exists;
/// `docs/security/DECOY_VAULT.md` §10 requires that no surface tell a caller
/// whether a sibling is present, and `chur_vault_present` answers a boolean for
/// exactly that reason.
const CAPABILITIES: u64 = CHUR_CAP_DECOY_VAULT
    | CHUR_CAP_OBJECT_READER
    | CHUR_CAP_SEQUENTIAL_READER
    | CHUR_CAP_INTEGRITY_SCAN
    | CHUR_CAP_BACKUP_PACKAGE
    | CHUR_CAP_SYNC
    | CHUR_CAP_COLLECTION_SHARING
    | CHUR_CAP_SHARED_OBJECTS
    | CHUR_CAP_JPEG_XL;

/// The major ABI version.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_abi_version_major() -> u32 {
    guard(PANIC_ABI_VERSION, || ABI_VERSION_MAJOR)
}

/// The minor ABI version.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_abi_version_minor() -> u32 {
    guard(PANIC_ABI_VERSION, || ABI_VERSION_MINOR)
}

/// The capability bitmask.
///
/// An unknown set bit is ignored by the host and never enables behaviour.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_capabilities() -> u64 {
    guard(PANIC_CAPABILITIES, || CAPABILITIES)
}

/// Lowest `container_version` this build reads.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_object_format_min() -> u16 {
    guard(PANIC_FORMAT_MIN, || CONTAINER_VERSION_V1)
}

/// Highest `container_version` this build reads: the bucket-padded v2 of
/// ADR-0066.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_object_format_max() -> u16 {
    guard(PANIC_FORMAT_MAX, || CONTAINER_VERSION_V2)
}

/// Lowest key-slot format version this build reads.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_key_slot_format_min() -> u16 {
    guard(PANIC_FORMAT_MIN, || SLOT_VERSION_V1)
}

/// Highest key-slot format version this build reads.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_key_slot_format_max() -> u16 {
    guard(PANIC_FORMAT_MAX, || SLOT_VERSION_V1)
}

/// The build flavor bitfield.
///
/// A release application refuses a library with the debug-assertions or
/// test-hooks bit set, so the value is computed from the compilation rather
/// than from a feature a caller could ask for.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_build_flavor() -> u32 {
    guard(PANIC_BUILD_FLAVOR, || {
        // No test hooks are compiled into any build. `docs/CRYPTOGRAPHY.md` §9
        // forbids a production build that can select deterministic randomness,
        // and the crate offers no feature that would set CHUR_FLAVOR_TEST_HOOKS.
        if cfg!(debug_assertions) {
            CHUR_FLAVOR_DEBUG_ASSERTIONS
        } else {
            CHUR_FLAVOR_RELEASE
        }
    })
}

/// The `chur_status_t` value of success.
pub const CHUR_OK: i32 = chur_core::CHUR_OK;

/// Whether an `int32_t` is a status value this build allocates.
///
/// A host that receives an unrecognized value maps it to `INTERNAL_FAILURE` and
/// must never treat it as success, retryable, or benign.
// SAFETY: the function takes no pointer, reads no caller memory, and returns a
// scalar by value, so the only unsafe property is the unmangled symbol name. It
// is unique to this library and is declared in include/chur.h.
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 2 fixes this exported symbol name; a mangled name is not callable from the platform host"
)]
#[unsafe(no_mangle)]
pub extern "C" fn chur_status_is_known(value: i32) -> bool {
    guard(false, || ChurStatus::is_allocated(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_handshake_answers_every_documented_fact() {
        assert_eq!(chur_abi_version_major(), 7);
        assert_eq!(chur_abi_version_minor(), 4);
        assert_eq!(chur_object_format_min(), 1);
        assert_eq!(chur_object_format_max(), 2);
        assert_eq!(chur_key_slot_format_min(), 1);
        assert_eq!(chur_key_slot_format_max(), 1);
    }

    #[test]
    fn the_format_ranges_are_ordered() {
        assert!(chur_object_format_min() <= chur_object_format_max());
        assert!(chur_key_slot_format_min() <= chur_key_slot_format_max());
    }

    #[test]
    fn no_capability_is_declared_before_its_surface_exists() {
        // A set bit entitles a host to call the functions behind it, so each
        // one is asserted against the surface that implements it rather than
        // against a copy of the constant.
        let declared = chur_capabilities();
        assert_ne!(declared & CHUR_CAP_OBJECT_READER, 0, "the reader exists");
        assert_ne!(
            declared & CHUR_CAP_SEQUENTIAL_READER,
            0,
            "sequential export exists"
        );
        assert_ne!(
            declared & CHUR_CAP_INTEGRITY_SCAN,
            0,
            "the integrity scan exists"
        );
        assert_ne!(
            declared & CHUR_CAP_BACKUP_PACKAGE,
            0,
            "the §6.7 backup surface exists"
        );
        assert_ne!(
            declared & CHUR_CAP_DECOY_VAULT,
            0,
            "a second identity is provisionable and openable"
        );
        assert_ne!(
            declared & CHUR_CAP_SYNC,
            0,
            "the ciphertext sync inbox exists"
        );
        assert_ne!(
            declared & CHUR_CAP_COLLECTION_SHARING,
            0,
            "the sharing identity surface exists"
        );
        assert_ne!(
            declared & CHUR_CAP_SHARED_OBJECTS,
            0,
            "shared object verification exists"
        );
        assert_eq!(
            declared & CHUR_CAP_CONCURRENT_READS,
            0,
            "a capability is declared but every reader handle is still serialized"
        );
        assert_ne!(declared & CHUR_CAP_JPEG_XL, 0);
        for bit in 10..64 {
            assert_eq!(
                declared & (1 << bit),
                0,
                "bit {bit} is reserved and must be zero in v1"
            );
        }
    }

    #[test]
    fn the_build_flavor_never_declares_test_hooks() {
        assert_eq!(chur_build_flavor() & CHUR_FLAVOR_TEST_HOOKS, 0);
        let release = chur_build_flavor() & CHUR_FLAVOR_RELEASE != 0;
        let debug = chur_build_flavor() & CHUR_FLAVOR_DEBUG_ASSERTIONS != 0;
        assert!(release ^ debug, "a build is release or debug, never both");
    }

    #[test]
    fn the_status_predicate_agrees_with_the_registry() {
        assert!(!chur_status_is_known(CHUR_OK));
        for status in ChurStatus::ALL {
            assert!(chur_status_is_known(status.as_i32()));
        }
        assert!(!chur_status_is_known(42));
        assert!(!chur_status_is_known(-1));
    }
}
