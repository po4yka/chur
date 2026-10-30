//! The Phase-1 export surface of `docs/interop/FFI_CONTRACT.md` §6.2.
//!
//! The surface is frozen: adding an export raises the minor ABI version, and
//! changing or removing one raises the major version.
//!
//! Every function here wraps its whole body in `crate::panic::guard_status`,
//! which §11 requires unconditionally, and converts a caught panic into
//! `INTERNAL_FAILURE`. Every pointer argument is validated for null before it
//! is read, every length is bounded before it is allocated against, and no
//! pointer is retained after return.
//!
//! The `unsafe` in this file is confined to turning a caller's pointer and
//! length into a slice, and to writing through a caller's out-parameter. Each
//! block states the invariants the caller must satisfy, which the header
//! documents as the contract.

use core::ffi::c_int;

use chur_catalog::vault;
use chur_core::{ChurStatus, Error, Id, Result};
use chur_crypto::Key;
use chur_format::constants::{MediaClass, ObjectState, StreamKind};
use chur_media::import::{CanonicalMedia, SourceCapability};
use chur_media::{backup, export, import, integrity, reader};

use crate::operation::{Operation, OperationKind, Stage};
use crate::panic::{guard_status, guard_status_for};
use crate::records::{
    ChurContentInfoV1, ChurImportRequestV2, ChurObjectRefV1, ChurProgressV1, ChurQueryV1,
    ChurRuntimeConfigV1, ChurScanRequestV1, ChurUnlockRequestV1, encode_page, query_from,
};
use crate::registry::{self, Entry, Handle, Kind};
use crate::runtime::Runtime;

/// The ABI type of a status: `chur_status_t`.
pub type Status = i32;

/// Success, which is `0` and is not an error code.
const OK: Status = chur_core::CHUR_OK;

/// Writes a 32-byte secret through a caller's buffer, §12.
///
/// It is the one place a secret crosses the boundary. The caller clears the
/// buffer as soon as it is done with it and never converts it to a string.
///
/// # Safety
///
/// `out` points to at least 32 writable bytes.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn write_secret(out: *mut u8, secret: &[u8; 32]) -> Result<()> {
    if out.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "the secret out-parameter is null",
        ));
    }
    // SAFETY: the caller guarantees 32 writable bytes that outlive the call.
    let buffer = unsafe { core::slice::from_raw_parts_mut(out, 32) };
    buffer.copy_from_slice(secret);
    Ok(())
}

/// Writes a 16-byte identifier through a caller's buffer.
///
/// # Safety
///
/// `out` points to at least 16 writable bytes.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn write_id(out: *mut u8, value: &Id) -> Result<()> {
    if out.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "the identifier out-parameter is null",
        ));
    }
    // SAFETY: the caller guarantees 16 writable bytes that outlive the call.
    let buffer = unsafe { core::slice::from_raw_parts_mut(out, 16) };
    buffer.copy_from_slice(value.as_bytes());
    Ok(())
}

/// Borrows a caller's data-plane byte range rather than a control value.
///
/// The bound is the derivative bound of `docs/interop/MEDIA_PIPELINE.md` §12
/// rather than the control-plane bound, because a screen preview is larger than
/// any argument [`borrow_bytes`] admits and is still bounded. It is the ceiling
/// for every data-plane record, so a caller whose own contract section states a
/// smaller one — the 16 MiB of `docs/interop/FFI_CONTRACT.md` §6.11 and §6.13,
/// the sync response bound of §6.8 — checks that bound itself before it borrows.
///
/// # Safety
///
/// As [`borrow_bytes`].
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn borrow_large<'a>(pointer: *const u8, length: u32) -> Result<&'a [u8]> {
    const MAX_DERIVATIVE_LEN: u32 = 33_554_432;
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "a length was given with a null pointer",
        ));
    }
    if length > MAX_DERIVATIVE_LEN {
        return Err(Error::new(
            ChurStatus::ResourceLimitExceeded,
            "the derivative exceeds the boundary bound",
        ));
    }
    // SAFETY: `pointer` is non-null and the caller guarantees `length`
    // initialized bytes that outlive the call.
    Ok(unsafe { core::slice::from_raw_parts(pointer, length as usize) })
}

/// Deletes an object whole, `CATALOG_SCHEMA_V1.md` §14.1.
pub(crate) fn delete_object(
    session: &mut vault::Session,
    object_id: &Id,
    now_ms: u64,
) -> Result<()> {
    crate::product::run_deletion(session, object_id, now_ms)
}

fn revoked_reader() -> Error {
    Error::new(
        ChurStatus::SessionExpired,
        "the object reader has been revoked",
    )
}

/// The largest byte length any string argument may declare.
///
/// It bounds every `*const u8` plus length pair before a slice is built from
/// it, which §15 asks for by name: an oversized length is `INVALID_INPUT`
/// rather than an allocation.
const MAX_ARGUMENT_LEN: u32 = 65_536;

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Borrows a caller's byte range.
///
/// # Safety
///
/// `pointer` must be null or point to at least `length` initialized bytes that
/// stay valid and unwritten for the call. The header states this for every
/// argument that reaches here.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn borrow_bytes<'a>(pointer: *const u8, length: u32) -> Result<&'a [u8]> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "a length was given with a null pointer",
        ));
    }
    if length > MAX_ARGUMENT_LEN {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "the argument length exceeds the boundary bound",
        ));
    }
    #[expect(
        unsafe_code,
        reason = "FFI_CONTRACT.md §7: the caller allocates and the pointer is valid for the call"
    )]
    // SAFETY: `pointer` is non-null and the caller guarantees `length`
    // initialized bytes that outlive the call, which the header requires.
    Ok(unsafe { core::slice::from_raw_parts(pointer, length as usize) })
}

/// Borrows a caller's writable byte range.
///
/// # Safety
///
/// As [`borrow_bytes`], and the range must be writable and not aliased.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn borrow_bytes_mut<'a>(
    pointer: *mut u8,
    capacity: usize,
) -> Result<&'a mut [u8]> {
    if capacity == 0 {
        return Ok(&mut []);
    }
    if pointer.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "a capacity was given with a null pointer",
        ));
    }
    #[expect(
        unsafe_code,
        reason = "FFI_CONTRACT.md §7: the caller allocates the destination buffer"
    )]
    // SAFETY: `pointer` is non-null and the caller guarantees `capacity`
    // writable bytes that outlive the call and are not aliased.
    Ok(unsafe { core::slice::from_raw_parts_mut(pointer, capacity) })
}

/// Writes a value through a caller's out-parameter.
///
/// # Safety
///
/// `out` must be null or point to a writable, aligned `T`.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn write_out<T>(out: *mut T, value: T) -> Result<()> {
    if out.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "an out-parameter is null",
        ));
    }
    #[expect(
        unsafe_code,
        reason = "FFI_CONTRACT.md §11: a result is written through an out-parameter"
    )]
    // SAFETY: `out` is non-null and the caller guarantees it points to a
    // writable, aligned `T` that outlives the call.
    unsafe {
        out.write(value);
    }
    Ok(())
}

/// Reads a caller's structure by reference.
///
/// # Safety
///
/// `pointer` must be null or point to a valid, aligned `T`.
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn read_request<'a, T>(pointer: *const T) -> Result<&'a T> {
    if pointer.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "a request structure is null",
        ));
    }
    #[expect(
        unsafe_code,
        reason = "FFI_CONTRACT.md §7: the caller allocates the request structure"
    )]
    // SAFETY: `pointer` is non-null and the caller guarantees a valid, aligned
    // `T` that outlives the call.
    Ok(unsafe { &*pointer })
}

// ---------------------------------------------------------------------------
// Runtime and session
// ---------------------------------------------------------------------------

/// Opens the process runtime, §14.
///
/// # Safety
///
/// `config` points to a valid `ChurRuntimeConfigV1` whose `root_path` covers
/// `root_path_length` bytes, and `out_runtime` points to a writable handle.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_runtime_open(
    config: *const ChurRuntimeConfigV1,
    out_runtime: *mut Handle,
) -> Status {
    guard_status(|| {
        // SAFETY: the caller guarantees the pointers above for the call.
        let config = unsafe { read_request(config)? };
        let path = unsafe { borrow_bytes(config.root_path, config.root_path_length)? };
        let text = core::str::from_utf8(path)
            .map_err(|_| Error::new(ChurStatus::InvalidInput, "the storage root is not UTF-8"))?;
        let runtime = Runtime::open(std::path::PathBuf::from(text))?;
        let handle = registry::insert(Entry::Runtime(std::sync::Mutex::new(runtime)))?;
        unsafe { write_out(out_runtime, handle) }
    })
}

/// Closes the runtime and every handle it owns.
///
/// # Safety
///
/// The handle is a value this process issued, or zero.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_runtime_close(runtime: Handle) -> Status {
    guard_status_for(runtime, || {
        // Closing the runtime closes everything: §3 says no handle revives
        // after lock, and a runtime close is a stronger event than a lock.
        // §14 permits one runtime per process, so closing it ends every
        // session it opened and everything those sessions own. The entries drop
        // outside the registry lock, which §8 requires: dropping a session
        // closes a database and dropping an operation joins a worker.
        let owned = registry::drain_owned_by(runtime);
        let taken = registry::close(runtime)?;
        drop(owned);
        drop(taken);
        Ok(())
    })
}

/// Unlocks a vault and opens a session, `KEY_SLOTS.md` §8.
///
/// It reconciles the import journal before the session becomes a handle.
/// `ARCHITECTURE.md` §21.3 puts that scan after a crash, and
/// `OBJECT_CONTAINER_V1.md` §14.4 fixes what the cleanup destroys and in
/// which order. This is the one export that opens a session over a vault this
/// process did not create, so it is the one place that runs: an interrupted
/// import keeps a live `ContentKey` envelope and a partial container until
/// the reconciliation kills them. v1 declares every interrupted import dead,
/// because no export resumes one, although §21.3 also permits the resume of
/// §14.3.
///
/// The host sees two consequences. A correct credential can return a storage
/// status and open no session, `ERROR_MODEL.md`; that is not an
/// authentication failure. And the reconciliation kills a live import that
/// another session of the same vault is running, which `FFI_CONTRACT.md`
/// §8.1 already forbids: one process opens a vault, and one runtime shares
/// one session.
///
/// # Safety
///
/// `request` points to a valid `ChurUnlockRequestV1` whose `secret` covers
/// `secret_length` bytes, and `out_session` points to a writable handle.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_vault_unlock(
    runtime: Handle,
    request: *const ChurUnlockRequestV1,
    out_session: *mut Handle,
) -> Status {
    guard_status_for(runtime, || {
        let entry = registry::get(runtime, Kind::Runtime)?;
        let Entry::Runtime(guarded) = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        // SAFETY: the caller guarantees the pointers above for the call.
        let request = unsafe { read_request(request)? };
        let secret = unsafe { borrow_bytes(request.secret, request.secret_length)? };
        // §8.1: at most one unlock is in flight per runtime, and a second
        // unlock returns CONFLICT before deriving anything, so a double-tapped
        // unlock button never starts two derivations. The claim outlives the
        // mutex borrow, which the derivation must not hold.
        let (root, _in_flight) = {
            let guard = registry::lock(guarded);
            let in_flight = guard.begin_unlock().ok_or_else(|| {
                Error::new(ChurStatus::Conflict, "an unlock is already in flight")
            })?;
            (guard.root().clone(), in_flight)
        };
        let now = now_ms();
        // `PASSWORD_PROFILE.md` §11: a password attempt waits after repeated
        // failures. The other factors are never delayed, and any success
        // resets the count.
        let factor = request.factor;
        let unlocked = crate::unlock_throttle::guarded(
            &root,
            factor == 1,
            crate::unlock_throttle::Clocks::now,
            || match factor {
                1 => vault::unlock_with_password(&root, secret, now),
                2 => {
                    let phrase = core::str::from_utf8(secret).map_err(|_| {
                        Error::new(
                            ChurStatus::AuthenticationFailed,
                            "the recovery phrase is not UTF-8",
                        )
                    })?;
                    vault::unlock_with_recovery(&root, phrase, now)
                }
                3 => {
                    let bytes: [u8; 32] = secret.try_into().map_err(|_| {
                        Error::new(
                            ChurStatus::AuthenticationFailed,
                            "a device secret is 32 bytes",
                        )
                    })?;
                    vault::unlock_with_apple_keychain(&root, &Key::new(bytes), now)
                }
                4 => {
                    // The Keystore already performed the unwrap, so what arrives is
                    // the root itself rather than a secret a slot body opens.
                    // ADR-0041 records why this family is the exception.
                    let bytes: [u8; 32] = secret.try_into().map_err(|_| {
                        Error::new(
                            ChurStatus::AuthenticationFailed,
                            "an unwrapped root secret is 32 bytes",
                        )
                    })?;
                    vault::unlock_with_android_keystore(&root, &Key::new(bytes), now)
                }
                _ => Err(Error::new(
                    ChurStatus::InvalidInput,
                    "the unlock request names an unallocated factor",
                )),
            },
        );
        let mut session = unlocked?;
        // `ARCHITECTURE.md` §21.3 scans the journal after a crash, and
        // `OBJECT_CONTAINER_V1.md` §14.4 gives the cleanup its order. It runs
        // here rather than at each call site, so no unlock path can skip it,
        // and it runs before the session becomes a handle, so no host call
        // reaches a vault whose journal still holds a dead transaction. The
        // other dead form of §14.4, a temporary container with no journal
        // record, is swept right after it.
        if let Err(error) = import::reconcile(&mut session) {
            // The session is not a handle yet, so no `chur_vault_lock` can
            // reach it, and `Session` has no `Drop`. A plain drop closes the
            // catalog through `rusqlite` alone, which discards the outcome of
            // step 5 of `PLAINTEXT_LIFECYCLE.md` §8, and runs step 8 not at
            // all. The lock outcome is discarded here, because the
            // reconciliation failure is the one the host must see.
            let _ = session.lock();
            return Err(error);
        }
        if let Err(error) = import::sweep_orphan_temporaries(&session) {
            let _ = session.lock();
            return Err(error);
        }
        // `PLAINTEXT_LIFECYCLE.md` §5: startup cleanup deletes every scratch
        // entry a previous process abandoned. It runs beside the import
        // reconciliation and before this session becomes a handle, so no host
        // call observes an entry that is about to be deleted and a crash the
        // previous process died in leaves no readable plaintext behind it.
        if let Err(error) = export::clear_scratch(&session) {
            let _ = session.lock();
            return Err(error);
        }
        // A backup that was killed leaves its encrypted catalog snapshot in
        // `incoming/`. It is removed here, for the same reason as the scratch
        // entries above.
        if let Err(error) = backup::clear_snapshot(&session) {
            let _ = session.lock();
            return Err(error);
        }
        if let Err(error) = crate::selective::sweep_staging(&session) {
            let _ = session.lock();
            return Err(error);
        }
        if let Err(error) = crate::product::sweep_expired_trash(&mut session, now) {
            let _ = session.lock();
            return Err(error);
        }
        let handle = registry::insert(Entry::Session {
            runtime,
            session: std::sync::Mutex::new(session),
            peer: std::sync::Mutex::new(None),
            publication_cache: std::sync::Mutex::new(
                crate::sharing_publish::VerificationCache::default(),
            ),
        })?;
        unsafe { write_out(out_session, handle) }
    })
}

/// Locks a session, `PLAINTEXT_LIFECYCLE.md` §8.
///
/// Every handle the session owns fails afterwards, which §4 requires: locking
/// invalidates the generation and no handle revives.
///
/// # Safety
///
/// The handle is a value this process issued.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_vault_lock(session: Handle, reason: u32) -> Status {
    guard_status_for(session, || {
        let _ = reason;
        let entry = registry::get(session, Kind::Session)?;
        // Steps 1 to 4 of §8: cancel every operation and invalidate every
        // reader this session owns before the catalog closes, so no worker is
        // inside a read when the connection goes. Dropping an operation cancels
        // and joins it, so this returns only once no worker is running.
        let owned = registry::drain_owned_by(session);
        drop(owned);
        let Entry::Session {
            session: guarded,
            publication_cache,
            ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        // Stop peer IO before waiting for a bounded native catalog call to finish.
        if let Entry::Session { peer, .. } = entry.as_ref() {
            registry::lock(peer).take();
        }
        let mut guard = registry::lock(guarded);
        // Steps 5, 6, and 8.
        let result = guard.lock();
        registry::lock(publication_cache).clear();
        result
    })
}

/// Closes a session handle.
///
/// Everything the session owns goes first. §4 makes a session's handles
/// invalid once the session is, and `drain_owned_by` reaches them by walking
/// from a slot that still holds its entry — so emptying this slot before
/// draining would leave a reader or an operation with no owner to reach it,
/// and an operation worker running against a session nothing can lock any
/// more. Dropping an operation cancels and joins it, so this returns only once
/// no worker of this session is running.
///
/// # Safety
///
/// The handle is a value this process issued, or zero.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_session_close(session: Handle) -> Status {
    guard_status_for(session, || {
        let owned = registry::drain_owned_by(session);
        drop(owned);
        let taken = registry::close(session)?;
        drop(taken);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Catalog queries
// ---------------------------------------------------------------------------

/// Writes one page of the catalog into a caller buffer, §6.4.
///
/// # Safety
///
/// `query` points to a valid `ChurQueryV1`, `destination` covers `capacity`
/// writable bytes, and `bytes_written` points to a writable `size_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_catalog_query(
    session: Handle,
    query: *const ChurQueryV1,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // §6.3's rule for a byte count applies here too: it is set on every
        // call, including every failure.
        // SAFETY: the caller guarantees `bytes_written` is writable.
        let _ = unsafe { write_out(bytes_written, 0usize) };
        let entry = registry::get(session, Kind::Session)?;
        // SAFETY: the caller guarantees the pointers above for the call.
        let request = unsafe { read_request(query)? };
        let terms = Some(unsafe { borrow_bytes(request.terms, request.terms_length)? });
        let cursor = match request.cursor_present {
            0 => None,
            1 => Some(request.cursor.as_slice()),
            _ => {
                return Err(Error::new(
                    ChurStatus::NonCanonicalEncoding,
                    "the cursor presence byte is neither 0x00 nor 0x01",
                ));
            }
        };
        let built = query_from(
            request.scope,
            request.sort,
            request.kinds,
            request.limit,
            &request.scope_id,
            cursor,
            terms,
        )?;
        let Entry::Session {
            session: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let page = {
            let mut guard = registry::lock(guarded);
            crate::product::sweep_expired_trash(&mut guard, now_ms())?;
            chur_catalog::query::page(guard.catalog_ref()?, &built)?
        };
        // SAFETY: the caller guarantees `destination` covers `capacity` bytes.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        let written = encode_page(&page, buffer)?;
        unsafe { write_out(bytes_written, written) }
    })
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Starts an import from a source descriptor, §13.
///
/// Rust duplicates the descriptor, because the import runs on a worker thread
/// and §13 requires an asynchronous lifetime to be Rust's own. The caller's
/// descriptor closes deterministically on its own schedule.
///
/// # Safety
///
/// `source_fd` is an open readable descriptor, `request` points to a valid
/// `ChurImportRequestV2`, its optional requested_object_id covers 16 readable bytes,
/// and `out_import` points to a writable handle.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_import_begin(
    session: Handle,
    source_fd: c_int,
    request: *const ChurImportRequestV2,
    out_import: *mut Handle,
) -> Status {
    guard_status_for(session, || {
        let entry = registry::get(session, Kind::Session)?;
        // SAFETY: the caller guarantees the pointers above for the call.
        let request = unsafe { read_request(request)? };
        let content_type =
            unsafe { borrow_bytes(request.content_type, request.content_type_length)? };
        let content_type = core::str::from_utf8(content_type)
            .map_err(|_| Error::new(ChurStatus::InvalidInput, "the content type is not UTF-8"))?
            .to_owned();
        let filename = if request.original_filename.is_null() {
            None
        } else {
            let bytes = unsafe {
                borrow_bytes(request.original_filename, request.original_filename_length)?
            };
            Some(
                core::str::from_utf8(bytes)
                    .map_err(|_| Error::new(ChurStatus::InvalidInput, "the filename is not UTF-8"))?
                    .to_owned(),
            )
        };
        let media_class = MediaClass::from_value(request.media_class).ok_or_else(|| {
            Error::new(
                ChurStatus::InvalidInput,
                "the import names an unallocated media class",
            )
        })?;
        let requested_object_id = if request.requested_object_id.is_null() {
            None
        } else {
            // SAFETY: a non-null optional identity covers 16 readable bytes for this call.
            Some(Id::from_slice(unsafe {
                borrow_bytes(request.requested_object_id, 16)?
            })?)
        };
        let capability = SourceCapability {
            requested_object_id,
            seekable: request.seekable == 1,
            known_length: (request.known_length_present == 1).then_some(request.known_length),
            content_type_hint: content_type.clone(),
            original_filename: filename,
            capture_time_ms: (request.capture_time_present == 1).then_some(request.capture_time_ms),
        };
        let media = CanonicalMedia {
            media_class,
            width: request.width,
            height: request.height,
            duration_ms: request.duration_ms,
        };
        // SAFETY: the caller guarantees `source_fd` is open and readable for
        // the duration of this call; the duplicate is Rust's from here on.
        let source = unsafe { duplicate_descriptor(source_fd)? };
        let total = capability.known_length.unwrap_or(0);
        let now = now_ms();
        let operation = Operation::spawn(OperationKind::Import, total, move |shared| {
            run_import(
                &entry,
                source,
                capability,
                media,
                &content_type,
                now,
                shared,
            )
        })?;
        let handle = registry::insert(Entry::Operation {
            owner: session,
            operation,
        })?;
        unsafe { write_out(out_import, handle) }
    })
}

/// Starts an export to a destination descriptor.
///
/// # Safety
///
/// As [`chur_import_begin`], with a writable destination.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_export_begin(
    session: Handle,
    object: *const ChurObjectRefV1,
    destination_fd: c_int,
    out_export: *mut Handle,
) -> Status {
    guard_status_for(session, || {
        let entry = registry::get(session, Kind::Session)?;
        // SAFETY: the caller guarantees the pointers above for the call.
        let object = unsafe { read_request(object)? };
        let object_id = Id::from_slice(&object.object_id)?;
        // SAFETY: the caller guarantees `destination_fd` is open and writable.
        let destination = unsafe { duplicate_descriptor(destination_fd)? };
        let operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            run_export(&entry, &object_id, destination, shared)
        })?;
        let handle = registry::insert(Entry::Operation {
            owner: session,
            operation,
        })?;
        unsafe { write_out(out_export, handle) }
    })
}

/// Starts an integrity scan, `CATALOG_SCHEMA_V1.md` §13.
///
/// # Safety
///
/// `request` points to a valid `ChurScanRequestV1` and `out_scan` to a writable
/// handle.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_integrity_scan_begin(
    session: Handle,
    request: *const ChurScanRequestV1,
    out_scan: *mut Handle,
) -> Status {
    guard_status_for(session, || {
        let entry = registry::get(session, Kind::Session)?;
        // SAFETY: the caller guarantees the pointers above for the call.
        let request = unsafe { read_request(request)? };
        let single = match request.single_object {
            0 => None,
            1 => Some(Id::from_slice(&request.object_id)?),
            _ => {
                return Err(Error::new(
                    ChurStatus::NonCanonicalEncoding,
                    "the single-object byte is neither 0x00 nor 0x01",
                ));
            }
        };
        let now = now_ms();
        let operation = Operation::spawn(OperationKind::IntegrityScan, 0, move |shared| {
            run_scan(&entry, single, now, shared)
        })?;
        let handle = registry::insert(Entry::Operation {
            owner: session,
            operation,
        })?;
        unsafe { write_out(out_scan, handle) }
    })
}

/// Copies an operation's progress snapshot, §10.
///
/// # Safety
///
/// `out_progress` points to a writable `ChurProgressV1`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_operation_poll(
    operation: Handle,
    out_progress: *mut ChurProgressV1,
) -> Status {
    guard_status_for(operation, || {
        let entry = registry::get(operation, Kind::Operation)?;
        let Entry::Operation { operation, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let progress = operation.poll();
        let mut object_id = [0u8; 16];
        if let Some(id) = progress.object_id {
            object_id.copy_from_slice(id.as_bytes());
        }
        let record = ChurProgressV1 {
            kind: progress.kind as u32,
            stage: progress.stage as u32,
            processed: progress.processed,
            total: progress.total,
            terminal: u8::from(progress.terminal),
            reserved: [0; 3],
            status: if progress.terminal {
                progress.status
            } else {
                OK
            },
            object_id,
        };
        // SAFETY: the caller guarantees `out_progress` is writable.
        unsafe { write_out(out_progress, record) }
    })
}

/// Cancels an operation, §9.
///
/// # Safety
///
/// The handle is a value this process issued.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_operation_cancel(operation: Handle) -> Status {
    guard_status_for(operation, || {
        let entry = registry::get(operation, Kind::Operation)?;
        let Entry::Operation { operation, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        operation.cancel();
        Ok(())
    })
}

/// Closes an operation handle, waiting for its worker.
///
/// # Safety
///
/// The handle is a value this process issued, or zero.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_operation_close(operation: Handle) -> Status {
    guard_status_for(operation, || {
        let taken = registry::close(operation)?;
        drop(taken);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Object reader
// ---------------------------------------------------------------------------

/// Opens a random-access reader, §6.
///
/// # Safety
///
/// `object` points to a valid `ChurObjectRefV1` and `out_reader` to a writable
/// handle.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_open(
    session: Handle,
    object: *const ChurObjectRefV1,
    stream_kind: u32,
    out_reader: *mut Handle,
) -> Status {
    guard_status_for(session, || {
        let entry = registry::get(session, Kind::Session)?;
        // SAFETY: the caller guarantees the pointers above for the call.
        let object = unsafe { read_request(object)? };
        let object_id = Id::from_slice(&object.object_id)?;
        let kind = u8::try_from(stream_kind)
            .ok()
            .and_then(StreamKind::from_value)
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::InvalidInput,
                    "the reader names an unallocated stream kind",
                )
            })?;
        let Entry::Session {
            session: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let guard = registry::lock(guarded);
        let _lifecycle = registry::reader_lifecycle();
        let opened = reader::open(&guard, &object_id, kind)?;
        let handle = registry::insert(Entry::Reader {
            session,
            root: std::fs::canonicalize(guard.root_dir().base()).map_err(|_| {
                Error::new(
                    ChurStatus::IoFailure,
                    "the reader storage root could not be resolved",
                )
            })?,
            store_id: guard.object_store_id(),
            object_id,
            reader: std::sync::Mutex::new(Some(opened)),
        })?;
        // Publish the handle while still holding the session lock. A permanent
        // deletion cannot miss a reader between key opening and registration.
        drop(guard);
        unsafe { write_out(out_reader, handle) }
    })
}

/// Writes the authenticated plaintext size.
///
/// # Safety
///
/// `out_size` points to a writable `uint64_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_size(reader: Handle, out_size: *mut u64) -> Status {
    guard_status_for(reader, || {
        let entry = registry::get(reader, Kind::Reader)?;
        let Entry::Reader {
            reader: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let size = registry::lock(guarded)
            .as_ref()
            .ok_or_else(revoked_reader)?
            .size();
        // SAFETY: the caller guarantees `out_size` is writable.
        unsafe { write_out(out_size, size) }
    })
}

/// Writes the content information, §6.1.
///
/// # Safety
///
/// `out_info` points to a writable `ChurContentInfoV1`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_content_info(
    reader: Handle,
    out_info: *mut ChurContentInfoV1,
) -> Status {
    guard_status_for(reader, || {
        let entry = registry::get(reader, Kind::Reader)?;
        let Entry::Reader {
            reader: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let info = registry::lock(guarded)
            .as_ref()
            .ok_or_else(revoked_reader)?
            .content_info()?;
        let mut content_type = [0u8; 64];
        let bytes = info.content_type.as_bytes();
        if bytes.len() >= content_type.len() {
            return Err(Error::new(
                ChurStatus::ResourceLimitExceeded,
                "the content type exceeds the §6.1 bound",
            ));
        }
        content_type[..bytes.len()].copy_from_slice(bytes);
        let record = ChurContentInfoV1 {
            plaintext_size: info.plaintext_size,
            content_type,
            media_kind: info.media_kind,
            byte_range_supported: u8::from(info.byte_range_supported),
            complete: u8::from(info.complete),
            reserved: [0; 4],
        };
        // SAFETY: the caller guarantees `out_info` is writable.
        unsafe { write_out(out_info, record) }
    })
}

/// Reads a plaintext range into a caller buffer, §6.3.
///
/// The status is the return value and the count is written through
/// `bytes_written`, which is set on every call including every failure.
///
/// # Safety
///
/// `destination` covers `capacity` writable bytes and `bytes_written` points to
/// a writable `size_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_read_at(
    reader: Handle,
    offset: u64,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(reader, || {
        // SAFETY: the caller guarantees `bytes_written` is writable.
        let _ = unsafe { write_out(bytes_written, 0usize) };
        let entry = registry::get(reader, Kind::Reader)?;
        let Entry::Reader {
            reader: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        // SAFETY: the caller guarantees `destination` covers `capacity` bytes.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        let written = registry::lock(guarded)
            .as_mut()
            .ok_or_else(revoked_reader)?
            .read_at(offset, buffer)?;
        unsafe { write_out(bytes_written, written) }
    })
}

/// Runs complete verification and writes the state it reached, §6.2.
///
/// Proven corruption is a lifecycle change rather than a verification verdict,
/// so it returns `OBJECT_CORRUPT` and writes no state.
///
/// # Safety
///
/// `out_state` points to a writable `uint32_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_verify_complete(
    reader: Handle,
    out_state: *mut u32,
) -> Status {
    guard_status_for(reader, || {
        let entry = registry::get(reader, Kind::Reader)?;
        let Entry::Reader {
            reader: guarded, ..
        } = entry.as_ref()
        else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let summary = registry::lock(guarded)
            .as_mut()
            .ok_or_else(revoked_reader)?
            .verify_complete()?;
        // SAFETY: the caller guarantees `out_state` is writable.
        unsafe { write_out(out_state, u32::from(summary.value())) }
    })
}

/// Closes a reader handle.
///
/// # Safety
///
/// The handle is a value this process issued, or zero.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "ADR-0016: the v1 C ABI requires an exported symbol"
)]
pub unsafe extern "C" fn chur_object_reader_close(reader: Handle) -> Status {
    guard_status_for(reader, || {
        let taken = registry::close(reader)?;
        drop(taken);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

pub(crate) fn session_of(
    entry: &std::sync::Arc<Entry>,
) -> Result<&std::sync::Mutex<vault::Session>> {
    match entry.as_ref() {
        Entry::Session { session, .. } => Ok(session),
        _ => Err(Error::new(
            ChurStatus::InvalidInput,
            "the handle is of another type",
        )),
    }
}

fn run_import(
    entry: &std::sync::Arc<Entry>,
    source: std::fs::File,
    capability: SourceCapability,
    media: CanonicalMedia,
    content_type: &str,
    now_ms: u64,
    shared: &crate::operation::Shared,
) -> Result<Option<Id>> {
    let mut source = crate::provider_io::ProviderIo::new(source, shared)?;
    let guarded = session_of(entry)?;
    let mut session = registry::lock(guarded);
    let running = import::begin(&mut session, capability, media, now_ms)?;
    let mut progress = crate::operation::SharedProgress::new(shared, Stage::Running);
    let object_id = import::stream_into(
        running,
        &mut session,
        &mut source,
        content_type,
        now_ms,
        &mut progress,
    )?;
    shared.advance(0, Stage::Committing);
    Ok(Some(object_id))
}

fn run_export(
    entry: &std::sync::Arc<Entry>,
    object_id: &Id,
    destination: std::fs::File,
    shared: &crate::operation::Shared,
) -> Result<Option<Id>> {
    let mut destination = crate::provider_io::ProviderIo::new(destination, shared)?;
    let guarded = session_of(entry)?;
    let session = registry::lock(guarded);
    shared.advance(0, Stage::Running);
    let mut progress = crate::operation::SharedProgress::new(shared, Stage::Running);
    let written = export::export_stream(
        &session,
        object_id,
        StreamKind::Original,
        &mut destination,
        &mut progress,
    )?;
    shared.advance(written, Stage::Committing);
    Ok(None)
}

fn run_scan(
    entry: &std::sync::Arc<Entry>,
    single: Option<Id>,
    now_ms: u64,
    shared: &crate::operation::Shared,
) -> Result<Option<Id>> {
    let guarded = session_of(entry)?;
    let targets = match single {
        Some(object_id) => vec![object_id],
        None => {
            let session = registry::lock(guarded);
            let mut all = Vec::new();
            let mut query = chur_catalog::query::ObjectQuery::timeline();
            loop {
                let page = chur_catalog::query::page(session.catalog_ref()?, &query)?;
                all.extend(page.objects.iter().map(|row| row.object_id));
                let Some(cursor) = page.next_cursor else {
                    break;
                };
                query.cursor = Some(cursor);
            }
            all
        }
    };
    // `docs/ERROR_MODEL.md` "Integrity states versus errors": each target
    // reaches an outcome, either an integrity state the catalog records or
    // proven corruption, which reaches the caller as OBJECT_CORRUPT. No outcome
    // ends the scan: it goes on to every remaining target, so one corrupt
    // object never hides the outcome for the rest, and the terminal snapshot's
    // `processed` still counts every object checked. A cancellation, or a
    // failure that reaches no outcome for a target, still ends the scan early
    // with its status.
    let mut corrupt = false;
    for (index, object_id) in targets.iter().enumerate() {
        if shared.cancelled() {
            return Err(Error::new(ChurStatus::Cancelled, "the scan was cancelled"));
        }
        {
            let mut session = registry::lock(guarded);
            let mut progress = crate::operation::SharedProgress::new(shared, Stage::Running);
            // The per-object probe matters as much as the per-target one: one
            // multi-gigabyte object verifies for minutes, and a scan that
            // checked only between objects would ignore a cancellation for all
            // of it.
            let outcome =
                integrity::scan_object_with(&mut session, object_id, now_ms, &mut progress)?;
            corrupt |= outcome.state == ObjectState::Corrupt;
        }
        shared.advance(index as u64 + 1, Stage::Running);
    }
    if corrupt {
        return Err(Error::new(
            ChurStatus::ObjectCorrupt,
            "at least one object is corrupt",
        ));
    }
    Ok(None)
}

/// Duplicates a caller's descriptor, §13.
///
/// # Safety
///
/// `fd` is an open descriptor for the duration of the call.
#[cfg(unix)]
#[expect(unsafe_code, reason = "the caller's pointer contract is stated above")]
pub(crate) unsafe fn duplicate_descriptor(fd: c_int) -> Result<std::fs::File> {
    use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd};

    if fd < 0 {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "the descriptor is not open",
        ));
    }
    #[expect(
        unsafe_code,
        reason = "FFI_CONTRACT.md §13: Rust duplicates the caller's descriptor for an asynchronous lifetime"
    )]
    // SAFETY: the caller guarantees `fd` is open for the duration of the call,
    // which is all `try_clone_to_owned` needs; the duplicate is independent
    // afterwards and the caller closes its own descriptor on its own schedule.
    let owned = unsafe { BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .map_err(|_| {
            Error::new(
                ChurStatus::IoFailure,
                "the descriptor could not be duplicated",
            )
        })?;
    #[expect(
        unsafe_code,
        reason = "the descriptor is owned here, so wrapping it in a File transfers that ownership"
    )]
    // SAFETY: `owned` is an `OwnedFd` this function just created, so the raw
    // value is valid and unowned by anything else.
    let file = unsafe { std::fs::File::from_raw_fd(owned.into_raw_fd()) };
    #[cfg(target_os = "android")]
    crate::provider_io::reject_provider_filesystem(&file)?;
    Ok(file)
}

/// The device clock, `CATALOG_SCHEMA_V1.md` §8.1.
///
/// A wrong device clock produces a wrong import time and Chur does not detect
/// it. Nothing cryptographic depends on the value and it is not ordering proof.
/// Retention is not judged against it either: trash and private-note expiry use
/// `chur_catalog::trusted_time`, which takes this value only as an input that
/// it bounds, `CATALOG_SCHEMA_V18.md`.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
