//! Pointer checks shared by the full and inbox-only C libraries.

use chur_core::{ChurStatus, Error, Result};

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
