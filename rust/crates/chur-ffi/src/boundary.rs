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

mod buffers;
pub mod inbox;
mod panic;

// The normal mobile library includes the complete vault ABI. The Share
// Extension links the same inbox code without the catalog or vault runtime.
#[cfg(feature = "vault")]
#[path = "lib.rs"]
mod vault;
#[cfg(feature = "vault")]
pub use vault::*;
