//! Panic containment at the boundary.
//!
//! `docs/interop/FFI_CONTRACT.md` §11 is unconditional: every exported symbol
//! wraps its whole body in `catch_unwind`, no "where applicable" exemption, and
//! the panic payload is dropped inside the boundary so no payload text crosses
//! it. The FFI artifacts build with `panic = "unwind"` for exactly this reason;
//! abort would convert a contained, redactable failure into a process kill that
//! skips session zeroization and removes the public shell along with the vault
//! (ADR-0016).
//!
//! A status-returning export converts a caught panic into `INTERNAL_FAILURE`.
//! The handshake exports of §2 have no status channel: they return a scalar and
//! cannot fail. [ADR-0037] fixes what they return instead — a value the host
//! already knows how to refuse, so a panicking library fails the gate rather
//! than reporting a version it did not compute.
//!
//! [ADR-0037]: https://github.com/po4yka/Chur/blob/main/docs/adr/0037-contain-panics-in-channel-less-exports.md

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use chur_core::ChurStatus;

/// Installs the redacting panic hook, once per process.
///
/// The default hook prints the panic payload, and a payload can hold a value a
/// caller passed in. §11 forbids that text crossing the boundary, so the hook
/// prints a fixed marker and the source location and nothing else. The location
/// is a path inside this repository and carries no private value.
///
/// The hook is process-wide. No other Rust runs in a Chur host process, and the
/// alternative is the default hook printing a payload the contract forbids.
fn install_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let location = info
                .location()
                .map_or_else(|| "unknown".to_owned(), ToString::to_string);
            // Synthetic reproduction only: where, never what.
            eprintln!("chur: contained panic at {location}");
        }));
    });
}

/// Runs the body of an export that has no status channel.
///
/// Returns `fallback` when the body panics. Every caller states a fallback the
/// host refuses, so containment is visible to the host rather than silent.
pub(crate) fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    install_hook();
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Runs the body of an export that returns `chur_status_t`.
///
/// A caught panic becomes [`ChurStatus::InternalFailure`], per §11.
///
/// No export uses it yet: the control plane lands in Phase 1. It is written now
/// so the first status-returning export cannot land without it, and its tests
/// are the panic injection §11 asks for on that path. The attribute is
/// conditional because the tests below do use it.
pub(crate) fn guard_status(body: impl FnOnce() -> chur_core::Result<()>) -> i32 {
    install_hook();
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => chur_core::CHUR_OK,
        Ok(Err(error)) => error.as_i32(),
        Err(_) => ChurStatus::InternalFailure.as_i32(),
    }
}

/// Runs the body of an export that returns `chur_status_t` and owns a handle.
///
/// §11 is unconditional about both halves: a caught panic becomes
/// [`ChurStatus::InternalFailure`], and the handle that owned the call is
/// invalidated so a later call on it also fails. An ordinary error result is
/// not a panic, so the handle survives it.
pub(crate) fn guard_status_for(
    handle: crate::registry::Handle,
    body: impl FnOnce() -> chur_core::Result<()>,
) -> i32 {
    install_hook();
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => chur_core::CHUR_OK,
        Ok(Err(error)) => error.as_i32(),
        Err(_) => {
            crate::registry::invalidate(handle);
            ChurStatus::InternalFailure.as_i32()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    /// Runs a body with the default hook restored afterwards, so a test that
    /// deliberately panics does not leave the process hook installed for the
    /// next test and does not print a payload.
    fn quietly<T>(body: impl FnOnce() -> T) -> T {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = body();
        std::panic::set_hook(previous);
        result
    }

    #[test]
    fn a_panicking_body_returns_the_fallback() {
        assert_eq!(quietly(|| guard(0u32, || panic!("injected"))), 0);
        assert_eq!(quietly(|| guard(7u64, || panic!("injected"))), 7);
        assert_eq!(quietly(|| guard(0xffffu16, || panic!("injected"))), 0xffff);
        assert!(!quietly(|| guard(false, || panic!("injected"))));
    }

    #[test]
    fn a_body_that_does_not_panic_returns_its_value() {
        assert_eq!(guard(0u32, || 42), 42);
        assert_eq!(guard(0u64, || 1 << 3), 8);
        assert!(guard(false, || true));
    }

    #[test]
    fn a_status_body_that_panics_becomes_internal_failure() {
        assert_eq!(
            quietly(|| guard_status(|| panic!("injected"))),
            ChurStatus::InternalFailure.as_i32()
        );
        assert_eq!(
            guard_status(|| Err(chur_core::err!(AuthenticationFailed, "an ordinary refusal"))),
            ChurStatus::AuthenticationFailed.as_i32()
        );
        assert_eq!(guard_status(|| Ok(())), chur_core::CHUR_OK);
    }

    #[test]
    fn a_panic_carrying_a_value_does_not_return_it() {
        // The payload is dropped inside the boundary. Nothing a caller supplied
        // can reach the return value or the hook's output.
        let secret = "a value a caller passed in";
        let observed = quietly(|| guard(0u32, move || panic!("{secret}")));
        assert_eq!(observed, 0);
    }

    /// Registers one operation handle the test owns and closes at the end.
    fn registered_handle() -> (
        crate::registry::Handle,
        crate::registry::Handle,
        std::path::PathBuf,
    ) {
        let path = std::env::temp_dir().join(format!(
            "chur-panic-owner-{}",
            chur_crypto::random::id().expect("id").to_hex()
        ));
        std::fs::create_dir_all(&path).expect("directory");
        let runtime = crate::registry::insert(crate::registry::Entry::Runtime(
            std::sync::Mutex::new(crate::runtime::Runtime::open(path.clone()).expect("runtime")),
        ))
        .expect("runtime handle");
        let operation = crate::operation::Operation::spawn(
            crate::operation::OperationKind::Import,
            0,
            |_shared| Ok(None),
        )
        .expect("spawn");
        let handle = crate::registry::insert(crate::registry::Entry::Operation {
            owner: runtime,
            operation,
        })
        .expect("insert");
        (handle, runtime, path)
    }

    #[test]
    fn a_panicking_call_invalidates_the_handle_that_owned_it() {
        let (handle, runtime, path) = registered_handle();
        assert_eq!(
            quietly(|| guard_status_for(handle, || panic!("injected"))),
            ChurStatus::InternalFailure.as_i32()
        );
        // §11: a later call on the invalidated handle also fails.
        assert_eq!(
            crate::registry::get(handle, crate::registry::Kind::Operation)
                .err()
                .map(|error| error.status()),
            Some(ChurStatus::SessionExpired)
        );
        drop(crate::registry::close(runtime).expect("close runtime"));
        std::fs::remove_dir_all(path).expect("remove directory");
    }

    #[test]
    fn an_ordinary_error_does_not_invalidate_the_handle() {
        let (handle, runtime, path) = registered_handle();
        assert_eq!(
            guard_status_for(handle, || Err(chur_core::err!(
                AuthenticationFailed,
                "an ordinary refusal"
            ))),
            ChurStatus::AuthenticationFailed.as_i32()
        );
        assert!(
            crate::registry::get(handle, crate::registry::Kind::Operation).is_ok(),
            "an ordinary error must not invalidate the handle"
        );
        drop(crate::registry::close(handle).expect("close"));
        drop(crate::registry::close(runtime).expect("close runtime"));
        std::fs::remove_dir_all(path).expect("remove directory");
    }
}
