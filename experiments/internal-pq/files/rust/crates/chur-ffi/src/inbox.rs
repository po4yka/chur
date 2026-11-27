//! Fixed-size key envelopes for the iOS App Group transfer. The extension
//! needs only the public recipient and the seal operation.

use chur_crypto::{Key, post_quantum as pq};

use crate::buffers::{read_request, write_out, write_secret};
use crate::panic::guard_status;

const INFO: &[u8] = b"CHUR\0INBOX\0KEY\0V2";
const HEADER: &[u8] = b"CHURIN02";

/// Expands the app's private seed into the public key for the extension.
///
/// # Safety
/// The input and output must be null or point to disjoint buffers of the sizes in the signature.
#[expect(unsafe_code, reason = "fixed-size buffers at the Apple inbox C ABI")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_inbox_public(
    seed: *const [u8; 32],
    out: *mut [u8; pq::RECIPIENT_LEN],
) -> i32 {
    // SAFETY: read_request and write_out check null. The caller provides the fixed-size buffers.
    guard_status(|| unsafe {
        write_out(out, pq::recipient_public(&Key::new(*read_request(seed)?))?)
    })
}

/// Wraps the per-file AES key for one recipient.
///
/// # Safety
/// The input and output must be null or point to disjoint buffers of the sizes in the signature.
#[expect(unsafe_code, reason = "fixed-size buffers at the Apple inbox C ABI")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_inbox_seal(
    recipient: *const [u8; pq::RECIPIENT_LEN],
    key: *const [u8; 32],
    out: *mut [u8; pq::ENVELOPE_LEN],
) -> i32 {
    // SAFETY: read_request and write_out check null. The caller provides the fixed-size buffers.
    guard_status(|| unsafe {
        write_out(
            out,
            pq::seal_key(
                read_request(recipient)?,
                INFO,
                HEADER,
                &Key::new(*read_request(key)?),
            )?,
        )
    })
}

/// Authenticates and unwraps a file key in the main app.
///
/// # Safety
/// The inputs must be null or readable for their declared lengths. Output must
/// be null or writable for 32 bytes. All buffers must be disjoint.
#[expect(unsafe_code, reason = "fixed-size buffers at the Apple inbox C ABI")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_inbox_open(
    seed: *const [u8; 32],
    envelope: *const [u8; pq::ENVELOPE_LEN],
    out: *mut u8,
) -> i32 {
    // SAFETY: the helpers check null. The caller provides the fixed-size buffers.
    guard_status(|| unsafe {
        let key = pq::open_key(
            &Key::new(*read_request(seed)?),
            INFO,
            HEADER,
            read_request(envelope)?,
        )?;
        write_secret(out, key.expose())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chur_core::ChurStatus;
    use std::ptr::{null, null_mut};

    #[test]
    #[expect(
        unsafe_code,
        reason = "exercises documented null and fixed-size C buffers"
    )]
    fn reject_invalid_buffers_and_preserve_output_on_authentication_failure() {
        let seed = [0x42; 32];
        let mut output = [0x19; 32];
        // SAFETY: the null pointers request errors; other buffers have the declared lengths.
        unsafe {
            assert_eq!(
                chur_inbox_public(&seed, null_mut()),
                ChurStatus::InvalidInput.as_i32()
            );
            assert_eq!(
                chur_inbox_seal(null(), &seed, null_mut()),
                ChurStatus::InvalidInput.as_i32()
            );
            assert_eq!(
                chur_inbox_open(&seed, &[0; pq::ENVELOPE_LEN], output.as_mut_ptr()),
                ChurStatus::AuthenticationFailed.as_i32()
            );
        }
        assert_eq!(output, [0x19; 32]);
    }
}
