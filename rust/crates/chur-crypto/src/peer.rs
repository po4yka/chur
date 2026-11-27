//! Direction-separated keys for ephemeral direct peer sessions.
//!
//! Version 2 mixes a fresh X25519 shared secret into the invitation secret, so
//! later disclosure of the invitation does not decrypt recorded traffic.
use crate::kdf::{self, Context, Label};
use crate::{Key, random};
use chur_core::{ChurStatus, Error, Result, ensure};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of one version-2 peer hello: magic, challenge, and ephemeral public key.
pub const HELLO_LEN: usize = 72;

/// One fresh X25519 key pair for exactly one handshake.
pub struct EphemeralKey(StaticSecret);

impl EphemeralKey {
    /// Generates a key pair from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        // The seed is generated in a wiped buffer, and `StaticSecret` wipes its bytes
        // on drop. Its constructor takes the bytes by value, so only that argument
        // temporary is not wiped; no named copy of the seed remains.
        let seed = random::secret::<32>()?;
        Ok(Self(StaticSecret::from(*seed.expose())))
    }

    /// The public key carried in the hello.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// Computes the shared secret and consumes the private key.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::AuthenticationFailed`] for a low-order remote key,
    /// which would make the shared secret independent of the local key.
    pub fn agree(self, remote: &[u8; 32]) -> Result<Key> {
        let shared = self.0.diffie_hellman(&PublicKey::from(*remote));
        ensure!(
            shared.was_contributory(),
            AuthenticationFailed,
            "peer ephemeral key is invalid"
        );
        // Copy into the wiped key buffer directly; `shared` is wiped on drop.
        let mut key = Key::zeroed();
        key.expose_mut().copy_from_slice(shared.as_bytes());
        Ok(key)
    }
}

/// The keys of one version-2 peer session.
pub struct SessionKeys {
    /// Initiator-to-listener direction key.
    pub initiator: Key,
    /// Listener-to-initiator direction key.
    pub listener: Key,
    /// Session value that each device signature covers.
    pub binding: Key,
}

/// Hashes both complete hellos in initiator, listener order.
///
/// # Errors
///
/// Returns [`ChurStatus::InvalidInput`] when a hello has the wrong length.
pub fn transcript(initiator: &[u8], listener: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        initiator.len() == HELLO_LEN && listener.len() == HELLO_LEN,
        InvalidInput,
        "peer hello is invalid"
    );
    let mut hash = Sha256::new();
    hash.update(b"CHUR\0P2P\0TRANSCRIPT\0V2");
    hash.update(initiator);
    hash.update(listener);
    Ok(hash.finalize().into())
}

/// Derives both direction keys and the signature binding from the invitation
/// secret, the X25519 shared secret, and the transcript hash.
///
/// # Errors
///
/// Returns [`ChurStatus::InternalFailure`] if HKDF rejects the output length.
pub fn session_keys(secret: &Key, shared: &Key, transcript: &[u8; 32]) -> Result<SessionKeys> {
    // PeerHandshakeSecret: the invitation secret, then the X25519 shared secret.
    let mut input = Zeroizing::new([0u8; 64]);
    input[..32].copy_from_slice(secret.expose());
    input[32..].copy_from_slice(shared.expose());
    let derive = |direction: u8| {
        kdf::derive(
            &*input,
            Label::PeerSession,
            &Context::peer_session(transcript, direction),
        )
    };
    Ok(SessionKeys {
        initiator: derive(1)?,
        listener: derive(0)?,
        binding: kdf::derive(
            &*input,
            Label::PeerTranscriptBinding,
            &Context::peer_transcript(transcript),
        )
        .map_err(|_| Error::new(ChurStatus::InternalFailure, "peer key derivation failed"))?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_secret_changes_every_key_for_one_invitation_and_transcript() {
        let secret = Key::new([7; 32]);
        let transcript = [9; 32];
        let first = session_keys(&secret, &Key::new([1; 32]), &transcript).unwrap();
        let second = session_keys(&secret, &Key::new([2; 32]), &transcript).unwrap();
        assert_ne!(first.initiator.expose(), second.initiator.expose());
        assert_ne!(first.listener.expose(), second.listener.expose());
        assert_ne!(first.binding.expose(), second.binding.expose());
        assert_ne!(first.initiator.expose(), first.listener.expose());
        assert_ne!(first.initiator.expose(), first.binding.expose());
    }

    #[test]
    fn both_sides_agree_and_a_low_order_key_is_refused() {
        let left = EphemeralKey::generate().unwrap();
        let right = EphemeralKey::generate().unwrap();
        let (left_public, right_public) = (left.public_key(), right.public_key());
        assert_eq!(
            left.agree(&right_public).unwrap().expose(),
            right.agree(&left_public).unwrap().expose()
        );
        let error = EphemeralKey::generate()
            .unwrap()
            .agree(&[0; 32])
            .err()
            .unwrap();
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }
}
