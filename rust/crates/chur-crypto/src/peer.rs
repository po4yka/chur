//! Ephemeral X-Wing recipient and invitation-bound keys for direct peer sessions.
use crate::kdf::{self, Context, Label};
use crate::post_quantum::{ENVELOPE_LEN, RECIPIENT_LEN, open_key, recipient_public, seal_key};
use crate::{Key, random};
use chur_core::{ChurStatus, Error, Result, ensure};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The wire magic fixes the suite for this internal protocol.
pub const MAGIC: &[u8; 8] = b"CHURP2P3";
/// The connector sends the first flight and proves device membership first.
pub const INITIATOR: u8 = 1;
/// The listener sends the second flight and proves device membership second.
pub const LISTENER: u8 = 0;
const HEADER_LEN: usize = MAGIC.len() + 1 + 32;
/// Version, role, challenge and one ephemeral X-Wing public key.
pub const OFFER_LEN: usize = HEADER_LEN + RECIPIENT_LEN;
/// Version, role, challenge and one HPKE envelope for the listener's random key.
pub const REPLY_LEN: usize = HEADER_LEN + ENVELOPE_LEN;
const INFO: &[u8] = b"CHUR\0P2P\0HANDSHAKE\0V3";

/// Check incoming magic and role as soon as their bytes arrive.
pub fn check_prefix(input: &[u8], role: u8) -> Result<()> {
    if let Some(magic) = input.get(..MAGIC.len()) {
        ensure!(
            !magic.starts_with(b"CHURP2P") || magic == MAGIC,
            UnsupportedVersion,
            "the peer at this address uses an unsupported peer protocol version"
        );
        ensure!(
            magic == MAGIC,
            AuthenticationFailed,
            "peer protocol differs"
        );
    }
    if let Some(received) = input.get(MAGIC.len()) {
        ensure!(
            *received == role,
            AuthenticationFailed,
            "incorrect peer role"
        );
    }
    Ok(())
}

fn header(role: u8) -> Result<[u8; HEADER_LEN]> {
    let mut result = [0; HEADER_LEN];
    result[..8].copy_from_slice(MAGIC);
    result[8] = role;
    random::fill(&mut result[9..])?;
    Ok(result)
}

fn aad(offer: &[u8; OFFER_LEN], reply: &[u8; REPLY_LEN]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OFFER_LEN + HEADER_LEN);
    bytes.extend_from_slice(offer);
    bytes.extend_from_slice(&reply[..HEADER_LEN]);
    bytes
}

fn transcript(offer: &[u8; OFFER_LEN], reply: &[u8; REPLY_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CHUR\0P2P\0TRANSCRIPT\0V3");
    hash.update(offer);
    hash.update(reply);
    hash.finalize().into()
}

/// The initiator holds this key until it receives one listener reply.
pub struct Offer {
    seed: Key,
    bytes: [u8; OFFER_LEN],
}

impl Offer {
    /// Generate an ephemeral recipient and an independent public challenge.
    pub fn generate() -> Result<Self> {
        let seed = random::secret()?;
        let mut bytes = [0; OFFER_LEN];
        bytes[..HEADER_LEN].copy_from_slice(&header(INITIATOR)?);
        bytes[HEADER_LEN..].copy_from_slice(&recipient_public(&seed)?);
        Ok(Self { seed, bytes })
    }

    /// Public first flight.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; OFFER_LEN] {
        &self.bytes
    }

    /// Open the response and discard the ephemeral private seed.
    pub fn finish(self, invitation: &Key, reply: &[u8; REPLY_LEN]) -> Result<SessionKeys> {
        check_prefix(reply, LISTENER)?;
        let envelope = reply[HEADER_LEN..]
            .try_into()
            .map_err(|_| Error::new(ChurStatus::InvalidInput, "invalid peer reply"))?;
        let shared = open_key(&self.seed, INFO, &aad(&self.bytes, reply), envelope)?;
        session_keys(invitation, &shared, &transcript(&self.bytes, reply))
    }
}

/// Encapsulate fresh key material to the initiator and derive the listener's session.
pub fn answer(invitation: &Key, offer: &[u8; OFFER_LEN]) -> Result<([u8; REPLY_LEN], SessionKeys)> {
    check_prefix(offer, INITIATOR)?;
    let recipient = offer[HEADER_LEN..]
        .try_into()
        .map_err(|_| Error::new(ChurStatus::InvalidInput, "invalid peer offer"))?;
    let shared = random::secret()?;
    let mut reply = [0; REPLY_LEN];
    reply[..HEADER_LEN].copy_from_slice(&header(LISTENER)?);
    let envelope = seal_key(recipient, INFO, &aad(offer, &reply), &shared)?;
    reply[HEADER_LEN..].copy_from_slice(&envelope);
    let keys = session_keys(invitation, &shared, &transcript(offer, &reply))?;
    Ok((reply, keys))
}

/// The keys and public transcript of a single peer session.
pub struct SessionKeys {
    /// Initiator-to-listener direction key.
    pub initiator: Key,
    /// Listener-to-initiator direction key.
    pub listener: Key,
    /// Session value that each device signature covers.
    pub binding: Key,
    /// Digest of the ordered, role-tagged flights.
    pub transcript: [u8; 32],
}

/// Derives both direction keys and the signature binding from the invitation
/// secret, the fresh listener secret, and the transcript hash.
///
/// # Errors
///
/// Returns [`ChurStatus::InternalFailure`] if HKDF rejects the output length.
fn session_keys(secret: &Key, shared: &Key, transcript: &[u8; 32]) -> Result<SessionKeys> {
    // PeerHandshakeSecret: the invitation secret, then the fresh listener secret.
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
        transcript: *transcript,
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
    fn independent_go_listener_reply_and_all_session_keys_match() {
        let seed = Key::new([0x42; 32]);
        let mut bytes = [0x11; OFFER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = INITIATOR;
        bytes[HEADER_LEN..].copy_from_slice(&recipient_public(&seed).unwrap());
        let fixture = include_bytes!("../../../../test-vectors/internal-pq/peer-session.bin");
        let (reply, expected) = fixture.split_at(REPLY_LEN);
        let keys = Offer { seed, bytes }
            .finish(&Key::new([0x44; 32]), reply.try_into().unwrap())
            .unwrap();
        assert_eq!(keys.transcript, expected[..32]);
        assert_eq!(keys.initiator.expose(), &expected[32..64]);
        assert_eq!(keys.listener.expose(), &expected[64..96]);
        assert_eq!(keys.binding.expose(), &expected[96..]);
    }

    #[test]
    fn neither_flight_accepts_a_noncontributory_curve_component() {
        let secret = Key::new([7; 32]);
        let offer = Offer::generate().unwrap();
        let (mut reply, _) = answer(&secret, offer.bytes()).unwrap();
        let mut invalid = *offer.bytes();
        invalid[OFFER_LEN - 32..].fill(0);
        assert!(answer(&secret, &invalid).is_err());
        let end = HEADER_LEN + crate::post_quantum::ENCAP_LEN;
        reply[end - 32..end].fill(0);
        assert!(offer.finish(&secret, &reply).is_err());
    }

    #[test]
    fn reply_opens_only_for_its_offer_and_binds_both_roles_and_challenges() {
        let secret = Key::new([7; 32]);
        let offer = Offer::generate().unwrap();
        let (reply, listener) = answer(&secret, offer.bytes()).unwrap();
        assert!(Offer::generate().unwrap().finish(&secret, &reply).is_err());
        assert!(check_prefix(&reply, INITIATOR).is_err());
        assert!(check_prefix(offer.bytes(), LISTENER).is_err());
        let connector = offer.finish(&secret, &reply).unwrap();
        assert_eq!(listener.transcript, connector.transcript);
        assert_eq!(listener.binding.expose(), connector.binding.expose());
        let offer = Offer::generate().unwrap();
        let (mut reply, _) = answer(&secret, offer.bytes()).unwrap();
        reply[HEADER_LEN - 1] ^= 1;
        assert!(offer.finish(&secret, &reply).is_err());
    }
}
