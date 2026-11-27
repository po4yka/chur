//! Device authentication of one direct peer session, defined in
//! `docs/sync/SYNC_PROTOCOL_V1.md` §3.2.
//!
//! Each device signs its claimed identity, the transcript hash of both hellos,
//! and the session binding with its enrolled Ed25519 key. The binding derives
//! from the invitation secret and the X25519 shared secret, so a signature is
//! valid for exactly one session.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_format::codec::{Reader, Writer};

use crate::identity::DeviceIdentity;
use crate::operation::verify_ed25519;

/// Length of one encoded authentication record.
pub const RECORD_LEN: usize = 16 + 16 + SIGNATURE_LEN;
const SIGNATURE_LEN: usize = 64;
const DOMAIN: &[u8] = b"CHUR\0P2P\0AUTH\0V2";

/// The local signer and the enrolled devices it accepts for one session.
pub struct PeerCredential {
    vault_id: Id,
    device_id: Id,
    identity: DeviceIdentity,
    trusted: Vec<(Id, [u8; 32])>,
}

impl PeerCredential {
    /// Builds a credential from the local enrolled identity and the signing keys
    /// of the active enrolled devices.
    #[must_use]
    pub fn new(
        vault_id: Id,
        device_id: Id,
        identity: DeviceIdentity,
        trusted: Vec<(Id, [u8; 32])>,
    ) -> Self {
        Self {
            vault_id,
            device_id,
            identity,
            trusted,
        }
    }

    /// The local device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }

    /// Encodes `vault_id || device_id || signature` for the given role. The
    /// initiator signs role 1 and the listener signs role 0.
    #[must_use]
    pub fn sign(&self, role: u8, transcript: &[u8; 32], binding: &[u8; 32]) -> Vec<u8> {
        let message = message(role, &self.vault_id, &self.device_id, transcript, binding);
        let signature = self.identity.signing_key().sign_bytes(&message);
        let mut writer = Writer::with_capacity(RECORD_LEN);
        writer
            .id(&self.vault_id)
            .id(&self.device_id)
            .fixed(&signature);
        writer.finish()
    }

    /// Verifies the remote record for the given remote role and returns the
    /// authenticated device. The claimed device must be another active enrolled
    /// device of this vault, and its enrolled key must verify the signature.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::AuthenticationFailed`] for another vault, an unknown,
    /// revoked or local device, or a signature that does not verify.
    pub fn verify(
        &self,
        role: u8,
        transcript: &[u8; 32],
        binding: &[u8; 32],
        record: &[u8],
    ) -> Result<Id> {
        let mut reader = Reader::new(record, ChurStatus::AuthenticationFailed);
        let vault_id = reader.id()?;
        let device_id = reader.id()?;
        let signature: [u8; SIGNATURE_LEN] = reader.fixed()?;
        reader.finish()?;
        ensure!(
            vault_id == self.vault_id,
            AuthenticationFailed,
            "peer belongs to another vault"
        );
        ensure!(
            device_id != self.device_id,
            AuthenticationFailed,
            "peer claims the local device"
        );
        let key = self
            .trusted
            .iter()
            .find(|(device, _)| device == &device_id)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "peer device is revoked or unknown",
                )
            })?;
        verify_ed25519(
            key,
            &signature,
            &message(role, &vault_id, &device_id, transcript, binding),
        )?;
        Ok(device_id)
    }
}

fn message(
    role: u8,
    vault: &Id,
    device: &Id,
    transcript: &[u8; 32],
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + 1 + 16 + 16 + 32 + 32);
    message.extend_from_slice(DOMAIN);
    message.push(role);
    message.extend_from_slice(vault.as_bytes());
    message.extend_from_slice(device.as_bytes());
    message.extend_from_slice(transcript);
    message.extend_from_slice(binding);
    message
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }
    fn credential(device: u8, seed: u8, trusted: &[(u8, u8)]) -> PeerCredential {
        PeerCredential::new(
            id(1),
            id(device),
            DeviceIdentity::from_seeds([seed; 32], [seed; 32]),
            trusted
                .iter()
                .map(|(device, seed)| {
                    (
                        id(*device),
                        DeviceIdentity::from_seeds([*seed; 32], [*seed; 32]).signing_public_key(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn a_record_verifies_only_for_its_role_transcript_binding_and_enrolled_key() {
        let listener = credential(2, 0x20, &[(3, 0x30), (4, 0x40)]);
        let connector = credential(3, 0x30, &[(2, 0x20)]);
        let record = connector.sign(1, &[5; 32], &[6; 32]);
        assert_eq!(
            listener.verify(1, &[5; 32], &[6; 32], &record).unwrap(),
            id(3)
        );
        for (role, transcript, binding) in [
            (0, [5; 32], [6; 32]),
            (1, [7; 32], [6; 32]),
            (1, [5; 32], [7; 32]),
        ] {
            let error = listener
                .verify(role, &transcript, &binding, &record)
                .unwrap_err();
            assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        }
        // Another member's identifier with this device's key does not verify.
        let impostor = credential(4, 0x30, &[]).sign(1, &[5; 32], &[6; 32]);
        assert!(listener.verify(1, &[5; 32], &[6; 32], &impostor).is_err());
        // An unknown device, the local device, and another vault are refused.
        for record in [
            credential(9, 0x90, &[]).sign(1, &[5; 32], &[6; 32]),
            credential(2, 0x20, &[]).sign(1, &[5; 32], &[6; 32]),
        ] {
            assert!(listener.verify(1, &[5; 32], &[6; 32], &record).is_err());
        }
        let mut other_vault = record.clone();
        other_vault[0] ^= 1;
        assert!(
            listener
                .verify(1, &[5; 32], &[6; 32], &other_vault)
                .is_err()
        );
    }
}
