//! Device enrollment requests and authority-signed HPKE approvals.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Key, commit, tuple::tag};
use chur_format::codec::{Reader, Writer};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::identity::{self, DeviceIdentity};
use crate::operation::verify_ed25519;

/// Largest complete pairing approval, including its public authority proof.
pub const APPROVAL_MAX: usize = 16_777_216;
/// Maximum signed membership records in one authority proof.
pub const AUTHORITY_RECORDS_MAX: usize = 4_096;

/// A fresh device proves possession of its new signing key and the vault root.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingRequest {
    vault_id: Id,
    request_id: Id,
    device_id: Id,
    signing_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
    root_proof: [u8; 32],
    signature: [u8; 64],
}

impl PairingRequest {
    /// Exact canonical request size.
    pub const LEN: usize = 210;

    /// Creates a public request. Private identity material stays with the caller.
    pub fn new(
        root: &Key,
        vault_id: Id,
        request_id: Id,
        device_id: Id,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        let mut request = Self {
            vault_id,
            request_id,
            device_id,
            signing_public_key: identity.signing_public_key(),
            hpke_public_key: identity.hpke_public_key(),
            root_proof: [0; 32],
            signature: [0; 64],
        };
        request.root_proof =
            commit::keyed_commit(root, tag::PAIRING_ROOT_PROOF, &request.identity_body());
        request.signature = identity
            .signing_key()
            .sign_bytes(&tagged(tag::PAIRING_REQUEST_SIGNATURE, &request.unsigned()));
        Ok(request)
    }

    /// Authenticates both new-key possession and the shared vault root.
    pub fn verify_root(&self, root: &Key) -> Result<()> {
        self.verify()?;
        ensure!(
            commit::verify_keyed(
                root,
                tag::PAIRING_ROOT_PROOF,
                &self.identity_body(),
                &self.root_proof
            ),
            AuthenticationFailed,
            "pairing request does not prove the vault root"
        );
        Ok(())
    }

    /// Authenticates new-key possession for the fingerprint inspection UI.
    pub fn verify(&self) -> Result<()> {
        verify_ed25519(
            &self.signing_public_key,
            &self.signature,
            &tagged(tag::PAIRING_REQUEST_SIGNATURE, &self.unsigned()),
        )
    }

    /// Vault that the request joins.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }
    /// Fresh request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &Id {
        &self.request_id
    }
    /// Fresh ordinary device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }
    /// Requested signing public key.
    #[must_use]
    pub const fn signing_public_key(&self) -> &[u8; 32] {
        &self.signing_public_key
    }
    /// Requested HPKE public key.
    #[must_use]
    pub const fn hpke_public_key(&self) -> &[u8; 32] {
        &self.hpke_public_key
    }
    /// Fingerprint to compare through a separate trusted channel.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        identity::fingerprint(
            &self.vault_id,
            &self.device_id,
            &self.signing_public_key,
            &self.hpke_public_key,
        )
    }
    /// Commitment bound by the approval and its encrypted credentials.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        commit::commit(tag::PAIRING_REQUEST_DIGEST, &[&self.encode()])
    }

    fn identity_body(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u16(1)
            .id(&self.vault_id)
            .id(&self.request_id)
            .id(&self.device_id)
            .fixed(&self.signing_public_key)
            .fixed(&self.hpke_public_key);
        writer.finish()
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut bytes = self.identity_body();
        bytes.extend_from_slice(&self.root_proof);
        bytes
    }
    /// Canonical public request bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.unsigned();
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Parses an exact canonical request and verifies its self-signature.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::LEN,
            InvalidInput,
            "pairing request length differs"
        );
        let mut reader = Reader::new(bytes, ChurStatus::InvalidInput);
        ensure!(
            reader.u16()? == 1,
            UnsupportedVersion,
            "pairing request version differs"
        );
        let request = Self {
            vault_id: reader.id()?,
            request_id: reader.id()?,
            device_id: reader.id()?,
            signing_public_key: reader.fixed()?,
            hpke_public_key: reader.fixed()?,
            root_proof: reader.fixed()?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// Signed public authority proof and an HPKE response for exactly one request.
pub struct PairingApproval {
    vault_id: Id,
    request_id: Id,
    recipient_device_id: Id,
    issuer_device_id: Id,
    request_digest: [u8; 32],
    authority_records: Vec<Vec<u8>>,
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
    signature: [u8; 64],
}

impl PairingApproval {
    /// Seals credentials and bootstrap records to the new identity, then signs
    /// their complete encoding with the authorizing ordinary device identity.
    pub fn seal(
        request: &PairingRequest,
        issuer_device_id: Id,
        authority_records: Vec<Vec<u8>>,
        issuer: &DeviceIdentity,
        plaintext: &[u8],
    ) -> Result<Self> {
        ensure!(
            authority_records.len() <= AUTHORITY_RECORDS_MAX && plaintext.len() <= APPROVAL_MAX,
            ResourceLimitExceeded,
            "pairing approval exceeds its bound"
        );
        let mut approval = Self {
            vault_id: *request.vault_id(),
            request_id: *request.request_id(),
            recipient_device_id: *request.device_id(),
            issuer_device_id,
            request_digest: request.digest(),
            authority_records,
            encapsulated_key: [0; 32],
            ciphertext: Vec::new(),
            signature: [0; 64],
        };
        let context = tagged(tag::PAIRING_APPROVAL_HPKE, &approval.header()?);
        let recipient =
            <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(request.hpke_public_key())
                .map_err(|_| {
                    Error::new(
                        ChurStatus::AuthenticationFailed,
                        "pairing recipient key is invalid",
                    )
                })?;
        let (encapsulated, ciphertext) =
            hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &recipient,
                &context,
                plaintext,
                &context,
            )
            .map_err(|_| {
                Error::new(
                    ChurStatus::InternalFailure,
                    "pairing approval sealing failed",
                )
            })?;
        approval
            .encapsulated_key
            .copy_from_slice(encapsulated.to_bytes().as_ref());
        approval.ciphertext = ciphertext;
        approval.signature = issuer.signing_key().sign_bytes(&tagged(
            tag::PAIRING_APPROVAL_SIGNATURE,
            &approval.unsigned()?,
        ));
        ensure!(
            approval.encode()?.len() <= APPROVAL_MAX,
            ResourceLimitExceeded,
            "pairing approval exceeds its bound"
        );
        Ok(approval)
    }
    /// Binds the approval to the local vault and exact pending request.
    pub fn verify_request(&self, request: &PairingRequest) -> Result<()> {
        ensure!(
            self.vault_id == *request.vault_id()
                && self.request_id == *request.request_id()
                && self.recipient_device_id == *request.device_id()
                && self.request_digest == request.digest(),
            AuthenticationFailed,
            "pairing approval does not match the pending request"
        );
        Ok(())
    }
    /// Authorizing device identifier, resolved from the authenticated membership proof.
    #[must_use]
    pub const fn issuer_device_id(&self) -> &Id {
        &self.issuer_device_id
    }
    /// Canonical signed membership records, each prefixed by its kind byte.
    #[must_use]
    pub fn authority_records(&self) -> &[Vec<u8>] {
        &self.authority_records
    }
    /// Verifies the authorizing signature before credentials become visible.
    pub fn verify(&self, issuer_key: &[u8; 32]) -> Result<()> {
        verify_ed25519(
            issuer_key,
            &self.signature,
            &tagged(tag::PAIRING_APPROVAL_SIGNATURE, &self.unsigned()?),
        )
    }
    /// Authenticates and decrypts a response for the pending private identity.
    pub fn open(
        &self,
        recipient: &DeviceIdentity,
        issuer_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.verify(issuer_key)?;
        let context = tagged(tag::PAIRING_APPROVAL_HPKE, &self.header()?);
        let private =
            <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(recipient.hpke_secret_bytes())
                .map_err(|_| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "pairing private identity is invalid",
                )
            })?;
        let encapsulated =
            <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&self.encapsulated_key)
                .map_err(|_| {
                    Error::new(
                        ChurStatus::AuthenticationFailed,
                        "pairing encapsulation is invalid",
                    )
                })?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            &context,
            &self.ciphertext,
            &context,
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "pairing approval did not authenticate",
            )
        })
    }
    fn header(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer
            .u16(1)
            .id(&self.vault_id)
            .id(&self.request_id)
            .id(&self.recipient_device_id)
            .id(&self.issuer_device_id)
            .fixed(&self.request_digest)
            .u32(self.authority_records.len() as u32);
        for record in &self.authority_records {
            writer.variable(record)?;
        }
        Ok(writer.finish())
    }
    fn unsigned(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer
            .fixed(&self.header()?)
            .fixed(&self.encapsulated_key)
            .variable(&self.ciphertext)?;
        Ok(writer.finish())
    }
    /// Canonical public approval code. Its credential payload stays encrypted.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.unsigned()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    /// Parses a bounded canonical approval without releasing credentials.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= APPROVAL_MAX,
            ResourceLimitExceeded,
            "pairing approval exceeds its bound"
        );
        let mut reader = Reader::new(bytes, ChurStatus::InvalidInput);
        ensure!(
            reader.u16()? == 1,
            UnsupportedVersion,
            "pairing approval version differs"
        );
        let vault_id = reader.id()?;
        let request_id = reader.id()?;
        let recipient_device_id = reader.id()?;
        let issuer_device_id = reader.id()?;
        let request_digest = reader.fixed()?;
        let count = reader.u32()? as usize;
        ensure!(
            count <= AUTHORITY_RECORDS_MAX,
            ResourceLimitExceeded,
            "pairing authority proof exceeds its bound"
        );
        let mut authority_records = Vec::new();
        for _ in 0..count {
            authority_records.push(reader.variable(1_048_576)?.to_vec());
        }
        let approval = Self {
            vault_id,
            request_id,
            recipient_device_id,
            issuer_device_id,
            request_digest,
            authority_records,
            encapsulated_key: reader.fixed()?,
            ciphertext: reader.variable(APPROVAL_MAX as u32)?.to_vec(),
            signature: reader.fixed()?,
        };
        reader.finish()?;
        Ok(approval)
    }
}

fn tagged(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    fn id(value: u8) -> Id {
        Id::new([value; 16]).expect("id")
    }
    #[test]
    fn a_restored_root_can_prepare_a_fresh_device_request() {
        let identity = DeviceIdentity::from_seeds([2; 32], [3; 32]);
        let root = Key::new([1; 32]);
        let request = PairingRequest::new(&root, id(4), id(5), id(6), &identity)
            .expect("a fresh root holder must prepare a request");
        assert_eq!(request.encode().len(), PairingRequest::LEN);
        let parsed = PairingRequest::decode(&request.encode()).expect("request roundtrip");
        parsed.verify_root(&root).expect("root proof");
        assert!(parsed.verify_root(&Key::new([9; 32])).is_err());
        assert_eq!(parsed.fingerprint(), request.fingerprint());
    }
    #[test]
    fn approval_binds_credentials_to_authority_and_the_pending_private_identity() {
        let root = Key::new([1; 32]);
        let recipient = DeviceIdentity::from_seeds([2; 32], [3; 32]);
        let issuer = DeviceIdentity::from_seeds([4; 32], [5; 32]);
        let request = PairingRequest::new(&root, id(6), id(7), id(8), &recipient).expect("request");
        let approval = PairingApproval::seal(
            &request,
            id(9),
            vec![vec![1; 32]],
            &issuer,
            b"https://trusted.example secret token",
        )
        .expect("seal");
        let encoded = approval.encode().expect("encode");
        assert!(!encoded.windows(7).any(|window| window == b"trusted"));
        let parsed = PairingApproval::decode(&encoded).expect("decode");
        parsed
            .verify_request(&request)
            .expect("pending request binding");
        assert_eq!(
            &*parsed
                .open(&recipient, &issuer.signing_public_key())
                .expect("open"),
            b"https://trusted.example secret token"
        );
        assert!(parsed.open(&issuer, &issuer.signing_public_key()).is_err());
        assert!(
            parsed
                .open(&recipient, &recipient.signing_public_key())
                .is_err()
        );
        let mut changed = encoded;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(
            PairingApproval::decode(&changed)
                .expect("framing remains valid")
                .open(&recipient, &issuer.signing_public_key())
                .is_err()
        );
    }
}
