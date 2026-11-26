//! The fixed collection grant of `docs/sync/COLLECTION_GRANTS.md`.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::post_quantum::{
    ENCAP_LEN as ENCAPSULATED_KEY_LEN, RECIPIENT_LEN, SIGNATURE_LEN, VERIFY_LEN,
    validate_encapsulation, validate_recipient,
};
use chur_crypto::secret::Key;
use chur_crypto::{commit::commit, tuple::tag};
use chur_format::codec::{Reader, Writer};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::identity::{DeviceIdentity, HPKE_SUITE_V2, SIGNING_SUITE_V2};
use crate::operation::PROTOCOL_VERSION_V2;
use crate::operation::{DeviceSigningKey, verify_device_signature};

const KEY_ID_LEN: usize = 16;
const WRAPPED_COLLECTION_KEY_LEN: usize = 48;

/// One cumulative v1 sharing permission profile.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PermissionProfile {
    /// Read replicated collection state.
    Read = 0x01,
    /// Read and author ordinary collection operations.
    Contribute = 0x03,
    /// Read, contribute, and change collection membership.
    ManageMembers = 0x07,
}

impl PermissionProfile {
    pub(crate) fn decode(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Read),
            0x03 => Ok(Self::Contribute),
            0x07 => Ok(Self::ManageMembers),
            _ => Err(Error::new(
                ChurStatus::UnsupportedVersion,
                "sharing permission profile is not supported",
            )),
        }
    }
}

/// One fixed signed grant for one collection epoch and recipient device.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectionGrant {
    grant_id: Id,
    source_vault_id: Id,
    collection_id: Id,
    collection_epoch: u64,
    collection_membership_generation: u64,
    recipient_identity_vault_id: Id,
    recipient_device_id: Id,
    recipient_hpke_key_id: [u8; KEY_ID_LEN],
    sender_device_id: Id,
    sender_signing_key_id: [u8; KEY_ID_LEN],
    permissions: PermissionProfile,
    sender_membership_generation: u64,
    created_sequence: u64,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
    wrapped_collection_key: [u8; WRAPPED_COLLECTION_KEY_LEN],
    sender_signature: [u8; SIGNATURE_LEN],
}

impl CollectionGrant {
    /// Exact canonical encoded length.
    pub const LEN: usize = 165 + ENCAPSULATED_KEY_LEN + WRAPPED_COLLECTION_KEY_LEN + SIGNATURE_LEN;

    /// Seals one collection key to one recipient device.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen grant fields"
    )]
    pub fn seal(
        grant_id: Id,
        source_vault_id: Id,
        collection_id: Id,
        collection_epoch: u64,
        collection_membership_generation: u64,
        recipient_identity_vault_id: Id,
        recipient_device_id: Id,
        recipient_hpke_public_key: &[u8; RECIPIENT_LEN],
        sender_device_id: Id,
        permissions: PermissionProfile,
        sender_membership_generation: u64,
        created_sequence: u64,
        collection_key: &Key,
        sender_signing_key: &DeviceSigningKey,
    ) -> Result<Self> {
        let grant = Self::unsigned(
            grant_id,
            source_vault_id,
            collection_id,
            collection_epoch,
            collection_membership_generation,
            recipient_identity_vault_id,
            recipient_device_id,
            sender_device_id,
            permissions,
            sender_membership_generation,
            created_sequence,
            recipient_hpke_public_key,
            sender_signing_key,
        )?;
        let context = grant.context_bytes();
        let recipient_public_key = recipient_public_key(recipient_hpke_public_key)?;
        let (encapsulated_key, wrapped_collection_key) =
            hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeS::Base,
                &recipient_public_key,
                &grant_info(&context),
                collection_key.expose(),
                &grant_aad(&context),
            )
            .map_err(|_| {
                Error::new(
                    ChurStatus::InternalFailure,
                    "collection grant HPKE seal failed",
                )
            })?;
        grant.finish_seal(
            encapsulated_key.to_bytes().as_ref(),
            &wrapped_collection_key,
            sender_signing_key,
        )
    }

    /// Seals with fixed test-only ephemeral input for published vectors.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen grant fields plus test input"
    )]
    pub fn seal_for_test_vector(
        grant_id: Id,
        source_vault_id: Id,
        collection_id: Id,
        collection_epoch: u64,
        collection_membership_generation: u64,
        recipient_identity_vault_id: Id,
        recipient_device_id: Id,
        recipient_hpke_public_key: &[u8; RECIPIENT_LEN],
        sender_device_id: Id,
        permissions: PermissionProfile,
        sender_membership_generation: u64,
        created_sequence: u64,
        collection_key: &Key,
        sender_signing_key: &DeviceSigningKey,
        ephemeral_ikm: [u8; 64],
    ) -> Result<Self> {
        let grant = Self::unsigned(
            grant_id,
            source_vault_id,
            collection_id,
            collection_epoch,
            collection_membership_generation,
            recipient_identity_vault_id,
            recipient_device_id,
            sender_device_id,
            permissions,
            sender_membership_generation,
            created_sequence,
            recipient_hpke_public_key,
            sender_signing_key,
        )?;
        let context = grant.context_bytes();
        let mut rng = FixedTestRng::new(ephemeral_ikm);
        let (encapsulated_key, wrapped_collection_key) =
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeS::Base,
                &recipient_public_key(recipient_hpke_public_key)?,
                &grant_info(&context),
                collection_key.expose(),
                &grant_aad(&context),
                &mut rng,
            )
            .map_err(|_| {
                Error::new(
                    ChurStatus::InternalFailure,
                    "collection grant HPKE seal failed",
                )
            })?;
        grant.finish_seal(
            encapsulated_key.to_bytes().as_ref(),
            &wrapped_collection_key,
            sender_signing_key,
        )
    }

    /// Verifies and opens the collection key for the bound recipient device.
    pub fn open_collection_key(
        &self,
        recipient_identity_vault_id: &Id,
        recipient_device_id: &Id,
        recipient_identity: &DeviceIdentity,
        sender_signing_public_key: &[u8; VERIFY_LEN],
    ) -> Result<Key> {
        ensure!(
            &self.recipient_identity_vault_id == recipient_identity_vault_id
                && &self.recipient_device_id == recipient_device_id
                && self.recipient_hpke_key_id
                    == hpke_key_id(
                        recipient_identity_vault_id,
                        recipient_device_id,
                        &recipient_identity.hpke_public_key(),
                    ),
            AuthenticationFailed,
            "collection grant recipient identity or key identifier does not match"
        );
        self.verify_sender_signature(sender_signing_public_key)?;
        let recipient_private_key =
            <XWing as KemTrait>::PrivateKey::from_bytes(recipient_identity.hpke_secret_bytes())
                .map_err(|_| {
                    Error::new(
                        ChurStatus::AuthenticationFailed,
                        "recipient HPKE private key is invalid",
                    )
                })?;
        let encapsulated_key = <XWing as KemTrait>::EncappedKey::from_bytes(&self.encapsulated_key)
            .map_err(|_| {
                Error::new(
                    ChurStatus::ObjectCorrupt,
                    "collection grant HPKE encapsulation is invalid",
                )
            })?;
        let context = self.context_bytes();
        // The HPKE plaintext is the collection key itself. It leaves the HPKE
        // library as a heap `Vec<u8>`, so it is zeroized on every drop path —
        // both when the key is copied out and when the length check fails —
        // instead of staying in freed-but-unwiped memory.
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeR::Base,
                &recipient_private_key,
                &encapsulated_key,
                &grant_info(&context),
                &self.wrapped_collection_key,
                &grant_aad(&context),
            )
            .map_err(|_| {
                Error::new(
                    ChurStatus::ObjectCorrupt,
                    "collection grant HPKE authentication failed",
                )
            })?,
        );
        let key: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
            Error::new(
                ChurStatus::ObjectCorrupt,
                "collection grant plaintext is not 32 bytes",
            )
        })?;
        Ok(Key::new(key))
    }

    /// Verifies the sender key identifier and ML-DSA-65 signature.
    pub fn verify_sender_signature(
        &self,
        sender_signing_public_key: &[u8; VERIFY_LEN],
    ) -> Result<()> {
        ensure!(
            self.sender_signing_key_id
                == signing_key_id(
                    &self.source_vault_id,
                    &self.sender_device_id,
                    sender_signing_public_key,
                ),
            AuthenticationFailed,
            "collection grant sender key identifier does not match"
        );
        verify_device_signature(
            sender_signing_public_key,
            &self.sender_signature,
            &self.signature_input(),
        )
    }

    /// Grant identifier and containing issue-operation identifier.
    #[must_use]
    pub const fn grant_id(&self) -> &Id {
        &self.grant_id
    }

    /// Source vault that owns the collection.
    #[must_use]
    pub const fn source_vault_id(&self) -> &Id {
        &self.source_vault_id
    }

    /// Shared security collection.
    #[must_use]
    pub const fn collection_id(&self) -> &Id {
        &self.collection_id
    }

    /// Collection key epoch wrapped by this grant.
    #[must_use]
    pub const fn collection_epoch(&self) -> u64 {
        self.collection_epoch
    }

    /// Membership generation that last changed this recipient.
    #[must_use]
    pub const fn collection_membership_generation(&self) -> u64 {
        self.collection_membership_generation
    }

    /// Recipient identity vault.
    #[must_use]
    pub const fn recipient_identity_vault_id(&self) -> &Id {
        &self.recipient_identity_vault_id
    }

    /// Recipient device.
    #[must_use]
    pub const fn recipient_device_id(&self) -> &Id {
        &self.recipient_device_id
    }

    /// Recipient HPKE key identifier.
    #[must_use]
    pub const fn recipient_hpke_key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.recipient_hpke_key_id
    }

    /// Sender device.
    #[must_use]
    pub const fn sender_device_id(&self) -> &Id {
        &self.sender_device_id
    }

    /// Sender device-membership generation.
    #[must_use]
    pub const fn sender_membership_generation(&self) -> u64 {
        self.sender_membership_generation
    }

    /// Recipient permission profile.
    #[must_use]
    pub const fn permissions(&self) -> PermissionProfile {
        self.permissions
    }

    /// Containing issue-operation device sequence.
    #[must_use]
    pub const fn created_sequence(&self) -> u64 {
        self.created_sequence
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields"
    )]
    fn from_fields(
        grant_id: Id,
        source_vault_id: Id,
        collection_id: Id,
        collection_epoch: u64,
        collection_membership_generation: u64,
        recipient_identity_vault_id: Id,
        recipient_device_id: Id,
        recipient_hpke_key_id: [u8; KEY_ID_LEN],
        sender_device_id: Id,
        sender_signing_key_id: [u8; KEY_ID_LEN],
        permissions: PermissionProfile,
        sender_membership_generation: u64,
        created_sequence: u64,
        encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
        wrapped_collection_key: [u8; WRAPPED_COLLECTION_KEY_LEN],
        sender_signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self> {
        let grant = Self {
            grant_id,
            source_vault_id,
            collection_id,
            collection_epoch,
            collection_membership_generation,
            recipient_identity_vault_id,
            recipient_device_id,
            recipient_hpke_key_id,
            sender_device_id,
            sender_signing_key_id,
            permissions,
            sender_membership_generation,
            created_sequence,
            encapsulated_key,
            wrapped_collection_key,
            sender_signature,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Encodes the fixed grant record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(Self::LEN);
        writer
            .u16(PROTOCOL_VERSION_V2)
            .u16(HPKE_SUITE_V2)
            .id(&self.grant_id)
            .id(&self.source_vault_id)
            .id(&self.collection_id)
            .u64(self.collection_epoch)
            .u64(self.collection_membership_generation)
            .id(&self.recipient_identity_vault_id)
            .id(&self.recipient_device_id)
            .fixed(&self.recipient_hpke_key_id)
            .id(&self.sender_device_id)
            .fixed(&self.sender_signing_key_id)
            .u8(self.permissions as u8)
            .u64(self.sender_membership_generation)
            .u64(self.created_sequence)
            .fixed(&self.encapsulated_key)
            .fixed(&self.wrapped_collection_key)
            .fixed(&self.sender_signature);
        writer.finish()
    }

    /// Decodes one fixed grant record.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V2,
            UnsupportedVersion,
            "collection grant version is not supported"
        );
        ensure!(
            reader.u16()? == HPKE_SUITE_V2,
            UnsupportedSuite,
            "collection grant HPKE profile is not supported"
        );
        let grant_id = reader.id()?;
        let source_vault_id = reader.id()?;
        let collection_id = reader.id()?;
        let collection_epoch = reader.u64()?;
        let collection_membership_generation = reader.u64()?;
        let recipient_identity_vault_id = reader.id()?;
        let recipient_device_id = reader.id()?;
        let recipient_hpke_key_id = reader.fixed::<KEY_ID_LEN>()?;
        let sender_device_id = reader.id()?;
        let sender_signing_key_id = reader.fixed::<KEY_ID_LEN>()?;
        let permissions = PermissionProfile::decode(reader.u8()?)?;
        let sender_membership_generation = reader.u64()?;
        let created_sequence = reader.u64()?;
        let encapsulated_key = reader.fixed::<ENCAPSULATED_KEY_LEN>()?;
        let wrapped_collection_key = reader.fixed::<WRAPPED_COLLECTION_KEY_LEN>()?;
        let sender_signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;
        Self::from_fields(
            grant_id,
            source_vault_id,
            collection_id,
            collection_epoch,
            collection_membership_generation,
            recipient_identity_vault_id,
            recipient_device_id,
            recipient_hpke_key_id,
            sender_device_id,
            sender_signing_key_id,
            permissions,
            sender_membership_generation,
            created_sequence,
            encapsulated_key,
            wrapped_collection_key,
            sender_signature,
        )
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.source_vault_id != self.recipient_identity_vault_id,
            InvalidInput,
            "collection grant recipient belongs to the source vault"
        );
        validate_counter(self.collection_epoch, "collection epoch")?;
        validate_counter(
            self.collection_membership_generation,
            "collection membership generation",
        )?;
        validate_counter(
            self.sender_membership_generation,
            "sender membership generation",
        )?;
        validate_counter(self.created_sequence, "grant creation sequence")?;
        ensure!(
            self.recipient_hpke_key_id != [0; KEY_ID_LEN]
                && self.sender_signing_key_id != [0; KEY_ID_LEN]
                && self.encapsulated_key != [0; ENCAPSULATED_KEY_LEN],
            InvalidInput,
            "collection grant key identifier or encapsulation is zero"
        );
        validate_encapsulation(&self.encapsulated_key)
    }

    fn context_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(165);
        writer
            .u16(PROTOCOL_VERSION_V2)
            .u16(HPKE_SUITE_V2)
            .id(&self.grant_id)
            .id(&self.source_vault_id)
            .id(&self.collection_id)
            .u64(self.collection_epoch)
            .u64(self.collection_membership_generation)
            .id(&self.recipient_identity_vault_id)
            .id(&self.recipient_device_id)
            .fixed(&self.recipient_hpke_key_id)
            .id(&self.sender_device_id)
            .fixed(&self.sender_signing_key_id)
            .u8(self.permissions as u8)
            .u64(self.sender_membership_generation)
            .u64(self.created_sequence);
        writer.finish()
    }

    fn signature_input(&self) -> Vec<u8> {
        let mut input =
            Vec::with_capacity(tag::SHARING_COLLECTION_GRANT.len() + Self::LEN - SIGNATURE_LEN);
        input.extend_from_slice(tag::SHARING_COLLECTION_GRANT);
        input.extend_from_slice(&self.encode()[..Self::LEN - SIGNATURE_LEN]);
        input
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen grant fields"
    )]
    fn unsigned(
        grant_id: Id,
        source_vault_id: Id,
        collection_id: Id,
        collection_epoch: u64,
        collection_membership_generation: u64,
        recipient_identity_vault_id: Id,
        recipient_device_id: Id,
        sender_device_id: Id,
        permissions: PermissionProfile,
        sender_membership_generation: u64,
        created_sequence: u64,
        recipient_hpke_public_key: &[u8; RECIPIENT_LEN],
        sender_signing_key: &DeviceSigningKey,
    ) -> Result<Self> {
        Self::from_fields(
            grant_id,
            source_vault_id,
            collection_id,
            collection_epoch,
            collection_membership_generation,
            recipient_identity_vault_id,
            recipient_device_id,
            hpke_key_id(
                &recipient_identity_vault_id,
                &recipient_device_id,
                recipient_hpke_public_key,
            ),
            sender_device_id,
            signing_key_id(
                &source_vault_id,
                &sender_device_id,
                &sender_signing_key.verifying_key(),
            ),
            permissions,
            sender_membership_generation,
            created_sequence,
            [1; ENCAPSULATED_KEY_LEN],
            [0; WRAPPED_COLLECTION_KEY_LEN],
            [0; SIGNATURE_LEN],
        )
    }

    fn finish_seal(
        mut self,
        encapsulated_key: &[u8],
        wrapped_collection_key: &[u8],
        sender_signing_key: &DeviceSigningKey,
    ) -> Result<Self> {
        self.encapsulated_key = encapsulated_key.try_into().map_err(|_| {
            Error::new(
                ChurStatus::InternalFailure,
                "collection grant encapsulation has the wrong size",
            )
        })?;
        self.wrapped_collection_key = wrapped_collection_key.try_into().map_err(|_| {
            Error::new(
                ChurStatus::InternalFailure,
                "wrapped collection key is not 48 bytes",
            )
        })?;
        self.sender_signature = sender_signing_key.sign_bytes(&self.signature_input());
        self.validate()?;
        Ok(self)
    }
}

fn recipient_public_key(bytes: &[u8; RECIPIENT_LEN]) -> Result<<XWing as KemTrait>::PublicKey> {
    validate_recipient(bytes)?;
    <XWing as KemTrait>::PublicKey::from_bytes(bytes).map_err(|_| {
        Error::new(
            ChurStatus::InvalidInput,
            "recipient HPKE public key is invalid",
        )
    })
}

#[cfg(any(test, feature = "test-vectors"))]
pub(crate) struct FixedTestRng {
    bytes: [u8; 64],
    offset: usize,
}

#[cfg(any(test, feature = "test-vectors"))]
impl FixedTestRng {
    pub(crate) const fn new(bytes: [u8; 64]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.bytes[self.offset % self.bytes.len()];
            self.offset += 1;
        }
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl hpke::rand_core::TryRng for FixedTestRng {
    type Error = hpke::rand_core::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl hpke::rand_core::TryCryptoRng for FixedTestRng {}

fn grant_info(context: &[u8]) -> Vec<u8> {
    [tag::SHARING_GRANT_HPKE_INFO, context].concat()
}

fn grant_aad(context: &[u8]) -> Vec<u8> {
    [tag::SHARING_GRANT_HPKE_AAD, context].concat()
}

fn validate_counter(value: u64, name: &'static str) -> Result<()> {
    if value == 0 || value == u64::MAX {
        return Err(Error::new(ChurStatus::InvalidInput, name));
    }
    Ok(())
}

/// Derives the v2 identifier of one ML-DSA-65 public key.
#[must_use]
pub fn signing_key_id(
    identity_vault_id: &Id,
    device_id: &Id,
    public_key: &[u8; VERIFY_LEN],
) -> [u8; KEY_ID_LEN] {
    key_id(
        tag::IDENTITY_SIGNING_KEY_ID,
        SIGNING_SUITE_V2,
        identity_vault_id,
        device_id,
        public_key,
    )
}

/// Derives the v2 identifier of one hybrid HPKE public key.
#[must_use]
pub fn hpke_key_id(
    identity_vault_id: &Id,
    device_id: &Id,
    public_key: &[u8; RECIPIENT_LEN],
) -> [u8; KEY_ID_LEN] {
    key_id(
        tag::IDENTITY_HPKE_KEY_ID,
        HPKE_SUITE_V2,
        identity_vault_id,
        device_id,
        public_key,
    )
}

fn key_id(
    domain: &[u8],
    suite: u16,
    identity_vault_id: &Id,
    device_id: &Id,
    public_key: &[u8],
) -> [u8; KEY_ID_LEN] {
    let commitment = commit(
        domain,
        &[
            identity_vault_id.as_bytes(),
            device_id.as_bytes(),
            &suite.to_be_bytes(),
            public_key,
        ],
    );
    let mut id = [0; KEY_ID_LEN];
    id.copy_from_slice(&commitment[..KEY_ID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    #[test]
    fn hybrid_hpke_matches_draft_05_appendix_a5() {
        use chur_crypto::post_quantum::recipient_public;
        use hpke::{aead::Aead, kdf::Kdf};

        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/internal-pq/hpke-pq-05-a5.json"
        ))
        .unwrap();
        let bytes = |field: &serde_json::Value| hex::decode(field.as_str().unwrap()).unwrap();
        assert_eq!(vector["mode"], 0);
        assert_eq!(vector["kem_id"], XWing::KEM_ID);
        assert_eq!(vector["kdf_id"], HkdfSha256::KDF_ID);
        assert_eq!(vector["aead_id"], ChaCha20Poly1305::AEAD_ID);

        let (sk, pk) = XWing::derive_keypair(&bytes(&vector["ikmR"]));
        let seed = Key::new(bytes(&vector["skRm"]).try_into().unwrap());
        let public = bytes(&vector["pkRm"]).try_into().unwrap();
        assert_eq!(sk.to_bytes().as_slice(), seed.expose());
        assert_eq!(pk.to_bytes().as_slice(), &public);
        assert_eq!(recipient_public(&seed).unwrap(), public);
        let recipient = recipient_public_key(&public).unwrap();

        let info = bytes(&vector["info"]);
        let mut rng = FixedTestRng::new(bytes(&vector["ikmE"]).try_into().unwrap());
        let (enc, mut sender) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &recipient,
            &info,
            &mut rng,
        )
        .unwrap();
        let expected_enc = bytes(&vector["enc"]).try_into().unwrap();
        validate_encapsulation(&expected_enc).unwrap();
        assert_eq!(enc.to_bytes().as_slice(), &expected_enc);
        let secret = XWing::decap(&sk, None, &enc).unwrap();
        assert_eq!(secret.0.as_slice(), bytes(&vector["shared_secret"]));
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &sk,
            &enc,
            &info,
        )
        .unwrap();

        for record in vector["encryptions"].as_array().unwrap() {
            let (pt, aad, ct) = (
                bytes(&record["pt"]),
                bytes(&record["aad"]),
                bytes(&record["ct"]),
            );
            assert_eq!(sender.seal(&pt, &aad).unwrap(), ct);
            assert_eq!(receiver.open(&ct, &aad).unwrap(), pt);
        }
        for export in vector["exports"].as_array().unwrap() {
            let context = bytes(&export["exporter_context"]);
            let expected = bytes(&export["exported_value"]);
            let mut output = vec![0; export["L"].as_u64().unwrap().try_into().unwrap()];
            sender.export(&context, &mut output).unwrap();
            assert_eq!(output, expected);
            output.fill(0);
            receiver.export(&context, &mut output).unwrap();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn key_purpose_separates_identical_public_bytes() {
        let vault_id = Id::new([1; 16]).expect("vault");
        let device_id = Id::new([2; 16]).expect("device");
        let public_key = [3; 32];

        assert_ne!(
            key_id(
                tag::IDENTITY_SIGNING_KEY_ID,
                SIGNING_SUITE_V2,
                &vault_id,
                &device_id,
                &public_key
            ),
            key_id(
                tag::IDENTITY_HPKE_KEY_ID,
                HPKE_SUITE_V2,
                &vault_id,
                &device_id,
                &public_key
            )
        );
    }

    #[test]
    fn permission_profiles_fail_closed_for_partial_bit_sets() {
        assert!(PermissionProfile::decode(0x02).is_err());
    }

    #[test]
    fn a_collection_grant_has_one_fixed_canonical_round_trip() {
        let grant = CollectionGrant::from_fields(
            Id::new([1; 16]).expect("grant"),
            Id::new([2; 16]).expect("source vault"),
            Id::new([3; 16]).expect("collection"),
            4,
            5,
            Id::new([6; 16]).expect("recipient vault"),
            Id::new([7; 16]).expect("recipient device"),
            [8; 16],
            Id::new([9; 16]).expect("sender device"),
            [10; 16],
            PermissionProfile::Contribute,
            11,
            12,
            [13; ENCAPSULATED_KEY_LEN],
            [14; 48],
            [15; SIGNATURE_LEN],
        )
        .expect("grant fields");

        let encoded = grant.encode();
        assert_eq!(encoded.len(), CollectionGrant::LEN);
        assert!(CollectionGrant::decode(&encoded).is_ok_and(|decoded| decoded == grant));
    }

    #[test]
    fn the_bound_recipient_opens_the_signed_collection_key() {
        let source_vault_id = Id::new([1; 16]).expect("source vault");
        let recipient_vault_id = Id::new([2; 16]).expect("recipient vault");
        let recipient_device_id = Id::new([3; 16]).expect("recipient device");
        let recipient = DeviceIdentity::from_seeds([4; 32], [5; 32]);
        let sender = DeviceSigningKey::from_seed([6; 32]);
        let collection_key = Key::new([7; 32]);
        let grant = CollectionGrant::seal(
            Id::new([8; 16]).expect("grant"),
            source_vault_id,
            Id::new([9; 16]).expect("collection"),
            1,
            1,
            recipient_vault_id,
            recipient_device_id,
            &recipient.hpke_public_key(),
            Id::new([10; 16]).expect("sender device"),
            PermissionProfile::Read,
            1,
            1,
            &collection_key,
            &sender,
        )
        .expect("seal grant");

        let opened = grant
            .open_collection_key(
                &recipient_vault_id,
                &recipient_device_id,
                &recipient,
                &sender.verifying_key(),
            )
            .expect("open grant");
        assert!(opened == collection_key);
    }

    #[test]
    fn modified_or_substituted_grant_material_fails_closed() {
        let source_vault_id = Id::new([1; 16]).expect("source vault");
        let recipient_vault_id = Id::new([2; 16]).expect("recipient vault");
        let recipient_device_id = Id::new([3; 16]).expect("recipient device");
        let recipient = DeviceIdentity::from_seeds([4; 32], [5; 32]);
        let sender = DeviceSigningKey::from_seed([6; 32]);
        let grant = CollectionGrant::seal(
            Id::new([8; 16]).expect("grant"),
            source_vault_id,
            Id::new([9; 16]).expect("collection"),
            1,
            1,
            recipient_vault_id,
            recipient_device_id,
            &recipient.hpke_public_key(),
            Id::new([10; 16]).expect("sender device"),
            PermissionProfile::Read,
            1,
            1,
            &Key::new([7; 32]),
            &sender,
        )
        .expect("seal grant");

        let ciphertext = 165 + ENCAPSULATED_KEY_LEN;
        let signature = ciphertext + WRAPPED_COLLECTION_KEY_LEN;
        let mut noncontributory = grant.encode();
        noncontributory[ciphertext - 32..ciphertext].fill(0);
        assert!(CollectionGrant::decode(&noncontributory).is_err());
        for offset in [148, 165, ciphertext - 32, ciphertext, signature] {
            let mut modified = grant.encode();
            modified[offset] ^= if offset == 148 { 0x02 } else { 0x01 };
            let modified = CollectionGrant::decode(&modified).expect("canonical grant");
            assert!(
                modified
                    .open_collection_key(
                        &recipient_vault_id,
                        &recipient_device_id,
                        &recipient,
                        &sender.verifying_key(),
                    )
                    .is_err()
            );
        }

        let substitute = DeviceIdentity::from_seeds([11; 32], [12; 32]);
        assert!(
            grant
                .open_collection_key(
                    &recipient_vault_id,
                    &recipient_device_id,
                    &substitute,
                    &sender.verifying_key(),
                )
                .is_err()
        );
        assert!(
            grant
                .open_collection_key(
                    &recipient_vault_id,
                    &recipient_device_id,
                    &recipient,
                    &DeviceSigningKey::from_seed([13; 32]).verifying_key(),
                )
                .is_err()
        );
    }

    #[cfg(feature = "test-vectors")]
    #[test]
    fn fixed_ephemeral_input_produces_one_repeatable_grant() {
        let recipient = DeviceIdentity::from_seeds([1; 32], [2; 32]);
        let sender = DeviceSigningKey::from_seed([3; 32]);
        let seal = || {
            CollectionGrant::seal_for_test_vector(
                Id::new([4; 16]).expect("grant"),
                Id::new([5; 16]).expect("source"),
                Id::new([6; 16]).expect("collection"),
                1,
                1,
                Id::new([7; 16]).expect("recipient vault"),
                Id::new([8; 16]).expect("recipient device"),
                &recipient.hpke_public_key(),
                Id::new([9; 16]).expect("sender device"),
                PermissionProfile::Read,
                1,
                1,
                &Key::new([10; 32]),
                &sender,
                [11; 64],
            )
            .expect("grant")
            .encode()
        };

        assert_eq!(seal(), seal());
    }
}
