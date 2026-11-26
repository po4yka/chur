//! Object-key delivery through single-use recipient keys.
//!
//! Collection logs protect metadata without retaining content keys. No durable operation contains an
//! object-key envelope. A device destroys the private prekey after it accepts
//! a grant, and deletion also destroys unused prekeys that a server could have
//! used for a withheld grant.

use crate::operation::{DeviceSigningKey, PROTOCOL_VERSION_V2, verify_device_signature};
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::post_quantum::{
    self, ENCAP_LEN, ENVELOPE_LEN, RECIPIENT_LEN, SIGNATURE_LEN, VERIFY_LEN,
};
use chur_crypto::{Key, commit::commit, tuple::tag};
use chur_format::codec::{Reader, Writer};

/// Maximum public requests returned in one transport page.
pub const PREKEYS_MAX: usize = 64;

/// A device signature binds one disposable public key to a collection.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectPrekey {
    prekey_id: Id,
    collection_id: Id,
    object_id: Id,
    object_generation: u64,
    container_commitment: [u8; 32],
    recipient_vault_id: Id,
    recipient_device_id: Id,
    generation: u64,
    public_key: [u8; RECIPIENT_LEN],
    signature: [u8; SIGNATURE_LEN],
}

impl ObjectPrekey {
    /// Exact encoded record length.
    pub const LEN: usize = 130 + RECIPIENT_LEN + SIGNATURE_LEN;

    /// Signs a fresh prekey. Its private bytes must stay outside signed logs.
    #[expect(
        clippy::too_many_arguments,
        reason = "the request binds the recipient and exact committed object"
    )]
    pub fn sign(
        prekey_id: Id,
        collection_id: Id,
        object_id: Id,
        object_generation: u64,
        container_commitment: [u8; 32],
        recipient_vault_id: Id,
        recipient_device_id: Id,
        generation: u64,
        private_key: &Key,
        signing_key: &DeviceSigningKey,
    ) -> Result<Self> {
        ensure!(
            generation != 0
                && generation != u64::MAX
                && object_generation != 0
                && object_generation != u64::MAX
                && container_commitment != [0; 32],
            InvalidInput,
            "prekey generation is zero"
        );
        let public_key = post_quantum::recipient_public(private_key)?;
        let mut record = Self {
            prekey_id,
            collection_id,
            object_id,
            object_generation,
            container_commitment,
            recipient_vault_id,
            recipient_device_id,
            generation,
            public_key,
            signature: [0; SIGNATURE_LEN],
        };
        record.signature = signing_key.sign_bytes(&record.signature_input());
        Ok(record)
    }

    /// Authenticates the prekey against its enrolled device signing key.
    pub fn verify(&self, signing_public_key: &[u8; VERIFY_LEN]) -> Result<()> {
        verify_device_signature(signing_public_key, &self.signature, &self.signature_input())?;
        post_quantum::validate_recipient(&self.public_key)
    }

    /// Stable prekey identifier.
    #[must_use]
    pub const fn prekey_id(&self) -> &Id {
        &self.prekey_id
    }
    /// Collection in which the key can be used.
    #[must_use]
    pub const fn collection_id(&self) -> &Id {
        &self.collection_id
    }
    /// Exact requested object.
    #[must_use]
    pub const fn object_id(&self) -> &Id {
        &self.object_id
    }
    /// Exact signed object generation.
    #[must_use]
    pub const fn object_generation(&self) -> u64 {
        self.object_generation
    }
    /// Exact signed container commitment.
    #[must_use]
    pub const fn container_commitment(&self) -> &[u8; 32] {
        &self.container_commitment
    }
    /// Addressed recipient vault.
    #[must_use]
    pub const fn recipient_vault_id(&self) -> &Id {
        &self.recipient_vault_id
    }
    /// Addressed recipient device.
    #[must_use]
    pub const fn recipient_device_id(&self) -> &Id {
        &self.recipient_device_id
    }
    /// Monotonic replacement generation for the local pool.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn fields(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u16(PROTOCOL_VERSION_V2)
            .id(&self.prekey_id)
            .id(&self.collection_id)
            .id(&self.object_id)
            .u64(self.object_generation)
            .fixed(&self.container_commitment)
            .id(&self.recipient_vault_id)
            .id(&self.recipient_device_id)
            .u64(self.generation)
            .fixed(&self.public_key);
        writer.finish()
    }

    fn signature_input(&self) -> Vec<u8> {
        tagged(tag::OBJECT_PREKEY_SIGNATURE, &self.fields())
    }

    /// Writes the canonical signed public record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.fields();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Reads one bounded public record.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::LEN,
            NonCanonicalEncoding,
            "object prekey length is invalid"
        );
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V2,
            UnsupportedVersion,
            "object prekey version is unsupported"
        );
        let record = Self {
            prekey_id: reader.id()?,
            collection_id: reader.id()?,
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            container_commitment: reader.fixed()?,
            recipient_vault_id: reader.id()?,
            recipient_device_id: reader.id()?,
            generation: reader.u64()?,
            public_key: reader.fixed()?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        ensure!(
            record.generation != 0
                && record.generation != u64::MAX
                && record.object_generation != 0
                && record.object_generation != u64::MAX
                && record.container_commitment != [0; 32],
            NonCanonicalEncoding,
            "object prekey generation is zero"
        );
        ensure!(
            post_quantum::validate_recipient(&record.public_key).is_ok(),
            NonCanonicalEncoding,
            "object prekey public key is invalid"
        );
        Ok(record)
    }
}

/// A signed HPKE object-key grant to one disposable recipient prekey.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectKeyGrant {
    grant_id: Id,
    collection_id: Id,
    object_id: Id,
    source_vault_id: Id,
    source_device_id: Id,
    recipient_vault_id: Id,
    recipient_device_id: Id,
    prekey_id: Id,
    object_generation: u64,
    container_commitment: [u8; 32],
    object_key_commitment: [u8; 32],
    envelope: [u8; ENVELOPE_LEN],
    signature: [u8; SIGNATURE_LEN],
}

impl ObjectKeyGrant {
    /// Exact encoded length.
    pub const LEN: usize = 202 + ENVELOPE_LEN + SIGNATURE_LEN;

    /// Wraps an object key without using a stable device HPKE secret.
    #[expect(
        clippy::too_many_arguments,
        reason = "the grant binds source, object, container and recipient"
    )]
    pub fn seal(
        grant_id: Id,
        source_vault_id: Id,
        source_device_id: Id,
        object_id: Id,
        object_generation: u64,
        container_commitment: [u8; 32],
        prekey: &ObjectPrekey,
        object_key: &Key,
        signing_key: &DeviceSigningKey,
    ) -> Result<Self> {
        let mut grant = Self::prepare(
            grant_id,
            source_vault_id,
            source_device_id,
            object_id,
            object_generation,
            container_commitment,
            prekey,
            object_key,
        )?;
        let context = tagged(tag::OBJECT_KEY_GRANT_HPKE, &grant.context());
        grant.envelope =
            post_quantum::seal_key(&prekey.public_key, &context, &context, object_key)?;
        grant.signature = signing_key.sign_bytes(&grant.signature_input());
        Ok(grant)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the grant binds source, object, container and recipient"
    )]
    fn prepare(
        grant_id: Id,
        source_vault_id: Id,
        source_device_id: Id,
        object_id: Id,
        object_generation: u64,
        container_commitment: [u8; 32],
        prekey: &ObjectPrekey,
        object_key: &Key,
    ) -> Result<Self> {
        ensure!(
            object_generation != 0
                && object_generation != u64::MAX
                && object_id == *prekey.object_id()
                && object_generation == prekey.object_generation()
                && container_commitment == *prekey.container_commitment(),
            AuthenticationFailed,
            "object grant does not match its request"
        );
        Ok(Self {
            grant_id,
            collection_id: *prekey.collection_id(),
            object_id,
            source_vault_id,
            source_device_id,
            recipient_vault_id: *prekey.recipient_vault_id(),
            recipient_device_id: *prekey.recipient_device_id(),
            prekey_id: *prekey.prekey_id(),
            object_generation,
            container_commitment,
            object_key_commitment: object_key_commitment(
                prekey.collection_id(),
                &object_id,
                object_key,
            ),
            envelope: [0; ENVELOPE_LEN],
            signature: [0; SIGNATURE_LEN],
        })
    }

    /// Builds reproducible HPKE bytes for the published interoperability vectors.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the frozen grant inputs plus test-only ephemeral randomness"
    )]
    pub fn seal_for_test_vector(
        grant_id: Id,
        source_vault_id: Id,
        source_device_id: Id,
        object_id: Id,
        object_generation: u64,
        container_commitment: [u8; 32],
        prekey: &ObjectPrekey,
        object_key: &Key,
        signing_key: &DeviceSigningKey,
        ephemeral: [u8; 64],
    ) -> Result<Self> {
        let mut grant = Self::prepare(
            grant_id,
            source_vault_id,
            source_device_id,
            object_id,
            object_generation,
            container_commitment,
            prekey,
            object_key,
        )?;
        use hpke::aead::ChaCha20Poly1305;
        use hpke::kdf::HkdfSha256;
        use hpke::kem::XWing;
        use hpke::{Deserializable, Kem, OpModeS, Serializable};
        post_quantum::validate_recipient(&prekey.public_key)?;
        let recipient =
            <XWing as Kem>::PublicKey::from_bytes(&prekey.public_key).map_err(|_| {
                Error::new(ChurStatus::AuthenticationFailed, "object prekey is invalid")
            })?;
        let context = tagged(tag::OBJECT_KEY_GRANT_HPKE, &grant.context());
        let mut rng = crate::grant::FixedTestRng::new(ephemeral);
        let (encapsulation, ciphertext) =
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeS::Base,
                &recipient,
                &context,
                object_key.expose(),
                &context,
                &mut rng,
            )
            .map_err(|_| {
                Error::new(
                    ChurStatus::InternalFailure,
                    "test object grant sealing failed",
                )
            })?;
        encapsulation.write_exact(&mut grant.envelope[..ENCAP_LEN]);
        grant.envelope[ENCAP_LEN..].copy_from_slice(&ciphertext);
        grant.signature = signing_key.sign_bytes(&grant.signature_input());
        Ok(grant)
    }

    /// Authenticates the immutable sender and recipient bindings.
    pub fn verify(&self, signing_public_key: &[u8; VERIFY_LEN]) -> Result<()> {
        verify_device_signature(signing_public_key, &self.signature, &self.signature_input())
    }

    /// Opens with the disposable prekey only. A stable identity cannot open it.
    pub fn open(
        &self,
        prekey: &ObjectPrekey,
        private_key: &Key,
        signing_public_key: &[u8; VERIFY_LEN],
    ) -> Result<Key> {
        self.verify(signing_public_key)?;
        ensure!(
            self.prekey_id == *prekey.prekey_id()
                && self.collection_id == *prekey.collection_id()
                && self.object_id == *prekey.object_id()
                && self.object_generation == prekey.object_generation()
                && self.container_commitment == *prekey.container_commitment()
                && self.recipient_vault_id == *prekey.recipient_vault_id()
                && self.recipient_device_id == *prekey.recipient_device_id()
                && post_quantum::recipient_public(private_key)? == prekey.public_key,
            AuthenticationFailed,
            "object grant prekey binding is invalid"
        );
        let context = tagged(tag::OBJECT_KEY_GRANT_HPKE, &self.context());
        let key = post_quantum::open_key(private_key, &context, &context, &self.envelope)?;
        ensure!(
            object_key_commitment(&self.collection_id, &self.object_id, &key)
                == self.object_key_commitment,
            AuthenticationFailed,
            "object grant key commitment is invalid"
        );
        Ok(key)
    }

    /// Grant identity.
    #[must_use]
    pub const fn grant_id(&self) -> &Id {
        &self.grant_id
    }
    /// Shared collection.
    #[must_use]
    pub const fn collection_id(&self) -> &Id {
        &self.collection_id
    }
    /// Source object.
    #[must_use]
    pub const fn object_id(&self) -> &Id {
        &self.object_id
    }
    /// Source vault.
    #[must_use]
    pub const fn source_vault_id(&self) -> &Id {
        &self.source_vault_id
    }
    /// Source signing device.
    #[must_use]
    pub const fn source_device_id(&self) -> &Id {
        &self.source_device_id
    }
    /// Recipient vault.
    #[must_use]
    pub const fn recipient_vault_id(&self) -> &Id {
        &self.recipient_vault_id
    }
    /// Recipient device.
    #[must_use]
    pub const fn recipient_device_id(&self) -> &Id {
        &self.recipient_device_id
    }
    /// Disposable key identity.
    #[must_use]
    pub const fn prekey_id(&self) -> &Id {
        &self.prekey_id
    }
    /// Committed source generation.
    #[must_use]
    pub const fn object_generation(&self) -> u64 {
        self.object_generation
    }
    /// Signed source container commitment.
    #[must_use]
    pub const fn container_commitment(&self) -> &[u8; 32] {
        &self.container_commitment
    }
    /// Commitment to the delivered object key.
    #[must_use]
    pub const fn object_key_commitment(&self) -> &[u8; 32] {
        &self.object_key_commitment
    }

    fn context(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u16(PROTOCOL_VERSION_V2)
            .id(&self.grant_id)
            .id(&self.collection_id)
            .id(&self.object_id)
            .id(&self.source_vault_id)
            .id(&self.source_device_id)
            .id(&self.recipient_vault_id)
            .id(&self.recipient_device_id)
            .id(&self.prekey_id)
            .u64(self.object_generation)
            .fixed(&self.container_commitment)
            .fixed(&self.object_key_commitment);
        writer.finish()
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut bytes = self.context();
        bytes.extend_from_slice(&self.envelope);
        bytes
    }
    fn signature_input(&self) -> Vec<u8> {
        tagged(tag::OBJECT_KEY_GRANT_SIGNATURE, &self.unsigned())
    }
    /// Canonical signed bytes; no private prekey is included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.unsigned();
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Parses one bounded grant.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::LEN,
            NonCanonicalEncoding,
            "object grant length is invalid"
        );
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V2,
            UnsupportedVersion,
            "object grant version is unsupported"
        );
        let record = Self {
            grant_id: reader.id()?,
            collection_id: reader.id()?,
            object_id: reader.id()?,
            source_vault_id: reader.id()?,
            source_device_id: reader.id()?,
            recipient_vault_id: reader.id()?,
            recipient_device_id: reader.id()?,
            prekey_id: reader.id()?,
            object_generation: reader.u64()?,
            container_commitment: reader.fixed()?,
            object_key_commitment: reader.fixed()?,
            envelope: reader.fixed()?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        let enc = record.envelope.first_chunk::<ENCAP_LEN>().ok_or_else(|| {
            Error::new(
                ChurStatus::NonCanonicalEncoding,
                "object grant encapsulation is incomplete",
            )
        })?;
        ensure!(
            post_quantum::validate_encapsulation(enc).is_ok(),
            NonCanonicalEncoding,
            "object grant encapsulation is invalid"
        );
        ensure!(
            record.object_generation != 0
                && record.object_generation != u64::MAX
                && record.container_commitment != [0; 32]
                && record.object_key_commitment != [0; 32],
            NonCanonicalEncoding,
            "object generation is zero"
        );
        Ok(record)
    }
}

/// Signed key-free commitment carried by object operations.
#[must_use]
pub fn object_key_commitment(collection_id: &Id, object_id: &Id, key: &Key) -> [u8; 32] {
    commit(
        tag::OBJECT_KEY_COMMITMENT,
        &[collection_id.as_bytes(), object_id.as_bytes(), key.expose()],
    )
}

fn tagged(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut tagged = domain.to_vec();
    tagged.extend_from_slice(bytes);
    tagged
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }
    #[test]
    fn signed_noncontributory_prekeys_are_rejected_before_hpke_sealing() {
        let recipient = DeviceSigningKey::from_seed([41; 32]);
        let source = DeviceSigningKey::from_seed([42; 32]);
        let valid = ObjectPrekey::sign(
            id(1),
            id(2),
            id(3),
            1,
            [4; 32],
            id(5),
            id(6),
            1,
            &Key::new([43; 32]),
            &recipient,
        )
        .expect("valid request");
        let mut one = [0; 32];
        one[0] = 1;
        let mut high_bit_zero = [0; 32];
        high_bit_zero[31] = 0x80;
        let mut field_modulus = [0xff; 32];
        field_modulus[0] = 0xed;
        field_modulus[31] = 0x7f;
        let mut invalid_keys = [[0; 32], one, high_bit_zero, field_modulus]
            .map(|point| {
                let mut public_key = valid.public_key;
                public_key[RECIPIENT_LEN - 32..].copy_from_slice(&point);
                public_key
            })
            .to_vec();
        let mut invalid_mlkem = valid.public_key;
        invalid_mlkem[..3].fill(0xff);
        invalid_keys.push(invalid_mlkem);
        for public_key in invalid_keys {
            let mut invalid = valid.clone();
            invalid.public_key = public_key;
            invalid.signature = recipient.sign_bytes(&invalid.signature_input());
            verify_device_signature(
                &recipient.verifying_key(),
                &invalid.signature,
                &invalid.signature_input(),
            )
            .expect("request has a real authorized device signature");
            assert_eq!(
                ObjectKeyGrant::seal(
                    id(7),
                    id(8),
                    id(9),
                    id(3),
                    1,
                    [4; 32],
                    &invalid,
                    &Key::new([44; 32]),
                    &source
                )
                .err()
                .map(|error| error.status()),
                Some(ChurStatus::AuthenticationFailed),
                "a signed invalid point is a refused request, never an internal failure"
            );
            assert_eq!(
                ObjectPrekey::decode(&invalid.encode())
                    .err()
                    .map(|error| error.status()),
                Some(ChurStatus::NonCanonicalEncoding)
            );
            assert_eq!(
                invalid
                    .verify(&recipient.verifying_key())
                    .err()
                    .map(|error| error.status()),
                Some(ChurStatus::AuthenticationFailed)
            );
        }
        valid
            .verify(&recipient.verifying_key())
            .expect("neighbor request remains valid");
        ObjectKeyGrant::seal(
            id(7),
            id(8),
            id(9),
            id(3),
            1,
            [4; 32],
            &valid,
            &Key::new([44; 32]),
            &source,
        )
        .expect("a valid later request can be answered");
    }

    #[test]
    fn object_grants_require_the_disposable_secret_after_round_trip() {
        let signer = DeviceSigningKey::from_seed([1; 32]);
        let recipient = DeviceSigningKey::from_seed([2; 32]);
        let private = Key::new([3; 32]);
        let prekey = ObjectPrekey::sign(
            id(4),
            id(5),
            id(12),
            1,
            [13; 32],
            id(6),
            id(7),
            1,
            &private,
            &recipient,
        )
        .expect("prekey");
        let decoded = ObjectPrekey::decode(&prekey.encode()).expect("decode prekey");
        decoded
            .verify(&recipient.verifying_key())
            .expect("signature");
        let key = Key::new([8; 32]);
        let grant = ObjectKeyGrant::seal(
            id(9),
            id(10),
            id(11),
            id(12),
            1,
            [13; 32],
            &prekey,
            &key,
            &signer,
        )
        .expect("grant");
        assert_eq!(prekey.encode().len(), 4655);
        assert_eq!(grant.encode().len(), 4679);
        for offset in [0, ENCAP_LEN - 32] {
            let mut altered = grant.clone();
            altered.envelope[offset] ^= 1;
            altered.signature = signer.sign_bytes(&altered.signature_input());
            assert!(
                altered
                    .open(&prekey, &private, &signer.verifying_key())
                    .is_err()
            );
        }
        let decoded = ObjectKeyGrant::decode(&grant.encode()).expect("decode grant");
        assert_eq!(
            decoded
                .open(&prekey, &private, &signer.verifying_key())
                .expect("open")
                .expose(),
            key.expose()
        );
        assert!(
            decoded
                .open(&prekey, &Key::new([14; 32]), &signer.verifying_key())
                .is_err()
        );
        assert!(
            decoded
                .open(&prekey, &private, &recipient.verifying_key())
                .is_err()
        );
        assert!(
            ObjectKeyGrant::seal(
                id(20),
                id(10),
                id(11),
                id(21),
                1,
                [13; 32],
                &prekey,
                &key,
                &signer
            )
            .is_err(),
            "one-use key cannot be reassigned to another object"
        );
        assert!(
            ObjectKeyGrant::seal(
                id(20),
                id(10),
                id(11),
                id(12),
                2,
                [13; 32],
                &prekey,
                &key,
                &signer
            )
            .is_err(),
            "request generation is authenticated"
        );
        assert!(
            ObjectKeyGrant::seal(
                id(20),
                id(10),
                id(11),
                id(12),
                1,
                [14; 32],
                &prekey,
                &key,
                &signer
            )
            .is_err(),
            "request binds ciphertext identity"
        );
        let mut modified_request = prekey.encode();
        modified_request[34] ^= 1;
        assert!(
            ObjectPrekey::decode(&modified_request)
                .expect("well-formed mutation")
                .verify(&recipient.verifying_key())
                .is_err()
        );
        let mut modified_grant = grant.encode();
        modified_grant[34] ^= 1;
        assert!(
            ObjectKeyGrant::decode(&modified_grant)
                .expect("well-formed mutation")
                .verify(&signer.verifying_key())
                .is_err()
        );
    }
}
