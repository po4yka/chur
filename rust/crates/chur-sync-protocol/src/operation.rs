//! The canonical outer sync operation of `docs/sync/OPERATION_LOG.md` §2.

use chur_core::limits::{COMMITMENT_LEN, ID_LEN, sync as bounds};
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::tuple::tag;
use chur_crypto::{Commitment, Key, Nonce, aead, commit};
use chur_format::codec::{Reader, Writer};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

const SIGNATURE_LEN: usize = 64;
const FIXED_FIELDS_LEN: usize = 2 + (ID_LEN * 4) + 8 + COMMITMENT_LEN + 4 + 4 + SIGNATURE_LEN;

/// Sync protocol v1.
pub const PROTOCOL_VERSION_V1: u16 = 0x0001;

/// One portable Ed25519 device signing key.
pub struct DeviceSigningKey(SigningKey);

impl DeviceSigningKey {
    /// Builds a signing key from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The public verification key carried by device membership.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub(crate) fn seed_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub(crate) fn sign_bytes(&self, bytes: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(bytes).to_bytes()
    }
}

pub(crate) fn verify_ed25519(
    verifying_key: &[u8; 32],
    signature: &[u8; SIGNATURE_LEN],
    bytes: &[u8],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(verifying_key).map_err(|_| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "device verification key is invalid",
        )
    })?;
    key.verify_strict(bytes, &Signature::from_bytes(signature))
        .map_err(|_| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "device signature did not verify",
            )
        })
}

/// One other device head observed by an operation's author.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedHead {
    device_id: Id,
    device_sequence: u64,
}

impl ObservedHead {
    /// Builds an observed head.
    #[must_use]
    pub const fn new(device_id: Id, device_sequence: u64) -> Self {
        Self {
            device_id,
            device_sequence,
        }
    }

    /// The device whose accepted sequence this entry names.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }

    /// The highest accepted sequence from that device.
    #[must_use]
    pub const fn device_sequence(&self) -> u64 {
        self.device_sequence
    }
}

/// One signed, encrypted sync operation.
#[derive(Clone, PartialEq, Eq)]
pub struct Operation {
    operation_id: Id,
    vault_id: Id,
    device_id: Id,
    device_sequence: u64,
    previous_operation_hash: [u8; 32],
    observed_heads: Vec<ObservedHead>,
    key_selector: Id,
    encrypted_payload: Vec<u8>,
    signature: [u8; 64],
}

impl Operation {
    /// Seals a private payload under the operation's cleartext routing fields.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields plus encryption inputs"
    )]
    pub fn seal(
        operation_id: Id,
        vault_id: Id,
        device_id: Id,
        device_sequence: u64,
        previous_operation_hash: [u8; 32],
        observed_heads: Vec<ObservedHead>,
        key_selector: Id,
        key: &Key,
        nonce: Nonce,
        plaintext: &[u8],
    ) -> Result<Self> {
        ensure!(
            plaintext.len() <= bounds::PAYLOAD_PLAINTEXT_MAX,
            ResourceLimitExceeded,
            "sync operation plaintext exceeds the protocol limit"
        );
        let mut operation = Self {
            operation_id,
            vault_id,
            device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        operation.validate_outer_fields()?;
        let sealed = aead::seal(key, &nonce, plaintext, &operation.aad())?;
        operation.encrypted_payload.reserve_exact(
            nonce
                .as_bytes()
                .len()
                .checked_add(sealed.len())
                .ok_or_else(|| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "sync encrypted payload length overflows the address space",
                    )
                })?,
        );
        operation
            .encrypted_payload
            .extend_from_slice(nonce.as_bytes());
        operation.encrypted_payload.extend_from_slice(&sealed);
        operation.validate()?;
        Ok(operation)
    }

    /// Builds an operation. Validation is shared with [`Self::decode`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields"
    )]
    pub fn new(
        operation_id: Id,
        vault_id: Id,
        device_id: Id,
        device_sequence: u64,
        previous_operation_hash: [u8; 32],
        observed_heads: Vec<ObservedHead>,
        key_selector: Id,
        encrypted_payload: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<Self> {
        let operation = Self {
            operation_id,
            vault_id,
            device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload,
            signature,
        };
        operation.validate()?;
        Ok(operation)
    }

    /// Encodes the canonical wire record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(
            FIXED_FIELDS_LEN
                + (self.observed_heads.len() * bounds::OBSERVED_HEAD_LEN)
                + self.encrypted_payload.len(),
        );
        self.write_outer_fields(&mut writer);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "validate bounds encrypted_payload below u32::MAX"
        )]
        writer
            .u32(self.encrypted_payload.len() as u32)
            .fixed(&self.encrypted_payload)
            .fixed(&self.signature);
        writer.finish()
    }

    /// Replaces the signature with one made by `key` over the frozen input.
    #[must_use]
    pub fn sign(mut self, key: &DeviceSigningKey) -> Self {
        self.signature = key.sign_bytes(&self.signing_bytes());
        self
    }

    /// Verifies the operation against one enrolled device key.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::AuthenticationFailed`] for any invalid key or
    /// signature.
    pub fn verify_signature(&self, verifying_key: &[u8; 32]) -> Result<()> {
        verify_ed25519(verifying_key, &self.signature, &self.signing_bytes())
    }

    /// Opens and authenticates the private payload.
    pub fn open_payload(&self, key: &Key) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let (nonce, sealed) = self
            .encrypted_payload
            .split_at(chur_core::limits::NONCE_LEN);
        aead::open(key, &Nonce::from_slice(nonce)?, sealed, &self.aad())
    }

    /// The hash-chain digest of the complete signed wire record.
    #[must_use]
    pub fn digest(&self) -> Commitment {
        commit::commit(tag::SYNC_OPERATION_CHAIN, &[&self.encode()])
    }

    /// Stable idempotency identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &Id {
        &self.operation_id
    }
    /// Vault whose log carries this operation.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }
    /// Authoring device.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }
    /// Per-device sequence.
    #[must_use]
    pub const fn device_sequence(&self) -> u64 {
        self.device_sequence
    }
    /// Digest of the preceding device operation, or zero at genesis.
    #[must_use]
    pub const fn previous_operation_hash(&self) -> &Commitment {
        &self.previous_operation_hash
    }
    /// Other-device causal heads observed by the author.
    #[must_use]
    pub fn observed_heads(&self) -> &[ObservedHead] {
        &self.observed_heads
    }
    /// Opaque payload-key selector.
    #[must_use]
    pub const fn key_selector(&self) -> &Id {
        &self.key_selector
    }

    fn aad(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(
            tag::SYNC_OPERATION.len()
                + FIXED_FIELDS_LEN
                + (self.observed_heads.len() * bounds::OBSERVED_HEAD_LEN),
        );
        writer.fixed(tag::SYNC_OPERATION);
        self.write_outer_fields(&mut writer);
        writer.finish()
    }

    fn write_outer_fields(&self, writer: &mut Writer) {
        writer
            .u16(PROTOCOL_VERSION_V1)
            .id(&self.operation_id)
            .id(&self.vault_id)
            .id(&self.device_id)
            .u64(self.device_sequence)
            .fixed(&self.previous_operation_hash);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "validate bounds observed_heads at 31 entries"
        )]
        writer.u32(self.observed_heads.len() as u32);
        for head in &self.observed_heads {
            writer.id(&head.device_id).u64(head.device_sequence);
        }
        writer.id(&self.key_selector);
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut wire = self.encode();
        wire.truncate(wire.len() - SIGNATURE_LEN);
        let mut bytes = Vec::with_capacity(tag::SYNC_OPERATION.len() + wire.len());
        bytes.extend_from_slice(tag::SYNC_OPERATION);
        bytes.extend_from_slice(&wire);
        bytes
    }

    /// Decodes one canonical wire record.
    ///
    /// # Errors
    ///
    /// Returns a structural or bounds error for malformed input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "sync operation protocol version is not supported"
        );
        let operation_id = reader.id()?;
        let vault_id = reader.id()?;
        let device_id = reader.id()?;
        let device_sequence = reader.u64()?;
        let previous_operation_hash = reader.fixed::<COMMITMENT_LEN>()?;
        let head_count = usize::try_from(reader.u32()?).map_err(|_| {
            chur_core::Error::new(
                ChurStatus::ResourceLimitExceeded,
                "observed head count does not fit this platform",
            )
        })?;
        ensure!(
            head_count <= bounds::OBSERVED_HEADS_MAX,
            ResourceLimitExceeded,
            "observed head count exceeds the protocol limit"
        );
        let mut observed_heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            observed_heads.push(ObservedHead::new(reader.id()?, reader.u64()?));
        }
        let key_selector = reader.id()?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the protocol maximum is below u32::MAX"
        )]
        let encrypted_payload = reader
            .variable(bounds::ENCRYPTED_PAYLOAD_MAX as u32)?
            .to_vec();
        let signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;
        Self::new(
            operation_id,
            vault_id,
            device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload,
            signature,
        )
    }

    fn validate(&self) -> Result<()> {
        self.validate_outer_fields()?;
        ensure!(
            self.encrypted_payload.len() >= bounds::ENCRYPTED_PAYLOAD_MIN,
            NonCanonicalEncoding,
            "encrypted payload is shorter than a nonce and tag"
        );
        ensure!(
            self.encrypted_payload.len() <= bounds::ENCRYPTED_PAYLOAD_MAX,
            ResourceLimitExceeded,
            "encrypted payload exceeds the protocol limit"
        );
        Ok(())
    }

    fn validate_outer_fields(&self) -> Result<()> {
        ensure!(
            self.device_sequence != 0,
            NonCanonicalEncoding,
            "device sequence is zero"
        );
        let genesis = self.previous_operation_hash == [0; COMMITMENT_LEN];
        ensure!(
            (self.device_sequence == 1) == genesis,
            NonCanonicalEncoding,
            "device sequence and previous operation hash disagree"
        );
        ensure!(
            self.observed_heads.len() <= bounds::OBSERVED_HEADS_MAX,
            ResourceLimitExceeded,
            "observed head count exceeds the protocol limit"
        );
        let mut previous: Option<&Id> = None;
        for head in &self.observed_heads {
            ensure!(
                head.device_sequence != 0,
                NonCanonicalEncoding,
                "observed device sequence is zero"
            );
            ensure!(
                head.device_id != self.device_id,
                NonCanonicalEncoding,
                "observed heads contain the authoring device"
            );
            if let Some(previous) = previous {
                ensure!(
                    previous.as_bytes() < head.device_id.as_bytes(),
                    NonCanonicalEncoding,
                    "observed heads are not sorted and unique"
                );
            }
            previous = Some(&head.device_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("non-zero identifier")
    }

    #[test]
    fn a_valid_operation_round_trips_through_canonical_bytes() {
        let operation = Operation::new(
            id(1),
            id(2),
            id(3),
            8,
            [4; 32],
            vec![ObservedHead::new(id(5), 7)],
            id(6),
            [vec![7; 24], vec![8; 16]].concat(),
            [9; 64],
        )
        .expect("valid operation");

        let bytes = operation.encode();
        assert_eq!(bytes.len(), 242);
        assert!(Operation::decode(&bytes).expect("decode") == operation);
    }

    #[test]
    fn a_signature_verifies_only_for_the_exact_operation_and_key() {
        let key = DeviceSigningKey::from_seed([10; 32]);
        let mut operation = Operation::new(
            id(1),
            id(2),
            id(3),
            1,
            [0; 32],
            Vec::new(),
            id(6),
            [vec![7; 24], vec![8; 16]].concat(),
            [0; 64],
        )
        .expect("valid operation")
        .sign(&key);

        operation
            .verify_signature(&key.verifying_key())
            .expect("signature must verify");
        assert!(
            operation
                .verify_signature(&DeviceSigningKey::from_seed([11; 32]).verifying_key())
                .is_err()
        );

        operation.encrypted_payload[24] ^= 1;
        assert!(operation.verify_signature(&key.verifying_key()).is_err());
    }

    #[test]
    fn a_payload_is_bound_to_its_outer_fields_and_complete_record_digest() {
        let payload_key = Key::new([12; 32]);
        let operation = Operation::seal(
            id(1),
            id(2),
            id(3),
            1,
            [0; 32],
            Vec::new(),
            id(6),
            &payload_key,
            Nonce::new([7; 24]),
            b"private operation",
        )
        .expect("seal");
        let unsigned_digest = operation.digest();
        let operation = operation.sign(&DeviceSigningKey::from_seed([9; 32]));

        assert_eq!(
            operation
                .open_payload(&payload_key)
                .expect("open")
                .as_slice(),
            b"private operation"
        );
        assert_ne!(operation.digest(), unsigned_digest);
        assert!(operation.open_payload(&Key::new([13; 32])).is_err());

        let mut changed_outer_field = operation.clone();
        changed_outer_field.key_selector = id(8);
        assert!(changed_outer_field.open_payload(&payload_key).is_err());

        let oversized = vec![0; bounds::PAYLOAD_PLAINTEXT_MAX + 1];
        assert_eq!(
            Operation::seal(
                id(1),
                id(2),
                id(3),
                1,
                [0; 32],
                Vec::new(),
                id(6),
                &payload_key,
                Nonce::new([7; 24]),
                &oversized,
            )
            .err()
            .expect("oversized payload must fail")
            .status(),
            ChurStatus::ResourceLimitExceeded
        );
    }
}
