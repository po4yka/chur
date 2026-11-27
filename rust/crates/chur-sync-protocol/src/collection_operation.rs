//! The shared-collection operation of `docs/sync/COLLECTION_OPERATION_LOG.md`.

use chur_core::limits::{COMMITMENT_LEN, ID_LEN, sync as bounds};
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::tuple::tag;
use chur_crypto::{Commitment, Key, Nonce, aead, commit};
use chur_format::codec::{Reader, Writer};
use zeroize::Zeroizing;

use crate::operation::{DeviceSigningKey, PROTOCOL_VERSION_V1, verify_ed25519};

const SIGNATURE_LEN: usize = 64;
const FIXED_FIELDS_LEN: usize = 2 + (ID_LEN * 4) + 8 + COMMITMENT_LEN + 4 + 4 + SIGNATURE_LEN;

/// One participant head observed by a collection operation's author.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectionObservedHead {
    issuer_identity_vault_id: Id,
    issuer_device_id: Id,
    device_sequence: u64,
}

impl CollectionObservedHead {
    /// Builds an observed collection head.
    #[must_use]
    pub const fn new(
        issuer_identity_vault_id: Id,
        issuer_device_id: Id,
        device_sequence: u64,
    ) -> Self {
        Self {
            issuer_identity_vault_id,
            issuer_device_id,
            device_sequence,
        }
    }

    /// Identity vault that owns the observed device.
    #[must_use]
    pub const fn issuer_identity_vault_id(&self) -> &Id {
        &self.issuer_identity_vault_id
    }

    /// Observed device.
    #[must_use]
    pub const fn issuer_device_id(&self) -> &Id {
        &self.issuer_device_id
    }

    /// Highest accepted sequence for the observed participant.
    #[must_use]
    pub const fn device_sequence(&self) -> u64 {
        self.device_sequence
    }
}

/// One signed, encrypted shared-collection operation.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectionOperation {
    operation_id: Id,
    issuer_identity_vault_id: Id,
    issuer_device_id: Id,
    device_sequence: u64,
    previous_operation_hash: [u8; COMMITMENT_LEN],
    observed_heads: Vec<CollectionObservedHead>,
    key_selector: Id,
    encrypted_payload: Vec<u8>,
    issuer_signature: [u8; SIGNATURE_LEN],
}

impl CollectionOperation {
    /// Seals a private payload under the clear collection routing fields.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields plus encryption inputs"
    )]
    pub fn seal(
        operation_id: Id,
        issuer_identity_vault_id: Id,
        issuer_device_id: Id,
        device_sequence: u64,
        previous_operation_hash: [u8; COMMITMENT_LEN],
        observed_heads: Vec<CollectionObservedHead>,
        key_selector: Id,
        key: &Key,
        nonce: Nonce,
        plaintext: &[u8],
    ) -> Result<Self> {
        ensure!(
            plaintext.len() <= bounds::PAYLOAD_PLAINTEXT_MAX,
            ResourceLimitExceeded,
            "collection operation plaintext exceeds the protocol limit"
        );
        let mut operation = Self {
            operation_id,
            issuer_identity_vault_id,
            issuer_device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload: Vec::new(),
            issuer_signature: [0; SIGNATURE_LEN],
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
                        "collection encrypted payload length overflows the address space",
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
        issuer_identity_vault_id: Id,
        issuer_device_id: Id,
        device_sequence: u64,
        previous_operation_hash: [u8; COMMITMENT_LEN],
        observed_heads: Vec<CollectionObservedHead>,
        key_selector: Id,
        encrypted_payload: Vec<u8>,
        issuer_signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self> {
        let operation = Self {
            operation_id,
            issuer_identity_vault_id,
            issuer_device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload,
            issuer_signature,
        };
        operation.validate()?;
        Ok(operation)
    }

    /// Encodes the canonical wire record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(
            FIXED_FIELDS_LEN
                + (self.observed_heads.len() * bounds::COLLECTION_OBSERVED_HEAD_LEN)
                + self.encrypted_payload.len(),
        );
        self.write_outer_fields(&mut writer);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "validation bounds encrypted payload below u32::MAX"
        )]
        writer
            .u32(self.encrypted_payload.len() as u32)
            .fixed(&self.encrypted_payload)
            .fixed(&self.issuer_signature);
        writer.finish()
    }

    /// Replaces the signature with one made by `key` over the frozen input.
    #[must_use]
    pub fn sign(mut self, key: &DeviceSigningKey) -> Self {
        self.issuer_signature = key.sign_bytes(&self.signing_bytes());
        self
    }

    /// Verifies the operation against one enrolled device key.
    pub fn verify_signature(&self, verifying_key: &[u8; 32]) -> Result<()> {
        verify_ed25519(verifying_key, &self.issuer_signature, &self.signing_bytes())
    }

    /// Opens and authenticates the private payload.
    pub fn open_payload(&self, key: &Key) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let (nonce, sealed) = self
            .encrypted_payload
            .split_at(chur_core::limits::NONCE_LEN);
        aead::open(key, &Nonce::from_slice(nonce)?, sealed, &self.aad())
    }

    /// Hash-chain digest of the complete signed wire record.
    #[must_use]
    pub fn digest(&self) -> Commitment {
        commit::commit(tag::SHARING_COLLECTION_OPERATION_CHAIN, &[&self.encode()])
    }

    /// Stable idempotency identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &Id {
        &self.operation_id
    }

    /// Identity vault that owns the authoring device.
    #[must_use]
    pub const fn issuer_identity_vault_id(&self) -> &Id {
        &self.issuer_identity_vault_id
    }

    /// Authoring device.
    #[must_use]
    pub const fn issuer_device_id(&self) -> &Id {
        &self.issuer_device_id
    }

    /// Epoch-scoped per-device sequence.
    #[must_use]
    pub const fn device_sequence(&self) -> u64 {
        self.device_sequence
    }

    /// Digest of the preceding operation in this participant stream.
    #[must_use]
    pub const fn previous_operation_hash(&self) -> &Commitment {
        &self.previous_operation_hash
    }

    /// Cross-vault causal heads observed by the author.
    #[must_use]
    pub fn observed_heads(&self) -> &[CollectionObservedHead] {
        &self.observed_heads
    }

    /// Opaque collection epoch selector.
    #[must_use]
    pub const fn key_selector(&self) -> &Id {
        &self.key_selector
    }

    fn aad(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(
            tag::SHARING_COLLECTION_OPERATION_AAD.len()
                + FIXED_FIELDS_LEN
                + (self.observed_heads.len() * bounds::COLLECTION_OBSERVED_HEAD_LEN),
        );
        writer.fixed(tag::SHARING_COLLECTION_OPERATION_AAD);
        self.write_outer_fields(&mut writer);
        writer.finish()
    }

    fn write_outer_fields(&self, writer: &mut Writer) {
        writer
            .u16(PROTOCOL_VERSION_V1)
            .id(&self.operation_id)
            .id(&self.issuer_identity_vault_id)
            .id(&self.issuer_device_id)
            .u64(self.device_sequence)
            .fixed(&self.previous_operation_hash);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "validation bounds observed heads at 287 entries"
        )]
        writer.u32(self.observed_heads.len() as u32);
        for head in &self.observed_heads {
            writer
                .id(&head.issuer_identity_vault_id)
                .id(&head.issuer_device_id)
                .u64(head.device_sequence);
        }
        writer.id(&self.key_selector);
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut wire = self.encode();
        wire.truncate(wire.len() - SIGNATURE_LEN);
        let mut bytes = Vec::with_capacity(tag::SHARING_COLLECTION_OPERATION.len() + wire.len());
        bytes.extend_from_slice(tag::SHARING_COLLECTION_OPERATION);
        bytes.extend_from_slice(&wire);
        bytes
    }

    /// Decodes one canonical wire record.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "collection operation protocol version is not supported"
        );
        let operation_id = reader.id()?;
        let issuer_identity_vault_id = reader.id()?;
        let issuer_device_id = reader.id()?;
        let device_sequence = reader.u64()?;
        let previous_operation_hash = reader.fixed::<COMMITMENT_LEN>()?;
        let head_count = usize::try_from(reader.u32()?).map_err(|_| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "collection observed head count does not fit this platform",
            )
        })?;
        ensure!(
            head_count <= bounds::COLLECTION_OBSERVED_HEADS_MAX,
            ResourceLimitExceeded,
            "collection observed head count exceeds the protocol limit"
        );
        let mut observed_heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            observed_heads.push(CollectionObservedHead::new(
                reader.id()?,
                reader.id()?,
                reader.u64()?,
            ));
        }
        let key_selector = reader.id()?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the protocol maximum is below u32::MAX"
        )]
        let encrypted_payload = reader
            .variable(bounds::ENCRYPTED_PAYLOAD_MAX as u32)?
            .to_vec();
        let issuer_signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;
        Self::new(
            operation_id,
            issuer_identity_vault_id,
            issuer_device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            encrypted_payload,
            issuer_signature,
        )
    }

    fn validate(&self) -> Result<()> {
        self.validate_outer_fields()?;
        ensure!(
            self.encrypted_payload.len() >= bounds::ENCRYPTED_PAYLOAD_MIN,
            NonCanonicalEncoding,
            "collection encrypted payload is shorter than a nonce and tag"
        );
        ensure!(
            self.encrypted_payload.len() <= bounds::ENCRYPTED_PAYLOAD_MAX,
            ResourceLimitExceeded,
            "collection encrypted payload exceeds the protocol limit"
        );
        Ok(())
    }

    fn validate_outer_fields(&self) -> Result<()> {
        ensure!(
            self.device_sequence != 0,
            NonCanonicalEncoding,
            "collection device sequence is zero"
        );
        let genesis = self.previous_operation_hash == [0; COMMITMENT_LEN];
        ensure!(
            (self.device_sequence == 1) == genesis,
            NonCanonicalEncoding,
            "collection device sequence and previous operation hash disagree"
        );
        ensure!(
            self.observed_heads.len() <= bounds::COLLECTION_OBSERVED_HEADS_MAX,
            ResourceLimitExceeded,
            "collection observed head count exceeds the protocol limit"
        );
        let author = (
            self.issuer_identity_vault_id.as_bytes(),
            self.issuer_device_id.as_bytes(),
        );
        let mut previous: Option<(&[u8; ID_LEN], &[u8; ID_LEN])> = None;
        for head in &self.observed_heads {
            ensure!(
                head.device_sequence != 0,
                NonCanonicalEncoding,
                "collection observed device sequence is zero"
            );
            let current = (
                head.issuer_identity_vault_id.as_bytes(),
                head.issuer_device_id.as_bytes(),
            );
            ensure!(
                current != author,
                NonCanonicalEncoding,
                "collection observed heads contain the authoring participant"
            );
            if let Some(previous) = previous {
                ensure!(
                    previous < current,
                    NonCanonicalEncoding,
                    "collection observed heads are not sorted and unique"
                );
            }
            previous = Some(current);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; ID_LEN]).expect("non-zero identifier")
    }

    fn encrypted_payload() -> Vec<u8> {
        [vec![7; 24], vec![8; 16]].concat()
    }

    #[test]
    fn a_valid_collection_operation_round_trips() {
        let operation = CollectionOperation::new(
            id(1),
            id(2),
            id(3),
            8,
            [4; COMMITMENT_LEN],
            vec![CollectionObservedHead::new(id(2), id(5), 7)],
            id(6),
            encrypted_payload(),
            [9; SIGNATURE_LEN],
        )
        .expect("valid operation");
        let bytes = operation.encode();
        assert_eq!(bytes.len(), 258);
        assert!(CollectionOperation::decode(&bytes).expect("decode") == operation);
    }

    #[test]
    fn observed_heads_must_be_sorted_by_vault_and_device() {
        let build = |heads| {
            CollectionOperation::new(
                id(1),
                id(3),
                id(3),
                1,
                [0; COMMITMENT_LEN],
                heads,
                id(6),
                encrypted_payload(),
                [0; SIGNATURE_LEN],
            )
        };
        assert!(
            build(vec![
                CollectionObservedHead::new(id(2), id(1), 1),
                CollectionObservedHead::new(id(1), id(2), 1)
            ])
            .is_err()
        );
        assert!(
            build(vec![
                CollectionObservedHead::new(id(1), id(2), 1),
                CollectionObservedHead::new(id(1), id(2), 2)
            ])
            .is_err()
        );
        assert!(build(vec![CollectionObservedHead::new(id(3), id(3), 1)]).is_err());
    }

    #[test]
    fn signature_encryption_and_digest_bind_the_complete_record() {
        let signing_key = DeviceSigningKey::from_seed([10; 32]);
        let payload_key = Key::new([11; 32]);
        let operation = CollectionOperation::seal(
            id(1),
            id(2),
            id(3),
            1,
            [0; COMMITMENT_LEN],
            Vec::new(),
            id(4),
            &payload_key,
            Nonce::new([5; 24]),
            b"private collection operation",
        )
        .expect("seal")
        .sign(&signing_key);
        operation
            .verify_signature(&signing_key.verifying_key())
            .expect("signature");
        assert_eq!(
            operation
                .open_payload(&payload_key)
                .expect("open")
                .as_slice(),
            b"private collection operation"
        );
        assert!(operation.open_payload(&Key::new([12; 32])).is_err());
        let mut changed = operation.clone();
        changed.key_selector = id(9);
        assert!(
            changed
                .verify_signature(&signing_key.verifying_key())
                .is_err()
        );
        assert!(changed.open_payload(&payload_key).is_err());
        assert_ne!(changed.digest(), operation.digest());
    }

    #[test]
    fn bounds_and_chain_genesis_fail_closed() {
        let build = |sequence, previous, heads| {
            CollectionOperation::new(
                id(1),
                id(2),
                id(3),
                sequence,
                previous,
                heads,
                id(4),
                encrypted_payload(),
                [0; SIGNATURE_LEN],
            )
        };
        assert!(build(0, [0; COMMITMENT_LEN], Vec::new()).is_err());
        assert!(build(1, [1; COMMITMENT_LEN], Vec::new()).is_err());
        assert!(build(2, [0; COMMITMENT_LEN], Vec::new()).is_err());
        let heads = (0..=bounds::COLLECTION_OBSERVED_HEADS_MAX)
            .map(|index| {
                let mut vault = [1; ID_LEN];
                vault[14..].copy_from_slice(&(index as u16 + 1).to_be_bytes());
                CollectionObservedHead::new(Id::new(vault).expect("id"), id(5), 1)
            })
            .collect();
        assert!(build(1, [0; COMMITMENT_LEN], heads).is_err());
    }
}
