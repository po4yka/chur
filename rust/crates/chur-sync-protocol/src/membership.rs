//! The membership records of `docs/sync/DEVICE_IDENTITY.md` §4 and §9.

use chur_core::limits::COMMITMENT_LEN;
use chur_core::{ChurStatus, Id, Result, ensure};
use chur_crypto::{Commitment, commit, tuple::tag};
use chur_format::codec::{Reader, Writer};

use crate::operation::{DeviceSigningKey, PROTOCOL_VERSION_V1, verify_ed25519};

const SIGNATURE_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNING_SUITE_V1: u16 = 1;
const HPKE_SUITE_V1: u16 = 1;
const SYNC_V1_CAPABILITY: u64 = 1;
const ENROLLMENT_LEN: usize = 270;
const REVOCATION_LEN: usize = 194;
const ENROLLMENT_KIND: u8 = 1;
const REVOCATION_KIND: u8 = 2;

/// One signed device enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentRecord {
    vault_id: Id,
    device_id: Id,
    signing_public_key: [u8; PUBLIC_KEY_LEN],
    hpke_public_key: [u8; PUBLIC_KEY_LEN],
    created_sequence: u64,
    issuer_device_id: Id,
    membership_generation: u64,
    previous_membership_commitment: Commitment,
    bootstrap_checkpoint_commitment: Commitment,
    signature: [u8; SIGNATURE_LEN],
}

impl EnrollmentRecord {
    /// Exact canonical encoded length.
    pub const LEN: usize = ENROLLMENT_LEN;

    /// Builds generation-1 self-enrollment.
    pub fn initial(
        vault_id: Id,
        device_id: Id,
        signing_public_key: [u8; PUBLIC_KEY_LEN],
        hpke_public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Result<Self> {
        Self::from_fields(
            vault_id,
            device_id,
            signing_public_key,
            hpke_public_key,
            1,
            device_id,
            1,
            [0; COMMITMENT_LEN],
            [0; COMMITMENT_LEN],
            [0; SIGNATURE_LEN],
        )
    }

    /// Builds a later enrollment.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields"
    )]
    pub fn new(
        vault_id: Id,
        device_id: Id,
        signing_public_key: [u8; PUBLIC_KEY_LEN],
        hpke_public_key: [u8; PUBLIC_KEY_LEN],
        created_sequence: u64,
        issuer_device_id: Id,
        membership_generation: u64,
        previous_membership_commitment: Commitment,
        bootstrap_checkpoint_commitment: Commitment,
    ) -> Result<Self> {
        Self::from_fields(
            vault_id,
            device_id,
            signing_public_key,
            hpke_public_key,
            created_sequence,
            issuer_device_id,
            membership_generation,
            previous_membership_commitment,
            bootstrap_checkpoint_commitment,
            [0; SIGNATURE_LEN],
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the frozen wire fields"
    )]
    fn from_fields(
        vault_id: Id,
        device_id: Id,
        signing_public_key: [u8; PUBLIC_KEY_LEN],
        hpke_public_key: [u8; PUBLIC_KEY_LEN],
        created_sequence: u64,
        issuer_device_id: Id,
        membership_generation: u64,
        previous_membership_commitment: Commitment,
        bootstrap_checkpoint_commitment: Commitment,
        signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self> {
        let record = Self {
            vault_id,
            device_id,
            signing_public_key,
            hpke_public_key,
            created_sequence,
            issuer_device_id,
            membership_generation,
            previous_membership_commitment,
            bootstrap_checkpoint_commitment,
            signature,
        };
        record.validate()?;
        Ok(record)
    }

    /// Signs the canonical enrollment with its issuer key.
    #[must_use]
    pub fn sign(mut self, key: &DeviceSigningKey) -> Self {
        self.signature = key.sign_bytes(&signing_bytes(tag::SYNC_ENROLLMENT, &self.encode()));
        self
    }

    /// Verifies the issuer signature.
    pub fn verify_signature(&self, key: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
        verify_ed25519(
            key,
            &self.signature,
            &signing_bytes(tag::SYNC_ENROLLMENT, &self.encode()),
        )
    }

    /// Encodes the fixed 270-byte record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(ENROLLMENT_LEN);
        writer
            .u16(PROTOCOL_VERSION_V1)
            .id(&self.vault_id)
            .id(&self.device_id)
            .u16(SIGNING_SUITE_V1)
            .fixed(&self.signing_public_key)
            .u16(HPKE_SUITE_V1)
            .fixed(&self.hpke_public_key)
            .u64(SYNC_V1_CAPABILITY)
            .u64(self.created_sequence)
            .id(&self.issuer_device_id)
            .u64(self.membership_generation)
            .fixed(&self.previous_membership_commitment)
            .fixed(&self.bootstrap_checkpoint_commitment)
            .fixed(&self.signature);
        writer.finish()
    }

    /// Decodes a canonical enrollment.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "enrollment protocol version is not supported"
        );
        let vault_id = reader.id()?;
        let device_id = reader.id()?;
        ensure!(
            reader.u16()? == SIGNING_SUITE_V1,
            UnsupportedVersion,
            "enrollment signing suite is not supported"
        );
        let signing_public_key = reader.fixed::<PUBLIC_KEY_LEN>()?;
        ensure!(
            reader.u16()? == HPKE_SUITE_V1,
            UnsupportedVersion,
            "enrollment HPKE suite is not supported"
        );
        let hpke_public_key = reader.fixed::<PUBLIC_KEY_LEN>()?;
        ensure!(
            reader.u64()? == SYNC_V1_CAPABILITY,
            UnsupportedVersion,
            "enrollment capabilities are not supported"
        );
        let created_sequence = reader.u64()?;
        let issuer_device_id = reader.id()?;
        let membership_generation = reader.u64()?;
        let previous_membership_commitment = reader.fixed::<COMMITMENT_LEN>()?;
        let bootstrap_checkpoint_commitment = reader.fixed::<COMMITMENT_LEN>()?;
        let signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;
        Self::from_fields(
            vault_id,
            device_id,
            signing_public_key,
            hpke_public_key,
            created_sequence,
            issuer_device_id,
            membership_generation,
            previous_membership_commitment,
            bootstrap_checkpoint_commitment,
            signature,
        )
    }

    /// The membership-chain head after this record.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        membership_commitment(ENROLLMENT_KIND, &self.encode())
    }

    /// Enrolled device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }
    /// Vault whose membership changes.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }
    /// Issuer device identifier.
    #[must_use]
    pub const fn issuer_device_id(&self) -> &Id {
        &self.issuer_device_id
    }
    /// Enrolled signing key.
    #[must_use]
    pub const fn signing_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.signing_public_key
    }
    /// Enrolled HPKE public key.
    #[must_use]
    pub const fn hpke_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.hpke_public_key
    }
    /// Issuer operation sequence that carries this record.
    #[must_use]
    pub const fn created_sequence(&self) -> u64 {
        self.created_sequence
    }
    /// Membership generation created by this record.
    #[must_use]
    pub const fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
    /// Previous membership-chain head.
    #[must_use]
    pub const fn previous_membership_commitment(&self) -> &Commitment {
        &self.previous_membership_commitment
    }
    /// Checkpoint floor attested for the new device.
    #[must_use]
    pub const fn bootstrap_checkpoint_commitment(&self) -> &Commitment {
        &self.bootstrap_checkpoint_commitment
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.signing_public_key != [0; PUBLIC_KEY_LEN],
            NonCanonicalEncoding,
            "enrollment signing key is zero"
        );
        ensure!(
            self.hpke_public_key != [0; PUBLIC_KEY_LEN],
            NonCanonicalEncoding,
            "enrollment HPKE key is zero"
        );
        ensure!(
            self.created_sequence != 0 && self.membership_generation != 0,
            NonCanonicalEncoding,
            "enrollment sequence or generation is zero"
        );
        if self.membership_generation == 1 {
            ensure!(
                self.device_id == self.issuer_device_id && self.created_sequence == 1,
                NonCanonicalEncoding,
                "initial enrollment is not self-issued at sequence one"
            );
            ensure!(
                self.previous_membership_commitment == [0; COMMITMENT_LEN]
                    && self.bootstrap_checkpoint_commitment == [0; COMMITMENT_LEN],
                NonCanonicalEncoding,
                "initial enrollment carries a predecessor"
            );
        } else {
            ensure!(
                self.previous_membership_commitment != [0; COMMITMENT_LEN]
                    && self.bootstrap_checkpoint_commitment != [0; COMMITMENT_LEN],
                NonCanonicalEncoding,
                "later enrollment lacks its predecessor or checkpoint"
            );
        }
        Ok(())
    }
}

/// One signed device revocation.
#[derive(Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    vault_id: Id,
    revoked_device_id: Id,
    final_accepted_device_sequence: u64,
    final_accepted_operation_digest: Commitment,
    membership_generation: u64,
    issuer_device_id: Id,
    previous_membership_commitment: Commitment,
    signature: [u8; SIGNATURE_LEN],
}

impl RevocationRecord {
    /// Exact canonical encoded length.
    pub const LEN: usize = REVOCATION_LEN;

    /// Builds an unsigned revocation record.
    pub fn new(
        vault_id: Id,
        revoked_device_id: Id,
        final_accepted_device_sequence: u64,
        final_accepted_operation_digest: Commitment,
        membership_generation: u64,
        issuer_device_id: Id,
        previous_membership_commitment: Commitment,
    ) -> Result<Self> {
        let record = Self {
            vault_id,
            revoked_device_id,
            final_accepted_device_sequence,
            final_accepted_operation_digest,
            membership_generation,
            issuer_device_id,
            previous_membership_commitment,
            signature: [0; SIGNATURE_LEN],
        };
        record.validate()?;
        Ok(record)
    }

    /// Signs the canonical revocation with its issuer key.
    #[must_use]
    pub fn sign(mut self, key: &DeviceSigningKey) -> Self {
        self.signature = key.sign_bytes(&signing_bytes(tag::SYNC_REVOCATION, &self.encode()));
        self
    }

    /// Verifies the issuer signature.
    pub fn verify_signature(&self, key: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
        verify_ed25519(
            key,
            &self.signature,
            &signing_bytes(tag::SYNC_REVOCATION, &self.encode()),
        )
    }

    /// Encodes the fixed 194-byte record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(REVOCATION_LEN);
        writer
            .u16(PROTOCOL_VERSION_V1)
            .id(&self.vault_id)
            .id(&self.revoked_device_id)
            .u64(self.final_accepted_device_sequence)
            .fixed(&self.final_accepted_operation_digest)
            .u64(self.membership_generation)
            .id(&self.issuer_device_id)
            .fixed(&self.previous_membership_commitment)
            .fixed(&self.signature);
        writer.finish()
    }

    /// Decodes a canonical revocation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "revocation protocol version is not supported"
        );
        let record = Self {
            vault_id: reader.id()?,
            revoked_device_id: reader.id()?,
            final_accepted_device_sequence: reader.u64()?,
            final_accepted_operation_digest: reader.fixed::<COMMITMENT_LEN>()?,
            membership_generation: reader.u64()?,
            issuer_device_id: reader.id()?,
            previous_membership_commitment: reader.fixed::<COMMITMENT_LEN>()?,
            signature: reader.fixed::<SIGNATURE_LEN>()?,
        };
        reader.finish()?;
        record.validate()?;
        Ok(record)
    }

    /// The membership-chain head after this record.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        membership_commitment(REVOCATION_KIND, &self.encode())
    }
    /// Removed device identifier.
    #[must_use]
    pub const fn revoked_device_id(&self) -> &Id {
        &self.revoked_device_id
    }
    /// Vault whose membership changes.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }
    /// Issuer device identifier.
    #[must_use]
    pub const fn issuer_device_id(&self) -> &Id {
        &self.issuer_device_id
    }
    /// Membership generation created by this record.
    #[must_use]
    pub const fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
    /// Previous membership-chain head.
    #[must_use]
    pub const fn previous_membership_commitment(&self) -> &Commitment {
        &self.previous_membership_commitment
    }
    /// Highest accepted sequence from the revoked device.
    #[must_use]
    pub const fn final_accepted_device_sequence(&self) -> u64 {
        self.final_accepted_device_sequence
    }
    /// Branch digest pinned at the revocation point.
    #[must_use]
    pub const fn final_accepted_operation_digest(&self) -> &Commitment {
        &self.final_accepted_operation_digest
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.revoked_device_id != self.issuer_device_id,
            NonCanonicalEncoding,
            "device revocation is self-issued"
        );
        ensure!(
            (self.final_accepted_device_sequence == 0)
                == (self.final_accepted_operation_digest == [0; COMMITMENT_LEN]),
            NonCanonicalEncoding,
            "device revocation point mixes genesis and an authored branch"
        );
        ensure!(
            self.membership_generation > 1
                && self.previous_membership_commitment != [0; COMMITMENT_LEN],
            NonCanonicalEncoding,
            "device revocation lacks a membership predecessor"
        );
        Ok(())
    }
}

fn signing_bytes(domain: &'static [u8], encoded: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len() - SIGNATURE_LEN);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded[..encoded.len() - SIGNATURE_LEN]);
    bytes
}

fn membership_commitment(kind: u8, encoded: &[u8]) -> Commitment {
    commit::commit(tag::SYNC_MEMBERSHIP_CHAIN, &[&[kind], encoded])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    #[test]
    fn initial_enrollment_is_signed_canonical_membership() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let record = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("record")
            .sign(&key);
        assert_eq!(record.encode().len(), ENROLLMENT_LEN);
        record
            .verify_signature(&key.verifying_key())
            .expect("signature");
        assert_eq!(
            EnrollmentRecord::decode(&record.encode())
                .expect("decode")
                .encode(),
            record.encode()
        );
        assert_ne!(record.commitment(), [0; COMMITMENT_LEN]);
    }

    #[test]
    fn revocation_is_signed_and_domain_separated() {
        let key = DeviceSigningKey::from_seed([5; 32]);
        let record = RevocationRecord::new(id(1), id(2), 9, [3; 32], 2, id(4), [5; 32])
            .expect("record")
            .sign(&key);
        assert_eq!(record.encode().len(), REVOCATION_LEN);
        record
            .verify_signature(&key.verifying_key())
            .expect("signature");
        assert_eq!(
            RevocationRecord::decode(&record.encode())
                .expect("decode")
                .encode(),
            record.encode()
        );
        assert_ne!(record.commitment(), [0; COMMITMENT_LEN]);
    }
    #[test]
    fn revocation_genesis_is_exact_and_canonical() {
        let record = RevocationRecord::new(id(1), id(2), 0, [0; 32], 2, id(4), [5; 32])
            .expect("never-authored device revocation");
        assert_eq!(
            RevocationRecord::decode(&record.encode())
                .expect("decode genesis revocation")
                .encode(),
            record.encode()
        );
        assert!(RevocationRecord::new(id(1), id(2), 0, [3; 32], 2, id(4), [5; 32]).is_err());
        assert!(RevocationRecord::new(id(1), id(2), 1, [0; 32], 2, id(4), [5; 32]).is_err());
    }
}
