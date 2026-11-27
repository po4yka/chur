//! Accepted device-membership state.

use std::collections::BTreeMap;

use chur_core::limits::sync as bounds;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Commitment;

use crate::membership::{EnrollmentRecord, RevocationRecord};

/// Whether a known device may still author operations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// The device may author operations and membership changes.
    Active,
    /// The device is retained only for historical verification.
    Revoked {
        /// Highest accepted sequence on the pinned branch.
        sequence: u64,
        /// Digest at that sequence.
        digest: Commitment,
    },
}

/// Public identity and acceptance status of one known device.
#[derive(Clone)]
pub struct DeviceMembership {
    signing_public_key: [u8; 32],
    historical_signing_keys: Vec<[u8; 32]>,
    hpke_public_key: [u8; 32],
    status: DeviceStatus,
}

impl DeviceMembership {
    /// Current signing public key.
    #[must_use]
    pub const fn signing_public_key(&self) -> &[u8; 32] {
        &self.signing_public_key
    }
    /// Keys accepted for historical device signatures, current key first.
    pub fn signing_public_keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        std::iter::once(&self.signing_public_key).chain(self.historical_signing_keys.iter())
    }
    /// Current recipient-encryption public key.
    #[must_use]
    pub const fn hpke_public_key(&self) -> &[u8; 32] {
        &self.hpke_public_key
    }
    /// Current acceptance status.
    #[must_use]
    pub const fn status(&self) -> DeviceStatus {
        self.status
    }
}

/// Validated membership state for one vault.
#[derive(Clone)]
pub struct MembershipState {
    vault_id: Id,
    generation: u64,
    commitment: Commitment,
    devices: BTreeMap<Id, DeviceMembership>,
}

impl MembershipState {
    /// Starts from a valid self-enrollment.
    pub fn bootstrap(record: &EnrollmentRecord) -> Result<Self> {
        record.verify_signature(record.signing_public_key())?;
        ensure!(
            record.membership_generation() == 1,
            AuthenticationFailed,
            "membership bootstrap is not generation one"
        );
        let mut devices = BTreeMap::new();
        devices.insert(
            *record.device_id(),
            DeviceMembership {
                signing_public_key: *record.signing_public_key(),
                historical_signing_keys: Vec::new(),
                hpke_public_key: *record.hpke_public_key(),
                status: DeviceStatus::Active,
            },
        );
        Ok(Self {
            vault_id: *record.vault_id(),
            generation: 1,
            commitment: record.commitment(),
            devices,
        })
    }

    /// Accepts one later enrollment carried by the named outer operation.
    pub fn accept_enrollment(
        &mut self,
        record: &EnrollmentRecord,
        outer_device_id: &Id,
        outer_sequence: u64,
    ) -> Result<()> {
        self.validate_successor(
            record.vault_id(),
            record.membership_generation(),
            record.previous_membership_commitment(),
        )?;
        ensure!(
            record.issuer_device_id() == outer_device_id
                && record.created_sequence() == outer_sequence,
            AuthenticationFailed,
            "enrollment does not match its outer operation"
        );
        let issuer_key = *self.active_signing_key(record.issuer_device_id())?;
        record.verify_signature(&issuer_key)?;

        let mut historical_signing_keys = Vec::new();
        if !self.devices.contains_key(record.device_id()) {
            let active = self
                .devices
                .values()
                .filter(|device| device.status == DeviceStatus::Active)
                .count();
            ensure!(
                active < bounds::ACTIVE_DEVICES_MAX,
                ResourceLimitExceeded,
                "enrollment exceeds the active device limit"
            );
        }
        if let Some(existing) = self.devices.get(record.device_id()) {
            ensure!(
                record.device_id() == record.issuer_device_id()
                    && existing.status == DeviceStatus::Active,
                AuthenticationFailed,
                "enrollment reuses a device identifier"
            );
            historical_signing_keys.clone_from(&existing.historical_signing_keys);
            if existing.signing_public_key != *record.signing_public_key() {
                historical_signing_keys.push(existing.signing_public_key);
            }
        }
        self.devices.insert(
            *record.device_id(),
            DeviceMembership {
                signing_public_key: *record.signing_public_key(),
                historical_signing_keys,
                hpke_public_key: *record.hpke_public_key(),
                status: DeviceStatus::Active,
            },
        );
        self.generation = record.membership_generation();
        self.commitment = record.commitment();
        Ok(())
    }

    /// Accepts one revocation carried by the named outer operation.
    pub fn accept_revocation(
        &mut self,
        record: &RevocationRecord,
        outer_device_id: &Id,
    ) -> Result<()> {
        self.validate_successor(
            record.vault_id(),
            record.membership_generation(),
            record.previous_membership_commitment(),
        )?;
        ensure!(
            record.issuer_device_id() == outer_device_id,
            AuthenticationFailed,
            "revocation does not match its outer operation"
        );
        let issuer_key = *self.active_signing_key(record.issuer_device_id())?;
        record.verify_signature(&issuer_key)?;
        let target = self
            .devices
            .get_mut(record.revoked_device_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "revocation names an unknown device",
                )
            })?;
        ensure!(
            target.status == DeviceStatus::Active,
            AuthenticationFailed,
            "revocation target is not active"
        );
        target.status = DeviceStatus::Revoked {
            sequence: record.final_accepted_device_sequence(),
            digest: *record.final_accepted_operation_digest(),
        };
        self.generation = record.membership_generation();
        self.commitment = record.commitment();
        Ok(())
    }

    /// Whether the device may author new operations.
    #[must_use]
    pub fn is_active(&self, device_id: &Id) -> bool {
        self.devices
            .get(device_id)
            .is_some_and(|device| device.status == DeviceStatus::Active)
    }

    /// Active device identifiers in canonical order.
    pub fn active_device_ids(&self) -> impl Iterator<Item = &Id> {
        self.devices.iter().filter_map(|(device_id, device)| {
            (device.status == DeviceStatus::Active).then_some(device_id)
        })
    }

    /// Known device identity and status.
    #[must_use]
    pub fn device(&self, device_id: &Id) -> Option<&DeviceMembership> {
        self.devices.get(device_id)
    }

    /// Latest accepted membership generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Latest accepted membership-chain head.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Vault whose membership this state authenticates.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }

    fn active_signing_key(&self, device_id: &Id) -> Result<&[u8; 32]> {
        let device = self.devices.get(device_id).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "membership issuer is unknown",
            )
        })?;
        ensure!(
            device.status == DeviceStatus::Active,
            AuthenticationFailed,
            "membership issuer is revoked"
        );
        Ok(&device.signing_public_key)
    }

    fn validate_successor(
        &self,
        vault_id: &Id,
        generation: u64,
        previous: &Commitment,
    ) -> Result<()> {
        ensure!(
            vault_id == &self.vault_id,
            AuthenticationFailed,
            "membership record belongs to another vault"
        );
        let expected = self.generation.checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "membership generation cannot advance",
            )
        })?;
        ensure!(
            generation == expected && previous == &self.commitment,
            SyncHeadRollback,
            "membership record is not the next accepted generation"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::operation::DeviceSigningKey;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    #[test]
    fn enrollment_then_revocation_advance_one_authenticated_chain() {
        let issuer_key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), issuer_key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&issuer_key);
        let mut state = MembershipState::bootstrap(&initial).expect("bootstrap");
        let second_key = DeviceSigningKey::from_seed([4; 32]);
        let enrollment = EnrollmentRecord::new(
            id(1),
            id(5),
            second_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [7; 32],
        )
        .expect("enrollment")
        .sign(&issuer_key);
        state
            .accept_enrollment(&enrollment, &id(2), 2)
            .expect("accept enrollment");
        assert!(state.is_active(&id(5)));
        let revocation =
            RevocationRecord::new(id(1), id(5), 1, [8; 32], 3, id(2), enrollment.commitment())
                .expect("revocation")
                .sign(&issuer_key);
        state
            .accept_revocation(&revocation, &id(2))
            .expect("accept revocation");
        assert!(!state.is_active(&id(5)));
    }

    #[test]
    fn rejected_membership_records_do_not_advance_state() {
        let issuer_key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), issuer_key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&issuer_key);
        let mut state = MembershipState::bootstrap(&initial).expect("bootstrap");
        let candidate_key = DeviceSigningKey::from_seed([4; 32]);

        let wrong_predecessor = EnrollmentRecord::new(
            id(1),
            id(5),
            candidate_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            [9; 32],
            [7; 32],
        )
        .expect("record")
        .sign(&issuer_key);
        assert_eq!(
            state
                .accept_enrollment(&wrong_predecessor, &id(2), 2)
                .expect_err("rollback")
                .status(),
            ChurStatus::SyncHeadRollback,
        );

        let wrong_signer = EnrollmentRecord::new(
            id(1),
            id(5),
            candidate_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [7; 32],
        )
        .expect("record")
        .sign(&candidate_key);
        assert_eq!(
            state
                .accept_enrollment(&wrong_signer, &id(2), 2)
                .expect_err("signature")
                .status(),
            ChurStatus::AuthenticationFailed,
        );
        assert_eq!(state.generation(), 1);
        assert!(!state.is_active(&id(5)));
    }

    #[test]
    fn key_rotation_keeps_the_old_verification_key() {
        let old_key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), old_key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&old_key);
        let mut state = MembershipState::bootstrap(&initial).expect("bootstrap");
        let new_key = DeviceSigningKey::from_seed([4; 32]);
        let rotation = EnrollmentRecord::new(
            id(1),
            id(2),
            new_key.verifying_key(),
            [5; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [6; 32],
        )
        .expect("rotation")
        .sign(&old_key);
        state
            .accept_enrollment(&rotation, &id(2), 2)
            .expect("accept rotation");
        let keys: Vec<_> = state
            .device(&id(2))
            .expect("device")
            .signing_public_keys()
            .copied()
            .collect();
        assert_eq!(keys, vec![new_key.verifying_key(), old_key.verifying_key()]);
    }

    #[test]
    fn enrollment_beyond_the_active_device_limit_is_rejected() {
        let key = DeviceSigningKey::from_seed([1; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [3; 32])
            .expect("initial")
            .sign(&key);
        let mut state = MembershipState::bootstrap(&initial).expect("bootstrap");
        let mut previous = initial.commitment();
        let enroll = |device: u8, generation: u64, previous| {
            EnrollmentRecord::new(
                id(1),
                id(device),
                key.verifying_key(),
                [6; 32],
                generation,
                id(2),
                generation,
                previous,
                [7; 32],
            )
            .expect("enrollment")
            .sign(&key)
        };
        for generation in 2..=32_u64 {
            let record = enroll(
                u8::try_from(generation).expect("byte") + 10,
                generation,
                previous,
            );
            state
                .accept_enrollment(&record, &id(2), generation)
                .expect("within the limit");
            previous = record.commitment();
        }
        let overflow = enroll(99, 33, previous);
        assert_eq!(
            state
                .accept_enrollment(&overflow, &id(2), 33)
                .expect_err("33rd active device")
                .status(),
            ChurStatus::ResourceLimitExceeded,
        );
        assert_eq!(state.generation(), 32);
        assert!(!state.is_active(&id(99)));
        // A key rotation for an existing device does not add a device.
        let rotation = enroll(2, 33, previous);
        state
            .accept_enrollment(&rotation, &id(2), 33)
            .expect("rotation at the limit");
        previous = rotation.commitment();
        // A revoked device no longer counts, so revocation makes room.
        let revocation = RevocationRecord::new(id(1), id(12), 1, [8; 32], 34, id(2), previous)
            .expect("revocation")
            .sign(&key);
        state
            .accept_revocation(&revocation, &id(2))
            .expect("revoke one device");
        previous = revocation.commitment();
        state
            .accept_enrollment(&enroll(99, 35, previous), &id(2), 35)
            .expect("enrollment after a revocation");
        assert!(state.is_active(&id(99)));
    }
}
