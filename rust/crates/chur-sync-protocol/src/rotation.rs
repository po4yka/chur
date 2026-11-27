//! Collection epoch rotation and eager object-key rewrap.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};

use crate::state::MembershipState;

const TAKEOVER_DELAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone)]
struct Rotation {
    owner_device_id: Id,
    membership_generation: u64,
    accepted_at_ms: u64,
    collection_envelope: CollectionKeyEnvelope,
}

/// In-memory rules for one collection's epoch transition.
#[derive(Clone)]
pub struct CollectionEpochState {
    vault_id: Id,
    collection_id: Id,
    current_epoch: u64,
    envelopes: BTreeMap<Id, ObjectKeyEnvelope>,
    rotation: Option<Rotation>,
}

/// Result of accepting a target-epoch object envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewrapOutcome {
    /// The old envelope was replaced.
    Applied,
    /// An authenticated target-epoch envelope already existed.
    AlreadyApplied,
}

impl CollectionEpochState {
    /// Builds state from the active objects of one completed epoch.
    pub fn new(
        vault_id: Id,
        collection_id: Id,
        current_epoch: u64,
        envelopes: Vec<ObjectKeyEnvelope>,
    ) -> Result<Self> {
        ensure!(
            current_epoch != 0 && current_epoch != u64::MAX,
            InvalidInput,
            "collection epoch is zero or has no successor"
        );
        let mut by_object = BTreeMap::new();
        for envelope in envelopes {
            ensure!(
                envelope.vault_id() == &vault_id
                    && envelope.collection_id() == &collection_id
                    && envelope.collection_epoch() == current_epoch,
                InvalidInput,
                "object envelope does not belong to the completed collection epoch"
            );
            ensure!(
                by_object.insert(*envelope.object_id(), envelope).is_none(),
                Conflict,
                "active object has duplicate key envelopes"
            );
        }
        Ok(Self {
            vault_id,
            collection_id,
            current_epoch,
            envelopes: by_object,
            rotation: None,
        })
    }

    /// Rebuilds one unfinished rotation from authenticated catalog rows.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments are the durable rotation record and its owning state"
    )]
    pub fn restore_active(
        vault_id: Id,
        collection_id: Id,
        target_epoch: u64,
        envelopes: Vec<ObjectKeyEnvelope>,
        owner_device_id: Id,
        membership_generation: u64,
        accepted_at_ms: u64,
        collection_envelope: CollectionKeyEnvelope,
        membership: &MembershipState,
        root: &Key,
    ) -> Result<Self> {
        ensure!(
            target_epoch > 1
                && membership_generation != 0
                && membership.vault_id() == &vault_id
                && membership.generation() >= membership_generation
                && membership.device(&owner_device_id).is_some(),
            AuthenticationFailed,
            "durable rotation membership is not accepted"
        );
        ensure!(
            collection_envelope.vault_id() == &vault_id
                && collection_envelope.collection_id() == &collection_id
                && collection_envelope.collection_epoch() == target_epoch,
            AuthenticationFailed,
            "durable collection envelope does not bind the target epoch"
        );
        collection_envelope.open(root)?;
        let previous_epoch = target_epoch - 1;
        let mut by_object = BTreeMap::new();
        for envelope in envelopes {
            ensure!(
                envelope.vault_id() == &vault_id
                    && envelope.collection_id() == &collection_id
                    && matches!(envelope.collection_epoch(), epoch if epoch == previous_epoch || epoch == target_epoch),
                CatalogCorrupt,
                "durable object envelope is outside the active rotation"
            );
            ensure!(
                by_object.insert(*envelope.object_id(), envelope).is_none(),
                CatalogCorrupt,
                "durable rotation has duplicate object envelopes"
            );
        }
        Ok(Self {
            vault_id,
            collection_id,
            current_epoch: target_epoch,
            envelopes: by_object,
            rotation: Some(Rotation {
                owner_device_id,
                membership_generation,
                accepted_at_ms,
                collection_envelope,
            }),
        })
    }

    /// Activates the next epoch after authenticating its collection envelope.
    pub fn begin_rotation(
        &mut self,
        membership: &MembershipState,
        owner_device_id: Id,
        membership_generation: u64,
        accepted_at_ms: u64,
        collection_envelope: CollectionKeyEnvelope,
        root: &Key,
    ) -> Result<()> {
        ensure!(
            self.rotation.is_none(),
            Conflict,
            "rotation is already active"
        );
        ensure!(
            membership.vault_id() == &self.vault_id
                && membership.generation() == membership_generation
                && membership.is_active(&owner_device_id),
            AuthenticationFailed,
            "rotation owner is not active at the accepted membership generation"
        );
        let target_epoch = self.current_epoch.checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "collection epoch cannot advance",
            )
        })?;
        ensure!(
            collection_envelope.vault_id() == &self.vault_id
                && collection_envelope.collection_id() == &self.collection_id
                && collection_envelope.collection_epoch() == target_epoch,
            AuthenticationFailed,
            "new collection envelope does not bind the next epoch"
        );
        collection_envelope.open(root)?;
        self.current_epoch = target_epoch;
        self.rotation = Some(Rotation {
            owner_device_id,
            membership_generation,
            accepted_at_ms,
            collection_envelope,
        });
        Ok(())
    }

    /// Accepts one authenticated rewrap and preserves idempotency on retries.
    pub fn apply_rewrap(
        &mut self,
        membership: &MembershipState,
        worker_device_id: &Id,
        now_ms: u64,
        previous_collection_key: &Key,
        current_collection_key: &Key,
        envelope: ObjectKeyEnvelope,
    ) -> Result<RewrapOutcome> {
        let rotation = self
            .rotation
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::Conflict, "collection has no active rotation"))?;
        ensure!(
            membership.vault_id() == &self.vault_id
                && membership.generation() >= rotation.membership_generation
                && membership.is_active(worker_device_id),
            AuthenticationFailed,
            "rewrap worker is not active in the accepted membership"
        );
        if worker_device_id != &rotation.owner_device_id {
            let takeover_at = rotation
                .accepted_at_ms
                .checked_add(TAKEOVER_DELAY_MS)
                .ok_or_else(|| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "rotation takeover time overflows",
                    )
                })?;
            ensure!(
                now_ms >= takeover_at,
                PermissionDenied,
                "rotation takeover delay has not elapsed"
            );
        }
        ensure!(
            envelope.vault_id() == &self.vault_id
                && envelope.collection_id() == &self.collection_id
                && envelope.collection_epoch() == self.current_epoch,
            AuthenticationFailed,
            "rewrapped envelope does not bind the active epoch"
        );
        let current = self.envelopes.get(envelope.object_id()).ok_or_else(|| {
            Error::new(
                ChurStatus::NotFound,
                "rewrapped envelope names no active object",
            )
        })?;
        let incoming_key = envelope.open(current_collection_key)?;
        if current.collection_epoch() == self.current_epoch {
            ensure!(
                current.open(current_collection_key)? == incoming_key,
                ObjectCorrupt,
                "duplicate rewrap changes the object key"
            );
            return Ok(RewrapOutcome::AlreadyApplied);
        }
        ensure!(
            envelope.envelope_generation() > current.envelope_generation(),
            SyncHeadRollback,
            "rewrapped envelope generation does not advance"
        );
        ensure!(
            current.open(previous_collection_key)? == incoming_key,
            ObjectCorrupt,
            "rewrapped envelope changes the object key"
        );
        self.envelopes.insert(*envelope.object_id(), envelope);
        Ok(RewrapOutcome::Applied)
    }

    /// Smallest active object that still lacks an authenticated target envelope.
    #[must_use]
    pub fn next_missing_object(&self) -> Option<&Id> {
        self.rotation.as_ref()?;
        self.envelopes.iter().find_map(|(object_id, envelope)| {
            (envelope.collection_epoch() != self.current_epoch).then_some(object_id)
        })
    }

    /// Whether an active rotation has authenticated every active object envelope.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.rotation.is_some() && self.next_missing_object().is_none()
    }

    /// Closes an active rotation after every object reached the target epoch.
    pub fn finish_rotation(&mut self) -> Result<()> {
        ensure!(
            self.is_complete(),
            Conflict,
            "collection rotation is not complete"
        );
        self.rotation = None;
        Ok(())
    }

    /// Current envelope for one active object.
    #[must_use]
    pub fn envelope(&self, object_id: &Id) -> Option<&ObjectKeyEnvelope> {
        self.envelopes.get(object_id)
    }

    /// Collection envelope that activated the current epoch.
    #[must_use]
    pub fn collection_envelope(&self) -> Option<&CollectionKeyEnvelope> {
        self.rotation
            .as_ref()
            .map(|rotation| &rotation.collection_envelope)
    }

    /// Epoch used for all newly created objects and operations.
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use chur_core::Id;
    use chur_crypto::{Key, Nonce};
    use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};

    use super::*;
    use crate::membership::{EnrollmentRecord, RevocationRecord};
    use crate::operation::DeviceSigningKey;
    use crate::state::MembershipState;

    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn membership() -> MembershipState {
        let owner_key = DeviceSigningKey::from_seed([3; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), owner_key.verifying_key(), [4; 32])
            .expect("initial")
            .sign(&owner_key);
        let mut state = MembershipState::bootstrap(&initial).expect("membership");
        let peer_key = DeviceSigningKey::from_seed([5; 32]);
        let peer = EnrollmentRecord::new(
            id(1),
            id(3),
            peer_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [7; 32],
        )
        .expect("peer")
        .sign(&owner_key);
        state
            .accept_enrollment(&peer, &id(2), 2)
            .expect("accept peer");
        state
    }

    fn old_envelope(object: u8, key: &Key) -> ObjectKeyEnvelope {
        ObjectKeyEnvelope::seal(
            key,
            id(1),
            id(10),
            1,
            id(object),
            1,
            Nonce::new([object; 24]),
            &Key::new([object; 32]),
        )
        .expect("old envelope")
    }

    fn destination(old: &ObjectKeyEnvelope, old_key: &Key, new_key: &Key) -> ObjectKeyEnvelope {
        old.rewrap(old_key, new_key, id(10), 2, 2, Nonce::new([9; 24]))
            .expect("rewrap")
    }

    fn rotation() -> (CollectionEpochState, MembershipState, Key, Key) {
        let root = Key::new([1; 32]);
        let old_key = Key::new([2; 32]);
        let new_key = Key::new([3; 32]);
        let mut state = CollectionEpochState::new(
            id(1),
            id(10),
            1,
            vec![
                old_envelope(30, &old_key),
                old_envelope(10, &old_key),
                old_envelope(20, &old_key),
            ],
        )
        .expect("state");
        let membership = membership();
        let collection =
            CollectionKeyEnvelope::seal(&root, id(1), id(10), 2, 2, Nonce::new([8; 24]), &new_key)
                .expect("collection envelope");
        state
            .begin_rotation(&membership, id(2), 2, 1_000, collection, &root)
            .expect("begin");
        (state, membership, old_key, new_key)
    }

    #[test]
    fn reverse_order_rewrap_still_resumes_at_the_smallest_hole() {
        let (mut state, membership, old_key, new_key) = rotation();
        let last = state.envelope(&id(30)).expect("last").clone();
        state
            .apply_rewrap(
                &membership,
                &id(2),
                1_000,
                &old_key,
                &new_key,
                destination(&last, &old_key, &new_key),
            )
            .expect("last first");
        assert_eq!(state.next_missing_object(), Some(&id(10)));

        for object in [10, 20] {
            let old = state.envelope(&id(object)).expect("old").clone();
            state
                .apply_rewrap(
                    &membership,
                    &id(2),
                    1_000,
                    &old_key,
                    &new_key,
                    destination(&old, &old_key, &new_key),
                )
                .expect("rewrap");
        }
        assert!(state.is_complete());
        assert_eq!(state.next_missing_object(), None);
    }

    #[test]
    fn another_active_device_takes_over_only_after_local_timeout() {
        let (mut state, membership, old_key, new_key) = rotation();
        let old = state.envelope(&id(10)).expect("old").clone();
        let target = destination(&old, &old_key, &new_key);
        assert!(
            state
                .apply_rewrap(
                    &membership,
                    &id(3),
                    1_000 + DAY_MS - 1,
                    &old_key,
                    &new_key,
                    target.clone(),
                )
                .is_err()
        );
        state
            .apply_rewrap(
                &membership,
                &id(3),
                1_000 + DAY_MS,
                &old_key,
                &new_key,
                target,
            )
            .expect("take over");
    }

    #[test]
    fn revoked_worker_and_wrong_object_key_cannot_advance_rotation() {
        let (mut state, mut membership, old_key, new_key) = rotation();
        let owner_key = DeviceSigningKey::from_seed([3; 32]);
        let revocation =
            RevocationRecord::new(id(1), id(3), 1, [9; 32], 3, id(2), *membership.commitment())
                .expect("revocation")
                .sign(&owner_key);
        membership
            .accept_revocation(&revocation, &id(2))
            .expect("accept revocation");
        let old = state.envelope(&id(10)).expect("old").clone();
        let wrong = ObjectKeyEnvelope::seal(
            &new_key,
            id(1),
            id(10),
            2,
            id(10),
            2,
            Nonce::new([7; 24]),
            &Key::new([99; 32]),
        )
        .expect("wrong key envelope");
        assert!(
            state
                .apply_rewrap(
                    &membership,
                    &id(3),
                    1_000 + DAY_MS,
                    &old_key,
                    &new_key,
                    destination(&old, &old_key, &new_key),
                )
                .is_err()
        );
        assert!(
            state
                .apply_rewrap(&membership, &id(2), 1_000, &old_key, &new_key, wrong,)
                .is_err()
        );
        assert_eq!(state.next_missing_object(), Some(&id(10)));
    }

    #[test]
    fn an_active_rotation_restores_and_finishes_only_after_every_rewrap() {
        let (mut state, membership, old_key, new_key) = rotation();
        let first = state.envelope(&id(10)).expect("first").clone();
        state
            .apply_rewrap(
                &membership,
                &id(2),
                1_000,
                &old_key,
                &new_key,
                destination(&first, &old_key, &new_key),
            )
            .expect("rewrap first");
        let envelopes = [10, 20, 30]
            .into_iter()
            .map(|object| state.envelope(&id(object)).expect("envelope").clone())
            .collect();
        let collection = state
            .collection_envelope()
            .expect("collection envelope")
            .clone();
        let mut restored = CollectionEpochState::restore_active(
            id(1),
            id(10),
            2,
            envelopes,
            id(2),
            2,
            1_000,
            collection,
            &membership,
            &Key::new([1; 32]),
        )
        .expect("restore rotation");
        assert_eq!(restored.next_missing_object(), Some(&id(20)));
        assert_eq!(
            restored.finish_rotation().expect_err("incomplete").status(),
            ChurStatus::Conflict
        );
        for object in [20, 30] {
            let old = restored.envelope(&id(object)).expect("old").clone();
            restored
                .apply_rewrap(
                    &membership,
                    &id(2),
                    1_000,
                    &old_key,
                    &new_key,
                    destination(&old, &old_key, &new_key),
                )
                .expect("rewrap");
        }
        restored.finish_rotation().expect("finish");
        assert!(restored.collection_envelope().is_none());
    }
}
