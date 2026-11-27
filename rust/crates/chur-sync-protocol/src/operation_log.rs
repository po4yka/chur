//! Replay, rollback, gap, and fork handling for signed device logs.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, bail, ensure};
use chur_crypto::{Commitment, Key, Nonce};

use crate::{
    checkpoint::Checkpoint,
    convergence::CausalStamp,
    membership::EnrollmentRecord,
    operation::{DeviceSigningKey, ObservedHead, Operation},
    state::{DeviceStatus, MembershipState},
};

/// Result of offering one authenticated operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The next operation was accepted.
    Applied,
    /// The exact accepted record was offered again.
    Duplicate,
    /// One or more earlier operations from this device are absent.
    PendingGap,
    /// One of the operation's cross-device causal heads is absent.
    PendingCause,
}

/// Result of accepting a signed checkpoint as a freshness lower bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// At least one per-device floor increased.
    Raised,
    /// Every checkpoint head was at or below an equal local floor.
    Unchanged,
}

#[derive(Clone)]
struct AcceptedHead {
    sequence: u64,
    digest: Commitment,
}

#[derive(Clone)]
struct AcceptedRecord {
    digest: Commitment,
    bytes: Vec<u8>,
}

/// Persisted lifecycle of a detected fork.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ForkState {
    /// Conflicting signed bytes were detected.
    Detected,
    /// The user has seen the report; the chain remains frozen.
    Acknowledged,
}

/// Signed records retained for reconciliation or incident evidence.
#[derive(Clone)]
pub struct ForkEvidence {
    state: ForkState,
    accepted_record: Vec<u8>,
    conflicting_record: Vec<u8>,
}

impl ForkEvidence {
    /// Current persisted fork state.
    #[must_use]
    pub const fn state(&self) -> ForkState {
        self.state
    }
    /// Previously accepted signed record.
    #[must_use]
    pub fn accepted_record(&self) -> &[u8] {
        &self.accepted_record
    }
    /// Conflicting signed record.
    #[must_use]
    pub fn conflicting_record(&self) -> &[u8] {
        &self.conflicting_record
    }
}

/// Accepted per-device operation heads and fork state.
#[derive(Clone, Default)]
pub struct OperationLog {
    heads: BTreeMap<Id, AcceptedHead>,
    accepted: BTreeMap<(Id, u64), AcceptedRecord>,
    operation_ids: BTreeMap<Id, Commitment>,
    floors: BTreeMap<Id, AcceptedHead>,
    checkpoints: BTreeMap<Id, Commitment>,
    forks: BTreeMap<Id, ForkEvidence>,
    /// Where each received record of a revoked device sits, and what it chains
    /// to, keyed by the digest of that record.
    ///
    /// `REVOCATION.md` §7 accepts a record at or below a revocation point only
    /// on the branch that point pins. This map lets the receiver walk that
    /// branch back from the point through records it holds but has not yet
    /// accepted. It is a cache of received records, not accepted state, so it
    /// is never persisted and never restored.
    revoked_links: BTreeMap<(Id, Commitment), (u64, Commitment)>,
}

impl OperationLog {
    /// Empty accepted log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the next signed operation from the current accepted local view.
    #[expect(
        clippy::too_many_arguments,
        reason = "the inputs are fresh wire values, encryption material, and authenticated state"
    )]
    pub fn author(
        &self,
        operation_id: Id,
        vault_id: Id,
        device_id: Id,
        key_selector: Id,
        key: &Key,
        nonce: Nonce,
        plaintext: &[u8],
        signing_key: &DeviceSigningKey,
        membership: &MembershipState,
    ) -> Result<Operation> {
        ensure!(
            membership.vault_id() == &vault_id,
            AuthenticationFailed,
            "local operation belongs to another vault"
        );
        let device = membership.device(&device_id).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "local operation author is not enrolled",
            )
        })?;
        ensure!(
            device.status() == DeviceStatus::Active
                && device.signing_public_key() == &signing_key.verifying_key(),
            AuthenticationFailed,
            "local operation key is not the current active device key"
        );
        let (device_sequence, previous_operation_hash) = self.head(&device_id).map_or_else(
            || Ok((1, [0; 32])),
            |(sequence, digest)| {
                Ok::<_, Error>((
                    sequence.checked_add(1).ok_or_else(|| {
                        Error::new(
                            ChurStatus::ResourceLimitExceeded,
                            "local device sequence has no successor",
                        )
                    })?,
                    digest,
                ))
            },
        )?;
        let observed_heads = self
            .heads
            .iter()
            .filter(|(observed_id, _)| {
                *observed_id != &device_id
                    && membership
                        .device(observed_id)
                        .is_some_and(|observed| observed.status() == DeviceStatus::Active)
            })
            .map(|(observed_id, head)| ObservedHead::new(*observed_id, head.sequence))
            .collect();
        let operation = Operation::seal(
            operation_id,
            vault_id,
            device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            key_selector,
            key,
            nonce,
            plaintext,
        )?
        .sign(signing_key);
        ensure!(
            self.check_inner(&operation, membership, None)? == ApplyOutcome::Applied,
            SyncHeadRollback,
            "local operation chain is not ready to advance"
        );
        Ok(operation)
    }

    /// Replays one record already committed in the protected local catalog.
    ///
    /// Unlike the receive path, this commits each prefix of a revoked device's
    /// already-accepted chain. The caller validates the final durable head
    /// after replay, so process restart does not need the whole chain in memory.
    pub fn restore_accepted(
        &mut self,
        operation: &Operation,
        membership: &MembershipState,
    ) -> Result<ApplyOutcome> {
        let device = membership.device(operation.device_id()).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "operation author is not enrolled",
            )
        })?;
        let cutoff = match device.status() {
            DeviceStatus::Active => None,
            DeviceStatus::Revoked { sequence, digest } => Some((sequence, digest)),
        };
        self.accept_inner(operation, membership, cutoff)
    }

    /// Rebuilds a row that was already committed in an authenticated protected
    /// catalog before a later revocation arrived. This is NOT an inbound or
    /// sharing-proof acceptance path. Signature, chain and causal checks remain;
    /// current revocation does not rewrite authenticated prior local history.
    #[doc(hidden)]
    pub fn restore_protected_catalog_history(
        &mut self,
        operation: &Operation,
        membership: &MembershipState,
    ) -> Result<ApplyOutcome> {
        let outcome = self.check_history(operation, membership, None)?;
        if outcome == ApplyOutcome::Applied {
            self.commit_inner(operation);
        }
        Ok(outcome)
    }

    /// Whether this signed branch contains an observation excluded by a later
    /// revocation. This is used only after ordinary authentication succeeds,
    /// when a private content projection has a missing cause.
    pub fn has_pruned_revocation_cause(
        &self,
        operation: &Operation,
        membership: &MembershipState,
    ) -> Result<bool> {
        if Self::observes_pruned_revocation(operation, membership) {
            return Ok(true);
        }
        let mut pending = operation
            .observed_heads()
            .iter()
            .map(|head| (*head.device_id(), head.device_sequence()))
            .collect::<Vec<_>>();
        if operation.device_sequence() > 1 {
            pending.push((*operation.device_id(), operation.device_sequence() - 1));
        }
        let mut visited = std::collections::BTreeSet::new();
        while let Some(position) = pending.pop() {
            if !visited.insert(position) {
                continue;
            }
            let Some(accepted) = self.accepted.get(&position) else {
                continue;
            };
            let record = Operation::decode(&accepted.bytes)?;
            if Self::observes_pruned_revocation(&record, membership) {
                return Ok(true);
            }
            pending.extend(
                record
                    .observed_heads()
                    .iter()
                    .map(|head| (*head.device_id(), head.device_sequence())),
            );
            if record.device_sequence() > 1 {
                pending.push((*record.device_id(), record.device_sequence() - 1));
            }
        }
        Ok(false)
    }

    /// Whether one signed observation extends beyond its current revocation cut.
    pub fn observes_pruned_revocation(operation: &Operation, membership: &MembershipState) -> bool {
        operation.observed_heads().iter().any(|head| {
            matches!(
                membership.device(head.device_id()).map(|device| device.status()),
                Some(DeviceStatus::Revoked { sequence, .. }) if head.device_sequence() > sequence
            )
        })
    }

    fn retire_revoked_floors(&mut self, membership: &MembershipState) {
        self.floors.retain(|device_id, floor| {
            !matches!(
                membership.device(device_id).map(|device| device.status()),
                Some(DeviceStatus::Revoked { sequence, .. }) if floor.sequence > sequence
            )
        });
    }

    /// Restores one authenticated checkpoint floor from the protected catalog.
    pub fn restore_floor(
        &mut self,
        device_id: &Id,
        sequence: u64,
        digest: Commitment,
        membership: &MembershipState,
    ) -> Result<()> {
        ensure!(
            membership.device(device_id).is_some() && sequence != 0 && digest != [0; 32],
            CatalogCorrupt,
            "a durable checkpoint floor is malformed"
        );
        if matches!(membership.device(device_id).map(|device| device.status()),
            Some(DeviceStatus::Revoked { sequence: cutoff, .. }) if sequence > cutoff)
        {
            self.floors.remove(device_id);
            return Ok(());
        }
        if let Some(record) = self.accepted.get(&(*device_id, sequence)) {
            ensure!(
                record.digest == digest,
                SyncChainFork,
                "a durable floor conflicts with accepted history"
            );
        }
        if let Some(current) = self.floors.get(device_id) {
            ensure!(
                sequence > current.sequence
                    || (sequence == current.sequence && digest == current.digest),
                SyncHeadRollback,
                "a durable floor moves backwards or changes branch"
            );
        }
        self.floors
            .insert(*device_id, AcceptedHead { sequence, digest });
        Ok(())
    }

    /// Restores the commitment of a checkpoint whose signed record was verified.
    pub fn restore_checkpoint_commitment(
        &mut self,
        issuer_device_id: &Id,
        commitment: Commitment,
        membership: &MembershipState,
    ) -> Result<()> {
        ensure!(
            membership.device(issuer_device_id).is_some() && commitment != [0; 32],
            CatalogCorrupt,
            "a durable checkpoint commitment is malformed"
        );
        self.checkpoints.insert(*issuer_device_id, commitment);
        Ok(())
    }

    /// Validates and accepts one operation from an active device.
    pub fn accept(
        &mut self,
        operation: &Operation,
        membership: &MembershipState,
    ) -> Result<ApplyOutcome> {
        let device = membership.device(operation.device_id()).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "operation author is not enrolled",
            )
        })?;
        // An active device hands the operation straight to `accept_inner`, which
        // already enforces every obligation a checkpoint floor carries.
        //
        // A record offered at the floor sequence with a digest other than the
        // floor's freezes the chain as fork evidence, and that check runs ahead
        // of the contiguity check, so it holds while the gap below is still
        // open. Contiguity then means a chain advances by one from sequence one,
        // so nothing above the floor is reachable until the record at the floor
        // sequence has itself been accepted. The floor is therefore crossed only
        // by the pinned history, whether it arrives in one slice or in many.
        //
        // What a discarded candidate added there was atomicity of the prefix
        // below the floor, and it cost the chain its only way forward: a floor
        // is installed only strictly above the local head, `accept_gated_with`
        // offers one operation per call, and a peer issues a checkpoint at the
        // end of every session (`ROLLBACK_PROTECTION.md` §6). So an ordinary
        // checkpoint stopped its author's chain permanently, and durably —
        // §7 there requires the opposite, since a device restored from backup
        // sets its floor before it accepts any operation and must then reach it
        // one batch at a time.
        //
        // A revocation point is different. `REVOCATION.md` §7 accepts a record
        // at or below the point only when the chain forward from it reaches
        // `final_accepted_operation_digest`, and `check_inner` cannot see that:
        // it looks backwards, and a record at sequence one needs no predecessor
        // at all. A revoked device keeps its signing key, so without the forward
        // condition it can author a fresh branch below the point that the issuer
        // never saw and no other rule refuses. The path below therefore takes a
        // record it cannot place on the pinned branch as branch learning alone,
        // through the received-record cache and not through accepted state.
        match device.status() {
            DeviceStatus::Active => self.accept_inner(operation, membership, None),
            DeviceStatus::Revoked { sequence, digest } => {
                let pinned = self.revoked_branch_holds(operation, sequence, &digest);
                match self.check_inner(operation, membership, Some((sequence, digest))) {
                    // `check_inner` verified the signature before it reached
                    // this outcome, so the held record is authentic and its
                    // own digest names the step it contributes to the branch.
                    Ok(ApplyOutcome::Applied) if !pinned => {
                        self.note_revoked_link(operation);
                        Ok(ApplyOutcome::PendingGap)
                    }
                    Ok(outcome) => {
                        if outcome == ApplyOutcome::Applied {
                            self.commit_inner(operation);
                        }
                        self.note_revoked_link(operation);
                        Ok(outcome)
                    }
                    Err(error) if error.status() == ChurStatus::SyncChainFork => {
                        self.freeze(operation)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Accepts a signed checkpoint without lowering any local floor.
    pub fn accept_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
        membership: &MembershipState,
    ) -> Result<CheckpointOutcome> {
        ensure!(
            checkpoint.vault_id() == membership.vault_id(),
            AuthenticationFailed,
            "checkpoint belongs to another vault"
        );
        let issuer = membership
            .device(checkpoint.issuer_device_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "checkpoint issuer is unknown",
                )
            })?;
        ensure!(
            issuer.status() == DeviceStatus::Active,
            AuthenticationFailed,
            "checkpoint issuer is revoked"
        );
        if !issuer
            .signing_public_keys()
            .any(|key| checkpoint.verify_signature(key).is_ok())
        {
            return Err(Error::new(
                ChurStatus::AuthenticationFailed,
                "checkpoint signature did not verify under device key history",
            ));
        }

        // A checkpoint already authenticated and retained by this log remains
        // an exact replay after a signed enrollment advances membership. It
        // contributes no new floors or authority. Unknown older checkpoints
        // still require the current membership below.
        if self.checkpoints.get(checkpoint.issuer_device_id()) == Some(&checkpoint.commitment()) {
            self.retire_revoked_floors(membership);
            return Ok(CheckpointOutcome::Unchanged);
        }
        ensure!(
            checkpoint.membership_generation() == membership.generation()
                && checkpoint.membership_commitment() == membership.commitment(),
            SyncHeadRollback,
            "checkpoint membership is not current"
        );

        // One pure pass names every floor the checkpoint raises and catches
        // every conflict before any state moves. A checkpoint that fails
        // therefore changes nothing, and one that succeeds changes exactly
        // the floors and the issuer commitment, which is what lets the
        // durable layer take the outcome in place instead of trial-cloning
        // the whole log per checkpoint.
        let mut pending: BTreeMap<Id, AcceptedHead> = BTreeMap::new();
        let mut raised = false;
        for checkpoint_head in checkpoint.heads() {
            ensure!(
                membership.device(checkpoint_head.device_id()).is_some(),
                AuthenticationFailed,
                "checkpoint names an unknown device"
            );
            let device_id = *checkpoint_head.device_id();
            if matches!(membership.device(&device_id).map(|device| device.status()),
                Some(DeviceStatus::Revoked { sequence, .. }) if checkpoint_head.device_sequence() > sequence)
            {
                continue;
            }
            let offered = AcceptedHead {
                sequence: checkpoint_head.device_sequence(),
                digest: *checkpoint_head.operation_digest(),
            };
            if matches!(
                self.accepted.get(&(device_id, offered.sequence)),
                Some(record) if record.digest != offered.digest
            ) {
                return self.reject_checkpoint_fork(device_id, checkpoint);
            }
            let floor = pending
                .get(&device_id)
                .or_else(|| self.floors.get(&device_id));
            if let Some(current) = floor {
                if offered.sequence < current.sequence {
                    continue;
                }
                if offered.sequence == current.sequence {
                    if offered.digest != current.digest {
                        return self.reject_checkpoint_fork(device_id, checkpoint);
                    }
                    continue;
                }
            }
            if let Some(current) = self.heads.get(&device_id) {
                if offered.sequence < current.sequence {
                    continue;
                }
                if offered.sequence == current.sequence {
                    if offered.digest != current.digest {
                        return self.reject_checkpoint_fork(device_id, checkpoint);
                    }
                    continue;
                }
            }
            pending.insert(device_id, offered);
            raised = true;
        }
        self.retire_revoked_floors(membership);
        self.floors.extend(pending);
        // Retain the latest checkpoint, not the last offered one: floors only
        // move up, so a replayed older checkpoint raises nothing and must not
        // displace the commitment a fresher checkpoint installed - a regressed
        // commitment is what breaks fork reporting against the issuer.
        if raised || !self.checkpoints.contains_key(checkpoint.issuer_device_id()) {
            self.checkpoints
                .insert(*checkpoint.issuer_device_id(), checkpoint.commitment());
        }
        Ok(if raised {
            CheckpointOutcome::Raised
        } else {
            CheckpointOutcome::Unchanged
        })
    }

    /// Establishes a new device's first freshness floor from its enrollment.
    pub fn bootstrap_from_enrollment(
        &mut self,
        enrollment: &EnrollmentRecord,
        checkpoint: &Checkpoint,
        membership: &MembershipState,
    ) -> Result<CheckpointOutcome> {
        ensure!(
            self.heads.is_empty()
                && self.accepted.is_empty()
                && self.floors.is_empty()
                && self.checkpoints.is_empty()
                && self.forks.is_empty(),
            Conflict,
            "bootstrap requires an empty operation log"
        );
        ensure!(
            enrollment.vault_id() == membership.vault_id()
                && enrollment.membership_generation() == membership.generation()
                && &enrollment.commitment() == membership.commitment()
                && membership.is_active(enrollment.device_id())
                && enrollment.device_id() != enrollment.issuer_device_id(),
            AuthenticationFailed,
            "enrollment is not the accepted membership head"
        );
        ensure!(
            checkpoint.commitment() == *enrollment.bootstrap_checkpoint_commitment()
                && checkpoint.vault_id() == membership.vault_id()
                && checkpoint.issuer_device_id() == enrollment.issuer_device_id(),
            AuthenticationFailed,
            "checkpoint does not match the enrollment attestation"
        );
        ensure!(
            checkpoint
                .membership_generation()
                .checked_add(1)
                .is_some_and(|generation| generation == enrollment.membership_generation())
                && checkpoint.membership_commitment()
                    == enrollment.previous_membership_commitment(),
            SyncHeadRollback,
            "checkpoint does not precede the enrolled membership generation"
        );
        let issuer = membership
            .device(checkpoint.issuer_device_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "checkpoint issuer is unknown",
                )
            })?;
        ensure!(
            issuer.status() == DeviceStatus::Active
                && issuer
                    .signing_public_keys()
                    .any(|key| checkpoint.verify_signature(key).is_ok()),
            AuthenticationFailed,
            "bootstrap checkpoint issuer or signature is not accepted"
        );

        let mut floors = BTreeMap::new();
        for head in checkpoint.heads() {
            ensure!(
                membership.device(head.device_id()).is_some()
                    && head.device_id() != enrollment.device_id(),
                AuthenticationFailed,
                "bootstrap checkpoint names a device outside prior membership"
            );
            if matches!(membership.device(head.device_id()).map(|device| device.status()),
                Some(DeviceStatus::Revoked { sequence, .. }) if head.device_sequence() > sequence)
            {
                continue;
            }
            floors.insert(
                *head.device_id(),
                AcceptedHead {
                    sequence: head.device_sequence(),
                    digest: *head.operation_digest(),
                },
            );
        }
        self.floors = floors;
        self.checkpoints
            .insert(*checkpoint.issuer_device_id(), checkpoint.commitment());
        Ok(CheckpointOutcome::Raised)
    }

    /// Atomically accepts one device's chain through its checkpoint floor.
    pub fn accept_device_chain(
        &mut self,
        operations: &[Operation],
        membership: &MembershipState,
    ) -> Result<Vec<ApplyOutcome>> {
        let first = operations
            .first()
            .ok_or_else(|| Error::new(ChurStatus::InvalidInput, "device chain is empty"))?;
        let device_id = *first.device_id();
        if matches!(
            membership.device(&device_id).map(|device| device.status()),
            Some(DeviceStatus::Revoked { .. })
        ) {
            return self.accept_revoked_chain(operations, membership);
        }
        let mut candidate = self.clone();
        let mut outcomes = Vec::with_capacity(operations.len());
        for operation in operations {
            ensure!(
                operation.device_id() == &device_id,
                InvalidInput,
                "device chain mixes devices"
            );
            match candidate.accept_inner(operation, membership, None) {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    if error.status() == ChurStatus::SyncChainFork {
                        *self = candidate;
                    }
                    return Err(error);
                }
            }
        }
        if !candidate.floor_satisfied(&device_id) {
            return Ok(vec![ApplyOutcome::PendingGap]);
        }
        *self = candidate;
        Ok(outcomes)
    }

    /// Atomically accepts a contiguous revoked-device chain through its pinned point.
    pub fn accept_revoked_chain(
        &mut self,
        operations: &[Operation],
        membership: &MembershipState,
    ) -> Result<Vec<ApplyOutcome>> {
        let first = operations
            .first()
            .ok_or_else(|| Error::new(ChurStatus::InvalidInput, "revoked-device chain is empty"))?;
        let device_id = *first.device_id();
        let device = membership.device(&device_id).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "operation author is not enrolled",
            )
        })?;
        let (cutoff_sequence, cutoff_digest) = match device.status() {
            DeviceStatus::Revoked { sequence, digest } => (sequence, digest),
            DeviceStatus::Active => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "device is not revoked",
                ));
            }
        };
        let mut candidate = self.clone();
        let mut outcomes = Vec::with_capacity(operations.len());
        for operation in operations {
            ensure!(
                operation.device_id() == &device_id,
                InvalidInput,
                "revoked chain mixes devices"
            );
            match candidate.accept_inner(
                operation,
                membership,
                Some((cutoff_sequence, cutoff_digest)),
            ) {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    if error.status() == ChurStatus::SyncChainFork {
                        *self = candidate;
                    }
                    return Err(error);
                }
            }
        }
        if !candidate.head_matches(&device_id, cutoff_sequence, &cutoff_digest) {
            return Ok(vec![ApplyOutcome::PendingGap]);
        }
        *self = candidate;
        Ok(outcomes)
    }

    /// Fork evidence for a frozen device chain.
    #[must_use]
    pub fn fork(&self, device_id: &Id) -> Option<&ForkEvidence> {
        self.forks.get(device_id)
    }

    /// Records that the user has seen a fork report without unfreezing it.
    pub fn acknowledge_fork(&mut self, device_id: &Id) -> Result<()> {
        let evidence = self
            .forks
            .get_mut(device_id)
            .ok_or_else(|| Error::new(ChurStatus::NotFound, "device chain has no fork"))?;
        evidence.state = ForkState::Acknowledged;
        Ok(())
    }

    /// Clears a frozen chain only after membership accepted its revocation.
    pub fn resolve_by_revocation(
        &mut self,
        device_id: &Id,
        membership: &MembershipState,
    ) -> Result<()> {
        ensure!(
            matches!(
                membership.device(device_id).map(|device| device.status()),
                Some(DeviceStatus::Revoked { .. })
            ),
            AuthenticationFailed,
            "device is not revoked"
        );
        self.forks
            .remove(device_id)
            .ok_or_else(|| Error::new(ChurStatus::NotFound, "device chain has no fork"))?;
        Ok(())
    }

    fn accept_inner(
        &mut self,
        operation: &Operation,
        membership: &MembershipState,
        cutoff: Option<(u64, Commitment)>,
    ) -> Result<ApplyOutcome> {
        match self.check_inner(operation, membership, cutoff) {
            Ok(outcome) => {
                if outcome == ApplyOutcome::Applied {
                    self.commit_inner(operation);
                }
                Ok(outcome)
            }
            Err(error) if error.status() == ChurStatus::SyncChainFork => self.freeze(operation),
            Err(error) => Err(error),
        }
    }

    /// Validates one offered operation against the accepted log, §4, and
    /// touches nothing.
    ///
    /// Every check precedes every write, which is what lets the durable layer
    /// take an accepted operation in place and undo the commit it could not
    /// persist, and what lets [`Self::author`] trial an operation without
    /// cloning the log. A conflict returns a bare
    /// [`ChurStatus::SyncChainFork`]; a caller that keeps state turns it into
    /// evidence with [`Self::freeze`], and one that does not lets it bubble.
    fn check_inner(
        &self,
        operation: &Operation,
        membership: &MembershipState,
        cutoff: Option<(u64, Commitment)>,
    ) -> Result<ApplyOutcome> {
        self.check_history(operation, membership, cutoff)
    }

    fn check_history(
        &self,
        operation: &Operation,
        membership: &MembershipState,
        cutoff: Option<(u64, Commitment)>,
    ) -> Result<ApplyOutcome> {
        ensure!(
            operation.vault_id() == membership.vault_id(),
            AuthenticationFailed,
            "operation belongs to another vault"
        );
        if self.forks.contains_key(operation.device_id()) {
            return Err(Error::new(
                ChurStatus::SyncChainFork,
                "device chain is frozen after a fork",
            ));
        }
        let device = membership.device(operation.device_id()).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "operation author is not enrolled",
            )
        })?;
        if !device
            .signing_public_keys()
            .any(|key| operation.verify_signature(key).is_ok())
        {
            return Err(Error::new(
                ChurStatus::AuthenticationFailed,
                "operation signature did not verify under device key history",
            ));
        }
        let digest = operation.digest();
        if let Some((sequence, pinned_digest)) = cutoff {
            ensure!(
                operation.device_sequence() <= sequence,
                AuthenticationFailed,
                "operation is above the accepted revocation point"
            );
            if operation.device_sequence() == sequence && digest != pinned_digest {
                bail!(
                    SyncChainFork,
                    "signed operation conflicts with the accepted device chain"
                );
            }
        }

        let record_key = (*operation.device_id(), operation.device_sequence());
        if let Some(accepted) = self.accepted.get(&record_key) {
            if digest == accepted.digest {
                return Ok(ApplyOutcome::Duplicate);
            }
            bail!(
                SyncChainFork,
                "signed operation conflicts with the accepted device chain"
            );
        }
        if self.floors.get(operation.device_id()).is_some_and(|floor| {
            operation.device_sequence() == floor.sequence && digest != floor.digest
        }) {
            bail!(
                SyncChainFork,
                "signed operation conflicts with the accepted device chain"
            );
        }
        ensure!(
            self.operation_ids
                .get(operation.operation_id())
                .is_none_or(|accepted| accepted == &digest),
            AuthenticationFailed,
            "operation identifier was reused at another log position"
        );
        if let Some(head) = self.heads.get(operation.device_id()) {
            if operation.device_sequence() < head.sequence {
                return Err(Error::new(
                    ChurStatus::SyncHeadRollback,
                    "operation is below the accepted device head",
                ));
            }
            if operation.device_sequence() > head.sequence.saturating_add(1) {
                return Ok(ApplyOutcome::PendingGap);
            }
            if operation.previous_operation_hash() != &head.digest {
                bail!(
                    SyncChainFork,
                    "signed operation conflicts with the accepted device chain"
                );
            }
        } else if operation.device_sequence() != 1 {
            return Ok(ApplyOutcome::PendingGap);
        }

        for observed in operation.observed_heads() {
            let device = membership.device(observed.device_id()).ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "operation observes an unknown device",
                )
            })?;
            // A still-authorized signer can retain an observation made before
            // it learned the revocation. That claim grants no authority to the
            // revoked device and cannot require its forbidden future records.
            let required = match device.status() {
                DeviceStatus::Active => observed.device_sequence(),
                DeviceStatus::Revoked { sequence, .. } => observed.device_sequence().min(sequence),
            };
            if required == 0 {
                continue;
            }
            if self
                .heads
                .get(observed.device_id())
                .is_none_or(|head| head.sequence < required)
            {
                return Ok(ApplyOutcome::PendingCause);
            }
        }
        Ok(ApplyOutcome::Applied)
    }

    /// Commits one operation [`Self::check_inner`] has just accepted.
    ///
    /// A commit only appends: one accepted record, one operation identifier,
    /// and one head that replaces exactly the predecessor the operation
    /// chains to. That shape is what makes [`Self::undo_accept`] exact.
    fn commit_inner(&mut self, operation: &Operation) {
        let digest = operation.digest();
        self.accepted.insert(
            (*operation.device_id(), operation.device_sequence()),
            AcceptedRecord {
                digest,
                bytes: operation.encode(),
            },
        );
        self.operation_ids.insert(*operation.operation_id(), digest);
        self.heads.insert(
            *operation.device_id(),
            AcceptedHead {
                sequence: operation.device_sequence(),
                digest,
            },
        );
    }

    /// Exactly undoes the commit of one operation the caller did not, or no
    /// longer can, persist or admit.
    ///
    /// The durable layer takes an accepted operation in before its catalog
    /// transaction, so a gate that refuses the record and a transaction that
    /// fails both have to give the log back the state the operation found.
    /// The inverse is exact because `Self::commit_inner` only appends: the
    /// accepted record and the operation identifier are removed by key, and
    /// the head returns to the predecessor the operation itself chains to, or
    /// disappears when the operation was the device's first. The contract is
    /// that the last commit for this exact operation is the one being undone,
    /// which the debug assertion states; anything else is a caller bug.
    /// A `Self::note_revoked_link` learning is a received-record cache and
    /// not accepted state, so it survives the undo.
    pub fn undo_accept(&mut self, operation: &Operation) {
        let device_id = *operation.device_id();
        let sequence = operation.device_sequence();
        debug_assert_eq!(
            self.accepted
                .get(&(device_id, sequence))
                .map(|record| record.digest),
            Some(operation.digest()),
            "undo_accept names an operation that was not committed"
        );
        self.accepted.remove(&(device_id, sequence));
        self.operation_ids.remove(operation.operation_id());
        match sequence.checked_sub(1) {
            None | Some(0) => {
                self.heads.remove(&device_id);
            }
            Some(previous) => {
                self.heads.insert(
                    device_id,
                    AcceptedHead {
                        sequence: previous,
                        digest: *operation.previous_operation_hash(),
                    },
                );
            }
        }
    }

    fn freeze(&mut self, operation: &Operation) -> Result<ApplyOutcome> {
        let same_sequence = (*operation.device_id(), operation.device_sequence());
        let accepted_record = self.accepted.get(&same_sequence).map_or_else(
            || {
                self.heads
                    .get(operation.device_id())
                    .and_then(|head| self.accepted.get(&(*operation.device_id(), head.sequence)))
                    .map_or_else(Vec::new, |record| record.bytes.clone())
            },
            |record| record.bytes.clone(),
        );
        self.forks.insert(
            *operation.device_id(),
            ForkEvidence {
                state: ForkState::Detected,
                accepted_record,
                conflicting_record: operation.encode(),
            },
        );
        Err(Error::new(
            ChurStatus::SyncChainFork,
            "signed operation conflicts with the accepted device chain",
        ))
    }

    /// Remembers what one received record of a revoked device chains to.
    ///
    /// The key is the digest of the record, and that digest binds both the
    /// sequence and the previous hash it is stored with. A fabricated record
    /// therefore describes only itself: it enters no branch it does not already
    /// belong to.
    fn note_revoked_link(&mut self, operation: &Operation) {
        self.revoked_links.insert(
            (*operation.device_id(), operation.digest()),
            (
                operation.device_sequence(),
                *operation.previous_operation_hash(),
            ),
        );
    }

    /// Whether the record sits on the branch its revocation point pins.
    ///
    /// `REVOCATION.md` §7 accepts a record at or below the point only when the
    /// chain forward from it reaches `final_accepted_operation_digest`. The
    /// receiver gets one record at a time and cannot look forward, so it tests
    /// the same condition backwards: it starts at the pinned digest and follows
    /// `previous_operation_hash` down through the records it holds. Each step
    /// is named by the digest of the record that carries it, so the walk
    /// follows the pinned branch alone. A receiver that does not hold every
    /// record between the point and this one gets `false` and holds this one,
    /// so the whole span from the point down must reach one inbox together.
    ///
    /// The walk decides one record only, and every accepted record still enters
    /// through the ordinary contiguity rule, so an accepted chain still starts
    /// at sequence one and `sync_log::load` still replays it upward.
    // ponytail: one descent per offered record, so a tail of length L costs
    // O(L^2) map reads to admit. Cache the highest proven sequence per device
    // if a long revoked import ever shows up in a profile.
    fn revoked_branch_holds(
        &self,
        operation: &Operation,
        cutoff_sequence: u64,
        cutoff_digest: &Commitment,
    ) -> bool {
        let device_id = *operation.device_id();
        let target = operation.device_sequence();
        if target > cutoff_sequence {
            return false;
        }
        let mut sequence = cutoff_sequence;
        let mut digest = *cutoff_digest;
        // The walk descends by one sequence per step and visits each held link
        // at most once, so the map length bounds it.
        for _ in 0..=self.revoked_links.len() {
            if sequence == target {
                return digest == operation.digest();
            }
            match self.revoked_links.get(&(device_id, digest)) {
                Some(&(linked_sequence, previous)) if linked_sequence == sequence => {
                    let Some(next) = sequence.checked_sub(1) else {
                        return false;
                    };
                    sequence = next;
                    digest = previous;
                }
                _ => return false,
            }
        }
        false
    }

    fn head_matches(&self, device_id: &Id, sequence: u64, digest: &Commitment) -> bool {
        self.heads
            .get(device_id)
            .is_some_and(|head| head.sequence == sequence && &head.digest == digest)
    }

    fn floor_satisfied(&self, device_id: &Id) -> bool {
        self.floors.get(device_id).is_none_or(|floor| {
            self.accepted
                .get(&(*device_id, floor.sequence))
                .is_some_and(|record| record.digest == floor.digest)
        })
    }

    fn reject_checkpoint_fork(
        &mut self,
        device_id: Id,
        checkpoint: &Checkpoint,
    ) -> Result<CheckpointOutcome> {
        // The pure pass that names this rejection has moved no state, so the
        // accepted records this log holds are exactly the ones the checkpoint
        // conflicts against.
        let accepted_record = checkpoint
            .heads()
            .iter()
            .find(|head| *head.device_id() == device_id)
            .and_then(|head| self.accepted.get(&(device_id, head.device_sequence())))
            .map_or_else(Vec::new, |record| record.bytes.clone());
        self.forks.insert(
            device_id,
            ForkEvidence {
                state: ForkState::Detected,
                accepted_record,
                conflicting_record: checkpoint.encode(),
            },
        );
        Err(Error::new(
            ChurStatus::SyncChainFork,
            "checkpoint conflicts with accepted device history",
        ))
    }

    /// Latest accepted head for one device.
    #[must_use]
    pub fn head(&self, device_id: &Id) -> Option<(u64, Commitment)> {
        self.heads
            .get(device_id)
            .map(|head| (head.sequence, head.digest))
    }

    /// Latest accepted causal position for every device chain.
    pub fn latest_operations(&self) -> Result<BTreeMap<Id, CausalStamp>> {
        self.heads
            .iter()
            .map(|(device_id, head)| {
                let record = self
                    .accepted
                    .get(&(*device_id, head.sequence))
                    .ok_or_else(|| {
                        Error::new(
                            ChurStatus::InternalFailure,
                            "an accepted device head has no operation record",
                        )
                    })?;
                let operation = Operation::decode(&record.bytes)?;
                ensure!(
                    operation.device_id() == device_id
                        && operation.device_sequence() == head.sequence
                        && operation.digest() == head.digest,
                    InternalFailure,
                    "an accepted device head does not match its operation record"
                );
                Ok((*device_id, CausalStamp::from_operation(&operation)))
            })
            .collect()
    }

    /// Durable checkpoint floor for one device.
    #[must_use]
    pub fn floor(&self, device_id: &Id) -> Option<(u64, Commitment)> {
        self.floors
            .get(device_id)
            .map(|floor| (floor.sequence, floor.digest))
    }

    /// Latest accepted checkpoint commitment from one issuer.
    #[must_use]
    pub fn checkpoint_commitment(&self, issuer_device_id: &Id) -> Option<&Commitment> {
        self.checkpoints.get(issuer_device_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{
        membership::{EnrollmentRecord, RevocationRecord},
        operation::DeviceSigningKey,
        state::MembershipState,
    };
    use chur_core::Id;
    use chur_crypto::{Key, Nonce};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn operation_for(
        key: &DeviceSigningKey,
        device_id: Id,
        sequence: u64,
        previous: [u8; 32],
        marker: u8,
    ) -> Operation {
        Operation::seal(
            id(marker),
            id(1),
            device_id,
            sequence,
            previous,
            Vec::new(),
            id(9),
            &Key::new([8; 32]),
            Nonce::new([marker; 24]),
            &[marker],
        )
        .expect("operation")
        .sign(key)
    }

    fn operation(
        key: &DeviceSigningKey,
        sequence: u64,
        previous: [u8; 32],
        marker: u8,
    ) -> Operation {
        operation_for(key, id(2), sequence, previous, marker)
    }

    #[test]
    fn duplicate_is_idempotent_and_conflict_freezes_the_device_chain() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let mut log = OperationLog::new();
        let first = operation(&key, 1, [0; 32], 5);
        assert!(log.accept(&first, &membership).expect("first") == ApplyOutcome::Applied);
        assert!(log.accept(&first, &membership).expect("duplicate") == ApplyOutcome::Duplicate);
        let conflict = operation(&key, 1, [0; 32], 6);
        assert_eq!(
            log.accept(&conflict, &membership)
                .expect_err("fork")
                .status(),
            ChurStatus::SyncChainFork
        );
        let evidence = log.fork(&id(2)).expect("evidence");
        assert!(!evidence.accepted_record().is_empty());
        assert!(!evidence.conflicting_record().is_empty());
        log.acknowledge_fork(&id(2)).expect("acknowledge");
        assert!(log.fork(&id(2)).expect("evidence").state() == ForkState::Acknowledged);
        let second = operation(&key, 2, first.digest(), 7);
        assert_eq!(
            log.accept(&second, &membership)
                .expect_err("frozen")
                .status(),
            ChurStatus::SyncChainFork
        );
    }

    #[test]
    fn gaps_wait_and_old_exact_records_remain_idempotent() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let first = operation(&key, 1, [0; 32], 5);
        let second = operation(&key, 2, first.digest(), 7);
        let mut log = OperationLog::new();
        assert!(log.accept(&second, &membership).expect("gap") == ApplyOutcome::PendingGap);
        assert!(log.accept(&first, &membership).expect("first") == ApplyOutcome::Applied);
        assert!(log.accept(&second, &membership).expect("second") == ApplyOutcome::Applied);
        assert!(log.accept(&first, &membership).expect("old duplicate") == ApplyOutcome::Duplicate);
    }

    #[test]
    fn one_operation_identifier_cannot_name_a_second_log_position() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let first = operation(&key, 1, [0; 32], 5);
        let reused = Operation::seal(
            *first.operation_id(),
            id(1),
            id(2),
            2,
            first.digest(),
            Vec::new(),
            id(9),
            &Key::new([8; 32]),
            Nonce::new([6; 24]),
            &[6],
        )
        .expect("operation")
        .sign(&key);
        let mut log = OperationLog::new();
        assert!(log.accept(&first, &membership).expect("first") == ApplyOutcome::Applied);

        assert_eq!(
            log.accept(&reused, &membership)
                .expect_err("identifier reuse")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        assert_eq!(log.head(&id(2)), Some((1, first.digest())));
    }

    #[test]
    fn an_undo_makes_room_for_a_different_record_at_the_same_sequence() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let first = operation(&key, 1, [0; 32], 5);
        let mut log = OperationLog::new();
        assert!(log.accept(&first, &membership).expect("first") == ApplyOutcome::Applied);

        // The durable layer takes an applied operation in before its catalog
        // transaction, so a gate refusal undoes the commit, and the device may
        // then offer a different record at the same sequence against the same
        // predecessor.
        let refused = operation(&key, 2, first.digest(), 6);
        assert!(log.accept(&refused, &membership).expect("refused") == ApplyOutcome::Applied);
        log.undo_accept(&refused);
        assert_eq!(log.head(&id(2)), Some((1, first.digest())));

        let admitted = operation(&key, 2, first.digest(), 7);
        assert!(log.accept(&admitted, &membership).expect("admitted") == ApplyOutcome::Applied);
        assert_eq!(log.head(&id(2)), Some((2, admitted.digest())));

        // The inverse is exact down to a device's first record, whose commit
        // also created the head the undo removes.
        log.undo_accept(&admitted);
        log.undo_accept(&first);
        assert_eq!(log.head(&id(2)), None);
    }

    #[test]
    fn key_rotation_keeps_historical_operations_verifiable() {
        let old_key = DeviceSigningKey::from_seed([3; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), old_key.verifying_key(), [4; 32])
            .expect("initial")
            .sign(&old_key);
        let mut membership = MembershipState::bootstrap(&initial).expect("membership");
        let new_key = DeviceSigningKey::from_seed([5; 32]);
        let rotation = EnrollmentRecord::new(
            id(1),
            id(2),
            new_key.verifying_key(),
            [6; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [7; 32],
        )
        .expect("rotation")
        .sign(&old_key);
        membership
            .accept_enrollment(&rotation, &id(2), 2)
            .expect("accept rotation");

        let first = operation(&old_key, 1, [0; 32], 8);
        let second = operation(&new_key, 2, first.digest(), 9);
        let mut log = OperationLog::new();
        assert!(log.accept(&first, &membership).expect("old signature") == ApplyOutcome::Applied);
        assert!(log.accept(&second, &membership).expect("new signature") == ApplyOutcome::Applied);
    }

    #[test]
    fn local_authoring_allocates_the_chain_and_current_causal_vector() {
        let owner_key = DeviceSigningKey::from_seed([3; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), owner_key.verifying_key(), [4; 32])
            .expect("initial")
            .sign(&owner_key);
        let mut membership = MembershipState::bootstrap(&initial).expect("membership");
        let peer_key = DeviceSigningKey::from_seed([5; 32]);
        let peer = EnrollmentRecord::new(
            id(1),
            id(6),
            peer_key.verifying_key(),
            [7; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [8; 32],
        )
        .expect("peer")
        .sign(&owner_key);
        membership
            .accept_enrollment(&peer, &id(2), 2)
            .expect("accept peer");
        let payload_key = Key::new([8; 32]);
        let mut log = OperationLog::new();

        let owner_first = log
            .author(
                id(10),
                id(1),
                id(2),
                id(9),
                &payload_key,
                Nonce::new([10; 24]),
                &[10],
                &owner_key,
                &membership,
            )
            .expect("owner first");
        assert_eq!(owner_first.device_sequence(), 1);
        assert!(owner_first.observed_heads().is_empty());
        assert_eq!(
            log.accept(&owner_first, &membership).expect("accept owner"),
            ApplyOutcome::Applied
        );

        let peer_first = log
            .author(
                id(11),
                id(1),
                id(6),
                id(9),
                &payload_key,
                Nonce::new([11; 24]),
                &[11],
                &peer_key,
                &membership,
            )
            .expect("peer first");
        assert!(peer_first.observed_heads() == [crate::operation::ObservedHead::new(id(2), 1)]);
        assert_eq!(
            log.accept(&peer_first, &membership).expect("accept peer"),
            ApplyOutcome::Applied
        );

        let owner_second = log
            .author(
                id(12),
                id(1),
                id(2),
                id(9),
                &payload_key,
                Nonce::new([12; 24]),
                &[12],
                &owner_key,
                &membership,
            )
            .expect("owner second");
        assert_eq!(owner_second.device_sequence(), 2);
        assert_eq!(
            owner_second.previous_operation_hash(),
            &owner_first.digest()
        );
        assert!(owner_second.observed_heads() == [crate::operation::ObservedHead::new(id(6), 1)]);
        assert_eq!(
            log.accept(&owner_second, &membership)
                .expect("accept owner second"),
            ApplyOutcome::Applied
        );
        let latest = log.latest_operations().expect("latest operations");
        assert_eq!(latest[&id(2)].operation_id(), owner_second.operation_id());
        assert_eq!(latest[&id(6)].operation_id(), peer_first.operation_id());
        let revocation = RevocationRecord::new(
            id(1),
            id(6),
            1,
            peer_first.digest(),
            3,
            id(2),
            peer.commitment(),
        )
        .expect("revocation")
        .sign(&owner_key);
        membership
            .accept_revocation(&revocation, &id(2))
            .expect("accept revocation");
        assert_eq!(
            membership.active_device_ids().copied().collect::<Vec<_>>(),
            vec![id(2)]
        );
        let owner_third = log
            .author(
                id(13),
                id(1),
                id(2),
                id(9),
                &payload_key,
                Nonce::new([13; 24]),
                &[13],
                &owner_key,
                &membership,
            )
            .expect("owner third");
        assert!(owner_third.observed_heads().is_empty());
        let Err(error) = log.author(
            id(14),
            id(1),
            id(2),
            id(9),
            &payload_key,
            Nonce::new([14; 24]),
            &[14],
            &DeviceSigningKey::from_seed([14; 32]),
            &membership,
        ) else {
            panic!("wrong current key authored an operation");
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }

    #[test]
    fn checkpoint_floor_requires_the_pinned_chain_before_advancing() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let first = operation(&key, 1, [0; 32], 5);
        let second = operation(&key, 2, first.digest(), 6);
        let checkpoint = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            2,
            1,
            enrollment.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(
                id(2),
                2,
                second.digest(),
            )],
            [7; 32],
            [0; 32],
        )
        .expect("checkpoint")
        .sign(&key);
        let mut log = OperationLog::new();
        assert!(
            log.accept_checkpoint(&checkpoint, &membership)
                .expect("checkpoint")
                == CheckpointOutcome::Raised
        );
        // An operation below the floor builds toward it, so it is accepted:
        // §7 of `ROLLBACK_PROTECTION.md` has a restored device set its floor
        // before it accepts anything and then reach it one batch at a time.
        assert!(
            log.accept(&first, &membership).expect("toward the floor") == ApplyOutcome::Applied
        );
        assert_eq!(log.head(&id(2)), Some((1, first.digest())));
        assert_eq!(
            log.accept_device_chain(&[first, second], &membership)
                .expect("chain")
                .len(),
            2
        );
        assert_eq!(
            log.head(&id(2)),
            Some((2, *checkpoint.heads()[0].operation_digest()))
        );
        let conflicting = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            2,
            1,
            enrollment.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(id(2), 2, [9; 32])],
            [7; 32],
            [0; 32],
        )
        .expect("conflicting checkpoint")
        .sign(&key);
        assert_eq!(
            log.accept_checkpoint(&conflicting, &membership)
                .expect_err("fork")
                .status(),
            ChurStatus::SyncChainFork,
        );
        assert!(log.fork(&id(2)).is_some());
    }

    #[test]
    fn new_device_bootstrap_uses_the_enrollment_attested_checkpoint_floor() {
        let owner_key = DeviceSigningKey::from_seed([3; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), owner_key.verifying_key(), [4; 32])
            .expect("initial")
            .sign(&owner_key);
        let first = operation(&owner_key, 1, [0; 32], 5);
        let checkpoint = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            1,
            1,
            initial.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(
                id(2),
                1,
                first.digest(),
            )],
            [10; 32],
            [0; 32],
        )
        .expect("checkpoint")
        .sign(&owner_key);
        let peer_key = DeviceSigningKey::from_seed([8; 32]);
        let peer = EnrollmentRecord::new(
            id(1),
            id(3),
            peer_key.verifying_key(),
            [9; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            checkpoint.commitment(),
        )
        .expect("peer")
        .sign(&owner_key);
        let mut membership = MembershipState::bootstrap(&initial).expect("membership");
        membership
            .accept_enrollment(&peer, &id(2), 2)
            .expect("accept peer");

        let mut log = OperationLog::new();
        assert_eq!(
            log.bootstrap_from_enrollment(&peer, &checkpoint, &membership)
                .expect("bootstrap"),
            CheckpointOutcome::Raised
        );
        assert_eq!(
            log.checkpoint_commitment(&id(2)),
            Some(&checkpoint.commitment())
        );
        assert!(log.accept(&first, &membership).expect("floor") == ApplyOutcome::Applied);

        let stale = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            1,
            1,
            initial.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(
                id(2),
                1,
                first.digest(),
            )],
            [6; 32],
            [0; 32],
        )
        .expect("stale checkpoint")
        .sign(&owner_key);
        assert_eq!(
            OperationLog::new()
                .bootstrap_from_enrollment(&peer, &stale, &membership)
                .expect_err("commitment mismatch")
                .status(),
            ChurStatus::AuthenticationFailed
        );
    }

    /// Membership with device 6 enrolled and active, and the keys to revoke it.
    fn enrolled_second_device() -> (
        MembershipState,
        DeviceSigningKey,
        DeviceSigningKey,
        Commitment,
    ) {
        let issuer_key = DeviceSigningKey::from_seed([3; 32]);
        let initial = EnrollmentRecord::initial(id(1), id(2), issuer_key.verifying_key(), [4; 32])
            .expect("initial")
            .sign(&issuer_key);
        let mut membership = MembershipState::bootstrap(&initial).expect("membership");
        let revoked_key = DeviceSigningKey::from_seed([5; 32]);
        let enrollment = EnrollmentRecord::new(
            id(1),
            id(6),
            revoked_key.verifying_key(),
            [7; 32],
            2,
            id(2),
            2,
            initial.commitment(),
            [8; 32],
        )
        .expect("enrollment")
        .sign(&issuer_key);
        membership
            .accept_enrollment(&enrollment, &id(2), 2)
            .expect("accept enrollment");
        (membership, issuer_key, revoked_key, enrollment.commitment())
    }

    /// Accepts the revocation of device 6 at one signed revocation point.
    fn revoke_second_device(
        membership: &mut MembershipState,
        issuer_key: &DeviceSigningKey,
        enrollment_commitment: Commitment,
        sequence: u64,
        digest: Commitment,
    ) {
        let revocation = RevocationRecord::new(
            id(1),
            id(6),
            sequence,
            digest,
            3,
            id(2),
            enrollment_commitment,
        )
        .expect("revocation")
        .sign(issuer_key);
        membership
            .accept_revocation(&revocation, &id(2))
            .expect("accept revocation");
    }

    #[test]
    fn protected_history_replay_does_not_admit_new_revoked_operations() {
        let (mut membership, issuer, peer, enrollment) = enrolled_second_device();
        let ready = operation_for(&peer, id(6), 1, [0; 32], 10);
        revoke_second_device(&mut membership, &issuer, enrollment, 0, [0; 32]);
        let mut protected = OperationLog::new();
        assert_eq!(
            protected
                .restore_protected_catalog_history(&ready, &membership)
                .expect("protected historical row"),
            ApplyOutcome::Applied
        );
        assert_eq!(
            protected
                .accept(&ready, &membership)
                .expect_err("untrusted delivery remains revoked")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        let mut untrusted = OperationLog::new();
        assert_eq!(
            untrusted
                .restore_accepted(&ready, &membership)
                .expect_err("untrusted issuer evidence remains cutoff checked")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        let invalid = operation_for(
            &DeviceSigningKey::from_seed([99; 32]),
            id(6),
            1,
            [0; 32],
            11,
        );
        assert_eq!(
            OperationLog::new()
                .restore_protected_catalog_history(&invalid, &membership)
                .expect_err("protected history still verifies signatures")
                .status(),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn revoked_device_chain_is_atomic_through_its_pinned_digest() {
        let (mut membership, issuer_key, revoked_key, enrollment_commitment) =
            enrolled_second_device();
        let first = operation_for(&revoked_key, id(6), 1, [0; 32], 10);
        let second = operation_for(&revoked_key, id(6), 2, first.digest(), 11);
        revoke_second_device(
            &mut membership,
            &issuer_key,
            enrollment_commitment,
            2,
            second.digest(),
        );

        let mut log = OperationLog::new();
        // `REVOCATION.md` §7: the receiver holds no record between this one and
        // the revocation point, so it cannot see the chain reach the point.
        assert!(log.accept(&first, &membership).expect("unpinned") == ApplyOutcome::PendingGap);
        assert!(log.head(&id(6)).is_none());
        // The record at the point names the record below it. The branch is then
        // known, and the chain is admitted one operation per call.
        assert!(
            log.accept(&second, &membership).expect("at the point") == ApplyOutcome::PendingGap
        );
        assert!(log.accept(&first, &membership).expect("pinned") == ApplyOutcome::Applied);
        assert_eq!(log.head(&id(6)), Some((1, first.digest())));
        assert!(log.accept(&second, &membership).expect("to the point") == ApplyOutcome::Applied);
        assert_eq!(
            log.accept_revoked_chain(&[first.clone(), second.clone()], &membership)
                .expect("chain")
                .len(),
            2
        );
        assert_eq!(log.head(&id(6)), Some((2, second.digest())));
        let mut restored = OperationLog::new();
        assert_eq!(
            restored
                .restore_accepted(&first, &membership)
                .expect("restore first"),
            ApplyOutcome::Applied
        );
        assert_eq!(restored.head(&id(6)), Some((1, first.digest())));
        assert_eq!(
            restored
                .restore_accepted(&second, &membership)
                .expect("restore second"),
            ApplyOutcome::Applied
        );
        restored
            .restore_floor(&id(6), 2, second.digest(), &membership)
            .expect("restore floor");
        assert_eq!(restored.floor(&id(6)), Some((2, second.digest())));
        let above = operation_for(&revoked_key, id(6), 3, second.digest(), 12);
        assert_eq!(
            log.accept(&above, &membership)
                .expect_err("above cutoff")
                .status(),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn a_revoked_device_cannot_apply_a_branch_the_point_does_not_pin() {
        let (mut membership, issuer_key, revoked_key, enrollment_commitment) =
            enrolled_second_device();
        let first = operation_for(&revoked_key, id(6), 1, [0; 32], 10);
        let second = operation_for(&revoked_key, id(6), 2, first.digest(), 11);
        revoke_second_device(
            &mut membership,
            &issuer_key,
            enrollment_commitment,
            2,
            second.digest(),
        );
        // The revoked device keeps its signing key and authors a first
        // operation on a branch the issuer never saw. A receiver enrolled after
        // the revocation holds the point and no record of this device.
        let fabricated = operation_for(&revoked_key, id(6), 1, [0; 32], 13);
        assert!(fabricated.digest() != first.digest());

        let mut log = OperationLog::new();
        assert!(
            log.accept(&fabricated, &membership).expect("unpinned") == ApplyOutcome::PendingGap
        );
        assert!(log.head(&id(6)).is_none());
        // The record at the point pins one branch. The fabricated record is not
        // on it, however often the server offers it.
        assert!(
            log.accept(&second, &membership).expect("at the point") == ApplyOutcome::PendingGap
        );
        assert!(
            log.accept(&fabricated, &membership)
                .expect("still unpinned")
                == ApplyOutcome::PendingGap
        );
        assert!(log.head(&id(6)).is_none());
        assert!(log.accept(&first, &membership).expect("pinned") == ApplyOutcome::Applied);
        assert_eq!(log.head(&id(6)), Some((1, first.digest())));
    }

    #[test]
    fn active_observations_wait_only_for_the_revoked_devices_pinned_prefix() {
        let (mut membership, issuer_key, _revoked_key, enrollment_commitment) =
            enrolled_second_device();
        let first = operation_for(&_revoked_key, id(6), 1, [0; 32], 10);
        let second = operation_for(&_revoked_key, id(6), 2, first.digest(), 11);
        revoke_second_device(
            &mut membership,
            &issuer_key,
            enrollment_commitment,
            2,
            second.digest(),
        );

        // The active author's old observation waits only for the signed
        // revocation point; the forbidden suffix is not its dependency.
        let above = Operation::seal(
            id(20),
            id(1),
            id(2),
            1,
            [0; 32],
            vec![crate::operation::ObservedHead::new(id(6), 3)],
            id(9),
            &Key::new([8; 32]),
            Nonce::new([21; 24]),
            &[21],
        )
        .expect("operation")
        .sign(&issuer_key);
        let mut log = OperationLog::new();
        assert_eq!(
            log.accept(&above, &membership).expect("historical claim"),
            ApplyOutcome::PendingCause
        );
        assert!(log.fork(&id(2)).is_none());

        // An author that had not yet observed the revocation may still name
        // the device at or below the point; that op waits for its cause.
        let below = Operation::seal(
            id(22),
            id(1),
            id(2),
            1,
            [0; 32],
            vec![crate::operation::ObservedHead::new(id(6), 2)],
            id(9),
            &Key::new([8; 32]),
            Nonce::new([23; 24]),
            &[23],
        )
        .expect("operation")
        .sign(&issuer_key);
        assert!(
            log.accept(&below, &membership).expect("legal claim") == ApplyOutcome::PendingCause
        );
        assert_eq!(
            log.accept_revoked_chain(&[first, second.clone()], &membership)
                .expect("pinned prefix"),
            vec![ApplyOutcome::Applied, ApplyOutcome::Applied]
        );
        assert_eq!(
            log.accept(&above, &membership).expect("active author"),
            ApplyOutcome::Applied
        );
        let forbidden = operation_for(&_revoked_key, id(6), 3, second.digest(), 24);
        assert_eq!(
            log.accept(&forbidden, &membership)
                .expect_err("no revoked authority")
                .status(),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn historical_revoked_checkpoint_heads_never_become_new_floors() {
        use crate::checkpoint::{Checkpoint, CheckpointHead, UNCOMPACTED_CATALOG_STATE_COMMITMENT};
        let (mut membership, issuer, revoked, commitment) = enrolled_second_device();
        let ready = operation_for(&revoked, id(6), 1, [0; 32], 50);
        let owner = operation_for(&issuer, id(2), 1, [0; 32], 51);
        let mut log = OperationLog::new();
        log.restore_floor(&id(6), 1, ready.digest(), &membership)
            .expect("earlier active floor");
        revoke_second_device(&mut membership, &issuer, commitment, 0, [0; 32]);
        let checkpoint = Checkpoint::new(
            id(1),
            id(2),
            1,
            membership.generation(),
            *membership.commitment(),
            vec![
                CheckpointHead::new(id(2), 1, owner.digest()),
                CheckpointHead::new(id(6), 1, ready.digest()),
            ],
            [9; 32],
            UNCOMPACTED_CATALOG_STATE_COMMITMENT,
        )
        .expect("checkpoint")
        .sign(&issuer);
        log.accept_checkpoint(&checkpoint, &membership)
            .expect("active issuer historical claim");
        assert_eq!(log.floor(&id(6)), None);
        assert_eq!(log.floor(&id(2)), Some((1, owner.digest())));
        log.restore_floor(&id(6), 1, ready.digest(), &membership)
            .expect("old durable floor ignored");
        assert_eq!(log.floor(&id(6)), None);
        assert_eq!(
            log.accept(&ready, &membership)
                .expect_err("no restored authority")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        let enrollment = EnrollmentRecord::new(
            id(1),
            id(90),
            [7; 32],
            [8; 32],
            2,
            id(2),
            membership.generation() + 1,
            *membership.commitment(),
            checkpoint.commitment(),
        )
        .expect("new device")
        .sign(&issuer);
        membership
            .accept_enrollment(&enrollment, &id(2), 2)
            .expect("enrollment");
        let mut bootstrap = OperationLog::new();
        bootstrap
            .bootstrap_from_enrollment(&enrollment, &checkpoint, &membership)
            .expect("bootstrap keeps current revocation bounds");
        assert_eq!(bootstrap.floor(&id(6)), None);
        assert_eq!(bootstrap.floor(&id(2)), Some((1, owner.digest())));
    }

    #[test]
    fn a_replayed_checkpoint_cannot_displace_the_retained_commitment() {
        let key = DeviceSigningKey::from_seed([3; 32]);
        let enrollment = EnrollmentRecord::initial(id(1), id(2), key.verifying_key(), [4; 32])
            .expect("enrollment")
            .sign(&key);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let first = operation(&key, 1, [0; 32], 5);
        let second = operation(&key, 2, first.digest(), 6);
        let third = operation(&key, 3, second.digest(), 7);
        let older = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            2,
            1,
            enrollment.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(
                id(2),
                2,
                second.digest(),
            )],
            [7; 32],
            [0; 32],
        )
        .expect("older checkpoint")
        .sign(&key);
        let newer = crate::checkpoint::Checkpoint::new(
            id(1),
            id(2),
            3,
            1,
            enrollment.commitment(),
            vec![crate::checkpoint::CheckpointHead::new(
                id(2),
                3,
                third.digest(),
            )],
            [8; 32],
            [0; 32],
        )
        .expect("newer checkpoint")
        .sign(&key);
        let mut log = OperationLog::new();
        assert!(
            log.accept_checkpoint(&older, &membership).expect("older") == CheckpointOutcome::Raised
        );
        assert_eq!(log.checkpoint_commitment(&id(2)), Some(&older.commitment()));
        assert!(
            log.accept_checkpoint(&newer, &membership).expect("newer") == CheckpointOutcome::Raised
        );
        assert_eq!(log.checkpoint_commitment(&id(2)), Some(&newer.commitment()));
        // The replayed older checkpoint raises no floor and must leave the
        // retained commitment alone.
        assert!(
            log.accept_checkpoint(&older, &membership).expect("replay")
                == CheckpointOutcome::Unchanged
        );
        assert_eq!(log.checkpoint_commitment(&id(2)), Some(&newer.commitment()));
    }

    #[test]
    fn a_revoked_device_cannot_extend_an_accepted_head_off_the_pinned_branch() {
        let (mut membership, issuer_key, revoked_key, enrollment_commitment) =
            enrolled_second_device();
        let first = operation_for(&revoked_key, id(6), 1, [0; 32], 10);
        let second = operation_for(&revoked_key, id(6), 2, first.digest(), 11);
        let third = operation_for(&revoked_key, id(6), 3, second.digest(), 12);
        // The receiver took the first operation while the device was active.
        let mut log = OperationLog::new();
        assert!(log.accept(&first, &membership).expect("active") == ApplyOutcome::Applied);
        revoke_second_device(
            &mut membership,
            &issuer_key,
            enrollment_commitment,
            3,
            third.digest(),
        );
        // The revoked device forges a successor of the accepted head and never
        // offers the rest of its real chain.
        let forged = operation_for(&revoked_key, id(6), 2, first.digest(), 14);
        assert!(forged.digest() != second.digest());
        assert!(log.accept(&forged, &membership).expect("unpinned") == ApplyOutcome::PendingGap);
        assert_eq!(log.head(&id(6)), Some((1, first.digest())));
        // The genuine tail still applies, one operation per call.
        assert!(log.accept(&third, &membership).expect("at the point") == ApplyOutcome::PendingGap);
        assert!(
            log.accept(&forged, &membership).expect("still unpinned") == ApplyOutcome::PendingGap
        );
        assert!(log.accept(&second, &membership).expect("pinned") == ApplyOutcome::Applied);
        assert!(log.accept(&third, &membership).expect("to the point") == ApplyOutcome::Applied);
        assert_eq!(log.head(&id(6)), Some((3, third.digest())));
    }
}
