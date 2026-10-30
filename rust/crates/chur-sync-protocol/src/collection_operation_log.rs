//! Acceptance state for epoch-scoped shared-collection operation streams.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Commitment, Key, Nonce};

use crate::collection_membership::CollectionMembershipState;
use crate::collection_operation::{CollectionObservedHead, CollectionOperation};
use crate::operation::DeviceSigningKey;
use crate::operation_log::{ApplyOutcome, ForkState};
use crate::payload::{OperationPayload, PayloadBody};
use crate::state::MembershipState;

type Participant = (Id, Id);

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

/// Signed collection records retained after a detected participant fork.
#[derive(Clone)]
pub struct CollectionForkEvidence {
    state: ForkState,
    accepted_record: Vec<u8>,
    conflicting_record: Vec<u8>,
}

impl CollectionForkEvidence {
    /// Current persisted fork state.
    #[must_use]
    pub const fn state(&self) -> ForkState {
        self.state
    }

    /// Previously accepted signed record, if available.
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

/// Accepted heads and conflicts for one collection epoch selector.
#[derive(Clone)]
pub struct CollectionOperationLog {
    collection_id: Id,
    collection_epoch: u64,
    key_selector: Id,
    heads: BTreeMap<Participant, AcceptedHead>,
    accepted: BTreeMap<(Id, Id, u64), AcceptedRecord>,
    operation_ids: BTreeMap<Id, Commitment>,
    forks: BTreeMap<Participant, CollectionForkEvidence>,
}

impl CollectionOperationLog {
    /// Starts an empty log for one authenticated collection key domain.
    #[must_use]
    pub fn new(collection_id: Id, collection_epoch: u64, key_selector: Id) -> Self {
        Self {
            collection_id,
            collection_epoch,
            key_selector,
            heads: BTreeMap::new(),
            accepted: BTreeMap::new(),
            operation_ids: BTreeMap::new(),
            forks: BTreeMap::new(),
        }
    }

    /// Builds the next signed operation from the accepted participant view.
    #[expect(
        clippy::too_many_arguments,
        reason = "the inputs are fresh wire values, encryption material, and authenticated state"
    )]
    pub fn author(
        &self,
        operation_id: Id,
        issuer_identity_vault_id: Id,
        issuer_device_id: Id,
        key: &Key,
        nonce: Nonce,
        payload: &OperationPayload,
        signing_key: &DeviceSigningKey,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<CollectionOperation> {
        ensure!(
            issuer_membership.vault_id() == &issuer_identity_vault_id,
            AuthenticationFailed,
            "local collection operation belongs to another identity vault"
        );
        let participant = (issuer_identity_vault_id, issuer_device_id);
        let (device_sequence, previous_operation_hash) = self.heads.get(&participant).map_or_else(
            || Ok((1, [0; 32])),
            |head| {
                Ok::<_, Error>((
                    head.sequence.checked_add(1).ok_or_else(|| {
                        Error::new(
                            ChurStatus::ResourceLimitExceeded,
                            "collection device sequence has no successor",
                        )
                    })?,
                    head.digest,
                ))
            },
        )?;
        let observed_heads = self
            .heads
            .iter()
            .filter(|(observed, _)| {
                **observed != participant
                    && participant_is_active(observed, source_membership, collection_membership)
            })
            .map(|((vault_id, device_id), head)| {
                CollectionObservedHead::new(*vault_id, *device_id, head.sequence)
            })
            .collect();
        let operation = CollectionOperation::seal(
            operation_id,
            issuer_identity_vault_id,
            issuer_device_id,
            device_sequence,
            previous_operation_hash,
            observed_heads,
            self.key_selector,
            key,
            nonce,
            &payload.encode(),
        )?
        .sign(signing_key);
        let mut candidate = self.clone();
        ensure!(
            candidate.accept(
                &operation,
                payload,
                issuer_membership,
                source_membership,
                collection_membership,
            )? == ApplyOutcome::Applied,
            SyncHeadRollback,
            "local collection operation chain is not ready to advance"
        );
        Ok(operation)
    }

    /// Validates and accepts one signed operation from a current participant.
    pub fn accept(
        &mut self,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<ApplyOutcome> {
        self.validate_context(operation, payload, collection_membership)?;
        collection_membership.authorize_collection_operation(
            operation,
            payload,
            issuer_membership,
        )?;
        ensure!(
            source_membership.vault_id() == collection_membership.source_vault_id(),
            AuthenticationFailed,
            "source membership belongs to another vault"
        );
        self.accept_chain(operation, source_membership, collection_membership, false)
    }

    /// Replays one record already committed in the protected local catalog.
    ///
    /// `accept` authorized the record against the membership in force when it
    /// arrived. Replay checks integrity and identity only: a later same-epoch
    /// downgrade (`COLLECTION_MEMBERSHIP.md` §2) or key re-pin changes who may
    /// author next, not whether history already accepted stays valid.
    pub fn restore_accepted(
        &mut self,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<ApplyOutcome> {
        self.validate_context(operation, payload, collection_membership)?;
        ensure!(
            issuer_membership.vault_id() == operation.issuer_identity_vault_id()
                && source_membership.vault_id() == collection_membership.source_vault_id(),
            CatalogCorrupt,
            "restored collection operation membership belongs to another vault"
        );
        let issuer = issuer_membership
            .device(operation.issuer_device_id())
            .ok_or_else(|| Error::new(ChurStatus::CatalogCorrupt, "restored issuer is unknown"))?;
        ensure!(
            issuer
                .signing_public_keys()
                .any(|key| operation.verify_signature(key).is_ok()),
            CatalogCorrupt,
            "restored collection operation signature is invalid"
        );
        if operation.issuer_identity_vault_id() != collection_membership.source_vault_id() {
            ensure!(
                collection_membership
                    .member(
                        operation.issuer_identity_vault_id(),
                        operation.issuer_device_id(),
                    )
                    .is_some(),
                CatalogCorrupt,
                "restored issuer is not a collection member"
            );
            ensure!(
                !matches!(
                    payload.body(),
                    PayloadBody::RewrapObjectKey { .. } | PayloadBody::PurgeObject { .. }
                ),
                CatalogCorrupt,
                "restored collection operation issuer is not authorized"
            );
        }
        self.accept_chain(operation, source_membership, collection_membership, true)
    }

    fn validate_context(
        &self,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        collection_membership: &CollectionMembershipState,
    ) -> Result<()> {
        ensure!(
            operation.key_selector() == &self.key_selector
                && payload.collection_id() == &self.collection_id
                && payload.collection_epoch() == self.collection_epoch
                && collection_membership.collection_id() == &self.collection_id
                && collection_membership.collection_epoch() == self.collection_epoch,
            AuthenticationFailed,
            "collection operation does not match this epoch log"
        );
        payload.validate_for_collection_operation(&self.collection_id, self.collection_epoch)
    }

    fn accept_chain(
        &mut self,
        operation: &CollectionOperation,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
        restore: bool,
    ) -> Result<ApplyOutcome> {
        let participant = (
            *operation.issuer_identity_vault_id(),
            *operation.issuer_device_id(),
        );
        if self.forks.contains_key(&participant) {
            return Err(Error::new(
                ChurStatus::SyncChainFork,
                "collection participant stream is frozen after a fork",
            ));
        }
        let digest = operation.digest();
        let record_key = (participant.0, participant.1, operation.device_sequence());
        if let Some(accepted) = self.accepted.get(&record_key) {
            if accepted.digest == digest {
                return Ok(ApplyOutcome::Duplicate);
            }
            return self.freeze(operation);
        }
        ensure!(
            self.operation_ids
                .get(operation.operation_id())
                .is_none_or(|accepted| accepted == &digest),
            AuthenticationFailed,
            "collection operation identifier was reused at another log position"
        );
        if let Some(head) = self.heads.get(&participant) {
            if operation.device_sequence() < head.sequence {
                return Err(Error::new(
                    ChurStatus::SyncHeadRollback,
                    "collection operation is below the accepted participant head",
                ));
            }
            if operation.device_sequence() > head.sequence.saturating_add(1) {
                return Ok(ApplyOutcome::PendingGap);
            }
            if operation.previous_operation_hash() != &head.digest {
                return self.freeze(operation);
            }
        } else if operation.device_sequence() != 1 {
            return Ok(ApplyOutcome::PendingGap);
        }

        for observed in operation.observed_heads() {
            let observed_participant = (
                *observed.issuer_identity_vault_id(),
                *observed.issuer_device_id(),
            );
            ensure!(
                if restore {
                    participant_is_known(
                        &observed_participant,
                        source_membership,
                        collection_membership,
                    )
                } else {
                    participant_is_active(
                        &observed_participant,
                        source_membership,
                        collection_membership,
                    )
                },
                AuthenticationFailed,
                "collection operation observes an unauthorized participant"
            );
            if self
                .heads
                .get(&observed_participant)
                .is_none_or(|head| head.sequence < observed.device_sequence())
            {
                return Ok(ApplyOutcome::PendingCause);
            }
        }

        self.accepted.insert(
            record_key,
            AcceptedRecord {
                digest,
                bytes: operation.encode(),
            },
        );
        self.operation_ids.insert(*operation.operation_id(), digest);
        self.heads.insert(
            participant,
            AcceptedHead {
                sequence: operation.device_sequence(),
                digest,
            },
        );
        Ok(ApplyOutcome::Applied)
    }

    /// Latest accepted head for one identity-vault device pair.
    #[must_use]
    pub fn head(&self, identity_vault_id: &Id, device_id: &Id) -> Option<(u64, Commitment)> {
        self.heads
            .get(&(*identity_vault_id, *device_id))
            .map(|head| (head.sequence, head.digest))
    }

    /// Fork evidence for one frozen participant stream.
    #[must_use]
    pub fn fork(&self, identity_vault_id: &Id, device_id: &Id) -> Option<&CollectionForkEvidence> {
        self.forks.get(&(*identity_vault_id, *device_id))
    }

    /// Restores fork evidence already committed in the protected catalog.
    pub fn restore_fork(
        &mut self,
        identity_vault_id: Id,
        device_id: Id,
        state: ForkState,
        accepted_record: Vec<u8>,
        conflicting_record: Vec<u8>,
    ) -> Result<()> {
        let accepted = CollectionOperation::decode(&accepted_record)?;
        let conflicting = CollectionOperation::decode(&conflicting_record)?;
        ensure!(
            accepted.key_selector() == &self.key_selector
                && conflicting.key_selector() == &self.key_selector
                && accepted.issuer_identity_vault_id() == &identity_vault_id
                && conflicting.issuer_identity_vault_id() == &identity_vault_id
                && accepted.issuer_device_id() == &device_id
                && conflicting.issuer_device_id() == &device_id,
            CatalogCorrupt,
            "restored collection fork projections disagree"
        );
        self.forks.insert(
            (identity_vault_id, device_id),
            CollectionForkEvidence {
                state,
                accepted_record,
                conflicting_record,
            },
        );
        Ok(())
    }

    /// Collection identifier bound to this log.
    #[must_use]
    pub const fn collection_id(&self) -> &Id {
        &self.collection_id
    }

    /// Collection epoch bound to this log.
    #[must_use]
    pub const fn collection_epoch(&self) -> u64 {
        self.collection_epoch
    }

    /// Opaque selector bound to this log.
    #[must_use]
    pub const fn key_selector(&self) -> &Id {
        &self.key_selector
    }

    fn freeze(&mut self, operation: &CollectionOperation) -> Result<ApplyOutcome> {
        let participant = (
            *operation.issuer_identity_vault_id(),
            *operation.issuer_device_id(),
        );
        let record_key = (participant.0, participant.1, operation.device_sequence());
        let accepted_record = self.accepted.get(&record_key).map_or_else(
            || {
                self.heads
                    .get(&participant)
                    .and_then(|head| {
                        self.accepted
                            .get(&(participant.0, participant.1, head.sequence))
                    })
                    .map_or_else(Vec::new, |record| record.bytes.clone())
            },
            |record| record.bytes.clone(),
        );
        self.forks.insert(
            participant,
            CollectionForkEvidence {
                state: ForkState::Detected,
                accepted_record,
                conflicting_record: operation.encode(),
            },
        );
        Err(Error::new(
            ChurStatus::SyncChainFork,
            "signed collection operation conflicts with the accepted participant stream",
        ))
    }
}

fn participant_is_active(
    participant: &Participant,
    source_membership: &MembershipState,
    collection_membership: &CollectionMembershipState,
) -> bool {
    if &participant.0 == collection_membership.source_vault_id() {
        return source_membership.vault_id() == &participant.0
            && source_membership.is_active(&participant.1);
    }
    collection_membership
        .member(&participant.0, &participant.1)
        .is_some_and(|member| member.is_active())
}

fn participant_is_known(
    participant: &Participant,
    source_membership: &MembershipState,
    collection_membership: &CollectionMembershipState,
) -> bool {
    if &participant.0 == collection_membership.source_vault_id() {
        return source_membership.vault_id() == &participant.0
            && source_membership.device(&participant.1).is_some();
    }
    collection_membership
        .member(&participant.0, &participant.1)
        .is_some()
}
