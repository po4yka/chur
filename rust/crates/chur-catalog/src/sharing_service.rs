//! Outbound collection-sharing orchestration over durable protocol primitives.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Key, Nonce, random};
use chur_format::envelope::CollectionKeyEnvelope;
use chur_sync_protocol::{
    KeyDomain,
    collection_membership::{
        CollectionMembershipAction, CollectionMembershipRecord, CollectionMembershipState,
        RecipientVerification,
    },
    grant::{CollectionGrant, PermissionProfile},
    membership::{EnrollmentRecord, RevocationRecord},
    operation::Operation,
    operation_log::{ApplyOutcome, OperationLog},
    payload::{OperationPayload, PayloadBody},
    state::{DeviceStatus, MembershipState},
};

use crate::{
    CatalogDb,
    model::{COLLECTION_POLICY_SHARED, COLLECTION_STATUS_ACTIVE, Collection},
    schema, sharing, store, sync_keys, sync_log, sync_membership, sync_receive, sync_rotation,
};

/// One canonical record in an issuer identity-membership chain.
#[derive(Clone)]
pub enum IssuerMembershipRecord {
    /// Device enrollment or key rotation.
    Enrollment(EnrollmentRecord),
    /// Device revocation and accepted operation head.
    Revocation(RevocationRecord),
}

/// Complete public evidence needed to authenticate one sharing issuer.
#[derive(Clone, Copy)]
pub struct IssuerEvidence<'a> {
    /// Canonical membership chain from generation one.
    pub membership: &'a [IssuerMembershipRecord],
    /// Complete operation prefixes for every referenced issuer device.
    pub operations: &'a [Operation],
}

/// Canonical records the sender uploads to the sharing relay, in dependency order.
pub struct PreparedShare {
    membership: CollectionMembershipRecord,
    membership_operation: Operation,
    grant: CollectionGrant,
    grant_operation: Operation,
}

impl PreparedShare {
    /// Collection membership change or exact replay needed by the recipient.
    #[must_use]
    pub const fn membership(&self) -> &CollectionMembershipRecord {
        &self.membership
    }

    /// Authenticated source-vault operation that carries the membership change.
    #[must_use]
    pub const fn membership_operation(&self) -> &Operation {
        &self.membership_operation
    }

    /// HPKE grant addressed to the recipient device.
    #[must_use]
    pub const fn grant(&self) -> &CollectionGrant {
        &self.grant
    }

    /// Authenticated source-vault operation that carries the grant.
    #[must_use]
    pub const fn grant_operation(&self) -> &Operation {
        &self.grant_operation
    }
}

/// Durable records produced by one complete forward-only member revocation.
pub struct PreparedShareRevocation {
    membership: CollectionMembershipRecord,
    membership_operation: Operation,
    rotation_operations: Vec<Operation>,
    grants: Vec<(CollectionGrant, Operation)>,
    rotation_complete: bool,
}

impl PreparedShareRevocation {
    /// Signed recipient revocation.
    #[must_use]
    pub const fn membership(&self) -> &CollectionMembershipRecord {
        &self.membership
    }

    /// Outer source-vault operation for the revocation.
    #[must_use]
    pub const fn membership_operation(&self) -> &Operation {
        &self.membership_operation
    }

    /// Newly authored epoch and object-key rewrap operations.
    #[must_use]
    pub fn rotation_operations(&self) -> &[Operation] {
        &self.rotation_operations
    }

    /// Current-epoch grants for every remaining active recipient device.
    #[must_use]
    pub fn grants(&self) -> &[(CollectionGrant, Operation)] {
        &self.grants
    }

    /// Whether eager object-key rewrap reached the end.
    #[must_use]
    pub const fn rotation_complete(&self) -> bool {
        self.rotation_complete
    }
}

/// Adds or updates one recipient and issues its current collection-key grant.
///
/// A retry returns the accepted records instead of advancing either chain.
pub fn prepare_share(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    collection_id: Id,
    recipient_enrollment: &EnrollmentRecord,
    permissions: PermissionProfile,
    fingerprint_verified: bool,
) -> Result<PreparedShare> {
    let recipient_membership = MembershipState::bootstrap(recipient_enrollment)?;
    let recipient_vault_id = *recipient_membership.vault_id();
    let recipient_device_id = *recipient_enrollment.device_id();
    prepare_share_to_device(
        db,
        root,
        source_vault_id,
        collection_id,
        recipient_vault_id,
        recipient_device_id,
        *recipient_enrollment.signing_public_key(),
        *recipient_enrollment.hpke_public_key(),
        permissions,
        fingerprint_verified,
        None,
    )
}

/// Authenticates a recipient vault history and shares to one active device.
#[expect(
    clippy::too_many_arguments,
    reason = "the request names the source, recipient evidence, target device, and policy"
)]
pub fn prepare_share_for_device(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    collection_id: Id,
    recipient: IssuerEvidence<'_>,
    recipient_device_id: Id,
    permissions: PermissionProfile,
    fingerprint_verified: bool,
) -> Result<PreparedShare> {
    let (states, _) = authenticate_issuers(std::slice::from_ref(&recipient))?;
    ensure!(
        states.len() == 1,
        InvalidInput,
        "recipient evidence must contain one identity vault"
    );
    let (recipient_vault_id, history) = states
        .first_key_value()
        .ok_or_else(|| Error::new(ChurStatus::InvalidInput, "recipient evidence is empty"))?;
    let recipient_membership = history
        .last_key_value()
        .map(|(_, state)| state)
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "recipient membership history is empty",
            )
        })?;
    let recipient_device = recipient_membership
        .device(&recipient_device_id)
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "recipient device is not enrolled",
            )
        })?;
    ensure!(
        recipient_device.status() == DeviceStatus::Active,
        AuthenticationFailed,
        "recipient device is revoked"
    );
    prepare_share_to_device(
        db,
        root,
        source_vault_id,
        collection_id,
        *recipient_vault_id,
        recipient_device_id,
        *recipient_device.signing_public_key(),
        *recipient_device.hpke_public_key(),
        permissions,
        fingerprint_verified,
        Some(history),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the internal boundary carries one authenticated recipient device"
)]
fn prepare_share_to_device(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    collection_id: Id,
    recipient_vault_id: Id,
    recipient_device_id: Id,
    recipient_signing_public_key: [u8; 32],
    recipient_hpke_public_key: [u8; 32],
    permissions: PermissionProfile,
    fingerprint_verified: bool,
    recipient_history: Option<&BTreeMap<u64, MembershipState>>,
) -> Result<PreparedShare> {
    ensure!(
        recipient_vault_id != source_vault_id,
        InvalidInput,
        "a source-vault device uses device enrollment instead of sharing"
    );
    let source_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "collection sharing has no local device membership",
        )
    })?;
    ensure!(
        source_membership.vault_id() == &source_vault_id,
        CatalogCorrupt,
        "local membership belongs to another vault"
    );
    let (source_device_id, identity) = sync_keys::local_identity(db, root, &source_membership)?
        .ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "collection sharing has no ordinary local identity",
            )
        })?;
    let collection = store::collection(db, &collection_id)?;
    let mut sharing_state = match sharing::load(db, &collection_id)? {
        Some(state) => state,
        None => sharing::provision(db, source_vault_id, collection_id, collection.current_epoch)?,
    };
    // The membership record and the grant declare the epoch the sharing state
    // holds, so the key they carry must be that epoch's key. `sharing::load`
    // admits the sharing state being one epoch ahead of the collections row
    // while a rotation is settling; sealing the collections row's key under
    // the new epoch's grant would hand the recipient the previous epoch's key
    // labeled as the current one, and `install_share` would store it as the
    // collection key of that epoch. Loading the declared epoch's envelope
    // fails closed when a rotation has not produced it yet.
    let collection_epoch = sharing_state.collection_epoch();
    let collection_key =
        sync_keys::collection_key(db, root, source_vault_id, collection_id, collection_epoch)?;
    let domain = KeyDomain::collection(&collection_key, &collection_id, collection_epoch)?;
    let mut log = sync_log::load(db, &source_membership)?;

    let existing = sharing_state
        .member(&recipient_vault_id, &recipient_device_id)
        .filter(|member| {
            member.is_active()
                && member.signing_public_key() == &recipient_signing_public_key
                && member.hpke_public_key() == &recipient_hpke_public_key
                && member.permissions() == permissions
        })
        .map(|member| member.membership_generation());
    let (membership, membership_operation) = if let Some(generation) = existing {
        let membership = sharing::membership_record_at(db, &collection_id, generation)?;
        let operation = operation_for(
            db,
            membership.issuer_device_id(),
            membership.created_sequence(),
        )?;
        (membership, operation)
    } else {
        if let Some(pin) = sharing_state.recipient_pin(&recipient_vault_id, &recipient_device_id) {
            let changed = pin.signing_public_key() != &recipient_signing_public_key
                || pin.hpke_public_key() != &recipient_hpke_public_key;
            if changed {
                // Keep the new pin in memory until author_sharing_operation
                // writes it with the membership record in one transaction.
                if fingerprint_verified {
                    sharing_state.verify_recipient_keys(
                        recipient_vault_id,
                        recipient_device_id,
                        recipient_signing_public_key,
                        recipient_hpke_public_key,
                    )?;
                } else {
                    let history = recipient_history.ok_or_else(|| {
                        Error::new(
                            ChurStatus::AuthenticationFailed,
                            "recipient key changed without authenticated rotation",
                        )
                    })?;
                    let pairs = device_pairs(history, &recipient_device_id);
                    ensure!(
                        rotation_follows(
                            &pairs,
                            pin.signing_public_key(),
                            pin.hpke_public_key(),
                            &recipient_signing_public_key,
                            &recipient_hpke_public_key
                        ),
                        AuthenticationFailed,
                        "recipient key changed without authenticated rotation"
                    );
                    sharing_state.rotate_recipient_keys(
                        recipient_vault_id,
                        recipient_device_id,
                        recipient_signing_public_key,
                        recipient_hpke_public_key,
                    )?;
                }
            }
        }
        let sequence = next_sequence(&log, &source_device_id)?;
        let membership = CollectionMembershipRecord::new(
            source_vault_id,
            collection_id,
            sharing_state.generation().checked_add(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "collection membership generation has no successor",
                )
            })?,
            *sharing_state.commitment(),
            CollectionMembershipAction::Upsert(permissions),
            recipient_vault_id,
            recipient_device_id,
            recipient_signing_public_key,
            recipient_hpke_public_key,
            sharing_state.collection_epoch(),
            source_vault_id,
            source_device_id,
            source_membership.generation(),
            sequence,
        )?
        .sign(identity.signing_key());
        let operation = sync_receive::author_sharing_operation(
            db,
            &mut log,
            &source_membership,
            &mut sharing_state,
            &domain,
            random::id()?,
            source_device_id,
            identity.signing_key(),
            PayloadBody::ChangeCollectionMembership(membership.clone()),
        )?;
        (membership, operation)
    };

    if fingerprint_verified
        && sharing_state.recipient_verification(&recipient_vault_id, &recipient_device_id)
            != Some(RecipientVerification::Verified)
    {
        sharing_state = sharing::verify_recipient_keys(
            db,
            &collection_id,
            recipient_vault_id,
            recipient_device_id,
            recipient_signing_public_key,
            recipient_hpke_public_key,
        )?;
    }
    let current_generation = sharing_state
        .member(&recipient_vault_id, &recipient_device_id)
        .ok_or_else(|| Error::new(ChurStatus::InternalFailure, "prepared member is absent"))?
        .membership_generation();
    let existing_grant = sharing::load_grants(db, &collection_id)?
        .into_iter()
        .find(|grant| {
            grant.recipient_identity_vault_id() == &recipient_vault_id
                && grant.recipient_device_id() == &recipient_device_id
                && grant.collection_epoch() == sharing_state.collection_epoch()
                && grant.collection_membership_generation() == current_generation
                && grant.permissions() == permissions
        });
    let (grant, grant_operation) = if let Some(grant) = existing_grant {
        let operation = operation_for(db, grant.sender_device_id(), grant.created_sequence())?;
        (grant, operation)
    } else {
        let sequence = next_sequence(&log, &source_device_id)?;
        let grant_id = random::id()?;
        let grant = CollectionGrant::seal(
            grant_id,
            source_vault_id,
            collection_id,
            sharing_state.collection_epoch(),
            current_generation,
            recipient_vault_id,
            recipient_device_id,
            &recipient_hpke_public_key,
            source_device_id,
            permissions,
            source_membership.generation(),
            sequence,
            &collection_key,
            identity.signing_key(),
        )?;
        let operation = sync_receive::author_sharing_operation(
            db,
            &mut log,
            &source_membership,
            &mut sharing_state,
            &domain,
            grant_id,
            source_device_id,
            identity.signing_key(),
            PayloadBody::IssueCollectionGrant(grant.clone()),
        )?;
        (grant, operation)
    };
    Ok(PreparedShare {
        membership,
        membership_operation,
        grant,
        grant_operation,
    })
}

/// Revokes one recipient, rotates the collection, eagerly rewraps every active
/// object key, and issues current grants to all remaining recipients.
#[expect(
    clippy::too_many_arguments,
    reason = "the request names the source, target recipient, time, and batch bound"
)]
pub fn prepare_share_revocation(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    collection_id: Id,
    recipient_vault_id: Id,
    recipient_device_id: Id,
    accepted_at_ms: u64,
    rotation_operation_limit: usize,
) -> Result<PreparedShareRevocation> {
    ensure!(
        rotation_operation_limit != 0,
        InvalidInput,
        "the revocation rotation batch limit is zero"
    );
    let source_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "collection revocation has no local device membership",
        )
    })?;
    ensure!(
        source_membership.vault_id() == &source_vault_id,
        CatalogCorrupt,
        "local membership belongs to another vault"
    );
    let (source_device_id, identity) = sync_keys::local_identity(db, root, &source_membership)?
        .ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "collection revocation has no ordinary local identity",
            )
        })?;
    let mut sharing_state = sharing::load(db, &collection_id)?
        .ok_or_else(|| Error::new(ChurStatus::NotFound, "collection has no sharing membership"))?;
    ensure!(
        sharing_state.source_vault_id() == &source_vault_id,
        AuthenticationFailed,
        "collection belongs to another source vault"
    );
    let target = sharing_state
        .member(&recipient_vault_id, &recipient_device_id)
        .ok_or_else(|| Error::new(ChurStatus::NotFound, "collection recipient is unknown"))?;
    let target_signing_key = *target.signing_public_key();
    let target_hpke_key = *target.hpke_public_key();
    if target.is_active() {
        // A new revocation mints the next epoch, and `sync_rotation::project_begin`
        // refuses to start a second rotation while one is unfinished. Refusing
        // there is too late: the `Revoke` record below commits in its own
        // transaction and has already moved the sharing epoch by the time the
        // rotation is attempted, which leaves the sharing epoch ahead of
        // `collections.current_epoch` with a rotation nothing can finish — a
        // state every later call, for either recipient, re-enters and fails in
        // the same way.
        //
        // The guard is on `is_active` rather than on the whole function because
        // §3.1 of `docs/sync/REVOCATION.md` resumes an unfinished walk by
        // calling this again for the recipient already revoked, and that call
        // must still be admitted.
        ensure!(
            sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?
                .is_complete(),
            Conflict,
            "the collection has an unfinished rotation from an earlier revocation"
        );
    }
    let mut log = sync_log::load(db, &source_membership)?;
    let (membership, membership_operation) = if target.is_active() {
        let old_key = sync_keys::collection_key(
            db,
            root,
            source_vault_id,
            collection_id,
            sharing_state.collection_epoch(),
        )?;
        let old_domain =
            KeyDomain::collection(&old_key, &collection_id, sharing_state.collection_epoch())?;
        let sequence = next_sequence(&log, &source_device_id)?;
        let membership = CollectionMembershipRecord::new(
            source_vault_id,
            collection_id,
            sharing_state.generation().checked_add(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "collection membership generation has no successor",
                )
            })?,
            *sharing_state.commitment(),
            CollectionMembershipAction::Revoke,
            recipient_vault_id,
            recipient_device_id,
            target_signing_key,
            target_hpke_key,
            sharing_state
                .collection_epoch()
                .checked_add(1)
                .ok_or_else(|| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "collection epoch has no successor",
                    )
                })?,
            source_vault_id,
            source_device_id,
            source_membership.generation(),
            sequence,
        )?
        .sign(identity.signing_key());
        let operation = sync_receive::author_sharing_operation(
            db,
            &mut log,
            &source_membership,
            &mut sharing_state,
            &old_domain,
            random::id()?,
            source_device_id,
            identity.signing_key(),
            PayloadBody::ChangeCollectionMembership(membership.clone()),
        )?;
        (membership, operation)
    } else {
        let membership =
            sharing::membership_record_at(db, &collection_id, target.membership_generation())?;
        ensure!(
            membership.action() == CollectionMembershipAction::Revoke
                && membership.recipient_identity_vault_id() == &recipient_vault_id
                && membership.recipient_device_id() == &recipient_device_id,
            CatalogCorrupt,
            "revoked recipient has no matching membership record"
        );
        let operation = operation_for(
            db,
            membership.issuer_device_id(),
            membership.created_sequence(),
        )?;
        (membership, operation)
    };

    let target_epoch = sharing_state.collection_epoch();
    let previous_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "revoked collection has no previous epoch",
        )
    })?;
    let previous_key =
        sync_keys::collection_key(db, root, source_vault_id, collection_id, previous_epoch)?;
    let previous_domain = KeyDomain::collection(&previous_key, &collection_id, previous_epoch)?;
    let mut keys = sync_keys::key_directory(db, root, source_vault_id)?;
    let collection = store::collection(db, &collection_id)?;
    let mut rotation_operations = Vec::new();
    if collection.current_epoch == previous_epoch {
        let current_key: Key = random::secret::<32>()?;
        let envelope = CollectionKeyEnvelope::seal(
            root,
            source_vault_id,
            collection_id,
            target_epoch,
            target_epoch,
            Nonce::random()?,
            &current_key,
        )?;
        rotation_operations.push(sync_receive::author_rotation_operation(
            db,
            &mut log,
            &source_membership,
            &mut keys,
            root,
            &previous_domain,
            source_device_id,
            identity.signing_key(),
            accepted_at_ms,
            &OperationPayload::new(
                collection_id,
                previous_epoch,
                PayloadBody::CreateCollectionEpoch {
                    previous_collection_epoch: previous_epoch,
                    membership_generation: source_membership.generation(),
                    collection_key_envelope: envelope,
                },
            )?,
        )?);
    } else {
        ensure!(
            collection.current_epoch == target_epoch,
            SyncHeadRollback,
            "collection epoch is outside the pending revocation"
        );
    }
    let current_key =
        sync_keys::collection_key(db, root, source_vault_id, collection_id, target_epoch)?;
    let current_domain = KeyDomain::collection(&current_key, &collection_id, target_epoch)?;
    while rotation_operations.len() < rotation_operation_limit {
        let rotation =
            sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?;
        let Some(object_id) = rotation.next_missing_object().copied() else {
            ensure!(
                rotation.is_complete(),
                InternalFailure,
                "collection rotation stopped before eager rewrap completed"
            );
            break;
        };
        let old_envelope = rotation.envelope(&object_id).ok_or_else(|| {
            Error::new(
                ChurStatus::CatalogCorrupt,
                "rotation target has no object-key envelope",
            )
        })?;
        let generation = old_envelope
            .envelope_generation()
            .checked_add(1)
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "object envelope generation has no successor",
                )
            })?;
        let envelope = old_envelope.rewrap(
            &previous_key,
            &current_key,
            collection_id,
            target_epoch,
            generation,
            Nonce::random()?,
        )?;
        rotation_operations.push(sync_receive::author_rotation_operation(
            db,
            &mut log,
            &source_membership,
            &mut keys,
            root,
            &current_domain,
            source_device_id,
            identity.signing_key(),
            accepted_at_ms,
            &OperationPayload::new(
                collection_id,
                target_epoch,
                PayloadBody::RewrapObjectKey {
                    object_id,
                    object_key_commitment: chur_sync_protocol::object_grant::object_key_commitment(
                        &collection_id,
                        &object_id,
                        &envelope.open(&current_key)?,
                    ),
                },
            )?,
        )?);
    }

    let rotation_complete =
        sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?
            .is_complete();
    let mut grants = Vec::new();
    if rotation_complete {
        let recipients = sharing_state
            .active_members()
            .map(|(vault_id, device_id, member)| {
                (
                    *vault_id,
                    *device_id,
                    *member.hpke_public_key(),
                    member.permissions(),
                    member.membership_generation(),
                )
            })
            .collect::<Vec<_>>();
        let existing_grants = sharing::load_grants(db, &collection_id)?;
        grants.reserve(recipients.len());
        for (vault_id, device_id, hpke_key, permissions, generation) in recipients {
            if let Some(grant) = existing_grants.iter().find(|grant| {
                grant.recipient_identity_vault_id() == &vault_id
                    && grant.recipient_device_id() == &device_id
                    && grant.collection_epoch() == target_epoch
                    && grant.collection_membership_generation() == generation
                    && grant.permissions() == permissions
            }) {
                grants.push((
                    grant.clone(),
                    operation_for(db, grant.sender_device_id(), grant.created_sequence())?,
                ));
                continue;
            }
            let sequence = next_sequence(&log, &source_device_id)?;
            let grant_id = random::id()?;
            let grant = CollectionGrant::seal(
                grant_id,
                source_vault_id,
                collection_id,
                target_epoch,
                generation,
                vault_id,
                device_id,
                &hpke_key,
                source_device_id,
                permissions,
                source_membership.generation(),
                sequence,
                &current_key,
                identity.signing_key(),
            )?;
            let operation = sync_receive::author_sharing_operation(
                db,
                &mut log,
                &source_membership,
                &mut sharing_state,
                &current_domain,
                grant_id,
                source_device_id,
                identity.signing_key(),
                PayloadBody::IssueCollectionGrant(grant.clone()),
            )?;
            grants.push((grant, operation));
        }
    }
    Ok(PreparedShareRevocation {
        membership,
        membership_operation,
        rotation_operations,
        grants,
        rotation_complete,
    })
}

/// The operations one source-device-loss epoch rotation publishes.
pub struct PreparedCollectionEpochRotation {
    operations: Vec<Operation>,
    complete: bool,
}

impl PreparedCollectionEpochRotation {
    /// Newly authored epoch and object-key rewrap operations.
    #[must_use]
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Whether eager object-key rewrap reached the end.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}

/// Rotates one shared collection after a device of the source vault was lost.
///
/// [`REVOCATION.md`](../../../docs/sync/REVOCATION.md) §2 rotates affected
/// collection epochs when a vault device is revoked, and
/// [`COLLECTION_MEMBERSHIP.md`](../../../docs/sync/COLLECTION_MEMBERSHIP.md) §2
/// names the authenticated `CreateCollectionEpoch` operation that carries the
/// advance without changing collection membership generation. A recipient
/// revocation advances the epoch through its own revocation record; a lost
/// source device has no record of its own, so the caller invokes this once per
/// shared collection when the vault observes the loss, and the operations
/// publish like any other authored operation.
pub fn prepare_collection_epoch_rotation_after_device_loss(
    db: &mut CatalogDb,
    root: &Key,
    source_vault_id: Id,
    collection_id: Id,
    accepted_at_ms: u64,
    rotation_operation_limit: usize,
) -> Result<PreparedCollectionEpochRotation> {
    ensure!(
        rotation_operation_limit != 0,
        InvalidInput,
        "the rotation batch limit is zero"
    );
    let source_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "collection rotation has no local device membership",
        )
    })?;
    ensure!(
        source_membership.vault_id() == &source_vault_id,
        CatalogCorrupt,
        "local membership belongs to another vault"
    );
    let (source_device_id, identity) = sync_keys::local_identity(db, root, &source_membership)?
        .ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "collection rotation has no ordinary local identity",
            )
        })?;
    let sharing_state = sharing::load(db, &collection_id)?
        .ok_or_else(|| Error::new(ChurStatus::NotFound, "collection has no sharing membership"))?;
    ensure!(
        sharing_state.source_vault_id() == &source_vault_id,
        AuthenticationFailed,
        "collection belongs to another source vault"
    );
    ensure!(
        sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?
            .is_complete(),
        Conflict,
        "the collection has an unfinished rotation from an earlier loss"
    );
    let target_epoch = sharing_state.collection_epoch();
    let previous_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "shared collection has no previous epoch",
        )
    })?;
    let previous_key =
        sync_keys::collection_key(db, root, source_vault_id, collection_id, previous_epoch)?;
    let previous_domain = KeyDomain::collection(&previous_key, &collection_id, previous_epoch)?;
    let mut keys = sync_keys::key_directory(db, root, source_vault_id)?;
    let collection = store::collection(db, &collection_id)?;
    ensure!(
        collection.current_epoch == previous_epoch,
        SyncHeadRollback,
        "collection epoch is outside the pending rotation"
    );
    let mut log = sync_log::load(db, &source_membership)?;
    let mut operations = Vec::new();
    let current_key: Key = random::secret::<32>()?;
    let envelope = CollectionKeyEnvelope::seal(
        root,
        source_vault_id,
        collection_id,
        target_epoch,
        target_epoch,
        Nonce::random()?,
        &current_key,
    )?;
    operations.push(sync_receive::author_rotation_operation(
        db,
        &mut log,
        &source_membership,
        &mut keys,
        root,
        &previous_domain,
        source_device_id,
        identity.signing_key(),
        accepted_at_ms,
        &OperationPayload::new(
            collection_id,
            previous_epoch,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch: previous_epoch,
                membership_generation: source_membership.generation(),
                collection_key_envelope: envelope,
            },
        )?,
    )?);
    let current_domain = KeyDomain::collection(&current_key, &collection_id, target_epoch)?;
    while operations.len() < rotation_operation_limit {
        let rotation =
            sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?;
        let Some(object_id) = rotation.next_missing_object().copied() else {
            ensure!(
                rotation.is_complete(),
                InternalFailure,
                "collection rotation stopped before eager rewrap completed"
            );
            break;
        };
        let old_envelope = rotation.envelope(&object_id).ok_or_else(|| {
            Error::new(
                ChurStatus::CatalogCorrupt,
                "rotation target has no object-key envelope",
            )
        })?;
        let generation = old_envelope
            .envelope_generation()
            .checked_add(1)
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "object envelope generation has no successor",
                )
            })?;
        let envelope = old_envelope.rewrap(
            &previous_key,
            &current_key,
            collection_id,
            target_epoch,
            generation,
            Nonce::random()?,
        )?;
        operations.push(sync_receive::author_rotation_operation(
            db,
            &mut log,
            &source_membership,
            &mut keys,
            root,
            &current_domain,
            source_device_id,
            identity.signing_key(),
            accepted_at_ms,
            &OperationPayload::new(
                collection_id,
                target_epoch,
                PayloadBody::RewrapObjectKey {
                    object_id,
                    object_key_commitment: chur_sync_protocol::object_grant::object_key_commitment(
                        &collection_id,
                        &object_id,
                        &envelope.open(&current_key)?,
                    ),
                },
            )?,
        )?);
    }
    let complete =
        sync_rotation::load(db, source_vault_id, collection_id, &source_membership, root)?
            .is_complete();
    Ok(PreparedCollectionEpochRotation {
        operations,
        complete,
    })
}

/// Authenticates and installs one current grant for the local recipient device.
///
/// Issuer operation logs are checked in memory and are not mixed into the local
/// identity-vault log. The accepted sharing state and wrapped collection key
/// commit in one catalog transaction.
pub fn accept_share(
    db: &mut CatalogDb,
    root: &Key,
    issuers: &[IssuerEvidence<'_>],
    membership_records: &[(CollectionMembershipRecord, Operation)],
    grant: &CollectionGrant,
    grant_operation: &Operation,
) -> Result<CollectionMembershipState> {
    ensure!(
        !membership_records.is_empty(),
        InvalidInput,
        "a share has no collection membership chain"
    );
    let (issuer_states, authenticated_operations) = authenticate_issuers(issuers)?;
    let local_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "share acceptance has no local device membership",
        )
    })?;
    let first = &membership_records[0].0;
    let mut collection_state = CollectionMembershipState::new(
        *first.source_vault_id(),
        *first.collection_id(),
        first.collection_epoch(),
    )?;
    let mut authenticated_rotations = Vec::new();
    for (record, operation) in membership_records {
        let issuer = issuer_state(
            &issuer_states,
            record.issuer_identity_vault_id(),
            record.issuer_membership_generation(),
        )?;
        require_authenticated_operation(&authenticated_operations, operation)?;
        ensure!(
            operation.vault_id() == record.issuer_identity_vault_id()
                && operation.device_id() == record.issuer_device_id()
                && operation.device_sequence() == record.created_sequence(),
            AuthenticationFailed,
            "collection membership does not match its authenticated operation"
        );
        if let Some(pin) = collection_state.recipient_pin(
            record.recipient_identity_vault_id(),
            record.recipient_device_id(),
        ) && (pin.signing_public_key() != record.recipient_signing_public_key()
            || pin.hpke_public_key() != record.recipient_hpke_public_key())
        {
            let pairs = if record.recipient_identity_vault_id() == local_membership.vault_id() {
                sync_membership::device_key_history(db, record.recipient_device_id())?
            } else {
                issuer_states
                    .get(record.recipient_identity_vault_id())
                    .map(|history| device_pairs(history, record.recipient_device_id()))
                    .unwrap_or_default()
            };
            ensure!(
                rotation_follows(
                    &pairs,
                    pin.signing_public_key(),
                    pin.hpke_public_key(),
                    record.recipient_signing_public_key(),
                    record.recipient_hpke_public_key(),
                ),
                AuthenticationFailed,
                "collection recipient key changed without authenticated rotation"
            );
            collection_state.rotate_recipient_keys(
                *record.recipient_identity_vault_id(),
                *record.recipient_device_id(),
                *record.recipient_signing_public_key(),
                *record.recipient_hpke_public_key(),
            )?;
            authenticated_rotations.push(record.collection_membership_generation());
        }
        collection_state.accept(record, issuer)?;
    }
    ensure!(
        u64::try_from(membership_records.len()).ok() == Some(collection_state.generation()),
        AuthenticationFailed,
        "collection membership evidence is not the complete chain"
    );
    ensure!(
        grant.source_vault_id() == collection_state.source_vault_id()
            && grant.collection_id() == collection_state.collection_id(),
        AuthenticationFailed,
        "collection grant belongs to another share"
    );
    require_authenticated_operation(&authenticated_operations, grant_operation)?;
    let current_sender_generation = issuer_states
        .get(grant_operation.vault_id())
        .and_then(|history| history.last_key_value())
        .map(|(generation, _)| *generation)
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "collection grant sender has no authenticated membership",
            )
        })?;
    // An honest grant stays valid under newer evidence, so a source that has
    // since enrolled a device or shared another collection keeps syncing this
    // one. The grant verifies against the state at its own generation, the
    // sender must still be active in the newest supplied state, and the newest
    // supplied state may not end below a generation already accepted.
    ensure!(
        grant.sender_membership_generation() <= current_sender_generation,
        AuthenticationFailed,
        "collection grant sender membership is newer than its evidence"
    );
    ensure_not_below_accepted_issuer(db, grant_operation.vault_id(), current_sender_generation)?;
    let current_sender = issuer_state(
        &issuer_states,
        grant_operation.vault_id(),
        current_sender_generation,
    )?;
    ensure!(
        current_sender
            .device(grant.sender_device_id())
            .is_some_and(|device| device.status() == DeviceStatus::Active),
        AuthenticationFailed,
        "collection grant sender is revoked"
    );
    let sender = issuer_state(
        &issuer_states,
        grant_operation.vault_id(),
        grant.sender_membership_generation(),
    )?;
    ensure!(
        grant_operation.device_id() == grant.sender_device_id()
            && grant_operation.device_sequence() == grant.created_sequence(),
        AuthenticationFailed,
        "collection grant does not match its authenticated operation"
    );
    collection_state.validate_grant(grant, sender)?;

    ensure!(
        local_membership.vault_id() == grant.recipient_identity_vault_id(),
        AuthenticationFailed,
        "collection grant names another recipient vault"
    );
    let (local_device_id, local_identity) = sync_keys::local_identity(db, root, &local_membership)?
        .ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "share acceptance has no ordinary local identity",
            )
        })?;
    let sender_device = sender.device(grant.sender_device_id()).ok_or_else(|| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "collection grant sender is unknown",
        )
    })?;
    let collection_key = grant.open_collection_key(
        local_membership.vault_id(),
        &local_device_id,
        &local_identity,
        sender_device.signing_public_key(),
    )?;
    let domain = KeyDomain::collection(
        &collection_key,
        collection_state.collection_id(),
        collection_state.collection_epoch(),
    )?;
    verify_current_payload(
        grant_operation,
        &domain,
        &PayloadBody::IssueCollectionGrant(grant.clone()),
    )?;
    for (record, operation) in membership_records {
        if operation.key_selector() == domain.selector() {
            verify_current_payload(
                operation,
                &domain,
                &PayloadBody::ChangeCollectionMembership(record.clone()),
            )?;
        }
    }

    install_share(
        db,
        root,
        *local_membership.vault_id(),
        &issuer_states,
        &authenticated_rotations,
        membership_records,
        grant,
        sender,
        &collection_state,
        &collection_key,
        current_sender_generation,
    )?;
    Ok(collection_state)
}

/// Rejects issuer evidence whose chain ends below a generation already relied on.
pub(crate) fn ensure_not_below_accepted_issuer(
    db: &CatalogDb,
    issuer_vault_id: &Id,
    evidence_generation: u64,
) -> Result<()> {
    ensure!(
        evidence_generation >= sharing::issuer_membership_high_water(db, issuer_vault_id)?,
        AuthenticationFailed,
        "issuer membership evidence is below an accepted generation"
    );
    Ok(())
}

pub(crate) type IssuerStates = BTreeMap<Id, BTreeMap<u64, MembershipState>>;
type AuthenticatedOperations = BTreeMap<(Id, Id, u64), Vec<u8>>;

pub(crate) fn authenticate_issuers(
    issuers: &[IssuerEvidence<'_>],
) -> Result<(IssuerStates, AuthenticatedOperations)> {
    let mut states = BTreeMap::new();
    let mut accepted_operations = BTreeMap::new();
    for evidence in issuers {
        let first = evidence.membership.first().ok_or_else(|| {
            Error::new(
                ChurStatus::InvalidInput,
                "an issuer membership chain is empty",
            )
        })?;
        let initial = match first {
            IssuerMembershipRecord::Enrollment(record) => record,
            IssuerMembershipRecord::Revocation(_) => {
                return Err(Error::new(
                    ChurStatus::AuthenticationFailed,
                    "an issuer membership chain does not start with enrollment",
                ));
            }
        };
        let vault_id = *initial.vault_id();
        let mut current = MembershipState::bootstrap(initial)?;
        let mut snapshots = BTreeMap::from([(current.generation(), current.clone())]);
        let mut enrollments = vec![(*initial.issuer_device_id(), initial.created_sequence())];
        let mut revoked = Vec::new();
        for record in &evidence.membership[1..] {
            match record {
                IssuerMembershipRecord::Enrollment(record) => {
                    current.accept_enrollment(
                        record,
                        record.issuer_device_id(),
                        record.created_sequence(),
                    )?;
                    enrollments.push((*record.issuer_device_id(), record.created_sequence()));
                }
                IssuerMembershipRecord::Revocation(record) => {
                    current.accept_revocation(record, record.issuer_device_id())?;
                    revoked.push((
                        *record.revoked_device_id(),
                        record.final_accepted_device_sequence(),
                        *record.final_accepted_operation_digest(),
                    ));
                }
            }
            ensure!(
                snapshots
                    .insert(current.generation(), current.clone())
                    .is_none(),
                AuthenticationFailed,
                "issuer membership repeats a generation"
            );
        }

        let mut log = OperationLog::new();
        let mut pending = evidence.operations.iter().collect::<Vec<_>>();
        while !pending.is_empty() {
            let mut next = Vec::new();
            let mut progressed = false;
            for operation in pending {
                let mut candidate = log.clone();
                match candidate.restore_accepted(operation, &current) {
                    Ok(ApplyOutcome::Applied | ApplyOutcome::Duplicate) => {
                        log = candidate;
                        progressed = true;
                    }
                    Ok(ApplyOutcome::PendingGap | ApplyOutcome::PendingCause) => {
                        next.push(operation);
                    }
                    Err(error) => return Err(error),
                }
            }
            ensure!(
                progressed,
                SyncHeadRollback,
                "issuer operations have a gap or an absent causal predecessor"
            );
            pending = next;
        }
        for operation in evidence.operations {
            let key = (
                vault_id,
                *operation.device_id(),
                operation.device_sequence(),
            );
            let encoded = operation.encode();
            ensure!(
                accepted_operations
                    .insert(key, encoded.clone())
                    .is_none_or(|existing| existing == encoded),
                SyncChainFork,
                "issuer operations conflict at one sequence"
            );
        }
        for (device_id, sequence) in enrollments {
            ensure!(
                accepted_operations.contains_key(&(vault_id, device_id, sequence)),
                SyncHeadRollback,
                "issuer enrollment has no authenticated outer operation"
            );
        }
        for (device_id, sequence, digest) in revoked {
            ensure!(
                if sequence == 0 {
                    digest == [0; 32] && log.head(&device_id).is_none()
                } else {
                    log.head(&device_id) == Some((sequence, digest))
                },
                SyncHeadRollback,
                "revoked issuer operation chain does not reach its pinned head"
            );
        }
        ensure!(
            states.insert(vault_id, snapshots).is_none(),
            InvalidInput,
            "issuer evidence repeats one vault"
        );
    }
    Ok((states, accepted_operations))
}

fn issuer_state<'a>(
    states: &'a IssuerStates,
    vault_id: &Id,
    generation: u64,
) -> Result<&'a MembershipState> {
    states
        .get(vault_id)
        .and_then(|history| history.get(&generation))
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "sharing issuer membership generation is absent",
            )
        })
}

fn device_pairs(
    history: &BTreeMap<u64, MembershipState>,
    device_id: &Id,
) -> Vec<([u8; 32], [u8; 32])> {
    history
        .values()
        .filter_map(|state| {
            state
                .device(device_id)
                .map(|device| (*device.signing_public_key(), *device.hpke_public_key()))
        })
        .collect()
}

fn rotation_follows(
    pairs: &[([u8; 32], [u8; 32])],
    old_signing: &[u8; 32],
    old_hpke: &[u8; 32],
    new_signing: &[u8; 32],
    new_hpke: &[u8; 32],
) -> bool {
    let Some(old_index) = pairs
        .iter()
        .position(|(signing, hpke)| signing == old_signing && hpke == old_hpke)
    else {
        return false;
    };
    pairs
        .iter()
        .skip(old_index + 1)
        .any(|(signing, hpke)| signing == new_signing && hpke == new_hpke)
}

fn require_authenticated_operation(
    operations: &AuthenticatedOperations,
    operation: &Operation,
) -> Result<()> {
    ensure!(
        operations
            .get(&(
                *operation.vault_id(),
                *operation.device_id(),
                operation.device_sequence(),
            ))
            .is_some_and(|accepted| accepted == &operation.encode()),
        AuthenticationFailed,
        "sharing record has no matching authenticated issuer operation"
    );
    Ok(())
}

fn verify_current_payload(
    operation: &Operation,
    domain: &KeyDomain,
    expected: &PayloadBody,
) -> Result<()> {
    ensure!(
        operation.key_selector() == domain.selector(),
        AuthenticationFailed,
        "sharing operation uses another collection key selector"
    );
    let payload = OperationPayload::decode(&operation.open_payload(domain.operation_key())?)?;
    payload.validate_for_operation(operation, domain.collection_id(), domain.collection_epoch())?;
    ensure!(
        payload.body() == expected,
        AuthenticationFailed,
        "sharing operation carries another canonical record"
    );
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the transaction receives the authenticated share and its local wrapping context"
)]
fn install_share(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    issuer_states: &IssuerStates,
    authenticated_rotations: &[u64],
    membership_records: &[(CollectionMembershipRecord, Operation)],
    grant: &CollectionGrant,
    sender: &MembershipState,
    incoming: &CollectionMembershipState,
    collection_key: &Key,
    evidence_generation: u64,
) -> Result<()> {
    let existing_state = sharing::load(db, incoming.collection_id())?;
    let existing_collection = match store::collection(db, incoming.collection_id()) {
        Ok(collection) => Some(collection),
        Err(error) if error.status() == ChurStatus::NotFound => None,
        Err(error) => return Err(error),
    };
    ensure!(
        existing_state.is_some() == existing_collection.is_some(),
        CatalogCorrupt,
        "shared collection and authorization state are incomplete"
    );
    let accepted_generation = existing_state
        .as_ref()
        .map_or(0, CollectionMembershipState::generation);
    ensure!(
        accepted_generation <= incoming.generation(),
        SyncHeadRollback,
        "incoming collection membership rolls back durable state"
    );
    let accepted_records = usize::try_from(accepted_generation).map_err(|_| {
        Error::new(
            ChurStatus::ResourceLimitExceeded,
            "accepted membership generation exceeds the address space",
        )
    })?;
    for (record, _) in membership_records.iter().take(accepted_records) {
        ensure!(
            sharing::membership_record_at(
                db,
                incoming.collection_id(),
                record.collection_membership_generation(),
            )?
            .encode()
                == record.encode(),
            SyncChainFork,
            "incoming collection membership conflicts with durable history"
        );
    }
    if let Some(collection) = existing_collection {
        ensure!(
            collection.policy_type == COLLECTION_POLICY_SHARED
                && collection.status == COLLECTION_STATUS_ACTIVE
                && collection.current_epoch <= incoming.collection_epoch(),
            Conflict,
            "collection identifier already has another local policy or epoch"
        );
    }
    let existing_grant = sharing::load_grants(db, incoming.collection_id())?
        .into_iter()
        .any(|stored| stored.encode() == grant.encode());
    let existing_envelope = if existing_collection
        .is_some_and(|collection| collection.current_epoch == incoming.collection_epoch())
    {
        let body = store::active_collection_envelope(
            db,
            incoming.collection_id(),
            incoming.collection_epoch(),
        )?;
        ensure!(
            sync_keys::collection_key(
                db,
                root,
                local_vault_id,
                *incoming.collection_id(),
                incoming.collection_epoch(),
            )?
            .expose()
                == collection_key.expose(),
            AuthenticationFailed,
            "incoming grant changes the accepted collection key"
        );
        Some(body)
    } else {
        None
    };
    if accepted_generation == incoming.generation() && existing_grant && existing_envelope.is_some()
    {
        return Ok(());
    }

    let envelope = existing_envelope.map_or_else(
        || {
            CollectionKeyEnvelope::seal(
                root,
                local_vault_id,
                *incoming.collection_id(),
                incoming.collection_epoch(),
                1,
                Nonce::random()?,
                collection_key,
            )
            .map(|envelope| envelope.encode())
        },
        Ok,
    )?;
    let created_revision = existing_collection.map_or_else(
        || {
            schema::generation(db)?.checked_add(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "catalog generation has no successor",
                )
            })
        },
        |collection| Ok(collection.created_revision),
    )?;
    let collection = Collection {
        collection_id: *incoming.collection_id(),
        current_epoch: incoming.collection_epoch(),
        policy_type: COLLECTION_POLICY_SHARED,
        created_revision,
        status: COLLECTION_STATUS_ACTIVE,
    };
    db.transaction(|transaction| {
        store::project_collection_with_envelope(transaction, &collection, 1, &envelope)?;
        let mut current = match &existing_state {
            Some(state) => state.clone(),
            None => {
                let state = CollectionMembershipState::new(
                    *incoming.source_vault_id(),
                    *incoming.collection_id(),
                    membership_records[0].0.collection_epoch(),
                )?;
                sharing::project_provision(transaction, &state)?;
                state
            }
        };
        for (record, _) in membership_records.iter().skip(accepted_records) {
            if authenticated_rotations.contains(&record.collection_membership_generation()) {
                current = sharing::project_recipient_rotation(
                    transaction,
                    &current,
                    *record.recipient_identity_vault_id(),
                    *record.recipient_device_id(),
                    *record.recipient_signing_public_key(),
                    *record.recipient_hpke_public_key(),
                )?;
            }
            let issuer = issuer_state(
                issuer_states,
                record.issuer_identity_vault_id(),
                record.issuer_membership_generation(),
            )?;
            current = sharing::project_membership(transaction, &current, record, issuer)?.0;
        }
        ensure!(
            current.generation() == incoming.generation()
                && current.commitment() == incoming.commitment()
                && current.collection_epoch() == incoming.collection_epoch(),
            AuthenticationFailed,
            "projected share does not match authenticated state"
        );
        sharing::project_grant(transaction, &current, grant, sender)?;
        sharing::raise_issuer_membership_mark(transaction, sender.vault_id(), evidence_generation)?;
        schema::bump_generation(transaction)?;
        Ok(())
    })
}

fn next_sequence(log: &sync_log::DurableOperationLog, device_id: &Id) -> Result<u64> {
    log.head(device_id).map_or(Ok(1), |(sequence, _)| {
        sequence.checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "local operation sequence has no successor",
            )
        })
    })
}

fn operation_for(db: &CatalogDb, device_id: &Id, sequence: u64) -> Result<Operation> {
    let bytes = sync_log::record_at(db, device_id, sequence)?.ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "sharing record has no authenticated outer operation",
        )
    })?;
    Operation::decode(&bytes).map_err(|_| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "sharing outer operation is malformed",
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
    use chur_sync_protocol::identity::DeviceIdentity;
    use chur_sync_protocol::membership::RevocationRecord;
    use chur_sync_protocol::operation::DeviceSigningKey;

    use super::*;
    use crate::{
        db::{CatalogKey, CatalogLocation},
        model::{
            COLLECTION_POLICY_SHARED, COLLECTION_POLICY_VAULT_DEFAULT, COLLECTION_STATUS_ACTIVE,
            Collection,
        },
        schema,
    };
    use chur_crypto::Nonce;
    use chur_sync_protocol::object_grant::{ObjectKeyGrant, ObjectPrekey};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    #[test]
    fn authenticated_recipient_rotations_keep_tofu_and_reject_substitution() {
        let source_vault = id(41);
        let collection_id = id(42);
        let root = Key::new([43; 32]);
        let catalog_key = CatalogKey::derive(&root, &source_vault).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        sync_receive::provision_local_identity(&mut db, &root, source_vault)
            .expect("source identity");
        let collection_key = Key::new([44; 32]);
        let envelope = CollectionKeyEnvelope::seal(
            &root,
            source_vault,
            collection_id,
            1,
            1,
            Nonce::new([45; 24]),
            &collection_key,
        )
        .expect("envelope");
        store::put_collection_with_envelope(
            &mut db,
            &Collection {
                collection_id,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &envelope.encode(),
        )
        .expect("collection");

        let vault = id(46);
        let device = id(47);
        let original = DeviceIdentity::from_seeds([48; 32], [49; 32]);
        let hpke_rotated = DeviceIdentity::from_seeds([48; 32], [50; 32]);
        let both_rotated = DeviceIdentity::from_seeds([51; 32], [50; 32]);
        let initial = EnrollmentRecord::initial(
            vault,
            device,
            original.signing_public_key(),
            original.hpke_public_key(),
        )
        .expect("initial")
        .sign(original.signing_key());
        prepare_share(
            &mut db,
            &root,
            source_vault,
            collection_id,
            &initial,
            PermissionProfile::Read,
            false,
        )
        .expect("initial share");
        let mut state = MembershipState::bootstrap(&initial).expect("membership");
        let operation_key = Key::new([52; 32]);
        let selector = id(53);
        let mut log = OperationLog::new();
        let first_outer = log
            .author(
                id(54),
                vault,
                device,
                selector,
                &operation_key,
                Nonce::new([55; 24]),
                b"initial",
                original.signing_key(),
                &state,
            )
            .expect("initial outer");
        log.accept(&first_outer, &state)
            .expect("accept initial outer");
        let first_rotation = EnrollmentRecord::new(
            vault,
            device,
            hpke_rotated.signing_public_key(),
            hpke_rotated.hpke_public_key(),
            2,
            device,
            2,
            *state.commitment(),
            [56; 32],
        )
        .expect("hpke rotation")
        .sign(original.signing_key());
        let second_outer = log
            .author(
                id(57),
                vault,
                device,
                selector,
                &operation_key,
                Nonce::new([58; 24]),
                b"hpke rotation",
                original.signing_key(),
                &state,
            )
            .expect("rotation outer");
        log.accept(&second_outer, &state)
            .expect("accept rotation outer");
        state
            .accept_enrollment(&first_rotation, &device, 2)
            .expect("accept hpke rotation");
        let records = [
            IssuerMembershipRecord::Enrollment(initial.clone()),
            IssuerMembershipRecord::Enrollment(first_rotation.clone()),
        ];
        let operations = [first_outer.clone(), second_outer.clone()];
        db.connection()
            .execute_batch(
                "CREATE TRIGGER reject_rotated_membership
                 BEFORE INSERT ON sharing_membership_records
                 WHEN NEW.membership_generation = 2
                 BEGIN SELECT RAISE(ABORT, 'test rejection'); END;",
            )
            .expect("install failure trigger");
        assert!(
            prepare_share_for_device(
                &mut db,
                &root,
                source_vault,
                collection_id,
                IssuerEvidence {
                    membership: &records,
                    operations: &operations,
                },
                device,
                PermissionProfile::Read,
                false,
            )
            .is_err()
        );
        let after_failure = sharing::load(&db, &collection_id)
            .expect("state still replays")
            .expect("sharing");
        assert_eq!(after_failure.generation(), 1);
        let pin = after_failure
            .recipient_pin(&vault, &device)
            .expect("old pin");
        assert_eq!(pin.signing_public_key(), &original.signing_public_key());
        assert_eq!(pin.hpke_public_key(), &original.hpke_public_key());
        db.connection()
            .execute_batch("DROP TRIGGER reject_rotated_membership")
            .expect("drop failure trigger");
        let rotated = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &records,
                operations: &operations,
            },
            device,
            PermissionProfile::Read,
            false,
        )
        .expect("authenticated hpke rotation");
        assert_eq!(
            rotated.membership().recipient_hpke_public_key(),
            &hpke_rotated.hpke_public_key()
        );
        let persisted = sharing::load(&db, &collection_id)
            .expect("reload")
            .expect("sharing");
        assert!(
            persisted.recipient_verification(&vault, &device)
                == Some(RecipientVerification::TrustOnFirstUse)
        );

        let substituted = DeviceIdentity::from_seeds([59; 32], [60; 32]);
        let forged_history = EnrollmentRecord::new(
            vault,
            device,
            substituted.signing_public_key(),
            substituted.hpke_public_key(),
            3,
            device,
            3,
            *state.commitment(),
            [61; 32],
        )
        .expect("substitution")
        .sign(substituted.signing_key());
        let forged_records = [
            IssuerMembershipRecord::Enrollment(initial.clone()),
            IssuerMembershipRecord::Enrollment(first_rotation.clone()),
            IssuerMembershipRecord::Enrollment(forged_history),
        ];
        assert!(
            prepare_share_for_device(
                &mut db,
                &root,
                source_vault,
                collection_id,
                IssuerEvidence {
                    membership: &forged_records,
                    operations: &operations
                },
                device,
                PermissionProfile::Read,
                false,
            )
            .is_err()
        );

        let second_rotation = EnrollmentRecord::new(
            vault,
            device,
            both_rotated.signing_public_key(),
            both_rotated.hpke_public_key(),
            3,
            device,
            3,
            *state.commitment(),
            [61; 32],
        )
        .expect("signing rotation")
        .sign(hpke_rotated.signing_key());
        let third_outer = log
            .author(
                id(62),
                vault,
                device,
                selector,
                &operation_key,
                Nonce::new([63; 24]),
                b"signing rotation",
                hpke_rotated.signing_key(),
                &state,
            )
            .expect("second rotation outer");
        let records = [
            IssuerMembershipRecord::Enrollment(initial),
            IssuerMembershipRecord::Enrollment(first_rotation),
            IssuerMembershipRecord::Enrollment(second_rotation),
        ];
        let operations = [first_outer, second_outer, third_outer];
        let rotated = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &records,
                operations: &operations,
            },
            device,
            PermissionProfile::Read,
            false,
        )
        .expect("authenticated signing rotation");
        assert_eq!(
            rotated.membership().recipient_signing_public_key(),
            &both_rotated.signing_public_key()
        );
        let persisted = sharing::load(&db, &collection_id)
            .expect("reload")
            .expect("sharing");
        assert!(
            persisted.recipient_verification(&vault, &device)
                == Some(RecipientVerification::TrustOnFirstUse)
        );
        let verified = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &records,
                operations: &operations,
            },
            device,
            PermissionProfile::Read,
            true,
        )
        .expect("verify unchanged recipient keys");
        assert_eq!(
            verified.membership().encode(),
            rotated.membership().encode()
        );
        let persisted = sharing::load(&db, &collection_id)
            .expect("reload verification")
            .expect("sharing");
        assert_eq!(persisted.generation(), 3);
        assert!(
            persisted.recipient_verification(&vault, &device)
                == Some(RecipientVerification::Verified)
        );
    }

    #[test]
    fn multi_recipient_device_loss_rotates_forward_and_replays() {
        let source_vault = id(1);
        let collection_id = id(2);
        let root = Key::new([3; 32]);
        let catalog_key = CatalogKey::derive(&root, &source_vault).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        sync_receive::provision_local_identity(&mut db, &root, source_vault)
            .expect("local identity");
        let collection_key = Key::new([4; 32]);
        let envelope = CollectionKeyEnvelope::seal(
            &root,
            source_vault,
            collection_id,
            1,
            1,
            Nonce::new([5; 24]),
            &collection_key,
        )
        .expect("collection envelope");
        store::put_collection_with_envelope(
            &mut db,
            &Collection {
                collection_id,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &envelope.encode(),
        )
        .expect("collection");
        let object_id = id(14);
        let object_key = Key::new([15; 32]);
        let object_envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            source_vault,
            collection_id,
            1,
            object_id,
            1,
            Nonce::new([16; 24]),
            &object_key,
        )
        .expect("object envelope");
        db.transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO objects VALUES (
                         ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 72
                     )",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                        id(17).as_bytes().as_slice(),
                    ],
                )
                .expect("object");
            transaction
                .execute(
                    "INSERT INTO object_key_envelopes VALUES (?1, 1, 1, ?2)",
                    rusqlite::params![object_id.as_bytes().as_slice(), object_envelope.encode(),],
                )
                .expect("object envelope");
            transaction
                .execute(
                    "INSERT INTO sync_object_envelope_epochs VALUES (?1, ?2, 1, 1)",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                    ],
                )
                .expect("envelope projection");
            Ok(())
        })
        .expect("object projection");
        let recipient_vault = id(6);
        let recipient_device = id(7);
        let recipient = DeviceIdentity::from_seeds([8; 32], [9; 32]);
        let enrollment = EnrollmentRecord::initial(
            recipient_vault,
            recipient_device,
            recipient.signing_public_key(),
            recipient.hpke_public_key(),
        )
        .expect("recipient enrollment")
        .sign(recipient.signing_key());

        let first = prepare_share(
            &mut db,
            &root,
            source_vault,
            collection_id,
            &enrollment,
            PermissionProfile::Contribute,
            true,
        )
        .expect("share");
        let replay = prepare_share(
            &mut db,
            &root,
            source_vault,
            collection_id,
            &enrollment,
            PermissionProfile::Contribute,
            true,
        )
        .expect("replay");
        let source_membership = sync_membership::load(&db)
            .expect("source membership")
            .expect("present");
        let source_key = source_membership
            .device(first.grant().sender_device_id())
            .expect("sender")
            .signing_public_key();
        assert_eq!(
            first
                .grant()
                .open_collection_key(&recipient_vault, &recipient_device, &recipient, source_key,)
                .expect("open")
                .expose(),
            collection_key.expose()
        );
        assert_eq!(first.membership().encode(), replay.membership().encode());
        assert_eq!(first.grant().encode(), replay.grant().encode());
        assert_eq!(
            first.membership_operation().encode(),
            replay.membership_operation().encode()
        );
        assert_eq!(
            first.grant_operation().encode(),
            replay.grant_operation().encode()
        );
        assert!(
            sharing::load(&db, &collection_id)
                .expect("sharing state")
                .expect("present")
                .recipient_verification(&recipient_vault, &recipient_device)
                == Some(RecipientVerification::Verified)
        );
        assert_eq!(
            sync_log::records_after(&db, first.grant().sender_device_id(), 0)
                .expect("operations")
                .len(),
            3
        );

        let second_vault = id(10);
        let second_device = id(11);
        let second = DeviceIdentity::from_seeds([12; 32], [13; 32]);
        let second_enrollment = EnrollmentRecord::initial(
            second_vault,
            second_device,
            second.signing_public_key(),
            second.hpke_public_key(),
        )
        .expect("second enrollment")
        .sign(second.signing_key());
        let mut recipient_membership =
            MembershipState::bootstrap(&second_enrollment).expect("recipient membership");
        let recipient_operation_key = Key::new([21; 32]);
        let recipient_selector = id(22);
        let mut recipient_log = OperationLog::new();
        let initial_operation = recipient_log
            .author(
                id(23),
                second_vault,
                second_device,
                recipient_selector,
                &recipient_operation_key,
                Nonce::new([24; 24]),
                b"initial",
                second.signing_key(),
                &recipient_membership,
            )
            .expect("initial operation");
        assert!(
            recipient_log
                .accept(&initial_operation, &recipient_membership)
                .is_ok()
        );
        let peer_device = id(25);
        let peer = DeviceIdentity::from_seeds([26; 32], [27; 32]);
        let peer_enrollment = EnrollmentRecord::new(
            second_vault,
            peer_device,
            peer.signing_public_key(),
            peer.hpke_public_key(),
            2,
            second_device,
            2,
            *recipient_membership.commitment(),
            [28; 32],
        )
        .expect("peer enrollment")
        .sign(second.signing_key());
        let peer_operation = recipient_log
            .author(
                id(29),
                second_vault,
                second_device,
                recipient_selector,
                &recipient_operation_key,
                Nonce::new([30; 24]),
                b"peer",
                second.signing_key(),
                &recipient_membership,
            )
            .expect("peer operation");
        recipient_membership
            .accept_enrollment(&peer_enrollment, &second_device, 2)
            .expect("accept peer");
        let recipient_records = [
            IssuerMembershipRecord::Enrollment(second_enrollment.clone()),
            IssuerMembershipRecord::Enrollment(peer_enrollment),
        ];
        let recipient_operations = [initial_operation, peer_operation];
        let incomplete_recipient = IssuerEvidence {
            membership: &recipient_records,
            operations: &recipient_operations[..1],
        };
        let Err(error) = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            incomplete_recipient,
            peer_device,
            PermissionProfile::Read,
            true,
        ) else {
            panic!("incomplete recipient evidence was accepted");
        };
        assert_eq!(error.status(), ChurStatus::SyncHeadRollback);
        let second_primary_share = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &recipient_records,
                operations: &recipient_operations,
            },
            second_device,
            PermissionProfile::Read,
            true,
        )
        .expect("second primary share");
        let second_share = prepare_share_for_device(
            &mut db,
            &root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &recipient_records,
                operations: &recipient_operations,
            },
            peer_device,
            PermissionProfile::Read,
            true,
        )
        .expect("second share");
        assert_eq!(second_share.grant().recipient_device_id(), &peer_device);
        assert_eq!(
            second_share
                .grant()
                .open_collection_key(&second_vault, &peer_device, &peer, source_key)
                .expect("peer grant")
                .expose(),
            collection_key.expose()
        );
        let revoked = prepare_share_revocation(
            &mut db,
            &root,
            source_vault,
            collection_id,
            second_vault,
            peer_device,
            1_000,
            1,
        )
        .expect("revoke share");
        assert!(revoked.membership().action() == CollectionMembershipAction::Revoke);
        assert!(!revoked.rotation_complete());
        assert_eq!(revoked.rotation_operations().len(), 1);
        assert!(revoked.grants().is_empty());
        // A second recipient cannot be revoked while the first rewrap is
        // unfinished, and the refusal writes nothing: the `Revoke` record used
        // to commit before the rotation was attempted, which left the sharing
        // epoch ahead of the collection's with a rotation nothing could finish.
        let Err(conflict) = prepare_share_revocation(
            &mut db,
            &root,
            source_vault,
            collection_id,
            second_vault,
            second_device,
            1_200,
            4_096,
        ) else {
            panic!("a second revocation started over an unfinished rotation");
        };
        assert_eq!(conflict.status(), ChurStatus::Conflict);
        assert_eq!(
            sharing::load(&db, &collection_id)
                .expect("sharing state")
                .expect("present")
                .collection_epoch(),
            2
        );
        // The pending rotation is still resumable, which the rest of this test
        // then proves by finishing it.
        let continued = prepare_share_revocation(
            &mut db,
            &root,
            source_vault,
            collection_id,
            second_vault,
            peer_device,
            1_500,
            4_096,
        )
        .expect("continue revocation");
        assert!(continued.rotation_complete());
        assert_eq!(continued.rotation_operations().len(), 1);
        assert_eq!(continued.grants().len(), 2);
        assert!(continued.grants().iter().all(|(grant, _)| {
            grant.collection_epoch() == 2 && grant.recipient_device_id() != &peer_device
        }));
        let first_remaining = continued
            .grants()
            .iter()
            .find(|(grant, _)| grant.recipient_device_id() == &recipient_device)
            .expect("first recipient grant")
            .0
            .open_collection_key(&recipient_vault, &recipient_device, &recipient, source_key)
            .expect("first recipient rotated key");
        let second_remaining = continued
            .grants()
            .iter()
            .find(|(grant, _)| grant.recipient_device_id() == &second_device)
            .expect("second recipient primary grant")
            .0
            .open_collection_key(&second_vault, &second_device, &second, source_key)
            .expect("second recipient rotated key");
        assert_eq!(first_remaining.expose(), second_remaining.expose());
        let rotation =
            sync_rotation::load(&db, source_vault, collection_id, &source_membership, &root)
                .expect("rotation");
        assert_eq!(
            rotation
                .envelope(&object_id)
                .expect("rewrapped object")
                .open(&first_remaining)
                .expect("open rewrapped object")
                .expose(),
            object_key.expose()
        );
        let replayed_revocation = prepare_share_revocation(
            &mut db,
            &root,
            source_vault,
            collection_id,
            second_vault,
            peer_device,
            2_000,
            4_096,
        )
        .expect("replay revocation");
        assert_eq!(
            revoked.membership().encode(),
            replayed_revocation.membership().encode()
        );
        assert!(replayed_revocation.rotation_operations().is_empty());
        assert_eq!(replayed_revocation.grants().len(), 2);
        assert_eq!(
            continued
                .grants()
                .iter()
                .map(|(grant, _)| grant.encode())
                .collect::<Vec<_>>(),
            replayed_revocation
                .grants()
                .iter()
                .map(|(grant, _)| grant.encode())
                .collect::<Vec<_>>()
        );
        let final_state = sharing::load(&db, &collection_id)
            .expect("sharing state")
            .expect("present");
        assert_eq!(final_state.collection_epoch(), 2);
        assert!(
            final_state
                .validate_grant(first.grant(), &source_membership)
                .is_err()
        );
        assert!(
            final_state
                .validate_grant(second_primary_share.grant(), &source_membership)
                .is_err()
        );
        assert!(
            final_state
                .validate_grant(second_share.grant(), &source_membership)
                .is_err()
        );
    }

    #[test]
    fn a_share_in_a_pending_rotation_window_fails_closed_rather_than_mismatching_the_epoch() {
        let source_vault = id(1);
        let collection_id = id(2);
        let root = Key::new([3; 32]);
        let catalog_key = CatalogKey::derive(&root, &source_vault).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        sync_receive::provision_local_identity(&mut db, &root, source_vault)
            .expect("local identity");
        let collection_key = Key::new([4; 32]);
        let envelope = CollectionKeyEnvelope::seal(
            &root,
            source_vault,
            collection_id,
            1,
            1,
            Nonce::new([5; 24]),
            &collection_key,
        )
        .expect("collection envelope");
        store::put_collection_with_envelope(
            &mut db,
            &Collection {
                collection_id,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &envelope.encode(),
        )
        .expect("collection");
        let object_id = id(14);
        let object_key = Key::new([15; 32]);
        let object_envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            source_vault,
            collection_id,
            1,
            object_id,
            1,
            Nonce::new([16; 24]),
            &object_key,
        )
        .expect("object envelope");
        db.transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO objects VALUES (
                         ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 72
                     )",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                        id(17).as_bytes().as_slice(),
                    ],
                )
                .expect("object");
            transaction
                .execute(
                    "INSERT INTO object_key_envelopes VALUES (?1, 1, 1, ?2)",
                    rusqlite::params![object_id.as_bytes().as_slice(), object_envelope.encode(),],
                )
                .expect("object envelope");
            transaction
                .execute(
                    "INSERT INTO sync_object_envelope_epochs VALUES (?1, ?2, 1, 1)",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                    ],
                )
                .expect("envelope projection");
            Ok(())
        })
        .expect("object projection");

        let recipient_vault = id(6);
        let first_device = id(7);
        let first_recipient = DeviceIdentity::from_seeds([8; 32], [9; 32]);
        let first_enrollment = EnrollmentRecord::initial(
            recipient_vault,
            first_device,
            first_recipient.signing_public_key(),
            first_recipient.hpke_public_key(),
        )
        .expect("first enrollment")
        .sign(first_recipient.signing_key());
        let settled = prepare_share(
            &mut db,
            &root,
            source_vault,
            collection_id,
            &first_enrollment,
            PermissionProfile::Read,
            true,
        )
        .expect("settled share");
        assert_eq!(settled.grant().collection_epoch(), 1);
        assert_eq!(
            settled
                .grant()
                .open_collection_key(
                    &recipient_vault,
                    &first_device,
                    &first_recipient,
                    sync_membership::load(&db)
                        .expect("membership")
                        .expect("present")
                        .device(settled.grant().sender_device_id())
                        .expect("sender")
                        .signing_public_key(),
                )
                .expect("grant key")
                .expose(),
            collection_key.expose()
        );

        // The window `sharing::load` admits: a projected revocation advanced
        // the sharing state's epoch, while the rotation operation that carries
        // the new epoch's envelope has not landed, so the collections row and
        // the envelope store are still at epoch 1.
        db.connection()
            .execute(
                "UPDATE sharing_collections SET current_epoch = 2 WHERE collection_id = ?1",
                rusqlite::params![collection_id.as_bytes().as_slice()],
            )
            .expect("pending rotation window");

        // A share prepared in that window must fail closed. The previous code
        // sealed the collections row's epoch-1 key under the new epoch's
        // grant; a recipient would have installed the epoch-1 key as the
        // collection key of epoch 2 (`install_share`).
        let second_device = id(11);
        let second_recipient = DeviceIdentity::from_seeds([12; 32], [13; 32]);
        let second_enrollment = EnrollmentRecord::initial(
            recipient_vault,
            second_device,
            second_recipient.signing_public_key(),
            second_recipient.hpke_public_key(),
        )
        .expect("second enrollment")
        .sign(second_recipient.signing_key());
        let Err(refused) = prepare_share(
            &mut db,
            &root,
            source_vault,
            collection_id,
            &second_enrollment,
            PermissionProfile::Read,
            true,
        ) else {
            panic!("a share was prepared for an epoch that has no key envelope");
        };
        assert_eq!(refused.status(), ChurStatus::NotFound);
    }

    #[test]
    fn recipient_authenticates_and_installs_a_share_atomically() {
        let source_vault = id(21);
        let collection_id = id(22);
        let source_root = Key::new([23; 32]);
        let source_catalog_key = CatalogKey::derive(&source_root, &source_vault).expect("key");
        let mut source =
            CatalogDb::open(&CatalogLocation::Memory, &source_catalog_key).expect("source");
        schema::open_at_current_version(&mut source, 1).expect("schema");
        sync_receive::provision_local_identity(&mut source, &source_root, source_vault)
            .expect("source identity");
        let source_collection_key = Key::new([24; 32]);
        let source_envelope = CollectionKeyEnvelope::seal(
            &source_root,
            source_vault,
            collection_id,
            1,
            1,
            Nonce::new([25; 24]),
            &source_collection_key,
        )
        .expect("source envelope");
        store::put_collection_with_envelope(
            &mut source,
            &Collection {
                collection_id,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &source_envelope.encode(),
        )
        .expect("source collection");
        let other_collection_id = id(62);
        let other_envelope = CollectionKeyEnvelope::seal(
            &source_root,
            source_vault,
            other_collection_id,
            1,
            1,
            Nonce::new([63; 24]),
            &Key::new([64; 32]),
        )
        .expect("other envelope");
        store::put_collection_with_envelope(
            &mut source,
            &Collection {
                collection_id: other_collection_id,
                current_epoch: 1,
                policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: COLLECTION_STATUS_ACTIVE,
            },
            1,
            &other_envelope.encode(),
        )
        .expect("other collection");

        let recipient_vault = id(26);
        let recipient_root = Key::new([27; 32]);
        let recipient_catalog_key =
            CatalogKey::derive(&recipient_root, &recipient_vault).expect("recipient key");
        let mut recipient =
            CatalogDb::open(&CatalogLocation::Memory, &recipient_catalog_key).expect("recipient");
        schema::open_at_current_version(&mut recipient, 1).expect("schema");
        let (recipient_enrollment, _) = sync_receive::provision_local_identity(
            &mut recipient,
            &recipient_root,
            recipient_vault,
        )
        .expect("recipient identity");
        let prepared = prepare_share(
            &mut source,
            &source_root,
            source_vault,
            collection_id,
            &recipient_enrollment,
            PermissionProfile::Read,
            true,
        )
        .expect("prepare share");
        let source_device = *prepared.grant().sender_device_id();
        let source_enrollment =
            sync_membership::enrollment_for_device(&source, &source_device).expect("enrollment");
        let operations = sync_log::records_after(&source, &source_device, 0)
            .expect("source operations")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        let evidence = IssuerEvidence {
            membership: &[IssuerMembershipRecord::Enrollment(
                source_enrollment.clone(),
            )],
            operations: &operations,
        };
        let membership = [(
            prepared.membership().clone(),
            prepared.membership_operation().clone(),
        )];
        let before = schema::generation(&recipient).expect("generation");
        let Err(error) = accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: evidence.membership,
                operations: &operations[1..],
            }],
            &membership,
            prepared.grant(),
            prepared.grant_operation(),
        ) else {
            panic!("incomplete issuer chain was accepted");
        };
        assert_eq!(error.status(), ChurStatus::SyncHeadRollback);
        recipient
            .connection()
            .execute_batch(
                "CREATE TRIGGER reject_received_grant
                 BEFORE INSERT ON sharing_grants
                 BEGIN SELECT RAISE(ABORT, 'test rejection'); END;",
            )
            .expect("trigger");
        assert!(
            accept_share(
                &mut recipient,
                &recipient_root,
                &[evidence],
                &membership,
                prepared.grant(),
                prepared.grant_operation(),
            )
            .is_err()
        );
        assert_eq!(
            store::collection(&recipient, &collection_id)
                .expect_err("failed transaction left a collection")
                .status(),
            ChurStatus::NotFound
        );
        assert!(
            sharing::load(&recipient, &collection_id)
                .expect("sharing state")
                .is_none()
        );
        recipient
            .connection()
            .execute_batch("DROP TRIGGER reject_received_grant")
            .expect("drop trigger");
        accept_share(
            &mut recipient,
            &recipient_root,
            &[evidence],
            &membership,
            prepared.grant(),
            prepared.grant_operation(),
        )
        .expect("accept share");
        let after = schema::generation(&recipient).expect("generation");
        assert!(after > before);
        assert_eq!(
            store::collection(&recipient, &collection_id)
                .expect("shared collection")
                .policy_type,
            COLLECTION_POLICY_SHARED
        );
        assert_eq!(
            sync_keys::collection_key(
                &recipient,
                &recipient_root,
                recipient_vault,
                collection_id,
                1,
            )
            .expect("recipient collection key")
            .expose(),
            source_collection_key.expose()
        );
        accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: evidence.membership,
                operations: evidence.operations,
            }],
            &membership,
            prepared.grant(),
            prepared.grant_operation(),
        )
        .expect("exact replay");
        assert_eq!(schema::generation(&recipient).expect("generation"), after);

        let original_membership = sync_membership::load(&recipient)
            .expect("membership")
            .expect("present");
        let (recipient_device, original_identity) =
            sync_keys::local_identity(&recipient, &recipient_root, &original_membership)
                .expect("local identity")
                .expect("present");
        let rotated_identity = DeviceIdentity::from_seeds([70; 32], [71; 32]);
        let rotation = EnrollmentRecord::new(
            recipient_vault,
            recipient_device,
            rotated_identity.signing_public_key(),
            rotated_identity.hpke_public_key(),
            2,
            recipient_device,
            2,
            *original_membership.commitment(),
            [72; 32],
        )
        .expect("rotation")
        .sign(original_identity.signing_key());
        let mut recipient_log = OperationLog::new();
        let operation_key = Key::new([73; 32]);
        let selector = id(74);
        let initial_outer = recipient_log
            .author(
                id(75),
                recipient_vault,
                recipient_device,
                selector,
                &operation_key,
                Nonce::new([76; 24]),
                b"initial",
                original_identity.signing_key(),
                &original_membership,
            )
            .expect("initial outer");
        recipient_log
            .accept(&initial_outer, &original_membership)
            .expect("accept outer");
        let rotation_outer = recipient_log
            .author(
                id(77),
                recipient_vault,
                recipient_device,
                selector,
                &operation_key,
                Nonce::new([78; 24]),
                b"rotate",
                original_identity.signing_key(),
                &original_membership,
            )
            .expect("rotation outer");
        let rotated_membership =
            sync_membership::accept_enrollment(&mut recipient, &rotation, &recipient_device, 2)
                .expect("accept local rotation");
        let rotated_envelope =
            chur_sync_protocol::identity::DeviceIdentityEnvelope::seal_for_local(
                &recipient_root,
                recipient_vault,
                recipient_device,
                2,
                Nonce::new([79; 24]),
                &rotated_identity,
            )
            .expect("rotated envelope");
        sync_keys::store_local_identity_envelope(
            &mut recipient,
            &recipient_root,
            &rotated_membership,
            &rotated_envelope,
        )
        .expect("store rotated identity");
        let recipient_records = [
            IssuerMembershipRecord::Enrollment(recipient_enrollment.clone()),
            IssuerMembershipRecord::Enrollment(rotation),
        ];
        let recipient_operations = [initial_outer, rotation_outer];
        let second = prepare_share_for_device(
            &mut source,
            &source_root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &recipient_records,
                operations: &recipient_operations,
            },
            recipient_device,
            PermissionProfile::Read,
            false,
        )
        .expect("prepare rotated share");
        // The same device also shares another collection while the source is
        // still at generation 1.
        let other = prepare_share_for_device(
            &mut source,
            &source_root,
            source_vault,
            other_collection_id,
            IssuerEvidence {
                membership: &recipient_records,
                operations: &recipient_operations,
            },
            recipient_device,
            PermissionProfile::Read,
            true,
        )
        .expect("other share");
        let source_operations = sync_log::records_after(&source, &source_device, 0)
            .expect("source operations")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        let collection_records = [
            (
                prepared.membership().clone(),
                prepared.membership_operation().clone(),
            ),
            (
                second.membership().clone(),
                second.membership_operation().clone(),
            ),
        ];
        let updated = accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: &[IssuerMembershipRecord::Enrollment(
                    source_enrollment.clone(),
                )],
                operations: &source_operations,
            }],
            &collection_records,
            second.grant(),
            second.grant_operation(),
        )
        .expect("accept rotated share");
        assert_eq!(updated.generation(), 2);
        let reloaded = sharing::load(&recipient, &collection_id)
            .expect("reload")
            .expect("sharing");
        assert_eq!(reloaded.generation(), 2);
        let other_records = [(
            other.membership().clone(),
            other.membership_operation().clone(),
        )];
        let generation_one = [IssuerMembershipRecord::Enrollment(
            source_enrollment.clone(),
        )];
        accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: &generation_one,
                operations: &source_operations,
            }],
            &other_records,
            other.grant(),
            other.grant_operation(),
        )
        .expect("accept other collection at generation 1");

        // The second recipient receives a grant while the sender is active,
        // but does not open it until the sender device has been revoked.
        let late_vault = id(28);
        let late_root = Key::new([29; 32]);
        let late_catalog_key = CatalogKey::derive(&late_root, &late_vault).expect("late key");
        let mut late_recipient =
            CatalogDb::open(&CatalogLocation::Memory, &late_catalog_key).expect("late recipient");
        schema::open_at_current_version(&mut late_recipient, 1).expect("late schema");
        let (late_enrollment, _) =
            sync_receive::provision_local_identity(&mut late_recipient, &late_root, late_vault)
                .expect("late identity");
        let late_share = prepare_share(
            &mut source,
            &source_root,
            source_vault,
            collection_id,
            &late_enrollment,
            PermissionProfile::Read,
            true,
        )
        .expect("late share");

        let mut source_membership = sync_membership::load(&source)
            .expect("source membership")
            .expect("present");
        let (_, source_identity) =
            sync_keys::local_identity(&source, &source_root, &source_membership)
                .expect("source identity")
                .expect("present");
        let mut log = sync_log::load(&source, &source_membership).expect("source log");
        let checkpoint = log
            .issue_own_checkpoint(
                &mut source,
                &source_membership,
                &source_device,
                source_identity.signing_key(),
                1,
            )
            .expect("source checkpoint");
        let replacement_device = id(30);
        let replacement_key = DeviceSigningKey::from_seed([31; 32]);
        let replacement_enrollment = EnrollmentRecord::new(
            source_vault,
            replacement_device,
            replacement_key.verifying_key(),
            [32; 32],
            log.head(&source_device).expect("source head").0 + 1,
            source_device,
            2,
            *source_membership.commitment(),
            checkpoint.commitment(),
        )
        .expect("replacement enrollment")
        .sign(source_identity.signing_key());
        let root_domain = KeyDomain::root(&source_root, &source_vault).expect("root domain");
        sync_receive::author_membership_operation(
            &mut source,
            &mut log,
            &mut source_membership,
            &root_domain,
            source_device,
            source_identity.signing_key(),
            PayloadBody::AddDevice(replacement_enrollment.clone()),
        )
        .expect("enroll replacement");
        // The sender device is still active at generation 2, so it issues a
        // fresh grant (new permissions force a new membership record). Accepting
        // it makes generation 2 the high-water mark.
        let fresh = prepare_share_for_device(
            &mut source,
            &source_root,
            source_vault,
            collection_id,
            IssuerEvidence {
                membership: &recipient_records,
                operations: &recipient_operations,
            },
            recipient_device,
            PermissionProfile::Contribute,
            false,
        )
        .expect("fresh grant at generation 2");
        let generation_two = [
            IssuerMembershipRecord::Enrollment(source_enrollment.clone()),
            IssuerMembershipRecord::Enrollment(replacement_enrollment.clone()),
        ];
        let generation_two_operations = sync_log::records_after(&source, &source_device, 0)
            .expect("generation two operations")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: &generation_two,
                operations: &generation_two_operations,
            }],
            &[
                collection_records[0].clone(),
                collection_records[1].clone(),
                (
                    late_share.membership().clone(),
                    late_share.membership_operation().clone(),
                ),
                (
                    fresh.membership().clone(),
                    fresh.membership_operation().clone(),
                ),
            ],
            fresh.grant(),
            fresh.grant_operation(),
        )
        .expect("accept grant at generation 2");
        // The relay now withholds the generation 2 enrollment and replays the
        // generation 1 share of the other collection with a generation 1 chain.
        let Err(error) = accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: &generation_one,
                operations: &source_operations,
            }],
            &other_records,
            other.grant(),
            other.grant_operation(),
        ) else {
            panic!("truncated source evidence was accepted");
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        assert_eq!(
            sharing::issuer_membership_high_water(&recipient, &source_vault).expect("high water"),
            2
        );
        // The honest source supplies current evidence with the same generation 1
        // grant: the other collection keeps syncing after the mark moved.
        accept_share(
            &mut recipient,
            &recipient_root,
            &[IssuerEvidence {
                membership: &generation_two,
                operations: &generation_two_operations,
            }],
            &other_records,
            other.grant(),
            other.grant_operation(),
        )
        .expect("generation 1 grant replays under generation 2 evidence");
        // Object key grants are held to the same mark: one signed under the
        // truncated generation 1 chain is refused before any object is looked up.
        let object_id = id(80);
        let prekey = ObjectPrekey::sign(
            id(81),
            other_collection_id,
            object_id,
            1,
            [82; 32],
            recipient_vault,
            recipient_device,
            1,
            &Key::new([83; 32]),
            rotated_identity.signing_key(),
        )
        .expect("object prekey");
        let object_grant = ObjectKeyGrant::seal(
            id(84),
            source_vault,
            source_device,
            object_id,
            1,
            [82; 32],
            &prekey,
            &Key::new([85; 32]),
            source_identity.signing_key(),
        )
        .expect("object grant");
        let Err(error) = crate::object_grants::accept(
            &mut recipient,
            &recipient_root,
            recipient_vault,
            &[IssuerEvidence {
                membership: &generation_one,
                operations: &source_operations,
            }],
            &object_grant,
        ) else {
            panic!("object grant under truncated source evidence was accepted");
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        assert!(error.to_string().contains("below an accepted generation"));
        // The fresh share added operations after `log` was loaded; the
        // revocation must pin the true head so they stay below its point.
        let (final_sequence, final_digest) = sync_log::load(&source, &source_membership)
            .expect("reloaded source log")
            .head(&source_device)
            .expect("final source head");
        let revocation = RevocationRecord::new(
            source_vault,
            source_device,
            final_sequence,
            final_digest,
            3,
            replacement_device,
            *source_membership.commitment(),
        )
        .expect("source revocation")
        .sign(&replacement_key);
        let current_operations = sync_log::records_after(&source, &source_device, 0)
            .expect("current operations")
            .iter()
            .map(|bytes| Operation::decode(bytes).expect("operation"))
            .collect::<Vec<_>>();
        let current_membership = [
            IssuerMembershipRecord::Enrollment(source_enrollment),
            IssuerMembershipRecord::Enrollment(replacement_enrollment),
            IssuerMembershipRecord::Revocation(revocation),
        ];
        let late_membership = [
            (
                prepared.membership().clone(),
                prepared.membership_operation().clone(),
            ),
            (
                second.membership().clone(),
                second.membership_operation().clone(),
            ),
            (
                late_share.membership().clone(),
                late_share.membership_operation().clone(),
            ),
        ];
        let Err(error) = accept_share(
            &mut late_recipient,
            &late_root,
            &[
                IssuerEvidence {
                    membership: &current_membership,
                    operations: &current_operations,
                },
                IssuerEvidence {
                    membership: &recipient_records,
                    operations: &recipient_operations,
                },
            ],
            &late_membership,
            late_share.grant(),
            late_share.grant_operation(),
        ) else {
            panic!("delayed grant from revoked sender was accepted");
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        assert!(
            sharing::load(&late_recipient, &collection_id)
                .expect("late sharing state")
                .is_none()
        );
    }
}
