//! Atomic inbound acceptance for encrypted sync operations.

use std::borrow::Cow;
use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Key, Nonce, random};
use chur_sync_protocol::collection_membership::CollectionMembershipState;
use chur_sync_protocol::convergence::MergeOutcome;
use chur_sync_protocol::identity::{DeviceIdentity, DeviceIdentityEnvelope};
use chur_sync_protocol::materialization::MaterializedState;
use chur_sync_protocol::membership::EnrollmentRecord;
use chur_sync_protocol::operation::{DeviceSigningKey, Operation};
use chur_sync_protocol::operation_log::ApplyOutcome;
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};
use chur_sync_protocol::state::MembershipState;
use chur_sync_protocol::{KeyDirectory, KeyDomain};

use crate::CatalogDb;
use crate::db::{from_sqlite_integer, map_sqlite};
use crate::sync_log::DurableOperationLog;
use crate::{sharing, sync_keys, sync_log, sync_membership, sync_rotation};

/// Provisions generation-one membership and its outer operation atomically.
pub fn provision_initial_membership(
    db: &mut CatalogDb,
    root: &Key,
    signing_key: &DeviceSigningKey,
    enrollment: &EnrollmentRecord,
) -> Result<(MembershipState, DurableOperationLog, Operation)> {
    provision_initial_membership_with_identity(db, root, signing_key, enrollment, None)
}

fn provision_initial_membership_with_identity(
    db: &mut CatalogDb,
    root: &Key,
    signing_key: &DeviceSigningKey,
    enrollment: &EnrollmentRecord,
    local_identity: Option<&DeviceIdentityEnvelope>,
) -> Result<(MembershipState, DurableOperationLog, Operation)> {
    let membership = MembershipState::bootstrap(enrollment)?;
    let domain = KeyDomain::root(root, membership.vault_id())?;
    let payload = OperationPayload::new(
        *membership.vault_id(),
        0,
        PayloadBody::AddDevice(enrollment.clone()),
    )?;
    let mut log = sync_log::load(db, &membership)?;
    let operation = log.author(
        random::id()?,
        *membership.vault_id(),
        *enrollment.device_id(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        signing_key,
        &membership,
    )?;
    payload.validate_for_operation(
        &operation,
        domain.collection_id(),
        domain.collection_epoch(),
    )?;
    ensure!(
        log.accept_with(db, &operation, &membership, |transaction| {
            sync_membership::project_provision(transaction, enrollment)?;
            if let Some(envelope) = local_identity {
                sync_keys::project_local_identity(transaction, envelope)?;
            }
            Ok(())
        })? == ApplyOutcome::Applied,
        InternalFailure,
        "fresh self-enrollment operation was not applied"
    );
    Ok((membership, log, operation))
}

/// Creates and atomically stores the first ordinary device identity.
pub fn provision_local_identity(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
) -> Result<(EnrollmentRecord, Operation)> {
    if let Some(membership) = sync_membership::load(db)? {
        ensure!(
            membership.vault_id() == &vault_id,
            CatalogCorrupt,
            "local membership belongs to another vault"
        );
        let (device_id, _) =
            sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
                Error::new(
                    ChurStatus::RecoveryRequired,
                    "sync membership has no ordinary local identity",
                )
            })?;
        let enrollment = sync_membership::enrollment_for_device(db, &device_id)?;
        let operation_bytes = sync_log::records_after(db, &device_id, 0)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "local identity has no initial operation",
                )
            })?;
        let operation = Operation::decode(&operation_bytes).map_err(|_| {
            Error::new(
                ChurStatus::CatalogCorrupt,
                "local identity initial operation is invalid",
            )
        })?;
        ensure!(
            operation.device_id() == &device_id && operation.device_sequence() == 1,
            CatalogCorrupt,
            "local identity initial operation contradicts its device"
        );
        return Ok((enrollment, operation));
    }
    let device_id = random::id()?;
    let identity = DeviceIdentity::generate()?;
    let enrollment = EnrollmentRecord::initial(
        vault_id,
        device_id,
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )?
    .sign(identity.signing_key());
    let envelope = DeviceIdentityEnvelope::seal_for_local(
        root,
        vault_id,
        device_id,
        1,
        Nonce::random()?,
        &identity,
    )?;
    let (_, _, operation) = provision_initial_membership_with_identity(
        db,
        root,
        identity.signing_key(),
        &enrollment,
        Some(&envelope),
    )?;
    Ok((enrollment, operation))
}

/// Rebuilds convergent private content from authenticated accepted records.
pub fn load_materialized_state(db: &CatalogDb, keys: &KeyDirectory) -> Result<MaterializedState> {
    let devices = crate::sync_log::device_ids(db)?;
    let operation_count = db
        .connection()
        .query_row("SELECT count(*) FROM sync_operations", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| map_sqlite(error, "accepted operations could not be counted"))?;
    let operation_count =
        from_sqlite_integer(operation_count, "the accepted operation count is malformed")?;
    let mut next_sequence = devices
        .iter()
        .copied()
        .map(|device_id| (device_id, 1))
        .collect::<BTreeMap<_, _>>();
    let mut restored = 0;
    let mut state = MaterializedState::new();
    let membership = sync_membership::load(db)?;
    let mut pruned_since = BTreeMap::<Id, u64>::new();

    while restored < operation_count {
        let mut progressed = false;
        for device_id in &devices {
            let sequence = next_sequence[device_id];
            let Some((operation, stored_digest)) =
                crate::sync_log::operation_at(db, device_id, sequence)?
            else {
                continue;
            };
            ensure!(
                operation.digest() == stored_digest,
                CatalogCorrupt,
                "an accepted operation digest contradicts its record"
            );
            // Restore causal predecessors before computing whether their
            // signed branches contain history excluded by current revocation.
            if operation.observed_heads().iter().any(|head| {
                let required = match membership
                    .as_ref()
                    .and_then(|m| m.device(head.device_id()))
                    .map(|device| device.status())
                {
                    Some(chur_sync_protocol::state::DeviceStatus::Revoked { sequence, .. }) => {
                        head.device_sequence().min(sequence)
                    }
                    _ => head.device_sequence(),
                };
                next_sequence.get(head.device_id()).copied().unwrap_or(1) - 1 < required
            }) {
                continue;
            }
            let pruned = membership.as_ref().is_some_and(|m| {
                chur_sync_protocol::operation_log::OperationLog::observes_pruned_revocation(
                    &operation, m,
                )
            }) || pruned_since
                .get(device_id)
                .is_some_and(|first| *first < sequence)
                || operation.observed_heads().iter().any(|head| {
                    pruned_since
                        .get(head.device_id())
                        .is_some_and(|first| *first <= head.device_sequence())
                });
            let payload = OperationPayload::open_for_operation(&operation, keys)
                .map_err(corrupt_materialized_state)?;
            if !matches!(
                payload.body(),
                PayloadBody::AddDevice(_)
                    | PayloadBody::DeviceReady
                    | PayloadBody::DeclareCollection { .. }
                    | PayloadBody::RevokeDevice(_)
                    | PayloadBody::CreateCollectionEpoch { .. }
                    | PayloadBody::RewrapObjectKey { .. }
                    | PayloadBody::ChangeCollectionMembership(_)
                    | PayloadBody::IssueCollectionGrant(_)
            ) {
                let mut candidate = state.clone();
                let result = candidate.apply(&operation, &payload);
                if matches!(result, Ok(MergeOutcome::PendingCause)) || (pruned && result.is_err()) {
                    if !pruned {
                        continue;
                    }
                    candidate = state.clone();
                    candidate.defer_revoked_content(&operation, &payload);
                } else {
                    result.map_err(corrupt_materialized_state)?;
                    for purge in candidate.retry_deferred_after(&payload) {
                        // The receiving/authoring transaction must commit a
                        // resolved terminal effect before publishing its state.
                        validate_projected_purge(db, &purge)?;
                    }
                }
                state = candidate;
            }
            if pruned {
                pruned_since.entry(*device_id).or_insert(sequence);
            }
            next_sequence.insert(
                *device_id,
                sequence.checked_add(1).ok_or_else(|| {
                    Error::new(
                        ChurStatus::CatalogCorrupt,
                        "an accepted operation sequence overflowed",
                    )
                })?,
            );
            restored = restored.checked_add(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "the accepted operation count overflowed",
                )
            })?;
            progressed = true;
        }
        ensure!(
            progressed,
            CatalogCorrupt,
            "accepted content history has a missing or cyclic cause"
        );
    }
    Ok(state)
}

fn validate_projected_purge(db: &CatalogDb, payload: &OperationPayload) -> Result<()> {
    let PayloadBody::PurgeObject { object_id, .. } = payload.body() else {
        return Ok(());
    };
    let projected: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM tombstones WHERE collection_id = ?1 AND object_id = ?2",
            rusqlite::params![
                payload.collection_id().as_bytes().as_slice(),
                object_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "resolved purge custody could not be checked"))?;
    ensure!(
        projected != 0,
        RecoveryRequired,
        "resolved permanent purge has not completed its custody projection"
    );
    Ok(())
}

fn corrupt_materialized_state(_error: Error) -> Error {
    Error::new(
        ChurStatus::CatalogCorrupt,
        "an accepted content operation could not be materialized",
    )
}

/// Returns tombstoned objects that the current durable checkpoint permits GC to discard.
pub fn gc_candidates(
    db: &CatalogDb,
    log: &DurableOperationLog,
    membership: &MembershipState,
    state: &MaterializedState,
    now_ms: u64,
) -> Result<Vec<Id>> {
    let active_devices = membership.active_device_ids().copied().collect::<Vec<_>>();
    let latest_operations = log.latest_operations()?;
    Ok(state.gc_candidates(
        now_ms,
        &active_devices,
        &latest_operations,
        log.own_checkpoint_covers_current_heads(db)?,
    ))
}

/// Authors and atomically persists one local convergent content operation.
#[expect(
    clippy::too_many_arguments,
    reason = "the operation joins durable state, device identity, key domain, and private payload"
)]
pub fn author_content_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &MembershipState,
    state: &mut MaterializedState,
    domain: &KeyDomain,
    device_id: Id,
    signing_key: &DeviceSigningKey,
    payload: &OperationPayload,
) -> Result<Operation> {
    let operation = log.author(
        random::id()?,
        *membership.vault_id(),
        device_id,
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        signing_key,
        membership,
    )?;
    payload.validate_for_operation(
        &operation,
        domain.collection_id(),
        domain.collection_epoch(),
    )?;
    let mut projected = state.clone();
    ensure!(
        projected.apply(&operation, payload)? == MergeOutcome::Applied,
        InvalidInput,
        "local content operation does not change the current state"
    );
    let resolved_purges = projected.retry_deferred_after(payload);
    ensure!(
        log.accept_with(db, &operation, membership, |tx| {
            crate::deletion::project_purge(tx, payload)?;
            for purge in &resolved_purges {
                crate::deletion::project_purge(tx, purge)?;
            }
            Ok(())
        })? == ApplyOutcome::Applied,
        InternalFailure,
        "fresh local content operation was not applied"
    );
    *state = projected;
    Ok(operation)
}

/// Authors and atomically persists one local device-membership operation.
pub fn author_membership_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &mut MembershipState,
    root_domain: &KeyDomain,
    device_id: Id,
    signing_key: &DeviceSigningKey,
    body: PayloadBody,
) -> Result<Operation> {
    match &body {
        PayloadBody::AddDevice(enrollment) => ensure!(
            log.checkpoint_commitment(enrollment.issuer_device_id())
                == Some(enrollment.bootstrap_checkpoint_commitment()),
            AuthenticationFailed,
            "local enrollment does not name the issuer's durable checkpoint"
        ),
        PayloadBody::RevokeDevice(revocation) => ensure!(
            log.head(revocation.revoked_device_id())
                .unwrap_or((0, [0; 32]))
                == (
                    revocation.final_accepted_device_sequence(),
                    *revocation.final_accepted_operation_digest(),
                ),
            AuthenticationFailed,
            "local revocation does not pin the latest accepted device head"
        ),
        _ => {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "operation is not a membership operation",
            ));
        }
    }
    let payload = OperationPayload::new(*membership.vault_id(), 0, body)?;
    let operation = log.author(
        random::id()?,
        *membership.vault_id(),
        device_id,
        *root_domain.selector(),
        root_domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        signing_key,
        membership,
    )?;
    payload.validate_for_operation(
        &operation,
        root_domain.collection_id(),
        root_domain.collection_epoch(),
    )?;
    let mut projected_membership = None;
    ensure!(
        log.accept_with(db, &operation, membership, |transaction| {
            projected_membership = Some(match payload.body() {
                PayloadBody::AddDevice(enrollment) => sync_membership::project_enrollment(
                    transaction,
                    membership,
                    enrollment,
                    operation.device_id(),
                    operation.device_sequence(),
                )?,
                PayloadBody::RevokeDevice(revocation) => sync_membership::project_revocation(
                    transaction,
                    membership,
                    revocation,
                    operation.device_id(),
                )?,
                _ => {
                    return Err(Error::new(
                        ChurStatus::InternalFailure,
                        "checked membership body changed before projection",
                    ));
                }
            });
            Ok(())
        })? == ApplyOutcome::Applied,
        InternalFailure,
        "fresh local membership operation was not applied"
    );
    *membership = projected_membership.ok_or_else(|| {
        Error::new(
            ChurStatus::InternalFailure,
            "local membership operation has no projection",
        )
    })?;
    Ok(operation)
}

/// Authors and atomically persists one collection membership or grant operation.
#[expect(
    clippy::too_many_arguments,
    reason = "sharing joins durable state, identity membership, and a collection key domain"
)]
pub fn author_sharing_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    issuer_membership: &MembershipState,
    sharing_state: &mut CollectionMembershipState,
    domain: &KeyDomain,
    operation_id: Id,
    device_id: Id,
    signing_key: &DeviceSigningKey,
    body: PayloadBody,
) -> Result<Operation> {
    ensure!(
        matches!(
            body,
            PayloadBody::ChangeCollectionMembership(_) | PayloadBody::IssueCollectionGrant(_)
        ),
        InvalidInput,
        "operation is not a collection-sharing security operation"
    );
    let payload = OperationPayload::new(
        *sharing_state.collection_id(),
        sharing_state.collection_epoch(),
        body,
    )?;
    let operation = log.author(
        operation_id,
        *issuer_membership.vault_id(),
        device_id,
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        signing_key,
        issuer_membership,
    )?;
    ensure!(
        accept_opened_sharing_operation(
            db,
            log,
            issuer_membership,
            sharing_state,
            &operation,
            &payload,
            false,
        )? == ApplyOutcome::Applied,
        InternalFailure,
        "fresh local sharing operation was not applied"
    );
    Ok(operation)
}

/// Authenticates, decrypts, and atomically commits one sharing security operation.
pub fn accept_sharing_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    issuer_membership: &MembershipState,
    sharing_state: &mut CollectionMembershipState,
    keys: &KeyDirectory,
    record: &[u8],
) -> Result<ApplyOutcome> {
    let operation = Operation::decode(record)?;
    let payload = OperationPayload::open_for_operation(&operation, keys)?;
    accept_opened_sharing_operation(
        db,
        log,
        issuer_membership,
        sharing_state,
        &operation,
        &payload,
        false,
    )
}

/// Identity-vault membership at the generation a sharing record was authored at.
///
/// The author stamps its own generation; a sibling that has since accepted an
/// unrelated enrollment or revocation is ahead of it. Checking the record
/// against the receiver's newer state returned `AuthenticationFailed`, which
/// `sync_engine` treats as a verdict: the record left the inbox and the
/// author's chain stalled there.
fn record_issuer_state<'a>(
    db: &CatalogDb,
    current: &'a MembershipState,
    payload: &OperationPayload,
) -> Result<Cow<'a, MembershipState>> {
    let generation = match payload.body() {
        PayloadBody::ChangeCollectionMembership(record) => record.issuer_membership_generation(),
        PayloadBody::IssueCollectionGrant(grant) => grant.sender_membership_generation(),
        _ => return Ok(Cow::Borrowed(current)),
    };
    if generation >= current.generation() {
        return Ok(Cow::Borrowed(current));
    }
    let historical = sync_membership::load_at_generation(db, generation)?;
    ensure!(
        historical.vault_id() == current.vault_id(),
        AuthenticationFailed,
        "sharing record issuer belongs to another vault"
    );
    Ok(Cow::Owned(historical))
}

/// Commits one authorized sharing operation.
///
/// `provision` writes the collection's own sharing row in the same transaction.
/// A peer device of the source vault holds none until the first membership
/// record reaches it, and provisioning outside this transaction would leave an
/// orphan row behind whenever the record then failed to apply — a state
/// `install_share` reports as `CatalogCorrupt`. The row is written only after
/// `authorize_operation` has verified the operation's signature, so nothing
/// unauthenticated reaches the catalog.
fn accept_opened_sharing_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    issuer_membership: &MembershipState,
    sharing_state: &mut CollectionMembershipState,
    operation: &Operation,
    payload: &OperationPayload,
    provision: bool,
) -> Result<ApplyOutcome> {
    sharing_state.authorize_operation(operation, payload, issuer_membership)?;
    let record_issuer = record_issuer_state(db, issuer_membership, payload)?;
    let mut projected_sharing = None;
    let outcome = log.accept_with(db, operation, issuer_membership, |transaction| {
        if provision {
            sharing::project_provision(transaction, sharing_state)?;
        }
        match payload.body() {
            PayloadBody::ChangeCollectionMembership(record) => {
                let (candidate, membership_outcome) =
                    sharing::project_membership(transaction, sharing_state, record, &record_issuer)?;
                ensure!(
                    membership_outcome
                        == chur_sync_protocol::collection_membership::CollectionMembershipOutcome::Applied,
                    InternalFailure,
                    "fresh sharing operation carried duplicate membership"
                );
                projected_sharing = Some(candidate);
            }
            PayloadBody::IssueCollectionGrant(grant) => ensure!(
                sharing::project_grant(transaction, sharing_state, grant, &record_issuer)?
                    == sharing::GrantStoreOutcome::Stored,
                InternalFailure,
                "fresh sharing operation carried duplicate grant"
            ),
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "operation is not a collection-sharing security operation",
                ));
            }
        }
        Ok(())
    });
    let outcome = match outcome {
        Ok(outcome) => outcome,
        // A grant identifier that arrives again with different bytes freezes
        // grant acceptance for the collection, per COLLECTION_MEMBERSHIP.md
        // §5. The application transaction rolled back, so the durable freeze
        // is recorded in its own transaction before the rejection returns.
        Err(error) if error.status() == ChurStatus::Conflict => {
            if let PayloadBody::IssueCollectionGrant(grant) = payload.body()
                && sharing::grant_identifier_conflicts(db, grant)?
            {
                sharing::record_grant_freeze(db, grant.collection_id())?;
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if let (ApplyOutcome::Applied, Some(candidate)) = (outcome, projected_sharing) {
        *sharing_state = candidate;
    }
    Ok(outcome)
}

/// Authors and atomically persists one local collection rotation operation.
#[expect(
    clippy::too_many_arguments,
    reason = "rotation joins durable state, key routing, device identity, and private payload"
)]
pub fn author_rotation_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &MembershipState,
    keys: &mut KeyDirectory,
    root: &Key,
    domain: &KeyDomain,
    device_id: Id,
    signing_key: &DeviceSigningKey,
    now_ms: u64,
    payload: &OperationPayload,
) -> Result<Operation> {
    ensure!(
        matches!(
            payload.body(),
            PayloadBody::CreateCollectionEpoch { .. } | PayloadBody::RewrapObjectKey { .. }
        ),
        InvalidInput,
        "operation is not a collection rotation operation"
    );
    let operation = log.author(
        random::id()?,
        *membership.vault_id(),
        device_id,
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        signing_key,
        membership,
    )?;
    payload.validate_for_operation(
        &operation,
        domain.collection_id(),
        domain.collection_epoch(),
    )?;
    ensure!(
        accept_rotation_operation(db, log, membership, keys, root, now_ms, &operation.encode(),)?
            == ApplyOutcome::Applied,
        InternalFailure,
        "fresh local rotation operation was not applied"
    );
    Ok(operation)
}

/// Authenticates, decrypts, and atomically routes one inbound operation.
#[expect(
    clippy::too_many_arguments,
    reason = "inbound acceptance joins durable membership, log, keys, and convergent state"
)]
pub fn accept_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &mut MembershipState,
    state: &mut MaterializedState,
    keys: &mut KeyDirectory,
    root: &Key,
    now_ms: u64,
    record: &[u8],
) -> Result<ApplyOutcome> {
    let operation = Operation::decode(record)?;
    // A valid new selector can precede its root-domain declaration in the
    // shuffled inbox. Authenticate the outer identity before retaining it;
    // only a decrypted and causally accepted operation can advance its head.
    if !keys.contains_selector(operation.key_selector()) {
        ensure!(
            operation.vault_id() == membership.vault_id(),
            AuthenticationFailed,
            "pending operation belongs to another vault"
        );
        let issuer = membership.device(operation.device_id()).ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "pending operation author is not enrolled",
            )
        })?;
        ensure!(
            issuer
                .signing_public_keys()
                .any(|key| operation.verify_signature(key).is_ok()),
            AuthenticationFailed,
            "pending operation signature did not verify"
        );
        return Ok(ApplyOutcome::PendingCause);
    }
    let payload = OperationPayload::open_for_operation(&operation, keys)?;
    match payload.body() {
        PayloadBody::DeclareCollection {
            collection_key_envelope,
        } => {
            let envelope = collection_key_envelope;
            ensure!(
                envelope.vault_id() == membership.vault_id(),
                AuthenticationFailed,
                "declared metadata key names another vault"
            );
            let secret = envelope.open(root)?;
            let domain = KeyDomain::collection(
                &secret,
                envelope.collection_id(),
                envelope.collection_epoch(),
            )?;
            keys.check_insert(&domain)?;
            let previous = match crate::store::collection(db, envelope.collection_id()) {
                Ok(collection) => {
                    ensure!(
                        collection.policy_type != crate::model::COLLECTION_POLICY_SHARED,
                        AuthenticationFailed,
                        "own declaration targets an external shared collection"
                    );
                    Some(collection)
                }
                Err(error) if error.status() == ChurStatus::NotFound => None,
                Err(error) => return Err(error),
            };
            let existing = match crate::store::active_collection_envelope(
                db,
                envelope.collection_id(),
                envelope.collection_epoch(),
            ) {
                Ok(bytes) => {
                    let stored = chur_format::envelope::CollectionKeyEnvelope::decode(&bytes)?;
                    ensure!(
                        stored.open(root)?.expose() == secret.expose(),
                        AuthenticationFailed,
                        "declared collection changes an existing metadata key"
                    );
                    Some(bytes)
                }
                Err(error) if error.status() == ChurStatus::NotFound => None,
                Err(error) => return Err(error),
            };
            let outcome = log.accept_with(db, &operation, membership, |tx| {
                if existing.is_none() {
                    crate::store::project_collection_with_envelope(tx, &crate::model::Collection {
                        collection_id: *envelope.collection_id(), current_epoch: envelope.collection_epoch(),
                        policy_type: crate::model::COLLECTION_POLICY_VAULT_DEFAULT,
                        created_revision: previous.as_ref().map_or(1, |value| value.created_revision),
                        status: previous.as_ref().map_or(crate::model::COLLECTION_STATUS_ACTIVE, |value| value.status),
                    }, envelope.envelope_generation(), &envelope.encode())?;
                    if let Some(old) = &previous {
                        tx.execute("UPDATE collections SET current_epoch = max(current_epoch, ?2) WHERE collection_id = ?1",
                            rusqlite::params![envelope.collection_id().as_bytes().as_slice(), crate::db::as_sqlite_integer(old.current_epoch, "collection epoch is too large")?])
                            .map_err(|error| map_sqlite(error, "declared epoch could not be preserved"))?;
                    }
                }
                Ok(())
            })?;
            if outcome == ApplyOutcome::Applied {
                keys.insert(domain)?;
            }
            Ok(outcome)
        }
        PayloadBody::DeviceReady => {
            ensure!(
                operation.device_sequence() == 1,
                InvalidInput,
                "device readiness is only the first device operation"
            );
            log.accept_with(db, &operation, membership, |_| Ok(()))
        }
        PayloadBody::AddDevice(_) | PayloadBody::RevokeDevice(_) => {
            accept_membership_operation(db, log, membership, keys, record)
        }
        PayloadBody::CreateCollectionEpoch { .. } | PayloadBody::RewrapObjectKey { .. } => {
            accept_rotation_operation(db, log, membership, keys, root, now_ms, record)
        }
        // `COLLECTION_OPERATION_LOG.md` §1 keeps kinds 0x11 and 0x12 out of the
        // collection stream, and `COLLECTION_MEMBERSHIP.md` §5 carries the
        // membership record on kind 0x11 of the identity-vault log, so this is
        // the only channel a peer device of the source vault can receive them
        // on. Refusing them here made `InvalidInput`, which `sync_engine`
        // classifies as a rejection: the record was deleted from the inbox and
        // the sibling's chain stalled at that sequence for good, so a second
        // source device learned of no member, grant or pin and would fork the
        // chain the moment it shared the same collection.
        PayloadBody::ChangeCollectionMembership(record) => {
            let (mut sharing_state, provision) = match sharing::load(db, payload.collection_id())? {
                Some(existing) => (existing, false),
                // A sibling holds no sharing rows until the first record
                // arrives; anything later is a gap rather than a beginning, and
                // `NotFound` is what `sync_engine` retains rather than drops.
                None if record.collection_membership_generation() == 1 => (
                    CollectionMembershipState::new(
                        *record.source_vault_id(),
                        *record.collection_id(),
                        record.collection_epoch(),
                    )?,
                    true,
                ),
                None => {
                    return Err(Error::new(
                        ChurStatus::NotFound,
                        "collection membership predecessor is not held",
                    ));
                }
            };
            accept_opened_sharing_operation(
                db,
                log,
                membership,
                &mut sharing_state,
                &operation,
                &payload,
                provision,
            )
        }
        PayloadBody::IssueCollectionGrant(_) => {
            let mut sharing_state =
                sharing::load(db, payload.collection_id())?.ok_or_else(|| {
                    Error::new(
                        ChurStatus::NotFound,
                        "collection grant precedes its collection membership",
                    )
                })?;
            accept_opened_sharing_operation(
                db,
                log,
                membership,
                &mut sharing_state,
                &operation,
                &payload,
                false,
            )
        }
        _ => accept_content_operation(db, log, membership, state, keys, record),
    }
}

/// Authenticates, decrypts, and atomically accepts one convergent content operation.
pub fn accept_content_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &MembershipState,
    state: &mut MaterializedState,
    keys: &KeyDirectory,
    record: &[u8],
) -> Result<ApplyOutcome> {
    let operation = Operation::decode(record)?;
    let payload = OperationPayload::open_for_operation(&operation, keys)?;
    let creates_new_album = match payload.body() {
        PayloadBody::CreateAlbum { album_id, .. } => state.album_name(album_id).is_none(),
        _ => false,
    };
    let mut projected_state = None;
    let purges = std::cell::RefCell::new(Vec::new());
    let album_projection = std::cell::RefCell::new(None);
    let resolved_memberships = std::cell::Cell::new(false);
    let outcome = log.accept_gated_with(
        db,
        &operation,
        membership,
        |authenticated_log| {
            let mut candidate = state.clone();
            let result = candidate.apply(&operation, &payload);
            if matches!(result, Ok(MergeOutcome::PendingCause)) || result.is_err() {
                if !authenticated_log.has_pruned_revocation_cause(&operation, membership)? {
                    result?;
                    return Ok(false);
                }
                candidate = state.clone();
                candidate.defer_revoked_content(&operation, &payload);
            } else {
                if matches!(payload.body(), PayloadBody::PurgeObject { .. }) {
                    purges.borrow_mut().push(payload.clone());
                }
                purges
                    .borrow_mut()
                    .extend(candidate.retry_deferred_after(&payload));
            }
            resolved_memberships
                .set(candidate.pending_operations(None) < state.pending_operations(None));
            if resolved_memberships.get()
                || matches!(
                    payload.body(),
                    PayloadBody::CreateAlbum { .. }
                        | PayloadBody::RenameAlbum { .. }
                        | PayloadBody::AddAlbumMembership { .. }
                        | PayloadBody::RemoveAlbumMembership { .. }
                )
            {
                *album_projection.borrow_mut() = Some(candidate.clone());
            }
            projected_state = Some(candidate);
            Ok(true)
        },
        |tx| {
            if let Some(state) = album_projection.borrow().as_ref() {
                project_album_operation(tx, state, &payload, creates_new_album)?;
                if resolved_memberships.get() {
                    crate::own_sync::project_live_album_memberships(tx, state)?;
                }
            }
            for purge in purges.borrow().iter() {
                crate::deletion::project_purge(tx, purge)?;
            }
            Ok(())
        },
    )?;
    if outcome == ApplyOutcome::Applied {
        if let PayloadBody::CreateObject { object_id, .. }
        | PayloadBody::CommitObject { object_id, .. } = payload.body()
        {
            crate::own_sync::mark_album_object_ready(db, object_id);
        }
        *state = projected_state.ok_or_else(|| {
            Error::new(
                ChurStatus::InternalFailure,
                "applied content operation has no projection state",
            )
        })?;
    }
    Ok(outcome)
}

fn project_album_operation(
    tx: &rusqlite::Transaction<'_>,
    state: &MaterializedState,
    payload: &OperationPayload,
    creates_new_album: bool,
) -> Result<()> {
    match payload.body() {
        PayloadBody::CreateAlbum { album_id, .. } if creates_new_album => {
            if let Some(name) = state.album_name(album_id) {
                let (present, total): (bool, i64) = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM albums WHERE album_id = ?1), (SELECT count(*) FROM albums)",
                    [album_id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(|error| map_sqlite(error, "received album bound could not be read"))?;
                ensure!(
                    present
                        || from_sqlite_integer(total, "received album count is negative")?
                            < chur_core::limits::catalog::ALBUMS_MAX,
                    ResourceLimitExceeded,
                    "received album exceeds the catalog bound"
                );
                tx.execute("INSERT INTO albums (album_id, name, created_ms, revision, parent_album_id, sort_position)
                    VALUES (?1, ?2, 0, 1, NULL,
                        (SELECT coalesce(max(sort_position) + 1, 0) FROM albums WHERE parent_album_id IS NULL))
                    ON CONFLICT(album_id) DO UPDATE SET name = excluded.name",
                    rusqlite::params![album_id.as_bytes().as_slice(), name])
                    .map_err(|error| map_sqlite(error, "received album could not be projected"))?;
            }
        }
        PayloadBody::RenameAlbum { album_id, .. } | PayloadBody::CreateAlbum { album_id, .. } => {
            if let Some(name) = state.album_name(album_id) {
                // Deletion remains a local v7 operation. A later rename must
                // not recreate a locally removed album or its subtree.
                tx.execute(
                    "UPDATE albums SET name = ?2, revision = revision + 1
                    WHERE album_id = ?1 AND name != ?2",
                    rusqlite::params![album_id.as_bytes().as_slice(), name],
                )
                .map_err(|error| map_sqlite(error, "received album name could not be projected"))?;
            }
        }
        PayloadBody::AddAlbumMembership {
            album_id,
            object_id,
        }
        | PayloadBody::RemoveAlbumMembership {
            album_id,
            object_id,
            ..
        } => crate::own_sync::project_album_member(tx, state, album_id, object_id)?,
        _ => {}
    }
    Ok(())
}

/// Authenticates, decrypts, and atomically commits one membership operation.
pub fn accept_membership_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &mut MembershipState,
    keys: &KeyDirectory,
    record: &[u8],
) -> Result<ApplyOutcome> {
    let operation = Operation::decode(record)?;
    let payload = OperationPayload::open_for_operation(&operation, keys)?;
    let mut projected_membership = None;
    let outcome = log.accept_with(db, &operation, membership, |transaction| {
        projected_membership = Some(match payload.body() {
            PayloadBody::AddDevice(enrollment) => sync_membership::project_enrollment(
                transaction,
                membership,
                enrollment,
                operation.device_id(),
                operation.device_sequence(),
            )?,
            PayloadBody::RevokeDevice(revocation) => sync_membership::project_received_revocation(
                transaction,
                membership,
                revocation,
                &operation,
            )?,
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "operation is not a membership operation",
                ));
            }
        });
        Ok(())
    })?;
    if outcome == ApplyOutcome::Applied {
        *membership = projected_membership.ok_or_else(|| {
            Error::new(
                ChurStatus::InternalFailure,
                "applied membership operation has no projection",
            )
        })?;
    }
    Ok(outcome)
}

/// Authenticates, decrypts, and atomically commits one collection rotation operation.
pub fn accept_rotation_operation(
    db: &mut CatalogDb,
    log: &mut DurableOperationLog,
    membership: &MembershipState,
    keys: &mut KeyDirectory,
    root: &Key,
    now_ms: u64,
    record: &[u8],
) -> Result<ApplyOutcome> {
    let operation = Operation::decode(record)?;
    let payload = OperationPayload::open_for_operation(&operation, keys)?;
    match payload.body() {
        PayloadBody::CreateCollectionEpoch {
            membership_generation,
            collection_key_envelope,
            ..
        } => {
            let collection_key = collection_key_envelope.open(root)?;
            let new_domain = KeyDomain::collection(
                &collection_key,
                payload.collection_id(),
                collection_key_envelope.collection_epoch(),
            )?;
            keys.check_insert(&new_domain)?;
            let sharing_state = sharing::load(db, payload.collection_id())?;
            if let Some(state) = &sharing_state {
                ensure!(
                    state.source_vault_id() == operation.vault_id(),
                    AuthenticationFailed,
                    "collection rotation comes from another sharing source vault"
                );
            }
            let outcome = log.accept_with(db, &operation, membership, |transaction| {
                sync_rotation::project_begin(
                    transaction,
                    *operation.vault_id(),
                    *payload.collection_id(),
                    membership,
                    *operation.device_id(),
                    *membership_generation,
                    now_ms,
                    collection_key_envelope.clone(),
                    root,
                )?;
                if let Some(state) = &sharing_state {
                    sharing::project_collection_epoch(
                        transaction,
                        state,
                        collection_key_envelope.collection_epoch(),
                    )?;
                }
                Ok(())
            })?;
            if outcome == ApplyOutcome::Applied {
                keys.insert(new_domain)?;
            }
            Ok(outcome)
        }
        PayloadBody::RewrapObjectKey {
            object_id,
            object_key_commitment,
        } => {
            let current_epoch = payload.collection_epoch();
            let previous_epoch = current_epoch.checked_sub(1).ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "rewrap operation has no previous collection epoch",
                )
            })?;
            let previous_key = sync_keys::collection_key(
                db,
                root,
                *operation.vault_id(),
                *payload.collection_id(),
                previous_epoch,
            )?;
            let current_key = sync_keys::collection_key(
                db,
                root,
                *operation.vault_id(),
                *payload.collection_id(),
                current_epoch,
            )?;
            // The signed log commits to the key without carrying it. Every
            // device rewraps its own live envelope with a fresh local nonce.
            let (stored, pending) = match crate::store::active_envelope(db, object_id) {
                Ok(bytes) => (
                    chur_format::envelope::ObjectKeyEnvelope::decode(&bytes)?,
                    false,
                ),
                Err(error) if error.status() == ChurStatus::NotFound => {
                    let state = load_materialized_state(db, keys)?;
                    let committed = state.committed_object(object_id).ok_or_else(|| {
                        Error::new(
                            ChurStatus::NotFound,
                            "rewrap precedes the accepted object commit",
                        )
                    })?;
                    ensure!(
                        committed.object_key_commitment() == object_key_commitment,
                        AuthenticationFailed,
                        "rewrap differs from the accepted object key commitment"
                    );
                    match crate::object_grants::pending_envelope(
                        db,
                        payload.collection_id(),
                        object_id,
                    ) {
                        Ok(envelope) => (envelope, true),
                        Err(error) if error.status() == ChurStatus::NotFound => {
                            return log.accept_with(db, &operation, membership, |_| Ok(()));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            let old_key = if stored.collection_epoch() == current_epoch {
                &current_key
            } else {
                ensure!(
                    stored.collection_epoch() == previous_epoch,
                    AuthenticationFailed,
                    "local object envelope is outside the rotation epochs"
                );
                &previous_key
            };
            let content = stored.open(old_key)?;
            ensure!(
                chur_sync_protocol::object_grant::object_key_commitment(
                    payload.collection_id(),
                    object_id,
                    &content
                ) == *object_key_commitment,
                AuthenticationFailed,
                "rewrap key commitment differs from local key"
            );
            let object_key_envelope = if stored.collection_epoch() == current_epoch {
                stored
            } else {
                stored.rewrap(
                    &previous_key,
                    &current_key,
                    *payload.collection_id(),
                    current_epoch,
                    stored.envelope_generation().checked_add(1).ok_or_else(|| {
                        Error::new(
                            ChurStatus::ResourceLimitExceeded,
                            "object envelope generation overflowed",
                        )
                    })?,
                    Nonce::random()?,
                )?
            };
            let outcome = log.accept_with(db, &operation, membership, |transaction| {
                if pending {
                    transaction
                        .execute(
                            "UPDATE pending_object_keys SET envelope = ?2 WHERE object_id = ?1 AND collection_id = ?3",
                            rusqlite::params![
                                object_id.as_bytes().as_slice(),
                                object_key_envelope.encode(),
                                payload.collection_id().as_bytes().as_slice()
                            ],
                        )
                        .map_err(|error| {
                            map_sqlite(error, "pending object envelope could not be rewrapped")
                        })?;
                    return Ok(());
                }
                sync_rotation::project_rewrap(
                    transaction,
                    *operation.vault_id(),
                    *payload.collection_id(),
                    membership,
                    operation.device_id(),
                    now_ms,
                    &previous_key,
                    &current_key,
                    object_key_envelope.clone(),
                    root,
                )?;
                Ok(())
            })?;
            // The rewrap deleted the old envelopes, but their former pages stay
            // in the WAL until a TRUNCATE checkpoint. The completed walk runs
            // one. A blocked checkpoint does not undo the committed rewrap, and
            // every unlock repeats the checkpoint, so its failure is not
            // reported here.
            if outcome == ApplyOutcome::Applied
                && !pending
                && sync_rotation::is_completed(db.connection(), payload.collection_id())?
            {
                let _ = db.checkpoint();
            }
            Ok(outcome)
        }
        _ => Err(Error::new(
            ChurStatus::InvalidInput,
            "operation is not a collection rotation operation",
        )),
    }
}
