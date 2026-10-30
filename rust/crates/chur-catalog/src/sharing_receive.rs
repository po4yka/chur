//! Recipient-side acceptance of signed collection content and download plans.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::constants::{IntegritySummary, ObjectState, StreamKind};
use chur_sync_protocol::{
    KeyDirectory, KeyDomain,
    collection_membership::{CollectionMembershipRecord, CollectionMembershipState},
    collection_operation::CollectionOperation,
    convergence::{CausalRelation, CausalStamp, MergeOutcome, ObjectLifecycle, causal_relation},
    grant::{CollectionGrant, PermissionProfile},
    operation::Operation,
    operation_log::ApplyOutcome,
    payload::{MetadataField, OperationPayload, PayloadBody},
};

use crate::db::{as_sqlite_integer, map_sqlite};
use crate::model::{Object, Stream};
use crate::schema::bump_generation;
use crate::sharing_log::Accepted;
use crate::{CatalogDb, sharing, sharing_log, sharing_service, store, sync_keys, sync_membership};
use rusqlite::params;

/// Authenticated immutable facts needed to fetch and verify one shared container.
pub struct SharedObject {
    /// Source vault that signed the object commit.
    pub source_vault_id: Id,
    /// Security collection that grants access to the object key.
    pub collection_id: Id,
    /// Stable object identifier.
    pub object_id: Id,
    /// Committed object generation.
    pub object_generation: u64,
    /// Original stream identifier.
    pub stream_id: Id,
    /// Opaque remote store identifier.
    pub store_id: Id,
    /// Exact encoded container length.
    pub container_length: u64,
    /// Signed final chunk commitment.
    pub container_commitment: [u8; 32],
    /// Signed wrapping of the object key.
    pub object_key_commitment: [u8; 32],
    /// Initial private metadata from the creation operation.
    pub metadata: Vec<MetadataField>,
}

/// Current selector and objects that have authenticated commits but no local copy.
pub struct ReceivePlan {
    /// Current collection selector for the paginated transport.
    pub selector: Id,
    /// Source vault identifier.
    pub source_vault_id: Id,
    /// Shared collection identifier.
    pub collection_id: Id,
    /// Committed objects absent from the local catalog.
    pub objects: Vec<SharedObject>,
    /// Records awaiting an earlier signed chain step or causal predecessor.
    pub pending_operations: usize,
    /// Records skipped because their authenticated issuer can never have authored them. Rust only; the FFI plan encoding omits it.
    pub rejected_operations: usize,
}

/// Applies one bounded page only after the issuer chain and addressed grant verify.
#[expect(
    clippy::too_many_arguments,
    reason = "share acceptance needs signed grant and issuer evidence"
)]
pub fn receive(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    issuers: &[sharing_service::IssuerEvidence<'_>],
    membership_records: &[(CollectionMembershipRecord, Operation)],
    grant: &CollectionGrant,
    grant_operation: &Operation,
    records: &[CollectionOperation],
) -> Result<ReceivePlan> {
    let collection_state = sharing_service::accept_share(
        db,
        root,
        issuers,
        membership_records,
        grant,
        grant_operation,
    )?;
    let (states, _) = sharing_service::authenticate_issuers(issuers)?;
    let mut memberships = states
        .into_iter()
        .map(|(vault_id, history)| {
            history
                .into_iter()
                .next_back()
                .map(|(_, state)| (vault_id, state))
                .ok_or_else(|| {
                    Error::new(ChurStatus::AuthenticationFailed, "issuer history is empty")
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let local_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "recipient membership is absent",
        )
    })?;
    ensure!(
        local_membership.vault_id() == &local_vault_id,
        AuthenticationFailed,
        "recipient membership names another vault"
    );
    memberships.insert(local_vault_id, local_membership);
    let collection_key = sync_keys::collection_key(
        db,
        root,
        local_vault_id,
        *collection_state.collection_id(),
        collection_state.collection_epoch(),
    )?;
    let domain = KeyDomain::collection(
        &collection_key,
        collection_state.collection_id(),
        collection_state.collection_epoch(),
    )?;
    let selector = *domain.selector();
    let mut keys = KeyDirectory::new(root, &local_vault_id)?;
    keys.insert(domain)?;
    let mut log = sharing_log::take_cached_log(
        db,
        *collection_state.collection_id(),
        collection_state.collection_epoch(),
        selector,
        &keys,
        &memberships,
        &collection_state,
    )?;
    let source = memberships
        .get(collection_state.source_vault_id())
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "source membership is absent",
            )
        })?;
    let mut pending_operations = 0;
    let mut rejected_operations = 0;
    for record in records {
        let issuer = memberships
            .get(record.issuer_identity_vault_id())
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::AuthenticationFailed,
                    "collection operation issuer is unknown",
                )
            })?;
        // A key that has not arrived is local state: the page fails so a retry can open the record.
        keys.domain(record.key_selector())?;
        let payload = match OperationPayload::open_for_collection_operation(record, &keys) {
            Ok(payload) => payload,
            // With the key held, opening is a function of the record bytes alone, so every
            // failure (seal, version, size, encoding, binding, kind) is the issuer's own.
            Err(_) => {
                collection_state.authenticate_collection_issuer(record, issuer)?;
                rejected_operations += 1;
                continue;
            }
        };
        let outcome = log.accept_with_keys(
            db,
            &keys,
            record,
            &payload,
            issuer,
            source,
            &collection_state,
        )?;
        match outcome {
            Accepted::Outcome(ApplyOutcome::Applied | ApplyOutcome::Duplicate) => {}
            Accepted::Outcome(ApplyOutcome::PendingGap | ApplyOutcome::PendingCause) => {
                pending_operations += 1;
            }
            Accepted::Rejected => rejected_operations += 1,
        }
    }
    sharing_log::store_cached_log(db, selector, log)?;
    let objects = pending_objects(db, &keys, &collection_state, &selector)?;
    Ok(ReceivePlan {
        selector,
        source_vault_id: *collection_state.source_vault_id(),
        collection_id: *collection_state.collection_id(),
        objects,
        pending_operations,
        rejected_operations,
    })
}

/// Resolves pending objects from the accepted, encrypted local operation log.
pub fn pending_for_collection(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    collection_id: Id,
) -> Result<ReceivePlan> {
    if crate::own_sync::is_local_collection(db, &collection_id)? {
        return crate::own_sync::pending_for_collection(db, root, local_vault_id, collection_id);
    }
    let (state, keys, selector) = recipient_context(db, root, local_vault_id, collection_id)?;
    let objects = pending_objects(db, &keys, &state, &selector)?;
    Ok(ReceivePlan {
        selector,
        source_vault_id: *state.source_vault_id(),
        collection_id,
        objects,
        pending_operations: 0,
        rejected_operations: 0,
    })
}

fn recipient_context(
    db: &CatalogDb,
    root: &Key,
    local_vault_id: Id,
    collection_id: Id,
) -> Result<(CollectionMembershipState, KeyDirectory, Id)> {
    let state = sharing::load(db, &collection_id)?
        .ok_or_else(|| Error::new(ChurStatus::NotFound, "shared collection is absent"))?;
    let local_membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "recipient membership is absent",
        )
    })?;
    let (device_id, _) = sync_keys::local_identity(db, root, &local_membership)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "recipient identity is absent"))?;
    ensure!(
        local_membership.vault_id() == &local_vault_id
            && state.is_authorized(&local_vault_id, &device_id, PermissionProfile::Read),
        AuthenticationFailed,
        "local device cannot read the shared collection"
    );
    let collection_key = sync_keys::collection_key(
        db,
        root,
        local_vault_id,
        collection_id,
        state.collection_epoch(),
    )?;
    let domain = KeyDomain::collection(&collection_key, &collection_id, state.collection_epoch())?;
    let selector = *domain.selector();
    let mut keys = KeyDirectory::new(root, &local_vault_id)?;
    keys.insert(domain)?;
    Ok((state, keys, selector))
}

/// Resolves one authenticated object without requiring a transport page cursor.
pub fn pending_object_for_collection(
    db: &mut CatalogDb,
    root: &Key,
    local_vault_id: Id,
    collection_id: Id,
    object_id: Id,
) -> Result<SharedObject> {
    if crate::own_sync::is_local_collection(db, &collection_id)? {
        return crate::own_sync::pending_object_for_collection(
            db,
            root,
            local_vault_id,
            collection_id,
            object_id,
        );
    }
    crate::object_grants::ensure_not_deleted(db, &collection_id, &object_id)?;
    let (state, keys, selector) = recipient_context(db, root, local_vault_id, collection_id)?;
    sharing_log::ensure_object_index(db, &selector, &keys)?;
    let (draft, missing) =
        project_object(db, &keys, &selector, object_id, state.source_vault_id())?;
    ensure!(
        missing == 0,
        NotFound,
        "shared object has a missing operation cause"
    );
    let draft = draft.ok_or_else(|| {
        Error::new(
            ChurStatus::NotFound,
            "shared object has no authenticated creation",
        )
    })?;
    ensure!(!draft.deleted(), NotFound, "shared object is deleted");
    let expected = committed_shared_object(draft, &state, object_id).ok_or_else(|| {
        Error::new(
            ChurStatus::NotFound,
            "shared object has no authenticated commit",
        )
    })?;
    ensure!(
        !store::object_present(db, &object_id)?,
        NotFound,
        "shared object is already activated"
    );
    Ok(expected)
}

struct Draft {
    created_generation: u64,
    created_stamp: CausalStamp,
    lifecycle: ObjectLifecycle,
    store_id: Id,
    stream_id: Id,
    metadata: Vec<MetadataField>,
    commit: Option<(u64, [u8; 32], [u8; 32])>,
}

impl Draft {
    fn deleted(&self) -> bool {
        !self.lifecycle.is_visible()
    }
}

/// Rebuilds the immutable create/commit projection from the accepted local log.
pub fn pending_objects(
    db: &mut CatalogDb,
    keys: &KeyDirectory,
    collection_state: &CollectionMembershipState,
    selector: &Id,
) -> Result<Vec<SharedObject>> {
    let domain = keys.domain(selector)?;
    ensure!(
        domain.collection_id() == collection_state.collection_id()
            && domain.collection_epoch() == collection_state.collection_epoch(),
        AuthenticationFailed,
        "shared object projection uses another collection epoch"
    );
    sharing_log::ensure_object_index(db, selector, keys)?;
    let dirty = sharing_log::dirty_object_ids(db, selector, 4096)?;
    let mut objects = Vec::new();
    for (object_id, revision) in dirty {
        match crate::object_grants::ensure_not_deleted(db, domain.collection_id(), &object_id) {
            Ok(()) => {}
            Err(error) if error.status() == ChurStatus::NotFound => {
                sharing_log::mark_object_clean(db, selector, &object_id, revision)?;
                continue;
            }
            Err(error) => return Err(error),
        }
        let (draft, missing) = project_object(
            db,
            keys,
            selector,
            object_id,
            collection_state.source_vault_id(),
        )?;
        let Some(draft) = draft else {
            // A CommitObject may precede CreateObject across accepted issuers.
            // The later create increments the projection revision and re-dirties it.
            sharing_log::mark_object_clean(db, selector, &object_id, revision)?;
            continue;
        };
        ensure!(
            missing == 0,
            CatalogCorrupt,
            "accepted shared object has an unresolved lifecycle cause"
        );
        let deleted = draft.deleted();
        let generation = draft.lifecycle.generation();
        let created_generation = draft.created_generation;
        let Some(expected) = committed_shared_object(draft, collection_state, object_id) else {
            // A later signed commit will mark this object dirty again.
            sharing_log::mark_object_clean(db, selector, &object_id, revision)?;
            continue;
        };
        if store::object_present(db, &object_id)? {
            let local = store::object(db, &object_id)?;
            let streams = store::streams(db, &object_id)?;
            ensure_present_matches(&local, &streams, &expected)?;
            reconcile_present(db, &local, created_generation, generation, deleted)?;
            sharing_log::mark_object_clean(db, selector, &object_id, revision)?;
            continue;
        }
        if !deleted {
            objects.push(expected);
            if objects.len() == crate::receive_queue::PAGE_MAX {
                break;
            }
        } else {
            sharing_log::mark_object_clean(db, selector, &object_id, revision)?;
        }
    }
    crate::receive_queue::dispatched(
        db,
        collection_state.collection_id(),
        &objects
            .iter()
            .map(|object| object.object_id)
            .collect::<Vec<_>>(),
    )?;
    Ok(objects)
}

fn project_object(
    db: &CatalogDb,
    keys: &KeyDirectory,
    selector: &Id,
    object_id: Id,
    source_vault_id: &Id,
) -> Result<(Option<Draft>, usize)> {
    let mut payloads = Vec::new();
    sharing_log::visit_object_records(db, keys, selector, &object_id, |record, payload| {
        payloads.push((CausalStamp::from_collection_operation(&record), payload));
        Ok(())
    })?;
    let (mut drafts, missing) = project_drafts(&payloads, source_vault_id)?;
    ensure!(
        drafts.len() <= 1,
        CatalogCorrupt,
        "object index contains another object"
    );
    Ok((drafts.remove(&object_id), missing))
}

/// Checks a new lifecycle event against the already accepted object history
/// before the signed operation and fail-closed hide become durable.
pub(crate) fn validate_lifecycle_candidate(
    db: &CatalogDb,
    keys: &KeyDirectory,
    source_vault_id: &Id,
    record: &CollectionOperation,
    payload: &OperationPayload,
) -> Result<Accepted> {
    let object_id = match payload.body() {
        PayloadBody::CreateObject { object_id, .. }
        | PayloadBody::CommitObject { object_id, .. }
        | PayloadBody::DeleteObject { object_id, .. }
        | PayloadBody::PurgeObject { object_id, .. }
        | PayloadBody::RestoreObject { object_id, .. } => *object_id,
        _ => return Ok(Accepted::Outcome(ApplyOutcome::Applied)),
    };
    let creation = matches!(
        payload.body(),
        PayloadBody::CreateObject { .. } | PayloadBody::CommitObject { .. }
    );
    let mut records = Vec::new();
    sharing_log::visit_object_records(
        db,
        keys,
        record.key_selector(),
        &object_id,
        |accepted, body| {
            records.push((CausalStamp::from_collection_operation(&accepted), body));
            Ok(())
        },
    )?;
    records.push((
        CausalStamp::from_collection_operation(record),
        payload.clone(),
    ));
    // Projection reads no state beyond these records, and the stored ones already projected,
    // so any failure is the candidate's.
    let Ok((_, missing)) = project_drafts(&records, source_vault_id) else {
        return Ok(Accepted::Rejected);
    };
    // A creation or commit never waits: projection keeps a commit until its creation arrives.
    Ok(Accepted::Outcome(if missing == 0 || creation {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::PendingCause
    }))
}

/// Refuses legacy accepted lifecycle records that cannot converge before
/// marking their v6 object index ready for recipient reads.
pub(crate) fn validate_backfill_lifecycle(
    records: &[(CausalStamp, OperationPayload)],
    source_vault_id: &Id,
) -> Result<()> {
    let relevant = records
        .iter()
        .filter(|(_, payload)| {
            matches!(
                payload.body(),
                PayloadBody::CreateObject { .. }
                    | PayloadBody::DeleteObject { .. }
                    | PayloadBody::PurgeObject { .. }
                    | PayloadBody::RestoreObject { .. }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if relevant.is_empty() {
        return Ok(());
    }
    let (_, missing) = project_drafts(&relevant, source_vault_id)?;
    ensure!(
        missing == 0,
        CatalogCorrupt,
        "accepted shared lifecycle has a missing cause"
    );
    Ok(())
}

fn committed_shared_object(
    draft: Draft,
    state: &CollectionMembershipState,
    object_id: Id,
) -> Option<SharedObject> {
    let (container_length, container_commitment, object_key_commitment) = draft.commit?;
    Some(SharedObject {
        source_vault_id: *state.source_vault_id(),
        collection_id: *state.collection_id(),
        object_id,
        object_generation: draft.lifecycle.generation(),
        stream_id: draft.stream_id,
        store_id: draft.store_id,
        container_length,
        container_commitment,
        object_key_commitment,
        metadata: draft.metadata,
    })
}

fn ensure_present_matches(
    local: &Object,
    streams: &[Stream],
    expected: &SharedObject,
) -> Result<()> {
    ensure!(
        local.collection_id == expected.collection_id
            && local.object_generation <= expected.object_generation
            && local.primary_stream_id == expected.stream_id
            && streams.iter().any(|stream| {
                stream.stream_kind == StreamKind::Original
                    && stream.stream_id == expected.stream_id
                    && stream.ciphertext_size == expected.container_length
                    && stream.final_commitment == expected.container_commitment
            }),
        Conflict,
        "existing shared object contradicts its signed commit"
    );
    Ok(())
}

fn reconcile_present(
    db: &mut CatalogDb,
    local: &Object,
    created_generation: u64,
    generation: u64,
    deleted: bool,
) -> Result<()> {
    ensure!(
        matches!(
            local.state,
            ObjectState::Active | ObjectState::SharedDeleted
        ) && local.object_generation >= created_generation
            && local.object_generation <= generation,
        Conflict,
        "existing shared object has an incompatible lifecycle state"
    );
    let target = if deleted {
        ObjectState::SharedDeleted
    } else {
        ObjectState::Active
    };
    if local.state == target && local.object_generation == generation {
        return Ok(());
    }
    ensure!(
        local.state != ObjectState::SharedDeleted
            || deleted
            || local.object_generation < generation,
        Conflict,
        "shared object cannot become active without a newer restore"
    );
    // A restore changes visibility, not the verification verdict of retained bytes.
    let summary = IntegritySummary::Unverified;
    let generation = as_sqlite_integer(generation, "shared object generation is too large")?;
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE objects SET object_generation = ?2, state = ?3, integrity_summary = ?4
                 WHERE object_id = ?1 AND object_generation = ?5 AND state = ?6",
                params![
                    local.object_id.as_bytes().as_slice(),
                    generation,
                    i64::from(target.value()),
                    i64::from(summary.value()),
                    as_sqlite_integer(
                        local.object_generation,
                        "shared object generation is too large"
                    )?,
                    i64::from(local.state.value()),
                ],
            )
            .map_err(|error| map_sqlite(error, "shared object lifecycle could not be projected"))?;
        ensure!(
            changed == 1,
            Conflict,
            "shared object lifecycle changed concurrently"
        );
        bump_generation(transaction)
    })
}

fn project_drafts(
    payloads: &[(CausalStamp, OperationPayload)],
    _source_vault_id: &Id,
) -> Result<(BTreeMap<Id, Draft>, usize)> {
    let mut drafts = BTreeMap::<Id, Draft>::new();
    let mut missing_creations = 0;
    for (stamp, payload) in payloads {
        if let PayloadBody::CreateObject {
            object_id,
            object_generation,
            store_id,
            stream_id,
            metadata_fields,
        } = payload.body()
        {
            ensure!(
                drafts
                    .insert(
                        *object_id,
                        Draft {
                            created_generation: *object_generation,
                            created_stamp: stamp.clone(),
                            lifecycle: ObjectLifecycle::new(*object_generation, stamp.clone())?,
                            store_id: *store_id,
                            stream_id: *stream_id,
                            metadata: metadata_fields.clone(),
                            commit: None,
                        }
                    )
                    .is_none(),
                AuthenticationFailed,
                "shared object has two creation records"
            );
        }
    }
    for (stamp, payload) in payloads {
        match payload.body() {
            PayloadBody::CreateObject { .. } => {}
            PayloadBody::CommitObject {
                object_id,
                object_generation,
                store_id,
                container_length,
                container_commitment,
                object_key_commitment,
            } => {
                let Some(draft) = drafts.get_mut(object_id) else {
                    missing_creations += 1;
                    continue;
                };
                ensure!(
                    draft.created_generation == *object_generation
                        && draft.store_id == *store_id
                        && draft.commit.is_none()
                        && causal_relation(&draft.created_stamp, stamp)? == CausalRelation::Before,
                    AuthenticationFailed,
                    "shared commit contradicts its creation"
                );
                draft.commit = Some((
                    *container_length,
                    *container_commitment,
                    *object_key_commitment,
                ));
            }
            _ => {}
        }
    }
    // Collection records are stored by participant, not global causal order.
    // Generations give lifecycle operations a stable order across participants.
    let mut lifecycle = payloads
        .iter()
        .filter_map(|(stamp, payload)| match payload.body() {
            PayloadBody::DeleteObject {
                object_id,
                object_generation,
                authored_at_ms,
            } => Some((
                *object_generation,
                false,
                stamp,
                *object_id,
                *authored_at_ms,
                None,
            )),
            PayloadBody::RestoreObject {
                object_id,
                tombstone_operation_id,
                new_object_generation,
            } => Some((
                *new_object_generation,
                true,
                stamp,
                *object_id,
                0,
                Some(*tombstone_operation_id),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    lifecycle.sort_unstable_by_key(|(generation, restore, stamp, ..)| {
        (*generation, !*restore, *stamp.operation_id())
    });
    for (generation, _restore, stamp, object_id, authored_at_ms, tombstone_id) in lifecycle {
        let Some(draft) = drafts.get_mut(&object_id) else {
            missing_creations += 1;
            continue;
        };
        let outcome = if let Some(tombstone_id) = tombstone_id {
            draft
                .lifecycle
                .restore(&tombstone_id, generation, stamp.clone())?
        } else {
            draft
                .lifecycle
                .delete(generation, authored_at_ms, stamp.clone())?
        };
        if outcome == MergeOutcome::PendingCause {
            missing_creations += 1;
        }
    }
    for (stamp, payload) in payloads {
        if let PayloadBody::PurgeObject {
            object_id,
            object_generation,
            ..
        } = payload.body()
        {
            let Some(draft) = drafts.get_mut(object_id) else {
                missing_creations += 1;
                continue;
            };
            if draft.lifecycle.purge(*object_generation, stamp.clone())?
                == MergeOutcome::PendingCause
            {
                missing_creations += 1;
            }
        }
    }
    Ok((drafts, missing_creations))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use crate::db::{CatalogKey, CatalogLocation};
    use crate::model::Collection;
    use crate::schema;
    use chur_crypto::{Key, Nonce};
    use chur_format::constants::{IntegritySummary, MediaClass};
    use chur_sync_protocol::{
        collection_operation::CollectionObservedHead, membership::EnrollmentRecord,
        operation::DeviceSigningKey, state::MembershipState,
    };

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn stamp(operation_id: Id, sequence: u64) -> CausalStamp {
        collection_stamp(operation_id, id(2), id(20), sequence, Vec::new())
    }

    fn collection_stamp(
        operation_id: Id,
        vault_id: Id,
        device_id: Id,
        sequence: u64,
        observed_heads: Vec<CollectionObservedHead>,
    ) -> CausalStamp {
        let record = CollectionOperation::new(
            operation_id,
            vault_id,
            device_id,
            sequence,
            if sequence == 1 { [0; 32] } else { [1; 32] },
            observed_heads,
            id(21),
            vec![7; 40],
            [9; 64],
        )
        .expect("collection record");
        CausalStamp::from_collection_operation(&record)
    }

    fn queued_ready_object() -> (CatalogDb, KeyDirectory, CollectionMembershipState, Id, Id) {
        let source = id(2);
        let collection = id(21);
        let ready = id(200);
        let catalog_root = Key::new([1; 32]);
        let catalog_key = CatalogKey::derive(&catalog_root, &source).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &catalog_key).expect("catalog");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        let state = sharing::provision(&mut db, source, collection, 1).expect("sharing");
        let domain = KeyDomain::collection(&Key::new([3; 32]), &collection, 1).expect("domain");
        let selector = *domain.selector();
        let operation_key = Key::new(*domain.operation_key().expose());
        let mut keys = KeyDirectory::new(&catalog_root, &source).expect("keys");
        keys.insert(domain).expect("domain key");
        let signing = DeviceSigningKey::from_seed([4; 32]);
        let enrollment =
            EnrollmentRecord::initial(source, id(20), signing.verifying_key(), [5; 32])
                .expect("enrollment")
                .sign(&signing);
        let membership = MembershipState::bootstrap(&enrollment).expect("membership");
        let mut log =
            sharing_log::DurableCollectionOperationLog::provision(&mut db, collection, 1, selector)
                .expect("log");
        let create = OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateObject {
                object_id: ready,
                object_generation: 1,
                store_id: id(201),
                stream_id: id(202),
                metadata_fields: Vec::new(),
            },
        )
        .expect("create");
        let commit = OperationPayload::new(
            collection,
            1,
            PayloadBody::CommitObject {
                object_id: ready,
                object_generation: 1,
                store_id: id(201),
                container_length: 64,
                container_commitment: [6; 32],
                object_key_commitment: [9; 32],
            },
        )
        .expect("commit");
        for (operation_id, nonce, payload) in [(id(203), 10, create), (id(204), 11, commit)] {
            log.author(
                &mut db,
                operation_id,
                source,
                id(20),
                &operation_key,
                Nonce::new([nonce; 24]),
                &payload,
                &signing,
                &membership,
                &membership,
                &state,
            )
            .expect("accepted object event");
        }
        (db, keys, state, selector, ready)
    }

    fn insert_incomplete_queue_prefix(db: &mut CatalogDb, selector: &Id, count: usize) {
        db.transaction(|transaction| {
            for index in 0..count {
                let mut bytes = [0; 16];
                bytes[0] = 1;
                bytes[14..].copy_from_slice(&(index as u16).to_be_bytes());
                transaction
                    .execute(
                        "INSERT INTO sharing_object_projection
                             (key_selector, object_id, revision, dirty) VALUES (?1, ?2, 1, 1)",
                        params![selector.as_bytes().as_slice(), bytes.as_slice()],
                    )
                    .map_err(|error| map_sqlite(error, "incomplete queue fixture failed"))?;
            }
            schema::bump_generation(transaction)
        })
        .expect("incomplete queue");
    }

    #[test]
    fn incomplete_queue_page_releases_later_ready_object_on_next_plan() {
        let (mut db, keys, state, selector, ready) = queued_ready_object();
        insert_incomplete_queue_prefix(&mut db, &selector, 4096);
        assert!(
            pending_objects(&mut db, &keys, &state, &selector)
                .expect("first bounded page")
                .is_empty()
        );
        assert_eq!(
            sharing_log::dirty_object_ids(&db, &selector, 4096).expect("remaining queue"),
            vec![(ready, 2)]
        );
        let ready_page =
            pending_objects(&mut db, &keys, &state, &selector).expect("next bounded page");
        assert_eq!(ready_page.len(), 1);
        assert_eq!(ready_page[0].object_id, ready);
    }

    #[test]
    fn incomplete_and_ready_objects_share_a_page_without_blocking_download() {
        let (mut db, keys, state, selector, ready) = queued_ready_object();
        insert_incomplete_queue_prefix(&mut db, &selector, 1);
        let page = pending_objects(&mut db, &keys, &state, &selector).expect("mixed page");
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].object_id, ready);
        assert_eq!(
            sharing_log::dirty_object_ids(&db, &selector, 4096).expect("remaining queue"),
            vec![(ready, 2)]
        );
    }

    #[test]
    fn cross_vault_delete_must_observe_creation_and_restore_its_tombstone() {
        let created = collection_stamp(id(30), id(2), id(20), 1, Vec::new());
        let unobserved_delete = collection_stamp(id(31), id(3), id(21), 1, Vec::new());
        let mut lifecycle = ObjectLifecycle::new(1, created.clone()).expect("created");
        assert_eq!(
            lifecycle
                .delete(1, 1, unobserved_delete)
                .expect_err("unobserved delete")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        let delete = collection_stamp(
            id(32),
            id(3),
            id(21),
            1,
            vec![CollectionObservedHead::new(id(2), id(20), 1)],
        );
        assert_eq!(
            lifecycle.delete(1, 1, delete.clone()).expect("delete"),
            MergeOutcome::Applied
        );
        assert!(!lifecycle.is_visible());
        let unobserved_restore = collection_stamp(id(33), id(4), id(22), 1, Vec::new());
        assert_eq!(
            lifecycle
                .restore(&id(32), 2, unobserved_restore)
                .expect_err("unobserved restore")
                .status(),
            ChurStatus::AuthenticationFailed
        );
        let restore = collection_stamp(
            id(34),
            id(4),
            id(22),
            1,
            vec![CollectionObservedHead::new(id(3), id(21), 1)],
        );
        assert_eq!(
            lifecycle.restore(&id(32), 2, restore).expect("restore"),
            MergeOutcome::Applied
        );
        assert!(lifecycle.is_visible());
    }

    #[test]
    fn legacy_lifecycle_backfill_rejects_missing_or_invalid_causes() {
        let collection = id(1);
        let object_id = id(3);
        let create = OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateObject {
                object_id,
                object_generation: 1,
                store_id: id(4),
                stream_id: id(5),
                metadata_fields: Vec::new(),
            },
        )
        .expect("create");
        let delete = OperationPayload::new(
            collection,
            1,
            PayloadBody::DeleteObject {
                object_id,
                object_generation: 1,
                authored_at_ms: 1,
            },
        )
        .expect("delete");
        let unobserved = collection_stamp(id(7), id(3), id(21), 1, Vec::new());
        assert_eq!(
            validate_backfill_lifecycle(&[(unobserved.clone(), delete.clone())], &id(2))
                .expect_err("missing creation")
                .status(),
            ChurStatus::CatalogCorrupt
        );
        assert_eq!(
            validate_backfill_lifecycle(
                &[
                    (
                        collection_stamp(id(6), id(2), id(20), 1, Vec::new()),
                        create,
                    ),
                    (unobserved, delete),
                ],
                &id(2),
            )
            .expect_err("unobserved creation")
            .status(),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn commit_before_create_in_device_order_projects_and_incomplete_page_waits() {
        let collection = id(1);
        let source = id(2);
        let object = id(3);
        let store = id(4);
        let create = OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateObject {
                object_id: object,
                object_generation: 1,
                store_id: store,
                stream_id: id(8),
                metadata_fields: Vec::new(),
            },
        )
        .expect("create");
        let commit = OperationPayload::new(
            collection,
            1,
            PayloadBody::CommitObject {
                object_id: object,
                object_generation: 1,
                store_id: store,
                container_length: 64,
                container_commitment: [9; 32],
                object_key_commitment: [7; 32],
            },
        )
        .expect("commit");

        let (incomplete, pending) =
            project_drafts(&[(stamp(id(9), 2), commit.clone())], &source).expect("incomplete page");
        assert!(incomplete.is_empty());
        assert_eq!(pending, 1);

        let (reversed, pending) = project_drafts(
            &[(stamp(id(9), 2), commit), (stamp(id(10), 1), create)],
            &source,
        )
        .expect("reversed order");
        assert_eq!(pending, 0);
        let draft = reversed.get(&object).expect("created object");
        assert_eq!(draft.commit.as_ref().map(|commit| commit.0), Some(64));
    }

    #[test]
    fn present_object_must_match_signed_generation_and_original_commit() {
        let collection = id(1);
        let source = id(2);
        let object_id = id(3);
        let stream_id = id(4);
        let expected = SharedObject {
            source_vault_id: source,
            collection_id: collection,
            object_id,
            object_generation: 2,
            stream_id,
            store_id: id(5),
            container_length: 64,
            container_commitment: [9; 32],
            object_key_commitment: [9; 32],
            metadata: Vec::new(),
        };
        let local = Object {
            object_id,
            object_generation: 2,
            collection_id: collection,
            primary_stream_id: stream_id,
            media_kind: MediaClass::Image,
            capture_time_ms: 1,
            import_time_ms: 1,
            capture_time_substituted: false,
            plaintext_size: 32,
            width: 1,
            height: 1,
            duration_ms: 0,
            favorite: false,
            state: ObjectState::Active,
            integrity_summary: IntegritySummary::CompleteVerified,
            thumbnail_ready: false,
            active_metadata_revision: 1,
        };
        let stream = Stream {
            stream_id,
            object_id,
            stream_kind: StreamKind::Original,
            stream_revision: 1,
            source_content_revision: 0,
            container_path_id: object_id,
            container_version: 1,
            suite_id: 1,
            ciphertext_size: 64,
            plaintext_size: 32,
            chunk_size: 262_144,
            complete_verified_ms: Some(1),
            final_commitment: [9; 32],
        };
        assert!(ensure_present_matches(&local, std::slice::from_ref(&stream), &expected).is_ok());

        let mut future_generation = local.clone();
        future_generation.object_generation = 3;
        assert_eq!(
            ensure_present_matches(&future_generation, std::slice::from_ref(&stream), &expected)
                .expect_err("generation mismatch")
                .status(),
            ChurStatus::Conflict,
        );
        let mut other_commit = stream.clone();
        other_commit.final_commitment = [10; 32];
        assert_eq!(
            ensure_present_matches(&local, &[other_commit], &expected)
                .expect_err("commitment mismatch")
                .status(),
            ChurStatus::Conflict,
        );
        let mut inactive = local.clone();
        inactive.state = ObjectState::Tombstoned;
        assert!(
            ensure_present_matches(&inactive, std::slice::from_ref(&stream), &expected).is_ok()
        );
        // The immutable signed container check is independent of lifecycle.
        // reconcile_present rejects an irreversible local tombstone.
    }

    #[test]
    fn delete_then_restore_before_download_keeps_original_commit_and_advances_generation() {
        let collection = id(1);
        let source = id(2);
        let object = id(3);
        let store = id(4);
        let create = OperationPayload::new(
            collection,
            1,
            PayloadBody::CreateObject {
                object_id: object,
                object_generation: 1,
                store_id: store,
                stream_id: id(5),
                metadata_fields: Vec::new(),
            },
        )
        .expect("create");
        let commit = OperationPayload::new(
            collection,
            1,
            PayloadBody::CommitObject {
                object_id: object,
                object_generation: 1,
                store_id: store,
                container_length: 64,
                container_commitment: [7; 32],
                object_key_commitment: [9; 32],
            },
        )
        .expect("commit");
        let delete = OperationPayload::new(
            collection,
            1,
            PayloadBody::DeleteObject {
                object_id: object,
                object_generation: 1,
                authored_at_ms: 1,
            },
        )
        .expect("delete");
        let restore = OperationPayload::new(
            collection,
            1,
            PayloadBody::RestoreObject {
                object_id: object,
                tombstone_operation_id: id(11),
                new_object_generation: 2,
            },
        )
        .expect("restore");
        let records = [
            (stamp(id(12), 4), restore.clone()),
            (stamp(id(13), 2), commit),
            (stamp(id(11), 3), delete),
            (stamp(id(14), 1), create),
        ];
        let (drafts, pending) = project_drafts(&records, &source).expect("projection");
        assert_eq!(pending, 0);
        let draft = drafts.get(&object).expect("object");
        assert!(!draft.deleted());
        assert_eq!(draft.lifecycle.generation(), 2);
        assert_eq!(draft.commit.as_ref().map(|commit| commit.0), Some(64));

        let second_delete = OperationPayload::new(
            collection,
            1,
            PayloadBody::DeleteObject {
                object_id: object,
                object_generation: 2,
                authored_at_ms: 2,
            },
        )
        .expect("second delete");
        let (drafts, pending) = project_drafts(
            &[
                (stamp(id(16), 5), second_delete),
                records[0].clone(),
                records[1].clone(),
                records[2].clone(),
                records[3].clone(),
            ],
            &source,
        )
        .expect("delete after restore");
        assert_eq!(pending, 0);
        let draft = drafts.get(&object).expect("object");
        assert!(draft.deleted());
        assert_eq!(draft.lifecycle.generation(), 2);

        let without_restore = &records[1..];
        let (drafts, pending) =
            project_drafts(without_restore, &source).expect("deleted projection");
        assert_eq!(pending, 0);
        assert!(drafts.get(&object).expect("object").deleted());

        let bad_restore = OperationPayload::new(
            collection,
            1,
            PayloadBody::RestoreObject {
                object_id: object,
                tombstone_operation_id: id(15),
                new_object_generation: 2,
            },
        )
        .expect("bad restore");
        let (drafts, pending) = project_drafts(
            &[
                (stamp(id(12), 4), bad_restore),
                records[1].clone(),
                records[2].clone(),
                records[3].clone(),
            ],
            &source,
        )
        .expect("missing tombstone");
        assert_eq!(pending, 1);
        assert!(drafts.get(&object).expect("object").deleted());
    }

    #[test]
    fn received_delete_hides_without_crypto_erasure_and_restore_reactivates() {
        let root = Key::new([1; 32]);
        let key = CatalogKey::derive(&root, &id(2)).expect("catalog key");
        let directory = std::env::temp_dir().join(format!(
            "chur-shared-lifecycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("test directory");
        let path = directory.join("catalog.db");
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &key).expect("catalog");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        let collection_id = id(3);
        store::put_collection(
            &mut db,
            &Collection {
                collection_id,
                current_epoch: 1,
                policy_type: 2,
                created_revision: 1,
                status: 1,
            },
        )
        .expect("collection");
        let object_id = id(4);
        db.connection()
            .execute(
                "INSERT INTO objects (
                    object_id, object_generation, collection_id, primary_stream_id, media_kind,
                    capture_time_ms, import_time_ms, capture_time_substituted, plaintext_size,
                    width, height, duration_ms, favorite, state, integrity_summary,
                    thumbnail_ready, active_metadata_revision, search_key
                ) VALUES (?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 4, 0, 1, 1)",
                params![
                    object_id.as_bytes().as_slice(),
                    collection_id.as_bytes().as_slice(),
                    id(5).as_bytes().as_slice(),
                ],
            )
            .expect("object");
        let active = store::object(&db, &object_id).expect("row");
        reconcile_present(&mut db, &active, 1, 1, true).expect("delete");
        let hidden = store::object(&db, &object_id).expect("hidden row");
        assert_eq!(hidden.state, ObjectState::SharedDeleted);
        assert_eq!(hidden.integrity_summary, IntegritySummary::Unverified);
        assert!(crate::deletion::sweep(&db).expect("sweep").is_empty());
        db.close().expect("close after delete");
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &key).expect("reopen");
        schema::open_at_current_version(&mut db, 2).expect("current schema");
        let hidden = store::object(&db, &object_id).expect("hidden after restart");
        assert_eq!(hidden.state, ObjectState::SharedDeleted);
        assert!(
            crate::deletion::sweep(&db)
                .expect("sweep after restart")
                .is_empty()
        );
        reconcile_present(&mut db, &hidden, 1, 2, false).expect("restore");
        let restored = store::object(&db, &object_id).expect("restored row");
        assert_eq!(restored.state, ObjectState::Active);
        assert_eq!(restored.object_generation, 2);
        assert_eq!(restored.integrity_summary, IntegritySummary::Unverified);
        db.close().expect("close after restore");
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
