//! Aggregate deterministic state derived from accepted decrypted operations.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result};

use crate::convergence::{
    CausalRelation, CausalStamp, MergeOutcome, ObjectLifecycle, ObservedRemoveSet, ScalarRegister,
    causal_relation,
};
use crate::operation::Operation;
use crate::payload::{MetadataFieldId, OperationPayload, PayloadBody};

#[derive(Clone)]
struct MaterializedObject {
    collection_id: Id,
    created: CausalStamp,
    store_id: Id,
    stream_id: Id,
    lifecycle: ObjectLifecycle,
    committed: Option<CommittedObject>,
    metadata: BTreeMap<MetadataFieldId, ScalarRegister<Vec<u8>>>,
}

#[derive(Clone)]
struct MaterializedAlbum {
    collection_id: Id,
    creations: BTreeMap<Id, CausalStamp>,
    initial_name: String,
    name: ScalarRegister<String>,
}

/// Authenticated immutable object information that still requires container verification.
#[derive(Clone)]
pub struct CommittedObject {
    store_id: Id,
    stream_id: Id,
    container_length: u64,
    container_commitment: [u8; 32],
    object_key_commitment: [u8; 32],
}

impl CommittedObject {
    /// Opaque server object identifier.
    #[must_use]
    pub const fn store_id(&self) -> &Id {
        &self.store_id
    }

    /// Primary original stream identifier needed to authenticate its manifest.
    #[must_use]
    pub const fn stream_id(&self) -> &Id {
        &self.stream_id
    }

    /// Complete encoded container length.
    #[must_use]
    pub const fn container_length(&self) -> u64 {
        self.container_length
    }

    /// Authenticated container final commitment.
    #[must_use]
    pub const fn container_commitment(&self) -> &[u8; 32] {
        &self.container_commitment
    }

    /// Key-free object-key commitment carried by the commit.
    #[must_use]
    pub const fn object_key_commitment(&self) -> &[u8; 32] {
        &self.object_key_commitment
    }
}

/// Convergent private state rebuilt from the accepted operation set.
#[derive(Clone, Default)]
pub struct MaterializedState {
    objects: BTreeMap<Id, MaterializedObject>,
    albums: BTreeMap<Id, MaterializedAlbum>,
    album_memberships: ObservedRemoveSet<(Id, Id)>,
    favorites: ObservedRemoveSet<Id>,
    tag_names: BTreeMap<Id, ScalarRegister<String>>,
    object_tags: ObservedRemoveSet<(Id, Id)>,
    deferred: BTreeMap<Id, (Operation, OperationPayload)>,
}

impl MaterializedState {
    /// Empty state before any accepted content operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one already authenticated operation and its bound private payload.
    ///
    /// Atomic: an `Err` or `PendingCause` result leaves the state unchanged, so
    /// callers apply in place and never clone the whole state to roll back.
    pub fn apply(
        &mut self,
        operation: &Operation,
        payload: &OperationPayload,
    ) -> Result<MergeOutcome> {
        let stamp = CausalStamp::from_operation(operation);
        match payload.body() {
            PayloadBody::CreateObject {
                object_id,
                object_generation,
                store_id,
                stream_id,
                metadata_fields,
            } => {
                if self.objects.contains_key(object_id) {
                    return Err(Error::new(
                        ChurStatus::AuthenticationFailed,
                        "object identifier was reused",
                    ));
                }
                let mut metadata = BTreeMap::new();
                for field in metadata_fields {
                    let mut register = ScalarRegister::new();
                    register.apply(stamp.clone(), field.value().to_vec())?;
                    metadata.insert(field.id(), register);
                }
                self.objects.insert(
                    *object_id,
                    MaterializedObject {
                        collection_id: *payload.collection_id(),
                        created: stamp.clone(),
                        store_id: *store_id,
                        stream_id: *stream_id,
                        lifecycle: ObjectLifecycle::new(*object_generation, stamp)?,
                        committed: None,
                        metadata,
                    },
                );
                Ok(MergeOutcome::Applied)
            }
            PayloadBody::CommitObject {
                object_id,
                object_generation,
                store_id,
                container_length,
                container_commitment,
                object_key_commitment,
            } => {
                let Some(object) = self.objects.get_mut(object_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                if *object_generation > object.lifecycle.generation() {
                    return Ok(MergeOutcome::PendingCause);
                }
                // A commit for a generation the object has already been
                // restored past still fills the one immutable commit slot:
                // discarding it as Obsolete made the catalog depend on
                // arrival order, because the same commit applied before the
                // restore and then survived it.
                if object.store_id != *store_id
                    || causal_relation(&object.created, &stamp)? != CausalRelation::Before
                    || object.committed.is_some()
                {
                    return Err(Error::new(
                        ChurStatus::AuthenticationFailed,
                        "object commit contradicts immutable creation state",
                    ));
                }
                object.committed = Some(CommittedObject {
                    store_id: *store_id,
                    stream_id: object.stream_id,
                    container_length: *container_length,
                    container_commitment: *container_commitment,
                    object_key_commitment: *object_key_commitment,
                });
                Ok(MergeOutcome::Applied)
            }
            PayloadBody::UpdateMetadata {
                object_id,
                object_generation,
                field,
            } => {
                let Some(object) = self.objects.get_mut(object_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                if *object_generation > object.lifecycle.generation() {
                    return Ok(MergeOutcome::PendingCause);
                }
                // An edit of a superseded generation still reaches the
                // register: the register resolves causal ordering on its own,
                // and CONFLICT_RESOLUTION.md §6 keeps a concurrent edit in the
                // retained state so a later restore shows it. Discarding it
                // here made the catalog depend on arrival order.
                let mut register = object
                    .metadata
                    .get(&field.id())
                    .cloned()
                    .unwrap_or_default();
                let outcome = register.apply(stamp, field.value().to_vec())?;
                object.metadata.insert(field.id(), register);
                Ok(outcome)
            }
            PayloadBody::CreateAlbum { album_id, name } => {
                if let Some(album) = self.albums.get_mut(album_id) {
                    if album.initial_name != *name
                        || album.collection_id != *payload.collection_id()
                    {
                        return Err(Error::new(
                            ChurStatus::AuthenticationFailed,
                            "album identifier was reused",
                        ));
                    }
                    if let Some(previous) = album.creations.get(stamp.operation_id()) {
                        return if causal_relation(previous, &stamp)? == CausalRelation::Same {
                            Ok(MergeOutcome::Duplicate)
                        } else {
                            Err(Error::new(
                                ChurStatus::AuthenticationFailed,
                                "album creation operation was reused",
                            ))
                        };
                    }
                    for created in album.creations.values() {
                        if causal_relation(created, &stamp)? != CausalRelation::Concurrent {
                            return Err(Error::new(
                                ChurStatus::AuthenticationFailed,
                                "album identifier was reused",
                            ));
                        }
                    }
                    // Old backups can carry the same logical album to two
                    // devices before either authored its first sync record.
                    album.creations.insert(*stamp.operation_id(), stamp);
                    return Ok(MergeOutcome::Applied);
                }
                self.albums.insert(
                    *album_id,
                    MaterializedAlbum {
                        collection_id: *payload.collection_id(),
                        creations: BTreeMap::from([(*stamp.operation_id(), stamp)]),
                        initial_name: name.clone(),
                        // Creation is one shared initial value. A duplicate initial
                        // snapshot must never compete with an explicit rename.
                        name: ScalarRegister::new(),
                    },
                );
                Ok(MergeOutcome::Applied)
            }
            PayloadBody::RenameAlbum { album_id, name } => {
                let Some(album) = self.albums.get_mut(album_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                for created in album.creations.values() {
                    if causal_relation(created, &stamp)? == CausalRelation::After {
                        return Err(Error::new(
                            ChurStatus::AuthenticationFailed,
                            "album rename precedes album creation",
                        ));
                    }
                }
                album.name.apply(stamp, name.clone())
            }
            PayloadBody::AddAlbumMembership {
                album_id,
                object_id,
            } => {
                if !self.albums.contains_key(album_id) || !self.objects.contains_key(object_id) {
                    return Ok(MergeOutcome::PendingCause);
                }
                self.album_memberships.add((*album_id, *object_id), stamp)
            }
            PayloadBody::RemoveAlbumMembership {
                album_id,
                object_id,
                removed_tokens,
            } => self
                .album_memberships
                .remove((*album_id, *object_id), stamp, removed_tokens),
            PayloadBody::SetFavorite {
                object_id,
                favorite,
                removed_tokens,
            } => {
                if !self.objects.contains_key(object_id) {
                    return Ok(MergeOutcome::PendingCause);
                }
                if *favorite {
                    self.favorites.add(*object_id, stamp)
                } else {
                    self.favorites.remove(*object_id, stamp, removed_tokens)
                }
            }
            PayloadBody::AddTag {
                tag_id,
                object_id,
                name,
            } => {
                if !self.objects.contains_key(object_id) {
                    return Ok(MergeOutcome::PendingCause);
                }
                let mut tag_name = self.tag_names.get(tag_id).cloned().unwrap_or_default();
                tag_name.apply(stamp.clone(), name.clone())?;
                let outcome = self.object_tags.add((*tag_id, *object_id), stamp)?;
                self.tag_names.insert(*tag_id, tag_name);
                Ok(outcome)
            }
            PayloadBody::RemoveTag {
                tag_id,
                object_id,
                removed_tokens,
            } => self
                .object_tags
                .remove((*tag_id, *object_id), stamp, removed_tokens),
            PayloadBody::DeleteObject {
                object_id,
                object_generation,
                authored_at_ms,
            } => {
                let Some(object) = self.objects.get_mut(object_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                object
                    .lifecycle
                    .delete(*object_generation, *authored_at_ms, stamp)
            }
            PayloadBody::PurgeObject {
                object_id,
                object_generation,
                ..
            } => {
                let Some(object) = self.objects.get_mut(object_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                object.lifecycle.purge(*object_generation, stamp)
            }
            PayloadBody::RestoreObject {
                object_id,
                tombstone_operation_id,
                new_object_generation,
            } => {
                let Some(object) = self.objects.get_mut(object_id) else {
                    return Ok(MergeOutcome::PendingCause);
                };
                object
                    .lifecycle
                    .restore(tombstone_operation_id, *new_object_generation, stamp)
            }
            PayloadBody::AddDevice(_)
            | PayloadBody::DeviceReady
            | PayloadBody::DeclareCollection { .. }
            | PayloadBody::RevokeDevice(_)
            | PayloadBody::CreateCollectionEpoch { .. }
            | PayloadBody::RewrapObjectKey { .. }
            | PayloadBody::ChangeCollectionMembership(_)
            | PayloadBody::IssueCollectionGrant(_) => Err(Error::new(
                ChurStatus::InvalidInput,
                "security operation is not materialized as content",
            )),
        }
    }

    /// Retains an authenticated fact whose content cause was cut by revocation.
    /// The caller must first verify its ordinary signature, chain and key domain.
    pub fn defer_revoked_content(&mut self, operation: &Operation, payload: &OperationPayload) {
        self.deferred.insert(
            *operation.operation_id(),
            (operation.clone(), payload.clone()),
        );
    }

    /// Accepted content that is still unavailable in this collection.
    #[must_use]
    pub fn pending_operations(&self, collection: Option<&Id>) -> usize {
        self.deferred
            .values()
            .filter(|(_, payload)| collection.is_none_or(|id| payload.collection_id() == id))
            .count()
    }

    /// Retries facts only when a related content target changes. Unrelated
    /// imports do not clone the gallery for each unavailable revoked object.
    /// Returns terminal effects for the caller's same catalog transaction.
    pub fn retry_deferred_after(&mut self, trigger: &OperationPayload) -> Vec<OperationPayload> {
        let targets = content_targets(trigger.body());
        let mut purges = Vec::new();
        loop {
            let ready = self
                .deferred
                .iter()
                .filter_map(|(id, (_, payload))| {
                    let other = content_targets(payload.body());
                    (payload.collection_id() == trigger.collection_id()
                        && targets
                            .iter()
                            .flatten()
                            .any(|target| other.contains(&Some(*target))))
                    .then_some(*id)
                })
                .collect::<Vec<_>>();
            let mut progressed = false;
            for id in ready {
                let Some((operation, payload)) = self.deferred.remove(&id) else {
                    continue;
                };
                match self.apply(&operation, &payload) {
                    Ok(outcome) if outcome != MergeOutcome::PendingCause => {
                        if outcome == MergeOutcome::Applied
                            && matches!(payload.body(), PayloadBody::PurgeObject { .. })
                        {
                            purges.push(payload);
                        }
                        progressed = true;
                    }
                    // An unresolved or contradictory private effect must not
                    // invalidate its authenticated author's unrelated branch.
                    _ => {
                        self.deferred.insert(id, (operation, payload));
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        purges
    }

    /// Whether a permanent deletion has been accepted for this object.
    #[must_use]
    pub fn object_is_purged(&self, id: &Id) -> bool {
        self.objects
            .get(id)
            .is_some_and(|object| object.lifecycle.is_purged())
    }

    /// Accepted immutable objects, including their converged visibility.
    pub fn committed_objects(&self) -> impl Iterator<Item = (Id, Id, u64, bool, &CommittedObject)> {
        self.objects.iter().filter_map(|(id, object)| {
            object.committed.as_ref().map(|commit| {
                (
                    *id,
                    object.collection_id,
                    object.lifecycle.generation(),
                    object.lifecycle.is_visible(),
                    commit,
                )
            })
        })
    }

    /// Displayed metadata bytes for one object field.
    #[must_use]
    pub fn metadata(&self, object_id: &Id, field: MetadataFieldId) -> Option<&[u8]> {
        self.objects
            .get(object_id)?
            .metadata
            .get(&field)?
            .displayed()
            .map(Vec::as_slice)
    }

    /// Deterministically displayed album name.
    #[must_use]
    pub fn album_name(&self, album_id: &Id) -> Option<&str> {
        let album = self.albums.get(album_id)?;
        Some(
            album
                .name
                .displayed()
                .map_or(album.initial_name.as_str(), String::as_str),
        )
    }

    /// Whether an object's live add tokens place it in an album.
    #[must_use]
    pub fn album_contains(&self, album_id: &Id, object_id: &Id) -> bool {
        self.album_memberships.contains(&(*album_id, *object_id))
    }

    /// Accepted live memberships, including media not downloaded locally yet.
    pub fn album_memberships(&self) -> impl Iterator<Item = (Id, Id)> + '_ {
        self.album_memberships.elements().copied()
    }

    /// Live observed add tokens for a catalog membership removal.
    #[must_use]
    pub fn album_membership_tokens(&self, album_id: &Id, object_id: &Id) -> Vec<Id> {
        self.album_memberships.add_tokens(&(*album_id, *object_id))
    }

    /// Whether an object has at least one live favorite token.
    #[must_use]
    pub fn is_favorite(&self, object_id: &Id) -> bool {
        self.favorites.contains(object_id)
    }

    /// Deterministically displayed tag name.
    #[must_use]
    pub fn tag_name(&self, tag_id: &Id) -> Option<&str> {
        self.tag_names.get(tag_id)?.displayed().map(String::as_str)
    }

    /// Immutable commit information, before local container verification.
    #[must_use]
    pub fn committed_object(&self, object_id: &Id) -> Option<&CommittedObject> {
        self.objects.get(object_id)?.committed.as_ref()
    }

    /// Deleted object identifiers that satisfy the authenticated retention gate.
    #[must_use]
    pub fn gc_candidates(
        &self,
        now_ms: u64,
        active_devices: &[Id],
        latest_operations: &BTreeMap<Id, CausalStamp>,
        checkpoint_covers_state: bool,
    ) -> Vec<Id> {
        self.objects
            .iter()
            .filter_map(|(object_id, object)| {
                object
                    .lifecycle
                    .eligible_for_gc(
                        now_ms,
                        active_devices,
                        latest_operations,
                        checkpoint_covers_state,
                    )
                    .then_some(*object_id)
            })
            .collect()
    }

    /// Whether a committed object is visible after tombstone convergence.
    #[must_use]
    pub fn is_presentable(&self, object_id: &Id) -> bool {
        self.objects
            .get(object_id)
            .is_some_and(|object| object.committed.is_some() && object.lifecycle.is_visible())
    }
}

fn content_targets(body: &PayloadBody) -> [Option<Id>; 2] {
    match body {
        PayloadBody::CreateObject { object_id, .. }
        | PayloadBody::CommitObject { object_id, .. }
        | PayloadBody::UpdateMetadata { object_id, .. }
        | PayloadBody::SetFavorite { object_id, .. }
        | PayloadBody::AddTag { object_id, .. }
        | PayloadBody::RemoveTag { object_id, .. }
        | PayloadBody::DeleteObject { object_id, .. }
        | PayloadBody::PurgeObject { object_id, .. }
        | PayloadBody::RestoreObject { object_id, .. } => [Some(*object_id), None],
        PayloadBody::CreateAlbum { album_id, .. } | PayloadBody::RenameAlbum { album_id, .. } => {
            [None, Some(*album_id)]
        }
        PayloadBody::AddAlbumMembership {
            album_id,
            object_id,
        }
        | PayloadBody::RemoveAlbumMembership {
            album_id,
            object_id,
            ..
        } => [Some(*object_id), Some(*album_id)],
        PayloadBody::AddDevice(_)
        | PayloadBody::DeviceReady
        | PayloadBody::DeclareCollection { .. }
        | PayloadBody::RevokeDevice(_)
        | PayloadBody::CreateCollectionEpoch { .. }
        | PayloadBody::RewrapObjectKey { .. }
        | PayloadBody::ChangeCollectionMembership(_)
        | PayloadBody::IssueCollectionGrant(_) => [None, None],
    }
}
