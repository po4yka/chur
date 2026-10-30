//! Key-free media publication and receive plans for enrolled devices of one vault.

use std::collections::{BTreeMap, BTreeSet};

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::constants::ObjectState;
use chur_format::envelope::ObjectKeyEnvelope;
use chur_sync_protocol::{
    KeyDirectory, KeyDomain,
    materialization::MaterializedState,
    object_grant::object_key_commitment,
    operation::Operation,
    payload::{MetadataField, MetadataFieldId, OperationPayload, PayloadBody},
    state::MembershipState,
};
use rusqlite::params;

use crate::{
    CatalogDb,
    db::map_sqlite,
    model::COLLECTION_POLICY_SHARED,
    sharing_publication::{self, Candidate},
    sharing_receive::{ReceivePlan, SharedObject},
    store, sync_keys, sync_log, sync_membership, sync_receive,
};

/// Signed own-vault operations for one verified source container.
pub struct Publication {
    /// Committed source identity.
    pub candidate: Candidate,
    /// Durable creation operation.
    pub create_operation: Operation,
    /// Durable key-free commit operation.
    pub commit_operation: Operation,
}

/// Local collections that belong to this vault rather than an external source.
pub fn collection_ids(db: &CatalogDb) -> Result<Vec<Id>> {
    let mut statement = db
        .connection()
        .prepare(
            "SELECT collection_id FROM collections WHERE policy_type != ?1 ORDER BY collection_id",
        )
        .map_err(|error| map_sqlite(error, "own collections could not be listed"))?;
    let rows = statement
        .query_map([i64::from(COLLECTION_POLICY_SHARED)], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|error| map_sqlite(error, "own collections could not be read"))?;
    rows.map(|row| {
        crate::row::id(
            &row.map_err(|error| map_sqlite(error, "own collection ID could not be read"))?,
            "own collection ID is malformed",
        )
    })
    .collect()
}

/// Whether an existing collection is locally owned.
pub fn is_local_collection(db: &CatalogDb, collection_id: &Id) -> Result<bool> {
    Ok(store::collection(db, collection_id)?.policy_type != COLLECTION_POLICY_SHARED)
}

/// Verified source history retained only for this unlocked catalog connection.
pub(crate) struct SourceCache {
    generation: u64,
    albums_bootstrapped: bool,
    ready_album_objects: BTreeSet<Id>,
    vault_id: Id,
    keys: KeyDirectory,
    log: sync_log::DurableOperationLog,
    state: MaterializedState,
    declarations: BTreeSet<(Id, u64)>,
    creates: BTreeMap<(Id, Id), Operation>,
    commits: BTreeMap<(Id, Id), Operation>,
}

fn take_source_cache(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    membership: &MembershipState,
) -> Result<SourceCache> {
    let generation = crate::schema::generation(db)?;
    let mut albums_bootstrapped = false;
    let mut ready_album_objects = BTreeSet::new();
    if let Some(cache) = db.own_source_cache.take()
        && cache.vault_id == vault_id
    {
        // Validate the complete derived key even when unrelated media changes
        // require replay. Preserve the legacy bootstrap result across them.
        let domain = KeyDomain::root(root, &vault_id)?;
        cache.keys.domain(domain.selector())?;
        cache.keys.check_insert(&domain)?;
        albums_bootstrapped = cache.albums_bootstrapped;
        ready_album_objects = cache.ready_album_objects.clone();
        if cache.generation == generation {
            return Ok(cache);
        }
    }
    #[cfg(test)]
    {
        db.own_source_replays += 1;
    }
    let keys = sync_keys::key_directory(db, root, vault_id)?;
    let log = sync_log::load(db, membership)?;
    let state = sync_receive::load_materialized_state(db, &keys)?;
    let mut cache = SourceCache {
        generation,
        albums_bootstrapped,
        ready_album_objects,
        vault_id,
        keys,
        log,
        state,
        declarations: BTreeSet::new(),
        creates: BTreeMap::new(),
        commits: BTreeMap::new(),
    };
    for issuer in sync_log::device_ids(db)? {
        let mut after = 0;
        loop {
            let page = sync_log::records_after(db, &issuer, after)?;
            if page.is_empty() {
                break;
            }
            for record in page {
                let operation = Operation::decode(&record)?;
                after = operation.device_sequence();
                let payload = OperationPayload::open_for_operation(&operation, &cache.keys)?;
                match payload.body() {
                    PayloadBody::DeclareCollection {
                        collection_key_envelope,
                    } => {
                        cache.declarations.insert((
                            *collection_key_envelope.collection_id(),
                            collection_key_envelope.collection_epoch(),
                        ));
                    }
                    PayloadBody::CreateObject { object_id, .. } => {
                        cache
                            .creates
                            .insert((*payload.collection_id(), *object_id), operation);
                    }
                    PayloadBody::CommitObject { object_id, .. } => {
                        cache
                            .commits
                            .insert((*payload.collection_id(), *object_id), operation);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(cache)
}

// This cache is discarded on every failed call. Apply in place rather than
// clone the whole gallery for each new object, then persist the accepted log.
fn author_cached_content(
    db: &mut CatalogDb,
    cache: &mut SourceCache,
    membership: &MembershipState,
    domain: &KeyDomain,
    device: Id,
    signing_key: &chur_sync_protocol::operation::DeviceSigningKey,
    payload: &OperationPayload,
) -> Result<Operation> {
    ensure!(
        matches!(
            payload.body(),
            PayloadBody::CreateObject { .. } | PayloadBody::CommitObject { .. }
        ),
        InvalidInput,
        "source cache authors only immutable object facts"
    );
    let operation = cache.log.author(
        chur_crypto::random::id()?,
        *membership.vault_id(),
        device,
        *domain.selector(),
        domain.operation_key(),
        chur_crypto::Nonce::random()?,
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
        cache.state.apply(&operation, payload)?
            == chur_sync_protocol::convergence::MergeOutcome::Applied,
        InvalidInput,
        "source content does not change accepted state"
    );
    let resolved_purges = cache.state.retry_deferred_after(payload);
    ensure!(
        cache.log.accept_with(db, &operation, membership, |tx| {
            for purge in &resolved_purges {
                crate::deletion::project_purge(tx, purge)?;
            }
            Ok(())
        })? == chur_sync_protocol::operation_log::ApplyOutcome::Applied,
        InternalFailure,
        "source content was not applied"
    );
    Ok(operation)
}

/// Authors immutable media facts in the ordinary device operation chain.
pub fn publish(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    collection_id: Id,
    candidates: &[Candidate],
) -> Result<Vec<Publication>> {
    ensure!(
        candidates.len() == 1 && is_local_collection(db, &collection_id)?,
        InvalidInput,
        "own publication requires one local source object"
    );
    // These checks run on every call, including a cache hit after revocation.
    let mut membership = sync_membership::load(db)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "own membership is absent"))?;
    ensure!(
        membership.vault_id() == &vault_id,
        AuthenticationFailed,
        "own membership names another vault"
    );
    let (device, identity) = sync_keys::local_identity(db, root, &membership)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "own identity is absent"))?;
    let mut cache = take_source_cache(db, root, vault_id, &membership)?;
    let result = (|| {
        let collection = store::collection(db, &collection_id)?;
        if !cache
            .declarations
            .contains(&(collection_id, collection.current_epoch))
        {
            let envelope = chur_format::envelope::CollectionKeyEnvelope::decode(
                &store::active_collection_envelope(db, &collection_id, collection.current_epoch)?,
            )?;
            let payload = OperationPayload::new(
                vault_id,
                0,
                PayloadBody::DeclareCollection {
                    collection_key_envelope: envelope,
                },
            )?;
            let domain = KeyDomain::root(root, &vault_id)?;
            let operation = cache.log.author(
                chur_crypto::random::id()?,
                vault_id,
                device,
                *domain.selector(),
                domain.operation_key(),
                chur_crypto::Nonce::random()?,
                &payload.encode(),
                identity.signing_key(),
                &membership,
            )?;
            ensure!(
                sync_receive::accept_operation(
                    db,
                    &mut cache.log,
                    &mut membership,
                    &mut cache.state,
                    &mut cache.keys,
                    root,
                    0,
                    &operation.encode()
                )? == chur_sync_protocol::operation_log::ApplyOutcome::Applied,
                InternalFailure,
                "local collection declaration was not applied"
            );
            cache
                .declarations
                .insert((collection_id, collection.current_epoch));
        }
        let item = sharing_publication::candidate(db, &collection_id, &candidates[0].object_id)?;
        ensure!(
            item.stream_id == candidates[0].stream_id
                && item.store_id == candidates[0].store_id
                && item.container_length == candidates[0].container_length
                && item.container_commitment == candidates[0].container_commitment,
            Conflict,
            "own source object changed before publication"
        );
        let collection_key =
            sync_keys::collection_key(db, root, vault_id, collection_id, collection.current_epoch)?;
        let domain =
            KeyDomain::collection(&collection_key, &collection_id, collection.current_epoch)?;
        let index = (collection_id, item.object_id);
        let create_operation = match cache.creates.get(&index) {
            Some(operation) => operation.clone(),
            None => {
                let operation = author_cached_content(
                    db,
                    &mut cache,
                    &membership,
                    &domain,
                    device,
                    identity.signing_key(),
                    &OperationPayload::new(
                        collection_id,
                        collection.current_epoch,
                        PayloadBody::CreateObject {
                            object_id: item.object_id,
                            object_generation: item.object_generation,
                            store_id: item.store_id,
                            stream_id: item.stream_id,
                            metadata_fields: sharing_publication::metadata_fields(
                                db,
                                &item.object_id,
                            )?,
                        },
                    )?,
                )?;
                cache.creates.insert(index, operation.clone());
                operation
            }
        };
        let commit_operation = match cache.commits.get(&index) {
            Some(operation) => operation.clone(),
            None => {
                let envelope =
                    ObjectKeyEnvelope::decode(&store::active_envelope(db, &item.object_id)?)?;
                let key = sync_keys::collection_key(
                    db,
                    root,
                    vault_id,
                    collection_id,
                    envelope.collection_epoch(),
                )?;
                let content = envelope.open(&key)?;
                let operation = author_cached_content(
                    db,
                    &mut cache,
                    &membership,
                    &domain,
                    device,
                    identity.signing_key(),
                    &OperationPayload::new(
                        collection_id,
                        collection.current_epoch,
                        PayloadBody::CommitObject {
                            object_id: item.object_id,
                            object_generation: item.object_generation,
                            store_id: item.store_id,
                            container_length: item.container_length,
                            container_commitment: item.container_commitment,
                            object_key_commitment: object_key_commitment(
                                &collection_id,
                                &item.object_id,
                                &content,
                            ),
                        },
                    )?,
                )?;
                cache.commits.insert(index, operation.clone());
                operation
            }
        };
        Ok(vec![Publication {
            candidate: item,
            create_operation,
            commit_operation,
        }])
    })();
    if result.is_ok() {
        cache.generation = crate::schema::generation(db)?;
        db.own_source_cache = Some(cache);
    }
    let publications = result?;
    // One source upload makes only this object's memberships newly ready.
    album_transaction(
        db,
        root,
        vault_id,
        None,
        Some(&publications[0].candidate.object_id),
    )?;
    Ok(publications)
}

/// Whether local album rows require an own-sync metadata domain.
pub fn has_albums(db: &CatalogDb) -> Result<bool> {
    db.connection()
        .query_row("SELECT EXISTS (SELECT 1 FROM albums)", [], |row| row.get(0))
        .map_err(|error| map_sqlite(error, "local album presence could not be read"))
}

/// A legacy or archive writer changed rows outside the signed album API.
pub(crate) fn mark_albums_dirty(db: &mut CatalogDb) {
    if let Some(cache) = db.own_source_cache.as_mut() {
        cache.albums_bootstrapped = false;
    }
}

/// An incoming object cause can make a durable local album add ready.
pub(crate) fn mark_album_object_ready(db: &mut CatalogDb, object: &Id) {
    if let Some(cache) = db.own_source_cache.as_mut() {
        cache.ready_album_objects.insert(*object);
    }
}

/// One user album edit. Tree and manual order remain local catalog data.
pub enum AlbumMutation<'a> {
    /// Create one logical album.
    Create(&'a crate::model::Album),
    /// Change an existing album name.
    Rename(&'a Id, &'a str),
    /// Add or remove one direct membership.
    Membership(&'a Id, &'a Id, bool, u64),
    /// Place a selection, with optional source removal.
    Place(
        store::AlbumDestination<'a>,
        Option<&'a Id>,
        &'a [Id],
        bool,
        u64,
    ),
    /// Remove a complete selection atomically.
    Remove(&'a Id, &'a [Id]),
}

struct AlbumAuthor<'a> {
    log: &'a mut sync_log::DurableOperationLog,
    state: &'a mut MaterializedState,
    membership: &'a MembershipState,
    domain: &'a KeyDomain,
    device: Id,
    signing_key: &'a chur_sync_protocol::operation::DeviceSigningKey,
}

impl AlbumAuthor<'_> {
    fn push(&mut self, tx: &rusqlite::Transaction<'_>, body: PayloadBody) -> Result<()> {
        let payload = OperationPayload::new(
            *self.domain.collection_id(),
            self.domain.collection_epoch(),
            body,
        )?;
        let operation = self.log.author(
            chur_crypto::random::id()?,
            *self.membership.vault_id(),
            self.device,
            *self.domain.selector(),
            self.domain.operation_key(),
            chur_crypto::Nonce::random()?,
            &payload.encode(),
            self.signing_key,
            self.membership,
        )?;
        payload.validate_for_operation(
            &operation,
            self.domain.collection_id(),
            self.domain.collection_epoch(),
        )?;
        ensure!(
            self.state.apply(&operation, &payload)?
                == chur_sync_protocol::convergence::MergeOutcome::Applied,
            InternalFailure,
            "local album operation did not apply"
        );
        self.log.accept_local_in(tx, &operation, self.membership)
    }

    fn remove(&mut self, tx: &rusqlite::Transaction<'_>, album: &Id, object: &Id) -> Result<()> {
        let tokens = self.state.album_membership_tokens(album, object);
        if !tokens.is_empty() {
            self.push(
                tx,
                PayloadBody::RemoveAlbumMembership {
                    album_id: *album,
                    object_id: *object,
                    removed_tokens: tokens,
                },
            )?;
        }
        Ok(())
    }
}

/// Existing catalog rows are also durable intent for memberships whose media
/// has not been published yet. No membership operation precedes CreateObject.
fn reconcile_album_rows(
    tx: &rusqlite::Transaction<'_>,
    author: &mut AlbumAuthor<'_>,
    object_filter: Option<&Id>,
    album_filter: &[Id],
    member_filter: Option<&[Id]>,
) -> Result<()> {
    let albums = {
        let sql = if album_filter.is_empty() {
            "SELECT album_id, name FROM albums WHERE ?1 IS NULL OR EXISTS
                (SELECT 1 FROM album_memberships m WHERE m.album_id = albums.album_id AND m.object_id = ?1)
                ORDER BY album_id"
        } else {
            "SELECT album_id, name FROM albums WHERE album_id = ?1"
        };
        let mut query = tx
            .prepare(sql)
            .map_err(|error| map_sqlite(error, "local sync albums could not be listed"))?;
        let mut albums = Vec::new();
        let selectors = if album_filter.is_empty() {
            vec![object_filter]
        } else {
            album_filter.iter().map(Some).collect()
        };
        for selector in selectors {
            let rows = query
                .query_map([selector.map(|id| id.as_bytes().as_slice())], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| map_sqlite(error, "local sync albums could not be read"))?;
            albums.extend(
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|error| map_sqlite(error, "local sync album row could not be read"))?,
            );
        }
        albums
    };
    for (id, name) in albums {
        let album = crate::row::id(&id, "local sync album ID is malformed")?;
        match author.state.album_name(&album) {
            None => author.push(
                tx,
                PayloadBody::CreateAlbum {
                    album_id: album,
                    name,
                },
            )?,
            Some(current) if current != name => author.push(
                tx,
                PayloadBody::RenameAlbum {
                    album_id: album,
                    name,
                },
            )?,
            Some(_) => {}
        }
        let objects = {
            let sql = if member_filter.is_some() {
                "SELECT object_id FROM album_memberships WHERE album_id = ?1 AND object_id = ?2"
            } else {
                "SELECT object_id FROM album_memberships WHERE album_id = ?1 ORDER BY object_id"
            };
            let mut query = tx
                .prepare(sql)
                .map_err(|error| map_sqlite(error, "local sync memberships could not be listed"))?;
            let mut objects = Vec::new();
            if let Some(selected) = member_filter {
                for object in selected {
                    let rows = query
                        .query_map(
                            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .map_err(|error| {
                            map_sqlite(error, "local sync membership could not be read")
                        })?;
                    objects.extend(rows.collect::<rusqlite::Result<Vec<_>>>().map_err(
                        |error| map_sqlite(error, "local sync membership row could not be read"),
                    )?);
                }
            } else {
                let rows = query
                    .query_map([album.as_bytes().as_slice()], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })
                    .map_err(|error| {
                        map_sqlite(error, "local sync memberships could not be read")
                    })?;
                objects.extend(
                    rows.collect::<rusqlite::Result<Vec<_>>>()
                        .map_err(|error| {
                            map_sqlite(error, "local sync membership row could not be read")
                        })?,
                );
            }
            objects
        };
        for id in objects {
            let object = crate::row::id(&id, "local sync membership ID is malformed")?;
            let pending: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM own_sync_pending_album_memberships WHERE album_id = ?1 AND object_id = ?2)",
                params![album.as_bytes().as_slice(), object.as_bytes().as_slice()], |row| row.get(0))
                .map_err(|error| map_sqlite(error, "pending album add could not be read"))?;
            if author.state.committed_object(&object).is_some()
                && (pending || !author.state.album_contains(&album, &object))
            {
                author.push(
                    tx,
                    PayloadBody::AddAlbumMembership {
                        album_id: album,
                        object_id: object,
                    },
                )?;
                // Catalog edit, local add token, and intent retirement commit together.
                store::clear_pending_album_add(tx, &album, &object)?;
            }
        }
    }
    Ok(())
}

/// Commits a user edit and every ready signed album effect in one transaction.
/// The default collection must already exist, including for an empty vault.
pub fn mutate_album(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    mutation: AlbumMutation<'_>,
) -> Result<Option<Id>> {
    album_transaction(db, root, vault_id, Some(mutation), None)
}

/// Publishes legacy album rows and memberships that became ready after upload.
pub fn reconcile_albums(db: &mut CatalogDb, root: &Key, vault_id: Id) -> Result<()> {
    if !has_albums(db)? {
        return Ok(());
    }
    album_transaction(db, root, vault_id, None, None).map(|_| ())
}

fn album_transaction(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    mutation: Option<AlbumMutation<'_>>,
    object_filter: Option<&Id>,
) -> Result<Option<Id>> {
    if mutation.is_none() && !has_albums(db)? {
        return Ok(None);
    }
    let collection_id = store::default_collection(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "album sync needs a default collection",
        )
    })?;
    let membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "album sync membership is absent",
        )
    })?;
    ensure!(
        membership.vault_id() == &vault_id,
        AuthenticationFailed,
        "album sync vault differs"
    );
    let (device, identity) =
        sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "album sync identity is absent",
            )
        })?;
    let mut cache = take_source_cache(db, root, vault_id, &membership)?;
    let bootstrap = mutation.is_none() && object_filter.is_none();
    if bootstrap && cache.albums_bootstrapped && cache.ready_album_objects.is_empty() {
        db.own_source_cache = Some(cache);
        return Ok(None);
    }
    let ready_objects = if bootstrap && cache.albums_bootstrapped {
        cache
            .ready_album_objects
            .iter()
            .copied()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let collection = store::collection(db, &collection_id)?;
    let key =
        sync_keys::collection_key(db, root, vault_id, collection_id, collection.current_epoch)?;
    let domain = KeyDomain::collection(&key, &collection_id, collection.current_epoch)?;
    let declaration = if cache
        .declarations
        .contains(&(collection_id, collection.current_epoch))
    {
        None
    } else {
        Some(OperationPayload::new(
            vault_id,
            0,
            PayloadBody::DeclareCollection {
                collection_key_envelope: chur_format::envelope::CollectionKeyEnvelope::decode(
                    &store::active_collection_envelope(
                        db,
                        &collection_id,
                        collection.current_epoch,
                    )?,
                )?,
            },
        )?)
    };
    let result = cache.log.local_transaction(db, &membership, |log, tx| {
        if let Some(payload) = declaration {
            let root_domain = KeyDomain::root(root, &vault_id)?;
            let operation = log.author(
                chur_crypto::random::id()?,
                vault_id,
                device,
                *root_domain.selector(),
                root_domain.operation_key(),
                chur_crypto::Nonce::random()?,
                &payload.encode(),
                identity.signing_key(),
                &membership,
            )?;
            payload.validate_for_operation(
                &operation,
                root_domain.collection_id(),
                root_domain.collection_epoch(),
            )?;
            log.accept_local_in(tx, &operation, &membership)?;
        }
        let mut author = AlbumAuthor {
            log,
            state: &mut cache.state,
            membership: &membership,
            domain: &domain,
            device,
            signing_key: identity.signing_key(),
        };
        let mut result = None;
        let mut album_filter = Vec::new();
        let mut member_filter = mutation.as_ref().map(|_| Vec::new());
        match mutation {
            Some(AlbumMutation::Create(album)) => {
                // Accepted creation history reserves the identity even after a local
                // subtree deletion. A retried desktop transfer must not revive it.
                if author.state.album_name(&album.album_id).is_some() {
                    let present: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM albums WHERE album_id = ?1)",
                            [album.album_id.as_bytes().as_slice()],
                            |row| row.get(0),
                        )
                        .map_err(|error| {
                            map_sqlite(error, "the requested album identity could not be checked")
                        })?;
                    ensure!(
                        present,
                        InvalidInput,
                        "the requested album identity was deleted"
                    );
                }
                store::put_album_in(tx, album)?;
                result = Some(album.album_id);
                album_filter.push(album.album_id);
            }
            Some(AlbumMutation::Rename(album, name)) => {
                store::rename_album_in(tx, album, name)?;
                album_filter.push(*album);
            }
            Some(AlbumMutation::Membership(album, object, member, now)) => {
                store::set_album_membership_in(tx, album, object, member, now)?;
                album_filter.push(*album);
                if member && let Some(selected) = member_filter.as_mut() {
                    selected.push(*object);
                }
                if !member {
                    author.remove(tx, album, object)?;
                }
            }
            Some(AlbumMutation::Place(destination, source, objects, moving, now)) => {
                let target =
                    store::place_album_members_in(tx, destination, source, objects, moving, now)?;
                result = Some(target);
                album_filter.push(target);
                if let Some(selected) = member_filter.as_mut() {
                    selected.extend_from_slice(objects);
                }
                if moving
                    && let Some(source) = source
                    && *source != target
                {
                    album_filter.push(*source);
                    for object in objects {
                        author.remove(tx, source, object)?;
                    }
                }
            }
            Some(AlbumMutation::Remove(album, objects)) => {
                store::remove_album_members_in(tx, album, objects)?;
                album_filter.push(*album);
                for object in objects {
                    author.remove(tx, album, object)?;
                }
            }
            None => {}
        }
        if ready_objects.is_empty() {
            reconcile_album_rows(
                tx,
                &mut author,
                object_filter,
                &album_filter,
                member_filter
                    .as_deref()
                    .or_else(|| object_filter.map(std::slice::from_ref)),
            )?;
        } else {
            for object in &ready_objects {
                reconcile_album_rows(
                    tx,
                    &mut author,
                    Some(object),
                    &[],
                    Some(std::slice::from_ref(object)),
                )?;
            }
        }
        Ok(result)
    });
    if result.is_ok() {
        if bootstrap {
            cache.albums_bootstrapped = true;
            cache.ready_album_objects.clear();
        }
        if let Some(object) = object_filter {
            cache.ready_album_objects.remove(object);
        }
        cache
            .declarations
            .insert((collection_id, collection.current_epoch));
        cache.generation = crate::schema::generation(db)?;
        db.own_source_cache = Some(cache);
    }
    result
}

/// Projects only authenticated live memberships after a media download.
/// Missing media retain their intent in accepted operation history.
pub fn project_received_album_memberships(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    object: &Id,
) -> Result<()> {
    let keys = sync_keys::key_directory(db, root, vault_id)?;
    let state = sync_receive::load_materialized_state(db, &keys)?;
    let albums = {
        let mut query = db
            .connection()
            .prepare("SELECT album_id FROM albums")
            .map_err(|error| map_sqlite(error, "received object albums could not be listed"))?;
        let rows = query
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| map_sqlite(error, "received object albums could not be read"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| map_sqlite(error, "received object album row could not be read"))?
    };
    db.transaction(|tx| {
        for bytes in albums {
            let album = crate::row::id(&bytes, "received object album ID is malformed")?;
            if state.album_contains(&album, object) {
                project_album_member(tx, &state, &album, object)?;
            }
        }
        Ok(())
    })
}

pub(crate) fn project_album_member(
    tx: &rusqlite::Transaction<'_>,
    state: &MaterializedState,
    album: &Id,
    object: &Id,
) -> Result<()> {
    let pending: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM own_sync_pending_album_memberships WHERE album_id = ?1 AND object_id = ?2)",
        params![album.as_bytes().as_slice(), object.as_bytes().as_slice()], |row| row.get(0))
        .map_err(|error| map_sqlite(error, "pending album projection guard could not be read"))?;
    if pending {
        return Ok(());
    }
    let changed = if state.album_contains(album, object) {
        let missing: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM albums WHERE album_id = ?1)
                AND EXISTS (SELECT 1 FROM objects WHERE object_id = ?2)
                AND NOT EXISTS (SELECT 1 FROM album_memberships WHERE album_id = ?1 AND object_id = ?2)",
            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()], |row| row.get(0))
            .map_err(|error| map_sqlite(error, "received membership presence could not be read"))?;
        if !missing {
            return Ok(());
        }
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM album_memberships WHERE album_id = ?1",
                [album.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "received album size could not be read"))?;
        ensure!(
            crate::db::from_sqlite_integer(count, "received album count is negative")?
                < chur_core::limits::catalog::ALBUM_MEMBERSHIPS_MAX,
            ResourceLimitExceeded,
            "received album exceeds its membership bound"
        );
        // Accepted membership precedes visibility until ordinary media verification.
        tx.execute("INSERT INTO album_memberships
            (album_id, object_id, capture_time_ms, added_ms, revision, sort_position)
            SELECT ?1, object_id, capture_time_ms, 0, 1,
              (SELECT coalesce(max(sort_position) + 1, 0) FROM album_memberships WHERE album_id = ?1)
            FROM objects WHERE object_id = ?2",
            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()])
            .map_err(|error| map_sqlite(error, "received album membership could not be projected"))?
    } else {
        tx.execute(
            "DELETE FROM album_memberships WHERE album_id = ?1 AND object_id = ?2",
            params![album.as_bytes().as_slice(), object.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "received album membership could not be removed"))?
    };
    if changed != 0 {
        tx.execute(
            "UPDATE albums SET revision = revision + 1 WHERE album_id = ?1",
            [album.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "received album revision could not advance"))?;
        crate::schema::bump_generation(tx)?;
    }
    Ok(())
}

pub(crate) fn project_live_album_memberships(
    tx: &rusqlite::Transaction<'_>,
    state: &MaterializedState,
) -> Result<()> {
    for (album, object) in state.album_memberships() {
        project_album_member(tx, state, &album, &object)?;
    }
    Ok(())
}

/// Authors an own-vault tombstone when this object has a durable content cause.
pub fn publish_deletion(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    object_id: &Id,
    now_ms: u64,
) -> Result<()> {
    let keys = sync_keys::key_directory(db, root, vault_id)?;
    let mut state = sync_receive::load_materialized_state(db, &keys)?;
    let Some((_, collection, generation, _visible, _)) = state
        .committed_objects()
        .find(|(id, _, _, _, _)| id == object_id)
    else {
        return Ok(());
    };
    if state.object_is_purged(object_id) {
        return Ok(());
    }
    let membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "own deletion membership is absent",
        )
    })?;
    let (device, identity) =
        sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "own deletion identity is absent",
            )
        })?;
    let current = store::collection(db, &collection)?;
    let key = sync_keys::collection_key(db, root, vault_id, collection, current.current_epoch)?;
    let domain = KeyDomain::collection(&key, &collection, current.current_epoch)?;
    let mut log = sync_log::load(db, &membership)?;
    sync_receive::author_content_operation(
        db,
        &mut log,
        &membership,
        &mut state,
        &domain,
        device,
        identity.signing_key(),
        &OperationPayload::new(
            collection,
            current.current_epoch,
            PayloadBody::PurgeObject {
                object_id: *object_id,
                object_generation: generation,
                authored_at_ms: now_ms,
            },
        )?,
    )?;
    Ok(())
}

/// Resolves missing local containers from accepted own-vault operations.
pub fn pending_for_collection(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    collection_id: Id,
) -> Result<ReceivePlan> {
    pending_for_collection_in(db, root, vault_id, collection_id, true)
}
fn pending_for_collection_in(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    collection_id: Id,
    dispatch: bool,
) -> Result<ReceivePlan> {
    ensure!(
        is_local_collection(db, &collection_id)?,
        AuthenticationFailed,
        "collection is not locally owned"
    );
    let keys = sync_keys::key_directory(db, root, vault_id)?;
    let state = sync_receive::load_materialized_state(db, &keys)?;
    // Repair a crash after media activation but before its album projection.
    db.transaction(|tx| project_live_album_memberships(tx, &state))?;
    let collection = store::collection(db, &collection_id)?;
    let key =
        sync_keys::collection_key(db, root, vault_id, collection_id, collection.current_epoch)?;
    let domain = KeyDomain::collection(&key, &collection_id, collection.current_epoch)?;
    let mut objects = Vec::new();
    for (object_id, scope, generation, visible, commit) in state.committed_objects() {
        if scope != collection_id {
            continue;
        }
        match crate::object_grants::ensure_not_deleted(db, &collection_id, &object_id) {
            Ok(()) => {}
            Err(error) if error.status() == ChurStatus::NotFound => continue,
            Err(error) => return Err(error),
        }
        if store::object_present(db, &object_id)? {
            let local = store::object(db, &object_id)?;
            ensure!(
                local.collection_id == collection_id
                    && local.primary_stream_id == *commit.stream_id(),
                AuthenticationFailed,
                "own object differs from its accepted commit"
            );
            if (!visible && local.state == ObjectState::Active)
                || (visible && local.state == ObjectState::SharedDeleted)
            {
                db.transaction(|tx| {
                    tx.execute("UPDATE objects SET state = ?2, object_generation = ?3 WHERE object_id = ?1",
                        params![object_id.as_bytes().as_slice(), i64::from(if visible { ObjectState::Active } else { ObjectState::SharedDeleted }.value()),
                            crate::db::as_sqlite_integer(generation, "own object generation is too large")?])
                        .map_err(|error| map_sqlite(error, "own object lifecycle could not be projected"))?;
                    if visible { store::reindex_search(tx, &object_id)?; }
                    else { tx.execute("DELETE FROM object_search WHERE rowid = ?1", [store::row_key(&object_id)])
                        .map_err(|error| map_sqlite(error, "own hidden object search could not be removed"))?; }
                    crate::schema::bump_generation(tx)
                })?;
            }
            continue;
        }
        if !visible {
            continue;
        }
        let metadata = [
            MetadataFieldId::OriginalFilename,
            MetadataFieldId::MediaType,
            MetadataFieldId::CaptureTime,
            MetadataFieldId::Caption,
            MetadataFieldId::Rating,
        ]
        .into_iter()
        .filter_map(|field| {
            state
                .metadata(&object_id, field)
                .map(|value| MetadataField::new(field, value.to_vec()))
        })
        .collect::<Result<Vec<_>>>()?;
        objects.push(SharedObject {
            source_vault_id: vault_id,
            collection_id,
            object_id,
            object_generation: generation,
            stream_id: *commit.stream_id(),
            store_id: *commit.store_id(),
            container_length: commit.container_length(),
            container_commitment: *commit.container_commitment(),
            object_key_commitment: *commit.object_key_commitment(),
            metadata,
        });
    }
    if dispatch {
        let tickets = crate::receive_queue::tickets(db, &collection_id)?;
        objects.sort_unstable_by_key(|object| {
            (
                tickets.get(&object.object_id).copied().unwrap_or(0),
                object.object_id,
            )
        });
        objects.truncate(crate::receive_queue::PAGE_MAX);
        crate::receive_queue::dispatched(
            db,
            &collection_id,
            &objects
                .iter()
                .map(|object| object.object_id)
                .collect::<Vec<_>>(),
        )?;
    }
    Ok(ReceivePlan {
        selector: *domain.selector(),
        source_vault_id: vault_id,
        collection_id,
        objects,
        pending_operations: state.pending_operations(Some(&collection_id)),
        rejected_operations: 0,
    })
}

/// Resolves one missing own-vault object without trusting transport metadata.
pub fn pending_object_for_collection(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    collection_id: Id,
    object_id: Id,
) -> Result<SharedObject> {
    crate::object_grants::ensure_not_deleted(db, &collection_id, &object_id)?;
    pending_for_collection_in(db, root, vault_id, collection_id, false)?
        .objects
        .into_iter()
        .find(|object| object.object_id == object_id)
        .ok_or_else(|| {
            Error::new(
                ChurStatus::NotFound,
                "own object is absent, deleted, or already active",
            )
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::{
        db::{CatalogKey, CatalogLocation},
        model::{Collection, MetadataRevision, Object, Stream},
        schema,
    };
    use chur_crypto::Nonce;
    use chur_format::constants::{IntegritySummary, MediaClass, StreamKind};
    use chur_format::envelope::CollectionKeyEnvelope;
    use chur_sync_protocol::{
        identity::{DeviceIdentity, DeviceIdentityEnvelope},
        membership::EnrollmentRecord,
    };

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    #[test]
    fn enrolled_peer_receives_key_free_media_and_disposable_key_without_sharing_acl() {
        let directory = std::env::temp_dir().join(format!(
            "chur-own-sync-{}",
            chur_crypto::random::id().unwrap().to_hex()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("source.db");
        let peer_path = directory.join("peer.db");
        let root = Key::new([1; 32]);
        let vault = id(2);
        let collection = id(3);
        let source_id = id(4);
        let peer_id = id(5);
        let source_identity = DeviceIdentity::from_seeds([6; 32], [7; 32]);
        let peer_identity = DeviceIdentity::from_seeds([8; 32], [9; 32]);
        let catalog_key = CatalogKey::derive(&root, &vault).unwrap();
        let mut source =
            CatalogDb::open(&CatalogLocation::File(&source_path), &catalog_key).unwrap();
        schema::open_at_current_version(&mut source, 1).unwrap();
        let initial = EnrollmentRecord::initial(
            vault,
            source_id,
            source_identity.signing_public_key(),
            source_identity.hpke_public_key(),
        )
        .unwrap()
        .sign(source_identity.signing_key());
        let (mut membership, mut log, _) = sync_receive::provision_initial_membership(
            &mut source,
            &root,
            source_identity.signing_key(),
            &initial,
        )
        .unwrap();
        let source_envelope = DeviceIdentityEnvelope::seal_for_local(
            &root,
            vault,
            source_id,
            1,
            Nonce::new([10; 24]),
            &source_identity,
        )
        .unwrap();
        sync_keys::store_local_identity_envelope(&mut source, &root, &membership, &source_envelope)
            .unwrap();
        let checkpoint = log
            .issue_own_checkpoint(
                &mut source,
                &membership,
                &source_id,
                source_identity.signing_key(),
                2,
            )
            .unwrap();
        let enrollment = EnrollmentRecord::new(
            vault,
            peer_id,
            peer_identity.signing_public_key(),
            peer_identity.hpke_public_key(),
            2,
            source_id,
            2,
            *membership.commitment(),
            checkpoint.commitment(),
        )
        .unwrap()
        .sign(source_identity.signing_key());
        let domain = KeyDomain::root(&root, &vault).unwrap();
        sync_receive::author_membership_operation(
            &mut source,
            &mut log,
            &mut membership,
            &domain,
            source_id,
            source_identity.signing_key(),
            PayloadBody::AddDevice(enrollment),
        )
        .unwrap();
        let collection_key = Key::new([11; 32]);
        let collection_envelope = CollectionKeyEnvelope::seal(
            &root,
            vault,
            collection,
            1,
            1,
            Nonce::new([12; 24]),
            &collection_key,
        )
        .unwrap();
        store::put_collection_with_envelope(
            &mut source,
            &Collection {
                collection_id: collection,
                current_epoch: 1,
                policy_type: crate::model::COLLECTION_POLICY_VAULT_DEFAULT,
                created_revision: 1,
                status: 1,
            },
            1,
            &collection_envelope.encode(),
        )
        .unwrap();
        source.checkpoint().unwrap();
        std::fs::copy(&source_path, &peer_path).unwrap();
        let mut peer = CatalogDb::open(&CatalogLocation::File(&peer_path), &catalog_key).unwrap();
        let peer_envelope = DeviceIdentityEnvelope::seal_for_local(
            &root,
            vault,
            peer_id,
            1,
            Nonce::new([13; 24]),
            &peer_identity,
        )
        .unwrap();
        sync_keys::store_local_identity_envelope(&mut peer, &root, &membership, &peer_envelope)
            .unwrap();
        let object = id(14);
        let stream = id(15);
        let content = Key::new([16; 32]);
        let envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            vault,
            collection,
            1,
            object,
            1,
            Nonce::new([17; 24]),
            &content,
        )
        .unwrap();
        store::activate_object(
            &mut source,
            &store::ObjectActivation {
                object: Object {
                    object_id: object,
                    object_generation: 1,
                    collection_id: collection,
                    primary_stream_id: stream,
                    media_kind: MediaClass::Image,
                    capture_time_ms: 1,
                    import_time_ms: 1,
                    capture_time_substituted: false,
                    plaintext_size: 4096,
                    width: 10,
                    height: 10,
                    duration_ms: 0,
                    favorite: false,
                    state: ObjectState::Active,
                    integrity_summary: IntegritySummary::CompleteVerified,
                    thumbnail_ready: false,
                    active_metadata_revision: 1,
                },
                stream: Stream {
                    stream_id: stream,
                    object_id: object,
                    stream_kind: StreamKind::Original,
                    stream_revision: 1,
                    source_content_revision: 0,
                    container_path_id: id(18),
                    container_version: 1,
                    suite_id: 1,
                    ciphertext_size: 4200,
                    plaintext_size: 4096,
                    chunk_size: 262144,
                    complete_verified_ms: Some(1),
                    final_commitment: [19; 32],
                },
                envelope: envelope.encode(),
                envelope_generation: 1,
                metadata: MetadataRevision {
                    object_id: object,
                    revision: 1,
                    active: true,
                    record: vec![1],
                    original_filename: Some("own.jpg".into()),
                    caption: None,
                    content_type: "image/jpeg".into(),
                    capture_time_ms: Some(1),
                    width: 10,
                    height: 10,
                    duration_ms: 0,
                },
            },
        )
        .unwrap();
        let candidate = sharing_publication::candidate(&source, &collection, &object).unwrap();
        let published = publish(&mut source, &root, vault, collection, &[candidate])
            .unwrap()
            .remove(0);
        let replay = publish(&mut source, &root, vault, collection, &[candidate])
            .unwrap()
            .remove(0);
        assert_eq!(
            published.commit_operation.encode(),
            replay.commit_operation.encode()
        );
        assert_eq!(source.own_source_replays, 1);
        for _ in 0..16 {
            let repeated = publish(&mut source, &root, vault, collection, &[candidate])
                .unwrap()
                .remove(0);
            assert_eq!(
                repeated.commit_operation.encode(),
                published.commit_operation.encode()
            );
        }
        assert_eq!(
            source.own_source_replays, 1,
            "unchanged source scans reuse one authenticated replay"
        );
        assert!(
            publish(
                &mut source,
                &Key::new([250; 32]),
                vault,
                collection,
                &[candidate]
            )
            .is_err(),
            "a cached history does not accept another root"
        );
        assert!(
            publish(&mut source, &root, id(249), collection, &[candidate]).is_err(),
            "a cached history does not accept another vault"
        );
        source.transaction(crate::schema::bump_generation).unwrap();
        publish(&mut source, &root, vault, collection, &[candidate]).unwrap();
        assert_eq!(
            source.own_source_replays, 2,
            "a changed catalog invalidates the verified replay"
        );
        let mut keys = sync_keys::key_directory(&peer, &root, vault).unwrap();
        let mut peer_log = sync_log::load(&peer, &membership).unwrap();
        let mut state = sync_receive::load_materialized_state(&peer, &keys).unwrap();
        for record in sync_log::records_after(&source, &source_id, 2).unwrap() {
            assert_eq!(
                sync_receive::accept_operation(
                    &mut peer,
                    &mut peer_log,
                    &mut membership,
                    &mut state,
                    &mut keys,
                    &root,
                    3,
                    &record
                )
                .unwrap(),
                chur_sync_protocol::operation_log::ApplyOutcome::Applied
            );
        }
        let plan = pending_for_collection(&mut peer, &root, vault, collection).unwrap();
        assert_eq!(plan.objects.len(), 1);
        assert_eq!(
            plan.objects[0].object_key_commitment,
            object_key_commitment(&collection, &object, &content)
        );
        let request =
            crate::object_grants::request(&mut peer, &root, vault, collection, object).unwrap();
        assert_eq!(request.recipient_device_id(), &peer_id);
        // Recovery can retain this unaccepted private request. An approved
        // fresh ordinary identity must issue its own addressed request.
        let fresh_id = id(23);
        let fresh = DeviceIdentity::from_seeds([24; 32], [25; 32]);
        let mut source_membership = membership.clone();
        let mut source_log = sync_log::load(&source, &source_membership).unwrap();
        let checkpoint = source_log
            .issue_own_checkpoint(
                &mut source,
                &source_membership,
                &source_id,
                source_identity.signing_key(),
                4,
            )
            .unwrap();
        let sequence = source_log.head(&source_id).unwrap().0 + 1;
        let enrolled = EnrollmentRecord::new(
            vault,
            fresh_id,
            fresh.signing_public_key(),
            fresh.hpke_public_key(),
            sequence,
            source_id,
            source_membership.generation() + 1,
            *source_membership.commitment(),
            checkpoint.commitment(),
        )
        .unwrap()
        .sign(source_identity.signing_key());
        let enrolled_op = sync_receive::author_membership_operation(
            &mut source,
            &mut source_log,
            &mut source_membership,
            &KeyDomain::root(&root, &vault).unwrap(),
            source_id,
            source_identity.signing_key(),
            PayloadBody::AddDevice(enrolled),
        )
        .unwrap();
        sync_receive::accept_operation(
            &mut peer,
            &mut peer_log,
            &mut membership,
            &mut state,
            &mut keys,
            &root,
            5,
            &enrolled_op.encode(),
        )
        .unwrap();
        let fresh_envelope = DeviceIdentityEnvelope::seal_for_local(
            &root,
            vault,
            fresh_id,
            1,
            Nonce::new([26; 24]),
            &fresh,
        )
        .unwrap();
        sync_keys::store_local_identity_envelope(&mut peer, &root, &membership, &fresh_envelope)
            .unwrap();
        let fresh_request =
            crate::object_grants::request(&mut peer, &root, vault, collection, object).unwrap();
        assert_eq!(fresh_request.recipient_device_id(), &fresh_id);
        assert_ne!(fresh_request.prekey_id(), request.prekey_id());
        let request = fresh_request;
        let grant = crate::object_grants::issue(&mut source, &root, vault, &request).unwrap();
        crate::object_grants::accept(&mut peer, &root, vault, &[], &grant).unwrap();
        assert_eq!(
            crate::object_grants::pending_envelope(&peer, &collection, &object)
                .unwrap()
                .open(&collection_key)
                .unwrap()
                .expose(),
            content.expose()
        );
        let private_count: i64 = peer
            .connection()
            .query_row("SELECT count(*) FROM object_key_requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            private_count, 0,
            "one-use private key is gone after acceptance"
        );
        peer.close().unwrap();
        let mut peer = CatalogDb::open(&CatalogLocation::File(&peer_path), &catalog_key).unwrap();
        crate::object_grants::accept(&mut peer, &root, vault, &[], &grant).unwrap();
        assert_eq!(
            pending_for_collection(&mut peer, &root, vault, collection)
                .unwrap()
                .objects
                .len(),
            1
        );
        source.close().unwrap();
        peer.close().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod album_sync_tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures fail immediately when a prerequisite or assertion fails"
    )]
    use super::*;
    use crate::{CatalogKey, CatalogLocation, model::*, schema};
    use chur_crypto::Nonce;
    use chur_format::{
        constants::{IntegritySummary, MediaClass, StreamKind},
        envelope::CollectionKeyEnvelope,
    };
    use chur_sync_protocol::{
        identity::{DeviceIdentity, DeviceIdentityEnvelope},
        membership::EnrollmentRecord,
    };

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    struct Pair {
        source: CatalogDb,
        peer: CatalogDb,
        root: Key,
        vault: Id,
        collection: Id,
        source_id: Id,
        peer_id: Id,
        directory: std::path::PathBuf,
    }

    impl Pair {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "chur-album-sync-{}",
                chur_crypto::random::id().unwrap().to_hex()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let root = Key::new([1; 32]);
            let vault = id(2);
            let collection = id(3);
            let source_id = id(4);
            let peer_id = id(5);
            let source_identity = DeviceIdentity::from_seeds([6; 32], [7; 32]);
            let peer_identity = DeviceIdentity::from_seeds([8; 32], [9; 32]);
            let key = CatalogKey::derive(&root, &vault).unwrap();
            let mut source =
                CatalogDb::open(&CatalogLocation::File(&directory.join("source.db")), &key)
                    .unwrap();
            schema::open_at_current_version(&mut source, 1).unwrap();
            let initial = EnrollmentRecord::initial(
                vault,
                source_id,
                source_identity.signing_public_key(),
                source_identity.hpke_public_key(),
            )
            .unwrap()
            .sign(source_identity.signing_key());
            let (mut membership, mut log, _) = sync_receive::provision_initial_membership(
                &mut source,
                &root,
                source_identity.signing_key(),
                &initial,
            )
            .unwrap();
            let envelope = DeviceIdentityEnvelope::seal_for_local(
                &root,
                vault,
                source_id,
                1,
                Nonce::new([10; 24]),
                &source_identity,
            )
            .unwrap();
            sync_keys::store_local_identity_envelope(&mut source, &root, &membership, &envelope)
                .unwrap();
            let checkpoint = log
                .issue_own_checkpoint(
                    &mut source,
                    &membership,
                    &source_id,
                    source_identity.signing_key(),
                    2,
                )
                .unwrap();
            let enrollment = EnrollmentRecord::new(
                vault,
                peer_id,
                peer_identity.signing_public_key(),
                peer_identity.hpke_public_key(),
                2,
                source_id,
                2,
                *membership.commitment(),
                checkpoint.commitment(),
            )
            .unwrap()
            .sign(source_identity.signing_key());
            let domain = KeyDomain::root(&root, &vault).unwrap();
            sync_receive::author_membership_operation(
                &mut source,
                &mut log,
                &mut membership,
                &domain,
                source_id,
                source_identity.signing_key(),
                PayloadBody::AddDevice(enrollment),
            )
            .unwrap();
            let envelope = CollectionKeyEnvelope::seal(
                &root,
                vault,
                collection,
                1,
                1,
                Nonce::new([12; 24]),
                &Key::new([11; 32]),
            )
            .unwrap();
            store::put_collection_with_envelope(
                &mut source,
                &Collection {
                    collection_id: collection,
                    current_epoch: 1,
                    policy_type: COLLECTION_POLICY_VAULT_DEFAULT,
                    created_revision: 1,
                    status: COLLECTION_STATUS_ACTIVE,
                },
                1,
                &envelope.encode(),
            )
            .unwrap();
            source.checkpoint().unwrap();
            std::fs::copy(directory.join("source.db"), directory.join("peer.db")).unwrap();
            let mut peer =
                CatalogDb::open(&CatalogLocation::File(&directory.join("peer.db")), &key).unwrap();
            let envelope = DeviceIdentityEnvelope::seal_for_local(
                &root,
                vault,
                peer_id,
                1,
                Nonce::new([13; 24]),
                &peer_identity,
            )
            .unwrap();
            sync_keys::store_local_identity_envelope(&mut peer, &root, &membership, &envelope)
                .unwrap();
            Self {
                source,
                peer,
                root,
                vault,
                collection,
                source_id,
                peer_id,
                directory,
            }
        }

        fn restart(&mut self) {
            let key = CatalogKey::derive(&self.root, &self.vault).unwrap();
            self.source.checkpoint().unwrap();
            self.peer.checkpoint().unwrap();
            self.source = CatalogDb::open(
                &CatalogLocation::File(&self.directory.join("source.db")),
                &key,
            )
            .unwrap();
            self.peer = CatalogDb::open(
                &CatalogLocation::File(&self.directory.join("peer.db")),
                &key,
            )
            .unwrap();
        }

        fn send(&mut self, reverse: bool) {
            let (source, target, device) = if reverse {
                (&self.peer, &mut self.source, self.peer_id)
            } else {
                (&self.source, &mut self.peer, self.source_id)
            };
            let mut membership = sync_membership::load(target).unwrap().unwrap();
            let mut keys = sync_keys::key_directory(target, &self.root, self.vault).unwrap();
            let mut log = sync_log::load(target, &membership).unwrap();
            let mut state = sync_receive::load_materialized_state(target, &keys).unwrap();
            let after = log.head(&device).map_or(0, |(sequence, _)| sequence);
            for record in sync_log::records_after(source, &device, after).unwrap() {
                assert_eq!(
                    sync_receive::accept_operation(
                        target,
                        &mut log,
                        &mut membership,
                        &mut state,
                        &mut keys,
                        &self.root,
                        100,
                        &record
                    )
                    .unwrap(),
                    chur_sync_protocol::operation_log::ApplyOutcome::Applied
                );
            }
        }

        fn album(&mut self, byte: u8, name: &str) -> Id {
            let album = Album {
                album_id: id(byte),
                name: name.into(),
                created_ms: 1,
                revision: 1,
            };
            mutate_album(
                &mut self.source,
                &self.root,
                self.vault,
                AlbumMutation::Create(&album),
            )
            .unwrap();
            album.album_id
        }

        fn activate(&mut self, reverse: bool, byte: u8) -> Id {
            let object_id = id(byte);
            let stream_id = id(byte + 1);
            let envelope = ObjectKeyEnvelope::seal(
                &Key::new([11; 32]),
                self.vault,
                self.collection,
                1,
                object_id,
                1,
                Nonce::new([byte; 24]),
                &Key::new([byte; 32]),
            )
            .unwrap();
            let db = if reverse {
                &mut self.peer
            } else {
                &mut self.source
            };
            store::activate_object(
                db,
                &store::ObjectActivation {
                    object: Object {
                        object_id,
                        object_generation: 1,
                        collection_id: self.collection,
                        primary_stream_id: stream_id,
                        media_kind: MediaClass::Image,
                        capture_time_ms: 1,
                        import_time_ms: 1,
                        capture_time_substituted: false,
                        plaintext_size: 4096,
                        width: 10,
                        height: 10,
                        duration_ms: 0,
                        favorite: false,
                        state: ObjectState::Active,
                        integrity_summary: IntegritySummary::CompleteVerified,
                        thumbnail_ready: false,
                        active_metadata_revision: 1,
                    },
                    stream: Stream {
                        stream_id,
                        object_id,
                        stream_kind: StreamKind::Original,
                        stream_revision: 1,
                        source_content_revision: 0,
                        container_path_id: id(byte + 2),
                        container_version: 1,
                        suite_id: 1,
                        ciphertext_size: 4200,
                        plaintext_size: 4096,
                        chunk_size: 262144,
                        complete_verified_ms: Some(1),
                        final_commitment: [19; 32],
                    },
                    envelope: envelope.encode(),
                    envelope_generation: 1,
                    metadata: MetadataRevision {
                        object_id,
                        revision: 1,
                        active: true,
                        record: vec![1],
                        original_filename: Some("album.jpg".into()),
                        caption: None,
                        content_type: "image/jpeg".into(),
                        capture_time_ms: Some(1),
                        width: 10,
                        height: 10,
                        duration_ms: 0,
                    },
                },
            )
            .unwrap();
            object_id
        }

        fn publish(&mut self, object: Id) {
            let candidate =
                sharing_publication::candidate(&self.source, &self.collection, &object).unwrap();
            publish(
                &mut self.source,
                &self.root,
                self.vault,
                self.collection,
                &[candidate],
            )
            .unwrap();
        }
    }

    #[test]
    fn albums_before_upload_survive_restart_receive_and_late_media_materialization() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Before upload");
        let object = pair.activate(false, 50);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album, "Renamed before upload"),
        )
        .unwrap();
        pair.restart();
        pair.publish(object);
        pair.send(false);
        let albums = store::albums(&pair.peer).unwrap();
        assert_eq!(albums[0].album.name, "Renamed before upload");
        assert_eq!(albums[0].member_count, 0);
        pair.restart();
        pair.activate(true, 50);
        project_received_album_memberships(&mut pair.peer, &pair.root, pair.vault, &object)
            .unwrap();
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 1);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Remove(&album, &[object]),
        )
        .unwrap();
        pair.send(false);
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 0);
        pair.restart();
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 0);
    }

    #[test]
    fn legacy_albums_bootstrap_and_pending_add_removed_before_publish_stays_removed() {
        let mut pair = Pair::new();
        let album = Album {
            album_id: id(40),
            name: "Legacy".into(),
            created_ms: 1,
            revision: 1,
        };
        store::put_album(&mut pair.source, &album).unwrap();
        let object = pair.activate(false, 50);
        store::set_album_membership(&mut pair.source, &album.album_id, &object, true, 3).unwrap();
        reconcile_albums(&mut pair.source, &pair.root, pair.vault).unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Remove(&album.album_id, &[object]),
        )
        .unwrap();
        pair.restart();
        pair.publish(object);
        pair.send(false);
        pair.activate(true, 50);
        project_received_album_memberships(&mut pair.peer, &pair.root, pair.vault, &object)
            .unwrap();
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 0);
        let keys = sync_keys::key_directory(&pair.peer, &pair.root, pair.vault).unwrap();
        assert!(
            !sync_receive::load_materialized_state(&pair.peer, &keys)
                .unwrap()
                .album_contains(&album.album_id, &object)
        );
    }

    #[test]
    fn album_outbox_failure_rolls_back_catalog_sequence_and_bulk_removal() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Original");
        let object = pair.activate(false, 50);
        pair.publish(object);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        let before = schema::generation(&pair.source).unwrap();
        let member = sync_membership::load(&pair.source).unwrap().unwrap();
        let head = sync_log::load(&pair.source, &member)
            .unwrap()
            .head(&pair.source_id);
        pair.source
            .connection()
            .execute_batch(
                "CREATE TEMP TRIGGER deny_album_sync BEFORE INSERT ON sync_operations
            BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END;",
            )
            .unwrap();
        assert!(
            mutate_album(
                &mut pair.source,
                &pair.root,
                pair.vault,
                AlbumMutation::Rename(&album, "Lost rename")
            )
            .is_err()
        );
        assert!(
            mutate_album(
                &mut pair.source,
                &pair.root,
                pair.vault,
                AlbumMutation::Remove(&album, &[object])
            )
            .is_err()
        );
        assert_eq!(
            store::albums(&pair.source).unwrap()[0].album.name,
            "Original"
        );
        assert_eq!(store::albums(&pair.source).unwrap()[0].member_count, 1);
        assert_eq!(schema::generation(&pair.source).unwrap(), before);
        assert_eq!(
            sync_log::load(&pair.source, &member)
                .unwrap()
                .head(&pair.source_id),
            head
        );
        pair.source
            .connection()
            .execute_batch("DROP TRIGGER deny_album_sync")
            .unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album, "Retry"),
        )
        .unwrap();
        pair.send(false);
        assert_eq!(store::albums(&pair.peer).unwrap()[0].album.name, "Retry");
    }

    #[test]
    fn concurrent_renames_converge_and_remote_edits_do_not_recreate_locally_deleted_albums() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Original");
        pair.send(false);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album, "Source rename"),
        )
        .unwrap();
        mutate_album(
            &mut pair.peer,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album, "Peer rename"),
        )
        .unwrap();
        pair.send(false);
        pair.send(true);
        assert_eq!(
            store::albums(&pair.source).unwrap()[0].album.name,
            store::albums(&pair.peer).unwrap()[0].album.name
        );
        pair.restart();
        store::delete_album(&mut pair.peer, &album).unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album, "After local delete"),
        )
        .unwrap();
        pair.send(false);
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        assert!(store::albums(&pair.peer).unwrap().is_empty());
    }
    #[test]
    fn concurrent_membership_remove_retains_an_unobserved_readd() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Concurrent membership");
        let object = pair.activate(false, 50);
        pair.publish(object);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        pair.send(false);
        pair.activate(true, 50);
        project_received_album_memberships(&mut pair.peer, &pair.root, pair.vault, &object)
            .unwrap();
        mutate_album(
            &mut pair.peer,
            &pair.root,
            pair.vault,
            AlbumMutation::Remove(&album, &[object]),
        )
        .unwrap();
        mutate_album(
            &mut pair.peer,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 4),
        )
        .unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Remove(&album, &[object]),
        )
        .unwrap();
        pair.send(false);
        pair.send(true);
        assert_eq!(store::albums(&pair.source).unwrap()[0].member_count, 1);
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 1);
        pair.restart();
        let keys = sync_keys::key_directory(&pair.source, &pair.root, pair.vault).unwrap();
        assert!(
            sync_receive::load_materialized_state(&pair.source, &keys)
                .unwrap()
                .album_contains(&album, &object)
        );
    }

    #[test]
    fn atomic_place_authors_destination_and_removal_and_repairs_interrupted_materialization() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Source");
        let object = pair.activate(false, 50);
        pair.publish(object);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        let target = Album {
            album_id: id(41),
            name: "Destination".into(),
            created_ms: 4,
            revision: 1,
        };
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Place(
                store::AlbumDestination::New(&target, Some(&album)),
                Some(&album),
                &[object],
                true,
                4,
            ),
        )
        .unwrap();
        pair.send(false);
        pair.activate(true, 50);
        // Crash before the ordinary download-completion hook. Planning repairs it.
        pair.restart();
        pending_for_collection(&mut pair.peer, &pair.root, pair.vault, pair.collection).unwrap();
        let albums = store::albums(&pair.peer).unwrap();
        assert_eq!(
            albums
                .iter()
                .find(|a| a.album.album_id == album)
                .unwrap()
                .member_count,
            0
        );
        let destination = albums
            .iter()
            .find(|a| a.album.album_id == target.album_id)
            .unwrap();
        assert_eq!(destination.member_count, 1);
        assert!(
            destination.parent_id.is_none(),
            "v7 hierarchy remains local"
        );
        assert_eq!(
            store::albums(&pair.source)
                .unwrap()
                .iter()
                .find(|a| a.album.album_id == target.album_id)
                .unwrap()
                .parent_id,
            Some(album)
        );
    }
    #[test]
    fn bootstrap_cache_survives_media_changes_and_legacy_writes_invalidate_it() {
        let mut pair = Pair::new();
        pair.album(40, "First");
        reconcile_albums(&mut pair.source, &pair.root, pair.vault).unwrap();
        assert!(
            pair.source
                .own_source_cache
                .as_ref()
                .unwrap()
                .albums_bootstrapped
        );
        pair.activate(false, 50);
        let membership = sync_membership::load(&pair.source).unwrap().unwrap();
        let cache =
            take_source_cache(&mut pair.source, &pair.root, pair.vault, &membership).unwrap();
        assert!(
            cache.albums_bootstrapped,
            "media activation must not trigger another full album scan"
        );
        pair.source.own_source_cache = Some(cache);
        store::put_album(
            &mut pair.source,
            &Album {
                album_id: id(41),
                name: "Imported archive album".into(),
                created_ms: 1,
                revision: 1,
            },
        )
        .unwrap();
        assert!(
            !pair
                .source
                .own_source_cache
                .as_ref()
                .unwrap()
                .albums_bootstrapped
        );
        reconcile_albums(&mut pair.source, &pair.root, pair.vault).unwrap();
        pair.send(false);
        assert_eq!(store::albums(&pair.peer).unwrap().len(), 2);
    }

    #[test]
    fn received_album_projection_failure_does_not_advance_the_accepted_head() {
        let mut pair = Pair::new();
        pair.album(40, "Received atomically");
        let mut membership = sync_membership::load(&pair.peer).unwrap().unwrap();
        let mut keys = sync_keys::key_directory(&pair.peer, &pair.root, pair.vault).unwrap();
        let mut log = sync_log::load(&pair.peer, &membership).unwrap();
        let mut state = sync_receive::load_materialized_state(&pair.peer, &keys).unwrap();
        let records = sync_log::records_after(&pair.source, &pair.source_id, 2).unwrap();
        assert_eq!(records.len(), 2, "declaration and album creation");
        sync_receive::accept_operation(
            &mut pair.peer,
            &mut log,
            &mut membership,
            &mut state,
            &mut keys,
            &pair.root,
            100,
            &records[0],
        )
        .unwrap();
        let before = log.head(&pair.source_id);
        pair.peer
            .connection()
            .execute_batch(
                "CREATE TEMP TRIGGER deny_received_album BEFORE INSERT ON albums
            BEGIN SELECT RAISE(ABORT, 'injected projection failure'); END;",
            )
            .unwrap();
        assert!(
            sync_receive::accept_operation(
                &mut pair.peer,
                &mut log,
                &mut membership,
                &mut state,
                &mut keys,
                &pair.root,
                100,
                &records[1]
            )
            .is_err()
        );
        assert_eq!(log.head(&pair.source_id), before);
        assert_eq!(
            sync_log::load(&pair.peer, &membership)
                .unwrap()
                .head(&pair.source_id),
            before
        );
        assert!(store::albums(&pair.peer).unwrap().is_empty());
        pair.peer
            .connection()
            .execute_batch("DROP TRIGGER deny_received_album")
            .unwrap();
        sync_receive::accept_operation(
            &mut pair.peer,
            &mut log,
            &mut membership,
            &mut state,
            &mut keys,
            &pair.root,
            100,
            &records[1],
        )
        .unwrap();
        assert_eq!(
            store::albums(&pair.peer).unwrap()[0].album.name,
            "Received atomically"
        );
    }
    #[test]
    fn pending_local_add_survives_remote_remove_restart_and_ready_reconciliation() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Pending intent");
        pair.send(false);
        let object = pair.activate(true, 50);
        mutate_album(
            &mut pair.peer,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        assert!(
            pair.peer
                .own_source_cache
                .as_ref()
                .unwrap()
                .albums_bootstrapped
        );
        pair.restart();
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        pair.activate(false, 50);
        pair.publish(object);
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 4),
        )
        .unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Remove(&album, &[object]),
        )
        .unwrap();
        pair.send(false);
        assert_eq!(
            store::albums(&pair.peer).unwrap()[0].member_count,
            1,
            "remote removal cannot erase an unsigned local add"
        );
        assert!(
            !pair
                .peer
                .own_source_cache
                .as_ref()
                .unwrap()
                .ready_album_objects
                .is_empty()
        );
        // Drain ready intent from the existing bootstrap cache, then verify restart persistence.
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        let pending: i64 = pair
            .peer
            .connection()
            .query_row(
                "SELECT count(*) FROM own_sync_pending_album_memberships",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "only a durable local add retires the intent");
        pair.restart();
        pair.send(true);
        assert_eq!(store::albums(&pair.source).unwrap()[0].member_count, 1);
        assert_eq!(store::albums(&pair.peer).unwrap()[0].member_count, 1);
    }

    #[test]
    fn matching_legacy_album_bootstraps_converge_before_exchange_and_preserve_rename() {
        let mut pair = Pair::new();
        let album = Album {
            album_id: id(40),
            name: "Legacy snapshot".into(),
            created_ms: 1,
            revision: 1,
        };
        store::put_album(&mut pair.source, &album).unwrap();
        store::put_album(&mut pair.peer, &album).unwrap();
        reconcile_albums(&mut pair.source, &pair.root, pair.vault).unwrap();
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Rename(&album.album_id, "Rename after one creation"),
        )
        .unwrap();
        pair.send(false);
        pair.send(true);
        assert_eq!(
            store::albums(&pair.source).unwrap()[0].album.name,
            "Rename after one creation"
        );
        assert_eq!(
            store::albums(&pair.peer).unwrap()[0].album.name,
            "Rename after one creation"
        );
        pair.restart();
        let keys = sync_keys::key_directory(&pair.peer, &pair.root, pair.vault).unwrap();
        assert_eq!(
            sync_receive::load_materialized_state(&pair.peer, &keys)
                .unwrap()
                .album_name(&album.album_id),
            Some("Rename after one creation")
        );
    }
    #[test]
    fn duplicate_legacy_creation_does_not_recreate_a_locally_deleted_album() {
        let mut pair = Pair::new();
        let album = Album {
            album_id: id(40),
            name: "Legacy".into(),
            created_ms: 1,
            revision: 1,
        };
        store::put_album(&mut pair.source, &album).unwrap();
        store::put_album(&mut pair.peer, &album).unwrap();
        reconcile_albums(&mut pair.source, &pair.root, pair.vault).unwrap();
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        store::delete_album(&mut pair.peer, &album.album_id).unwrap();
        pair.send(false);
        assert!(store::albums(&pair.peer).unwrap().is_empty());
        pair.restart();
        reconcile_albums(&mut pair.peer, &pair.root, pair.vault).unwrap();
        assert!(store::albums(&pair.peer).unwrap().is_empty());
    }

    #[test]
    fn caller_persisted_album_identity_cannot_revive_a_deleted_folder() {
        let mut pair = Pair::new();
        let album_id = pair.album(40, "Desktop folder");
        store::delete_album(&mut pair.source, &album_id).unwrap();
        let album = Album {
            album_id,
            name: "Desktop folder".into(),
            created_ms: 1,
            revision: 1,
        };
        for reopening in [false, true] {
            if reopening {
                pair.restart();
            }
            let error = mutate_album(
                &mut pair.source,
                &pair.root,
                pair.vault,
                AlbumMutation::Create(&album),
            )
            .unwrap_err();
            assert_eq!(error.status(), ChurStatus::InvalidInput);
            assert!(store::albums(&pair.source).unwrap().is_empty());
        }
    }

    #[test]
    fn failed_signed_add_rolls_back_both_pending_intent_and_visible_membership() {
        let mut pair = Pair::new();
        let album = pair.album(40, "Atomic add");
        let object = pair.activate(false, 50);
        pair.publish(object);
        pair.source
            .connection()
            .execute_batch(
                "CREATE TEMP TRIGGER deny_local_add BEFORE INSERT ON sync_operations
            BEGIN SELECT RAISE(ABORT, 'injected signed add failure'); END;",
            )
            .unwrap();
        assert!(
            mutate_album(
                &mut pair.source,
                &pair.root,
                pair.vault,
                AlbumMutation::Membership(&album, &object, true, 3)
            )
            .is_err()
        );
        assert_eq!(store::albums(&pair.source).unwrap()[0].member_count, 0);
        let pending: i64 = pair
            .source
            .connection()
            .query_row(
                "SELECT count(*) FROM own_sync_pending_album_memberships",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0);
        pair.source
            .connection()
            .execute_batch("DROP TRIGGER deny_local_add")
            .unwrap();
        pair.restart();
        mutate_album(
            &mut pair.source,
            &pair.root,
            pair.vault,
            AlbumMutation::Membership(&album, &object, true, 3),
        )
        .unwrap();
        pair.send(false);
        let keys = sync_keys::key_directory(&pair.peer, &pair.root, pair.vault).unwrap();
        assert!(
            sync_receive::load_materialized_state(&pair.peer, &keys)
                .unwrap()
                .album_contains(&album, &object)
        );
    }
}
