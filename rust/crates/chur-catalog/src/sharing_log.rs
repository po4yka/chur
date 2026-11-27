//! Durable collection-operation streams in catalog v4.

use std::collections::BTreeMap;

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Commitment, Key, Nonce};
use chur_format::constants::{IntegritySummary, ObjectState};
use chur_sync_protocol::{
    KeyDirectory,
    collection_membership::{CollectionAuthorization, CollectionMembershipState},
    collection_operation::CollectionOperation,
    collection_operation_log::CollectionOperationLog,
    convergence::CausalStamp,
    operation::DeviceSigningKey,
    operation_log::{ApplyOutcome, ForkState},
    payload::{OperationPayload, PayloadBody},
    state::MembershipState,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{
    db::{CatalogDb, as_sqlite_integer, from_sqlite_integer, map_sqlite},
    model::COLLECTION_POLICY_SHARED,
    schema::bump_generation,
};

type StoredOperation = (Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>);

#[cfg(test)]
thread_local! {
    static LOG_LOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Result of keyed acceptance, which can also refuse a record for good.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// The log handled the record as the protocol outcome says.
    Outcome(ApplyOutcome),
    /// The record is authenticated but is not accepted, and no operation row of it was stored.
    /// A permanent verdict, or a record of a member stream that forked.
    Rejected,
}

/// What persisting a freshly accepted operation did.
enum Persisted {
    /// The operation is stored and the log revision moves to this value.
    Stored(u64),
    /// The operation was not stored; the caller undoes the in-place accept and reports this.
    Refused(Accepted),
}

/// One durable locally authored record that the transport must publish.
pub struct OutboundRecord {
    /// Monotonic catalog row cursor. Collection logs are append-only and are not vacuumed.
    pub cursor: u64,
    /// Collection route authenticated when the operation was accepted.
    pub collection_id: Id,
    /// Complete signed operation bytes.
    pub record: Vec<u8>,
}

/// Returns at most 64 locally authored records, including tombstones whose
/// objects no longer exist. The host advances the cursor only after relay ACK.
pub fn outbound_after(
    db: &CatalogDb,
    local_vault_id: &Id,
    local_device_id: &Id,
    after_cursor: u64,
) -> Result<Vec<OutboundRecord>> {
    let mut statement = db.connection().prepare(
        "SELECT s.rowid, t.collection_id, s.key_selector, s.digest, s.record
           FROM sharing_operations s JOIN sharing_operation_streams t ON t.key_selector = s.key_selector
          WHERE s.issuer_identity_vault_id = ?1 AND s.issuer_device_id = ?2 AND s.rowid > ?3
          ORDER BY s.rowid LIMIT 64",
    ).map_err(|error| map_sqlite(error, "outbound collection operations could not be prepared"))?;
    let rows = statement
        .query_map(
            params![
                local_vault_id.as_bytes().as_slice(),
                local_device_id.as_bytes().as_slice(),
                as_sqlite_integer(after_cursor, "outbound collection cursor is too large")?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .map_err(|error| map_sqlite(error, "outbound collection operations could not be read"))?;
    let mut result = Vec::new();
    let mut bytes = 0usize;
    for row in rows {
        let (cursor, collection, selector, digest, record) = row.map_err(|error| {
            map_sqlite(error, "outbound collection operation could not be read")
        })?;
        let operation = CollectionOperation::decode(&record)?;
        ensure!(
            operation.issuer_identity_vault_id() == local_vault_id
                && operation.issuer_device_id() == local_device_id
                && operation.key_selector().as_bytes().as_slice() == selector
                && operation.digest().as_slice() == digest,
            CatalogCorrupt,
            "outbound collection operation differs from its projection"
        );
        if bytes.saturating_add(record.len()) > 16_777_216 {
            break;
        }
        bytes += record.len();
        result.push(OutboundRecord {
            cursor: from_sqlite_integer(cursor, "outbound cursor is negative")?,
            collection_id: crate::row::id(&collection, "outbound collection ID is malformed")?,
            record,
        });
    }
    Ok(result)
}

/// One collection operation log rebuilt from authenticated durable rows.
pub struct DurableCollectionOperationLog {
    log: CollectionOperationLog,
    revision: u64,
}

/// One validated log retained only while its decrypted catalog stays open.
pub(crate) struct CachedCollectionLog {
    selector: Id,
    revision: u64,
    log: DurableCollectionOperationLog,
}

impl DurableCollectionOperationLog {
    /// Starts and stores one empty collection epoch stream.
    pub fn provision(
        db: &mut CatalogDb,
        collection_id: Id,
        collection_epoch: u64,
        key_selector: Id,
    ) -> Result<Self> {
        db.transaction(|transaction| {
            ensure_stream(transaction, &collection_id, collection_epoch, &key_selector)?;
            bump_generation(transaction)
        })?;
        Ok(Self {
            log: CollectionOperationLog::new(collection_id, collection_epoch, key_selector),
            revision: 0,
        })
    }

    /// Authors and persists the next signed operation in this collection stream.
    #[expect(
        clippy::too_many_arguments,
        reason = "the signed collection operation binds its author and both membership states"
    )]
    pub fn author(
        &mut self,
        db: &mut CatalogDb,
        operation_id: Id,
        issuer_vault_id: Id,
        device_id: Id,
        key: &Key,
        nonce: Nonce,
        payload: &OperationPayload,
        signing_key: &DeviceSigningKey,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<CollectionOperation> {
        let operation = self.log.author(
            operation_id,
            issuer_vault_id,
            device_id,
            key,
            nonce,
            payload,
            signing_key,
            issuer_membership,
            source_membership,
            collection_membership,
        )?;
        ensure!(
            self.accept(
                db,
                &operation,
                payload,
                issuer_membership,
                source_membership,
                collection_membership,
            )? == ApplyOutcome::Applied,
            InternalFailure,
            "fresh collection operation was not accepted"
        );
        Ok(operation)
    }

    /// Authors a lifecycle operation after its accepted content cause verifies.
    #[expect(
        clippy::too_many_arguments,
        reason = "the signed lifecycle operation binds its keys and both memberships"
    )]
    pub fn author_with_keys(
        &mut self,
        db: &mut CatalogDb,
        keys: &KeyDirectory,
        operation_id: Id,
        issuer_vault_id: Id,
        device_id: Id,
        key: &Key,
        nonce: Nonce,
        payload: &OperationPayload,
        signing_key: &DeviceSigningKey,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<CollectionOperation> {
        let operation = self.log.author(
            operation_id,
            issuer_vault_id,
            device_id,
            key,
            nonce,
            payload,
            signing_key,
            issuer_membership,
            source_membership,
            collection_membership,
        )?;
        ensure!(
            self.accept_with_keys(
                db,
                keys,
                &operation,
                payload,
                issuer_membership,
                source_membership,
                collection_membership
            )? == Accepted::Outcome(ApplyOutcome::Applied),
            InternalFailure,
            "fresh lifecycle operation was not accepted"
        );
        Ok(operation)
    }

    /// Validates and stores one operation without advancing memory before SQL commits.
    pub fn accept(
        &mut self,
        db: &mut CatalogDb,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<ApplyOutcome> {
        match self.accept_inner(
            db,
            None,
            operation,
            payload,
            issuer_membership,
            source_membership,
            collection_membership,
        )? {
            Accepted::Outcome(outcome) => Ok(outcome),
            Accepted::Rejected => Err(Error::new(
                ChurStatus::InternalFailure,
                "keyless acceptance cannot reject a record",
            )),
        }
    }

    /// Accepts object lifecycle records only after their content cause verifies.
    #[expect(
        clippy::too_many_arguments,
        reason = "the signed record and membership evidence are explicit"
    )]
    pub fn accept_with_keys(
        &mut self,
        db: &mut CatalogDb,
        keys: &KeyDirectory,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<Accepted> {
        self.accept_inner(
            db,
            Some(keys),
            operation,
            payload,
            issuer_membership,
            source_membership,
            collection_membership,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the signed record and membership evidence are explicit"
    )]
    fn accept_inner(
        &mut self,
        db: &mut CatalogDb,
        keys: Option<&KeyDirectory>,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        issuer_membership: &MembershipState,
        source_membership: &MembershipState,
        collection_membership: &CollectionMembershipState,
    ) -> Result<Accepted> {
        if matches!(
            payload.body(),
            PayloadBody::DeleteObject { .. }
                | PayloadBody::RestoreObject { .. }
                | PayloadBody::PurgeObject { .. }
        ) {
            ensure!(
                keys.is_some(),
                AuthenticationFailed,
                "object lifecycle requires content-cause validation"
            );
        }
        // Keyless callers cannot report a refusal, so the log rejects the record below instead.
        // The verdict is read only, so it runs before the log is touched.
        if keys.is_some()
            && let CollectionAuthorization::Forbidden(_) = collection_membership
                .classify_collection_operation(operation, payload, issuer_membership)?
        {
            return Ok(Accepted::Rejected);
        }
        // The log takes the operation in place and every refusal below gives it back with the exact inverse, so no whole-log clone runs per operation.
        let was_forked = self
            .log
            .fork(
                operation.issuer_identity_vault_id(),
                operation.issuer_device_id(),
            )
            .is_some();
        let accepted = self.log.accept(
            operation,
            payload,
            issuer_membership,
            source_membership,
            collection_membership,
        );
        match accepted {
            Ok(ApplyOutcome::Applied) => {
                match self.persist_applied(db, keys, operation, payload, collection_membership) {
                    Ok(Persisted::Stored(next_revision)) => {
                        self.revision = next_revision;
                        Ok(Accepted::Outcome(ApplyOutcome::Applied))
                    }
                    Ok(Persisted::Refused(refusal)) => {
                        self.log.undo_accept(operation);
                        Ok(refusal)
                    }
                    Err(error) => {
                        self.log.undo_accept(operation);
                        Err(error)
                    }
                }
            }
            Ok(ApplyOutcome::Duplicate) => {
                check_stored_operation(db, operation)?;
                Ok(Accepted::Outcome(ApplyOutcome::Duplicate))
            }
            Ok(outcome @ (ApplyOutcome::PendingGap | ApplyOutcome::PendingCause)) => {
                Ok(Accepted::Outcome(outcome))
            }
            Err(error) if error.status() == ChurStatus::SyncChainFork => {
                let Some(next_revision) = self.revision.checked_add(1) else {
                    if !was_forked {
                        self.log.undo_fork(
                            operation.issuer_identity_vault_id(),
                            operation.issuer_device_id(),
                        );
                    }
                    return Err(Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "collection log revision overflowed",
                    ));
                };
                let evidence = self
                    .log
                    .fork(
                        operation.issuer_identity_vault_id(),
                        operation.issuer_device_id(),
                    )
                    .ok_or_else(|| {
                        Error::new(
                            ChurStatus::InternalFailure,
                            "collection fork has no evidence",
                        )
                    })?;
                let persisted = db.transaction(|transaction| {
                    transaction
                        .execute(
                            "INSERT INTO sharing_operation_forks
                                 (key_selector, issuer_identity_vault_id, issuer_device_id,
                                  state, accepted_record, conflicting_record)
                             VALUES (?1, ?2, ?3, 1, ?4, ?5)
                             ON CONFLICT DO UPDATE SET
                                 state = 1, accepted_record = excluded.accepted_record,
                                 conflicting_record = excluded.conflicting_record",
                            params![
                                self.log.key_selector().as_bytes().as_slice(),
                                operation.issuer_identity_vault_id().as_bytes().as_slice(),
                                operation.issuer_device_id().as_bytes().as_slice(),
                                evidence.accepted_record(),
                                evidence.conflicting_record(),
                            ],
                        )
                        .map_err(|sqlite| {
                            map_sqlite(sqlite, "collection fork evidence could not be stored")
                        })?;
                    bump_log_revision(transaction, self.log.key_selector())?;
                    bump_generation(transaction)
                });
                if let Err(persist_error) = persisted {
                    if !was_forked {
                        self.log.undo_fork(
                            operation.issuer_identity_vault_id(),
                            operation.issuer_device_id(),
                        );
                    }
                    return Err(persist_error);
                }
                self.revision = next_revision;
                // A member's equivocation freezes only that member's stream, so the page goes on.
                // A source device that forks still fails the page.
                if keys.is_some()
                    && operation.issuer_identity_vault_id()
                        != collection_membership.source_vault_id()
                {
                    return Ok(Accepted::Rejected);
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Persists one operation the log has just taken in; a refusal means the caller must undo the in-place accept.
    fn persist_applied(
        &self,
        db: &mut CatalogDb,
        keys: Option<&KeyDirectory>,
        operation: &CollectionOperation,
        payload: &OperationPayload,
        collection_membership: &CollectionMembershipState,
    ) -> Result<Persisted> {
        let next_revision = self.revision.checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "collection log revision overflowed",
            )
        })?;
        if let Some(keys) = keys {
            ensure_object_index(db, operation.key_selector(), keys)?;
            let cause = crate::sharing_receive::validate_lifecycle_candidate(
                db,
                keys,
                collection_membership.source_vault_id(),
                operation,
                payload,
            )?;
            if matches!(
                cause,
                Accepted::Rejected | Accepted::Outcome(ApplyOutcome::PendingCause)
            ) {
                return Ok(Persisted::Refused(cause));
            }
            ensure!(
                cause == Accepted::Outcome(ApplyOutcome::Applied),
                InternalFailure,
                "lifecycle validator returned an invalid state"
            );
        }
        db.transaction(|transaction| {
            ensure_stream(
                transaction,
                self.log.collection_id(),
                self.log.collection_epoch(),
                self.log.key_selector(),
            )?;
            insert_operation(transaction, operation)?;
            insert_object_event(transaction, operation, payload)?;
            hide_accepted_shared_delete(transaction, payload)?;
            crate::deletion::project_purge(transaction, payload)?;
            bump_log_revision(transaction, self.log.key_selector())?;
            bump_generation(transaction)
        })?;
        Ok(Persisted::Stored(next_revision))
    }

    /// Latest accepted head for one participant.
    #[must_use]
    pub fn head(&self, identity_vault_id: &Id, device_id: &Id) -> Option<(u64, Commitment)> {
        self.log.head(identity_vault_id, device_id)
    }
}

/// Restores one current collection epoch from authenticated catalog rows.
pub fn load(
    db: &CatalogDb,
    collection_id: Id,
    collection_epoch: u64,
    key_selector: Id,
    keys: &KeyDirectory,
    memberships: &BTreeMap<Id, MembershipState>,
    collection_membership: &CollectionMembershipState,
) -> Result<DurableCollectionOperationLog> {
    #[cfg(test)]
    LOG_LOADS.with(|loads| loads.set(loads.get() + 1));
    let revision = stream_revision(db, &key_selector)?;
    let stored_stream: Option<(Vec<u8>, i64)> = db
        .connection()
        .query_row(
            "SELECT collection_id, collection_epoch
               FROM sharing_operation_streams WHERE key_selector = ?1",
            [key_selector.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "collection operation stream could not be read"))?;
    let Some((stored_collection, stored_epoch)) = stored_stream else {
        ensure!(
            stream_revision(db, &key_selector)? == revision,
            Conflict,
            "collection log changed during replay"
        );
        return Ok(DurableCollectionOperationLog {
            log: CollectionOperationLog::new(collection_id, collection_epoch, key_selector),
            revision,
        });
    };
    ensure!(
        Id::from_slice(&stored_collection).map_err(corrupt)? == collection_id
            && from_sqlite_integer(stored_epoch, "collection operation epoch is malformed")?
                == collection_epoch,
        CatalogCorrupt,
        "collection operation stream projection disagrees"
    );
    let source_membership = memberships
        .get(collection_membership.source_vault_id())
        .ok_or_else(|| Error::new(ChurStatus::CatalogCorrupt, "source membership is absent"))?;
    let mut statement = db
        .connection()
        .prepare(
            "SELECT issuer_identity_vault_id, issuer_device_id, device_sequence,
                    operation_id, digest, record
               FROM sharing_operations WHERE key_selector = ?1
              ORDER BY issuer_identity_vault_id, issuer_device_id, device_sequence",
        )
        .map_err(|error| map_sqlite(error, "collection operations could not be prepared"))?;
    let rows = statement
        .query_map([key_selector.as_bytes().as_slice()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "collection operations could not be read"))?;
    let mut pending = Vec::new();
    for row in rows {
        let row: StoredOperation =
            row.map_err(|error| map_sqlite(error, "a collection operation row could not be read"))?;
        let operation = CollectionOperation::decode(&row.5).map_err(corrupt)?;
        ensure_operation_projection(&operation, &row)?;
        let payload =
            OperationPayload::open_for_collection_operation(&operation, keys).map_err(corrupt)?;
        pending.push((operation, payload));
    }
    let mut log = CollectionOperationLog::new(collection_id, collection_epoch, key_selector);
    while !pending.is_empty() {
        let mut progress = false;
        let mut next = Vec::new();
        for (operation, payload) in pending {
            let issuer = memberships
                .get(operation.issuer_identity_vault_id())
                .ok_or_else(|| {
                    Error::new(ChurStatus::CatalogCorrupt, "issuer membership is absent")
                })?;
            match log
                .restore_accepted(
                    &operation,
                    &payload,
                    issuer,
                    source_membership,
                    collection_membership,
                )
                .map_err(corrupt)?
            {
                ApplyOutcome::Applied | ApplyOutcome::Duplicate => progress = true,
                ApplyOutcome::PendingGap | ApplyOutcome::PendingCause => {
                    next.push((operation, payload));
                }
            }
        }
        ensure!(
            progress,
            CatalogCorrupt,
            "collection operation history has a gap or missing cause"
        );
        pending = next;
    }
    restore_forks(db, &mut log, &key_selector)?;
    ensure!(
        stream_revision(db, &key_selector)? == revision,
        Conflict,
        "collection log changed during replay"
    );
    Ok(DurableCollectionOperationLog { log, revision })
}

/// Reuses a validated chain until its durable accepted-row revision changes.
///
/// The cache is owned by `CatalogDb` and drops when the vault locks. A failed
/// body leaves no cached state: a committed prefix can be replayed next time.
#[expect(
    clippy::too_many_arguments,
    reason = "the log's authenticated epoch context is explicit"
)]
pub fn with_cached_log<T>(
    db: &mut CatalogDb,
    collection_id: Id,
    collection_epoch: u64,
    selector: Id,
    keys: &KeyDirectory,
    memberships: &BTreeMap<Id, MembershipState>,
    collection_membership: &CollectionMembershipState,
    body: impl FnOnce(&mut CatalogDb, &mut DurableCollectionOperationLog) -> Result<T>,
) -> Result<T> {
    let mut log = take_cached_log(
        db,
        collection_id,
        collection_epoch,
        selector,
        keys,
        memberships,
        collection_membership,
    )?;
    let result = body(db, &mut log);
    if result.is_ok() {
        store_cached_log(db, selector, log)?;
    }
    result
}

/// Takes the session cache for an author that persists several operations.
pub fn take_cached_log(
    db: &mut CatalogDb,
    collection_id: Id,
    collection_epoch: u64,
    selector: Id,
    keys: &KeyDirectory,
    memberships: &BTreeMap<Id, MembershipState>,
    collection_membership: &CollectionMembershipState,
) -> Result<DurableCollectionOperationLog> {
    let revision = stream_revision(db, &selector)?;
    let cached = db.sharing_log_cache.take();
    let log = match cached {
        Some(entry) if entry.selector == selector && entry.revision == revision => entry.log,
        _ => load(
            db,
            collection_id,
            collection_epoch,
            selector,
            keys,
            memberships,
            collection_membership,
        )?,
    };
    Ok(log)
}

/// Stores only a successfully advanced log under its committed revision.
pub fn store_cached_log(
    db: &mut CatalogDb,
    selector: Id,
    log: DurableCollectionOperationLog,
) -> Result<()> {
    let current = stream_revision(db, &selector)?;
    db.sharing_log_cache = (log.revision == current).then_some(CachedCollectionLog {
        selector,
        revision: log.revision,
        log,
    });
    Ok(())
}

fn stream_revision(db: &CatalogDb, selector: &Id) -> Result<u64> {
    let value: Option<i64> = db
        .connection()
        .query_row(
            "SELECT log_revision FROM sharing_operation_streams WHERE key_selector = ?1",
            [selector.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "collection log revision could not be read"))?;
    value.map_or(Ok(0), |revision| {
        from_sqlite_integer(revision, "collection log revision is malformed")
    })
}

/// Visits the durable local copy of one collection operation stream in order.
pub fn visit_records(
    db: &CatalogDb,
    selector: &Id,
    mut visit: impl FnMut(CollectionOperation) -> Result<()>,
) -> Result<()> {
    let mut statement = db
        .connection()
        .prepare(
            "SELECT issuer_identity_vault_id, issuer_device_id, device_sequence,
                    operation_id, digest, record
               FROM sharing_operations WHERE key_selector = ?1
             ORDER BY issuer_identity_vault_id, issuer_device_id, device_sequence",
        )
        .map_err(|error| map_sqlite(error, "collection operations could not be prepared"))?;
    let rows = statement
        .query_map([selector.as_bytes().as_slice()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "collection operations could not be read"))?;
    for row in rows {
        let stored: StoredOperation =
            row.map_err(|error| map_sqlite(error, "collection operation could not be read"))?;
        let operation = CollectionOperation::decode(&stored.5).map_err(corrupt)?;
        ensure_operation_projection(&operation, &stored)?;
        ensure!(
            operation.key_selector() == selector,
            CatalogCorrupt,
            "collection selector projection disagrees"
        );
        visit(operation)?;
    }
    Ok(())
}

/// Returns the durable local copy of one collection operation stream.
pub fn records(db: &CatalogDb, selector: &Id) -> Result<Vec<CollectionOperation>> {
    let mut operations = Vec::new();
    visit_records(db, selector, |operation| {
        operations.push(operation);
        Ok(())
    })?;
    Ok(operations)
}

/// Builds the v6 object index once from already accepted SQLCipher rows.
///
/// Old rows passed chain and signature validation when accepted. This replay
/// checks their stored outer projection, encrypted payload, selector, and
/// object identity. Issuer evidence is not available on an offline read, so
/// it does not claim a new signature or causal-chain validation.
pub fn ensure_object_index(db: &mut CatalogDb, selector: &Id, keys: &KeyDirectory) -> Result<()> {
    let ready: Option<i64> = db
        .connection()
        .query_row(
            "SELECT object_index_ready FROM sharing_operation_streams WHERE key_selector = ?1",
            [selector.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "shared object index state could not be read"))?;
    if ready.is_none() || ready == Some(1) {
        return Ok(());
    }
    ensure!(
        ready == Some(0),
        CatalogCorrupt,
        "shared object index state is invalid"
    );
    let domain = keys.domain(selector)?;
    db.transaction(|transaction| {
        let stream: (Vec<u8>, i64, i64) = transaction
            .query_row(
                "SELECT collection_id, collection_epoch, object_index_ready
                   FROM sharing_operation_streams WHERE key_selector = ?1",
                [selector.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| map_sqlite(error, "shared object index state could not be checked"))?;
        ensure!(
            Id::from_slice(&stream.0).map_err(corrupt)? == *domain.collection_id()
                && from_sqlite_integer(stream.1, "collection epoch is malformed")?
                    == domain.collection_epoch(),
            CatalogCorrupt,
            "shared object index selector contradicts its stream"
        );
        if stream.2 == 1 {
            return Ok(());
        }
        ensure!(stream.2 == 0, CatalogCorrupt, "shared object index state is invalid");
        let source_bytes: Vec<u8> = transaction
            .query_row(
                "SELECT source_vault_id FROM sharing_collections WHERE collection_id = ?1",
                [domain.collection_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "shared collection source could not be read"))?;
        let source_vault_id = Id::from_slice(&source_bytes).map_err(corrupt)?;
        transaction
            .execute(
                "DELETE FROM sharing_object_projection WHERE key_selector = ?1",
                [selector.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "shared object projection could not be rebuilt"))?;
        let mut statement = transaction
            .prepare(
                "SELECT issuer_identity_vault_id, issuer_device_id, device_sequence,
                        operation_id, digest, record
                   FROM sharing_operations WHERE key_selector = ?1
                  ORDER BY issuer_identity_vault_id, issuer_device_id, device_sequence",
            )
            .map_err(|error| map_sqlite(error, "collection operations could not be prepared"))?;
        let rows = statement
            .query_map([selector.as_bytes().as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            })
            .map_err(|error| map_sqlite(error, "collection operations could not be read"))?;
        let mut indexed = 0i64;
        let mut lifecycle_by_object = BTreeMap::<Id, Vec<(CausalStamp, OperationPayload)>>::new();
        for row in rows {
            let stored: StoredOperation = row
                .map_err(|error| map_sqlite(error, "collection operation could not be read"))?;
            let operation = CollectionOperation::decode(&stored.5).map_err(corrupt)?;
            ensure_operation_projection(&operation, &stored)?;
            ensure!(operation.key_selector() == selector, CatalogCorrupt, "collection selector projection disagrees");
            let payload = OperationPayload::open_for_collection_operation(&operation, keys).map_err(corrupt)?;
            ensure!(
                payload.collection_id() == domain.collection_id()
                    && payload.collection_epoch() == domain.collection_epoch(),
                CatalogCorrupt,
                "shared object payload contradicts its stream"
            );
            payload.validate_for_collection_operation(domain.collection_id(), domain.collection_epoch()).map_err(corrupt)?;
            let Some((object_id, kind)) = object_event(&payload) else {
                continue;
            };
            if matches!(kind, 1 | 3 | 4) {
                lifecycle_by_object.entry(object_id).or_default().push((
                    CausalStamp::from_collection_operation(&operation),
                    payload.clone(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO sharing_object_operations
                         (key_selector, object_id, operation_id, kind)
                     VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                    params![
                        selector.as_bytes().as_slice(),
                        object_id.as_bytes().as_slice(),
                        operation.operation_id().as_bytes().as_slice(),
                        kind,
                    ],
                )
                .map_err(|error| map_sqlite(error, "shared object event could not be indexed"))?;
            let stored_event: Option<(Vec<u8>, i64)> = transaction
                .query_row(
                    "SELECT object_id, kind FROM sharing_object_operations
                      WHERE key_selector = ?1 AND operation_id = ?2",
                    params![selector.as_bytes().as_slice(), operation.operation_id().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| map_sqlite(error, "shared object event could not be checked"))?;
            ensure!(
                stored_event.is_some_and(|(id, stored_kind)| id == object_id.as_bytes() && stored_kind == kind),
                CatalogCorrupt,
                "shared object event index contradicts signed payload"
            );
            transaction
                .execute(
                    "INSERT INTO sharing_object_projection
                         (key_selector, object_id, revision, dirty) VALUES (?1, ?2, 1, 1)
                     ON CONFLICT(key_selector, object_id) DO UPDATE SET
                         revision = revision + 1, dirty = 1",
                    params![selector.as_bytes().as_slice(), object_id.as_bytes().as_slice()],
                )
                .map_err(|error| map_sqlite(error, "shared object projection could not be rebuilt"))?;
            indexed += 1;
        }
        for records in lifecycle_by_object.values() {
            crate::sharing_receive::validate_backfill_lifecycle(records, &source_vault_id)?;
        }
        let stored_count: i64 = transaction
            .query_row(
                "SELECT count(*) FROM sharing_object_operations WHERE key_selector = ?1",
                [selector.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite(error, "shared object event count could not be checked"))?;
        ensure!(stored_count == indexed, CatalogCorrupt, "shared object index has extra events");
        transaction
            .execute(
                "UPDATE sharing_operation_streams SET object_index_ready = 1 WHERE key_selector = ?1",
                [selector.as_bytes().as_slice()],
            )
            .map_err(|error| map_sqlite(error, "shared object index could not be activated"))?;
        bump_generation(transaction)
    })
}

/// Visits only the signed events indexed for one object.
pub fn visit_object_records(
    db: &CatalogDb,
    keys: &KeyDirectory,
    selector: &Id,
    object_id: &Id,
    mut visit: impl FnMut(CollectionOperation, OperationPayload) -> Result<()>,
) -> Result<()> {
    ensure_index_ready(db, selector)?;
    let domain = keys.domain(selector)?;
    let mut statement = db
        .connection()
        .prepare(
            "SELECT i.kind, s.issuer_identity_vault_id, s.issuer_device_id,
                    s.device_sequence, s.operation_id, s.digest, s.record
               FROM sharing_object_operations i
               JOIN sharing_operations s
                 ON s.key_selector = i.key_selector AND s.operation_id = i.operation_id
              WHERE i.key_selector = ?1 AND i.object_id = ?2
              ORDER BY s.issuer_identity_vault_id, s.issuer_device_id, s.device_sequence",
        )
        .map_err(|error| map_sqlite(error, "shared object records could not be prepared"))?;
    let rows = statement
        .query_map(
            params![
                selector.as_bytes().as_slice(),
                object_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    (
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ),
                ))
            },
        )
        .map_err(|error| map_sqlite(error, "shared object records could not be read"))?;
    for row in rows {
        let (kind, stored): (i64, StoredOperation) =
            row.map_err(|error| map_sqlite(error, "shared object record could not be read"))?;
        let operation = CollectionOperation::decode(&stored.5).map_err(corrupt)?;
        ensure_operation_projection(&operation, &stored)?;
        ensure!(
            operation.key_selector() == selector,
            CatalogCorrupt,
            "shared object selector contradicts the record"
        );
        let payload =
            OperationPayload::open_for_collection_operation(&operation, keys).map_err(corrupt)?;
        ensure!(
            payload.collection_id() == domain.collection_id()
                && payload.collection_epoch() == domain.collection_epoch()
                && object_event(&payload) == Some((*object_id, kind)),
            CatalogCorrupt,
            "shared object index contradicts signed payload"
        );
        visit(operation, payload)?;
    }
    Ok(())
}

/// Returns a bounded queue of objects changed by accepted signed events.
pub fn dirty_object_ids(db: &CatalogDb, selector: &Id, limit: usize) -> Result<Vec<(Id, u64)>> {
    ensure!(
        limit > 0 && limit <= 4096,
        InvalidInput,
        "shared object page limit is invalid"
    );
    ensure_index_ready(db, selector)?;
    let mut statement = db
        .connection()
        .prepare(
            "SELECT p.object_id, p.revision FROM sharing_object_projection p
             JOIN sharing_operation_streams s ON s.key_selector = p.key_selector
             LEFT JOIN object_receive_dispatch q ON q.collection_id = s.collection_id AND q.object_id = p.object_id
             LEFT JOIN objects o ON o.object_id = p.object_id
             LEFT JOIN pending_object_keys k ON k.object_id = p.object_id AND k.collection_id = s.collection_id
             LEFT JOIN object_key_requests r ON r.object_id = p.object_id AND r.collection_id = s.collection_id
             WHERE p.key_selector = ?1 AND p.dirty = 1
             ORDER BY coalesce(q.ticket,0), CASE WHEN o.object_id IS NOT NULL THEN 0
                 WHEN k.object_id IS NOT NULL THEN 1 WHEN r.object_id IS NULL THEN 2 ELSE 3 END,
                 p.object_id LIMIT ?2",
        )
        .map_err(|error| map_sqlite(error, "shared object queue could not be prepared"))?;
    statement
        .query_map(
            params![selector.as_bytes().as_slice(), limit as i64],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|error| map_sqlite(error, "shared object queue could not be read"))?
        .map(|row| {
            let (id, revision) = row
                .map_err(|error| map_sqlite(error, "shared object queue row could not be read"))?;
            Ok((
                Id::from_slice(&id).map_err(corrupt)?,
                from_sqlite_integer(revision, "shared object revision is malformed")?,
            ))
        })
        .collect()
}

/// Clears only the revision that the recipient actually reconciled.
pub fn mark_object_clean(
    db: &mut CatalogDb,
    selector: &Id,
    object_id: &Id,
    expected_revision: u64,
) -> Result<bool> {
    ensure_index_ready(db, selector)?;
    db.transaction(|transaction| {
        let changed = transaction
            .execute(
                "UPDATE sharing_object_projection SET dirty = 0
                  WHERE key_selector = ?1 AND object_id = ?2 AND revision = ?3 AND dirty = 1",
                params![
                    selector.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                    as_sqlite_integer(expected_revision, "shared object revision is too large")?,
                ],
            )
            .map_err(|error| map_sqlite(error, "shared object queue could not be advanced"))?;
        if changed == 1 {
            bump_generation(transaction)?;
        }
        Ok(changed == 1)
    })
}

fn ensure_index_ready(db: &CatalogDb, selector: &Id) -> Result<()> {
    let ready: Option<i64> = db
        .connection()
        .query_row(
            "SELECT object_index_ready FROM sharing_operation_streams WHERE key_selector = ?1",
            [selector.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "shared object index state could not be read"))?;
    ensure!(
        ready.is_none() || ready == Some(1),
        MigrationRequired,
        "shared object index needs backfill"
    );
    Ok(())
}

fn ensure_stream(
    transaction: &Transaction<'_>,
    collection_id: &Id,
    collection_epoch: u64,
    key_selector: &Id,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO sharing_operation_streams
                 (key_selector, collection_id, collection_epoch, object_index_ready, log_revision)
             VALUES (?1, ?2, ?3, 1, 0)
             ON CONFLICT DO NOTHING",
            params![
                key_selector.as_bytes().as_slice(),
                collection_id.as_bytes().as_slice(),
                as_sqlite_integer(collection_epoch, "collection operation epoch is too large")?,
            ],
        )
        .map_err(|error| map_sqlite(error, "collection operation stream could not be stored"))?;
    let stored: (Vec<u8>, i64) = transaction
        .query_row(
            "SELECT collection_id, collection_epoch
               FROM sharing_operation_streams WHERE key_selector = ?1",
            [key_selector.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| map_sqlite(error, "collection operation stream could not be checked"))?;
    ensure!(
        Id::from_slice(&stored.0).map_err(corrupt)? == *collection_id
            && from_sqlite_integer(stored.1, "collection operation epoch is malformed")?
                == collection_epoch,
        AuthenticationFailed,
        "collection operation selector collides with another stream"
    );
    Ok(())
}

fn bump_log_revision(transaction: &Transaction<'_>, selector: &Id) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE sharing_operation_streams SET log_revision = log_revision + 1
              WHERE key_selector = ?1",
            [selector.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite(error, "collection log revision could not advance"))?;
    ensure!(
        changed == 1,
        CatalogCorrupt,
        "collection log stream is absent"
    );
    Ok(())
}

fn insert_operation(transaction: &Transaction<'_>, operation: &CollectionOperation) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO sharing_operations
                 (key_selector, issuer_identity_vault_id, issuer_device_id,
                  device_sequence, operation_id, digest, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                operation.key_selector().as_bytes().as_slice(),
                operation.issuer_identity_vault_id().as_bytes().as_slice(),
                operation.issuer_device_id().as_bytes().as_slice(),
                as_sqlite_integer(
                    operation.device_sequence(),
                    "collection sequence is too large"
                )?,
                operation.operation_id().as_bytes().as_slice(),
                operation.digest().as_slice(),
                operation.encode(),
            ],
        )
        .map_err(|error| map_sqlite(error, "collection operation could not be stored"))?;
    Ok(())
}

fn object_event(payload: &OperationPayload) -> Option<(Id, i64)> {
    match payload.body() {
        PayloadBody::CreateObject { object_id, .. } => Some((*object_id, 1)),
        PayloadBody::CommitObject { object_id, .. } => Some((*object_id, 2)),
        PayloadBody::DeleteObject { object_id, .. } => Some((*object_id, 3)),
        PayloadBody::RestoreObject { object_id, .. } => Some((*object_id, 4)),
        PayloadBody::RewrapObjectKey { object_id, .. } => Some((*object_id, 5)),
        PayloadBody::PurgeObject { object_id, .. } => Some((*object_id, 6)),
        _ => None,
    }
}

fn insert_object_event(
    transaction: &Transaction<'_>,
    operation: &CollectionOperation,
    payload: &OperationPayload,
) -> Result<()> {
    let Some((object_id, kind)) = object_event(payload) else {
        return Ok(());
    };
    transaction
        .execute(
            "INSERT INTO sharing_object_operations
                 (key_selector, object_id, operation_id, kind) VALUES (?1, ?2, ?3, ?4)",
            params![
                operation.key_selector().as_bytes().as_slice(),
                object_id.as_bytes().as_slice(),
                operation.operation_id().as_bytes().as_slice(),
                kind,
            ],
        )
        .map_err(|error| map_sqlite(error, "shared object event could not be indexed"))?;
    transaction
        .execute(
            "INSERT INTO sharing_object_projection
                 (key_selector, object_id, revision, dirty) VALUES (?1, ?2, 1, 1)
             ON CONFLICT(key_selector, object_id) DO UPDATE SET
                 revision = revision + 1, dirty = 1",
            params![
                operation.key_selector().as_bytes().as_slice(),
                object_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|error| map_sqlite(error, "shared object projection could not be updated"))?;
    Ok(())
}

/// Hides a recipient copy in the same commit as its signed DeleteObject.
/// Source default collections are excluded; RestoreObject remains visible only
/// after the recipient checks and reconciles the full signed lifecycle.
fn hide_accepted_shared_delete(
    transaction: &Transaction<'_>,
    payload: &OperationPayload,
) -> Result<()> {
    let PayloadBody::DeleteObject {
        object_id,
        object_generation,
        ..
    } = payload.body()
    else {
        return Ok(());
    };
    transaction
        .execute(
            "UPDATE objects SET state = ?1, integrity_summary = ?2
              WHERE object_id = ?3 AND collection_id = ?4 AND state = ?5
                AND object_generation <= ?6
                AND EXISTS (
                    SELECT 1 FROM collections WHERE collection_id = ?4 AND policy_type = ?7
                )",
            params![
                i64::from(ObjectState::SharedDeleted.value()),
                i64::from(IntegritySummary::Unverified.value()),
                object_id.as_bytes().as_slice(),
                payload.collection_id().as_bytes().as_slice(),
                i64::from(ObjectState::Active.value()),
                as_sqlite_integer(*object_generation, "shared delete generation is too large")?,
                i64::from(COLLECTION_POLICY_SHARED),
            ],
        )
        .map_err(|error| map_sqlite(error, "accepted shared delete could not hide its object"))?;
    Ok(())
}

fn check_stored_operation(db: &CatalogDb, operation: &CollectionOperation) -> Result<()> {
    let stored: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT record FROM sharing_operations
              WHERE key_selector = ?1 AND issuer_identity_vault_id = ?2
                AND issuer_device_id = ?3 AND device_sequence = ?4",
            params![
                operation.key_selector().as_bytes().as_slice(),
                operation.issuer_identity_vault_id().as_bytes().as_slice(),
                operation.issuer_device_id().as_bytes().as_slice(),
                as_sqlite_integer(
                    operation.device_sequence(),
                    "collection sequence is too large"
                )?,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "collection operation could not be checked"))?;
    ensure!(
        stored.as_deref() == Some(operation.encode().as_slice()),
        CatalogCorrupt,
        "durable collection operation differs from accepted replay"
    );
    Ok(())
}

fn ensure_operation_projection(
    operation: &CollectionOperation,
    row: &StoredOperation,
) -> Result<()> {
    ensure!(
        Id::from_slice(&row.0).map_err(corrupt)? == *operation.issuer_identity_vault_id()
            && Id::from_slice(&row.1).map_err(corrupt)? == *operation.issuer_device_id()
            && from_sqlite_integer(row.2, "collection sequence is malformed")?
                == operation.device_sequence()
            && Id::from_slice(&row.3).map_err(corrupt)? == *operation.operation_id()
            && row.4.as_slice() == operation.digest(),
        CatalogCorrupt,
        "collection operation projection disagrees with its record"
    );
    Ok(())
}

fn restore_forks(db: &CatalogDb, log: &mut CollectionOperationLog, selector: &Id) -> Result<()> {
    let mut statement = db.connection().prepare(
        "SELECT issuer_identity_vault_id, issuer_device_id, state, accepted_record, conflicting_record
           FROM sharing_operation_forks WHERE key_selector = ?1",
    ).map_err(|error| map_sqlite(error, "collection forks could not be prepared"))?;
    let rows = statement
        .query_map([selector.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(|error| map_sqlite(error, "collection forks could not be read"))?;
    for row in rows {
        let (vault, device, state, accepted, conflicting) =
            row.map_err(|error| map_sqlite(error, "a collection fork row could not be read"))?;
        let state = match state {
            1 => ForkState::Detected,
            2 => ForkState::Acknowledged,
            _ => {
                return Err(Error::new(
                    ChurStatus::CatalogCorrupt,
                    "collection fork state is invalid",
                ));
            }
        };
        log.restore_fork(
            Id::from_slice(&vault).map_err(corrupt)?,
            Id::from_slice(&device).map_err(corrupt)?,
            state,
            accepted,
            conflicting,
        )
        .map_err(corrupt)?;
    }
    Ok(())
}

fn corrupt(error: Error) -> Error {
    Error::new(ChurStatus::CatalogCorrupt, error.context())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use chur_crypto::{Key, Nonce, random};
    use chur_sync_protocol::{
        KeyDomain,
        collection_membership::{CollectionMembershipAction, CollectionMembershipRecord},
        collection_operation::CollectionObservedHead,
        grant::PermissionProfile,
        membership::EnrollmentRecord,
        operation::DeviceSigningKey,
        payload::PayloadBody,
    };

    use crate::{
        db::{CatalogKey, CatalogLocation},
        model::COLLECTION_POLICY_VAULT_DEFAULT,
        schema, sharing,
    };

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).expect("id")
    }

    fn identity(vault: Id, device: Id, seed: u8) -> (DeviceSigningKey, MembershipState) {
        let key = DeviceSigningKey::from_seed([seed; 32]);
        let enrollment =
            EnrollmentRecord::initial(vault, device, key.verifying_key(), [seed + 1; 32])
                .expect("enrollment")
                .sign(&key);
        (
            key,
            MembershipState::bootstrap(&enrollment).expect("membership"),
        )
    }

    fn open() -> CatalogDb {
        let root: Key = random::secret::<32>().expect("root");
        let vault = random::id().expect("id");
        let key = CatalogKey::derive(&root, &vault).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("open");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        db
    }

    #[test]
    fn cross_vault_operations_and_heads_restore_after_reopen() {
        let mut db = open();
        let (source_key, source_membership) = identity(id(1), id(2), 10);
        let (recipient_key, recipient_membership) = identity(id(3), id(4), 20);
        sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
        let record = CollectionMembershipRecord::new(
            id(1),
            id(5),
            1,
            [0; 32],
            CollectionMembershipAction::Upsert(PermissionProfile::Contribute),
            id(3),
            id(4),
            recipient_key.verifying_key(),
            [21; 32],
            1,
            id(1),
            id(2),
            1,
            1,
        )
        .expect("record")
        .sign(&source_key);
        let collection_membership =
            sharing::accept_membership(&mut db, &record, &source_membership)
                .expect("member")
                .0;
        let collection_key = Key::new([30; 32]);
        let domain = KeyDomain::collection(&collection_key, &id(5), 1).expect("domain");
        let selector = *domain.selector();
        let operation_key = Key::new(*domain.operation_key().expose());
        let mut keys = KeyDirectory::new(&Key::new([31; 32]), &id(1)).expect("keys");
        keys.insert(domain).expect("domain");
        let payload = OperationPayload::new(
            id(5),
            1,
            PayloadBody::CreateAlbum {
                album_id: id(6),
                name: "Shared".to_owned(),
            },
        )
        .expect("payload");
        let source = CollectionOperation::seal(
            id(7),
            id(1),
            id(2),
            1,
            [0; 32],
            Vec::new(),
            selector,
            &operation_key,
            Nonce::new([32; 24]),
            &payload.encode(),
        )
        .expect("source")
        .sign(&source_key);
        let recipient = CollectionOperation::seal(
            id(8),
            id(3),
            id(4),
            1,
            [0; 32],
            vec![CollectionObservedHead::new(id(1), id(2), 1)],
            selector,
            &operation_key,
            Nonce::new([33; 24]),
            &payload.encode(),
        )
        .expect("recipient")
        .sign(&recipient_key);
        let mut log =
            DurableCollectionOperationLog::provision(&mut db, id(5), 1, selector).expect("log");
        assert_eq!(
            log.accept(
                &mut db,
                &source,
                &payload,
                &source_membership,
                &source_membership,
                &collection_membership,
            )
            .expect("source"),
            ApplyOutcome::Applied
        );
        // A failed SQL commit must leave the in-memory log exactly as it was.
        insert_operation_raw_v5(&db, &recipient);
        let refused = log.accept(
            &mut db,
            &recipient,
            &payload,
            &recipient_membership,
            &source_membership,
            &collection_membership,
        );
        assert!(refused.is_err());
        assert_eq!(log.head(&id(3), &id(4)), None);
        db.connection()
            .execute(
                "DELETE FROM sharing_operations WHERE operation_id = ?1",
                params![id(8).as_bytes().as_slice()],
            )
            .expect("clear");
        assert_eq!(
            log.accept(
                &mut db,
                &recipient,
                &payload,
                &recipient_membership,
                &source_membership,
                &collection_membership,
            )
            .expect("recipient"),
            ApplyOutcome::Applied
        );
        let memberships =
            BTreeMap::from([(id(1), source_membership), (id(3), recipient_membership)]);
        let restored = load(
            &db,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &collection_membership,
        )
        .expect("restore");
        assert_eq!(restored.head(&id(1), &id(2)).map(|head| head.0), Some(1));
        assert_eq!(restored.head(&id(3), &id(4)).map(|head| head.0), Some(1));

        db.connection()
            .execute(
                "UPDATE sharing_operations SET digest = ?1 WHERE operation_id = ?2",
                params![[9u8; 32], id(8).as_bytes().as_slice()],
            )
            .expect("tamper");
        assert_eq!(
            load(
                &db,
                id(5),
                1,
                selector,
                &keys,
                &memberships,
                &collection_membership,
            )
            .err()
            .expect("tamper rejected")
            .status(),
            ChurStatus::CatalogCorrupt
        );
    }

    #[test]
    fn cached_authored_log_replays_once_per_session_and_reopens_with_same_records() {
        let directory = std::env::temp_dir().join(format!(
            "chur-log-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("test directory");
        let path = directory.join("catalog.db");
        let root = Key::new([40; 32]);
        let catalog_key = CatalogKey::derive(&root, &id(1)).expect("catalog key");
        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &catalog_key).expect("open");
        schema::open_at_current_version(&mut db, 1).expect("schema");
        let (signing, membership) = identity(id(1), id(2), 10);
        let state = sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
        let domain = KeyDomain::collection(&Key::new([30; 32]), &id(5), 1).expect("domain");
        let selector = *domain.selector();
        let mut keys = KeyDirectory::new(&root, &id(1)).expect("keys");
        keys.insert(domain).expect("domain");
        let memberships = BTreeMap::from([(id(1), membership.clone())]);
        LOG_LOADS.with(|loads| loads.set(0));
        let mut authored = Vec::new();
        for index in 0..2 {
            let payload = OperationPayload::new(
                id(5),
                1,
                PayloadBody::CreateAlbum {
                    album_id: id(6 + index),
                    name: format!("Album {index}"),
                },
            )
            .expect("payload");
            let operation = with_cached_log(
                &mut db,
                id(5),
                1,
                selector,
                &keys,
                &memberships,
                &state,
                |db, log| {
                    log.author(
                        db,
                        id(8 + index),
                        id(1),
                        id(2),
                        keys.domain(&selector)?.operation_key(),
                        Nonce::new([50 + index; 24]),
                        &payload,
                        &signing,
                        &membership,
                        &membership,
                        &state,
                    )
                },
            )
            .expect("author");
            authored.push(operation);
        }
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 1);
        let mut other =
            CatalogDb::open(&CatalogLocation::File(&path), &catalog_key).expect("second writer");
        let external_payload = OperationPayload::new(
            id(5),
            1,
            PayloadBody::CreateAlbum {
                album_id: id(20),
                name: "External".to_owned(),
            },
        )
        .expect("external payload");
        let external = with_cached_log(
            &mut other,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &state,
            |db, log| {
                log.author(
                    db,
                    id(21),
                    id(1),
                    id(2),
                    keys.domain(&selector)?.operation_key(),
                    Nonce::new([53; 24]),
                    &external_payload,
                    &signing,
                    &membership,
                    &membership,
                    &state,
                )
            },
        )
        .expect("external author");
        authored.push(external);
        other.close().expect("close second writer");
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 2);
        with_cached_log(
            &mut db,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &state,
            |_, log| {
                assert_eq!(log.head(&id(1), &id(2)).map(|head| head.0), Some(3));
                Ok(())
            },
        )
        .expect("other writer invalidates cache");
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 3);
        let stale = take_cached_log(&mut db, id(5), 1, selector, &keys, &memberships, &state)
            .expect("take before another writer");
        let mut other = CatalogDb::open(&CatalogLocation::File(&path), &catalog_key)
            .expect("interleaved writer");
        let interleaved_payload = OperationPayload::new(
            id(5),
            1,
            PayloadBody::CreateAlbum {
                album_id: id(22),
                name: "Interleaved".to_owned(),
            },
        )
        .expect("interleaved payload");
        let interleaved = with_cached_log(
            &mut other,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &state,
            |db, log| {
                log.author(
                    db,
                    id(23),
                    id(1),
                    id(2),
                    keys.domain(&selector)?.operation_key(),
                    Nonce::new([54; 24]),
                    &interleaved_payload,
                    &signing,
                    &membership,
                    &membership,
                    &state,
                )
            },
        )
        .expect("interleaved author");
        authored.push(interleaved);
        other.close().expect("close interleaved writer");
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 4);
        store_cached_log(&mut db, selector, stale).expect("store stale log");
        assert!(db.sharing_log_cache.is_none());
        with_cached_log(
            &mut db,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &state,
            |_, log| {
                assert_eq!(log.head(&id(1), &id(2)).map(|head| head.0), Some(4));
                Ok(())
            },
        )
        .expect("stale cache was discarded");
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 5);
        db.close().expect("close");

        let mut db = CatalogDb::open(&CatalogLocation::File(&path), &catalog_key).expect("reopen");
        schema::open_at_current_version(&mut db, 2).expect("schema after reopen");
        with_cached_log(
            &mut db,
            id(5),
            1,
            selector,
            &keys,
            &memberships,
            &state,
            |db, log| {
                assert_eq!(log.head(&id(1), &id(2)).map(|head| head.0), Some(4));
                let payload = OperationPayload::new(
                    id(5),
                    1,
                    PayloadBody::CreateAlbum {
                        album_id: id(6),
                        name: "Album 0".to_owned(),
                    },
                )?;
                assert_eq!(
                    log.accept(db, &authored[0], &payload, &membership, &membership, &state,)?,
                    ApplyOutcome::Duplicate
                );
                Ok(())
            },
        )
        .expect("idempotent replay");
        assert_eq!(LOG_LOADS.with(std::cell::Cell::get), 6);
        let durable = records(&db, &selector).expect("durable records");
        assert_eq!(
            durable
                .iter()
                .map(CollectionOperation::encode)
                .collect::<Vec<_>>(),
            authored
                .iter()
                .map(CollectionOperation::encode)
                .collect::<Vec<_>>()
        );
        db.close().expect("close after reopen");
        std::fs::remove_dir_all(directory).expect("remove test catalog");
    }

    #[test]
    fn v5_object_index_backfill_checks_stored_rows_and_is_atomic() {
        let mut db = open();
        schema::reset_to_v3(&mut db).expect("v3");
        schema::migrate_v3_to_v4(&mut db).expect("v4");
        schema::migrate_v4_to_v5(&mut db).expect("v5");
        let (signing, _) = identity(id(1), id(2), 10);
        sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
        let root = Key::new([31; 32]);
        let domain = KeyDomain::collection(&Key::new([30; 32]), &id(5), 1).expect("domain");
        let selector = *domain.selector();
        let create_payload = OperationPayload::new(
            id(5),
            1,
            PayloadBody::CreateObject {
                object_id: id(6),
                object_generation: 1,
                store_id: id(8),
                stream_id: id(9),
                metadata_fields: Vec::new(),
            },
        )
        .expect("create payload");
        let create = CollectionOperation::seal(
            id(10),
            id(1),
            id(2),
            1,
            [0; 32],
            Vec::new(),
            selector,
            domain.operation_key(),
            Nonce::new([31; 24]),
            &create_payload.encode(),
        )
        .expect("create")
        .sign(&signing);
        let payload = OperationPayload::new(
            id(5),
            1,
            PayloadBody::DeleteObject {
                object_id: id(6),
                object_generation: 1,
                authored_at_ms: 1,
            },
        )
        .expect("payload");
        let operation = CollectionOperation::seal(
            id(7),
            id(1),
            id(2),
            2,
            create.digest(),
            Vec::new(),
            selector,
            domain.operation_key(),
            Nonce::new([32; 24]),
            &payload.encode(),
        )
        .expect("operation")
        .sign(&signing);
        let mut keys = KeyDirectory::new(&root, &id(1)).expect("keys");
        keys.insert(domain).expect("domain");
        db.connection()
            .execute(
                "INSERT INTO sharing_operation_streams VALUES (?1, ?2, 1)",
                params![selector.as_bytes().as_slice(), id(5).as_bytes().as_slice()],
            )
            .expect("v5 stream");
        // v5 had already accepted these signed rows; backfill rechecks the
        // stored projection and decrypted content, not unavailable issuer evidence.
        insert_operation_raw_v5(&db, &create);
        insert_operation_raw_v5(&db, &operation);
        schema::migrate_v5_to_v6(&mut db).expect("v6");

        db.connection()
            .execute(
                "UPDATE sharing_operations SET digest = ?1 WHERE operation_id = ?2",
                params![[9u8; 32], id(7).as_bytes().as_slice()],
            )
            .expect("tamper projection");
        assert_eq!(
            ensure_object_index(&mut db, &selector, &keys)
                .expect_err("tamper rejected")
                .status(),
            ChurStatus::CatalogCorrupt
        );
        let indexed: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sharing_object_operations",
                [],
                |row| row.get(0),
            )
            .expect("index count");
        assert_eq!(indexed, 0);
        db.connection()
            .execute(
                "UPDATE sharing_operations SET digest = ?1 WHERE operation_id = ?2",
                params![operation.digest().as_slice(), id(7).as_bytes().as_slice()],
            )
            .expect("restore projection");
        db.connection()
            .execute(
                "DELETE FROM sharing_operations WHERE operation_id = ?1",
                [create.operation_id().as_bytes().as_slice()],
            )
            .expect("remove cause");
        assert_eq!(
            ensure_object_index(&mut db, &selector, &keys)
                .expect_err("legacy lifecycle without cause rejected")
                .status(),
            ChurStatus::CatalogCorrupt
        );
        insert_operation_raw_v5(&db, &create);
        ensure_object_index(&mut db, &selector, &keys).expect("backfill");
        ensure_object_index(&mut db, &selector, &keys).expect("repeat backfill");
        let mut found = Vec::new();
        visit_object_records(&db, &keys, &selector, &id(6), |record, opened| {
            if record.operation_id() == create.operation_id() {
                assert_eq!(record.encode(), create.encode());
                assert!(opened.body() == create_payload.body());
            } else {
                assert_eq!(record.encode(), operation.encode());
                assert!(opened.body() == payload.body());
            }
            found.push(record);
            Ok(())
        })
        .expect("target records");
        assert_eq!(found.len(), 2);
        assert_eq!(
            dirty_object_ids(&db, &selector, 64).expect("dirty"),
            vec![(id(6), 2)]
        );
        assert!(mark_object_clean(&mut db, &selector, &id(6), 2).expect("clean"));
        assert!(
            dirty_object_ids(&db, &selector, 64)
                .expect("clean queue")
                .is_empty()
        );
    }

    fn insert_operation_raw_v5(db: &CatalogDb, operation: &CollectionOperation) {
        db.connection()
            .execute(
                "INSERT INTO sharing_operations VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    operation.key_selector().as_bytes().as_slice(),
                    operation.issuer_identity_vault_id().as_bytes().as_slice(),
                    operation.issuer_device_id().as_bytes().as_slice(),
                    operation.device_sequence() as i64,
                    operation.operation_id().as_bytes().as_slice(),
                    operation.digest().as_slice(),
                    operation.encode(),
                ],
            )
            .expect("v5 accepted row");
    }

    #[test]
    fn accepted_delete_hides_only_a_recipient_shared_object_in_its_transaction() {
        for (policy, expected) in [
            (COLLECTION_POLICY_SHARED, ObjectState::SharedDeleted),
            (COLLECTION_POLICY_VAULT_DEFAULT, ObjectState::Active),
        ] {
            let mut db = open();
            let (signing, membership) = identity(id(1), id(2), 10);
            let state = sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
            db.connection()
                .execute(
                    "INSERT INTO collections VALUES (?1, 1, ?2, 1, 1)",
                    params![id(5).as_bytes().as_slice(), i64::from(policy)],
                )
                .expect("collection");
            db.connection()
                .execute(
                    "INSERT INTO objects VALUES (
                        ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 4, 0, 1, 1
                    )",
                    params![
                        id(6).as_bytes().as_slice(),
                        id(5).as_bytes().as_slice(),
                        id(7).as_bytes().as_slice(),
                    ],
                )
                .expect("object");
            let domain = KeyDomain::collection(&Key::new([30; 32]), &id(5), 1).expect("domain");
            let create_payload = OperationPayload::new(
                id(5),
                1,
                PayloadBody::CreateObject {
                    object_id: id(6),
                    object_generation: 1,
                    store_id: id(7),
                    stream_id: id(7),
                    metadata_fields: Vec::new(),
                },
            )
            .expect("create payload");
            let create = CollectionOperation::seal(
                id(8),
                id(1),
                id(2),
                1,
                [0; 32],
                Vec::new(),
                *domain.selector(),
                domain.operation_key(),
                Nonce::new([30; 24]),
                &create_payload.encode(),
            )
            .expect("create")
            .sign(&signing);
            let payload = OperationPayload::new(
                id(5),
                1,
                PayloadBody::DeleteObject {
                    object_id: id(6),
                    object_generation: 1,
                    authored_at_ms: 1,
                },
            )
            .expect("payload");
            let operation = CollectionOperation::seal(
                id(9),
                id(1),
                id(2),
                2,
                create.digest(),
                Vec::new(),
                *domain.selector(),
                domain.operation_key(),
                Nonce::new([31; 24]),
                &payload.encode(),
            )
            .expect("operation")
            .sign(&signing);
            let mut keys = KeyDirectory::new(&Key::new([32; 32]), &id(1)).expect("keys");
            let selector = *domain.selector();
            keys.insert(domain).expect("domain");
            let mut log =
                DurableCollectionOperationLog::provision(&mut db, id(5), 1, selector).expect("log");
            assert_eq!(
                log.accept(
                    &mut db,
                    &create,
                    &create_payload,
                    &membership,
                    &membership,
                    &state
                )
                .expect("create accepted"),
                ApplyOutcome::Applied
            );
            let pending_payload = OperationPayload::new(
                id(5),
                1,
                PayloadBody::DeleteObject {
                    object_id: id(6),
                    object_generation: 2,
                    authored_at_ms: 1,
                },
            )
            .expect("pending payload");
            let pending = CollectionOperation::seal(
                id(10),
                id(1),
                id(2),
                2,
                create.digest(),
                Vec::new(),
                selector,
                keys.domain(&selector).expect("domain").operation_key(),
                Nonce::new([33; 24]),
                &pending_payload.encode(),
            )
            .expect("pending delete")
            .sign(&signing);
            assert_eq!(
                log.accept_with_keys(
                    &mut db,
                    &keys,
                    &pending,
                    &pending_payload,
                    &membership,
                    &membership,
                    &state
                )
                .expect("missing generation stays pending"),
                Accepted::Outcome(ApplyOutcome::PendingCause)
            );
            let state_before: i64 = db
                .connection()
                .query_row(
                    "SELECT state FROM objects WHERE object_id = ?1",
                    [id(6).as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("state before valid delete");
            assert_eq!(state_before, i64::from(ObjectState::Active.value()));
            assert_eq!(
                log.accept_with_keys(
                    &mut db,
                    &keys,
                    &operation,
                    &payload,
                    &membership,
                    &membership,
                    &state
                )
                .expect("accepted"),
                Accepted::Outcome(ApplyOutcome::Applied)
            );
            let row: (i64, i64) = db
                .connection()
                .query_row(
                    "SELECT state, integrity_summary FROM objects WHERE object_id = ?1",
                    [id(6).as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("object after accepted delete");
            assert_eq!(row.0, i64::from(expected.value()));
            assert_eq!(
                row.1,
                i64::from(if policy == COLLECTION_POLICY_SHARED {
                    IntegritySummary::Unverified.value()
                } else {
                    IntegritySummary::CompleteVerified.value()
                })
            );
        }
    }

    #[test]
    fn a_member_cannot_author_source_only_or_unpermitted_records_whatever_the_order() {
        let create = PayloadBody::CreateObject {
            object_id: id(6),
            object_generation: 1,
            store_id: id(7),
            stream_id: id(7),
            metadata_fields: Vec::new(),
        };
        let commit = |container: u8| PayloadBody::CommitObject {
            object_id: id(6),
            object_generation: 1,
            store_id: id(7),
            container_length: 1,
            container_commitment: [container; 32],
            object_key_commitment: [container; 32],
        };
        // A Contribute member may not sign the source-only kinds, nor may a READ member sign any.
        let forged_cases = [
            (PermissionProfile::Contribute, create.clone()),
            (PermissionProfile::Contribute, commit(9)),
            (
                PermissionProfile::Contribute,
                PayloadBody::PurgeObject {
                    object_id: id(6),
                    object_generation: 1,
                    authored_at_ms: 1,
                },
            ),
            (
                PermissionProfile::Contribute,
                PayloadBody::RewrapObjectKey {
                    object_id: id(6),
                    object_key_commitment: [2; 32],
                },
            ),
            (
                PermissionProfile::Read,
                PayloadBody::SetFavorite {
                    object_id: id(6),
                    favorite: true,
                    removed_tokens: Vec::new(),
                },
            ),
        ];
        for member_first in [true, false] {
            for (profile, forged_body) in &forged_cases {
                let mut db = open();
                let (source_key, source_membership) = identity(id(1), id(2), 10);
                let (member_key, member_membership) = identity(id(3), id(4), 20);
                sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
                let grant = CollectionMembershipRecord::new(
                    id(1),
                    id(5),
                    1,
                    [0; 32],
                    CollectionMembershipAction::Upsert(*profile),
                    id(3),
                    id(4),
                    member_key.verifying_key(),
                    [21; 32],
                    1,
                    id(1),
                    id(2),
                    1,
                    1,
                )
                .expect("grant")
                .sign(&source_key);
                let state = sharing::accept_membership(&mut db, &grant, &source_membership)
                    .expect("member")
                    .0;
                let domain = KeyDomain::collection(&Key::new([30; 32]), &id(5), 1).expect("domain");
                let selector = *domain.selector();
                let seal = |op: u8, vault: Id, device: Id, prior: [u8; 32], body: &PayloadBody| {
                    let payload = OperationPayload::new(id(5), 1, body.clone()).expect("payload");
                    let record = CollectionOperation::seal(
                        id(op),
                        vault,
                        device,
                        if prior == [0; 32] { 1 } else { 2 },
                        prior,
                        Vec::new(),
                        selector,
                        domain.operation_key(),
                        Nonce::new([op; 24]),
                        &payload.encode(),
                    )
                    .expect("operation");
                    let signed = if vault == id(1) {
                        record.sign(&source_key)
                    } else {
                        record.sign(&member_key)
                    };
                    (signed, payload)
                };
                let source_create = seal(8, id(1), id(2), [0; 32], &create);
                let source_commit = seal(9, id(1), id(2), source_create.0.digest(), &commit(2));
                // The member signs a rival creation or commit of the source's object.
                let forged = seal(10, id(3), id(4), [0; 32], forged_body);
                let mut keys = KeyDirectory::new(&Key::new([32; 32]), &id(1)).expect("keys");
                keys.insert(domain).expect("domain");
                let mut log = DurableCollectionOperationLog::provision(&mut db, id(5), 1, selector)
                    .expect("log");
                let page = if member_first {
                    [&forged, &source_create, &source_commit]
                } else {
                    [&source_create, &source_commit, &forged]
                };
                let verdicts = page
                    .iter()
                    .map(|(record, payload)| {
                        let issuer = if record.issuer_identity_vault_id() == &id(1) {
                            &source_membership
                        } else {
                            &member_membership
                        };
                        log.accept_with_keys(
                            &mut db,
                            &keys,
                            record,
                            payload,
                            issuer,
                            &source_membership,
                            &state,
                        )
                        .expect("accepted")
                    })
                    .collect::<Vec<_>>();
                let applied = Accepted::Outcome(ApplyOutcome::Applied);
                let expected = if member_first {
                    [
                        Accepted::Rejected,
                        applied,
                        Accepted::Outcome(ApplyOutcome::Applied),
                    ]
                } else {
                    [
                        applied,
                        Accepted::Outcome(ApplyOutcome::Applied),
                        Accepted::Rejected,
                    ]
                };
                assert_eq!(verdicts, expected);
                // The rejected record is not stored, and the source's commit is the one planned.
                let rows: Vec<Vec<u8>> = db
                    .connection()
                    .prepare("SELECT operation_id FROM sharing_operations ORDER BY device_sequence")
                    .expect("prepare")
                    .query_map([], |row| row.get(0))
                    .expect("rows")
                    .collect::<std::result::Result<_, _>>()
                    .expect("ids");
                assert_eq!(
                    rows,
                    vec![id(8).as_bytes().to_vec(), id(9).as_bytes().to_vec()]
                );
                let planned =
                    crate::sharing_receive::pending_objects(&mut db, &keys, &state, &selector)
                        .expect("planned");
                assert_eq!(planned.len(), 1);
                assert_eq!(planned[0].container_commitment, [2; 32]);
            }
        }
    }

    #[test]
    fn a_member_fork_is_recorded_and_skipped_but_a_source_fork_fails_the_page() {
        let mut db = open();
        let (source_key, source_membership) = identity(id(1), id(2), 10);
        let (member_key, member_membership) = identity(id(3), id(4), 20);
        sharing::provision(&mut db, id(1), id(5), 1).expect("sharing");
        let grant = CollectionMembershipRecord::new(
            id(1),
            id(5),
            1,
            [0; 32],
            CollectionMembershipAction::Upsert(PermissionProfile::Contribute),
            id(3),
            id(4),
            member_key.verifying_key(),
            [21; 32],
            1,
            id(1),
            id(2),
            1,
            1,
        )
        .expect("grant")
        .sign(&source_key);
        let state = sharing::accept_membership(&mut db, &grant, &source_membership)
            .expect("member")
            .0;
        let domain = KeyDomain::collection(&Key::new([30; 32]), &id(5), 1).expect("domain");
        let selector = *domain.selector();
        let seal = |op: u8, vault: Id, device: Id, sequence: u64, prior: [u8; 32], object: u8| {
            let payload = OperationPayload::new(
                id(5),
                1,
                PayloadBody::SetFavorite {
                    object_id: id(object),
                    favorite: true,
                    removed_tokens: Vec::new(),
                },
            )
            .expect("payload");
            let record = CollectionOperation::seal(
                id(op),
                vault,
                device,
                sequence,
                prior,
                Vec::new(),
                selector,
                domain.operation_key(),
                Nonce::new([op; 24]),
                &payload.encode(),
            )
            .expect("operation");
            let signed = if vault == id(1) {
                record.sign(&source_key)
            } else {
                record.sign(&member_key)
            };
            (signed, payload)
        };
        let member_first = seal(8, id(3), id(4), 1, [0; 32], 6);
        let member_rival = seal(9, id(3), id(4), 1, [0; 32], 7);
        let member_later = seal(10, id(3), id(4), 2, member_first.0.digest(), 6);
        let source_first = seal(11, id(1), id(2), 1, [0; 32], 6);
        let source_rival = seal(12, id(1), id(2), 1, [0; 32], 7);
        let mut keys = KeyDirectory::new(&Key::new([32; 32]), &id(1)).expect("keys");
        keys.insert(domain).expect("domain");
        let mut log =
            DurableCollectionOperationLog::provision(&mut db, id(5), 1, selector).expect("log");
        let mut accept =
            |db: &mut CatalogDb, (record, payload): &(CollectionOperation, OperationPayload)| {
                let issuer = if record.issuer_identity_vault_id() == &id(1) {
                    &source_membership
                } else {
                    &member_membership
                };
                log.accept_with_keys(
                    db,
                    &keys,
                    record,
                    payload,
                    issuer,
                    &source_membership,
                    &state,
                )
            };
        let forks = |db: &CatalogDb, vault: u8| -> i64 {
            db.connection()
                .query_row(
                    "SELECT count(*) FROM sharing_operation_forks WHERE issuer_identity_vault_id = ?1",
                    [id(vault).as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("fork rows")
        };
        assert_eq!(
            accept(&mut db, &member_first).expect("first"),
            Accepted::Outcome(ApplyOutcome::Applied)
        );
        // The rival freezes the member stream and is skipped once its evidence is durable.
        assert_eq!(
            accept(&mut db, &member_rival).expect("rival"),
            Accepted::Rejected
        );
        assert_eq!(forks(&db, 3), 1);
        // Later records of the frozen stream, also on a later page, are skipped too.
        assert_eq!(
            accept(&mut db, &member_later).expect("later"),
            Accepted::Rejected
        );
        assert_eq!(
            accept(&mut db, &member_first).expect("repeat"),
            Accepted::Rejected
        );
        assert_eq!(forks(&db, 3), 1);
        // The source stream is unaffected by the member fork.
        assert_eq!(
            accept(&mut db, &source_first).expect("source"),
            Accepted::Outcome(ApplyOutcome::Applied)
        );
        // A source device that forks still fails the page, after its evidence is stored.
        assert_eq!(
            accept(&mut db, &source_rival)
                .expect_err("source fork")
                .status(),
            ChurStatus::SyncChainFork
        );
        assert_eq!(forks(&db, 1), 1);
        let rows: Vec<Vec<u8>> = db
            .connection()
            .prepare("SELECT operation_id FROM sharing_operations ORDER BY operation_id")
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("rows")
            .collect::<std::result::Result<_, _>>()
            .expect("ids");
        assert_eq!(
            rows,
            vec![id(8).as_bytes().to_vec(), id(11).as_bytes().to_vec()]
        );
    }
}
