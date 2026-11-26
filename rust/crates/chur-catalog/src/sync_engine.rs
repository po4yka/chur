//! Locked ciphertext staging and unlocked inbound processing.

use chur_core::limits::sync as bounds;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_crypto::commit;
use chur_sync_protocol::checkpoint::Checkpoint;
use chur_sync_protocol::operation::Operation;
use chur_sync_protocol::operation_log::{ApplyOutcome, CheckpointOutcome};

use crate::paths::VaultRoot;
use crate::sync_staging::LockedStaging;
use crate::{CatalogDb, sync_keys, sync_log, sync_membership, sync_receive};

const STAGED_RECORD_TAG: &[u8] = b"CHUR\0SYNC\0STAGED-RECORD\0V1";

/// An opaque record family known to the transport while keys are unavailable.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum StagedKind {
    /// One signed encrypted operation.
    Operation = 1,
    /// One signed checkpoint.
    Checkpoint = 2,
}

/// Result of one bounded unlocked inbox pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProcessReport {
    /// Records accepted into durable catalog state.
    pub applied: usize,
    /// Exact replays or unchanged checkpoints removed from the inbox.
    pub duplicates: usize,
    /// Records retained until a missing causal predecessor arrives.
    pub pending: usize,
    /// Invalid records removed after full unlocked validation.
    pub rejected: usize,
    /// Stable status of the first rejected record, or of the first fork or
    /// rollback verdict when the pass reached one.
    ///
    /// A verdict replaces an earlier status of another kind. A server can
    /// stage a record with a bad signature ahead of the forked
    /// record and hide the verdict behind its rejection. The engine freezes the
    /// chain and drops the record, so no later pass reports the fork again,
    /// and `ERROR_MODEL.md` "Wire and persistence compatibility" says a server
    /// can neither induce nor suppress it (`ROLLBACK_PROTECTION.md` §4).
    pub first_rejection: Option<ChurStatus>,
}

/// Durably stores an opaque inbound record without opening vault keys.
pub fn stage_inbound(
    root: &VaultRoot,
    vault_id: Id,
    kind: StagedKind,
    staged_at_ms: u64,
    record: &[u8],
) -> Result<()> {
    stage_inbound_records(root, vault_id, kind, staged_at_ms, [record])
}

/// Durably stores a page of one record kind under a single staging claim.
pub fn stage_inbound_records<'a>(
    root: &VaultRoot,
    vault_id: Id,
    kind: StagedKind,
    staged_at_ms: u64,
    records: impl IntoIterator<Item = &'a [u8]>,
) -> Result<()> {
    let mut framed = Vec::new();
    let mut available = bounds::RESPONSE_BYTES_MAX;
    for record in records {
        ensure!(
            framed.len() < bounds::RESPONSE_OPERATIONS_MAX && record.len() <= available,
            ResourceLimitExceeded,
            "staged page exceeds the sync response limit"
        );
        available -= record.len();
        match kind {
            StagedKind::Operation => {
                Operation::decode(record)?;
            }
            StagedKind::Checkpoint => {
                Checkpoint::decode(record)?;
            }
        }
        let mut bytes = Vec::with_capacity(record.len() + 1);
        bytes.push(kind as u8);
        bytes.extend_from_slice(record);
        let digest = commit::commit(STAGED_RECORD_TAG, &[&bytes]);
        framed.push((Id::from_slice(&digest[..16])?, bytes));
    }
    ensure!(!framed.is_empty(), InvalidInput, "staged page is empty");
    LockedStaging::open(root.sync_inbox(&vault_id))?.stage_many(staged_at_ms, framed)
}

/// Checks that the authenticated peer signed a checkpoint whose prefixes have arrived.
/// An accepted checkpoint can also name a future floor. That floor alone cannot
/// confirm that this device has received the peer's history.
pub fn confirm_peer_history(db: &CatalogDb, peer: &Id, bytes: &[u8]) -> Result<()> {
    let checkpoint = Checkpoint::decode(bytes)?;
    let membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "peer membership is absent",
        )
    })?;
    ensure!(
        checkpoint.vault_id() == membership.vault_id()
            && checkpoint.issuer_device_id() == peer
            && membership.is_active(peer),
        AuthenticationFailed,
        "checkpoint does not identify the active peer"
    );
    let issuer = membership.device(peer).ok_or_else(|| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "checkpoint issuer is unknown",
        )
    })?;
    ensure!(
        issuer
            .signing_public_keys()
            .any(|key| checkpoint.verify_signature(key).is_ok()),
        AuthenticationFailed,
        "checkpoint signature did not verify"
    );
    require_checkpoint_prefixes(db, &membership, &checkpoint)
}

pub(crate) fn require_checkpoint_prefixes(
    db: &CatalogDb,
    membership: &chur_sync_protocol::state::MembershipState,
    checkpoint: &Checkpoint,
) -> Result<()> {
    for head in checkpoint.heads() {
        if sync_log::above_revocation_cutoff(membership, head.device_id(), head.device_sequence()) {
            continue;
        }
        let (operation, _) = sync_log::operation_at(db, head.device_id(), head.device_sequence())?
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::RecoveryRequired,
                    "checkpoint history is incomplete",
                )
            })?;
        ensure!(
            operation.digest() == *head.operation_digest(),
            SyncHeadRollback,
            "checkpoint differs from delivered history"
        );
    }
    Ok(())
}

/// Validates and applies retained records after the vault unlocks.
pub fn process_staged(
    db: &mut CatalogDb,
    root: &Key,
    vault_id: Id,
    staging: &mut LockedStaging,
    now_ms: u64,
) -> Result<ProcessReport> {
    let mut membership = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::InvalidInput,
            "sync is not provisioned for this vault",
        )
    })?;
    if membership.vault_id() != &vault_id {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "staged sync vault does not match the unlocked vault",
        ));
    }
    let mut log = sync_log::load(db, &membership)?;
    let mut keys = sync_keys::key_directory(db, root, vault_id)?;
    let mut state = sync_receive::load_materialized_state(db, &keys)?;
    let mut report = ProcessReport::default();

    // A pass that removes nothing can still teach the log something: a held
    // record of a revoked device carries one step of the branch its revocation
    // point pins (`REVOCATION.md` §7), and the record below it becomes
    // admissible only on the pass after that. So one more pass runs after a
    // pass that removed nothing, and the loop ends when that pass removes
    // nothing either.
    let mut settled = false;
    loop {
        let records = staging.records(now_ms)?;
        if records.len() == 0 {
            report.pending = 0;
            break;
        }
        let mut removed = false;
        let mut pending = 0;
        for record in records {
            let record = record?;
            match process_one(
                db,
                root,
                &mut membership,
                &mut log,
                &mut keys,
                &mut state,
                record.staged_at_ms(),
                record.bytes(),
            ) {
                Ok(RecordOutcome::Applied) => {
                    staging.remove(record.id())?;
                    report.applied += 1;
                    removed = true;
                }
                Ok(RecordOutcome::Duplicate) => {
                    staging.remove(record.id())?;
                    report.duplicates += 1;
                    removed = true;
                }
                Ok(RecordOutcome::Pending) => pending += 1,
                Err(error) if is_rejection(error.status()) => {
                    staging.remove(record.id())?;
                    report.rejected += 1;
                    let status = error.status();
                    if report
                        .first_rejection
                        .is_none_or(|first| !is_verdict(first) && is_verdict(status))
                    {
                        report.first_rejection = Some(status);
                    }
                    removed = true;
                }
                Err(error) => return Err(error),
            }
        }
        report.pending = pending;
        if removed {
            settled = false;
        } else if settled {
            break;
        } else {
            settled = true;
        }
    }
    report.pending += state.pending_operations(None);
    Ok(report)
}

enum RecordOutcome {
    Applied,
    Duplicate,
    Pending,
}

#[expect(
    clippy::too_many_arguments,
    reason = "one staged record updates the same durable sync state loaded once by its bounded batch"
)]
fn process_one(
    db: &mut CatalogDb,
    root: &Key,
    membership: &mut chur_sync_protocol::state::MembershipState,
    log: &mut sync_log::DurableOperationLog,
    keys: &mut chur_sync_protocol::KeyDirectory,
    state: &mut chur_sync_protocol::materialization::MaterializedState,
    staged_at_ms: u64,
    framed: &[u8],
) -> Result<RecordOutcome> {
    let (&kind, record) = framed
        .split_first()
        .ok_or_else(|| Error::new(ChurStatus::InvalidInput, "staged sync record is empty"))?;
    match kind {
        value if value == StagedKind::Operation as u8 => {
            match sync_receive::accept_operation(
                db,
                log,
                membership,
                state,
                keys,
                root,
                staged_at_ms,
                record,
            ) {
                Ok(ApplyOutcome::Applied) => Ok(RecordOutcome::Applied),
                Ok(ApplyOutcome::Duplicate) => Ok(RecordOutcome::Duplicate),
                Ok(ApplyOutcome::PendingGap | ApplyOutcome::PendingCause) => {
                    Ok(RecordOutcome::Pending)
                }
                Err(error) if error.status() == ChurStatus::NotFound => Ok(RecordOutcome::Pending),
                Err(error) => Err(error),
            }
        }
        value if value == StagedKind::Checkpoint as u8 => {
            let checkpoint = Checkpoint::decode(record)?;
            match log.accept_checkpoint(db, &checkpoint, membership, false, staged_at_ms)? {
                CheckpointOutcome::Raised => Ok(RecordOutcome::Applied),
                CheckpointOutcome::Unchanged => Ok(RecordOutcome::Duplicate),
            }
        }
        _ => Err(Error::new(
            ChurStatus::InvalidInput,
            "staged sync record kind is invalid",
        )),
    }
}

fn is_verdict(status: ChurStatus) -> bool {
    matches!(
        status,
        ChurStatus::SyncChainFork | ChurStatus::SyncHeadRollback
    )
}

fn is_rejection(status: ChurStatus) -> bool {
    matches!(
        status,
        ChurStatus::AuthenticationFailed
            | ChurStatus::InvalidInput
            | ChurStatus::ResourceLimitExceeded
            | ChurStatus::Conflict
            | ChurStatus::SyncChainFork
            | ChurStatus::SyncHeadRollback
            | ChurStatus::UnsupportedVersion
            | ChurStatus::UnsupportedSuite
            | ChurStatus::NonCanonicalEncoding
            | ChurStatus::ObjectCorrupt
    )
}
