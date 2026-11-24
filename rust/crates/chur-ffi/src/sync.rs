//! Phase 3 locked staging and unlocked validation C ABI.

use chur_catalog::sync_engine::{self, ProcessReport, StagedKind};
use chur_catalog::sync_staging::LockedStaging;
use chur_catalog::{sync_log, sync_membership};
use chur_core::limits::sync as bounds;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_format::codec::Writer;

use crate::api::{Status, borrow_bytes_mut, borrow_large, write_out};
use crate::panic::guard_status_for;
use crate::registry::{self, Entry, Handle, Kind};

/// Caller-owned summary written by [`chur_sync_process`].
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ChurSyncReportV1 {
    /// Records accepted into durable catalog state.
    pub applied: u64,
    /// Exact replays or unchanged checkpoints.
    pub duplicates: u64,
    /// Records retained for missing causal predecessors.
    pub pending: u64,
    /// Invalid records rejected after unlocked validation.
    pub rejected: u64,
    /// First stable rejection status, or zero. A fork or rollback verdict
    /// replaces an earlier status of another kind.
    pub first_rejection: i32,
    /// Reserved and zero in ABI 1.4.
    pub reserved: [u8; 4],
}

/// Writes authenticated active device heads from the unlocked catalog.
///
/// The record is version:u16, count:u32, then count*(device_id:16, sequence:u64).
/// All integers are big-endian. A known device with no accepted operation has sequence zero.
///
/// # Safety
///
/// `destination` covers `capacity` writable bytes and `bytes_written` is writable and aligned.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "the sync head C ABI uses caller-owned output pointers"
)]
pub unsafe extern "C" fn chur_sync_heads(
    session: Handle,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, 0usize)? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let db = session.catalog()?;
            let membership = sync_membership::load(db)?.ok_or_else(|| {
                Error::new(
                    ChurStatus::InvalidInput,
                    "sync is not provisioned for this vault",
                )
            })?;
            let log = sync_log::load(db, &membership)?;
            let devices: Vec<_> = membership.active_device_ids().collect();
            ensure!(
                devices.len() <= bounds::CHECKPOINT_HEADS_MAX,
                ResourceLimitExceeded,
                "the accepted device list exceeds the sync bound"
            );
            let mut writer = Writer::new();
            writer.u16(1).u32(devices.len() as u32);
            for device in devices {
                writer
                    .id(device)
                    .u64(log.head(device).map_or(0, |(sequence, _)| sequence));
            }
            writer.finish()
        };
        // SAFETY: the caller guarantees the writable destination range above.
        let output = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= output.len(),
            ResourceLimitExceeded,
            "the destination is smaller than the accepted sync heads"
        );
        output[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Stages one opaque operation or checkpoint while its vault may be locked.
///
/// # Safety
///
/// `vault_id` points to 16 readable bytes. `record` points to `record_length`
/// readable bytes for this call, or is null when that length is zero.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.8 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sync_stage(
    runtime: Handle,
    vault_id: *const u8,
    kind: u8,
    staged_at_ms: u64,
    record: *const u8,
    record_length: u32,
) -> Status {
    guard_status_for(runtime, || {
        let entry = registry::get(runtime, Kind::Runtime)?;
        let Entry::Runtime(guarded) = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        // SAFETY: the caller guarantees both readable ranges above for this call.
        let vault_id = Id::from_slice(unsafe { fixed_id(vault_id)? })?;
        ensure!(
            u64::from(record_length) <= bounds::RESPONSE_BYTES_MAX as u64,
            ResourceLimitExceeded,
            "the staged record exceeds the sync response bound"
        );
        // SAFETY: the caller guarantees this readable range for the call.
        let record = unsafe { borrow_large(record, record_length)? };
        if kind == 3 {
            let records = operation_page(record)?;
            let guard = registry::lock(guarded);
            return sync_engine::stage_inbound_records(
                guard.root(),
                vault_id,
                StagedKind::Operation,
                staged_at_ms,
                records,
            );
        }
        let kind = match kind {
            1 => StagedKind::Operation,
            2 => StagedKind::Checkpoint,
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "the staged record kind is not allocated",
                ));
            }
        };
        let guard = registry::lock(guarded);
        sync_engine::stage_inbound(guard.root(), vault_id, kind, staged_at_ms, record)
    })
}

fn operation_page(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        let (length, rest) = bytes.split_first_chunk::<4>().ok_or_else(|| {
            Error::new(
                ChurStatus::InvalidInput,
                "the sync page length is truncated",
            )
        })?;
        let (record, rest) = rest
            .split_at_checked(u32::from_be_bytes(*length) as usize)
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::InvalidInput,
                    "the sync page record is truncated",
                )
            })?;
        ensure!(
            !record.is_empty() && records.len() < 256,
            InvalidInput,
            "the sync page has an empty record or too many records"
        );
        records.push(record);
        bytes = rest;
    }
    ensure!(!records.is_empty(), InvalidInput, "the sync page is empty");
    Ok(records)
}

/// Validates and applies the current vault's locked inbox after unlock.
///
/// # Safety
///
/// `out_report` points to one writable, aligned [`ChurSyncReportV1`].
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.8 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sync_process(
    session: Handle,
    now_ms: u64,
    out_report: *mut ChurSyncReportV1,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(out_report, ffi_report(&ProcessReport::default()))? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let vault_id = session.vault_id();
        let root_dir = session.root_dir().clone();
        let root = session.root_secret()?.duplicate();
        let mut staging = LockedStaging::open(root_dir.sync_inbox(&vault_id))?;
        let report =
            sync_engine::process_staged(session.catalog()?, &root, vault_id, &mut staging, now_ms)?;
        crate::product::finish_pending_deletions(&mut session, now_ms)?;
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(out_report, ffi_report(&report)) }
    })
}

/// Counts the chains the open vault holds a fork for, by state, §6.24.
///
/// `ROLLBACK_PROTECTION.md` §4 persists the fork state until it clears, and
/// the pass that found the fork reports it once, so this is how a host that
/// restarted still tells the user.
///
/// # Safety
///
/// `out_detected` and `out_acknowledged` each point to one writable, aligned
/// `uint64_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.24 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sync_fork_state(
    session: Handle,
    out_detected: *mut u64,
    out_acknowledged: *mut u64,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees both writable out-parameters above.
        unsafe {
            write_out(out_detected, 0)?;
            write_out(out_acknowledged, 0)?;
        }
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let counts = sync_log::fork_counts(registry::lock(session).catalog()?)?;
        // SAFETY: the caller guarantees both writable out-parameters above.
        unsafe {
            write_out(out_detected, counts.detected)?;
            write_out(out_acknowledged, counts.acknowledged)
        }
    })
}

/// Marks every detected fork as seen, §6.24. Every chain stays frozen.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.24 fixes this exported symbol"
)]
pub extern "C" fn chur_sync_fork_acknowledge(session: Handle) -> Status {
    guard_status_for(session, || {
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        sync_log::acknowledge_forks(session.catalog()?)
    })
}

fn ffi_report(report: &ProcessReport) -> ChurSyncReportV1 {
    ChurSyncReportV1 {
        applied: report.applied as u64,
        duplicates: report.duplicates as u64,
        pending: report.pending as u64,
        rejected: report.rejected as u64,
        first_rejection: report.first_rejection.map_or(0, ChurStatus::as_i32),
        reserved: [0; 4],
    }
}

#[expect(
    unsafe_code,
    reason = "the caller's fixed identifier pointer contract is stated above"
)]
unsafe fn fixed_id<'a>(pointer: *const u8) -> Result<&'a [u8]> {
    if pointer.is_null() {
        return Err(Error::new(
            ChurStatus::InvalidInput,
            "the vault identifier pointer is null",
        ));
    }
    // SAFETY: the caller guarantees 16 initialized bytes for this call.
    Ok(unsafe { core::slice::from_raw_parts(pointer, 16) })
}
