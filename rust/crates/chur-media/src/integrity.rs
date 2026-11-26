//! Integrity scanning.
//!
//! `docs/format/CATALOG_SCHEMA_V1.md` §13 requires stable codes rather than
//! secret error strings, and §5.1 fixes the vocabulary: an integrity scan
//! produces an `integrity_summary`, and proven corruption is a lifecycle change
//! rather than a verdict.

use chur_catalog::store;
use chur_catalog::vault::Session;
use chur_core::{ChurStatus, Id, Result};
use chur_format::constants::{IntegritySummary, ObjectState, StreamKind};

use crate::progress::Progress;
use crate::reader;
use crate::store::container_exists;

/// The outcome of scanning one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOutcome {
    /// The object scanned.
    pub object_id: Id,
    /// The lifecycle state the scan left the object in.
    pub state: ObjectState,
    /// The verdict, meaningful only while the state is `ACTIVE`.
    pub integrity_summary: IntegritySummary,
}

/// Scans one object's original stream and records the verdict.
///
/// The three outcomes are distinct and none of them is a guess:
///
/// - the container is absent, so the object is `QUARANTINED`. §5.1 keeps that
///   an integrity value rather than a lifecycle change, because an absent
///   container is a fact about this device and not a verdict on the object;
/// - the container is present and every record authenticates, so the object is
///   `COMPLETE_VERIFIED`;
/// - a cryptographic or structural check failed, which proves the object
///   unusable, so `state` becomes `CORRUPT` and no summary is recorded.
pub fn scan_object(session: &mut Session, object_id: &Id, now_ms: u64) -> Result<ScanOutcome> {
    scan_object_with(
        session,
        object_id,
        now_ms,
        &mut crate::progress::Uninterrupted,
    )
}

/// Scans one object, stopping when `progress` reports cancellation.
///
/// Verifying one multi-gigabyte object runs for minutes, so a scan that checked
/// the flag only between objects would ignore a cancellation for the whole of
/// the object it is on. A cancelled scan leaves the row at `UNVERIFIED` rather
/// than `VERIFYING`: nothing is running any more, and no verdict was reached.
pub fn scan_object_with(
    session: &mut Session,
    object_id: &Id,
    now_ms: u64,
    progress: &mut impl Progress,
) -> Result<ScanOutcome> {
    let object = store::object(session.catalog_ref()?, object_id)?;
    if object.state == ObjectState::Corrupt {
        return Ok(ScanOutcome {
            object_id: *object_id,
            state: object.state,
            integrity_summary: object.integrity_summary,
        });
    }
    let streams = store::streams(session.catalog_ref()?, object_id)?;
    let Some(original) = streams
        .iter()
        .find(|stream| stream.stream_kind == StreamKind::Original)
    else {
        store::mark_corrupt(session.catalog()?, object_id)?;
        return Ok(ScanOutcome {
            object_id: *object_id,
            state: ObjectState::Corrupt,
            integrity_summary: IntegritySummary::Unverified,
        });
    };

    let store_id = session.object_store_id();
    if !container_exists(session.root_dir(), &store_id, &original.container_path_id) {
        store::set_integrity_summary(
            session.catalog()?,
            object_id,
            IntegritySummary::Quarantined,
            now_ms,
        )?;
        return Ok(ScanOutcome {
            object_id: *object_id,
            state: ObjectState::Active,
            integrity_summary: IntegritySummary::Quarantined,
        });
    }

    store::set_integrity_summary(
        session.catalog()?,
        object_id,
        IntegritySummary::Verifying,
        now_ms,
    )?;

    let verdict = (|| -> Result<IntegritySummary> {
        let mut handle = reader::open(session, object_id, StreamKind::Original)?;
        handle.verify_complete_with(&|| progress.cancelled())
    })();

    match verdict {
        Ok(summary) => {
            store::set_integrity_summary(session.catalog()?, object_id, summary, now_ms)?;
            Ok(ScanOutcome {
                object_id: *object_id,
                state: ObjectState::Active,
                integrity_summary: summary,
            })
        }
        Err(error) if proves_corruption(error.status()) => {
            store::mark_corrupt(session.catalog()?, object_id)?;
            Ok(ScanOutcome {
                object_id: *object_id,
                state: ObjectState::Corrupt,
                integrity_summary: IntegritySummary::Unverified,
            })
        }
        Err(error) if error.status() == ChurStatus::ObjectIncomplete => {
            store::set_integrity_summary(
                session.catalog()?,
                object_id,
                IntegritySummary::Incomplete,
                now_ms,
            )?;
            Ok(ScanOutcome {
                object_id: *object_id,
                state: ObjectState::Active,
                integrity_summary: IntegritySummary::Incomplete,
            })
        }
        Err(error) if is_unsupported(error.status()) => {
            store::set_integrity_summary(
                session.catalog()?,
                object_id,
                IntegritySummary::Unsupported,
                now_ms,
            )?;
            Ok(ScanOutcome {
                object_id: *object_id,
                state: ObjectState::Active,
                integrity_summary: IntegritySummary::Unsupported,
            })
        }
        Err(error) => {
            // A read failure is not a verdict, and neither is a cancellation:
            // the storage layer failed or the caller stopped, and leaving the
            // object VERIFYING would claim a scan is still running.
            store::set_integrity_summary(
                session.catalog()?,
                object_id,
                IntegritySummary::Unverified,
                now_ms,
            )?;
            Err(error)
        }
    }
}

/// Whether a status proves the object unusable rather than merely unread.
///
/// `OBJECT_CORRUPT` is the only status a v1 reader produces that means a
/// cryptographic or structural check failed on bytes it actually read.
const fn proves_corruption(status: ChurStatus) -> bool {
    matches!(status, ChurStatus::ObjectCorrupt)
}

/// Whether a status means the build cannot read the container's version.
const fn is_unsupported(status: ChurStatus) -> bool {
    matches!(
        status,
        ChurStatus::UnsupportedVersion | ChurStatus::UnsupportedSuite
    )
}
