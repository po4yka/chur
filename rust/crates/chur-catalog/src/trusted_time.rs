//! The trusted time that trash and private-note retention are judged against.
//!
//! The device clock can jump: a manual change, a dead RTC battery, a bad NTP
//! result. Permanent erasure must not follow such a jump, so every retention
//! deadline and every expiry check uses this clock instead. It is a high-water
//! mark in the catalog that moves forward only by time the process can justify:
//!
//! - within a process, by the monotonic time since the mark last moved;
//! - for the first advance in a process, by the gap to the device clock;
//! - never by more than [`MAX_ADVANCE_MS`] in one advance, and never backwards.
//!
//! The first call on a catalog with no mark takes the device clock. A forward
//! jump therefore delays erasure (late) and can never cause it (early): the
//! mark advances by at most the real time that passed, plus one day per
//! process start. `docs/format/CATALOG_SCHEMA_V18.md` states the contract.

use std::time::{Duration, Instant};

use chur_core::Result;
use rusqlite::{OptionalExtension, params};

use crate::db::{CatalogDb, as_sqlite_integer, map_sqlite};

/// The most one advance moves the mark: one day.
pub const MAX_ADVANCE_MS: u64 = 24 * 60 * 60 * 1000;

/// A smaller advance is not written, so a page query does not cost a durable commit.
const WRITE_GRANULARITY_MS: u64 = 60 * 1000;

/// The trusted time for retention now, advancing and storing the mark as the module rules allow.
///
/// The returned value never decreases for one catalog and trails real time at most.
pub fn now(db: &mut CatalogDb, wall_ms: u64) -> Result<u64> {
    advance(db, wall_ms, Instant::now())
}

pub(crate) fn advance(db: &mut CatalogDb, wall_ms: u64, at: Instant) -> Result<u64> {
    let mark = db
        .connection()
        .query_row(
            "SELECT trusted_ms FROM trusted_time WHERE only_row = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "the trusted time could not be read"))?
        .map(|value| u64::try_from(value).unwrap_or(0));
    let Some(mark) = mark else {
        write(db, wall_ms)?;
        db.trusted_anchor = Some(at);
        return Ok(wall_ms);
    };
    // A first advance has no monotonic proof, so it restarts the reference at this instant.
    let (anchor, advance_ms, proven) = match db.trusted_anchor {
        Some(anchor) => (anchor, millis(at.saturating_duration_since(anchor)), true),
        None => (at, wall_ms.saturating_sub(mark), false),
    };
    let advance_ms = advance_ms.min(MAX_ADVANCE_MS);
    if advance_ms < WRITE_GRANULARITY_MS {
        // The sub-minute remainder of a first call is dropped.
        db.trusted_anchor = Some(anchor);
        return Ok(mark);
    }
    let advanced = mark.saturating_add(advance_ms);
    write(db, advanced)?;
    let spent = if proven { advance_ms } else { 0 };
    db.trusted_anchor = Some(anchor + Duration::from_millis(spent));
    Ok(advanced)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn write(db: &mut CatalogDb, trusted_ms: u64) -> Result<()> {
    let value = as_sqlite_integer(trusted_ms, "the trusted time is out of range")?;
    db.transaction(|tx| {
        tx.execute(
            "INSERT INTO trusted_time (only_row, trusted_ms) VALUES (1, ?1)
             ON CONFLICT (only_row) DO UPDATE SET trusted_ms = excluded.trusted_ms
             WHERE excluded.trusted_ms > trusted_time.trusted_ms",
            params![value],
        )
        .map_err(|error| map_sqlite(error, "the trusted time could not be written"))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::db::{CatalogKey, CatalogLocation};
    use crate::schema::open_at_current_version;
    use chur_crypto::{Key, random};

    const DAY: u64 = MAX_ADVANCE_MS;
    const START: u64 = 1_700_000_000_000;

    fn catalog() -> CatalogDb {
        let root: Key = random::secret::<32>().expect("root");
        let key = CatalogKey::derive(&root, &random::id().expect("id")).expect("key");
        let mut db = CatalogDb::open(&CatalogLocation::Memory, &key).expect("open");
        open_at_current_version(&mut db, 1).expect("schema");
        db
    }

    fn stored(db: &CatalogDb) -> Option<i64> {
        db.connection()
            .query_row("SELECT trusted_ms FROM trusted_time", [], |row| row.get(0))
            .optional()
            .expect("read")
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn the_first_call_takes_the_device_clock_and_stores_it() {
        let mut db = catalog();
        assert_eq!(stored(&db), None);
        assert_eq!(advance(&mut db, START, Instant::now()).unwrap(), START);
        assert_eq!(stored(&db), Some(START as i64));
    }

    #[test]
    fn a_forward_clock_jump_in_a_running_process_moves_nothing() {
        let mut db = catalog();
        let base = Instant::now();
        advance(&mut db, START, base).unwrap();
        assert_eq!(
            advance(&mut db, START + 30 * DAY, at(base, 5_000)).unwrap(),
            START
        );
        assert_eq!(stored(&db), Some(START as i64));
    }

    #[test]
    fn monotonic_time_advances_the_mark_by_exactly_the_elapsed_time() {
        let mut db = catalog();
        let base = Instant::now();
        advance(&mut db, START, base).unwrap();
        // The device clock claims a month; the process measured one hour.
        let hour = 60 * 60 * 1000;
        assert_eq!(
            advance(&mut db, START + 30 * DAY, at(base, hour)).unwrap(),
            START + hour
        );
        assert_eq!(stored(&db), Some((START + hour) as i64));
    }

    #[test]
    fn one_advance_is_capped_at_a_day_and_keeps_the_unspent_elapsed_time() {
        let mut db = catalog();
        let base = Instant::now();
        advance(&mut db, START, base).unwrap();
        let later = at(base, 3 * DAY);
        assert_eq!(advance(&mut db, START, later).unwrap(), START + DAY);
        assert_eq!(advance(&mut db, START, later).unwrap(), START + 2 * DAY);
        assert_eq!(advance(&mut db, START, later).unwrap(), START + 3 * DAY);
        assert_eq!(advance(&mut db, START, later).unwrap(), START + 3 * DAY);
    }

    #[test]
    fn a_new_process_trusts_the_device_clock_by_one_day_at_most() {
        let mut db = catalog();
        advance(&mut db, START, Instant::now()).unwrap();
        db.trusted_anchor = None;
        let base = Instant::now();
        assert_eq!(
            advance(&mut db, START + 30 * DAY, base).unwrap(),
            START + DAY
        );
        // The jump is not remembered: the next call measures its own elapsed time.
        assert_eq!(
            advance(&mut db, START + 30 * DAY, at(base, 5_000)).unwrap(),
            START + DAY
        );
    }

    #[test]
    fn a_clock_set_back_never_moves_the_mark_back() {
        let mut db = catalog();
        advance(&mut db, START, Instant::now()).unwrap();
        db.trusted_anchor = None;
        let base = Instant::now();
        assert_eq!(advance(&mut db, START - 40 * DAY, base).unwrap(), START);
        // The process still measures real time while the device clock is wrong.
        let hour = 60 * 60 * 1000;
        assert_eq!(
            advance(&mut db, START - 40 * DAY, at(base, hour)).unwrap(),
            START + hour
        );
        assert_eq!(stored(&db), Some((START + hour) as i64));
    }

    #[test]
    fn an_advance_under_a_minute_is_not_written_and_is_not_lost() {
        let mut db = catalog();
        let base = Instant::now();
        advance(&mut db, START, base).unwrap();
        assert_eq!(advance(&mut db, START, at(base, 59_000)).unwrap(), START);
        assert_eq!(stored(&db), Some(START as i64));
        assert_eq!(
            advance(&mut db, START, at(base, 61_000)).unwrap(),
            START + 61_000
        );
    }
}
