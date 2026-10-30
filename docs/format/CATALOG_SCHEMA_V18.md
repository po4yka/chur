# Catalog schema v18

> **Status:** Accepted

Catalog format `0x0012` adds the trusted-time high-water mark that trash and private-note retention are judged against. The migration does not rewrite originals, encrypted media, keys, metadata, history, trash entries or notes.

`trusted_time` is a strict table in the existing SQLCipher catalog. It holds no row until the first retention check initializes it.

| Column | Contract |
| --- | --- |
| `only_row` | Primary key; the check constraint allows the value 1 only |
| `trusted_ms` | Non-negative Unix time in milliseconds; the SQL upsert never lowers it |

## Rules

The device clock can jump: a manual change, a dead RTC battery, a bad NTP result. A permanent erasure must not follow such a jump. Every retention deadline, every restore check and every expiry check of trash entries and of private notes therefore uses the trusted time, not the device clock. The mark moves only as follows.

- The first check on a catalog with no row stores the device clock and returns it.
- A later check in the same unlock session advances the mark by the monotonic time since the mark last moved. The device clock does not enter this advance, so a forward jump, or a clock set back, changes nothing.
- The first advance in a session has no monotonic reference. It advances the mark by the gap to the device clock, if the clock is ahead. A clock that is behind the mark advances nothing.
- One advance is at most one day (86,400,000 ms). Monotonic time that one advance did not spend stays available to the next advance in the same session.
- An advance below one minute is not written, so a page query does not cost a durable commit. The mark can therefore trail the true time by less than a minute.
- The mark never decreases. The write is `ON CONFLICT DO UPDATE ... WHERE excluded.trusted_ms > trusted_time.trusted_ms`.

A trash entry and a trashed note store `expires_ms = trusted time + 30 days`, and are erased when the trusted time reaches `expires_ms`. The trusted time grows by at most the real time that passed, plus one day for each unlock session. Erasure can therefore be late, and it is never earlier than 30 days after the trash action, except by the one-day advance of a new session. A device clock 30 days ahead erases nothing at once: it lets the mark advance by one day for each unlock session and, within a session, by the real elapsed time. The device clock is still the source of the first mark. A catalog whose first check follows a wrong clock keeps that mark; Chur does not detect it.

The monotonic reference lives in memory only. It does not count time that the device spends asleep, so a long-running session can trail real time, and a restart repairs the gap by at most one day. Trash and note `deleted_ms` values written by these paths are trusted time. Display times, import times, `updated_ms` of pins and edits, and sync timestamps continue to use the device clock.

The trusted time is local state. It does not enter sync records. A vault backup and a portable catalog export include the table. A restore keeps the restored mark, which is older than the mark of the device that made the backup only by the time since the backup.

## Migration

The authenticated v17→v18 transition uses the descriptor `MIGRATING` state. One SQLCipher transaction creates the table and records version 18. A failed transaction retains both the v17 version and schema. A process interruption on either side of the SQL commit resumes that step before unlock returns. Restore runs each earlier migration in order and then this step. New catalogs install v18 directly. Readers that support only v17 reject the authenticated descriptor as `UNSUPPORTED_VERSION`; there is no downgrade exception. Retain an encrypted backup until the upgrade is accepted.

Trash entries that v17 wrote keep their deadlines, which came from the device clock. They expire when the trusted time reaches them.
