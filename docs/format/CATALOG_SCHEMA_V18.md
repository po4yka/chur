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
- The first check in a new session with an existing mark starts a monotonic reference and returns the mark.
- Later checks advance the mark by the monotonic time since it last moved.
- One advance is at most one day (86,400,000 ms). Elapsed time that one advance did not use stays available in the same session.
- An advance below one minute does not write a new mark. This avoids a durable commit for each page query.
- The mark never decreases. The write is `ON CONFLICT DO UPDATE ... WHERE excluded.trusted_ms > trusted_time.trusted_ms`.

A trash entry and a trashed note store `expires_ms = trusted time + 30 days`. Chur erases them when the mark reaches that deadline. A system clock change after initialization cannot advance the mark, even across repeated unlocks. Time outside an open session does not count. The retention period can therefore exceed 30 calendar days. The user can still explicitly delete a trash item.

Display times, import times, `updated_ms` of pins and edits, and sync timestamps continue to use the device clock.

The trusted time is local state. It does not enter sync records. A vault backup and a portable catalog export include the table. A restore keeps the restored mark, which is older than the mark of the device that made the backup only by the time since the backup.

## Migration

The authenticated v17→v18 transition uses the descriptor `MIGRATING` state. One SQLCipher transaction creates the table and records version 18. A failed transaction retains both the v17 version and schema. A process interruption on either side of the SQL commit resumes that step before unlock returns. Restore runs each earlier migration in order and then this step. New catalogs install v18 directly. Readers that support only v17 reject the authenticated descriptor as `UNSUPPORTED_VERSION`; there is no downgrade exception. Retain an encrypted backup until the upgrade is accepted.

Trash entries that v17 wrote keep their deadlines, which came from the device clock. They expire when the trusted time reaches them.
