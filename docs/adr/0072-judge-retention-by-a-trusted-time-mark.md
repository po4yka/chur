# ADR-0072: Judge Retention by a Trusted-Time Mark

- **Status:** Accepted
- **Date:** 2026-10-30
- **Decision owners:** @po4yka
- **Related:** [`../format/CATALOG_SCHEMA_V18.md`](../format/CATALOG_SCHEMA_V18.md), [`../format/CATALOG_SCHEMA_V8.md`](../format/CATALOG_SCHEMA_V8.md), [`../format/CATALOG_SCHEMA_V1.md`](../format/CATALOG_SCHEMA_V1.md) §8.1 and §14.1, [`0046`](0046-freeze-sync-operation-payloads.md)

## Context

Trash and private-note retention compared each deadline with the device clock. The sweep runs at every unlock and before every catalog query, and it destroys the key envelope and the containers of each expired entry. A clock that jumped 30 days ahead therefore erased every trashed item at once, including an item trashed a minute before. `CATALOG_SCHEMA_V1.md` §8.1 says that a wrong device clock is not detected and that nothing depends on it. Permanent erasure depended on it. [`0046`](0046-freeze-sync-operation-payloads.md) makes the same kind of choice for sync tombstones: a timestamp is a conservative cleanup input and never an authority.

## Decision

1. The catalog keeps one trusted-time high-water mark (catalog v18). Trash deadlines, trash restore checks, note deadlines, note restore checks and the expiry checks of both are judged against it.
2. The mark advances by the monotonic time since it last moved inside an unlock session. The first advance of a session takes the gap to the device clock. One advance is at most one day. The mark never decreases. The first check on a catalog with no mark takes the device clock.
3. A deadline is the trusted time at the trash action plus 30 days. Erasure may be late and is not earlier than the real elapsed time allows.
4. The mark is local catalog state. It is not a sync record, and the sync tombstone rules are unchanged.
5. The sync staging expiry stays on the device clock. It discards only a staged copy of data that the sender can send again.

## Alternatives considered

### A confirmation before a sweep that sees a large jump

Rejected. The sweep runs without a user present, at unlock and at every query.

### Compare against the last observed device-clock time and refuse to move back

Rejected. It stops a clock that is set back, but a clock that jumps forward is then stored as the new truth, and the next sweep erases the data.

### A boot-clock reference stored with the mark

Rejected for now. It needs platform code in the catalog crate for a bound that the one-day advance already gives. The in-memory monotonic reference is enough to make a jump harmless inside a session.

## Consequences

- A forward jump delays erasure and never causes it. A clock set back does not stall retention inside a session.
- A user who restarts the app each day with a clock 30 days ahead sees the mark advance by one day for each start. That is the declared bound.
- A device that sleeps for long periods inside one process keeps a trailing mark until the next unlock session.
- A catalog whose very first check follows a wrong clock keeps a wrong mark. This is the one case the design does not cover.
- The catalog format moves to v18, so a v17-only reader refuses the vault.
