# Catalog schema v8: recoverable trash

> **Status:** Accepted implementation contract; security release gates remain separate

Version 8 adds `trash_entries(object_id, deleted_ms, expires_ms)` with an object foreign key and indexes for expiry and recent deletion. New catalogs install this schema. Existing v7 catalogs migrate inside the authenticated descriptor migration protocol; restored backups migrate through v8 before installation.

Moving an active object to trash sets `state = TRASHED`, writes its deletion and expiry times, removes its search row, and bumps the catalog generation in one transaction. The expiry is 30 days after deletion, measured on the trusted time of [catalog v18](CATALOG_SCHEMA_V18.md), not the device clock. Album, tag, favourite, metadata, container, and key rows remain. Restoring reverses the state transition, removes the trash entry, rebuilds search, and bumps the generation in one transaction. Selection updates are atomic.

The trash query scope orders by deletion time descending and excludes all other states. Ordinary scopes require `ACTIVE`, so trashed media are absent from albums, favourites, tags, timeline, and search. Readers can open trashed media for its preview. Permanent deletion removes the trash entry when it enters `DELETING`, then follows the existing cryptographic erasure and garbage collection protocol. Expired entries are purged on unlock and before catalog queries; interrupted purges roll forward on the next unlock.
