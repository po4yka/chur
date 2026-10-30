# Private Catalog Schema v6

> **Status:** Accepted normative physical schema extension

Catalog v6 extends [`CATALOG_SCHEMA_V5.md`](CATALOG_SCHEMA_V5.md). The tables stay in the SQLCipher catalog. They index accepted collection object operations and track objects that need recipient reconciliation. No index field enters a signed record.

## 1. Accepted object events

`sharing_object_operations` maps each object event to its stored signed record. Its key is `(key_selector, object_id, operation_id)`. A foreign key binds it to `sharing_operations`. The event kind identifies CreateObject, CommitObject, DeleteObject, RestoreObject, or RewrapObjectKey. A unique index permits at most one CreateObject and one CommitObject for an object in one collection epoch. Only a source-vault device can author CreateObject and CommitObject, so a recipient skips any such record from another issuer, and a repeated creation or commit, before it stores the record. The skip does not fail the rest of the received page.

`sharing_object_projection` has one row per indexed object. `revision` increases for each accepted object event. `dirty` is set in the same transaction as the event. Recipient reconciliation clears it only if the revision still matches. The `(key_selector, dirty, object_id)` index supplies a bounded queue without a wire cursor.

The reader uses the index to select one object's records. It still decodes each selected signed record and checks the stored outer fields, selector, decrypted payload, object ID, and event kind. The index does not replace collection chain validation.

## 2. Validated log cache

`sharing_operation_streams` gains `log_revision` and `object_index_ready`. Every accepted operation or fork change increments `log_revision` in its SQL transaction. A decrypted session may retain one validated collection log while this revision matches. It drops the cache on lock, on a changed revision, or after an unsuccessful operation. Recipient materialization does not change `log_revision`.

## 3. Migration and backfill

The `v5 -> v6` schema step creates the tables and columns and records version `0x0006` in one transaction. Existing streams start with `object_index_ready = 0`. New empty streams start ready. After unlock, the first reader of an old stream uses the collection key to check its already accepted SQLCipher rows and build the index in one transaction. It checks each row's outer projection, selector, decrypted payload, and object identity. It also rejects a stored DeleteObject or RestoreObject whose signed causal history has no valid object cause. A mismatch rolls back the whole backfill; the stream stays unready. A restart may repeat the transaction safely.

The old rows passed signature and chain checks when they were accepted. Offline backfill has no issuer evidence and does not claim to repeat those checks. The encrypted catalog and the accepted signed rows are the migration trust boundary.

## 4. Atomic delete visibility

After a new DeleteObject passes chain and object lifecycle checks, acceptance changes a matching active recipient object to `SHARED_DELETED` in the same SQL transaction as the signed record and index update. A source default collection is not changed. RestoreObject does not make an object visible until recipient reconciliation verifies its content.
