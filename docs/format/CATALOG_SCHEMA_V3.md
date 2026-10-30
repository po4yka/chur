# Private Catalog Schema v3

> **Status:** Accepted normative physical schema extension

Catalog v3 extends [`CATALOG_SCHEMA_V2.md`](CATALOG_SCHEMA_V2.md) with durable collection-sharing state. All tables remain inside the same SQLCipher database and transaction domain.

## 1. Sharing collections

`sharing_collections` has one row per security collection:

```text
collection_id:bytes[16] primary key
source_vault_id:bytes[16]
initial_epoch:u64
membership_generation:u64
membership_commitment:bytes[32]
current_epoch:u64
```

Generation zero uses the all-zero commitment. `initial_epoch` and `current_epoch` are non-zero and cannot decrease.

## 2. Membership records

`sharing_membership_records` stores the complete 292-byte `CollectionMembershipRecordV1`, its generation, commitment, issuer signing key used at acceptance, and the recipient projection needed for bounded lookup. Generation is unique per collection. The record and every projection must agree when the catalog opens.

## 3. Recipient pins

`sharing_recipient_pins` is keyed by collection, recipient identity vault, and recipient device. It stores the 32-byte Ed25519 public key, the 32-byte X25519 public key, and verification state `1` for trust on first use or `2` for explicitly verified. A key change and its accepted membership record commit in one transaction.

## 4. Grants

`sharing_grants` stores the complete 309-byte `CollectionGrantV1`, collection, recipient identity vault, recipient device, recipient membership generation, and collection epoch. `grant_id` is the primary key. Identical replay changes no row. Different record bytes for the same identifier are a conflict. The accepted identity-membership generation of each evidence issuer is stored apart from these rows in `sharing_issuer_marks` ([`CATALOG_SCHEMA_V19.md`](CATALOG_SCHEMA_V19.md)).

## 5. Migration

The only new step is `v2 -> v3`. It creates empty sharing tables and indexes, then changes `vault_state.catalog_format_version` to `0x0003` in the same transaction. The authenticated descriptor uses the existing `MIGRATING` protocol. A v1 catalog first completes `v1 -> v2`; no migration step is skipped.

## 6. Invariants

- protocol records are decoded and authenticated before insertion;
- catalog load decodes every record and checks every projection;
- source and recipient keys are public only; collection keys stay in existing encrypted envelope records;
- membership, pin, grant, and epoch updates are crash-atomic;
- an accepted collection rotation advances `sharing_collections.current_epoch` in the same transaction as the collection envelope and rotation row;
- restoration never weakens a TOFU or explicitly verified pin.
