# Collection Membership v1

> **Status:** Accepted normative Phase 4 protocol

This document defines the authenticated member and permission state of one security collection. One entry represents one recipient device, not a user.

## 1. Fixed record

`CollectionMembershipRecordV1` is exactly 292 bytes:

```text
record_version:u16                         = 0x0001
source_vault_id:bytes[16]
collection_id:bytes[16]
collection_membership_generation:u64
previous_membership_commitment:bytes[32]
action:u8                                  = 0x01 UPSERT or 0x02 REVOKE
recipient_identity_vault_id:bytes[16]
recipient_device_id:bytes[16]
recipient_signing_public_key:bytes[32]
recipient_hpke_public_key:bytes[32]
permissions:u8                             = 0x01, 0x03, 0x07; REVOKE uses 0x00
collection_epoch:u64
issuer_identity_vault_id:bytes[16]
issuer_device_id:bytes[16]
issuer_membership_generation:u64
created_sequence:u64
issuer_signature:bytes[64]
```

Identifiers, generations, epochs, sequences, and public keys are non-zero. Generations and epochs cannot equal `u64::MAX`. The recipient identity vault differs from the source vault. Generation one names the all-zero predecessor; every later record names the commitment of generation minus one.

The signature input is `CHUR\x00SHARING\x00COLLECTION-MEMBERSHIP\x00V1` followed by the first 228 record bytes. The chain commitment is:

```text
BLAKE3-256("CHUR\x00SHARING\x00MEMBERSHIP-CHAIN\x00V1" || complete_record)
```

## 2. Actions and permissions

`UPSERT` adds a recipient device or changes its permission. It uses one canonical cumulative profile from [`COLLECTION_GRANTS.md`](COLLECTION_GRANTS.md) §6. Repeating the same recipient keys and permission at a later generation is non-canonical.

One collection has at most 256 active recipient devices. A revoked historical entry does not count against this bound. The source vault still has the separate 32-active-device bound from [`DEVICE_IDENTITY.md`](DEVICE_IDENTITY.md).

`REVOKE` names the exact keys of an active entry, uses permission byte zero, and advances `collection_epoch` by exactly one. The removed entry becomes historical verification state and cannot author later operations or membership changes.

A permission downgrade that retains `READ` uses `UPSERT` at the current epoch. It changes operation authorization but cannot remove a collection key already delivered. Removing read access uses `REVOKE`, a new epoch, eager object-key rewrap, and grants to remaining devices.

Revoking a device of the source vault can also advance the collection epoch through an authenticated `CreateCollectionEpoch` operation without changing collection membership generation. The client commits that accepted epoch to collection-sharing state in the same transaction that starts eager rewrap. This keeps later grants bound to the current key after source-device loss.

A recipient that does not hold the source vault's operation log — every external recipient — never observes that operation. The next authenticated membership record names the issuer's current epoch, and the recipient follows the advance from that record; an epoch below the locally accepted one stays a rollback.

## 3. Issuer authorization

An issuer is accepted only when its signature key and `issuer_membership_generation` select authenticated current state:

- a device of `source_vault_id` is active in source device membership; or
- an external recipient device is active in this collection with `MANAGE_MEMBERS`.

The record is carried by operation kind `0x11`. `issuer_identity_vault_id`, `issuer_device_id`, and `created_sequence` equal the containing operation values. The operation is encrypted under the collection epoch that is current before the change.

## 4. Recipient key verification

The first accepted key pair for a recipient device is pinned on first use. The UI offers the fingerprint and QR representation of [`DEVICE_IDENTITY.md`](DEVICE_IDENTITY.md) §5 before the first share. Names and avatars are not key evidence.

A different signing or HPKE key blocks the membership change and all new grants until the user explicitly verifies the new fingerprint. V1 defines no silent key replacement and no dismissible warning.

## 5. Grant binding and staleness

An accepted grant must match the active recipient entry exactly: collection, recipient identity and device, HPKE key identifier, permission profile, collection epoch, and the generation that last changed that recipient. A later membership record for another recipient does not stale the grant. A later record for the same recipient does.

The accepted membership generation of each issuer vault (the source vault, or a `ManageMembers` delegate vault) is a stored high-water mark (`sharing_issuer_marks`), raised in the transaction that accepts the evidence and never lowered, so pruning collection rows cannot lower it. See [`COLLECTION_GRANTS.md`](COLLECTION_GRANTS.md) §9 and [`../format/CATALOG_SCHEMA_V19.md`](../format/CATALOG_SCHEMA_V19.md).

Grant replay is idempotent only when complete bytes match. Reusing a grant identifier with different bytes freezes grant acceptance for that collection as a security conflict.

## 6. Recovery and device loss

A recovered source device restores the membership chain and recipient pins before it issues a grant. A new recipient device has new keys and receives its own membership entry and grant; private identity material is never copied from another device.

Loss of one recipient device revokes only that device, advances the epoch, eagerly rewraps active object keys, and issues current-epoch grants to every remaining active device. Previously downloaded old-epoch content can remain accessible to the lost device.

## 7. Tests

- canonical round trip, signature, predecessor, and generation ordering;
- TOFU pin, verified change, and unverified substitution;
- source issuer, member manager, insufficient permission, and revoked issuer;
- add, upgrade, downgrade, revoke, stale grant, and conflicting replay;
- multi-device and multi-recipient independence;
- recovery and lost-device epoch rotation.
