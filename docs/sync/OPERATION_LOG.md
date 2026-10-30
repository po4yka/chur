# Authenticated Operation Log

> **Status:** Accepted normative Phase 3 protocol

The operation log represents private catalog changes as canonical encrypted and signed records. The local SQLCipher catalog is a materialized view; raw database pages are never the sync protocol.

## 1. Goals

- authenticate device authorship;
- detect replay and per-device rollback/forks;
- provide deterministic idempotent application;
- synchronize mutable metadata separately from immutable media;
- support tombstones and conflict resolution;
- expose no private payload to peer.

## 2. Operation structure

This section owns the operation record: the field order below is the wire order. [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §52, [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §34.3, and the root [`README.md`](../../README.md) point here and do not restate it. [ADR-0044](../adr/0044-freeze-the-v1-sync-operation-record.md) freezes the widths, encrypted-payload framing, limits, and signing bytes.

```text
OperationV1 =
    protocol_version:u16 = 0x0001
    operation_id:bytes[16]
    vault_id:bytes[16]
    device_id:bytes[16]
    device_sequence:u64
    previous_operation_hash:bytes[32]
    observed_heads:list of ObservedHeadV1
    key_selector:bytes[16]
    encrypted_payload:bytes
    signature:bytes[64]
```

Private payload is encrypted under the exact root or collection sync-operation key of §6 before signing.

`encrypted_payload` is one canonical variable-byte field: its `u32` length prefixes a 24-byte XChaCha20-Poly1305 nonce followed by ciphertext including the 16-byte authentication tag. The plaintext is at most 1,048,576 bytes, so the field length is from 40 through 1,048,616 bytes. The nonce has no second length prefix.

The domain tag is not stored. The Ed25519 signing input is `CHUR\x00SYNC\x00OPERATION\x00V1` followed by every wire field from `protocol_version` through the length-prefixed `encrypted_payload`, excluding `signature`.

There is no separate payload commitment field. The AEAD tag of `encrypted_payload` already authenticates the payload against the outer AAD of §6, and the Ed25519 signature of §7 covers `encrypted_payload` byte for byte, so a third commitment would restate what two authenticated values already say.

## 3. Operation kinds

The v1 kind values and exact encrypted bodies are frozen in
[`OPERATION_PAYLOAD_V1.md`](OPERATION_PAYLOAD_V1.md). All allocated kinds are
critical: an unknown payload version or kind fails closed.

## 4. Per-device chain and observed heads

For each device:

```text
device_sequence = previous device_sequence + 1

operation_digest = BLAKE3-256(
      "CHUR\x00SYNC\x00OPERATION-CHAIN\x00V1"
   || complete canonical record bytes as written, signature field included
)

previous_operation_hash = operation_digest of this device's prior operation
                        = 32 zero bytes when device_sequence is 1
```

BLAKE3-256 is the commitment primitive of suite `0x0001`; the output is 32 bytes. The domain tag is a fixed ASCII byte constant with no length prefix, per [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §7, allocated in §15.5 of that document. The hash input is every byte of the prior record as it was written on the wire, in the order §2 lists, including the signature, so the chain commits to the signature as well as to the content and a re-signed variant of an accepted operation breaks the chain.

The genesis value is 32 zero bytes. An all-zero digest is not producible in practice, and an all-zero value carries no other meaning in this field, so a genesis link can never be mistaken for a real head. A record with `device_sequence` of 1 and a non-zero `previous_operation_hash`, or a later record with an all-zero one, is rejected.

`operation_digest` is also the concurrency tie-break of [`CONFLICT_RESOLUTION.md`](CONFLICT_RESOLUTION.md) §1, so a receiver computes it once per operation and uses it twice.

Clients store the latest accepted head. A duplicate identical record is idempotent; a different record at an accepted sequence is a fork/security error.

The chain orders a device against itself only. Cross-device ordering comes from `observed_heads`, the signed vector of accepted heads the author held when it created the operation. See [`../adr/0014-observed-heads-causality-vector.md`](../adr/0014-observed-heads-causality-vector.md).

### 4.1 Structure and limits

```text
ObservedHeadV1 =
    device_id:bytes[16]
    device_sequence:u64

observed_heads = list of ObservedHeadV1
```

Encoding follows [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md): a `u32` count followed by 24-byte elements sorted by ascending `device_id` byte value. Duplicate `device_id`, unsorted entries, a `device_sequence` of zero, an entry for the authoring device, and a count above the maximum are non-canonical and fail closed.

- the authoring device is excluded, so `(device_id, device_sequence)` together with `observed_heads` is the complete causal position of the operation;
- one entry is present for every other device from which the author has accepted at least one operation, and for no other device;
- `device_sequence` is the highest sequence accepted from that device;
- a vault has at most 32 active devices, so `observed_heads` holds at most 31 entries, 748 bytes including the count; a receiver rejects an enrollment of a new device identifier while 32 devices are active with `ResourceLimitExceeded`, and a key rotation of an existing device is not counted again.

### 4.2 Happens-before

Operation B observes operation A when B's entry for A's device is at or above A's `device_sequence`, or when both share an author and A has the lower sequence. A and B are concurrent when neither observes the other. This relation decides every causal rule in [`CONFLICT_RESOLUTION.md`](CONFLICT_RESOLUTION.md); a tie-breaker applies only to concurrent operations.

### 4.3 Referenced heads not held

An operation that observes a required head the receiver does not hold is not a fork and is not applied out of order. Section 4.4 bounds required heads after revocation:

- hold it in a pending set bounded by 1024 operations and 8 MiB per vault, whichever bound is reached first;
- request the missing heads and retry the pending set after each accepted batch;
- when a bound is reached, or when a sync session ends with the operation still unresolved, drop it and fetch it again later; nothing is applied before its observed heads are held;
- an entry naming an unknown device is a missing head, because enrollment is itself an operation;
- a referenced head the peer never delivers is omission or fork, handled by [`ROLLBACK_PROTECTION.md`](ROLLBACK_PROTECTION.md) §9.

### 4.4 Revocation

A revoked device must not pin the vector:

- the `RevokeDevice` operation records the revoked device's final accepted head, so ordering against that device's earlier operations survives without an entry in every later operation;
- native authors omit devices whose revocation they have accepted;
- an active author's retained observation of a revoked device is a historical claim. Its required dependency is `min(observed_sequence, final_accepted_device_sequence)`. A zero cutoff requires no record from that device. This does not authorize any operation above the signed cutoff;
- an author that had not yet observed the revocation may still name the device, and its operation is handled under [`REVOCATION.md`](REVOCATION.md) §7;
- a revoked device stops counting against the 32-device maximum once its revocation is accepted.

## 5. Operation ID

`operation_id` is 16 random bytes from the vault CSPRNG, encoded as bytes per [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §8. It is never derived from the signed bytes: it is a field of the record whose signed bytes would derive it, so the derived form is circular, and it is never a plaintext-content hash.

It is a deduplication and idempotency key only. Two received records are the same operation when their complete canonical bytes are identical; that is what §4 means by a duplicate identical record. Records sharing an `operation_id` but differing in any other byte are not duplicates: at the same `(device_id, device_sequence)` they are a fork under §4, and at any other position the second one is rejected as reuse of an identifier. Signature and chain validation remain authoritative.

`operation_id` is not a conflict tie-break input. The tie-break reads `operation_digest` from §4, which commits to the whole record including `observed_heads`, and which the receiver has already computed for the chain.

## 6. Encryption

The cleartext outer record is closed. It carries exactly the fields of §2 and nothing else:

```text
protocol_version
operation_id
vault binding
device_id
device_sequence
previous_operation_hash
observed_heads
key_selector
encrypted_payload
Ed25519 signature
```

Every other field of an operation lives inside `encrypted_payload`: `operation_kind`, the collection and key epoch the operation belongs to, and every object, album, tag, and device identifier the operation names. Without this, the peer reads a timestamped per-device stream of delete, favorite, rename, and tag events attributed to a collection, which is a behavioural profile of a private library and contradicts §1. A new routing need is a `protocol_version` change, not a new cleartext field.

`key_selector` is the 16-byte pseudorandom output fixed by [ADR-0051](../adr/0051-derive-sync-operation-keys-and-selectors.md). Root-domain operations derive it from `VaultRootSecret`; other operations derive it from `SecurityCollectionKey[epoch]`. The selector and payload key use separate HKDF labels. It is opaque: it carries no collection identity and no ordering, and the peer learns only that two operations use the same key domain. Root-domain operations carry the vault's root selector.

The root payload key is `RootSyncOperationKey = HKDF-SHA-256(VaultRootSecret, "chur/v1/root/sync-operations", vault_id)`. A collection payload key is `CollectionSyncOperationKey[epoch] = HKDF-SHA-256(SecurityCollectionKey[epoch], "chur/v1/collection/sync-operations", collection_id, collection_epoch)`. Exact HKDF framing and selector derivation are owned by [`../security/KEY_HIERARCHY.md`](../security/KEY_HIERARCHY.md) §3 and ADR-0051. A receiver derives a session selector directory from locally available wrapped keys and rejects an unknown or colliding selector before decryption.

The payload AAD is `CHUR\x00SYNC\x00OPERATION\x00V1` followed by the exact wire encoding from `protocol_version` through `key_selector`, excluding `encrypted_payload` and `signature`. AAD must be readable before decryption, so no field inside the ciphertext may appear in it: `operation_kind`, collection, epoch, and object identifiers are authenticated as payload plaintext by the AEAD tag, and the signature of §7 binds the sealed payload to the outer record.

What the peer still observes is enumerated in [`PEER_TRUST_MODEL.md`](PEER_TRUST_MODEL.md).

## 7. Signatures

The signature covers the byte sequence fixed in §2. It authenticates device identity and prevents peer modification.

Signing occurs only after local catalog transaction prepares a durable pending operation. Failed upload does not reuse sequence for a different operation.

## 8. Local transaction

```text
begin catalog transaction
apply local logical change
allocate operation sequence
create encrypted signed operation
store pending operation and new local device head
commit atomically
upload asynchronously
```

If signing fails, logical change must not commit as sync-visible state unless an explicit local-only policy exists.

## 9. Receive/apply

1. bound and canonically parse outer record;
2. verify known device/key and signature;
3. validate sequence, previous hash, fork state, and observed heads per §4.2 to §4.4;
4. decrypt and validate payload/schema/epoch;
5. apply idempotently under catalog transaction;
6. update accepted head/checkpoint;
7. schedule object transfer/derived work separately.

## 10. Checkpoints

Signed checkpoints may summarize accepted per-device heads and materialized state commitment. They improve bootstrap and rollback detection but do not prove peer completeness without cross-device/witness comparison.

## 11. Tombstones

Deletion operations create durable tombstones with causal ordering. A tombstone authored by device A at `device_sequence` `s` is retained until whichever comes first of:

- every device in the accepted membership has acknowledged it and 30 days have passed since it was authored;
- 180 days have passed since it was authored.

Acknowledgment needs no operation kind of its own. Device D has acknowledged the tombstone once the receiver holds an operation authored by D whose `observed_heads` entry for A is at or above `s`; the vector of §4 already carries exactly that fact. A revoked device stops counting toward the condition once its revocation is accepted.

The 180-day cap stops one permanently offline device from blocking object ciphertext and local-row garbage collection forever. V1 retains the signed tombstone operation after that cleanup, as [`ROLLBACK_PROTECTION.md`](ROLLBACK_PROTECTION.md) §6.1 requires, so a stale device still receives the delete and cannot resurrect the object.

## 12. Limits

- encrypted payload plaintext: at most 1,048,576 bytes;
- encrypted payload field: 40 through 1,048,616 bytes;
- operations per response/batch: at most 256;
- total operation record bytes per response/batch: at most 16,777,216;
- `observed_heads`: at most 31 entries, as §4.1 requires;
- sequence arithmetic is checked and `u64::MAX` cannot advance;
- every nested collection in a logical payload has its own bound;
- decompression is forbidden in v1 operation payloads.

A parser checks every declared length, count, and multiplication before allocation or signature work. The response limits are transport bounds; the pending-set bound of §4.3 and locked-staging bounds of [`SYNC_PROTOCOL_V1.md`](SYNC_PROTOCOL_V1.md) §7 remain smaller when they apply.

## 13. Tests

- valid chain and batching;
- duplicate identical operation;
- different operation same sequence;
- missing/interleaved sequence;
- wrong previous hash/signature/key/domain;
- unknown/revoked device;
- payload tamper/wrong epoch;
- local crash before/after operation commit;
- peer replay/rollback/fork/omission;
- deterministic conflict application;
- cross-platform vectors.

An authenticated active-device branch can contain a private payload whose required content was removed from future delivery by revocation. Its signed outer record and head may be retained without applying that private effect. This exception requires a signed pruned observation in its causal ancestry. Ordinary missing causes retain the pending-log rule. Related accepted facts retry the deferred projection. Unresolved or contradictory private effects stay pending and do not block unrelated descendants. A resolved `PurgeObject` removes custody in the same catalog transaction; the key-erasure barrier still applies.
