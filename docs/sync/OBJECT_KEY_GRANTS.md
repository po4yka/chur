# Disposable Object-Key Grants

> **Status:** Accepted normative current protocol. There are no deployed clients to migrate.

Collection operations contain key commitments. They never contain an object-key envelope. Collection grants and retained collection epochs can open collection metadata, but they cannot open an object's content. A content key is delivered through an object-bound request and a disposable X25519 key. The receiver must request the key after it has accepted the signed object commit. The source must be online for a later sync pass to answer the request. Until then, the object waits for its key.

## 1. Signed request

`ObjectPrekey` is exactly 226 bytes, in this order:

```text
version:u16 = 1
prekey_id:bytes[16]
collection_id:bytes[16]
object_id:bytes[16]
object_generation:u64
container_commitment:bytes[32]
recipient_vault_id:bytes[16]
recipient_device_id:bytes[16]
generation:u64
public_key:bytes[32]
signature:bytes[64]
```

The device signs `CHUR\x00OBJECT-PREKEY\x00SIGNATURE\x00V1` followed by all fields before `signature`. The source verifies the signature with the currently authorized recipient's Ed25519 key. The object ID, generation and container commitment must match an active source object. The source never answers a request for a deleted object. One prekey can receive only the object to which its signed request is bound.

The recipient creates a request only for an accepted, committed object with no local permanent-deletion tombstone and no active local copy. The private X25519 bytes are random and are stored only in a mutable SQLCipher row. They are not derived from the root or stable device identity, and are never included in an operation, request, grant or peer record. Each authenticated pending object has at most one outstanding local request. Transport pages contain at most 64 requests; unavailable objects do not consume a lifetime pool. An exact retry uses the same request.

## 2. Signed grant

`ObjectKeyGrant` is exactly 346 bytes, in this order:

```text
version:u16 = 1
grant_id:bytes[16]
collection_id:bytes[16]
object_id:bytes[16]
source_vault_id:bytes[16]
source_device_id:bytes[16]
recipient_vault_id:bytes[16]
recipient_device_id:bytes[16]
prekey_id:bytes[16]
object_generation:u64
container_commitment:bytes[32]
object_key_commitment:bytes[32]
encapsulated_key:bytes[32]
wrapped_key:bytes[48]
signature:bytes[64]
```

The key commitment is BLAKE3-256 with domain `CHUR\x00OBJECT-KEY\x00COMMITMENT\x00V1` and ordered inputs `collection_id`, `object_id`, and the 32-byte object key. It must match the accepted `CommitObject` payload.

The HPKE profile is DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256 and ChaCha20-Poly1305. The plaintext is the 32-byte object key. Both HPKE `info` and `aad` are `CHUR\x00OBJECT-KEY-GRANT\x00HPKE\x00V1` followed by the grant fields through `object_key_commitment`. The source signs `CHUR\x00OBJECT-KEY-GRANT\x00SIGNATURE\x00V1` followed by the grant fields through `wrapped_key`.

The recipient verifies the source's authenticated device membership and signature, its own recipient address, the exact stored request and the accepted object commit before it opens HPKE. Stable device HPKE private keys cannot open these grants.

## 3. Local custody and retry

Acceptance stores a fresh local `ObjectKeyEnvelope` in `pending_object_keys` and deletes the disposable private key in the same catalog transaction. It then completes a verified WAL truncation before it reports success. A failed barrier is an error; an exact retry repeats the barrier. The public request and grant can remain in the pending row for retry. They contain no reachable content key after the private prekey is destroyed.

Container activation verifies the complete container with the pending key. In one transaction it installs the object's active envelope and removes the pending envelope. The local envelope belongs to the recipient vault. It is not copied into the signed content log. A crash between ciphertext rename and activation is retried from the pending envelope.

## 4. Permanent deletion

Deletion destroys all active local object envelopes, and any superseded envelope that an earlier version kept, the object's pending envelope and its disposable private request key. `secure_delete=ON` overwrites deleted cells. The object remains `DELETING` until a verified WAL truncation removes the old frames. Only then can it become `TOMBSTONED` and enter physical garbage collection.

A local tombstone referenced by an own-vault or shared signed log survives physical garbage collection. It prevents a replayed commit from creating another key request, including after restart or a backup made after deletion. A source must not send unsolicited keys to unbound prekeys: that would make a deleted key reachable again through a later request. Requests bind the exact object instead.

Retained signed operation chains, collection keys, stable device identities, public requests and grants contain no reachable content key after this sequence. The peer can retain old ciphertext and old public grant records without changing that result. A recipient that still holds its own live object key, and a backup made before deletion, are independent copies. Deletion in one vault does not erase those copies.

A source's permanent deletion publishes `PurgeObject` before local key erasure. Receipt removes keys and pending private prekeys in the accepted-log transaction, even if no local media row exists yet. The receive/process completion path always verifies WAL truncation. A blocked checkpoint returns failure and the next unlocked process rolls the deletion forward before reporting success. A recipient's local deletion creates no global purge operation.

Collection metadata keys remain available through root-domain `DeclareCollection` and normal rotation records. These records contain no content key. A recipient can accept a key-free rewrap record for an object it has not downloaded; the accepted immutable key commitment must match. It rewraps an existing pending local envelope when present. It can then request the content key under the current metadata epoch without blocking another device's chain.

## 5. Transport

The peer stores bounded public requests and addressed grants. It does not hold private prekeys or plaintext content keys. Collection permissions gate request publication, source processing and recipient delivery. Request decoding rejects non-contributory X25519 public keys before admission or HPKE work.

A source can acknowledge an unavailable or contradictory request only for its own device. The request remains available to other sources. An exact recipient retry resets these transient dismissals and moves the request to the FIFO tail, so later requests can proceed.

Only durable native acceptance permits a successful grant ACK. An addressed recipient rejects a bad response through `POST /v1/vaults/{vault}/sharing/object-key-grants/reject` with its 16-byte grant ID. Rejection removes that response, retains the original request and private prekey, and quarantines that source device for this request. The quarantine survives an exact request retry. Another active source can answer with the correct commitment. If native acceptance reports `NOT_FOUND`, the recipient instead uses `POST /v1/vaults/{vault}/sharing/object-key-grants/discard` with the 16-byte grant ID. This removes the delivery and request without a successful receipt or source quarantine. A restored older backup can publish its original request again. Missing, invalid or withheld responses keep an object pending. They never create a key from a stable identity or a permanent log.

Pending media uses durable dispatch tickets in `object_receive_dispatch`. A native plan holds at most 256 downloads. The ticket is the primary queue order, and the next visit rotates the first attempted item. This order survives restart and backup. A missing key or unavailable container cannot permanently hide later objects behind the 4096-row projection scan. Private prekeys remain until their grant is accepted or their exact object is permanently deleted; an unavailable neighbor never evicts them.

Permanent-deletion tombstones bind both the collection and object ID. A purge removes private requests and pending envelopes only when their collection binding matches. An existing request must match both IDs before reuse or identity replacement. A foreign collection cannot erase custody or prevent a later request by reusing public object identifiers.

Temporary private requests and pending envelopes are keyed by `(collection_id, object_id)`. Two authenticated collections can retain separate custody for the same public object ID. Request reuse, identity replacement, grant acceptance, epoch rewrap, queue joins, activation cleanup, and deletion use both IDs. The active catalog keeps one object row per object ID. Reconciliation rejects a conflicting collection binding and cannot rebind that active row. A stale download plan is rejected before it can unlink or replace an already activated object's container. Activation and this check hold the same mutable session lock.
