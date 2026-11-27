# Chur Key Hierarchy

> **Status:** Proposed normative key-ownership and lifecycle model

## 1. Overview

```text
Password / Device protector / Recovery / Peer device
                       ↓ key slot
               VaultRootSecret (32 bytes)
                       ↓ HKDF root domains
       ┌───────────────┼───────────────────────┐
       ↓               ↓                       ↓
CollectionEnvelopeKey  CatalogDatabaseKey      Other root-domain keys
       ↓
SecurityCollectionKey[epoch] (random)
       ↓ wrap
ObjectKey (random per object)
       ↓ HKDF object domains
Manifest / Content / Metadata / Thumbnail / Preview / Commit keys
```

A password is not a root key. A platform biometric is not a key. Android Keystore and iOS Keychain gate a key-slot operation that releases or unwraps `VaultRootSecret`.

## 2. Key classes

| Key | Size | Creation | Persistence |
| --- | ---: | --- | --- |
| `VaultRootSecret` | 32 bytes | Rust CSPRNG | only wrapped in key slots |
| `PasswordKEK` | 32 bytes | Argon2id | never persisted |
| platform KEK/wrapping key | platform-specific | Keystore/Keychain flow | platform service / device slot |
| `RecoverySecret` | 32 bytes | Rust CSPRNG | user-controlled representation only |
| `SecurityCollectionKey` | 32 bytes | Rust CSPRNG per epoch | wrapped under root-derived key or recipient grant |
| `ObjectKey` | 32 bytes | Rust CSPRNG per object | wrapped in one or more object envelopes |
| stream/domain key | 32 bytes | HKDF from parent | never persisted unless format explicitly requires |
| device identity private key | algorithm-specific | Rust/platform CSPRNG | wrapped under identity-domain key/platform policy |

## 3. HKDF label registry

The root secret must not be used directly for unrelated AEAD operations. HKDF-SHA-256 derives versioned domains.

This table is the only registry of HKDF domain labels. [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), [`../ARCHITECTURE.md`](../ARCHITECTURE.md), and the root [`../../README.md`](../../README.md) explain why domain separation exists and refer here for the strings.

| Label | Derived key | Input key | Output |
| --- | --- | --- | ---: |
| `chur/v1/root/collection-envelope` | `CollectionEnvelopeKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/catalog-database` | `CatalogDatabaseKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/catalog-records` | `CatalogRecordRootKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/search` | `SearchKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/identifiers` | `IdentifierKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/local-fingerprint` | `LocalFingerprintKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/private-settings` | `PrivateSettingsKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/device-identity-wrap` | `IdentityWrapKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/backup-manifest` | `BackupManifestKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/descriptor-auth` | `DescriptorAuthKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/sync-operations` | `RootSyncOperationKey` | `VaultRootSecret` | 32 bytes |
| `chur/v1/root/sync-selector` | `RootSyncSelectorMaterial` | `VaultRootSecret` | 32 bytes |
| `chur/v1/collection/object-envelope` | `ObjectEnvelopeKey` | `SecurityCollectionKey[epoch]` | 32 bytes |
| `chur/v1/collection/metadata` | `CollectionMetadataKey` | `SecurityCollectionKey[epoch]` | 32 bytes |
| `chur/v1/collection/sync-operations` | `CollectionSyncOperationKey[epoch]` | `SecurityCollectionKey[epoch]` | 32 bytes |
| `chur/v1/collection/sync-selector` | `CollectionSyncSelectorMaterial[epoch]` | `SecurityCollectionKey[epoch]` | 32 bytes |
| `chur/v1/object/manifest` | `ManifestKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/content` | `ContentKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/metadata` | `MetadataKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/thumbnail` | `ThumbnailKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/preview` | `PreviewKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/poster-frame` | `PosterFrameKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/waveform` | `WaveformKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/ocr` | `OcrKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/face` | `FaceKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/embedding` | `EmbeddingKey` | `ObjectKey` | 32 bytes |
| `chur/v1/object/final-commit` | `FinalCommitKey` | `ObjectKey` | 32 bytes |
| `chur/v1/recovery/root-envelope` | `RecoveryKEK` | `RecoverySecret` | 32 bytes |
| `chur/v1/slot/apple-device-kek` | `AppleDeviceKEK` | `DeviceUnlockSecret` | 32 bytes |
| `chur/v1/peer/session` | `PeerDirectionKey[direction]` | `PeerHandshakeSecret` | 32 bytes |
| `chur/v1/peer/transcript-binding` | `PeerTranscriptBinding` | `PeerHandshakeSecret` | 32 bytes |

Labels are ASCII protocol constants and every row is covered by test vectors. The label alone does not fix the key: each derivation also binds the context fields required by [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13, so `CollectionEnvelopeKey` is per vault, collection, and epoch, and an object-domain key is per object.

### Context elements

[`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13 makes the HKDF `info` value the tuple `CanonicalTuple("CHUR\x00KDF\x00INFO\x00V1", purpose_label, context_fields)` and delegates the element list after the label to the specification that owns the derivation. The table below is that list for every label above, so one label always selects one element list. Element types and widths are those of [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §2, and the elements follow the `u32`-prefixed label string in the order shown, with no separator.

A context binds the scope over which the derived key must be unique. Every root label therefore carries `vault_id`, every collection label carries the collection identity and its epoch, and every object label carries the object identity and the revision of the stream it protects.

| Label | Context elements, in order |
| --- | --- |
| `chur/v1/root/collection-envelope` | `vault_id:bytes[16]`, `collection_id:bytes[16]`, `collection_epoch:u64` |
| `chur/v1/root/catalog-database` | `vault_id:bytes[16]` |
| `chur/v1/root/catalog-records` | `vault_id:bytes[16]` |
| `chur/v1/root/search` | `vault_id:bytes[16]` |
| `chur/v1/root/identifiers` | `vault_id:bytes[16]` |
| `chur/v1/root/local-fingerprint` | `vault_id:bytes[16]` |
| `chur/v1/root/private-settings` | `vault_id:bytes[16]` |
| `chur/v1/root/device-identity-wrap` | `vault_id:bytes[16]` |
| `chur/v1/root/backup-manifest` | `vault_id:bytes[16]` |
| `chur/v1/root/descriptor-auth` | `vault_id:bytes[16]` |
| `chur/v1/root/sync-operations` | `vault_id:bytes[16]` |
| `chur/v1/root/sync-selector` | `vault_id:bytes[16]` |
| `chur/v1/collection/object-envelope` | `collection_id:bytes[16]`, `collection_epoch:u64`, `object_id:bytes[16]` |
| `chur/v1/collection/metadata` | `collection_id:bytes[16]`, `collection_epoch:u64` |
| `chur/v1/collection/sync-operations` | `collection_id:bytes[16]`, `collection_epoch:u64` |
| `chur/v1/collection/sync-selector` | `collection_id:bytes[16]`, `collection_epoch:u64` |
| `chur/v1/object/manifest` | `object_id:bytes[16]`, `stream_id:bytes[16]`, `stream_kind:u8`, `stream_revision:u32` |
| `chur/v1/object/content` | `object_id:bytes[16]`, `stream_id:bytes[16]`, `stream_kind:u8`, `stream_revision:u32` |
| `chur/v1/object/final-commit` | `object_id:bytes[16]`, `stream_id:bytes[16]`, `stream_kind:u8`, `stream_revision:u32` |
| `chur/v1/object/metadata` | `object_id:bytes[16]`, `metadata_revision:u32` |
| `chur/v1/object/thumbnail` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/preview` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/poster-frame` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/waveform` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/ocr` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/face` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/object/embedding` | `object_id:bytes[16]`, `stream_kind:u8`, `source_content_revision:u32`, `stream_revision:u32` |
| `chur/v1/recovery/root-envelope` | `vault_id:bytes[16]`, `slot_id:bytes[16]`, `slot_generation:u64` |
| `chur/v1/slot/apple-device-kek` | `vault_id:bytes[16]`, `slot_id:bytes[16]`, `slot_generation:u64` |
| `chur/v1/peer/session` | `transcript_hash:bytes[32]`, `direction:u8` |
| `chur/v1/peer/transcript-binding` | `transcript_hash:bytes[32]` |

Four rules read out of the table:

- **the three container labels carry `stream_id`.** [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §29 requires at least the object identity, the stream kind, and the stream revision. `ManifestKey`, `ContentKey`, and `FinalCommitKey` protect the records of one container, which carries `stream_id` in its manifest, so they bind that identifier as well and one container's keys never open another;
- **the derived-asset labels protect a single-record asset.** [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §41 permits a derived asset to use either the chunk container or a smaller single-record AEAD format. A derived asset stored as a container derives its record keys from `ObjectKey` under the three container labels, with that stream's `stream_kind` and `stream_revision`; a derived asset stored as one record uses its own kind label here. Both bind the object, the kind, and the revision, so neither accepts an asset of another object or another kind;
- **a slot label carries `slot_generation`.** A replaced slot is a new generation under [`KEY_SLOTS.md`](KEY_SLOTS.md) §9, so a copied or superseded slot derives a different KEK and cannot unwrap the current root;
- **`identity_id` is not a context element.** Real and decoy identities hold independent root secrets and independent `vault_id` values under §11, so the vault identifier already names the identity and a second element would add no separation.

A change to any element list is a new label plus the migration the change rule below requires. Adding an element to a frozen list silently changes key bytes and is a defect.

### Label rules

- a label is lowercase ASCII with the segments `chur` / protocol version / tier / purpose, separated by `/`;
- the tier segment names the input key: `root` for `VaultRootSecret`, `collection` for a security-collection key, `object` for an `ObjectKey`, `recovery` for a `RecoverySecret`, `peer` for the `PeerHandshakeSecret` of one direct peer session (the invitation secret followed by the X25519 shared secret, see [`../sync/SYNC_PROTOCOL_V1.md`](../sync/SYNC_PROTOCOL_V1.md) §3.1), and `slot` for a secret a key slot holds outside the root chain, such as the Keychain-held `DeviceUnlockSecret` of [`KEY_SLOTS.md`](KEY_SLOTS.md) §5. `RecoverySecret` is also slot-held and keeps the `recovery` tier it was registered under, because a label is never redefined. A root-derived label always keeps the `/root/` segment; a form such as `chur/v1/search` is not a valid label;
- the purpose segment is plural when the key covers a class of records (`catalog-records`, `identifiers`, `private-settings`) and singular when it covers one named artifact or stream (`catalog-database`, `backup-manifest`, `manifest`, `content`);
- the purpose segment names the protected artifact, not the media type it comes from: `poster-frame` and `waveform`, not `video-poster` or `audio-waveform`;
- a label enters this table before it is implemented, and no derivation uses a label that is absent from it;
- a specification that writes out a derivation may restate the label that derivation consumes; the strings must then be identical, and a divergence is a defect.

### Changing a label

A label selects key bytes, so a label is never redefined. A different purpose, tier, or spelling is a new label plus a migration that rewraps or re-encrypts everything derived under the old one. The old label and its vectors stay here until no reachable data depends on it. Editing a label in place is a silent key change and is a defect, not a correction.

The presence of a label does not mean that a feature uses it. v1 does not derive `CatalogRecordRootKey` or `MetadataKey`: object metadata, album names, captions and notes are columns of the catalog, which SQLCipher alone protects under `CatalogDatabaseKey`. Current metadata search, private-note search, and OCR/content search use SQLCipher under `CatalogDatabaseKey`. They do not derive `SearchKey` or `OcrKey` for the index. Face and semantic embeddings remain unimplemented. Future encrypted segment storage would require its own approved contract; do not reinterpret these frozen labels.

The iOS Share Extension receiving key is outside this vault hierarchy. The main app owns an independent device-local RSA private key and publishes only its public key to the App Group. Per-item AES keys protect temporary incoming ciphertext; they are never vault keys or exported credential slots. See [ADR-0064](../adr/0064-receive-system-shares.md).

## 4. Security collection keys

A Security Collection is an access-control/key domain, not necessarily a UI album. The key is random and has an explicit epoch.

```text
Collection A epoch 1 → objects created before rotation
Collection A epoch 2 → new objects and rewrapped envelopes
```

Rotation may rewrap object keys incrementally. Media bytes need not be re-encrypted unless the object key itself is rotated.

## 5. Object keys

Every object receives a fresh random `ObjectKey`, even when content is identical. An object may have multiple envelopes when it belongs to multiple access domains or is shared to multiple authorized contexts.

Compromise of one object key must not reveal:

- other object keys;
- collection keys;
- catalog/search keys;
- root secret;
- real or decoy sibling vaults.

## 6. Object-domain derivation

Object-domain labels and their derived keys are registered in §3. An object-domain key is derived from the object's random `ObjectKey`, never from a collection or root key.

A stream revision also receives a fresh random nonce prefix. Domain separation does not replace nonce uniqueness.

## 7. Identifier keys

User-facing or server-visible identifiers should be random or derived through a dedicated identifier domain. An unkeyed plaintext hash must not become a global object identifier.

`LocalFingerprintKey` is root-derived rather than object-derived, because a fingerprint computed under a per-object random key can never match two objects with identical content.

A keyed local fingerprint may support duplicate detection only when:

- derived under `LocalFingerprintKey`;
- never exposed globally by default;
- collision and deletion behavior are specified;
- users can disable or rebuild it.

## 8. Key lifetimes

| State | Root | Collection | Object/stream | Catalog key |
| --- | --- | --- | --- | --- |
| Locked | unavailable | unavailable | unavailable | unavailable |
| Unlocking | temporary candidate | none until root validated | none | none |
| Unlocked | Rust session secret | loaded/on demand | loaded/on demand | active in Rust catalog connection |
| Locking | zeroized in place | zeroized/evicted | readers invalidated and zeroized | DB closed then zeroized |
| Background ciphertext sync | unavailable | unavailable | unavailable | unavailable |

Caches must not extend a key lifetime beyond the session that created them.

## 9. Rotation

### Password change

Derive a new `PasswordKEK` with fresh salt/parameters and rewrap the unchanged root.

### Device re-enrollment

Use a valid password/recovery/root session to create a new platform slot. Remove the old slot only after the new one verifies.

### Collection rotation

Create `SecurityCollectionKey[epoch+1]`, write/verify its root envelope, then rewrap object keys. Old epochs remain readable only as long as policy requires.

### Object-key rotation

Required when an object key is suspected compromised or a construction changes in a way that cannot be solved by envelope rewrap. This re-encrypts object streams.

### Root rotation

Rare and expensive at the key-management layer but does not require media re-encryption: rewrap all collection/catalog/identity domains transactionally. It requires complete inventory and recovery planning.

## 10. Deletion and crypto-erasure

An object becomes cryptographically inaccessible only after every reachable envelope for its object key is destroyed, including:

- active catalog rows;
- WAL/journal/snapshots after compaction policy;
- backups;
- synced devices;
- collection grants;
- exported packages.

Chur cannot force an authorized recipient to erase previously obtained keys or plaintext.

## 11. Real and decoy hierarchy

Real and decoy vaults start with separate random root secrets. No derived label, collection key, object key, platform alias, recovery secret, or identity key is shared.

```text
RealRoot   ── independent tree
DecoyRoot  ── independent tree
```

## 12. Implementation requirements

- secret types use fixed-size buffers where practical;
- randomness failures abort creation;
- secret material never enters general serialization;
- no default `Debug` for secret-bearing structs;
- key handles are scoped to a session generation;
- all derivation and wrapping operations have deterministic vectors;
- unsupported key sizes or labels fail closed.
