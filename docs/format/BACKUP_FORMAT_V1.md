# Chur Backup Format v1

> **Status:** Proposed portable backup contract

The backup format packages a complete or incremental encrypted vault for user-controlled storage and cross-device restore. It is distinct from the live vault layout and from sync transport.

## 1. Goals

- portable across Android, iOS, and CLI;
- no device-bound Keystore/Keychain dependency;
- authenticate inventory and completeness;
- preserve immutable object containers without decrypting them;
- include a recoverable root envelope;
- support streaming creation and restore;
- fail safely under truncation, reordering, or stale manifests.

### Current implementation and portability gap

The code implements full native CHURBAK1 creation and restore. Selective archives and external-file encryption create a new independent vault and then use that same full-package path. Incremental backup and `age` outer wrapping remain proposed, not supported app features.

Builds before [ADR-0068](../adr/0068-carry-a-portable-catalog-export-in-backup-v2.md) wrote version 1 packages whose `CatalogExport` record is a copy of the encrypted SQLCipher file. That copy differs from the canonical catalog-export requirement in [catalog v1](CATALOG_SCHEMA_V1.md) §15 and [ADR-0038](../adr/0038-adopt-sqlcipher-as-the-v1-catalog-engine.md). ADR-0068 resolves the divergence with package version 2, defined in [`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md): the catalog travels as a logical export in sealed records, and the final commit also commits to every record that is not a container. Every writer now produces version 2. A reader still restores a version 1 package through §8 of this document, and the version 1 description of the catalog record below applies only to those packages.

## 2. Package model

```text
BackupPackageV1
├── PublicBackupPreamble
├── EncryptedBackupManifest
├── PortableVaultDescriptor
├── EncryptedCanonicalCatalogExport
├── ObjectContainer entries
├── ObjectKey/Collection envelopes
├── Optional incremental operation segment
└── AuthenticatedFinalBackupCommit
```

### 2.1 Public preamble

`PublicBackupPreamble` is exactly 32 bytes and begins at file offset 0. Integers are unsigned big-endian per [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §2.

```text
offset  size  field                           v1 value
0x00     8    magic                           43 48 55 52 42 41 4B 31   "CHURBAK1"
0x08     2    backup_version:u16              0x0001
0x0A     2    canonical_encoding_profile:u16  0x0001
0x0C     2    suite_id:u16                    0x0001
0x0E     2    flags:u16                       0x0000
0x10     4    public_header_length:u32        0x00000020   (32)
0x14     4    reserved:u32                    0x00000000
0x18     8    record_count:u64                variable
0x20          end of preamble
```

The magic, the version, the encoding profile, the suite, and the package record types are allocated in [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §15; the registry records the allocation, and this section is the authority for these package bytes.

A v1 reader must reject the package unless:

- `magic` matches all eight bytes;
- `flags`, `reserved`, and `public_header_length` hold exactly their listed v1 values;
- `record_count` is within the bound in §13;
- `backup_version`, `canonical_encoding_profile`, and `suite_id` are supported values.

An unknown version, profile, or suite fails as `UNSUPPORTED_*`. A fixed field that holds any other value fails as `VAULT_CORRUPT`; it is never ignored. `record_count` is the only variable preamble field. It bounds allocation before any credential exists, and the final backup commit authenticates it, so a modified value surfaces as a commit authentication failure rather than as a successful parse.

### 2.2 Package records

Every component after the preamble is one record. The first begins at offset `0x20` and each later one begins immediately after the previous one:

```text
offset  size            field                v1 value
0x00     1              record_type:u8       allocated in CANONICAL_ENCODING_V1.md §15.3
0x01     1              record_version:u8    0x01
0x02     2              reserved:u16         0x0000
0x04     8              payload_length:u64
0x0C     payload_length payload
```

A reader dispatches on `record_type` before it reads any other field. An unallocated `record_type`, a `record_version` other than `0x01`, or a non-zero `reserved` fails as `VAULT_CORRUPT`. Records appear in the order of the package model above: the encrypted backup manifest is always the first record, the final backup commit is always the last, and no bytes follow it.

### 2.3 Outer framing

The native package of §2.1 and §2.2 is the framing. There is no Chur-native archive layer around it. The first eight bytes of a file decide how it is opened:

- `43 48 55 52 42 41 4B 31` (`CHURBAK1`) is an unwrapped native package, parsed by §2.1;
- `61 67 65 2D 65 6E 63 72` (`age-encr`) is the start of the `age` v1 binary header line;
- `2D 2D 2D 2D 2D 42 45 47` (`-----BEG`) is the start of an `age` ASCII-armored header;
- any other value is not a Chur backup and is rejected before any further parsing.

An `age` layer is removed first, and the plaintext it yields must itself begin with `CHURBAK1`. Exactly zero or one `age` layer is permitted; a wrapper inside a wrapper is rejected rather than unwrapped again. The wrapper is transport only and does not replace the inventory and completeness semantics of §5 and §7.

## 3. Portable slots

Included:

- password slot and parameters when configured;
- recovery slot ciphertext;
- portable recipient envelope explicitly selected by user.

Excluded:

- Android Keystore aliases/keys;
- iOS `ThisDeviceOnly` Keychain items;
- local session handles;
- local device-only caches and transfer state;
- private identity keys other than the one optional root-wrapped recovery identity of [ADR-0048](../adr/0048-recover-a-device-from-a-portable-identity-envelope.md).

For a sync-enabled vault, the creating device seals its current private identity into a recovery-only `DeviceIdentityEnvelopeV1` for the backup. The separate `Envelope` record and the encrypted catalog snapshot contain the same recovery envelope. The snapshot excludes ordinary and retired private identity envelopes. It includes the latest checkpoint signed by that device, with a freshness floor for each current accepted head. Backup creation does not replace the live ordinary identity or change the live catalog. Restore authenticates the catalog envelope under the root key and requires its canonical bytes to match the separate `Envelope` record before it installs the descriptor. A local-only backup has no `Envelope` record.

## 4. Backup manifest

Encrypted manifest includes:

```text
backup_id
backup_version
source_vault_id or privacy-preserving bound identity
created_time metadata
base_backup_id for incremental
catalog generation/schema
object inventory: IDs, versions, ciphertext lengths, commitments
slot inventory
operation-log heads when applicable
required free-space/restore policy metadata
```

`backup_version` here repeats the public preamble field of §2.1, which is the authority for the value and the copy the §13 limit bounds. A restore rejects the package as `VAULT_CORRUPT` when the two differ.

The manifest carries the ordered inventory commitment of §7.2 and the two entry counts rather than the entries themselves. At the §13 bound of 1048576 stream entries the list would be about 109 MB, which exceeds the §13 manifest payload cap of 16 MiB, and a restore would have to hold the whole inventory before reading a byte of content. Each entry travels instead in the head of the record it describes, and a reader recomputes the commitment as it walks the package, so completeness is authenticated with one entry in memory at a time.

The manifest is sealed under `BackupManifestKey`, derived by HKDF-SHA-256 from `VaultRootSecret` under the label `chur/v1/root/backup-manifest` registered in [`../security/KEY_HIERARCHY.md`](../security/KEY_HIERARCHY.md) §3. That label's context element list is `vault_id:bytes[16]` alone, frozen by [ADR-0034](../adr/0034-freeze-the-hkdf-context-element-lists.md); an earlier version of this section named `backup_id` as a second element, which was never true of the registry and is corrected here.

The AAD binds the backup instead:

```text
manifest_aad = CanonicalTuple(
      "CHUR\x00BACKUP\x00MANIFEST-AAD\x00V1",
      backup_version:u16, suite_id:u16, vault_id:bytes[16])
```

It binds the vault and not the backup, and deliberately: a restore must open the manifest before it can learn which backup it is reading, because the identifier is inside the sealed plaintext and §2.1 leaves no room for it in the public preamble. The identifier is checked rather than bound — the manifest and the final backup commit must name the same backup, and both are sealed under a key only a holder of the root can derive. The residual case a bound identifier would have caught is a whole authentic older package of the same vault, which is the rollback §10 already declines to detect.

The final backup commit of §7 is sealed under the same key and differs only in its domain tag, `CHUR\x00BACKUP\x00FINAL-COMMIT-AAD\x00V1`, so neither record opens as the other.

This is the only manifest-key source in v1. A password slot and a recovery slot both restore the same `VaultRootSecret`, so there is no separate portable content key and no key-source discriminant in the preamble; §8 step 3 has one deterministic input.

## 5. Full backup

A full backup includes every active object/container/envelope required to reconstruct the chosen vault identity and its catalog state. Completeness verification checks every inventory entry and final commit before activation.

### 5.1 Independent selective archives

A [selective archive](../product/SELECTIVE_ENCRYPTED_EXPORT.md) is a full package of a newly created, independent vault that contains only the selected content. Its root, credentials, identifiers, and catalog are new. It does not reuse the source vault descriptor or a filtered source catalog. The package framing and authentication remain CHURBAK1. Normal restore installs it as a separate vault; the selective import operation authenticates it in isolated staging, then copies content under new destination identifiers and keys.

## 6. Incremental backup

Incremental support is future/proposed. It must define:

- authenticated base backup ID/commitment;
- changed/new object inventory;
- tombstones/deletions;
- catalog operation segment;
- maximum chain length and compaction;
- restore ordering and missing-base failure;
- rollback/stale incremental handling.

An incremental must never silently restore without its exact authenticated base.

## 7. Streaming creation

```text
open consistent catalog snapshot
write temp package
write encrypted manifest placeholder or streaming manifest records
copy ciphertext containers without plaintext
compute ordered inventory commitment
write authenticated final backup commit
fsync destination
verify structural completeness
atomic finalize where destination supports it
```

When writing to a non-atomic external provider, incomplete state remains explicitly marked and is never advertised as complete.

The catalog snapshot is an encrypted copy of the catalog in the fixed directory `incoming/backup-snapshot/` of the vault. The writer removes the directory when the backup ends. If a process stops before that, the next unlock removes the directory before the session opens, and the next backup removes it before it writes a new copy. Thus no more than one snapshot copy can exist, and it does not outlive the next unlock.

### 7.1 Inventory order

A stream inventory entry is one canonical structure per backed-up stream, and a slot inventory entry is one per portable slot:

```text
StreamInventoryEntryV1              SlotInventoryEntryV1
object_id:bytes[16]                 slot_id:bytes[16]
stream_id:bytes[16]                 slot_type:u8
stream_kind:u8                      slot_generation:u64
stream_revision:u32
ciphertext_length:u64
manifest_commitment:bytes[32]
ordered_chunk_commitment:bytes[32]
```

Stream entries are sorted into one total order: ascending `object_id` byte order, then ascending `stream_id` byte order, then ascending `stream_revision`. Those three keys are unique together, so the order is total and two conforming writers that back up the same vault content emit the same sequence. Slot entries follow, sorted by ascending `slot_id` byte order.

### 7.2 Inventory commitment

```text
inventory_commitment = BLAKE3-256(
      "CHUR\x00BACKUP\x00INVENTORY-COMMITMENT\x00V1"
   || StreamInventoryEntryV1[0]
   || ...
   || StreamInventoryEntryV1[M-1]
   || SlotInventoryEntryV1[0]
   || ...
   || SlotInventoryEntryV1[K-1]
)
```

The domain tag is a fixed ASCII byte constant with no length prefix, per [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §3 and §7, and is allocated in §15.5 there. Entries are fed in the §7.1 order as their canonical bytes, with no count prefix and no separator; `M` and `K` are authenticated by the final backup commit. The output is 32 bytes. For an empty inventory the commitment is BLAKE3-256 of the domain tag alone. The value alone is not trusted; it is sealed inside the authenticated final backup commit.

## 8. Restore transaction

1. parse public preamble and enforce limits;
2. obtain password/recovery/recipient factor;
3. authenticate manifest and root context;
4. verify package/inventory completeness;
5. restore to temporary app-private namespace;
6. validate catalog and object-key references. The catalog's `catalog_generation` must equal the manifest's `catalog_generation`, and must not be lower than the `catalog_generation` that the package descriptor records. If not, the restore stops with `VAULT_CORRUPT` before it installs anything. The catalog header commitment identifies the catalog file only, and every copy of the same catalog has the same header, so this check is what refuses a catalog export from a different package of the same vault;
7. verify object final commits at the required level;
8. create new local platform key slot;
9. sync every restored directory (each shard directory, `objects/`, the vault directory and its parent), then commit local vault descriptor atomically. A directory sync error stops the restore. Only a result that means the platform cannot sync a directory is accepted;
10. clean temporary state.

The restore checks the target registry only after steps 2 and 3 have obtained the factor and authenticated the package descriptor, so a caller who holds no valid package gets the same result on every device. It then returns `CONFLICT` and installs nothing when the registry already holds two identities, holds an identity with the package's `vault_id`, or holds an identity the package credential opens. The check repeats just before the descriptor is installed. Unlock returns the first identity a credential opens, so a second copy under one credential would be chosen at random and the other would be unreachable. A restore with a recovery phrase cannot see the package's password, so a package password that equals an installed identity's password is not detected; the user can change one password after the restore.

## 9. Confidentiality and leakage

The outer package may reveal:

- total backup size;
- creation/modification time from filesystem/provider;
- number/size of outer records if not fully wrapped;
- format version.

A single encrypted outer stream or `age` wrapper can reduce record-level leakage but does not hide total size or access timing.

## 10. Rollback

A backup can be authentic but old. The package carries generation/log heads, but detecting restoration of a deliberately old offline backup requires user awareness or an external trusted checkpoint. Restore UI must show safe, decrypted backup metadata only after authentication.

## 11. Real and decoy

Default: one package contains one vault identity. Combining real and decoy in one manifest leaks the sibling relationship and is forbidden without an explicit alternate design.

## 12. Recovery rotation

Old backups retain old portable slots. Rotating a password or recovery secret does not revoke old backup packages. Users must replace/delete old backups if that guarantee matters.

## 13. Limits

- only `backup_version` `0x0001` and `0x0002` ([`BACKUP_FORMAT_V2.md`](BACKUP_FORMAT_V2.md)), `canonical_encoding_profile` `0x0001`, and `suite_id` `0x0001` are accepted;
- `record_count` between 2 and 1048576; a package holds at least the encrypted backup manifest and the final backup commit;
- at most 1048576 stream inventory entries and at most 16 slot inventory entries;
- backup manifest record payload at most 16777216 bytes (16 MiB);
- an object container entry payload is bounded by the container limits in [`OBJECT_CONTAINER_V1.md`](OBJECT_CONTAINER_V1.md) §16;
- `payload_length` and every running offset use checked `u64`, and the 32-byte preamble plus every record header and payload must total the package length exactly;
- nesting: a native record never contains a native record, and §2.3 permits exactly zero or one `age` layer;
- v1 defines no compression inside the package, so no declared output size can exceed its input and no decompression bomb is representable;
- the key-slot and Argon2 bounds of [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §11 are validated before any derivation runs;
- restore performs no free-space preflight of its own: the backup manifest carries `free_space_required` — the package length plus 67108864 bytes (64 MiB) — for a caller that can ask, and a destination that fills fails on the write and takes the partial vault directory with it, so nothing openable survives;

## 14. Test vectors

- minimal empty vault;
- mixed photo/video/audio objects;
- complete and truncated package;
- reordered/duplicated/missing object entries;
- wrong password/recovery;
- incremental with correct/wrong/missing base;
- old catalog/object versions requiring migration;
- Android→iOS→CLI restore;
- no device-bound slot imported;
- real/decoy package isolation;
- interrupted external-provider write.
