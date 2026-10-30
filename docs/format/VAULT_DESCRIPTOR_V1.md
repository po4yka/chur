# Vault Descriptor v1

> **Status:** Proposed normative logical and binary contract; the field layout of §2, the sub-descriptors of §5 to §7, and the descriptor-authentication construction of §8 are frozen. Deterministic vectors are outstanding.

`VaultDescriptorV1` is the small pre-unlock structure that identifies a vault format, lists bounded key-slot descriptors, locates encrypted catalog/object state, and records transaction/migration generation. It contains no private user metadata.

## 1. Goals

- allow safe parsing before expensive authentication;
- bind key slots to one vault identity;
- distinguish complete initialization from interrupted setup;
- locate opaque catalog/object roots;
- support atomic descriptor generations;
- expose only minimal unavoidable metadata;
- remain portable across Android, iOS, and CLI.

## 2. Conceptual structure

```text
VaultDescriptorV1
├── magic
├── descriptor_version
├── canonical_encoding_profile
├── crypto_policy_id
├── vault_id
├── descriptor_generation
├── state
├── catalog_descriptor
├── object_store_descriptor
├── key_slot_descriptors[]
├── migration_descriptor?
└── descriptor_authentication
```

V1 values for `magic`, `descriptor_version`, `canonical_encoding_profile`, `crypto_policy_id`, and the `state` discriminants of §4 are allocated in [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §15; the registry records the allocation, and this section is the authority for these descriptor bytes.

### 2.1 Public head

The descriptor begins with a fixed 40-byte head. Integers are unsigned big-endian per [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §2.

```text
offset  size  field                           v1 value
0x00     8    magic                           43 48 55 52 56 4C 54 31   "CHURVLT1"
0x08     2    descriptor_version:u16          0x0001
0x0A     2    canonical_encoding_profile:u16  0x0001
0x0C     2    crypto_policy_id:u16            0x0001
0x0E     2    flags:u16                       0x0000
0x10     4    public_header_length:u32        0x00000028   (40)
0x14     4    descriptor_length:u32           variable, total encoded bytes including the trailing tag
0x18    16    vault_id                        random, never all zero
0x28          end of head
```

`descriptor_length` and `vault_id` are the only variable head fields. A reader rejects the descriptor unless `magic` matches all eight bytes, `flags` and `public_header_length` hold exactly their listed values, `vault_id` is not all zero, `descriptor_length` is within §13, and the version, profile, and policy identifiers are supported. Both variable fields sit inside the authenticated body of §8, so a modified value fails the tag rather than opening a session.

### 2.2 Body

The body follows the head immediately and is encoded as a structure under [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §4, in this order:

```text
field                      type                             size
descriptor_generation      u64                                 8
state                      u8, §15.4 discriminant              1
catalog_descriptor         structure of §5                    60
object_store_descriptor    structure of §6                    24
key_slot_descriptors       list<KeySlotDescriptorV1> of §7     4 + entries
migration_descriptor       optional<MigrationDescriptorV1>     1, plus 32 when present
descriptor_authentication  bytes[32], the tag of §8           32
```

A `state` outside the five allocated discriminants is rejected; it is never treated as an unknown but tolerable value.

`MigrationDescriptorV1` is present exactly when `state` is `MIGRATING` or `RECOVERING`, and is then exactly 32 bytes:

```text
field                        type       size
from_descriptor_version      u16           2
to_descriptor_version        u16           2
from_catalog_format_version  u16           2
to_catalog_format_version    u16           2
migration_generation         u64           8
checkpoint_id                bytes[16]    16
```

V1 defines no migration extension records, so the optional is either absent or exactly 33 bytes including its presence byte, and never variable in length.

## 3. Public fields

Permitted before unlock:

- fixed magic and version;
- suite/policy identifiers needed to select a supported reader;
- random vault identifier;
- opaque directory/file identifiers;
- bounded slot descriptors and KDF parameters;
- descriptor generation and transaction state;
- migration-required version numbers;
- authentication bytes that cannot be verified until a root candidate exists.

Forbidden:

- real/decoy label;
- filename, album, media type, count, date, location;
- user email/account name;
- plaintext catalog schema content;
- recovery secret or platform key bytes.

## 4. State machine

Proposed states:

```text
INITIALIZING
ACTIVE
MIGRATING
RECOVERING
DELETING
```

`ACTIVE` is the only ordinary openable state. Other states require a bounded recovery/migration flow and fail closed for normal feature access.

A state transition writes a new descriptor generation; it does not mutate authenticated fields in place.

## 5. Catalog descriptor

Conceptual fields:

```text
offset  size  field                          v1 value
0x00     2    catalog_format_version:u16     0x0001 through 0x0012
0x02     2    catalog_crypto_suite:u16       0x0001
0x04    16    opaque_catalog_path_id         random, never all zero
0x14     8    catalog_generation:u64
0x1C    32    catalog_header_commitment      BLAKE3-256
0x3C          end of catalog descriptor
```

The structure is exactly 60 bytes and carries no variable field. `catalog_format_version` must equal the value the catalog itself records, per [`CATALOG_SCHEMA_V1.md`](CATALOG_SCHEMA_V1.md) §2.

`catalog_header_commitment` commits to the first 16 bytes of the catalog database file, [ADR-0039](../adr/0039-freeze-the-catalog-header-commitment.md):

```text
catalog_header_commitment = BLAKE3-256(
    "CHUR\x00CATALOG\x00HEADER-COMMITMENT\x00V1" || catalog_file[0..16]
)
```

Under the engine of [ADR-0038](../adr/0038-adopt-sqlcipher-as-the-v1-catalog-engine.md) those bytes are the database's per-file salt: written once when the database is created, never rewritten, and plaintext by construction. The value is therefore stable across every ordinary catalog write, so a catalog transaction does not require a new descriptor generation, and it is not secret, so a descriptor readable before any credential exists discloses nothing by carrying it.

It is computed when the catalog is created and checked at every unlock, before the connection opens. It proves which file this descriptor belongs to; it does not prove the file's contents, which the engine's own per-page authentication covers, and it does not detect a rollback to an older copy of the same file, which `catalog_generation` above covers.

The catalog key is derived after root validation. The descriptor does not contain plaintext schema or SQLCipher passphrase.

## 6. Object-store descriptor

Conceptual fields:

```text
offset  size  field                            v1 value
0x00     2    object_store_format_version:u16  0x0001
0x02    16    opaque_root_path_id              random, never all zero
0x12     2    naming_profile_id:u16            0x0001
0x14     2    container_version_floor:u16      0x0001
0x16     2    container_version_ceiling:u16    0x0001 or 0x0002
0x18          end of object-store descriptor
```

The structure is exactly 24 bytes and carries no variable field. `container_version_floor` must be less than or equal to `container_version_ceiling`, and both carry values of the `container_version` namespace of [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §15.2. The floor is `0x0001`. The ceiling is `0x0001` or `0x0002`, and a reader refuses any other value as `UNSUPPORTED_VERSION`. A new vault records `0x0002`. Before the first container of version `0x0002` is written into a vault whose ceiling is `0x0001`, the writer raises the ceiling in one new descriptor generation, per [ADR-0066](../adr/0066-pad-object-containers-to-size-buckets.md). A build that reads only v1 containers therefore refuses the vault as a whole rather than one object at a time.

Physical paths are app-internal and resolved by the platform/storage adapter from opaque IDs.

## 7. Key-slot descriptors

Each entry declares only bounded information needed to attempt a slot. `KeySlotDescriptorV1` is a fixed 34-byte header followed by one length-prefixed body:

```text
offset  size             field                v1 value
0x00    16               slot_id              random, never all zero
0x10     1               slot_type:u8         allocated in CANONICAL_ENCODING_V1.md §15.4
0x11     1               reserved:u8          0x00
0x12     2               slot_version:u16     0x0001
0x14     2               wrap_suite_id:u16    0x0001
0x16     8               slot_generation:u64
0x1E     4               slot_body_length:u32
0x22     slot_body_length slot_body
```

`slot_body` carries both the public parameters and the wrapped-root payload or the platform envelope reference for that family. They are not alternatives at this level: one length-prefixed body always holds whichever of them the family defines. Its internal schema is selected by `slot_type` and owned by [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md), so the descriptor parser bounds and steps over a body it does not interpret without guessing its shape. [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) stays authoritative for slot behaviour and policy.

A `slot_type` that §15.4 does not allocate is rejected. V1 defines no safe forwarding for an unknown slot family, so an unknown value is never carried through a descriptor rewrite. `0x05` parses as an allocated family and is never attempted as an unlock method in v1.

Slot count, `slot_body_length`, and the total of all slot bodies are capped by §13. Duplicate `slot_id` values, and duplicate `(slot_id, slot_generation)` pairs, are rejected.

## 8. Descriptor authentication

After a candidate root is unwrapped, Rust derives a descriptor-authentication key and verifies the canonical descriptor body. This proves:

- the slot is bound to this vault;
- catalog/object descriptors were not substituted;
- generation/state fields are authentic;
- a wrong but structurally valid root is rejected.

The construction is a keyed authenticator. It encrypts nothing, so it has no separate AAD and no nonce: every field an AAD would carry is inside the authenticated input.

```text
DescriptorAuthKey = HKDF-SHA-256(
    IKM     = VaultRootSecret,
    label   = "chur/v1/root/descriptor-auth",
    context = vault_id,
    length  = 32
)
```

The label is registered in [`../security/KEY_HIERARCHY.md`](../security/KEY_HIERARCHY.md) §3; the extract and expand construction is [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §13. The key is stable for the life of the root secret. A new descriptor generation reuses it and does not derive a new one.

`descriptor_authentication` is exactly the last 32 bytes of the encoded descriptor and holds `descriptor_auth_tag`. The descriptor body is every byte before it:

```text
descriptor_body     = encoded_descriptor[0 .. descriptor_length - 32]
descriptor_auth_tag = encoded_descriptor[descriptor_length - 32 .. descriptor_length]

descriptor_auth_tag = BLAKE3-256-keyed(
    key   = DescriptorAuthKey,
    input =    "CHUR\x00VAULT\x00DESCRIPTOR-AUTH\x00V1"
            || descriptor_body
)
```

The domain tag is a fixed ASCII byte constant with no length prefix, per [`CANONICAL_ENCODING_V1.md`](CANONICAL_ENCODING_V1.md) §3 and §7. The output is 32 bytes and nothing follows it, so the trailing-byte rule of §13 still applies.

Authenticating the bytes as written, rather than a re-encoded field tuple, binds every field of §2 under one rule: magic, `descriptor_version`, `canonical_encoding_profile`, `crypto_policy_id`, `vault_id`, `descriptor_generation`, `state`, the catalog and object-store descriptors, every key-slot descriptor with its framing, and the optional migration descriptor. A field added by a later encoding profile is authenticated without a change to this section, and two implementations cannot disagree about field order.

The tag proves authenticity, not freshness. An older but authentic descriptor generation is a §10 problem, not an authentication failure.

Verification order:

1. reject an encoded descriptor shorter than the smallest body a v1 parser accepts plus 32 bytes;
2. parse and bound the body under §13, before any credential is used;
3. unwrap a candidate root from one key slot;
4. derive `DescriptorAuthKey` and recompute the tag over `descriptor_body`;
5. compare the 32 bytes in constant time;
6. accept the root and open a session only on equality.

On inequality the candidate root and every key derived from it are zeroized, no session opens, and the caller receives `AUTHENTICATION_FAILED`. A mismatch is never reported as `VAULT_CORRUPT`: a damaged descriptor and a wrong credential share one external failure, as required by [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §3. Steps 1 and 2 run before any credential is used and keep their own parser error codes.

Real and decoy identities hold independent root secrets, so a credential valid for the sibling vault fails here exactly as an invalid credential does. The two must stay indistinguishable:

- the tag comparison is constant time over all 32 bytes and never returns early;
- a failed slot unwrap is followed by the same derivation and tag computation over a random 32-byte substitute root, and the result is discarded, so the work performed does not depend on which step failed;
- the same candidate set is attempted in the same order for every attempt, whatever the outcome;
- every failure emits the same error code, the same safe metadata, and the same retry classification, and no log event names the failing step;
- retry pacing and lockout counters do not depend on which candidate failed.

Whole-device indistinguishability is not claimed; the residual signals are listed in [`../security/DECOY_VAULT.md`](../security/DECOY_VAULT.md) §5.

## 9. Initialization transaction

```text
create random vault ID/root
create encrypted catalog temp
create object-store directory temp
create at least one key slot temp
write descriptor generation 0 as INITIALIZING
fsync all components
verify slot and descriptor
write generation 1 ACTIVE
atomic install
```

A crash before `ACTIVE` must be recoverable or removable without exposing a partially trusted vault.

## 10. Generation and rollback

Local descriptor generations are strictly increasing. A lower generation discovered beside a newer authenticated catalog state is suspicious and must not be selected silently.

`catalog.catalog_generation` binds the descriptor to the freshness of its catalog:

1. A lock writes a new descriptor generation that records the catalog's current `catalog_generation` when the catalog is ahead of the descriptor.
2. Every unlock reads the catalog's `catalog_generation` after the catalog opens. If the value is lower than the descriptor's `catalog.catalog_generation`, the unlock stops with `VAULT_CORRUPT`. The catalog is then an older copy of the same file, and the header commitment of §5 cannot detect it.
3. If the value is higher, the session that wrote it stopped before its lock. The unlock records the higher value in a new descriptor generation before the session starts.

This check detects a catalog that is older than the last recorded lock or unlock. It does not detect a copy taken after the last recorded state, and it does not detect an older descriptor that is written back together with its catalog.

Sync and backup rollback protection is separate; a copied old but authentic standalone vault may require an external trusted checkpoint to detect.

## 11. Discovery and real/decoy handling

Each identity has an independent descriptor and random path ID. The descriptor does not identify its role.

Descriptors are found through the registry, which is the first thing the application reads and the only thing it reads before any credential exists:

- the registry is the `registry/` directory of [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §14.4. Each entry is one file holding one encoded `VaultDescriptorV1`;
- an entry is named with 32 lowercase hexadecimal characters and the suffix `.vd`. The 16 bytes come from the CSPRNG when the descriptor is first written and are unrelated to `vault_id`, to any key, and to creation order, so the name discloses nothing and two identities cannot be told apart by their filenames;
- the registry holds at most 2 entries; a third is `RESOURCE_LIMIT_EXCEEDED`. Two is the product maximum: one real identity and one decoy;
- the candidate set is every entry in the directory, ordered by filename bytes ascending. This is the fixed enumeration order §8 requires, and it depends on neither creation time, nor modification time, nor which candidate is real;
- an entry that fails the parser limits of §13 is skipped before any credential is used and its failure is attributed to no credential; it still counts toward the cap;
- one credential attempt evaluates every candidate before it returns, whatever the outcome. This section fixes which entries are enumerated and in what order; the password-candidate list and its cost belong to [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §8, which fixes every password attempt at two Argon2id derivations, padded with dummy derivations, whatever the registry holds, so the cost of an attempt never counts the entries.

An ordinary failure must not reveal which candidate matched, which the per-candidate constant-work rules of §8 already require.

## 12. Backup behavior

Portable backup includes:

- descriptor fields required for restore;
- portable password/recovery slots;
- catalog and object inventory;
- excludes device-bound Keystore/Keychain material.

Restore writes a new local platform slot after authenticating a portable slot.

## 13. Parser limits

- `descriptor_length` between 220 and 65536 inclusive. 220 is the smallest v1 descriptor: the 40-byte head of §2.1, a 148-byte body holding one key-slot descriptor whose body is the 16-byte minimum and an absent migration descriptor, and the 32-byte tag. §8 step 1 rejects anything shorter;
- `key_slot_descriptors` count between 1 and 16;
- `slot_body_length` between 16 and 4096, and the sum of all slot bodies at most 16384;
- every identifier is exactly 16 bytes and v1 carries no variable-length path or name, so no string length remains to cap;
- `migration_descriptor` exactly 32 bytes when present, and v1 defines no migration extension records;
- only `descriptor_version` `0x0001`, `canonical_encoding_profile` `0x0001`, `crypto_policy_id` `0x0001`, catalog format version `0x0001` through `0x000a`, `catalog_crypto_suite` `0x0001`, `object_store_format_version` `0x0001`, `naming_profile_id` `0x0001`, and `slot_version` `0x0001` are accepted;
- `wrap_suite_id` is `0x0002` for an `AndroidKeystoreSlotV1` and `0x0001` for every other family, per [`KEY_SLOT_BODIES_V1.md`](KEY_SLOT_BODIES_V1.md) §5. Any other pairing of `slot_type` and `wrap_suite_id` is rejected;
- generation arithmetic checked in `u64`, with `0xFFFFFFFFFFFFFFFF` rejected in every generation field so an increment always exists;
- nesting depth is 2, the head followed by one level of sub-descriptors, and v1 defines no deeper structure.

Reject trailing bytes and non-canonical encoding.

## 14. Required tests

- valid minimal recoverable descriptor;
- device-bound-only descriptor;
- maximum permitted slots;
- duplicate IDs/generations;
- wrong root/descriptor authentication;
- failed slot unwrap that still performs descriptor-authentication work;
- state transition crash at every step;
- stale generation;
- unsupported version/suite/profile;
- real/decoy external indistinguishability;
- backup restore without device slots;
- migration-required descriptor.
