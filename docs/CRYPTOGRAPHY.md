# Chur Cryptography

> **Status:** Proposed normative cryptographic design  
> **Audience:** Rust, mobile-platform, application, security, protocol, and audit contributors  
> **Last updated:** 2026-11-26\
> **Related:** [README](../README.md) · [Architecture](ARCHITECTURE.md)

Chur is a local-first encrypted media vault for Android and iOS. This document defines the cryptographic model that supports the product and system architecture: key ownership, key derivation, key wrapping, password processing, media encryption, integrity verification, platform-protected unlock, recovery, synchronization, and collection sharing.

The central rule is:

> **Rust owns the private cryptographic lifecycle. Android Keystore and iOS Keychain gate access to short root-key material. Kotlin, Compose, SwiftUI, UIKit, Room, DataStore, media players, and network clients never become independent owners of the vault protocol.**

This branch implements the internal post-quantum profile with native ABI 8.4. It requires MLKEM768-X25519 for recipient encryption and ML-DSA-65 for device signatures. The classical v1 sections below document the earlier protocol. Before public release, check compatibility with the final hybrid HPKE specification and complete device acceptance. [Internal profile](adr/0073-internal-post-quantum-profile.md) · [Release gates](assurance/RELEASE_GATES.md)

---

## 1. Normative language and document status

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** describe requirements for any implementation that claims compatibility with this design.

Individual statements are classified as **Decision**, **Invariant**, **Proposal**, **Deferred**, or **Non-goal**, defined once in [`README.md`](README.md#statement-classification). A **Decision** here is fixed unless replaced by an ADR and a migration plan, and **Deferred** means excluded from the initial local vault. The status of this document as a whole is in its header and uses the document-status vocabulary of the same file.

This file is normative for cryptographic responsibilities and security properties. It is not yet a byte-level interoperability specification. Dedicated [format specifications](README.md#formats) define the versioned encodings for:

```text
VaultDescriptorV1
KeySlotV1
CollectionKeyEnvelopeV1
ObjectKeyEnvelopeV1
ChurObjectV1
CatalogSchemaV1
BackupManifestV1
DeviceOperationV1
CollectionGrantV1
```

If this document conflicts with an audited, versioned byte-level specification, the newer specification and its migration ADR take precedence.

---

## 2. Scope

This document covers:

- cryptographic primitives and their intended purposes;
- generation, derivation, wrapping, storage, rotation, and destruction of keys;
- password-derived key-encryption keys;
- Android Keystore and iOS Keychain unlock slots;
- recovery and peer-device slots;
- independent real and decoy vault identities;
- security-collection and per-object envelope encryption;
- independent authenticated media chunks;
- encrypted manifests, metadata, previews, thumbnails, and final commits;
- complete-object verification and corruption handling;
- private-catalog encryption;
- encrypted backup, synchronization, and collection sharing;
- secret handling across Rust/KMP/platform boundaries;
- test vectors, fuzzing, migration, and audit requirements.

This document does not define:

- user-interface appearance;
- full application state and navigation architecture;
- exact SQL schema;
- server API endpoints;
- media codec implementation;
- byte-exact object framing;
- a claim of protection from a compromised unlocked operating system;
- cryptographically undetectable hidden volumes.

---

### Platform ingress exception

The iOS Share Extension uses the temporary receiving transport from [ADR-0064](adr/0064-receive-system-shares.md). In the [internal post-quantum profile](adr/0073-internal-post-quantum-profile.md), the app stores a separate X-Wing seed in its own device-local Keychain. The extension receives the public key and seals a fresh 256-bit item key with X-Wing HPKE, HKDF-SHA256 and ChaCha20-Poly1305. AES-256-GCM protects metadata and ordered content chunks. The app authenticates the complete envelope before native import. [Apple host contract](../apps/iosApp/README.md#incoming-system-shares)

## 3. Cryptographic ownership boundary

### 3.1 Rust MUST own

Rust is the canonical owner of:

- all random private key generation;
- password KDF execution and parameter validation;
- key-slot parsing, creation, upgrade, and deletion;
- root, collection, object, stream, catalog, search, recovery, and identity keys;
- HKDF labels and derivation rules;
- AEAD nonce construction and uniqueness policy;
- key wrapping and unwrapping;
- encrypted manifest, metadata, chunk, and final-commit construction;
- object completeness and integrity decisions;
- cryptographic migrations;
- canonical sync and sharing payload construction;
- redaction rules for secret-bearing errors and debug output.

### 3.2 KMP MAY own

KMP may own:

- user-facing use cases and UDF state;
- opaque session, object, collection, and reader handles;
- short-lived UI projections returned by Rust;
- progress and cancellation state;
- public-shell data;
- platform orchestration;
- ciphertext-only transfer scheduling.

KMP MUST NOT define a second cryptographic format, derive private keys, construct nonces, serialize private metadata for persistence, or decide that an object is complete.

### 3.3 Platform services MAY own

Android Keystore and iOS Keychain may own or protect:

- non-exportable platform wrapping keys;
- device-bound unlock secrets;
- access-control policy requiring user presence, biometric authentication, or device passcode;
- platform-specific ciphertext envelopes for the short vault root secret.

They MUST NOT be used as streaming encryptors for photo, audio, or video payloads.

---

## 4. Security goals

The design aims to provide:

1. **Confidentiality at rest** for media bytes, metadata, filenames, EXIF, GPS, album membership, thumbnails, previews, waveforms, OCR, search indexes, and private settings.
2. **Integrity and authenticity** for every independently readable encrypted record.
3. **Truncation detection** for complete objects through an authenticated final commit.
4. **Context binding** so a valid chunk, key envelope, manifest, or grant cannot be silently transplanted into a different object or purpose.
5. **Blast-radius reduction** through independent random keys per vault, security collection, and media object.
6. **Password independence** so changing a password does not require re-encrypting media.
7. **Collection-level sharing** without public-key encryption of bulk media.
8. **Random access** for large videos and audio without whole-file decryption.
9. **Crash consistency** for import, migration, key rotation, and catalog updates.
10. **Fail-closed parsing** for unsupported versions, invalid lengths, invalid parameters, stale handles, and corrupted records.
11. **Cross-platform determinism** for protocol bytes and test vectors.
12. **Cryptographic agility without negotiation downgrade**, using explicit versioned suites controlled by local policy.

---

## 5. Non-goals and unavoidable limitations

Chur does not claim to prevent:

- plaintext observation after unlock by a compromised OS, kernel, root/jailbreak tooling, debugger, runtime instrumentation, or memory inspection;
- malicious accessibility services, keyboards, clipboard managers, or screen-capture malware from observing user input or displayed content;
- photography of the screen by an external camera;
- traffic analysis, object-count leakage, or access-pattern leakage without optional batching;
- ciphertext-size leakage beyond the size bucket: a container of version `0x0002` stores each object in a size bucket ([`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §18, [ADR-0066](adr/0066-pad-object-containers-to-size-buckets.md)), so its file length discloses the bucket, the chunk size, and an empty object, but not the exact object size; a v1 container written before that version discloses its exact size;
- physical secure overwrite on flash storage with wear levelling, copy-on-write, snapshots, or cloud backups;
- retention of plaintext or keys by an authorized sharing recipient;
- rollback to an old user-controlled backup unless the user compares trusted generations or device log heads;
- detection of every malicious-server omission without transparency or out-of-band consistency mechanisms;
- an undetectable real vault in the presence of forensic storage analysis.

The primary guarantee is confidentiality and integrity of private data while the vault is locked and the attacker obtains application storage, a remote ciphertext store, or an encrypted backup without a valid unlocking secret.

---

## 6. Cryptographic profile v1

This table describes the historical v1 profile. ADR-0073 replaces its recipient and signature algorithms in internal builds.

| Purpose | Chur v1 direction | Status |
| --- | --- | --- |
| Media, metadata, manifests, commits, Rust-owned key envelopes | XChaCha20-Poly1305 | Accepted |
| Password to KEK | Argon2id v1.3 | Accepted |
| Key derivation and domain separation | HKDF-SHA-256 | Accepted |
| Random generation | operating-system CSPRNG through Rust `getrandom` | Accepted |
| Ordered ciphertext commitment | BLAKE3, authenticated by an AEAD-protected final commit | Proposed |
| Android platform root wrapping | Android Keystore AES-256-GCM | Accepted |
| iOS device unlock secret | Keychain-protected random secret with access control | Accepted |
| Collection recipient encryption | RFC 9180 HPKE: X25519/HKDF-SHA-256/ChaCha20-Poly1305 | Implemented; independent sharing audit remains open |
| Device operation signatures | Ed25519 | Implemented for sync and collection sharing |
| Optional corporate/FIPS-oriented local suite | AES-256-GCM | Deferred |
| Optional nonce-misuse-resistant suite | AES-256-GCM-SIV | Deferred |
| Optional hybrid post-quantum recipient | X25519 plus ML-KEM profile | Deferred |

The v1 implementation MUST NOT allow a server, backup file, user setting, or untrusted input to select an arbitrary algorithm. The local policy maps a recognized suite identifier to a fixed implementation.

---

## 7. Primitive rationale

### 7.1 XChaCha20-Poly1305

XChaCha20-Poly1305 is the default local AEAD because it provides:

- a 256-bit key;
- a 192-bit nonce;
- authenticated encryption suitable for independent records;
- efficient software performance on mobile CPUs;
- a large nonce space compatible with random per-stream prefixes;
- mature pure-Rust implementations.

The large nonce does not remove the uniqueness requirement. A `(key, nonce)` pair MUST never repeat.

Chur uses XChaCha20-Poly1305 for:

- encrypted object manifests;
- independent content chunks;
- metadata and derived assets;
- final commit records;
- password and recovery key slots;
- root-to-collection envelopes;
- collection-to-object envelopes;
- private protocol records where a standard external protocol does not prescribe another AEAD.

### 7.2 AES-256-GCM

AES-256-GCM is not the default Rust media suite. It may later be added for environments where hardware AES acceleration, external interoperability, or certification requirements justify the additional implementation and audit surface.

Any future AES-GCM profile MUST define deterministic nonce construction with strict uniqueness under each key. Random 96-bit nonces under a long-lived global key are not an acceptable Chur construction.

### 7.3 AES-256-GCM-SIV

AES-GCM-SIV may later be used where resilience to accidental nonce reuse outweighs its additional complexity and performance characteristics. It is not a substitute for correct nonce management.

### 7.4 Argon2id

Argon2id converts a user password into a key-encryption key. It MUST NOT be used to derive content keys directly.

Argon2id provides memory hardness and a hybrid resistance profile intended to reduce the efficiency of offline password guessing. Its security depends on meaningful memory/time parameters and strict resource bounds.

### 7.5 HKDF-SHA-256

HKDF provides explicit domain separation between cryptographic purposes. A key derived for content MUST NOT be reused for metadata, manifests, thumbnails, final commits, search, identity wrapping, or catalog encryption.

### 7.6 BLAKE3

BLAKE3 is proposed for fast incremental commitments over ordered ciphertext records and optional keyed local fingerprints.

An unkeyed BLAKE3 digest is not an authenticator. Chur only treats an unkeyed commitment as security-relevant when the commitment itself is inside an AEAD-authenticated record.

### 7.7 HPKE and Ed25519

HPKE encrypts a small collection key to a recipient. Ed25519 authenticates the sender or device operation. These are separate responsibilities:

```text
HPKE
    confidentiality to recipient

Ed25519
    sender/device authenticity and operation integrity
```

Bulk media remains encrypted under symmetric object keys.

---

## 8. Algorithm registry and crypto agility

Every persistent cryptographic record MUST carry or inherit an explicit version and suite identifier.

The registry will distinguish at least:

```text
local_aead_suite
password_kdf_profile
hkdf_profile
commitment_profile
platform_slot_type
recipient_kem
recipient_kdf
recipient_aead
signature_suite
canonical_encoding_version
```

Rules:

1. Unknown suites MUST fail closed.
2. Deprecated suites MAY be read only by a migration path explicitly allowed by local policy.
3. New writes MUST use the current approved suite.
4. A server MUST NOT negotiate a weaker suite.
5. User-visible settings MUST NOT expose arbitrary cryptographic combinations.
6. A suite change requires test vectors, migration rules, and an ADR.
7. The suite identifier MUST be covered by AEAD AAD or an authenticated enclosing record.
8. Algorithm confusion between local XChaCha and RFC-defined HPKE ChaCha20-Poly1305 MUST be impossible through distinct record types and suite registries.

The byte-level registry is deferred to the format specifications.

---

## 9. Randomness

All production random values MUST originate from the operating-system CSPRNG through Rust.

Required random values include:

- `VaultRootSecret`;
- `SecurityCollectionKey`;
- `ObjectKey`;
- recovery secrets;
- device identity private keys;
- salts;
- XChaCha nonces and nonce prefixes;
- opaque vault, collection, object, stream, operation, and slot identifiers;
- temporary object names;
- padding where enabled.

Requirements:

- no fallback PRNG;
- no timestamps, UUID v1 values, counters, device identifiers, passwords, filenames, or content hashes as key material;
- RNG failure MUST abort the operation;
- deterministic RNGs MUST be restricted to tests and test-vector generation;
- test-only deterministic RNG injection MUST be impossible in production builds;
- random identifiers MUST be independent from plaintext content.

Random keys are 32 bytes unless a versioned external primitive requires another size.

---

## 10. Canonical encoding and context construction

Cryptographic inputs that cross process, platform, backup, or network boundaries MUST have one canonical binary encoding.

Ad hoc concatenation such as:

```text
label || objectId || chunkIndex
```

is forbidden unless every field is fixed-width and the exact order is specified.

Canonical tuple bytes, including the encoding of the leading domain tag, are defined by [`format/CANONICAL_ENCODING_V1.md`](format/CANONICAL_ENCODING_V1.md) §7.1, which governs them under the authority hierarchy in [`README.md`](README.md). Every `CanonicalTuple(...)` in this document is that construct.

Independently of the encoding profile, JSON and platform-default serialization MUST NOT be used for key material, nonces, AEAD AAD, signatures, or key envelopes, and enum identifiers MUST be used instead of localized strings. The profile itself remains **Proposed** until test vectors are published.

All protocol integers MUST use one specified byte order. The current direction is unsigned big-endian for values embedded in nonce/AAD tuples and canonical binary fields.

---

## 11. Secret type model

Rust MUST use explicit secret-bearing types rather than raw `Vec<u8>` values throughout the core.

Conceptual types:

```rust
struct VaultRootSecret(SecretBytes<32>);
struct SecurityCollectionKey(SecretBytes<32>);
struct ObjectKey(SecretBytes<32>);
struct StreamKey(SecretBytes<32>);
struct PasswordKek(SecretBytes<32>);
struct RecoverySecret(SecretBytes<32>);
struct DeviceIdentityPrivateKey(SecretBytes<32>);
```

Requirements:

- secret types MUST zeroize on drop where the language/runtime permits;
- secret types MUST NOT derive ordinary `Debug`;
- `Display`, serialization, cloning, equality, and conversion MUST be explicitly reviewed;
- secret-bearing errors MUST be redacted;
- key material MUST NOT be included in panic messages, tracing spans, metrics, analytics, or crash reports;
- only the narrow FFI adapter may convert platform buffers into secret types;
- immutable language strings are not acceptable containers for binary keys;
- copies MUST be minimized and bounded;
- secret types MUST NOT expose hash implementations that could leak into collections or logs accidentally.

Useful implementation candidates include `zeroize`, `secrecy`, and `subtle`, subject to dependency review.

---

## 12. Key hierarchy

The key hierarchy separates recovery/access control from bulk data encryption.

```text
Password
    │
    └── Argon2id
            │
            ▼
       PasswordKEK ─────────────┐
                                │
Android Keystore slot ──────────┼──► VaultRootSecret
                                │
iOS Keychain slot ──────────────┤
                                │
Recovery slot ──────────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 │                    │                    │
                 ▼                    ▼                    ▼
        CatalogDatabaseKey     Root domain keys     IdentityWrapKey
                                      │
                                      ▼
                         SecurityCollectionKey[epoch]
                                      │
                                      ▼
                                  ObjectKey
                                      │
           ┌───────────────┬──────────┼───────────┬──────────────┐
           ▼               ▼          ▼           ▼              ▼
      ManifestKey     ContentKey  MetadataKey  PreviewKey  FinalCommitKey
```

Important distinctions:

- `VaultRootSecret` is random, not password-derived.
- Security-collection keys are random, not deterministically derived from the root.
- Object keys are random, not deterministically derived from collection keys.
- Stream/purpose keys are derived from the object key with HKDF.
- Password, device, and recovery credentials wrap or release only the root secret.

---

## 13. HKDF construction and domain labels

All derived keys use HKDF-SHA-256 with explicit domain separation.

Conceptually:

```text
PRK = HKDF-Extract(
    salt = 32 zero bytes,
    IKM  = parent secret
)

DerivedKey = HKDF-Expand(
    PRK,
    info = CanonicalTuple(
        "CHUR\x00KDF\x00INFO\x00V1",
        purpose_label,
        context_fields
    ),
    length = 32
)
```

The extract salt is exactly 32 bytes of `0x00`, the RFC 5869 default for HKDF-SHA-256 when no salt is supplied. It is the same value for every vault, platform, profile, and derivation, and it MUST NOT vary; all domain separation is carried by `info`. In the `info` tuple, `purpose_label` is one of the labels registered in [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3, encoded as a UTF-8 string, and `context_fields` expands to one element per value listed for that label in the context registry of §3 there, which is the only definition of a context element list. Tuple bytes follow [`format/CANONICAL_ENCODING_V1.md`](format/CANONICAL_ENCODING_V1.md) §7.1.

Every domain label, the key it derives, its input key, its output length, and its context element list are registered in [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3. That table is the only definition of a label string. Where this document writes out a derivation, it may restate the label that derivation consumes; the strings must then be identical to the registry.

Requirements:

- context fields include the relevant opaque identifiers and epochs;
- labels follow the registry rules in [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3, including that a label is never redefined and that a changed label is a new label plus a migration;
- direct use of a parent secret in multiple AEAD contexts is forbidden;
- derived keys MUST NOT be promoted back to parent-key status.

---

## 14. Vault root secret

`VaultRootSecret` is a random 32-byte value generated once for each cryptographically independent vault identity.

It MUST:

- be generated in Rust from the OS CSPRNG;
- never be persisted in plaintext;
- never be used directly to encrypt media chunks;
- never be used directly as an SQLCipher passphrase without a dedicated HKDF derivation;
- never leave the process except through a narrowly reviewed platform wrap/release operation;
- be held only while the vault session is unlocked;
- be zeroized when the session locks;
- be re-created only when establishing a new independent vault identity.

Changing a password, biometric configuration, platform slot, or recovery slot MUST NOT change the root secret unless the user explicitly creates a new vault and migrates data.

---

## 15. Root-derived domain keys

The root secret derives independent keys for root-level purposes.

At minimum:

| Derived key | Purpose |
| --- | --- |
| `CollectionEnvelopeKey` | wraps random security-collection keys |
| `CatalogDatabaseKey` | opens the Rust-owned private catalog |
| `CatalogRecordRootKey` | protects catalog records if field/record encryption is used |
| `SearchKey` | protects private search structures and keyed fingerprints |
| `IdentifierKey` | optional keyed opaque-identifier derivations where required |
| `PrivateSettingsKey` | protects private settings outside the catalog if any exist |
| `IdentityWrapKey` | wraps device identity private keys |
| `BackupManifestKey` | authenticates a Chur-native backup package manifest |

A derived root-domain key MUST be scoped to one vault ID through its HKDF context.

---

## 16. Key slots overview

A key slot is an independent mechanism capable of releasing or unwrapping one `VaultRootSecret`.

Planned slot types:

```text
PasswordSlotV1
AndroidKeystoreSlotV1
AppleKeychainSlotV1
RecoverySlotV1
PeerDeviceSlotV1        future
```

Every slot MUST include or inherit:

```text
slot_id
slot_type
slot_version
vault_id
identity_id
suite/profile identifiers
public parameters
nonce or platform envelope metadata
wrapped root secret or platform reference
generation
```

Slot metadata is untrusted before successful authentication. Parsers MUST validate all lengths, enum values, and resource parameters before allocation or KDF execution.

Deletion or rollback of slots by an attacker may cause denial of service. Confidentiality does not imply availability.

---

## 17. Password encoding

Password-to-byte conversion MUST be stable across Android, iOS, CLI, and future clients.

The normative profile is [`security/PASSWORD_PROFILE.md`](security/PASSWORD_PROFILE.md) §3, which governs on conflict.

Chur v1 direction:

- capture the exact Unicode scalar sequence entered by the user;
- do not trim whitespace;
- do not case-fold;
- do not perform locale-sensitive transformations;
- do not silently normalize NFC, NFKC, NFD, or NFKD;
- encode the resulting sequence as UTF-8;
- persist a password-encoding profile identifier in the slot;
- cap the encoded input length before Argon2 allocation.

The no-normalization rule avoids silently mapping distinct passwords to one value. It means visually similar Unicode sequences may represent different passwords. The UI SHOULD warn against unusual combining sequences and MUST require confirmation when creating or changing a password.

The current proposed encoded-password bounds are:

```text
minimum: 1 byte
maximum: 1024 bytes
```

These constants require final review before the format is frozen.

KMP/Swift UI code will necessarily hold user-entered text briefly. It SHOULD convert to a mutable UTF-8 buffer as soon as practical, clear that buffer best-effort after the FFI call, disable clipboard/autofill behaviors according to product policy, and avoid retaining password values in ViewModel state, saved state, analytics, or crash reports.

---

## 18. Password slot and Argon2id

### 18.1 Derivation

```text
Password bytes
    ↓
Argon2id(
    password,
    random salt,
    memory cost,
    time cost,
    parallelism,
    output length = 32
)
    ↓
PasswordKEK
```

`PasswordKEK` wraps the random vault root secret with XChaCha20-Poly1305.

### 18.2 Mobile creation profile

The creation profile is frozen in [`security/PASSWORD_PROFILE.md`](security/PASSWORD_PROFILE.md) §4, which governs it under the authority hierarchy in [`README.md`](README.md): Argon2id version `0x13`, 65536 KiB of memory, 3 iterations, parallelism 1, a 16-byte random salt, and 32 bytes of output. That floor is also the v1 default. Calibration MAY raise memory or iterations inside the §18.3 bounds and MUST NOT lower any parameter.

A device that cannot allocate the memory floor MUST NOT write a password slot and MUST NOT unlock one. It fails with `KDF_MEMORY_UNAVAILABLE`; v1 defines no reduced profile, so one password derives one key on every supported device. The rule and its rationale are `PASSWORD_PROFILE.md` §6.

### 18.3 Hard validation bounds

Before Argon2 execution, implementations MUST validate:

- password byte length;
- salt length;
- memory cost lower and upper bounds;
- time-cost lower and upper bounds;
- parallelism lower and upper bounds;
- output length exactly 32 bytes;
- Argon2 version and variant;
- integer multiplication/size overflow.

Untrusted files and servers MUST NOT force arbitrary Argon2 resource consumption.

Parser safety bounds, frozen for v1 and checked before Argon2 starts:

```text
memory:      64 MiB minimum for newly created v1 slots
             512 MiB hard maximum accepted by v1 parser
iterations:  3 minimum for newly created v1 slots
             10 hard maximum accepted by v1 parser
parallelism: 1–4
salt:        16–32 bytes
```

Legacy or accessibility profiles, if needed, require explicit profile identifiers and migration policy rather than silent weakening.

### 18.4 Root wrapping

Conceptually:

```text
slot_nonce = random 24 bytes
slot_aad   = CanonicalTuple(
    "CHUR\x00SLOT\x00PASSWORD\x00V1",
    vault_id,
    identity_id,
    slot_id,
    slot_generation,
    password_profile_id,
    Argon2 public parameters
)

wrapped_root = XChaCha20Poly1305.Encrypt(
    key       = PasswordKEK,
    nonce     = slot_nonce,
    plaintext = VaultRootSecret,
    aad       = slot_aad
)
```

A separate password verifier SHOULD NOT be stored unless independently justified. Successful AEAD unwrap followed by authenticated vault-descriptor validation is sufficient to identify a valid credential. That validation is a keyed BLAKE3-256 authenticator under `chur/v1/root/descriptor-auth`, frozen in [`format/VAULT_DESCRIPTOR_V1.md`](format/VAULT_DESCRIPTOR_V1.md) §8, which governs it under the authority hierarchy in [`README.md`](README.md).

### 18.5 Password changes

Changing a password MUST:

1. unlock the existing root secret using a valid slot;
2. derive a new `PasswordKEK` with a fresh random salt and current parameters;
3. create a new slot generation;
4. durably write and fsync the new slot set;
5. atomically activate the new descriptor;
6. remove obsolete local slot envelopes according to backup/recovery policy;
7. leave media, collection keys, and object keys unchanged.

An old backup may still contain an old password slot. Chur MUST communicate that password changes do not retroactively rewrite external backups.

---

## 19. Android Keystore slot

Android Keystore protects a short root-secret envelope with a non-exportable platform key.

Recommended direction:

```text
Keystore key:
    algorithm: AES
    size:      256 bits
    mode:      GCM
    purpose:   encrypt/decrypt
    auth:      user-authentication policy

plaintext wrapped by platform:
    VaultRootSecret (32 bytes)
```

Requirements:

- generate the platform key in Android Keystore;
- prefer hardware-backed TEE support;
- offer StrongBox only as an optional stricter profile with explicit fallback handling;
- use a fresh 96-bit GCM nonce for every new root envelope;
- bind the slot AAD required by [`security/KEY_SLOTS.md`](security/KEY_SLOTS.md) §2 through `Cipher.updateAAD` on every wrap and every unwrap, so a superseded slot generation cannot be replayed under the same Keystore key. The binding is not optional; an adapter that cannot carry AAD MUST move the binding into an authenticated enclosing record under §8 rule 7 rather than omit it;
- store only the ciphertext, nonce, key alias/reference, generation, and public policy metadata outside Keystore;
- never use the Keystore key for media chunks;
- treat biometric authentication as authorization to use the key, not as key material;
- retain a password or recovery slot for recoverable vaults;
- handle permanent key invalidation without data loss when a portable slot exists.

The platform alias MUST NOT contain a user filename, real/decoy label, album name, or other private semantic data.

A platform unwrap returns the root secret to the process. Android Keystore protects the non-exportable Keystore key, not an already unlocked Rust process.

---

## 20. iOS Keychain slot

The preferred iOS design stores a random device unlock secret in Keychain and uses it to unwrap the root secret in Rust.

```text
Keychain-protected DeviceUnlockSecret
    ↓
HKDF-SHA-256 under `chur/v1/slot/apple-device-kek`
    ↓
AppleDeviceKEK
    ↓
XChaCha20-Poly1305 unwrap
    ↓
VaultRootSecret
```

```text
AppleDeviceKEK = HKDF-SHA-256(
    IKM     = DeviceUnlockSecret,
    label   = "chur/v1/slot/apple-device-kek",
    context = vault_id:bytes[16], slot_id:bytes[16], slot_generation:u64,
    length  = 32
)
```

The label is registered in [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3 and the extract and expand construction is §13. Every context element is a field of [`format/VAULT_DESCRIPTOR_V1.md`](format/VAULT_DESCRIPTOR_V1.md) §2 and §7, so a reader reproduces the derivation from a parsed descriptor, and `vault_id` alone separates a real vault from its decoy.

This keeps the portable Rust slot format explicit while Keychain controls release of the device secret.

Recommended Keychain direction:

```text
accessibility:
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly

access control default:
    userPresence

strict optional mode:
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    biometryCurrentSet
```

Requirements:

- store only short random secret material in Keychain;
- use `ThisDeviceOnly` for device-bound slots;
- require a recoverable password/recovery slot before enabling an invalidation-prone strict profile;
- never use Secure Enclave or Keychain as a streaming media cipher;
- treat LocalAuthentication as an access-control gate, not a deterministic key source;
- avoid synchronizable Keychain items for device-bound vault slots;
- use an opaque account/service identifier without private semantic data;
- delete and recreate the device slot when access-control policy changes;
- handle biometric/passcode changes and Keychain access failures explicitly.

A direct Keychain item containing `VaultRootSecret` is technically possible, but the device-secret-plus-Rust-envelope model is preferred for consistent slot versioning, rewrapping, and testability.

---

## 21. Recovery slot

A recovery secret is a high-entropy random value, not a user-chosen backup password.

```text
RecoverySecret = random 32 bytes
RecoveryKEK    = HKDF-SHA-256(
    parent  = RecoverySecret,
    purpose = "chur/v1/recovery/root-envelope",
    context = vault_id:bytes[16], slot_id:bytes[16], slot_generation:u64
)
```

`RecoveryKEK` wraps `VaultRootSecret` with XChaCha20-Poly1305.

Requirements:

- generate the secret in Rust;
- display/export it only through an explicit recovery flow;
- represent it with a versioned checksum-protected encoding, such as a mnemonic or QR payload;
- preserve a canonical binary 32-byte value underneath the presentation;
- never upload plaintext recovery material;
- require user confirmation that recovery material was saved;
- support rotation by creating a new recovery slot before deleting the previous slot;
- make loss semantics explicit.

A mnemonic word list or QR encoding is presentation-layer work and does not alter the cryptographic secret.

---

## 22. Future peer-device slot

A future device may receive access through an authenticated key agreement rather than the user's password.

A peer-device slot may contain:

- recipient device public-key identifier;
- sender device identity;
- HPKE encapsulation;
- encrypted root or collection bootstrap secret;
- permissions and expiry;
- sender signature;
- operation-log reference.

Root-level peer-device distribution has a larger blast radius than collection-level sharing and MUST require a separate protocol review.

---

## 23. Real and decoy vault identities

Real and decoy vaults MUST be cryptographically independent.

```text
Real credential
    ↓
Real VaultRootSecret
    ↓
Real root-domain keys
    ↓
Real catalog and objects

Decoy credential
    ↓
Decoy VaultRootSecret
    ↓
Decoy root-domain keys
    ↓
Decoy catalog and objects
```

They MUST NOT share:

- root secrets;
- password KEKs;
- platform key aliases or Keychain item identifiers;
- recovery secrets;
- collection keys;
- object keys;
- private catalog databases;
- object-key envelopes;
- encrypted search indexes;
- thumbnail, preview, waveform, or playback caches;
- session generations;
- private navigation state;
- sync identities or accounts unless explicitly designed and disclosed.

The unlock result exposed to ordinary application features is an opaque `VaultSessionHandle`, not an `isDecoy` boolean.

Where multiple password identities coexist, implementations MUST use the same Argon2 profile and uniform high-level error behavior. Every unlock attempt that uses a password MUST run the same constant number of Argon2id derivations, padded with dummy derivations, as required by [`security/KEY_SLOTS.md`](security/KEY_SLOTS.md) §8. One derivation cannot be reused against a second slot: each slot carries its own random salt, so its Argon2id output is salt-bound. This equalizes the derivation cost of an attempt; it does not create an undetectable hidden volume, and the residual signals are listed in [`security/DECOY_VAULT.md`](security/DECOY_VAULT.md) §5.

Chur describes this feature as **Decoy Vault** or **coercion-resistant UX**, not cryptographic plausible deniability.

---

## 24. Security collections and albums

A security collection is a cryptographic key domain. An album is a user-facing grouping.

They are not automatically the same concept.

```text
SecurityCollection
    unit of sharing, membership, epoch, and key rotation

Album
    logical metadata relation; an object may appear in multiple albums
```

The initial local vault MAY use one private security collection while supporting many albums.

A new security collection is justified by:

- different sharing membership;
- different access policy;
- a family/team space;
- independent key rotation;
- a separately recoverable domain;
- another vault identity.

Each security collection receives a random 32-byte key and a monotonic or otherwise unambiguous epoch.

---

## 25. Collection-key envelope

A collection key is random and wrapped by a root-derived envelope key.

The record layout, the wrapping-key derivation, the AAD tuple, the nonce placement, and the generation rules are frozen in [`format/COLLECTION_KEY_ENVELOPE_V1.md`](format/COLLECTION_KEY_ENVELOPE_V1.md), which governs them under the authority hierarchy in [`README.md`](README.md).

Collection keys MUST NOT be deterministically derived from the root. Random collection keys can be shared, rotated, and rewrapped independently.

---

## 26. Collection epochs and rotation

Each collection key belongs to an epoch.

```text
CollectionKey(epoch = 1)
CollectionKey(epoch = 2)
CollectionKey(epoch = 3)
```

On membership change or compromise:

1. generate a new random collection key;
2. increment the epoch;
3. use the new epoch for new object envelopes;
4. rewrap every active object key of the collection to the new epoch; ownership, resumption, and the completion bound are normative in [`sync/REVOCATION.md`](sync/REVOCATION.md) §3.1, and rewrap MUST complete before the revocation is presented as complete;
5. distribute only the new epoch to current members;
6. record the change in the signed operation log when sync exists.

A rewrap deletes the earlier envelopes of the object in the transaction that commits the new one, and the completed rotation truncates the WAL. A rewrap keeps the object key, so after a completed rotation the owning device re-encrypts each rewrapped or trashed object under a fresh object key in a background operation that starts after unlock, per [`sync/REVOCATION.md`](sync/REVOCATION.md) §3.2 and [ADR-0069](adr/0069-re-encrypt-objects-after-revocation.md).

Revocation cannot remove plaintext or keys already copied by a former authorized recipient.

---

## 27. Object keys

Every media object receives an independent random 32-byte `ObjectKey`.

An object key protects one logical object and its derived streams through domain-separated subkeys.

Benefits:

- compromise of one object does not expose other objects;
- moving an object between collections requires only key-envelope changes;
- password changes do not touch media;
- collection rotation rewraps small keys rather than gigabytes;
- deletion can destroy local key envelopes without rewriting ciphertext;
- backup and repair can reason about objects independently.

An object key MUST NOT be:

- derived from a filename;
- derived from a content hash;
- reused for another object;
- stored in plaintext in the catalog;
- exposed to KMP or platform media APIs;
- used directly for multiple semantic purposes without HKDF.

---

## 28. Object-key envelope

The object-key envelope is separate from the immutable media container.

This separation prevents a circular dependency and allows collection changes without modifying media ciphertext.

The record layout, the wrapping-key derivation, the AAD tuple, the nonce placement, and the generation rules are frozen in [`format/OBJECT_KEY_ENVELOPE_V1.md`](format/OBJECT_KEY_ENVELOPE_V1.md), which governs them under the authority hierarchy in [`README.md`](README.md). The AAD binds `vault_id`, `collection_id`, `collection_epoch`, `object_id`, `suite_id`, and `envelope_generation` in that order; it does not bind `encoding_profile`, and no `object_key_version` field exists in v1.

One object MAY have multiple envelopes when authorized in multiple security collections. Each envelope wraps the same object key under a different collection domain.

The object container MUST NOT embed the only copy of the wrapped object key in a way that forces bulk re-encryption during collection changes.

---

## 29. Object stream keys

The object key derives independent keys for each stream and purpose.

```text
ObjectKey
├── ManifestKey
├── ContentKey
├── MetadataKey
├── ThumbnailKey
├── PreviewKey
├── PosterFrameKey
├── WaveformKey
├── OcrKey
├── EmbeddingKey
└── FinalCommitKey
```

`LocalFingerprintKey` is not an object-domain key. It is root-derived under `chur/v1/root/local-fingerprint`, because a fingerprint computed under a per-object random key can never match two objects with identical content, which is the only purpose the key has. See [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3.

Context MUST include at least:

```text
object_id
stream_kind
stream_revision
```

The exact element list of every object-domain label is frozen in the context registry of [`security/KEY_HIERARCHY.md`](security/KEY_HIERARCHY.md) §3, which governs it under the authority hierarchy in [`README.md`](README.md).

A new revision of metadata, preview, thumbnail, waveform, or other mutable stream MUST derive a revision-scoped key or at minimum receive a fresh nonce prefix under a context-bound key. The preferred design includes the revision in HKDF context and also uses fresh nonces.

Content originals are immutable after commit. A transformed or replaced original becomes a new content revision or a new object according to product semantics.

---

## 30. Encrypted object model

The encrypted object is an immutable sequence of authenticated records.

Conceptual `ChurObjectV1`:

```text
┌─────────────────────────────────────┐
│ Public preamble                     │
│ magic / version / suite / lengths   │
├─────────────────────────────────────┤
│ Encrypted immutable manifest        │
├─────────────────────────────────────┤
│ Encrypted chunk record 0            │
├─────────────────────────────────────┤
│ Encrypted chunk record 1            │
├─────────────────────────────────────┤
│ ...                                 │
├─────────────────────────────────────┤
│ Encrypted chunk record N            │
├─────────────────────────────────────┤
│ Encrypted authenticated final commit│
└─────────────────────────────────────┘
```

The public preamble is minimal and contains no private filename, MIME type, dimensions, date, duration, album, path, GPS, or user-visible object identifier.

The object-key envelope is stored separately in the private catalog or an envelope store.

---

## 31. Public preamble

The preamble provides only the information needed to parse and bound the container.

Candidate fields:

```text
magic
container_format_version
local_aead_suite_id
canonical_encoding_version
encrypted_manifest_length
record_layout_version
```

Requirements:

- fixed maximum size;
- strict magic and version validation;
- strict length bounds before allocation;
- no user metadata;
- no algorithm negotiation beyond recognized local policy;
- no plaintext total media size unless a later explicit leakage tradeoff is approved;
- unknown flags MUST fail closed unless the format marks them safely ignorable.

A corrupted or unsupported preamble MUST NOT trigger large allocation, KDF work, or partial plaintext output.

---

## 32. Encrypted immutable manifest

The manifest describes the immutable cryptographic structure known before streaming begins.

Its sealed plaintext fields, their order, and their widths are frozen in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §5, which governs them under the authority hierarchy in [`README.md`](README.md). The immutable media properties it may carry are the closed list of §5.1 there.

The manifest MUST NOT carry `total_plaintext_length` or `chunk_count`, because the source length may be unknown at import start. Those values belong in the final commit.

Manifest encryption:

```text
manifest_nonce = random 24 bytes
manifest_aad   = CanonicalTuple(
    "CHUR\x00OBJECT\x00MANIFEST-AAD\x00V1",
    object_id:bytes[16],
    stream_id:bytes[16],
    stream_kind:u8,
    stream_revision:u32,
    suite_id:u16
)

manifest_ciphertext = XChaCha20Poly1305.Encrypt(
    key       = ManifestKey,
    nonce     = manifest_nonce,
    plaintext = CanonicalManifest,
    aad       = manifest_aad
)
```

This element list, in this order and at these widths, is the only manifest AAD. The tag is 27 bytes and the elements add 39, so `manifest_aad` is exactly 66 bytes. Every value is a field of `CanonicalManifest` in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §5 or of the preamble in §3 there, and each keeps the width that section gives it.

`manifest_commitment` is frozen in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §5: BLAKE3-256 over a domain tag, `manifest_nonce`, and `manifest_ciphertext_and_tag`. It commits to the sealed record, not to `CanonicalManifest`.

The commitment binds chunk and final-commit AAD to the exact manifest record. Because it covers ciphertext, a reader computes it from container bytes before any key is available, which is what lets a locked object be structurally verified. It is therefore public and MUST NOT be treated as evidence of authenticity: a substituted manifest record carries its own matching commitment. The manifest becomes trusted when its AEAD verifies under `ManifestKey`; a chunk or final commit becomes trusted when its own AEAD verifies over AAD carrying that commitment.

---

## 33. Chunk sizing

Chunk size is a performance parameter stored in the authenticated manifest.

Initial benchmark candidates:

```text
photos and small files: 256 KiB
large audio/video:       1 MiB
maximum v1 candidate:    8 MiB
```

These are not frozen protocol constants.

Selection must consider:

- random-seek amplification;
- playback startup latency;
- Rust-to-player call overhead;
- file-descriptor I/O;
- memory pressure;
- battery and thermal cost;
- resumable upload granularity;
- integrity-repair granularity;
- codec read patterns.

The parser MUST enforce a hard lower and upper bound. An attacker MUST NOT be able to request arbitrarily large chunk buffers through a corrupted manifest.

---

## 34. Chunk nonce construction

Each content stream revision receives a fresh random 16-byte nonce prefix.

For chunk index `i`:

```text
chunk_nonce = nonce_prefix_128 || i_u64_be
```

This creates the 24-byte nonce required by XChaCha20-Poly1305.

Requirements:

- `nonce_prefix_128` is generated from the OS CSPRNG;
- the prefix is unique for every stream revision under a given content key;
- `chunk_index` starts at zero and increases by one;
- indexes MUST NOT repeat or be reordered in the canonical object;
- index arithmetic MUST reject overflow;
- a new stream revision MUST use a fresh prefix even if its key derivation context already changes;
- every chunk index MUST be durably reserved in the import journal before it is encrypted, and resumed or abandoned imports MUST follow [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §14.2 to §14.4, which fixes the ordering, the resume check, and the retirement of a dead transaction's key and prefix.

The design does not rely on probabilistic random nonces for every chunk. It uses one random prefix plus a deterministic index under a unique object/revision key context.

---

## 35. Chunk additional authenticated data

Each chunk is bound to its semantic position.

The AAD tuple:

```text
chunk_aad = CanonicalTuple(
    "CHUR\x00OBJECT\x00CHUNK-AAD\x00V1",
    container_version:u16,
    suite_id:u16,
    object_id:bytes[16],
    stream_id:bytes[16],
    stream_kind:u8,
    stream_revision:u32,
    manifest_commitment:bytes[32],
    chunk_index:u64,
    chunk_plaintext_length:u32
)
```

This element list, in this order and at these widths, is the only chunk AAD. The tag is 24 bytes and the elements add 85, so `chunk_aad` is exactly 109 bytes for every chunk. `container_version` and `suite_id` are the preamble fields of [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §3; `chunk_index` and `chunk_plaintext_length` are the `chunk_index` and `plaintext_length` of the chunk record header in §8 there; the rest are `CanonicalManifest` fields of §5.

The AAD prevents silent:

- chunk reordering;
- chunk duplication at another index;
- transfer between objects;
- transfer between stream kinds;
- transfer between revisions;
- reinterpretation under another suite or format;
- substitution against a different manifest.

`total_chunk_count` and `total_plaintext_size` are intentionally excluded so unknown-length streaming import remains possible. Completeness is handled by the final commit.

---

## 36. Chunk encryption

For each plaintext chunk:

```text
ciphertext_and_tag = XChaCha20Poly1305.Encrypt(
    key       = ContentKey,
    nonce     = chunk_nonce,
    plaintext = chunk_bytes,
    aad       = chunk_aad
)
```

Requirements:

- tag verification MUST complete before plaintext is released;
- decryption failure MUST return a stable corruption/authentication error;
- a failed chunk MUST NOT be retried with alternate keys or suites unless an explicit migration context exists;
- plaintext buffer length MUST be bounded by the authenticated manifest and parser limits;
- chunk records MUST use a canonical framing whose ciphertext length is checked before allocation;
- readers MUST reject duplicate indexes and invalid gaps when complete-object verification is requested;
- encryption MUST be in-place where practical without exposing uninitialized memory.

The player may receive an authenticated plaintext range from one or more verified chunks before the entire object is verified. That state MUST be represented explicitly.

---

## 37. Ordered ciphertext commitment

During import, Rust incrementally computes a commitment over the canonical ordered chunk records.

Conceptually:

```text
ordered_commitment = BLAKE3(
    CanonicalChunkRecord(0) ||
    CanonicalChunkRecord(1) ||
    ... ||
    CanonicalChunkRecord(N)
)
```

The exact committed bytes MUST include sufficient framing to prevent ambiguity, such as:

- record type;
- chunk index;
- ciphertext length;
- ciphertext and AEAD tag.

The commitment enables efficient detection of missing, added, duplicated, or reordered ciphertext records before or alongside full plaintext verification.

The BLAKE3 value is not independently trusted. It becomes authenticated only because it is included in the AEAD-protected final commit.

---

## 38. Final authenticated commit

The final commit proves that the producer completed the object and defines its total structure.

Its sealed plaintext fields, their order, and their widths are frozen in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §11, which governs them under the authority hierarchy in [`README.md`](README.md).

Encryption:

```text
commit_nonce = random 24 bytes
commit_aad   = CanonicalTuple(
    "CHUR\x00OBJECT\x00FINAL-COMMIT-AAD\x00V1",
    object_id:bytes[16],
    stream_id:bytes[16],
    stream_kind:u8,
    stream_revision:u32,
    manifest_commitment:bytes[32],
    suite_id:u16
)

commit_ciphertext = XChaCha20Poly1305.Encrypt(
    key       = FinalCommitKey,
    nonce     = commit_nonce,
    plaintext = CanonicalFinalCommit,
    aad       = commit_aad
)
```

This element list, in this order and at these widths, is the only final-commit AAD. The tag is 31 bytes and the elements add 71, so `commit_aad` is exactly 102 bytes. It is the manifest AAD of §32 with `manifest_commitment` inserted before `suite_id`, so the commit is bound to the exact manifest record the chunks are bound to.

An object without a valid final commit is incomplete, even if every available chunk authenticates.

Extra trailing bytes after the final commit MUST be rejected unless a future format explicitly defines authenticated append segments.

---

## 39. Verification states

The API MUST distinguish at least:

```text
Unverified
VerifiedRange
CompleteVerifiedObject
Corrupt
Incomplete
Unsupported
```

### 39.1 Verified range

A requested range is `VerifiedRange` when:

- every contributing chunk AEAD tag verified;
- each chunk AAD matched the manifest and requested position;
- the returned bytes are bounded to authenticated plaintext lengths.

This is sufficient for playback or image decoding of that range.

### 39.2 Complete verified object

An object is `CompleteVerifiedObject` only when:

- preamble and manifest parse and authenticate;
- final commit parses and authenticates;
- the expected chunk count is present;
- no chunks are missing, duplicated, or reordered;
- total plaintext length matches;
- last chunk length matches;
- ordered ciphertext commitment matches;
- every chunk AEAD tag verifies, unless a separate ciphertext-only structural verification state is explicitly reported.

### 39.3 Incomplete versus corrupt

- missing final commit after an interrupted import is `Incomplete`;
- an invalid AEAD tag is `Corrupt`;
- unsupported suite/version is `Unsupported`;
- truncated bytes inconsistent with a valid transaction are `Corrupt` or `Incomplete` according to journal state.

Callers MUST NOT collapse these states into a generic success boolean.

---

## 40. Metadata encryption

Private metadata includes:

- original filename and source path;
- MIME/media type;
- EXIF and GPS;
- capture/import timestamps;
- dimensions, orientation, duration, frame rate, codecs, HDR profile;
- album membership, tags, captions, favorites;
- OCR, face clusters, classifications, embeddings;
- source application/device information;
- edit history;
- deletion and sync tombstones.

Metadata MUST be encrypted at rest.

Metadata is mutable and revisioned:

```text
MetadataRevision
├── object_id
├── revision
├── previous_revision reference or hash
├── fresh random nonce
├── encrypted canonical metadata
└── authenticated context
```

Each revision MUST use a fresh nonce and revision-bound key context. Reusing nonce index zero under the same metadata key is forbidden.

v1 status: the catalog does not seal metadata revisions. Metadata is stored as queryable columns of the SQLCipher catalog, and the catalog's page encryption under `CatalogDatabaseKey` is its only protection at rest. `MetadataKey` and `CatalogRecordRootKey` are defined labels that no v1 code derives. The structure above is the target of a later sealed-metadata design; see [`format/CATALOG_SCHEMA_V1.md`](format/CATALOG_SCHEMA_V1.md) §8.

Mutable metadata SHOULD be separate from immutable media bytes so a favorite, caption, or album change does not rewrite a multi-gigabyte object.

---

## 41. Derived assets

Thumbnails, previews, video poster frames, waveforms, OCR, and embeddings are private data.

Each derived asset MUST be:

- encrypted under its own domain-separated key;
- bound to `object_id`;
- bound to source content revision;
- bound to asset kind and asset revision;
- stored under a random/opaque physical name;
- invalidated or regenerated when its source revision changes;
- excluded from public Room/DataStore and shared caches.

A thumbnail from one object MUST NOT be accepted as a valid thumbnail for another object even if both decrypt under a compromised shared cache implementation.

Derived assets may use the same chunk-container mechanism or a smaller single-record AEAD format, provided the format is versioned and bounded.

---

## 42. Physical object names

Filesystem object names MUST be random or keyed opaque identifiers.

Forbidden names include:

```text
passport.jpg
Paris/2026-09-11.mov
SHA256(plaintext)
MIME-type extensions that reveal private semantics
```

Acceptable layout:

```text
objects/
  24/
    2415cfdb-aa85-4ae7-...
  f1/
    f192e0e2-89a3-...
```

Directory sharding may use bytes of a random object identifier. Object IDs MUST NOT be derived from plaintext content.

---

## 43. Private catalog cryptography

The private catalog is owned by Rust.

Implemented under [ADR-0038](adr/0038-adopt-sqlcipher-as-the-v1-catalog-engine.md):

```text
Rust-owned SQLCipher database
    key = CatalogDatabaseKey
```

Requirements regardless of implementation:

- private metadata is encrypted at rest;
- object keys remain wrapped under collection keys even inside an encrypted database;
- collection keys remain wrapped under root-derived envelope keys;
- database, WAL, journal, temporary, and backup files receive appropriate platform file protection;
- the connection closes on lock;
- `CatalogDatabaseKey` is zeroized on lock;
- prepared statements and in-memory projections do not survive the session;
- KMP Room never accesses the private database;
- sync does not replicate raw database pages;
- migrations are Rust-owned and transactional.

If SQLCipher size, cross-compilation, or performance is unacceptable, the alternative MUST still be a Rust-owned authenticated encrypted catalog with explicit indexes and migration rules. Field-level encryption alone MUST account for sorting, indexing, length leakage, nonce revisions, and WAL behavior.

---

## 44. Private search and keyed fingerprints

Search indexes, OCR indexes, face embeddings, and semantic embeddings are private.

The metadata FTS5 index is defined by [`format/CATALOG_SCHEMA_V1.md`](format/CATALOG_SCHEMA_V1.md) §16.4. [Catalog v10](format/CATALOG_SCHEMA_V10.md) adds recognized document/image text and combined object FTS inside the same SQLCipher database under `CatalogDatabaseKey`; it derives no separate search or OCR key. [Private notes](format/CATALOG_SCHEMA_V9.md) have a separate title/body FTS table. No index text enters public storage or sync operations. Full backup preserves it; selective archives omit recognized text and rebuild only included metadata.

Face and semantic embeddings remain deferred. The `SearchKey` and object `OcrKey` labels are reserved domain definitions, not the current content-index storage mechanism. A future encrypted-segment design requires a separate approved contract.

Global deduplication through an unkeyed plaintext hash is forbidden because it reveals equality and allows confirmation attacks.

Acceptable deduplication directions:

- no deduplication;
- local-only deduplication while unlocked;
- a user/vault-specific keyed fingerprint:

```text
fingerprint = BLAKE3-keyed(
    key  = LocalFingerprintKey,
    data = canonical plaintext bytes
)
```

A keyed fingerprint MUST NOT be uploaded as a globally comparable identifier unless the leakage is explicitly accepted.

---

## 45. Atomic encrypted import

The import transaction is cryptographic state, not only file I/O.

```text
source stream
    ↓
new random ObjectKey
    ↓
new manifest and nonce prefix
    ↓
per chunk: durably reserve the index in the import journal, then encrypt
    ↓
streamed chunk encryption into temporary object
    ↓
ordered ciphertext commitment
    ↓
authenticated final commit
    ↓
fsync temporary object
    ↓
structural verification
    ↓
atomic rename to immutable object
    ↓
object-key envelope and catalog transaction
    ↓
commit import journal
```

Requirements:

- source plaintext MUST be processed in bounded buffers;
- temporary output is ciphertext, not a plaintext copy;
- the original MUST NOT be deleted before durable encrypted commit;
- the catalog MUST NOT reference an uncommitted object;
- a finalized orphan object MUST be recoverable through startup reconciliation, and a temporary object with no journal record is always dead;
- every chunk index MUST be durably reserved in the import journal before it is encrypted, per [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §14.2;
- an abandoned or cancelled transaction is dead under §14.4: its temporary object is deleted and its key and prefix pair is retired, never reused;
- import progress MUST not expose private filenames in logs or notifications;
- cancellation MUST leave either a transaction resumable under §14.3 from its journaled reserved index, or a removable dead one;
- source size MAY be unknown at start;
- media probing and thumbnail creation MUST follow the plaintext-lifecycle policy.

Import verification has one default and one opt-in mode, and the default is what `ACTIVE` means for an imported object.

The default is structural verification. After fsync, and before the catalog activates the object, the importer re-reads the container from disk and verifies the magic and every constant preamble field, the manifest record framing and `manifest_commitment`, every chunk record header in ascending index order, `ordered_chunk_commitment` over the exact record bytes it just read, and the final commit record under its AEAD. No chunk is decrypted. This proves that the bytes that reached the disk are the bytes that were written and that they are internally consistent under a key, because `ordered_chunk_commitment` covers the same bytes a chunk AEAD verification would read and is itself sealed inside the final commit.

Paranoid verification, which additionally decrypts and authenticates every chunk before activation, is an opt-in setting and MUST NOT be the default. It roughly doubles import time for a guarantee the ordered commitment already provides against storage error, and any residual bit flip is detected by the first read of the affected range.

An import that fails the default verification does not activate the object and is dead under [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §14.4. Source deletion is offered only after the default verification passes and the catalog transaction commits; that pair is the fixed meaning of "durably committed" in SEC-022.

---

## 46. Protected export

Export reverses the object pipeline:

```text
encrypted object
    ↓
unwrapped ObjectKey
    ↓
authenticated range/sequential decryption
    ↓
protected destination stream
    ↓
platform share/save flow
```

Requirements:

- plaintext is never exposed before each contributing AEAD tag verifies;
- complete export SHOULD require `CompleteVerifiedObject`;
- output uses a caller-provided file descriptor/stream where possible;
- temporary plaintext files require an explicit scratch policy;
- scratch files use random names, app-private storage, strongest compatible platform protection, backup exclusion, and immediate cleanup;
- startup cleanup removes abandoned plaintext scratch files;
- logs and UI effects MUST not include private filesystem paths;
- physical overwrite on flash MUST NOT be promised.

---

## 47. Random-access media decryption

Random access uses the authenticated manifest to map plaintext ranges to chunk records.

```text
requested [offset, length)
    ↓
validate bounds against final commit when available
    ↓
calculate affected chunk indexes
    ↓
read ciphertext records
    ↓
verify each AEAD tag and AAD
    ↓
copy requested subranges to bounded caller buffer
```

Requirements:

- offsets and lengths use checked arithmetic;
- negative, overflowing, or out-of-range requests fail before I/O;
- readers return only authenticated bytes;
- caches are session-scoped and cleared on lock;
- decrypted cache entries are bounded and never persisted to disk;
- a stale reader handle returns `SESSION_EXPIRED` after lock;
- media players cannot retain a Rust session indefinitely through reference cycles;
- the data-plane API SHOULD use direct/native buffers rather than repeated `ByteArray` copies.

Sequential import/export and random-access playback may share chunk primitives but MUST expose different high-level state contracts.

---

## 48. Crypto-erasure and deletion

Local crypto-erasure means every locally accessible envelope for an object key has been destroyed.

Deletion MUST consider:

- current catalog row;
- collection envelopes;
- alternate collection memberships;
- SQLCipher WAL/journal pages;
- catalog snapshots;
- local backup manifests;
- pending sync operations;
- device caches;
- real/decoy separation;
- exported backup files outside application control.

After key-envelope destruction, ordinary ciphertext deletion is still performed, but Chur does not claim physical overwrite on flash.

In synchronized/shared systems, Chur cannot force another authorized device or recipient to destroy a previously received key or plaintext copy.

---

## 49. Native backup package

The implemented native full-backup path writes package version 2 of [`format/BACKUP_FORMAT_V2.md`](format/BACKUP_FORMAT_V2.md) and [ADR-0068](adr/0068-carry-a-portable-catalog-export-in-backup-v2.md). It carries the following encrypted state. This list is an inventory, not a new record layout:

```text
BackupManifestV1
portable key slots
vault descriptor
collection-key envelopes
canonical catalog export (CatalogExportV1), in sealed records
object-key envelopes
immutable encrypted objects
encrypted derived assets
migration/version metadata
```

Requirements:

- device-only Keystore/Keychain slots are excluded;
- at least one password or recovery slot can restore the root secret;
- package metadata that reveals private semantics is encrypted;
- `BackupManifestV1` is authenticated under `BackupManifestKey` and under no other key; a recovery slot restores the same `VaultRootSecret` from which that key is derived, as [`format/BACKUP_FORMAT_V1.md`](format/BACKUP_FORMAT_V1.md) §4 requires;
- each catalog export record is sealed under `BackupManifestKey` with an AAD under `CHUR\x00BACKUP\x00CATALOG-EXPORT-AAD\x00V1` that binds the vault, the backup, the record index, the record type, the chunk index, and the final flag, so a record from another backup, a moved record, and a cut export fail authentication;
- the final backup commit seals a BLAKE3-256 record commitment under `CHUR\x00BACKUP\x00RECORD-COMMITMENT\x00V1` over the index, header, and payload of every record that is not a container, beside the inventory commitment that covers the containers;
- the package carries no SQLCipher page; a restore imports the catalog rows into a new SQLCipher catalog, and a version 1 package that carries a copy of the SQLCipher file still restores through the version 1 path;
- restore validates every length, suite, key slot, manifest, envelope, and object before activation;
- restore writes into a new temporary vault namespace and atomically activates it;
- backup generation and creation time shown after unlock are authenticated;
- rollback to an older user-provided backup is possible and must be communicated.

---

## 50. age-compatible outer backup

An `age`-compatible stream may be used as an outer export/transport layer.

Possible model:

```text
Chur-native encrypted backup package
    ↓
age recipient encryption
    ↓
portable file or stream
```

`age` does not replace:

- the Chur catalog;
- object-key envelopes;
- per-object media encryption;
- albums and metadata revisions;
- real/decoy topology;
- sync operation history.

The outer framing and its detection are defined in [`format/BACKUP_FORMAT_V1.md`](format/BACKUP_FORMAT_V1.md) §2.3, which governs them under the authority hierarchy in [`README.md`](README.md): an unwrapped package begins with `CHURBAK1`, and exactly zero or one `age` layer MAY wrap it. Interoperability tests, recipient and recovery UX, package-size analysis, and license and dependency review remain outstanding.

---

## 51. Ciphertext-only synchronization

The self-hosted reference server stores opaque encrypted data.

It MAY observe:

- account and device identifiers required by the service;
- opaque object IDs;
- ciphertext sizes;
- upload/download timing;
- encrypted object and operation versions;
- wrapped collection keys;
- signed operation-log metadata that is intentionally public to the protocol.

It MUST NOT require:

- plaintext filenames;
- MIME/media type;
- EXIF or GPS;
- album names;
- thumbnails;
- plaintext content hashes;
- root, collection, object, or recovery keys.

Immutable object upload model:

```text
upload encrypted chunks
    ↓
server confirms stored ciphertext
    ↓
upload authenticated final commit
    ↓
publish encrypted catalog operation
```

The server MUST NOT be treated as the authority for object integrity. Clients verify cryptographic records locally.

---

## 52. Authenticated device operation log

AEAD alone does not prevent replay or rollback of previously valid ciphertext.

A synchronized vault requires signed device operations.

Requirements:

- every device has a distinct signing key;
- private signing keys are wrapped by `IdentityWrapKey`;
- sequence numbers never decrease for one device;
- each operation commits to the previous operation hash for that device;
- clients remember the latest accepted head;
- replay, duplicate sequence, and chain fork are detected;
- operations use canonical binary encoding before signing;
- the server cannot forge operations without a device key;
- server omission remains possible and requires transparency/out-of-band consistency for stronger guarantees.

The signed record's fields, including the `observed_heads` causality vector that carries cross-device ordering, are defined by [`sync/OPERATION_LOG.md`](sync/OPERATION_LOG.md) §2 and §4.

---

## 53. Collection sharing with HPKE

Sharing encrypts the collection key, not media payloads.

The Phase 4 HPKE profile is:

```text
KEM:  DHKEM(X25519, HKDF-SHA-256)
KDF:  HKDF-SHA-256
AEAD: ChaCha20-Poly1305
```

This uses the RFC 9180 AEAD with a 96-bit nonce internally. It is distinct from Chur's local XChaCha20-Poly1305 records.

Grant flow:

```text
Sender unwraps SecurityCollectionKey[epoch]
    ↓
HPKE seal to recipient X25519 public key
    ↓
construct canonical CollectionGrantV1
    ↓
sign grant with sender/device Ed25519 key
    ↓
store/relay encrypted grant
```

The exact fixed record is defined in [`sync/COLLECTION_GRANTS.md`](sync/COLLECTION_GRANTS.md). Its fields are:

```text
grant version and HPKE profile
grant, source-vault, and collection identifiers
collection epoch and membership generation
recipient identity-vault, device, and HPKE-key identifiers
sender device, signing-key, and membership identifiers
cumulative permission profile and creation operation sequence
HPKE encapsulated key and fixed 48-byte ciphertext
sender signature
```

HPKE `info` and AAD use separate domain tags followed by the same fixed grant context. The HPKE plaintext is exactly one 32-byte `SecurityCollectionKey`; the sender signature covers the outer context, encapsulation, and ciphertext. V1 has no expiry because a device clock cannot revoke a key already delivered.

Base-mode HPKE alone does not authenticate the sender. The Ed25519 signature provides explicit sender/device authenticity and durable offline verification.

---

## 54. Identity and verification

Implemented sharing identities use separate key purposes:

```text
X25519 key pair
    recipient encryption / HPKE

Ed25519 key pair
    operation and grant signatures
```

Requirements:

- never reuse one private key across X25519 and Ed25519 purposes;
- private keys are generated in Rust;
- private keys are encrypted under root-derived identity-wrap keys;
- public-key fingerprints use the construction and rendering fixed by [`sync/DEVICE_IDENTITY.md`](sync/DEVICE_IDENTITY.md) §5; an implementation MUST NOT define a second representation;
- recipient verification is explicit for high-value sharing;
- key replacement and device addition are signed and logged;
- identity recovery receives separate threat-model review.

Secure Enclave device keys may supplement device attestation or platform identity but MUST NOT silently replace the portable protocol identity.

---

## 55. Revocation semantics

Revocation can prevent future access but cannot erase past access.

On member/device removal:

1. create a new collection epoch and random key;
2. stop issuing new envelopes/grants to the removed identity;
3. rewrap object keys for current members eagerly, per [`sync/REVOCATION.md`](sync/REVOCATION.md) §3.1;
4. encrypt future metadata and operations under the new epoch;
5. record the membership change in the signed operation log;
6. delete the superseded object envelopes and truncate the WAL when the rewrap completes;
7. re-encrypt every rewrapped or trashed object under a fresh object key, automatically, in a cancellable background operation that starts after unlock, per [`sync/REVOCATION.md`](sync/REVOCATION.md) §3.2 and [ADR-0069](adr/0069-re-encrypt-objects-after-revocation.md).

A former member who already obtained an object key keeps access only to ciphertext of that object that it copied before the re-encryption. Neither the rewrap nor the re-encryption revokes keys, ciphertext, or plaintext already copied.

---

## 56. Post-quantum readiness

The internal prototype uses a separate vault policy, recipient suite and device signature. Its format and release conditions are in [ADR-0073](adr/0073-internal-post-quantum-profile.md). The v1 description below applies to the classical profile.

Bulk media encryption already uses 256-bit symmetric keys and does not require an immediate post-quantum replacement.

Post-quantum concerns primarily affect:

- long-lived recipient key envelopes;
- device bootstrap;
- identity and signatures;
- backups intended to remain confidential for decades.

The protocol registry MUST allow future recipient types such as a hybrid X25519 plus ML-KEM construction without changing media chunks or object keys.

No post-quantum KEM or signature is part of Chur v1. Adding one requires:

- a standardized construction;
- hybrid-composition review;
- larger-key and ciphertext benchmarks;
- mobile implementation review;
- test vectors;
- independent audit.

---

## 57. Side-channel and metadata leakage

Encryption does not automatically hide:

- number of objects;
- approximate ciphertext size;
- object creation/deletion timing;
- backup and sync timing;
- frequency and range of access;
- presence of multiple encrypted namespaces;
- database/page growth;
- device/account relationships required by a sync service.

Chur MUST document these leakages.

Mitigations MAY include:

- size buckets or padding;
- batched uploads;
- delayed/coalesced metadata operations;
- opaque random identifiers;
- encrypted operation payloads;
- local-only search and deduplication;
- separate public/private telemetry policies.

Oblivious RAM, traffic-mixing networks, and cryptographically hidden volumes are non-goals for the initial product.

---

## 58. Padding policy

Padding is optional because it costs storage, bandwidth, battery, and complexity.

Object bucket padding is enabled for every new object container. `container_version` `0x0002` pads the chunk stream with zero bytes to the bucket of [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §18.1: a power of two of at least 4 KiB up to 1 MiB, a whole number of MiB up to 32 MiB, and 16 buckets per power-of-two interval above that. The cost is less than 1 MiB or less than one sixteenth of the object. The version is bound into every chunk AAD, the padding is inside the chunk AEAD and the ordered commitment, the true length is inside the authenticated final commit, and a reader refuses a padding byte other than zero and a stream that is not exactly the bucket. [ADR-0066](adr/0066-pad-object-containers-to-size-buckets.md) records the decision and its cost. Record padding and network batch padding remain unimplemented.

Potential profiles:

```text
None
    ciphertext reveals approximate plaintext size plus framing

Record padding
    final chunk padded to a fixed boundary

Object bucket padding
    object padded to configured size buckets

Network batch padding
    upload groups padded or delayed
```

Any padding profile MUST be:

- authenticated;
- encoded in encrypted metadata or manifest policy;
- removed only after AEAD verification;
- bounded to prevent storage-exhaustion attacks;
- benchmarked before default enablement.

Random unauthenticated trailing bytes are not an acceptable padding format.

---

## 59. Plaintext lifecycle

Plaintext is a toxic temporary resource.

### 59.1 Import

- read bounded source ranges;
- encrypt immediately;
- avoid plaintext temporary copies;
- extract metadata and derivatives in a controlled pipeline;
- clear mutable buffers after use;
- do not persist source URI/path as plaintext private metadata outside Rust.

### 59.2 Viewing and playback

- decrypt only requested ranges;
- release bytes only after tag verification;
- use bounded session caches;
- never place private decoded data in a shared disk cache;
- clear caches and stop players on lock.

### 59.3 Codec-required scratch files

Where a platform codec requires a file URL:

- use app-private scratch storage;
- use a random name;
- exclude from backup;
- apply strongest compatible platform file protection;
- register cleanup before exposing the path;
- delete immediately after use;
- run startup cleanup after crashes;
- never claim guaranteed physical overwrite.

### 59.4 Lock

Locking MUST:

- invalidate the Rust session generation;
- cancel active operations;
- zeroize root and derived session secrets;
- close the private catalog;
- invalidate object readers;
- clear private image/media caches;
- destroy private navigation state;
- return future stale-handle calls as `SESSION_EXPIRED`.

---

## 60. FFI secret crossing

The FFI boundary must remain narrow.

Allowed secret crossings include:

- password bytes from the UI adapter into Rust for Argon2id;
- platform-released device secret into Rust on iOS;
- root-secret bytes into/out of the Android Keystore adapter for a single wrap/unwrap operation;
- recovery secret during explicit import/export.

Requirements:

- never serialize secret material as JSON;
- never use `String` for binary keys;
- use explicit pointer/length or fixed-size buffer contracts;
- validate lengths before reading;
- immediately copy into zeroizing Rust types;
- clear caller-owned mutable buffers best-effort;
- no secret-bearing callbacks or async event payloads;
- no panic unwinding across FFI;
- no key material in exception text;
- use coarse-grained calls rather than exposing primitive-level crypto operations to KMP.

The KMP API SHOULD expose operations such as:

```text
open_vault
lock_vault
create_password_slot
rewrap_platform_slot
import_object_from_fd
read_plaintext_range
verify_object
export_object_to_fd
rotate_collection_key
```

It SHOULD NOT expose `xchacha_encrypt`, `hkdf_expand`, or raw-key getters.

---

## 61. Error handling and oracles

Cryptographic errors require stable, redacted semantics.

External error classes are the stable codes registered in [`ERROR_MODEL.md`](ERROR_MODEL.md). This document MUST NOT define an error name or value: a credential failure is `AUTHENTICATION_FAILED`, a damaged authenticated record is `OBJECT_CORRUPT` or `CATALOG_CORRUPT`, and a missing final commit is `OBJECT_INCOMPLETE`.

Requirements:

- wrong password, wrong decoy password, invalid slot tag, and invalid root descriptor SHOULD map to a uniform credential failure where practical;
- parser errors MUST not include secret or private plaintext;
- AEAD failures MUST not reveal partial plaintext;
- retry behavior MUST not search alternate algorithms dynamically;
- resource-limit errors occur before expensive allocation/KDF work;
- debug builds MUST preserve redaction;
- no raw third-party crypto error reaches analytics or user-facing logs.

Perfect timing indistinguishability across platform services and multiple slot types is not claimed, but obvious avoidable identity oracles SHOULD be removed.

---

## 62. Logging and diagnostics

Security-safe logs use event codes and opaque local correlation IDs.

Acceptable examples:

```text
VAULT_UNLOCK_FAILED
IMPORT_COMMIT_SUCCEEDED
OBJECT_FINAL_COMMIT_MISSING
OBJECT_CHUNK_AUTH_FAILED
PLATFORM_SLOT_INVALIDATED
MIGRATION_ROLLED_BACK
SESSION_LOCKED_BACKGROUND
```

Forbidden log values:

- passwords or password lengths where unnecessary;
- salts, nonces, tags, keys, envelopes, recovery values;
- private filenames, paths, album names, EXIF, GPS;
- real/decoy identity labels;
- object counts tied to public-shell telemetry;
- decrypted query text;
- raw FFI buffers;
- secret-bearing Rust `Debug` output.

Crash reporting MUST apply the same policy. A release build SHOULD include automated tests that scan collected logs for seeded private values.

---

## 63. Migration rules

Cryptographic migrations are Rust-owned, versioned, resumable transactions.

Migration categories:

```text
format-only migration
    rewrite authenticated metadata/framing without changing object plaintext

key-envelope migration
    rewrap collection/object/root keys

suite migration
    decrypt and re-encrypt affected records under a new approved suite

catalog migration
    transform encrypted schema and indexes

identity/sync migration
    replace grants, signatures, or operation formats
```

Requirements:

- preserve the original until the new form is durably committed;
- use temporary namespaces and explicit journals;
- support crash recovery at every step;
- validate old and new forms;
- never mutate an immutable object in place without a rollback-safe copy;
- publish deterministic test vectors for each version transition;
- reject downgrade writes after migration;
- keep read-only migration support only as long as policy requires;
- separate parser support from permission to create deprecated formats.

---

## 64. Test vectors

Before persistent production data, Chur MUST publish deterministic vectors for:

- HKDF root-domain derivations;
- collection-key envelopes;
- object-key envelopes;
- password slot creation and unwrap;
- recovery slot creation and unwrap;
- manifest encryption;
- nonce construction;
- chunk AAD and encryption;
- ordered ciphertext commitment;
- final commit encryption;
- metadata revisions;
- backup manifest authentication;
- HPKE collection grants;
- Ed25519 operation signatures;
- every format migration.

Each vector set SHOULD contain:

```text
input values
canonical encoded bytes
intermediate derived values where safe for test data
nonce and AAD bytes
ciphertext and tag
expected parsed structure
expected failure mutations
```

Test vectors contain synthetic, explicitly non-production keys.

---

## 65. Cross-platform interoperability

The same bytes MUST work across clients:

```text
Encrypt on Android
Decrypt and verify on iOS
Inspect with chur-cli

Encrypt on iOS
Decrypt and verify on Android
Inspect with chur-cli

Create with chur-cli
Import on both mobile platforms
```

Interoperability tests MUST cover:

- Unicode password encoding;
- integer byte order;
- canonical encoding;
- zero-length and one-byte inputs;
- exact chunk-boundary inputs;
- final partial chunks;
- large object offsets;
- all supported key-slot types;
- platform invalidation and portable recovery;
- corrupted and unsupported inputs.

Platform-native crypto is limited to platform key slots; all portable vault records are generated and parsed by the same Rust core.

---

## 66. Corruption and adversarial test matrix

Every parser and verifier MUST be tested against:

- bit flips in each preamble field;
- oversized manifest lengths;
- unknown suite/version;
- truncated nonce, ciphertext, or tag;
- corrupted manifest;
- duplicate chunk index;
- reordered chunks;
- missing middle chunk;
- missing final chunk;
- missing final commit;
- extra trailing record;
- chunk copied from another object;
- chunk copied from another revision;
- manifest copied from another object;
- forged plaintext length;
- forged chunk count;
- integer overflow near maximum offsets;
- invalid Argon2 parameters;
- malformed salt or password length;
- corrupted collection/object key envelope;
- stale collection epoch;
- rollback of metadata revision;
- replayed device operation;
- forged HPKE grant or signature;
- interrupted slot rotation;
- interrupted suite migration;
- catalog/object disagreement.

No malformed input may cause unbounded allocation, panic across FFI, secret logging, or unauthenticated plaintext output.

---

## 67. Fuzzing

Planned fuzz targets:

```text
parse_vault_descriptor
parse_key_slot
validate_argon2_profile
unwrap_password_slot
parse_collection_key_envelope
parse_object_key_envelope
parse_object_preamble
parse_encrypted_manifest
parse_chunk_record
construct_chunk_aad
decrypt_chunk
parse_final_commit
verify_complete_object
decode_metadata_revision
parse_backup_manifest
apply_catalog_migration
parse_sync_operation
verify_device_log_chain
parse_collection_grant
validate_ffi_input
```

Fuzz harnesses MUST impose the same production limits before allocation.

Corpus seeds SHOULD include valid vectors for every supported version and minimal invalid variants. Sanitizers, Miri where applicable, and platform-specific native fuzzing SHOULD cover unsafe FFI adapters.

---

## 68. Nonce and key-uniqueness testing

Tests MUST demonstrate that:

- every new vault gets a new root secret;
- every collection epoch gets a new random collection key;
- every object gets a new random object key;
- every stream revision gets a fresh nonce prefix;
- chunk indexes never repeat within a stream revision;
- resumed imports continue from journaled state;
- aborted imports do not reuse key/prefix pairs;
- metadata rewrites never reuse a `(key, nonce)` pair;
- platform slot rewrites use fresh GCM/XChaCha nonces;
- test RNG injection cannot compile into release artifacts.

Statistical testing is not a substitute for construction-level uniqueness rules, but it can detect implementation regressions.

---

## 69. Cryptographic implementation mapping

Preferred Rust crate direction:

```text
chacha20poly1305     XChaCha20-Poly1305
argon2               Argon2id
hkdf                 HKDF
sha2                 SHA-256
blake3               ordered commitments / keyed local fingerprints
getrandom            OS entropy
rand_core            RNG traits where required
zeroize              secret cleanup
secrecy               explicit secret wrappers
subtle                constant-time helpers
ed25519-dalek         future signatures
x25519-dalek / hpke   future HPKE implementation, after review
```

The exact dependency set and versions require supply-chain review and lockfile pinning.

Crate boundaries:

```text
chur-crypto
    primitives, key types, slots, derivation, envelopes

chur-format
    canonical encoding, object records, versions

chur-catalog
    encrypted private catalog and migrations

chur-media
    import, range read, export, derived assets

chur-sync-protocol
    device operations, HPKE grants, signatures

chur-ffi
    stable C ABI and generated-binding adapter

chur-cli
    vectors, inspection, verification, repair, migration
```

The core MUST avoid unnecessary `unsafe`. Required unsafe code is isolated in narrow adapters with explicit invariants and tests.

---

## 70. Prohibited constructions

The following are forbidden:

- password used directly as root, collection, object, or media key;
- SHA-256 or another fast hash used as the password KDF;
- one global media key for all objects;
- deterministic object keys derived from filenames or hashes;
- AES-ECB;
- unauthenticated AES-CBC/CTR;
- AEAD nonce reuse;
- restarting a chunk counter under the same key and prefix;
- using the same derived key for content and metadata;
- releasing plaintext before AEAD verification;
- treating successful prefix decryption as complete-object verification;
- storing private metadata in Room, DataStore, `SavedStateHandle`, user defaults, or public notifications;
- storing plaintext object keys inside SQLCipher as a substitute for object envelopes;
- using plaintext content hashes as remote object names;
- global cross-user deduplication by plaintext equality;
- accepting arbitrary KDF parameters from a server/import without bounds;
- algorithm negotiation controlled by untrusted input;
- JSON serialization of keys, nonces, signatures, or AEAD AAD;
- public-key encryption of entire media files for sharing;
- reuse of Ed25519 keys as X25519 keys without an explicitly standardized conversion protocol;
- secret-bearing `Debug`, logs, metrics, or crash attachments;
- representing a decoy UI filter as an independent vault;
- claiming secure erase of flash blocks;
- claiming an independent security audit before one is completed.

---

## 71. Security invariants

Every implementation and migration MUST preserve these invariants:

1. Rust is the canonical owner of portable vault cryptography.
2. The vault root secret is random and never persisted in plaintext.
3. Passwords derive KEKs and never become data keys.
4. Password KDF parameters are bounded before execution.
5. Platform authentication gates key use but is not deterministic key material.
6. Collection keys are random and independent by epoch.
7. Object keys are random and independent by object.
8. Every semantic purpose has an explicit HKDF label.
9. Real and decoy identities share no private roots or caches.
10. The object-key envelope is separate from immutable media ciphertext.
11. Albums are not implicitly security collections.
12. Every stream revision receives a fresh nonce prefix.
13. No `(key, nonce)` pair repeats.
14. Chunk AAD binds object, stream, revision, manifest, index, and length.
15. Plaintext is released only after the relevant AEAD tag verifies.
16. Valid chunks do not imply a complete object.
17. A complete object requires a valid final commit and full structural agreement.
18. Mutable metadata uses revision-safe nonces and context.
19. Derived assets are bound to the source content revision.
20. Private catalog keys disappear on lock.
21. Private Room/DataStore persistence is forbidden.
22. Native handles expire on lock independently of UI cleanup.
23. Source media is not deleted before durable encrypted import commit.
24. Object deletion accounts for every accessible key envelope.
25. Unkeyed content hashes are not global identifiers.
26. Sync servers never become cryptographic authorities.
27. Replay/rollback requires explicit operation-log defenses.
28. Sharing encrypts collection keys, not bulk media.
29. Sender authenticity is separate from HPKE confidentiality.
30. Unsupported suites fail closed.
31. New writes never silently use deprecated suites.
32. Secret types do not produce unredacted debug output.
33. Logs and crash reports contain no private or secret values.
34. All cryptographic inputs use canonical encoding.
35. Migration is transactional and vector-tested.
36. Production RNG has no deterministic fallback.
37. Recovery is explicit; forgotten credentials may cause irreversible loss.
38. Audit claims match completed audit scope and version.

---

## 72. Release and audit gates

Before Chur is described as a production vault:

1. freeze the v1 canonical encoding;
2. publish key-slot and object-container specifications;
3. publish cross-platform test vectors;
4. implement parser resource limits;
5. complete corruption and fuzz campaigns;
6. test process death and platform-key invalidation;
7. test Android/iOS/CLI interoperability;
8. review all secret-bearing FFI crossings;
9. review Rust dependencies and unsafe code;
10. commission an independent audit of the Rust core, format parsers, KDF policy, and platform-slot adapters;
11. remediate findings and publish a summary;
12. create `SECURITY.md` and a private vulnerability-reporting channel.

Before cloud sync or sharing:

1. specify and audit device identity;
2. specify signed operation logs and rollback behavior;
3. specify HPKE grant encoding and sender verification;
4. define revocation and collection-epoch semantics;
5. publish multi-device vectors;
6. audit the server/client protocol separately from local storage.

An audit applies only to the reviewed commit, protocol versions, build configuration, and scope.

---

## 73. Lessons from reference implementations

Chur uses reference projects for design review, not as drop-in protocols.

### Ente

Useful lessons:

- master/root key to collection key to file/object key hierarchy;
- separate encryption of file bytes and metadata;
- sharing by encrypting collection keys to recipients;
- cross-client cryptographic core direction;
- independent audit findings around streaming completion, Argon2 parameter limits, and secret leakage through debug representations.

Chur therefore requires:

- explicit complete-object state;
- strict KDF resource bounds;
- redacted secret types;
- a Rust-owned portable protocol.

### Cryptomator

Useful lessons:

- authenticated chunk framing;
- AAD binding chunks to position/context;
- clear threat-model documentation;
- acknowledgment of size/count/access leakage.

Chur differs by being media-first rather than an encrypted filesystem overlay.

### age

Useful lessons:

- modern recipient-based encryption;
- streaming encrypted export;
- explicit versioned format;
- separation of payload encryption from recipient wrapping.

Chur may use age as an outer backup layer but keeps its own catalog and object format.

---

## 74. Open cryptographic decisions

The following MUST be resolved before v1 production bytes are frozen:

1. exact canonical binary encoding — resolved: the profile is defined in [`format/CANONICAL_ENCODING_V1.md`](format/CANONICAL_ENCODING_V1.md), and the sealed plaintext schemas of the manifest and the final commit are frozen in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §5 and §11;
2. exact algorithm/suite numeric registry — resolved in [`format/CANONICAL_ENCODING_V1.md`](format/CANONICAL_ENCODING_V1.md) §15;
3. final Argon2id mobile creation profile and latency target — resolved in [`security/PASSWORD_PROFILE.md`](security/PASSWORD_PROFILE.md) §4 and [ADR-0026](adr/0026-argon2id-memory-floor-and-candidate-set.md): the floor is also the v1 default and calibration may only raise a parameter;
4. final Argon2 parser hard bounds — resolved in §18.3, which [`security/KEY_SLOTS.md`](security/KEY_SLOTS.md) §11 checks before any derivation runs;
5. exact password input maximum;
6. exact HKDF extract salt and canonical `info` bytes — resolved in §13: the extract salt is 32 zero bytes, and tuple bytes follow [`format/CANONICAL_ENCODING_V1.md`](format/CANONICAL_ENCODING_V1.md) §7.1;
7. exact chunk-size defaults and limits — resolved in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §6 and §16;
8. exact BLAKE3 ordered-commitment framing — resolved in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §10;
9. whether object IDs appear in the public preamble or only encrypted records — resolved in [`format/OBJECT_CONTAINER_V1.md`](format/OBJECT_CONTAINER_V1.md) §3: encrypted records only;
10. SQLCipher versus an alternative Rust-owned encrypted catalog implementation;
11. catalog field-level encryption policy inside SQLCipher;
12. standard versus paranoid import verification default — resolved in §45: the default is structural and commitment verification over the re-read container with no chunk decryption, and full re-decryption is an opt-in setting;
13. backup package encoding and optional age profile — resolved in [`format/BACKUP_FORMAT_V1.md`](format/BACKUP_FORMAT_V1.md) §2;
14. recovery-secret mnemonic/checksum format — resolved in [`security/RECOVERY.md`](security/RECOVERY.md) §2: 24 BIP-39 English words with the BIP-39 checksum, a `chur-recovery-v1` marker outside the mnemonic, and NFKD plus lowercase plus whitespace-collapse normalization on re-entry ([ADR-0029](adr/0029-freeze-the-recovery-secret-encoding.md));
15. exact real/decoy password-slot candidate-discovery behavior — resolved in [`security/KEY_SLOTS.md`](security/KEY_SLOTS.md) §8 and [ADR-0026](adr/0026-argon2id-memory-floor-and-candidate-set.md): a constant two-candidate list padded with dummy derivations;
16. HPKE library and canonical grant encoding;
17. device-log consistency and malicious-server omission strategy — resolved by [ADR-0044](adr/0044-freeze-the-v1-sync-operation-record.md): per-device chains, signed observed heads, and checkpoint floors detect every omitted cause they name, while a wholly unobserved hidden branch remains outside the v1 guarantee;
18. optional padding profiles;
19. future AES/FIPS profile requirements;
20. scope and schedule of independent audits.

Each resolved item SHOULD produce an ADR or dedicated specification rather than an undocumented code choice.

---

## 75. Required follow-up specifications

The decomposition is complete. [`README.md`](README.md) indexes every normative document this file defers to, and the decisions that still require a specification are the backlog in [`adr/README.md`](adr/README.md).

---

## 76. References

Standards and primary references:

- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 9180 — Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html)
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html)
- [NIST SP 800-38D — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [RustCrypto `chacha20poly1305`](https://docs.rs/chacha20poly1305)
- [RustCrypto `argon2`](https://docs.rs/argon2)
- [RustCrypto `hkdf`](https://docs.rs/hkdf)
- [`zeroize`](https://docs.rs/zeroize)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)

Reference architectures and formats:

- [Ente repository](https://github.com/ente/ente)
- [Ente architecture](https://ente.io/architecture/)
- [Ente Rust cryptography audit, April 2026](https://ente.com/reports/winfunc-Audit-Report-Apr-2026.pdf)
- [Cryptomator security target](https://docs.cryptomator.org/security/security-target/)
- [Cryptomator vault cryptography](https://docs.cryptomator.org/security/vault/)
- [age format](https://age-encryption.org/v1)

Platform references:

- [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
- [Android key invalidation](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException)
- [Android Auto Backup](https://developer.android.com/identity/data/autobackup)
- [Apple Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [Apple Data Protection classes](https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web)

Licenses and protocol assumptions MUST be reviewed before implementation code is reused. Architectural similarity does not imply protocol compatibility or license permission.

---

## 77. Summary

The Chur cryptographic model is:

```text
random VaultRootSecret
    protected by password, device, and recovery slots
        ↓
random SecurityCollectionKey per access domain and epoch
        ↓
random ObjectKey per media object
        ↓
HKDF-separated manifest/content/metadata/preview/commit keys
        ↓
independent XChaCha20-Poly1305 media chunks
        + authenticated immutable manifest
        + authenticated final commit
        + separate rewrappable object-key envelope
```

The resulting system provides:

- password changes without media re-encryption;
- independent object compromise boundaries;
- random-access authenticated playback;
- explicit complete-object verification;
- platform-backed daily unlock;
- recoverable root-key envelopes;
- independent real and decoy vault identities;
- ciphertext-only backup, sync, and collection sharing, subject to release gates;
- one portable Rust cryptographic implementation across Android, iOS, and CLI.

The design remains provisional until canonical encodings, parameters, vectors, fault tests, and an independent audit are complete.

## Direct peer session keys

The internal build uses CHURP2P3. The following paragraph specifies the previous classical transport. [Peer protocol v3](sync/PEER_PROTOCOL_V3.md)

The foreground peer transport has a separate `CHURP2P2` namespace; version-1 `CHURP2P1` hellos are refused. A one-use 256-bit invitation secret, two fresh 32-byte challenges, and an ephemeral X25519 exchange derive direction-separated 32-byte keys and a session binding with HKDF-SHA-256 under the registered `chur/v1/peer/*` labels. Each device signs the transcript hash and the binding with its enrolled Ed25519 device key, and Rust verifies that signature against the enrolled key before any synchronization data moves. The transcript hash, info labels, nonce construction, frame bound, and sequence AAD are specified in [SYNC_PROTOCOL_V1.md](sync/SYNC_PROTOCOL_V1.md). These keys are never used for vault, collection, or object encryption and never enter a portable backup. The ephemeral private keys are erased after the handshake, so disclosure of an invitation after a session does not permit decryption of its recorded traffic. Object and operation encryption retain their independent native keys and verification requirements.
