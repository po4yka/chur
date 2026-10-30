# Collection Grants

> **Status:** Accepted normative Phase 4 protocol

A collection grant authorizes a recipient device/user to unwrap one Security Collection key epoch. This grant opens collection metadata. Object content keys use separate [disposable object-key grants](OBJECT_KEY_GRANTS.md). The signed operation log never contains an object-key envelope. Public-key cryptography wraps only small keys, never bulk media.

## 1. Cryptographic profile

HPKE profile `0x0001` is the RFC 9180 suite:

```text
KEM: DHKEM(X25519, HKDF-SHA-256)
KDF: HKDF-SHA-256
AEAD: ChaCha20-Poly1305
```

Sender/device authentication uses a separate Ed25519 signature over the canonical grant. HPKE Base mode alone does not prove sender identity.

## 2. Grant record

`CollectionGrantV1` is exactly 309 bytes:

```text
grant_version:u16                         = 0x0001
hpke_profile:u16                          = 0x0001
grant_id:bytes[16]
source_vault_id:bytes[16]
collection_id:bytes[16]
collection_epoch:u64
collection_membership_generation:u64
recipient_identity_vault_id:bytes[16]
recipient_device_id:bytes[16]
recipient_hpke_key_id:bytes[16]
sender_device_id:bytes[16]
sender_signing_key_id:bytes[16]
permissions:u8                            = 0x01, 0x03, or 0x07
sender_membership_generation:u64
created_sequence:u64
encapsulated_key:bytes[32]
wrapped_collection_key:bytes[48]
sender_signature:bytes[64]
```

Every identifier, generation, epoch, and sequence is non-zero. `u64::MAX` is invalid for a generation or epoch because it has no successor. The source and recipient identity-vault identifiers must differ: another device of the source vault uses Phase 3 enrollment, not sharing. `grant_id` equals the containing issue-grant operation identifier, and `created_sequence` equals its device sequence.

`sender_membership_generation` selects the accepted sender-device membership of [`DEVICE_IDENTITY.md`](DEVICE_IDENTITY.md) §4. `collection_membership_generation` independently selects the recipient and permission state of this collection. Neither value substitutes for the other.

## 3. HPKE plaintext/context

The HPKE plaintext is exactly the 32-byte `SecurityCollectionKey` for `collection_epoch`. Public-key encryption receives no media, metadata, or variable-length value.

The grant context is the first 165 bytes of the record, from `grant_version` through `created_sequence`. HPKE uses:

```text
info = "CHUR\x00SHARING\x00GRANT-HPKE-INFO\x00V1" || grant_context
aad  = "CHUR\x00SHARING\x00GRANT-HPKE-AAD\x00V1"  || grant_context
```

The 32-byte X25519 encapsulation and the 48-byte HPKE ciphertext follow the context. The ciphertext length is fixed: 32 key bytes plus the 16-byte ChaCha20-Poly1305 tag.

## 4. Sender signature

The Ed25519 input is `CHUR\x00SHARING\x00COLLECTION-GRANT\x00V1` followed by the first 245 bytes of the record, from `grant_version` through `wrapped_collection_key`. The recipient verifies:

- known authorized sender device;
- signature/key validity at membership generation;
- recipient key match;
- grant not revoked/stale;
- collection epoch accepted;
- HPKE decrypt/context.

The sender signing key identifier and recipient HPKE key identifier are the leading 16 bytes of:

```text
BLAKE3-256(key-id domain tag
    || identity_vault_id:bytes[16]
    || device_id:bytes[16]
    || suite:u16
    || public_key:bytes[32])
```

The signing tag is `CHUR\x00IDENTITY\x00SIGNING-KEY-ID\x00V1`; the HPKE tag is `CHUR\x00IDENTITY\x00HPKE-KEY-ID\x00V1`. The suite is `0x0001` for both v1 key types. A directory entry whose recomputed identifier differs is rejected before signature verification or HPKE open.

## 5. Recipient verification

Recipient key trust follows [`PEER_TRUST_MODEL.md`](PEER_TRUST_MODEL.md): an external recipient's keys are pinned on the first grant, and out-of-band verification before that first grant is offered but not required. Peer-provided names/avatars are not sufficient cryptographic proof. The fingerprint the user compares is constructed in [`DEVICE_IDENTITY.md`](DEVICE_IDENTITY.md) §5.

A change to a pinned recipient key blocks: no further grant is issued to that recipient until the user re-verifies the fingerprint, or until a signed identity rotation chaining to the pinned key authorizes the change. It is not a dismissible banner.

For an authenticated rotation, the old and new signing and HPKE key pairs must occur in that order in the same device's validated identity-membership chain. The source checks the recipient evidence before it issues a new membership record. A recipient checks its own durable identity-membership chain when it accepts the new grant. A signed collection-membership record alone does not authorize a key substitution. Rotation retains the pin's existing TOFU or user-verified level.

## 6. Permissions

The only v1 permission profiles are cumulative:

```text
0x01 READ
0x03 CONTRIBUTE      = READ | 0x02
0x07 MANAGE_MEMBERS  = CONTRIBUTE | 0x04
```

Every other byte fails closed. `READ` accepts replicated content state. `CONTRIBUTE` additionally authors ordinary collection operations, but not `CreateObject`, `CommitObject`, `RewrapObjectKey`, or `PurgeObject`, which only a source-vault device authors. `MANAGE_MEMBERS` additionally issues, changes, and revokes grants. Permissions affect accepted signed operations, not ciphertext ability already granted. A recipient with a collection key can decrypt all objects in that epoch available to it.

## 7. Multiple devices

A grant is always for one recipient device. A user-level interface issues one grant per verified active device. Phase 4 adds no separate user identity protocol.

## 8. Membership changes

Adding member:

- validate signed membership operation;
- issue grants for current epoch;
- no media re-encryption.

Removing member:

- sign revocation;
- create new collection epoch;
- rewrap active object keys under new epoch, eagerly and to completion per [`REVOCATION.md`](REVOCATION.md) §3.1;
- issue new grants to remaining members;
- prevent future operations/grants from removed device;
- accept that old epoch data previously downloaded remains accessible.

## 9. Replay and stale grants

Clients reject grants below the accepted sender membership generation, below the accepted membership generation for that recipient device, or below the accepted collection epoch, and reject a revoked grant. A later membership change for another recipient does not stale an existing grant. Identical grant replay is idempotent. Reusing one grant ID with different bytes is a security error. The authenticated membership chain is defined in [`COLLECTION_MEMBERSHIP.md`](COLLECTION_MEMBERSHIP.md).

## 10. Recovery and device rotation

New recipient devices require new verified keys and grants. They do not copy another device's private key. Device loss revokes that device's grant, advances collection membership, and rotates the collection epoch before remaining-device grants are issued.

## 11. Post-quantum extension

The `hpke_profile` field reserves future recipient types without changing local media containers. A hybrid X25519+ML-KEM profile requires a new allocated value, vectors, and audit; the peer never negotiates it.

## 12. Excluded from v1

There is no grant expiry. A device clock is not an authorization authority, and expiry cannot erase a key already delivered. There is no user-level identity record: multi-device users are the set of their individually enrolled and granted devices.

## 13. Tests

- valid sender/recipient grant;
- wrong recipient/key/context;
- modified encapsulation/ciphertext/permissions/epoch;
- invalid/unknown/revoked sender;
- replay/stale/conflicting grant;
- multi-device recipient;
- membership add/remove/epoch rotation;
- key-directory substitution;
- cross-platform HPKE/signature vectors;
- no bulk media passed to public-key encryption.
