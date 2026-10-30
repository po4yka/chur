# Architecture Decision Records

> **Status:** Accepted ADR process, template, and index

ADRs record durable architectural choices, alternatives, consequences, and security impact. They explain **why** a decision exists; normative format and behavior remain in focused specifications.

## Status values

An ADR uses the document-status vocabulary defined once in [`../README.md`](../README.md#document-status): **Proposed**, **Accepted**, **Experimental**, **Deprecated**, **Superseded**, or **Rejected**. An ADR spells the superseded label `Superseded by ADR-NNNN` so the metadata line names the replacement.

## Template

```markdown
# ADR-NNNN: Title

- Status: Proposed
- Date: YYYY-MM-DD
- Decision owners: ...
- Related: links

## Context

## Decision

## Alternatives considered

## Consequences

### Positive

### Tradeoffs

## Security impact

## Compatibility impact

## Validation

## Follow-up
```

`Security impact` covers privacy impact and names the affected `SEC-` identifiers from [`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md). `Compatibility impact` covers migration and downgrade behavior. A Proposed ADR may title its validation section `Validation required before acceptance`.

## Process

- create an ADR for a decision affecting ownership, trust boundary, persisted/wire bytes, key lifecycle, major dependency, platform security policy, or release gate;
- do not edit the historical decision into a different choice after acceptance; supersede it with a new ADR;
- update related normative docs and vectors in the same change or state the sequencing explicitly;
- accepted ADRs must identify unresolved proposals and evidence required;
- security-sensitive ADRs require a second reviewer when possible.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-rust-owns-private-vault.md) | Rust owns the private vault | Accepted |
| [0002](0002-independent-aead-chunks.md) | Independent AEAD chunks for media | Accepted |
| [0003](0003-separate-object-key-envelope.md) | Separate object-key envelope from immutable container | Accepted |
| [0004](0004-rust-owned-private-catalog.md) | Rust-owned private catalog; SQLCipher preferred pending validation | Proposed |
| [0005](0005-real-and-decoy-vault-isolation.md) | Real and decoy vault cryptographic isolation | Accepted |
| [0006](0006-control-and-data-plane-ffi.md) | Split FFI control and data planes | Accepted |
| [0007](0007-local-first-before-sync.md) | Stabilize local vault before sync/sharing | Accepted |
| [0008](0008-freeze-object-container-v1-layout.md) | Freeze the object container v1 public layout | Accepted |
| [0009](0009-one-hkdf-label-registry.md) | One HKDF label registry | Accepted |
| [0010](0010-define-canonical-tuple-and-freeze-hkdf-salt.md) | Define the canonical tuple encoding and freeze the HKDF extract salt | Accepted |
| [0011](0011-freeze-vault-descriptor-authentication.md) | Freeze vault-descriptor authentication | Accepted |
| [0012](0012-import-journal-durability-ordering.md) | Reserve chunk indexes in the import journal before use | Accepted |
| [0013](0013-allocate-v1-format-constants.md) | Allocate the v1 format constants in one registry | Accepted |
| [0014](0014-observed-heads-causality-vector.md) | Observed-heads causality vector in the operation record | Accepted |
| [0016](0016-freeze-the-v1-c-abi.md) | Freeze the v1 C ABI: exports, handles, status type, and panic containment | Accepted |
| [0017](0017-freeze-the-supported-device-set.md) | Freeze the supported device set and the benchmark baseline | Accepted |
| [0018](0018-freeze-backup-package-framing.md) | Freeze the backup package framing and manifest key | Accepted |
| [0019](0019-freeze-remaining-v1-record-layouts.md) | Freeze the remaining v1 record layouts | Accepted |
| [0020](0020-set-the-v1-parser-limits.md) | Set the v1 parser limits | Accepted |
| [0021](0021-freeze-conflict-tie-break-and-set-semantics.md) | Freeze the conflict tie-break and set semantics | Accepted |
| [0022](0022-freeze-operation-chain-hash-and-identifier.md) | Freeze the operation chain hash, identifier, and cleartext field set | Accepted |
| [0023](0023-define-signed-checkpoint-and-bootstrap-attestation.md) | Signed checkpoint record and new-device bootstrap attestation | Accepted |
| [0024](0024-freeze-revocation-point-and-eager-rewrap.md) | Accepted revocation point and eager epoch rewrap | Accepted |
| [0025](0025-freeze-the-object-key-envelope-aad.md) | Freeze the object-key envelope AAD | Accepted |
| [0026](0026-argon2id-memory-floor-and-candidate-set.md) | Argon2id memory floor and the constant password-candidate set | Accepted |
| [0027](0027-freeze-the-deletion-transaction.md) | Freeze the deletion transaction and the crypto-erasure point | Accepted |
| [0028](0028-freeze-the-catalog-query-surface.md) | Freeze the catalog query surface, index set, and v1 search | Accepted |
| [0029](0029-freeze-the-recovery-secret-encoding.md) | Freeze the recovery-secret human encoding as BIP-39 English | Accepted |
| [0030](0030-freeze-the-vault-registry-and-discovery.md) | Freeze the vault registry layout and discovery order | Accepted |
| [0031](0031-continuous-integration-owns-gate-enforcement.md) | Continuous integration owns release-gate enforcement | Accepted |
| [0032](0032-vault-creation-requires-a-password-slot.md) | Vault creation requires a verified password slot | Accepted |
| [0033](0033-chur-operates-no-sync-service.md) | Chur operates no sync service; deployments are user-controlled | Accepted |
| [0034](0034-freeze-the-hkdf-context-element-lists.md) | Freeze the HKDF context element list of every v1 label | Accepted |
| [0035](0035-freeze-the-object-aad-tuple-widths.md) | Freeze the element widths of the three object AAD tuples | Accepted |
| [0036](0036-freeze-the-v1-key-slot-bodies.md) | Freeze the four v1 key-slot bodies and their AAD tuples | Accepted |
| [0037](0037-contain-panics-in-channel-less-exports.md) | Contain panics in exports that have no status channel | Accepted |
| [0038](0038-adopt-sqlcipher-as-the-v1-catalog-engine.md) | Adopt SQLCipher as the v1 catalog engine | Accepted |
| [0039](0039-freeze-the-catalog-header-commitment.md) | Freeze the catalog header commitment | Accepted |
| [0040](0040-add-a-rust-jni-adapter-crate.md) | Add a Rust JNI adapter crate for the Android boundary | Accepted |
| [0041](0041-the-android-keystore-slot-exchanges-root-bytes.md) | The Android Keystore slot exchanges root bytes with the host | Accepted |
| [0042](0042-freeze-the-audio-waveform-record.md) | Freeze the audio waveform as a peak-envelope record | Accepted |
| [0043](0043-the-backup-manifest-carries-a-commitment-not-an-inventory.md) | The backup manifest carries the inventory's commitment, not its entries | Accepted |
| [0044](0044-freeze-the-v1-sync-operation-record.md) | Freeze the v1 sync operation record, limits, and omission claim | Accepted |
| [0045](0045-freeze-device-membership-records.md) | Freeze v1 enrollment, revocation, membership, and checkpoint commitments | Accepted |
| [0046](0046-freeze-sync-operation-payloads.md) | Freeze v1 sync operation payloads and kind registry | Accepted |
| [0047](0047-resume-rewrap-from-the-next-missing-envelope.md) | Resume eager rewrap from the smallest missing target-epoch envelope | Accepted |
| [0048](0048-recover-a-device-from-a-portable-identity-envelope.md) | Recover a lost sync device through a portable identity envelope and checkpoint | Accepted |
| [0049](0049-add-sync-state-in-catalog-v2.md) | Add durable encrypted-sync state through catalog v2 and a crash-safe migration | Accepted |
| [0051](0051-derive-sync-operation-keys-and-selectors.md) | Derive sync operation keys and opaque selectors from existing secret domains | Accepted |
| [0052](0052-keep-v1-sync-history-uncompacted.md) | Commit collection epochs and keep v1 sync history uncompacted | Accepted |
| [0053](0053-freeze-the-v1-collection-grant.md) | Freeze the v1 collection grant, permissions, and HPKE context | Accepted |
| [0054](0054-freeze-collection-membership-records.md) | Freeze v1 collection membership, permission, and revocation records | Accepted |
| [0055](0055-add-sharing-state-in-catalog-v3.md) | Add durable collection-sharing state through catalog v3 | Accepted |
| [0056](0056-add-collection-scoped-sharing-operation-streams.md) | Add collection-scoped cross-vault sharing operation streams | Accepted |
| [0057](0057-add-collection-operation-streams-in-catalog-v4.md) | Add durable collection operation streams through catalog v4 | Accepted |
| [0058](0058-record-the-grant-acceptance-freeze-in-catalog-v5.md) | Record the grant acceptance freeze through catalog v5 | Accepted |
| [0059](0059-permit-user-started-requests-for-public-platform-security-data.md) | Permit user-started requests for public platform-security data | Accepted |
| [0060](0060-bounded-document-previews.md) | Import arbitrary files and bound private document previews | Proposed |
| [0061](0061-local-private-notes.md) | Store local private notes in the encrypted catalog | Proposed |
| [0062](0062-independent-selective-archives.md) | Create independent selective archives | Proposed |
| [0063](0063-local-encrypted-content-search.md) | Keep local OCR text in the encrypted catalog | Proposed |
| [0064](0064-receive-system-shares.md) | Receive system shares through explicit vault import | Proposed |
| [0066](0066-pad-object-containers-to-size-buckets.md) | Pad object containers to size buckets in container version 2 | Accepted |
| [0068](0068-carry-a-portable-catalog-export-in-backup-v2.md) | Carry a portable catalog export and a record commitment in backup version 2 | Accepted |
| [0069](0069-re-encrypt-objects-after-revocation.md) | Delete superseded envelopes and re-encrypt objects after a revocation | Accepted |
| [0070](0070-public-utilities-and-configured-entry.md) | Public utilities and configured entry | Accepted |
| [0072](0072-judge-retention-by-a-trusted-time-mark.md) | Judge trash and note retention by a trusted-time mark | Accepted |

Rows are ordered by ADR number. Number 0015 was not used; no ADR carries it and none will.

## Future ADR backlog

This list registers the decisions that still require an ADR. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §43 points here and keeps no list of its own. [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §74 is the second register: it tracks every open cryptographic decision item by item and annotates each one as it is resolved, and an item there is copied here only when it needs an ADR of its own. An entry leaves this list only when an accepted ADR, or a specification of rank 1 to rank 3 in the [authority hierarchy](../README.md#authority-hierarchy), records the decision.

- the exact password input maximum, [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §74 item 5, which [`../security/PASSWORD_PROFILE.md`](../security/PASSWORD_PROFILE.md) §3 proposes as 1024 encoded bytes and does not freeze; the rest of that profile is decided, the Unicode rules in §3 there, the Argon2id floor and default in §4 and [`0026`](0026-argon2id-memory-floor-and-candidate-set.md), and the Argon2 parser bounds in [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §18.3;
- Android Keystore and iOS Keychain exact policies, including the Apple slot representation that [`../security/KEY_SLOTS.md`](../security/KEY_SLOTS.md) §5 leaves open between a protected `DeviceUnlockSecret` and wrapped root bytes held directly as the Keychain secret;
- device identity portability, including whether the optional Secure Enclave or Android hardware identity keys of [`../sync/DEVICE_IDENTITY.md`](../sync/DEVICE_IDENTITY.md) §6 become a second suite;
- post-quantum recipient profile per [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §56 and [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §11.

- [ADR-0065: Peer-only sync without accounts](0065-peer-only-sync-without-accounts.md) — excludes every service backend and limits synchronization to explicit direct foreground connections.
- [ADR-0067: Signed peer transcript with X25519](0067-signed-peer-transcript-with-x25519.md) — authenticates each peer device with its enrolled key and adds an ephemeral X25519 exchange to the direct peer handshake.
