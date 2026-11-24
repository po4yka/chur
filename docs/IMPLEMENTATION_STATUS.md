# Implementation status

> **Status:** Accepted implementation inventory; not release approval\
> **Checked against:** feature code at `32419678a325283a5ba52f2e581d4332f209e2e2`, 2026-10-16; five P2 corrections on the `27a0a36d` baseline, 2026-10-17

This inventory describes the current pre-release code. Product contracts own behavior and limits. [Roadmap](../ROADMAP.md) owns phase scope; [release gates](assurance/RELEASE_GATES.md) own approval. Code, a local test pass, CI, device acceptance, and an independent audit are separate evidence.

## Network model update — 2026-10-20

The previous service transport has been removed. There is no account or backend of any operator. Direct foreground P2P now replaces HTTP sync, saved endpoints/tokens, background tasks, and service-mediated sharing UI. The new path includes explicit pairing, one-use invitations, signed-history verification, addressed object keys, resumable originals, and two-way completion. See [ADR-0065](adr/0065-peer-only-sync-without-accounts.md). Device acceptance and independent review of the replacement remain unverified; dated older sync evidence does not cover it.

## Available features

| Area | Current behavior and contract |
| --- | --- |
| Public shells | Notes, Calculator, Camera, and Chur, chosen during first-launch onboarding or authenticated Settings. Public Notes and confirmed camera photos are not encrypted by Chur and enter platform backup. [Discreet Mode](product/DISCREET_MODE.md) |
| Guided onboarding | First-launch choice, private setup and control guidance, manual replay, and public pet lessons. [ADR-0071](adr/0071-pet-shell-and-guided-onboarding.md), [local validation](assurance/PET_ONBOARDING_VALIDATION_2026-10-22.md). |
| Vault access | password or vault PIN, device slots, optional recovery, whole-app gate, and an independent decoy identity. [Provisioning](security/PROVISIONING.md), [key slots](security/KEY_SLOTS.md), [recovery](security/RECOVERY.md) |
| Media library | photos, video, audio, favorites, tags, filtering, pagination, recoverable Trash, authenticated playback, and encrypted derivatives. [Media pipeline](interop/MEDIA_PIPELINE.md) |
| Documents and files | all file types stored as opaque encrypted originals, bounded text/PDF previews, metadata search, export, backup, and the ordinary library actions. [Contract](product/DOCUMENTS_AND_FILES.md) |
| Recently added | Library → Browse; orders by import time and pages through all active history. Private notes keep their own section. [Contract](product/RECENTLY_ADDED.md) |
| Albums | nested albums, manual order, ancestor links, child navigation, and Back behavior. [Contract](product/ALBUM_NAVIGATION.md) |
| Folder export | one native folder selection exports the full album subtree as plaintext, with safe names, no overwrite, cancellation, and partial counts. [Contract](product/ALBUM_EXPORT.md) |
| Audio artwork | embedded covers are bounded, normalized, and encrypted during media import. Existing missing covers are not automatically rebuilt. [Contract](product/AUDIO_ARTWORK.md) |
| Private notes | local explicit-save editor, title/body search, pinning, Trash, UTF-8 export, full backup, and selective archives. Notes do not sync or enter collection sharing. [Contract](product/PRIVATE_NOTES.md) |
| Content search | foreground local text extraction and English/Russian image/PDF OCR. Text and FTS stay in SQLCipher. No semantic search, network OCR, or automatic background indexing. [Contract](product/CONTENT_SEARCH.md) |
| Full backup | Portable backup v2 stores the catalog and encrypted originals. Restore also reads v1. Device-bound slots do not travel. [Format](format/BACKUP_FORMAT_V2.md) |
| Selective archives | independent password and keys for selected originals, album subtrees, and saved private notes. Restore as a separate vault or import fresh copies. [Contract](product/SELECTIVE_ENCRYPTED_EXPORT.md) |
| External encryption | Public Settings or Vault Settings encrypts selected external files into CHURBAK1 without library import or a required local vault. [Contract](product/EXTERNAL_FILE_ENCRYPTION.md) |
| Share to Chur | Android SEND/SEND_MULTIPLE and an iOS Share Extension receive files, media, text, and URLs; normal authentication and destination confirmation precede import. Links are stored as text. [Contract](product/INCOMING_SHARES.md) |
| App icon actions | iOS Home Screen Quick Actions and Android dynamic App Shortcuts for Import, Search, Lock and hide, and New private note; normal authorization with one authentication for an explicit private command. [Contract](product/APP_ICON_ACTIONS.md) |
| Lock and privacy | immediate, idle, background, and panic lock; private screenshot/recents policy; Android Quick Settings Lock Chur tile. [Discreet Mode](product/DISCREET_MODE.md#lock-behavior) |
| Device synchronization | Direct foreground P2P only; no account, backend, saved endpoint, or background transfer. [Protocol](sync/SYNC_PROTOCOL_V1.md) |

## Storage and transfer boundaries

- Public Notes and the public camera album are outside the vault. The whole-app gate controls UI access and does not encrypt those public stores.
- Private notes and recognized content use separate tables and FTS surfaces inside SQLCipher. Media Search does not search private-note bodies or public Notes.
- Full backup preserves local private notes and the content index. Selective archives carry selected notes and originals but omit OCR records; sync and collection sharing omit local notes and OCR records. Index supported content again on the receiving device.
- Selective and external archives use a new temporary vault, independent keys, and CHURBAK1. Their password does not change the source vault. Published copies cannot be revoked by changing or deleting the source.
- iOS incoming ciphertext is a temporary, backup-excluded App Group queue, not a backup format or synchronized vault. The extension gets only an independent public receiving key. Android incoming URI sources are process-local and do not survive process death.
- Plaintext export leaves the vault boundary. The destination can retain it. Cancellation can leave completed files and, after process death, an incomplete provider file.

## Compatibility baseline

| Domain | Current value |
| --- | --- |
| Catalog | v19 (`0x0013`); sequential authenticated migrations from supported older schemas |
| Native ABI | 7.4; query capabilities before opening the runtime |
| Object container, descriptor, key-slot | see the [constant registry](format/CANONICAL_ENCODING_V1.md#15-constant-registry) |
| Android | minimum API 29, compile/target API 37; arm64-v8a and x86_64 |
| iOS | minimum 18.0; arm64 device and arm64 simulator; UIKit host plus Share Extension |

The repository manifests, lockfiles, and wrapper own dependency versions. [Development](../DEVELOPMENT.md) gives the current module layout and checks. No public release or backward downgrade guarantee follows from this table.

## Evidence and remaining acceptance

The peer-only replacement was checked locally on 2026-10-20: 805 Rust workspace tests and 427 Kotlin host tests passed without skips; workspace Clippy passed with warnings denied; Android debug and test APKs, both iOS Kotlin targets, and the complete iOS Simulator application built successfully. The P2P tests use two real encrypted vaults, JNI, and TCP to verify bidirectional originals and album edits, restart and reconnect, revocation, and socket closure on lock. Physical-device peer transfer and visual UI acceptance were not exercised in this session.

The [five P2 corrections](assurance/P2_CORRECTIONS_2026-10-17.md) cover external MIME bounds, private-note Trash export, committed imports after decoder shutdown failure, iOS provider cancellation, and video frame ownership. The dated record lists their regression coverage and acceptance limits.

The implementation work ran Rust workspace tests, clippy, and formatting; Android host tests, APK/lint checks, and focused emulator tests; Kotlin/Native tests and framework/device compilation; Swift helper tests; and a whole iOS app/extension build. The incoming-share flow also ran through Safari's real simulator Share sheet, encrypted staging, normal unlock, confirmation, and text viewing. These observations apply to the tested feature checkout, not to every provider or physical device.

CI runs Rust, vectors, fuzz smoke, policy checks, shared host/native tests, and Android application checks. Its macOS job builds the iOS app and extension for the simulator and runs Swift helper tests. Android instrumentation and signed iOS distribution builds require separate checks.

Still open:

- the independent local-format, backup, synchronization, and sharing reviews required by the release gates;
- the supported physical-device matrix, platform-key invalidation, provider interoperability, cross-device restore, and performance/energy acceptance;
- iOS distribution provisioning for `group.dev.po4yka.chur.incoming` on both `dev.po4yka.chur` and `dev.po4yka.chur.share`; a simulator pass does not establish distribution entitlements;
- a complete release evidence package, including reporting setup, SBOM, signing, and compliance decisions.

Historical [phase evidence](README.md#assurance) and dated inspection reports describe their own snapshots. They must not be read as the current ABI, schema, vector count, or a release approval.

## Further work

Private-note synchronization, automatic/repeated background OCR, Office content extraction, semantic/embedding search, generated captions, additional public shells, widgets/private system search, and a standalone decrypt-without-import tool are not implemented by the features above. Documents still remain storable and exportable when no preview or content extractor supports them. See [Later exploration](../ROADMAP.md#later-exploration).
