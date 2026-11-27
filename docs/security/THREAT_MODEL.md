# Chur Threat Model

> **Status:** Proposed normative threat model  
> **Scope:** implemented local vault, documents, notes, OCR, archives, incoming shares, sync, and collection sharing; production gates remain open

## 1. Security objective

Chur protects the confidentiality and integrity of private photos, videos, audio, documents, arbitrary files, notes, recognized text, metadata, derivatives, and access keys while a vault is locked. It also reduces accidental disclosure while the application is in use. The strongest guarantee is **data-at-rest protection under a locked-vault model**.

Chur does not turn a compromised unlocked operating system into a trusted execution environment.

Discreet Mode can replace the ordinary visible entry with an explicit eight-digit transition code. This code only routes to normal authentication. It provides no protection against a person who knows the About fallback or inspects OS app information. Public notes, calculation history, photos, and videos are unencrypted app data and can enter system backup. They have no access to private keys or vault files.

## 2. Protected assets

| Asset | Confidentiality | Integrity | Availability |
| --- | ---: | ---: | ---: |
| `VaultRootSecret` and derived keys | Critical | Critical | Critical |
| Password and recovery inputs | Critical | Critical | Critical |
| Collection and object keys | Critical | Critical | Critical |
| Original media plaintext | Critical | Critical | High |
| Metadata, EXIF, GPS, names, tags | Critical | High | High |
| Thumbnails, previews, waveforms | Critical | High | Medium |
| Private catalog and search indexes | Critical | Critical | High |
| Device identity private keys | Critical | Critical | High |
| Sync operation log and tombstones | High | Critical | High |
| Independent archive passwords and temporary vault keys | Critical | Critical | High |
| iOS incoming receiving key and queued content | Critical | Critical | High |
| Public Notes and public camera photos | Outside vault protection | Medium | Medium |
| Ciphertext and opaque identifiers | Medium | Critical | High |
| Security configuration and audit state | High | Critical | High |

## 3. Trust boundaries

```text
User
  ↓ credentials / consent
Platform UI and key services
  ↓ bounded bytes and authorization
KMP application orchestration
  ↓ versioned FFI
Rust vault runtime
  ↓ encrypted catalog and object store
Application filesystem / directly connected peer
```

Trusted for their stated role:

- Rust cryptographic and storage core;
- correctly configured Android Keystore and iOS Keychain services;
- platform sandbox and data-protection mechanisms while the OS is not compromised;
- user-controlled password/recovery secret;
- deterministic specifications and tests used to build the release.

Not trusted with plaintext or root keys:

- public JSON, preferences, camera files, and ordinary platform backup;
- directly connected sync peer;
- analytics, crash reporting, and log collection;
- public-shell UI;
- other applications and content providers;
- network intermediaries;
- sharing recipients beyond granted access.

## 4. Attacker profiles

### A1 — Casual observer

Can see the launcher, notifications, recents, public shell, and unlocked screen from nearby. Cannot bypass OS access controls.

### A2 — Person holding an unlocked device

Can open applications and interact with Chur but does not know the private credential. May attempt screenshots, search, deep links, accessibility exploration, or public-shell inspection.

Under the default device-slot policy this adversary may already hold a working vault credential. Convenient mode, defined in [`KEY_SLOTS.md`](KEY_SLOTS.md) §1, is satisfied by the device unlock code as well as by biometry on both platforms: `userPresence` accepts the passcode on iOS, and the Android policy accepts a device credential. A person who knows the phone's passcode, PIN, or pattern therefore opens the vault through the device slot without knowing the password or the recovery secret, and that person is usually a partner, a family member, or anyone who has watched the code being typed. Resisting A2 and A8 requires strict mode, or an unlock that asks for the vault password independently of the device credential; nothing else in this model substitutes for it.

### A3 — Thief with a locked device

Controls the physical device and can attempt offline extraction, reboot, backup recovery, or OS authentication attacks without a valid credential.

### A4 — Sandbox-extraction attacker

Obtains application files, databases, backups, or filesystem snapshots but not an unlocked in-process root secret.

### A5 — Malicious or compromised peer

Controls stored ciphertext, responses, ordering, replay, omission, timing, and availability. Does not know user secrets.

### A6 — Rooted/jailbroken or instrumented-device attacker

Can inspect process memory, intercept calls, modify code, or observe plaintext after unlock. This exceeds the primary guarantee.

### A7 — Malicious input provider

Supplies malformed media, containers, backups, catalogs, key slots, sync records, lengths, KDF parameters, or codec inputs.

### A8 — Coercive UI inspector

Can demand that the user unlock the application and inspect visible content. Decoy Vault reduces disclosure but does not provide an undetectable hidden volume.

This adversary is assumed to know that the decoy feature exists: the store listing and the platform review notes describe it, by requirement. The control therefore rests on indistinguishability rather than on surprise, and its limits are stated in [`DECOY_VAULT.md`](DECOY_VAULT.md) §10. Under the convenient device-slot policy described in A2, this adversary also does not need any credential from the user if they know the device unlock code, and the decoy is irrelevant in that case.

### A9 — Previously authorized recipient

Possesses collection keys or plaintext obtained legitimately and may retain it after revocation.

### A10 — Supply-chain attacker

Attempts to compromise dependencies, build scripts, CI actions, signing, generated bindings, or release artifacts.

## 5. Security assumptions

- the user chooses a password with sufficient entropy or safely stores a recovery secret;
- under the default convenient device-slot policy, anyone the user has trusted with the device unlock code is trusted with the vault; a user who cannot make that assumption chooses strict mode or no device slot;
- OS random generation is functioning;
- approved cryptographic libraries implement their documented algorithms correctly;
- the locked device's platform security is not fully bypassed;
- release artifacts correspond to reviewed source and pinned dependencies;
- the application can obtain an app-private filesystem location;
- platform media APIs may see transient plaintext when needed for decoding or export;
- ciphertext size and access timing are not fully hidden.

## 6. Threats and controls

| ID | Threat | Primary controls | Residual risk |
| --- | --- | --- | --- |
| T-001 | offline password guessing | Argon2id, random salt, bounded/upgradeable parameters | weak user password remains weak |
| T-002 | sandbox copy reveals media | encrypted catalog, object containers, encrypted derivatives | sizes and object count may leak |
| T-003 | one key exposes all objects | independent random object keys | root/collection compromise has wider impact |
| T-004 | nonce reuse | per-revision random prefix, monotonic chunk index, tests | RNG or state-machine failure |
| T-005 | chunk substitution/reorder | canonical AAD binds object/stream/revision/index | implementation bug |
| T-006 | object truncation | authenticated final commit and complete verification | playback may intentionally verify only ranges |
| T-007 | malicious lengths/KDF parameters | hard limits before allocation/work | bounded denial of service remains possible |
| T-008 | interrupted import creates visible partial object | journal, temp ciphertext, fsync, atomic rename, catalog transaction | device/storage failure may require repair |
| T-009 | password change corrupts data | rewrap root only, transactional slot update | loss if every valid slot is destroyed |
| T-010 | platform key invalidation causes lockout | independent password/recovery slot | user may lose every factor |
| T-011 | logs/crashes leak private data | deny-by-default logging, redacted errors, tests | OS/runtime may inspect memory directly |
| T-012 | public shell reveals private state | separate stores/graph/navigation/cache | storage volume may remain observable |
| T-013 | real and decoy share state | separate roots/catalogs/namespaces/aliases/sessions | filesystem forensics may infer extra data |
| T-014 | stale media reader survives lock | session generation, in-place zeroization, cancellation | compromised process can bypass application logic |
| T-015 | peer replays old valid data | signed operation chains, local accepted heads | peer omission across devices is difficult to prove |
| T-016 | recipient impersonation | verified identity keys, signed grants, human verification | user may verify wrong identity |
| T-017 | revoked recipient retains access | collection epoch rotation and rewrap, deletion of superseded envelopes, automatic re-encryption under fresh object keys (ADR-0069) | ciphertext, keys, and plaintext already obtained remain available; objects stay under the rewrapped key until the background re-encryption reaches them |
| T-018 | malicious codec input | isolated Android decoder process with Binder range reads and no app storage, system media service sandboxes, minimal parsing, bounded resources | platform codec vulnerabilities; app-UID platform media and OCR children |
| T-019 | dependency compromise | pinning, review, SBOM, reproducible release evidence | ecosystem compromise can still occur |
| T-020 | backup omits objects | authenticated backup manifest and completeness check | stale but authentic backup remains possible without trusted checkpoint |
| T-021 | another local app or host process connects to desktop control | abstract UNIX socket with a random name that serves only the ADB shell UID or root, link shown only on screen and never copied, random 128-bit pairing code shown in the unlocked vault, length bounds, session shutdown on pause/lock | a compromised unlocked device or paired desktop can observe authorized commands |

### Additional local-feature boundaries

- Private notes and OCR text persist only in SQLCipher, including their FTS pages. Notes remain local; OCR records are local derived data. Full backup includes them, while sync/sharing omit both and selective archives omit OCR records.
- Documents, PDFs, OCR, embedded artwork, and incoming providers add untrusted parser inputs. Bounded memory, disposable Android decoder custody, platform parser isolation, cancellation, and import fallback reduce risk; they do not prove a malformed file safe. Tesseract's bundled native libraries and models remain in dependency review scope.
- Android decodes in-process image formats, JPEG XL, PDF pages, and embedded artwork in an `isolatedProcess` child. It has its own UID, no app storage, and no descriptor for app data; it reads source bytes through bounded Binder ranges. An isolated process cannot reach the system media services or read Tesseract's model files. Video, audio, and HEIF/AVIF therefore use a separate app-UID platform media child, where the system media processes parse and decode. OCR uses a separate app-UID child that receives only decoded pixels and uses no network. On API 29, PDF pages for OCR render in the platform media child, because that API level has no anonymous descriptor that `PdfRenderer` accepts in an isolated process. Residual risk: a defect in the HEIF/AVIF client path or in Tesseract and Leptonica on hostile pixels runs with the app's file access and network permission, and the main-process probe still reads image headers and media metadata. See [Android](../ANDROID.md#151-decoder-processes) section 15.1.
- Selective and external archives use independent keys and a new archive password. External encryption needs no local vault. Source deletion, lock, and later password changes cannot revoke published archives or plaintext exports.
- Android incoming sources use transient grants and process memory. Process death loses the pending batch. Untrusted intent extras, provider metadata, late results, and stale generations must not bypass confirmation or cross vault identities.
- The iOS extension writes a separate bounded, protected, backup-excluded encrypted queue. Its public RSA key can encrypt but cannot decrypt; the private receiving key stays in the main app's device-local Keychain. It is independent of every vault root. Queue maintenance is not a secure-flash-erasure guarantee. [ADR-0064](../adr/0064-receive-system-shares.md) states the trusted same-team extension assumption and the complete-envelope check.
- Public camera photos and public Notes are not encrypted by Chur and enter ordinary backup. The optional app gate does not change this. The Android lock tile exposes no identity, count, filename, thumbnail, or unlocked state.

See [Implementation status](../IMPLEMENTATION_STATUS.md), [Plaintext Lifecycle](PLAINTEXT_LIFECYCLE.md), and the individual [product contracts](../README.md#product) for limits and remaining acceptance.

## 7. Locked-state guarantee

When a vault is locked:

- no root, collection, object, stream, or catalog key remains intentionally available to feature code;
- private catalog connections are closed;
- native session handles are invalid;
- private navigation and decoded caches are cleared;
- persisted private media and metadata are ciphertext;
- platform device-bound factors may remain available only through Keystore/Keychain policy;
- public shell remains usable without access to private state.

Best-effort memory clearing cannot prove that a hostile OS did not copy earlier plaintext.

## 8. Unlocked-state exposure

While unlocked, Chur must minimize but cannot eliminate exposure. Plaintext may exist in:

- Rust buffers;
- direct/native FFI buffers;
- image and media decoder surfaces;
- Media3/AVFoundation buffers;
- protected scratch files for operations requiring a URL;
- visible UI and accessibility semantics.

The controls are bounded lifetimes, session-scoped caches, protected files, capture/snapshot policy, and immediate lock invalidation.

## 9. Metadata leakage

Even with full encryption, observers may learn:

- approximate ciphertext sizes;
- number of physical objects;
- import order: committed container access and modification times are normalized to the Unix epoch at commit under [`../format/OBJECT_CONTAINER_V1.md`](../format/OBJECT_CONTAINER_V1.md) §14, but directory-entry order and inode allocation order still correlate with the order objects were imported, and that residual is accepted;
- network timing and transfer volume;
- existence of a large encrypted application data set;
- device activity.

Padding, batching, and metadata normalization may reduce leakage later. Oblivious storage is out of scope.

## 10. Real and decoy limitations

Decoy Vault protects against ordinary and coercive interface inspection by presenting an independently encrypted plausible data set. It does not guarantee that forensic analysis cannot infer another vault from storage size, aliases, backups, or I/O patterns.

Marketing and UI must not use “undetectable,” “hidden volume,” or equivalent claims without a separate proven construction.

## 11. Direct peer model

Peers and their networks remain untrusted. Native signatures, causal validation, checkpoint floors, object-key authorization, and full container verification remain mandatory. Chur has no account, backend, relay, remote storage, or support-held recovery key. Availability, peer omission, traffic analysis, and deletion of previously received copies remain limited.

## 12. Verification mapping

Every accepted threat control must map to at least one of:

- unit or known-answer test;
- property test;
- corruption/fault-injection test;
- fuzz target;
- Android/iOS integration test;
- cross-platform vector;
- independent review item;
- release gate.

The authoritative mapping lives in [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md) and [`../assurance/SECURITY_TEST_PLAN.md`](../assurance/SECURITY_TEST_PLAN.md).

## 13. Review triggers

Update this threat model when adding:

- a new public shell or launcher disguise;
- background plaintext access;
- extensions, widgets, app groups, or shared processes;
- sync, sharing, web, desktop, or server-side recovery;
- new crypto suite or KDF profile;
- new catalog or container format;
- third-party telemetry or codec stack;
- enterprise/FIPS mode;
- post-quantum recipient support.
