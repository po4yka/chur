# Security Release Gates

> **Status:** Proposed normative advancement criteria

Features advance only when the evidence for their threat surface is complete. A successful build or feature demo is not a security release gate.

## Enforcement

A gate item is enforced by continuous integration, by a named review procedure, or by nothing. `.github/workflows/rust.yml` is the enforcing workflow; the repository maintainer owns it, creating it is Phase 0 scope in [`../../ROADMAP.md`](../../ROADMAP.md), and [ADR-0031](../adr/0031-continuous-integration-owns-gate-enforcement.md) fixes its v1 minimum job set: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo deny check`, run against `rust/` with every action pinned to an immutable commit SHA per [`../DEPENDENCY_POLICY.md`](../DEPENDENCY_POLICY.md#version-policy). Fuzz, vector-digest, benchmark, Gradle, and Xcode jobs join that set when their subject exists; a document may not name a job that does not.

The workflow exists and runs those four jobs. It also runs the vector-set check, the C ABI harness, the fuzz smoke pass, and the Gradle and Kotlin/Native test jobs, which joined it as their subjects landed. Its file is still named `rust.yml` because ADR-0031 named it when Rust was the only build. A gate item that one of them covers is enforced from the first pull request they ran on; every other item is still enforced by a named review procedure or by nothing, and every gated release records which of its items had no enforcing job. A contributor may run the equivalent command locally and attach its output to a pull request; that attachment is evidence for that pull request and is never recorded as a passed gate. A pull request whose every change is a top-level Markdown file or a file under `docs/` runs only `cargo fmt`, `cargo clippy`, `cargo test`, `cargo deny`, `vendored skills`, and `android backup rules`; the `changed paths` job skips the other jobs, which no such change can affect because no build, test, or script reads those paths. A new push to a pull request cancels the run on its earlier head; a push to `main` is never cancelled, so every `main` commit keeps its full run and its release candidate. A push to `main` runs every job.

The macOS CI job builds the Swift host and embedded Share Extension for the iOS Simulator and runs the Swift package helper tests. This build uses simulator settings with signing disabled. Distribution signing and entitlements still require archive inspection.

## Current feature acceptance

Files, private notes, selective archives, external encryption, OCR, public camera, the Android lock tile, and incoming shares extend the review surface without advancing a gate. The [current inventory](../IMPLEMENTATION_STATUS.md) links their contracts. Each release must include:

- parser, source/output bound, cancellation, stale-session, and partial-publication evidence for files and archives;
- note/index SQLCipher migration, cleanup, backup, and transfer-exclusion evidence;
- real English/Russian image/PDF recognition, native dependency/license/advisory review, decoder custody, and Android 16 KiB packaging checks;
- cold/warm OS Share delivery, provider revocation, encrypted iOS queue integrity, lock cleanup, and no automatic replay after import;
- iOS app/extension archive inspection with the registered App Group on both distribution profiles; simulator ad-hoc signing is insufficient;
- public-shell backup and no-private-data leakage checks, and a neutral Android tile that cannot unlock or reveal an identity.

[Development](../../DEVELOPMENT.md) gives local checks. CI does not execute Android instrumentation. Physical-device provider, key-slot, camera, performance, and interoperability checks remain separate.

## Gate 0 — design prototype

Permitted:

- local developer experiments;
- synthetic data only;
- unstable formats;
- no security claims.

Required:

- ownership boundaries documented;
- no committed production secrets;
- major design decisions tracked by ADR.

## Gate 1 — local alpha

Permitted:

- test/user-generated non-critical local vaults;
- no sync/sharing;
- explicit pre-audit warning.

Required:

- canonical encoding and v1 draft formats;
- key-slot/password profile;
- deterministic positive/negative vectors;
- Rust unit/property/corruption tests;
- FFI contract and platform prototype tests;
- recovery and process-death flows;
- security invariants mapped to tests.

## Gate 2 — local beta

Required:

- complete local threat model;
- all local parsers fuzzed;
- fault injection for initialization/import/slot/migration;
- Android/iOS device matrix;
- real/public storage leakage tests;
- plaintext lifecycle inspection;
- backup/restore if offered;
- no unresolved critical/high internal findings;
- published known limitations.

## Gate 3 — production local vault

Required:

- byte-frozen local formats and stable vectors;
- independent review of Rust crypto/format/catalog/FFI and platform key-slot integration;
- remediation and regression tests for findings;
- signed/repeatable release process and SBOM;
- `SECURITY.md` private reporting configured;
- migration/recovery evidence;
- support policy and production warning removed only when justified;
- the compliance record above is complete, with the classification, storefronts, jurisdictions, exclusions, and filings named.

## Gate 4 — portable backup

Additional requirements:

- backup format and vectors;
- complete/truncated/stale package tests;
- cross-platform restore;
- device-slot exclusion proof;
- old password/recovery rotation semantics documented;
- external review of backup manifest/completeness construction.

Phase 2 met four of the six and left two. The format exists and is exercised by `chur-format` `backup::tests`, `chur-media` `tests/backup_flow.rs`, and `chur-cli` `tests/backup_flow.rs`; the complete, truncated, tampered, reordered, and wrong-credential cases are among them; `a_device_bound_slot_does_not_travel` is the exclusion proof; and the rotation semantics of [`../format/BACKUP_FORMAT_V1.md`](../format/BACKUP_FORMAT_V1.md) §12 are stated in the product surface beside the action that writes a package.

The vectors are partly there. Twenty-six vectors under the `backup` format word carry every deterministic structure the format defines — for version 1 the public preamble, the record header, the two inventory entries, the ordered inventory commitment, and the two sealed records; for version 2 the catalog export stream, a sealed catalog export record, the record commitment, and the version 2 final commit — with the negative cases §5 of [`../format/TEST_VECTORS.md`](../format/TEST_VECTORS.md) requires. A *whole package* is not among them and cannot be: every sealed record has a random nonce, so two runs over one vault produce two packages that differ in bytes and mean the same thing. The eleven cases §14 of the backup format lists are covered by `chur-media` `tests/backup_flow.rs` as round trips instead.

Two requirements remain open: the independent backup-construction review and supported-device cross-platform restore. Local native/mobile tests do not supply either approval. The catalog-export divergence is resolved in format and code: [ADR-0068](../adr/0068-carry-a-portable-catalog-export-in-backup-v2.md) defines package version 2, whose catalog is the logical `CatalogExportV1` of [`../format/BACKUP_FORMAT_V2.md`](../format/BACKUP_FORMAT_V2.md) and carries no SQLCipher page. The cross-build evidence is local: `a_version_one_package_still_restores_and_moves_on_to_version_two` restores a package that the build before ADR-0068 wrote, on the same platform. A version 2 package restored on each supported platform is still required before the gate can close. [`EVIDENCE_PHASE_2.md`](EVIDENCE_PHASE_2.md) §5 is historical evidence, not a current gate pass.

## Gate 5 — synchronization

Additional requirements:

- direct peer trust model;
- device identity and signed operation log;
- device revocation, including the revocation point recorded in the operation log and the collection-epoch rotation that follows it;
- sync protocol/conflict/tombstone specs;
- checkpoint format and trust rule, with new-device bootstrap attested against a checkpoint commitment;
- replay/rollback/fork malicious-peer tests;
- ciphertext-only background verification;
- recovery across multiple devices;
- protocol-focused independent review.

## Gate 6 — sharing

Additional requirements:

- collection grant and recipient verification specs;
- HPKE/signature vectors;
- membership/epoch/rewrap/revocation tests;
- multi-device/multi-recipient interoperability;
- explicit recipient-retention limitation;
- separate sharing-protocol audit.

## Compliance

Two things are decided here and are not release paperwork.

Chur ships only the standard published algorithms of [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), adds no proprietary construction, and performs no cryptanalytic function, so the classification path is mass-market self-classification for both stores. No build variant may shorten a key, substitute an algorithm, disable a slot type, or remove the discreet presentation in order to enter a market; a market that cannot accept the shipped design is a market Chur does not enter. This rule exists before the formats freeze, because the alternative is a per-market format and a second set of vectors.

The remainder is a determination rather than a design choice, and the repository maintainer owns it. Before Gate 3 the evidence package records the export classification and its basis, the storefronts and jurisdictions the release targets, any market excluded and the reason, and any filing or notification made. Gate 1 and Gate 2 builds are not publicly distributed, so the record blocks Gate 3 only. `IOS.md` §37, `ANDROID.md` §37, and [`../interop/IOS_INTEGRATION.md`](../interop/IOS_INTEGRATION.md) answer store questions from that record and must not answer independently. The wording of the shared answers those documents cite is owned by [`../product/DISCREET_MODE.md`](../product/DISCREET_MODE.md); this record owns the classification and the jurisdictions behind it.

## Blocking findings

- Critical/High: block applicable gate until fixed and independently verified.
- Medium: block unless a documented risk acceptance with bounded scope, mitigation, owner, and expiry is approved.
- Low/Informational: tracked; may ship when no invariant is violated.

Severity labels do not override direct violation of a mandatory invariant.

## Evidence package

[`EVIDENCE_PHASE_0.md`](EVIDENCE_PHASE_0.md) is this record for Phase 0. It states what is met, what is not, and every item with no enforcing job. [`EVIDENCE_PHASE_1.md`](EVIDENCE_PHASE_1.md) is the same record for Phase 1, and it corrects the statements of the Phase 0 record that Phase 1 made untrue.

Each gated release records:

```text
source commit/tag
format/protocol versions
vector-set digest
toolchains/dependency locks
CI/test matrix
gate items with no enforcing job
fuzz campaign summary
performance/resource results
migration/backup evidence
audit/review reports and remediation
known limitations/waivers
artifact checksums/SBOM/signing evidence
```

## Emergency fixes

An emergency security release may narrow ordinary process but must still include a regression test, impact analysis, safe migration/compatibility decision, and follow-up review. It cannot silently change persisted bytes.
