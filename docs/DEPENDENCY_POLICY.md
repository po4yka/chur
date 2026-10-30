# Chur Dependency Policy

> **Status:** Proposed normative supply-chain policy

Chur minimizes dependency and native-code surface because a vault inherits the security properties, maintenance quality, and build integrity of every component that can read secrets or produce persisted bytes.

## Principles

- prefer small, focused, actively maintained libraries;
- prefer standards-based primitives over custom constructions;
- prefer pure Rust in the secure core unless a mature native dependency provides a clear advantage;
- keep protocol bytes independent from serializer defaults and dependency versions;
- pin toolchains and lock dependency graphs;
- review transitive dependencies, features, licenses, and build scripts;
- remove unused dependencies promptly.

## Security-sensitive categories

The following require explicit review:

- cryptographic primitives and key handling;
- parsers, canonical encoders, compression, and image/media codecs;
- SQLCipher, SQLite, OpenSSL, or other C/C++ code;
- FFI and binding generators;
- networking, TLS, certificate validation, and serialization;
- code generation, Gradle plugins, Cargo build scripts, and CI actions;
- logging, crash reporting, analytics, and telemetry;
- backup, cloud, and identity SDKs.

## Approved cryptographic direction

The v1 design prefers audited or widely reviewed Rust implementations for:

```text
XChaCha20-Poly1305
Argon2id
HKDF-SHA-256
SHA-256
BLAKE3 for authenticated commitments when finalized
X25519 / Ed25519 for implemented sync and collection-sharing identities
secure randomness through getrandom/OS CSPRNG
zeroization helpers
```

A library being popular is not sufficient. Review API misuse resistance, maintenance, audit history, target support, constant-time claims, `unsafe`, and transitive dependencies.

## Adding a dependency

A pull request must document:

1. required capability;
2. considered alternatives, including standard-library or existing dependency solutions;
3. owner and maintenance activity;
4. license and notice obligations;
5. audit or review history;
6. Rust `unsafe` and native-code footprint;
7. build scripts and network access;
8. Android/iOS target compatibility;
9. binary-size and performance impact;
10. data, permissions, and telemetry behavior;
11. update and removal plan.

Security-critical additions require a dedicated reviewer.

## Version policy

- commit Gradle and Cargo lockfiles where applicable;
- pin GitHub Actions to immutable commit SHAs;
- avoid floating Git dependencies;
- record source revision for vendored code;
- upgrade deliberately with changelog and compatibility review;
- do not allow dependency updates to silently change persisted or wire bytes;
- keep a documented minimum Rust/toolchain policy once implementation begins.

## Haze 2 Android navigation material

The Android source set of `shared/app` uses the exact **2.0.1** release of
`dev.chrisbanes.haze:haze`, `haze-blur`, and `haze-glass`. These render navigation
material over shared Compose content. iOS uses UIKit and does not link Haze.
The alternative evaluated was Kyant Backdrop; implementing and maintaining a
second custom optics engine would add unnecessary rendering and lifecycle code.

- **Owner and license:** [Chris Banes / Haze](https://github.com/chrisbanes/haze/tree/2.0.1),
  Apache-2.0. Preserve the upstream license and applicable notices in distribution.
  Release/source inspection is not an independent security audit.
- **Scope:** Android graphics and Compose runtime dependencies; no Rust or C ABI
  change, new permission, persistent cache, background service, analytics, or
  runtime network request is required by this integration. Resolve transitives
  through the checked-in Gradle lockfiles. Dependency updates remain deliberate.
- **Resolved Android graph:** the three direct modules also bring
  `haze-utils:2.0.1` and their Android variants. The combined Markdown/Haze
  Android runtime locks select Activity 1.13.0,
  Core 1.19.1, AndroidX and JetBrains Lifecycle 2.11.0, Tracing 2.0.3,
  and NavigationEvent 1.0.0. Core compile/metadata entries remain at 1.18.0;
  the higher runtime resolution preserves Haze's constraint. Collection keeps
  its 1.5.0 compile and 1.6.0 runtime resolutions, with common resolution
  metadata at 1.6.0. Compose 1.12.1 and Kotlin 2.4.21 are unchanged by this
  integration. Haze adds no iOS renderer artifacts, native library, or change
  to stored vault formats. The four reviewed Android
  AARs total 887,401 downloaded bytes and contain no `jni/` or `prefab/`
  entries; this is not a measurement of the final APK size increase.
- **Runtime policy:** API 33+ uses AGSL glass, API 31–32 uses RenderEffect blur,
  and API 29–30 uses opaque surfaces. Increased contrast uses opaque surfaces.
  Source retention is `ClearWhenUnavailable`; the source and effect graph belong
  to the private composition, keyed by session generation, and leave with it.
  Native media surfaces are not copied. The experimental full-37.2 window-backdrop backend remains disabled:
  selected-source capture gives the application control over private input.
- **Cost and acceptance:** the extra offscreen layers affect GPU memory and frame
  timing; a readable fallback does not prove optical parity. Measure the
  integrated app, not only upstream samples. No device performance guarantee is
  implied by the dependency choice.
- **Removal/update:** platform chrome is behind the `PlatformVaultScaffold`
  boundary. Haze can be updated or removed in the Android implementation without
  changing shared screen state, native iOS controls, or stored vault bytes.

## Vendored agent skills

`.agents/` and `.claude/` hold agent instruction files copied from third-party repositories. They are vendored content under this policy, not generated state: they are tracked, reviewed on update, and never run against a real vault, a production secret, or user media. They contribute no code to the Android, iOS, Rust, or CLI artifacts and are excluded from release evidence and from the SBOM.

`skills-lock.json` is their manifest. Each entry records the upstream repository, the path within it, a content hash, and the upstream commit the content was taken from. The commit satisfies "record source revision for vendored code" above; a content hash alone proves integrity but not provenance, so it is not a substitute.

Every entry now carries a `commit`. The seven vendored skills trace to five distinct upstream commits, and each recorded commit reproduces the vendored bytes exactly. Thirty-nine rust-skills entries were removed on 2026-10-24: across about 800 agent session transcripts only `rust-lints` was ever invoked, and every listed skill adds its description to each session's context.

`.agents/hooks/` holds the Ponytail lifecycle hook scripts, from the same upstream as the `ponytail*` skills. Unlike the skills they are executable: `.claude/settings.json` and `.codex/hooks.json` run them with Node.js at session start, at subagent start, and on each prompt, on a developer machine only, and they write only Ponytail's mode flag under the agent's own configuration directory and, when a user changes the default level, `~/.config/ponytail/config.json`. `hooks-lock.json` records the upstream commit and the SHA-256 of each file; the same checker fails on a changed or unlocked file and, with `--verify-upstream`, on a file the recorded commit does not reproduce. `.agents/NOTICE.md` carries the MIT license that the skills and the hooks require.

Two hashes are recorded, and they are not interchangeable:

- `computedHash` belongs to the external skill-synchronisation tool, and this repository does not verify it. As written by `skills` 1.7.0, it covers the whole skill directory, with files in case-insensitive path order, so it is not the same value as `contentHash`. The values an earlier version of the tool recorded before the update to rust-skills `v0.2.0` did not reproduce a skill that also vendors a `references/` directory. It is kept because the tool owns it;
- `contentHash` is the value this repository verifies. It covers the whole vendored directory: SHA-256 over every file under it, in ascending order of the file's path relative to that directory, feeding for each file the relative path as UTF-8 with `/` separators and then the file bytes.

`scripts/check-vendored-skills.py` recomputes `contentHash` for every entry, reports a skill that is vendored but unlocked or locked but absent, and fails on any mismatch. It runs offline and is a job of the enforcing workflow. With `--verify-upstream` and a clone of each upstream repository it also checks that every recorded commit still reproduces the vendored bytes, which is the provenance half and needs the network.

A skill synchronisation updates both hashes and the commit, and the checker is what proves it did.

## Recorded additions

### `hpke` 0.14.0, Rust sharing protocol

- **Capability:** RFC 9180 Base-mode sealing and opening of one 32-byte collection key with DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256, and ChaCha20-Poly1305. Phase 4 and ADR-0053 require this exact interoperable construction.
- **Alternatives:** the Rust standard library has no HPKE API. The existing X25519, HKDF, and ChaCha20-Poly1305 primitives are not an HPKE implementation; composing RFC 9180 locally would create a new unaudited cryptographic protocol. A TLS library adds unrelated transport, certificate, native, and configuration surfaces.
- **Owner and maintenance:** `rozbb/rust-hpke` is the active upstream. Version 0.14.0 was the current crates.io release at adoption and declares MSRV 1.85, below this workspace's floor of 1.89.
- **License and review:** the crate is MIT OR Apache-2.0. No independent audit of this release was found. RFC 9180 known-answer vectors, Chur grant vectors, mobile-target builds, and the separate Gate 6 sharing audit remain mandatory.
- **Unsafe and native footprint:** the crate is pure Rust and advertises RFC 9180 compliance. The published source has no native library requirement. Its cryptographic backends remain part of the sharing audit scope.
- **Features:** exact version `=0.14.0`, default features disabled, only `alloc`, `getrandom`, `x25519`, and `chacha` enabled. ML-KEM/X-Wing, SHAKE, NIST curves, AES-GCM, and the broad KAT feature are absent.
- **Targets and size:** the selected profile reuses `x25519-dalek` 3.0.0 but introduces newer RustCrypto core versions for HPKE. Android and Apple native builds, duplicate-version review, and artifact-size checks remain release gates.
- **Data and telemetry:** the crate receives in-process public/private key bytes, fixed grant context, and one collection key. It performs no application file, process, network, permission, logging, analytics, or telemetry operation. Its randomness feature reads the operating-system CSPRNG for sender encapsulation.
- **Update and removal:** updates require RFC and Chur vectors, malformed-input tests, lockfile and advisory review, all mobile targets, and explicit protocol compatibility review. Removal requires another reviewed RFC 9180 implementation; a local construction is not an acceptable fallback.

### Ktor Client 3.5.2, shared sync transport

- **Capability:** a Kotlin Multiplatform HTTP client that transfers opaque Phase 3 records and ciphertext on Android and iOS.
- **Alternatives:** the Kotlin standard library has no network client. Separate native clients would duplicate the wire boundary and behavior.
- **Owner, license, and version:** JetBrains maintains Ktor under Apache 2.0. The exact first-adoption version is 3.5.2.
- **Features and targets:** common code uses only the client core and raw byte bodies. Android uses the OkHttp engine, and iOS uses the Darwin engine. No content negotiation, serializer, logging, WebSocket, server, or telemetry feature is enabled.
- **Data and security:** Ktor receives opaque signed records, ciphertext, random identifiers, and a per-device transport token. Platform TLS validates HTTPS. Plain HTTP is rejected except for loopback development endpoints.
- **Update and removal:** updates require Android host tests, both iOS compilations, server integration tests, dependency-graph review, and advisory checks. Removal requires another shared byte-oriented HTTP transport.

### `axum` 0.8.9 and `tokio` 1.53.1, Rust sync server

- **Capability:** a small HTTP/1 process for the Phase 3 self-hosted reference server. Axum maps bounded opaque request bodies to the existing synchronous server core. Tokio supplies the listener and task runtime.
- **Alternatives:** the standard library has no HTTP server. A hand-written parser would add an unsafe trust boundary. A larger web framework would add features the service does not use.
- **Owner and maintenance:** the Tokio project maintains both crates. The exact first-adoption versions are `=0.8.9` and `=1.53.1`.
- **License:** both crates are MIT licensed.
- **Features:** Axum default features are disabled; only `http1` and `tokio` are enabled. Tokio default features are disabled; only macros, networking, the multithreaded runtime, and signal support are enabled. The server has no JSON, WebSocket, HTTP/2, client, TLS, tracing, or template feature.
- **Data and telemetry:** the crates receive opaque protocol bytes and network metadata. They add no analytics or third-party log shipping. TLS and any request log remain at the operator's reverse proxy.
- **Update and removal:** updates require the HTTP integration tests, advisory checks, lockfile review, and a live upload/download smoke test. Removal requires another bounded HTTP transport.

### `x25519-dalek` 3.0.0, Rust sync core

- **Capability:** X25519 device key pairs for Phase 3 enrollment, collection-key grants, and portable identity recovery, and the ephemeral key exchange of the version-2 direct peer handshake in `chur-crypto` (ADR-0067). The handshake uses the same `static_secrets` and `zeroize` features with one fresh key pair for each connection; no feature is added. The protocol already selects X25519 and requires a key separate from Ed25519.
- **Alternatives:** the Rust standard library and the existing Chur crates have no X25519 API. A local implementation would add an unaudited cryptographic primitive. A general TLS or cryptography library would add unrelated protocols and native code.
- **Owner and maintenance:** the dalek-cryptography project maintains it in the same active `curve25519-dalek` workspace as `ed25519-dalek`. Version 3.0.0 has MSRV 1.85, below this workspace's floor of 1.89.
- **License:** BSD-3-Clause, with the same notice obligation as the repository.
- **Review history:** it uses the dalek Curve25519 implementation covered by the project's public review history. This does not replace the independent Phase 3 protocol review required by Gate 5.
- **Unsafe and native footprint:** `x25519-dalek` is pure Rust, has no `build.rs`, and contains no `unsafe`. Its existing `curve25519-dalek` dependency has the reviewed build and optimized arithmetic surface recorded for `ed25519-dalek` below.
- **Features:** exact version `=3.0.0`, default features disabled, only `static_secrets` and `zeroize` enabled. Chur supplies key bytes through its existing OS CSPRNG. Serde, crate-owned randomness, reusable-secret, and precomputed-table features are absent.
- **Targets and size:** the crate is `no_std` and uses no platform API. It adds `rand_core` as an inert trait dependency and reuses the existing curve implementation. Android and iOS target builds remain release gates.
- **Data and telemetry:** it receives only in-process key bytes and performs no file, environment, process, network, permission, logging, or telemetry operation.
- **Update and removal:** updates require identity and grant vectors, mobile-target builds, advisory checks, and explicit lockfile review. Removal requires another reviewed X25519 implementation.

### `ed25519-dalek` 3.0.0, Rust sync core

- **Capability:** RFC 8032 Ed25519 signatures for Phase 3 device identities, operation records, enrollment, revocation, and checkpoints. `CRYPTOGRAPHY.md` §5 and §52 already select Ed25519 and name this implementation direction.
- **Alternatives:** the Rust standard library has no Ed25519. A local implementation would create a new cryptographic primitive to audit. A TLS or general cryptography library adds unrelated protocol, native, and configuration surface.
- **Owner and maintenance:** the dalek-cryptography project maintains it in the active `curve25519-dalek` workspace. Version 3.0.0 uses Rust 2024 and MSRV 1.85, below this workspace's floor of 1.89.
- **License:** BSD-3-Clause, the repository license. The transitive RustCrypto `ed25519` and `signature` interfaces are Apache-2.0 OR MIT.
- **Review history:** the dalek libraries received a public Quarkslab review in 2019. That is supporting evidence, not the independent Phase 3 protocol review required by Gate 5.
- **Unsafe and native footprint:** `ed25519-dalek` is pure Rust, has no `build.rs`, and forbids unsafe code when batch verification is disabled. Chur enables no batch or hazardous low-level API. Its `curve25519-dalek` dependency uses a build script only to select compiler and target capabilities, a derive macro, and target-specific unsafe optimized arithmetic; `sha2` also uses target-specific unsafe optimized code. These transitive paths perform no network, process, or application-file I/O and remain in the cryptographic review scope.
- **Features:** exact version `=3.0.0`, default features disabled, only `fast` and `zeroize` enabled. Serde, PEM, PKCS#8, batch verification, legacy compatibility, digest/prehash, RNG, and `hazmat` are absent.
- **Targets and size:** the crate is `no_std`, requires no platform API, and supports the Android/iOS Rust targets. `fast` includes the curve precomputation table; the release artifact size is measured with the Phase 3 native packages.
- **Data and telemetry:** it accepts in-process keys and bytes and performs no file, environment, process, network, permission, logging, or telemetry operation.
- **Update and removal:** protocol bytes and RFC 8032 verification semantics are pinned by vectors. Updates are deliberate lockfile changes with vector, mobile-target, advisory, and size checks. Removal requires another reviewed RFC 8032 implementation.

### `androidx.media3`, Android only

- **Capability:** playing a video or a recording from a vault-backed byte source. [`interop/MEDIA_PIPELINE.md`](interop/MEDIA_PIPELINE.md) §1 puts codec probing and decoding on the platform, and §9 has the player ask for plaintext ranges; Media3 is the platform's player on Android and the only one whose `DataSource` interface accepts a source that is neither a file nor a URL.
- **Alternatives:** the framework `MediaPlayer` accepts a `FileDescriptor` or a `Uri` and no custom source, so it would need either a plaintext file on disk — which [`security/PLAINTEXT_LIFECYCLE.md`](security/PLAINTEXT_LIFECYCLE.md) §5 bounds to the cases where a platform API accepts nothing else — or a local socket, which is a second boundary with no authentication of its own. Neither is smaller than adding the library.
- **Owner and maintenance:** Google, as part of AndroidX. Actively released.
- **License:** Apache 2.0, with the notice obligation the other AndroidX artifacts already carry.
- **Native footprint:** the artifacts used here are Java and Kotlin. `media3-exoplayer` loads the platform's own codecs through `MediaCodec` and this build adds no software decoder extension.
- **Build scripts and network:** none beyond the ordinary Maven resolution the Gradle lockfile pins.
- **Reach:** it never sees a container, a key, or a path. It receives plaintext ranges from `ChurDataSource`, which holds one reader lease and calls `chur_object_reader_read_at`, so every byte it decodes is downstream of an authenticated chunk. A codec failure is a decode failure and cannot reach ciphertext.
- **Telemetry:** none is enabled. The artifacts used are `media3-exoplayer`, `media3-datasource`, and `media3-ui`; no analytics or cast artifact is added.
- **Removal plan:** the seam is `VaultPlayer`, an `expect` function with one Android implementation. Replacing the player replaces that file.

iOS adds nothing: `AVFoundation` is part of the platform, and the resource-loader delegate that feeds it is written in Kotlin/Native beside the Android data source.

### `androidx.security:security-state` 1.1.0, Android only

- **Capability:** the system security patch line of [`ANDROID.md`](ANDROID.md) §25.1. The library reads the installed patch level, asks the trusted on-device update clients over IPC for a staged level, and compares the device with a published vulnerability report, including the supplemental patches of the bulletin's risk-based releases.
- **Alternatives:** `Build.VERSION.SECURITY_PATCH` gives only the declared system level. It gives no staged level, because the update-client IPC contract is defined by this library. It also has no bulletin comparison that counts supplemental patches. A local reimplementation would copy a Google-maintained contract that changes with the bulletin format.
- **Owner and maintenance:** Google, as part of AndroidX. Version 1.1.0 is the stable release of September 2026.
- **License:** Apache 2.0, with the notice obligation that the other AndroidX artifacts already carry.
- **Native footprint:** none. The AAR holds Java bytecode only and declares `minSdkVersion` 24, below the floor of 29 in [ADR-0017](adr/0017-freeze-the-supported-device-set.md).
- **Transitive dependencies:** `androidx.annotation`, `androidx.core`, `androidx.webkit`, `androidx.concurrent:concurrent-futures-ktx`, Guava `listenablefuture` 1.0 (the empty compatibility artifact), `kotlinx-serialization-json`, and `kotlinx-coroutines-core`. The Gradle lockfile pins the resolved versions.
- **Build scripts and network:** the library performs no network request. The app fetches the report itself and hands it to the library, under [ADR-0059](adr/0059-permit-user-started-requests-for-public-platform-security-data.md).
- **Reach:** it never sees a vault value. It reads system properties, binds to the update-client services, and parses the report JSON as untrusted input. The merged manifest gains the `<queries>` element that `ANDROID.md` §24 describes.
- **Telemetry:** none. The library writes only `Log` lines about provider lookup, which carry no vault data.
- **Removal plan:** the seam is `SystemSecurity.kt` in the Android host and one optional field of `VaultUiState`. Removing the library removes that file and hides the row.

### `proptest` 1.12, Rust tests only

- **Capability:** property tests in `chur-format/tests/properties.rs`. They check round trips over arbitrary values and the `CANONICAL_ENCODING_V1.md` §8 rule that an accepted input, also one with a changed byte, re-encodes to the same bytes. The unit tests pin boundary values, and the fuzz targets check only that a parser does not panic.
- **Alternatives:** a hand-written random loop has no shrinking and no failure persistence. `arbitrary` is already in the fuzz graph, but it has no strategies and no shrinking outside libFuzzer.
- **Owner and license:** the `proptest-rs` organization maintains it under MIT OR Apache-2.0.
- **Footprint:** a dev-dependency only, so it never enters a library, an FFI artifact, or an app. Default features are off and only `std` is on: no process fork, timeout thread, or temp-file graph. It adds `rand`, `rand_xorshift`, `regex-syntax`, `unarray`, and `core_detect` to the test graph. No `unsafe` code of ours, no build script, no network access.
- **Update and removal:** Dependabot updates it with the cargo group. Removal deletes the test file and the dev-dependency.

## Cargo features

Disable default features unless they are understood. Features that add platform key access, network clients, file-system traversal, dynamic loading, serialization formats, or native libraries require review.

### `zeroize` for `argon2` 0.6 and `chacha20poly1305` 0.11

- **Change:** both crates keep default features disabled and enable `alloc` and `zeroize`. The feature adds a dependency edge to `zeroize` 1.9.1, which the lockfile already contains. It adds no package, version, algorithm, build script, or native code.
- **Reason:** without the feature, `argon2` does not wipe its initial hash and `Block` does not implement `Zeroize`, and `chacha20poly1305` does not wipe the key that a cipher instance holds. With parallelism 1, the final Argon2 block determines the password KEK.
- **Use:** `chur-crypto` gives Argon2 a block buffer that it owns as `Zeroizing<Vec<Block>>`, because `Argon2::hash_password_into` releases its own buffer without a wipe. The derived key does not change; a unit test compares it with the output of the primitive's own buffer.
- **Update:** a later version of either crate must keep this feature, and a review must confirm that the feature still wipes the same state.

## Native dependencies

SQLCipher/OpenSSL/FFmpeg/libheif-like dependencies require:

- reproducible source or trusted binary provenance;
- target/architecture matrix;
- symbol and linkage inspection;
- license review;
- patch and vulnerability process;
- binary-size measurement;
- sandbox and codec attack-surface analysis;
- release artifact verification.

Do not download executable dependencies during a release build from mutable URLs.

## Build scripts and plugins

Cargo `build.rs`, Gradle plugins, KSP processors, and code generators execute with developer/CI privileges. Review them as code execution dependencies. Generated output must be reproducible and traceable to a pinned generator.

## Unsafe code

`unsafe_code = "forbid"` in `[workspace.lints.rust]` is the default for every crate in `rust/`. `forbid` cannot be lifted by an inner `allow` or `expect`, so a crate that must contain `unsafe` cannot inherit it. Two crates are exempt, `chur-ffi` and `chur-jni`, and no third is without an ADR.

`chur-ffi` is the first: the v1 C ABI of [`interop/FFI_CONTRACT.md`](interop/FFI_CONTRACT.md) requires `#[unsafe(no_mangle)] pub extern "C"` exports and a caller-allocated raw-buffer data plane, and neither compiles under `forbid`. `rust/crates/chur-ffi/Cargo.toml` therefore declares its own `[lints.rust]` and `[lints.clippy]` tables instead of inheriting, and sets `unsafe_code = "deny"`; a block overrides that level with `#[expect(unsafe_code, reason = ...)]` and an adjacent SAFETY comment.

`chur-jni` is the second, under [ADR-0040](adr/0040-add-a-rust-jni-adapter-crate.md). JNI requires a native function whose symbol name encodes the Java class and method, and [`interop/FFI_CONTRACT.md`](interop/FFI_CONTRACT.md) §6.2 forbids such a symbol in the Chur library, so the Android adapter is a second artifact. It holds no logic: every function reads the JVM arguments, calls one `chur_*` export, and writes the result back.

Two consequences follow and are requirements, not notes. A crate-local lint table replaces inheritance rather than extending it, so it repeats every workspace level, and a change to `[workspace.lints]` must be applied to it in the same pull request. Adding a third crate to this exception requires an ADR; loosening the workspace lint instead of adding a crate-local table is a defect.

New `unsafe` code must:

- be isolated to a narrow module;
- state safety invariants adjacent to the block;
- have misuse and boundary tests;
- avoid exposing raw pointers to feature code;
- be included in security-review scope;
- be inspected when compiler or target assumptions change.

## Licenses

The repository uses BSD 3-Clause, but dependencies may use other compatible licenses. AGPL/GPL code must not be copied or linked without an explicit distribution and architecture decision. Preserve required notices and source-offer obligations.

## Vulnerability management

CI should eventually run:

```text
cargo audit or equivalent advisory checks
cargo deny for licenses/bans/sources
Gradle dependency vulnerability scanning
SBOM generation
secret scanning
pinned-action verification
```

An advisory is triaged by reachability, affected feature, attack preconditions, and availability of a fixed version. A waived advisory requires a documented owner, rationale, and expiry.

## Provenance and releases

Release artifacts should provide:

- source commit;
- dependency lockfiles;
- toolchain versions;
- SBOM;
- checksums/signatures;
- Android/iOS native architecture inventory;
- reproducible or independently repeatable build instructions;
- record of security gates passed.

## Telemetry SDKs

A dependency that captures logs, crashes, analytics, sessions, screens, or network traffic is denied by default for private-vault processes. Any future use requires a privacy review, strict redaction, opt-in policy where appropriate, and tests proving that private values cannot leave the device.

### Tesseract4Android 4.9.0 and bundled English/Russian models

- **Capability:** offline recognition of photos and rasterized PDF pages on Android. Existing Android APIs can render a page but cannot recognize text. Apple Vision provides the iOS path without an extra dependency.
- **Alternatives:** ML Kit's Latin recognizer does not cover Russian. A downloaded model would add a network and availability dependency. A local OCR engine with bundled English and Russian models meets the offline requirement.
- **Owner and pin:** Adaptech maintains [Tesseract4Android](https://github.com/adaptech-cz/Tesseract4Android/tree/15c534717b1cb58261b58d4e4c1200c7f81f668c). The exact standard artifact is `cz.adaptech.tesseract4android:tesseract4android:4.9.0`. The JitPack repository is restricted to that group. `:shared:feature-import:verifyOfflineOcrInputs` checks the reviewed AAR and model SHA-256 values before Android compilation and asset packaging. No OpenMP variant is used.
- **Models and provenance:** `eng.traineddata` and `rus.traineddata` come from [tessdata_fast revision 87416418657359cb625c412a48b6e1d6d41c29bd](https://github.com/tesseract-ocr/tessdata_fast/tree/87416418657359cb625c412a48b6e1d6d41c29bd). Both are committed unchanged. The runtime verifies their hashes before it installs the public model files under `noBackupFilesDir/ocr/tessdata`. It does not accept model paths or model bytes from imported documents or archives. Builds and runtime do not download models.
- **License:** the wrapper, Tesseract, and models use Apache-2.0. Leptonica, libjpeg, and libpng have their own permissive licenses. Upstream license texts and attribution are bundled under `shared/feature-import/src/androidMain/assets/ocr/`.
- **Native footprint and compatibility:** the AAR contains Tesseract 5.5.1, Leptonica 1.85.0, libjpeg 9f, and libpng 1.6.48. It is 12,848,454 bytes. Chur packages only its existing arm64-v8a and x86_64 targets. The native libraries for those targets total about 7.51 MB and 7.95 MB before compression. All eight reviewed 64-bit ELF libraries have 16 KiB load-segment alignment. The models add 7,974,826 bytes before compression. API 29 is above the engine's API 21 minimum. Mobile build and actual OCR tests remain separate release checks.
- **Review and parser boundary:** this is a native C/C++ and JNI parser addition, not an independently audited component. Recognition runs in a separate disposable `:ocr` process. Tesseract opens its models only from a directory path, and an isolated process has no readable app directory, so this process runs as the app UID. It receives only ARGB_8888 page pixels in an anonymous memory region, which it reads without mapping: no source bytes, descriptor for app data, vault handle, or key. The isolated `:media_decoder` process produces the pixels (on API 29, the `:media_platform` process produces PDF pages): image pixels come from the existing Android codec path, and PDF pixels come from `PdfRenderer`. Tesseract receives a `Bitmap`, not an imported filename or an encoded PNG/JPEG file. The parent enforces one decoder owner, bounded results, cancellation, and process exit before it releases decoded data.
- **Advisory scope:** model parsers are security-sensitive. Only the two hash-pinned bundled models reach Tesseract. The packaged libpng 1.6.48 is older than later upstream security fixes. Chur does not call its encoded-image file parser: the selected JNI entry point accepts decoded bitmaps. This limits the exposed path and does not establish that the bundled native binary is free of defects. Review the complete native dependency set on each update.
- **Data and permissions:** the engine has no Chur network, analytics, log, system-index, or public Notes integration. It adds no permission. Originals, page rasters, and text remain in memory; model files contain no private data. Recognized bytes go to the SQLCipher content index, and temporary byte arrays are cleared on success, failure, and cancellation.
- **Update and removal:** review upstream release notes and advisories, exact artifact/model hashes, native libraries and licenses, ELF alignment, real English/Russian image and PDF recognition, decoder cancellation, and the Android build before each update. Remove the dependency, model assets, and pinned-input check together if Android OCR is replaced. The encrypted index format does not depend on the engine, and a new engine must rebuild derived records.

### Markdown renderer 0.46.0 and local code highlighting

- **Capability:** shared Android/iOS CommonMark/GFM preview and code highlighting for public/private notes. Approved by the user during implementation on 2026-10-18. Source editing remains application-owned; preview never rewrites stored source.
- **Alternatives:** custom Markdown parsing/rendering duplicates a mature parser; Markwon is Android-only; Swift renderers are iOS-only; a WebView editor adds a browser/bridge lifecycle. No existing dependency supplied this capability.
- **Pins and maintenance:** `com.mikepenz:multiplatform-markdown-renderer-m3` and `-code` 0.46.0, [upstream release](https://github.com/mikepenz/multiplatform-markdown-renderer/releases/tag/v0.46.0). Transitive JetBrains Markdown 0.7.17 and Highlights 1.1.0 are locked in Gradle lockfiles.
- **Licenses:** [renderer Apache-2.0 with inherited MIT portions](https://github.com/mikepenz/multiplatform-markdown-renderer/blob/v0.46.0/LICENSE); [Highlights Apache-2.0](https://github.com/SnipMeDev/Highlights/blob/1.1.0/LICENSE). Preserve upstream notices; these are not cryptographic dependencies or independently audited parsers.
- **Boundary:** Kotlin/Compose libraries, no new Rust unsafe/native parser or platform permissions. No Coil/Ktor image-loader module, telemetry, remote fetch, CDN, WebView or new plaintext store is installed. Code headers/copy buttons remain disabled. URI handling is intercepted and gated by explicit confirmation.
- **Compatibility and cost:** validate Android and iOS with this repository's pinned Kotlin/Compose toolchain. Parsing/highlighting adds code size, CPU and transient document/layout allocations; benchmark actual long notes before changing existing note bounds. No claim of zero-copy or secure erasure follows from these dependencies.
- **Updates/removal:** update exact versions and locks deliberately, reviewing syntax/layout and private lifecycle regressions. Stored Markdown is independent of renderer serialization, so replacement does not require converting user source.

### Boot clock for the password-attempt delay

`chur-ffi` adds a direct edge to `libc` 0.2, default features off, on Unix targets only. It reads `CLOCK_BOOTTIME` on Android and `CLOCK_MONOTONIC` on Apple platforms through `clock_gettime`, and `kern.bootsessionuuid` through `sysctlbyname` on Apple platforms, which the standard library does not expose, for the delay of [`security/PASSWORD_PROFILE.md`](security/PASSWORD_PROFILE.md) §11. `std::time::Instant` cannot be stored across a process restart and does not count time asleep on every target. `libc` 0.2.189 is already in the production lockfile through `getrandom` and `cpufeatures`, so no package version is added. The edge adds two `unsafe` calls in `chur-ffi`, each with its SAFETY comment. No build script, network access, permission, or telemetry is added. Remove the edge if the standard library exposes a boot clock.

### Note attachment serialization

The catalog reuses already-pinned workspace `serde`/`serde_json` and existing `base64ct` 1.8.3 (alloc) for the portable JSON package and standard padded Base64. These are direct dependency edges to libraries already present in the production lockfile; no package version, crypto algorithm, network loader, or archive extractor is added. Temporary file bytes, Base64 strings and export buffers are zeroized. Native catalog validation remains independent of the UI package decoder.

### Portable JPEG XL decoder (2026-10-21)

The user approved `jxl-oxide =0.12.6` for Android and iOS. The OS codec alone
cannot provide the same JPEG XL support on both platforms. The crate is a
pure Rust decoder, under MIT OR Apache-2.0. Its optional `moxcms` feature
converts embedded ICC profiles to sRGB. Default features are off: no Rayon,
image encoder, CLI, native C codec, or network client enters the app graph.
The exact requirement follows the user's approval. Review a security update
before changing this pin.

The lockfile adds the `jxl-*` parser and rendering crates, Brotli decoding,
tracing, allocation helpers, and `moxcms` with `pxfm`, `num-traits`, and
`autocfg`. All licenses pass the existing allow list. Published source was
scanned for process, network, environment, and home-directory access. Runtime
parser code has no such access. `num-traits/build.rs` only runs compiler
feature probes through `autocfg`; it was read before the first build. The
candidate graph passed `cargo deny --locked check`: advisories, licenses,
bans, and sources. The pre-existing duplicate `syn` versions remain warnings.

Treat every source as untrusted. The adapter admits only a codestream or
standard container signature, at most 64 MiB encoded bytes, source dimensions
at most 16384 per edge and 64 Mi pixels, 1024 displayed frames, and 4096
internal frames. It checks source dimensions before feeding remaining frame
payloads. ImageHeader is parsed before decoder initialization. Encoded and decoded ICC
profile declarations are each capped at 1 MiB, before upstream ICC allocations.
The retained header prefix is at most 2 MiB. The adapter uses the container
parser to extract codestream events only: Exif, XML, compressed `brob`, JPEG
reconstruction, and other ancillary boxes never enter the pixel decoder. This
avoids unbounded decompression of metadata that viewing does not need. The
already locked `jxl-bitstream`, `jxl-oxide-common`, `jxl-coding`, and `jxl-grid`
crates are direct dependencies for this preflight and typed allocation errors.
The decoder grid allocation tracker has a 256 MiB ceiling. That
tracker does not cover every dependency allocation, including compressed
input, ICC profiles, and frame metadata; the encoded-size and frame limits
provide additional bounds. Each output is at most 4096 per edge. Output is
RGBA8 sRGB with straight alpha; this is an SDR display path, not HDR output.
Scaling does not upscale and uses nearest samples.

The caller keeps source bytes in a transient direct buffer or supplies a
borrowed seekable FD. FD reads use positional IO and do not change its offset.
There are no plaintext temporary files. Rust clears its transient 4 KiB encoded
read buffer and row buffer, and Kotlin clears each caller-owned output before
release. The upstream decoder's private cached grids do not expose a secure
wipe API: close releases those allocations, with the same residual allocator
risk as a platform image decoder. Do not claim that decoder close proves
zeroization of every upstream allocation. Viewers must close the decoder and
release image surfaces on lock, disposal, and memory pressure.

Every C and JNI export contains panics and returns fixed status codes, with
no untrusted decoder error text. Handles use the existing typed generational
registry; forged values are never dereferenced. ABI 7.1 adds four decoder
exports and capability bit 9 without changing the vault or sync format.
