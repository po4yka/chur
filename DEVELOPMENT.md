# Chur Development Guide

> **Status:** Accepted development environment and workflow

This document describes the checked-in Android, iOS, KMP, and Rust builds. Run commands from the indicated directory. A local pass is evidence for that checkout; it does not approve a security release gate.

## Target toolchain

| Area | Target |
| --- | --- |
| JDK | 21, pinned for Gradle builds |
| Kotlin | 2.4.20 / K2 |
| Compose Multiplatform | 1.12.1 |
| Gradle | 9.8.1, pinned by wrapper and distribution SHA-256 |
| Android | compile/target API 37; NDK pinned in version catalog |
| Xcode | 27.1 or later for Duo reserved-region APIs; deployment target iOS 18.0 |
| Swift | toolchain shipped with pinned Xcode |
| Rust | exact version pinned by `rust/rust-toolchain.toml`; supported floor in `rust-version` |
| Cargo tools | pinned or locked where reproducibility matters |

Do not rely on globally mutable defaults for JDK, NDK, Rust target, Xcode, or code-generation versions.

The version catalog is [`gradle/libs.versions.toml`](gradle/libs.versions.toml). The wrapper owns the Gradle version, and `rust/rust-toolchain.toml` owns the Rust toolchain. CI builds all four mobile Rust targets and runs shared tests. It does not compile the Swift app or Share Extension; those require the local Xcode checks below. Xcode and its Swift toolchain are not pinned by CI.

## Repository layout

```text
apps/androidApp/        Android host and instrumentation tests
apps/iosApp/            Xcode host, Share Extension, Swift package tests
shared/app/             shared screens, controller, routes, platform UI
shared/core-model/      error taxonomy and vector contract
shared/core-ffi/        NativeVault and hand-written C ABI adapters
shared/core-vault/      private repository and session/lock state
shared/core-platform-keys/ Android Keystore and Apple Keychain slots
shared/core-sync/       foreground direct peer transport and orchestration
shared/feature-import/  codecs, OCR, descriptors, export contracts
shared/feature-notes/   public Notes and JSON persistence
rust/crates/            secure core, JNI/C ABI, CLI, direct peer transport
rust/fuzz/              separate Cargo workspace
scripts/                native builds, device control, release/policy checks
docs/
test-vectors/
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module ownership. There is no convention-plugin build or separate module for each private screen.

## Initial setup

1. Install the pinned JDK and set `JAVA_HOME`.
2. Install Android Studio and the pinned SDK/NDK components.
3. Install Xcode and select it with `xcode-select`.
4. Install rustup and the repository-pinned toolchain.
5. Install required Rust targets for Android and iOS.
6. Clone the repository without copying local credentials into it.
7. Verify that generated/native artifact directories are ignored.

Use `./gradlew --version`, `rustup show` from `rust/`, and `xcodebuild -version` to check the selected tools. `ANDROID_HOME` identifies the SDK. Set `ANDROID_NDK_HOME` for the native script if more than one NDK is installed; Gradle uses the catalog pin.

## Internal post-quantum build

Normal Gradle, Cargo and Xcode commands use the classical profile and native ABI 7.4. Use the following command from the checkout root for the internal profile. Each invocation needs a new directory with an existing parent. Choose a sibling of the checkout or an empty path under a temporary directory.

```text
scripts/build-internal-pq.sh prepare NEW_DIRECTORY
scripts/build-internal-pq.sh test NEW_DIRECTORY
scripts/build-internal-pq.sh android NEW_DIRECTORY
scripts/build-internal-pq.sh ios NEW_DIRECTORY
```

The script copies the current working-tree contents of tracked files, applies the internal source and vector changes, and adds the internal files in the destination. The source checkout stays available for ordinary builds. Untracked files, including SDK settings and signing credentials, are outside the snapshot. Set the SDK environment variables from Initial setup. The script stops if the destination already exists or if an internal change no longer applies to the copied sources.

| Command | Result in the new directory |
|---|---|
| `prepare` | A source tree ready for inspection or native builds. |
| `test` | The Rust workspace tests, release C ABI handshake and CLI vector verification. Cargo writes the build output under `rust/target/`. |
| `android` | A Debug APK under `apps/androidApp/build/outputs/apk/debug/`. |
| `ios` | An ad-hoc signed iOS Simulator Debug app and its UI tests under `build/xcode/Build/Products/Debug-iphonesimulator/`. |

After the `ios` build, run `NEW_DIRECTORY/apps/iosApp/test-share-simulator.sh` to send a file through the system Share sheet and read its contents in the internal vault. The check uses a disposable simulator.

Both internal apps use `dev.po4yka.chur.pqinternal`, native ABI 8.4 and a new vault. Use the ordinary application for historical vaults. Keep test measurements with the source revision, build profile, ABI and target device. [Profile decision](docs/adr/0073-internal-post-quantum-profile.md) · [Release checks](docs/assurance/RELEASE_GATES.md#internal-post-quantum-profile)

## Build commands

The `:shared:app` and `:shared:feature-import` iOS tests use Apple Vision, ImageIO, and the system type registry. They need a fully booted simulator. A standalone simulator process can return no text or fail to resolve a registered media type without an API error. CI creates, boots, and removes its own compatible iPhone simulator. For a local run, boot a simulator that you own and set `CHUR_IOS_TEST_DEVICE` to its UDID. The build does not change the state of existing devices. Without this variable, Gradle uses its normal Xcode-selected device, which must already be booted.

The workflow named in [`docs/assurance/RELEASE_GATES.md`](docs/assurance/RELEASE_GATES.md#enforcement) is the CI source of truth, and it runs every check below on each pull request. Locally, after the last edit, run only the checks for the paths you changed:

| Changed paths | Local check |
|---|---|
| `rust/crates/<crate>` | `cargo test --locked -p <crate>` and `cargo clippy --locked -p <crate> --all-targets -- -D warnings`; use `--workspace` when a `pub` item that other crates use changed |
| `chur-ffi` exports, `include/chur.h`, or `chur-jni` | also the C ABI harness below and `scripts/build-native-targets.sh android` or `apple` |
| `test-vectors/` or the format code | `vectors verify` |
| `shared/<module>` | `./gradlew :shared:<module>:testAndroidHostTest`; add `iosSimulatorArm64Test` for `iosMain` code, and `jvmTest` exists only in `:shared:core-model` |
| `apps/androidApp` | `./gradlew :apps:androidApp:assembleDebug :apps:androidApp:lintDebug`; `check-backup-rules.py` for `res/xml` or the manifest |
| `apps/iosApp` | the `xcodebuild` command of the `kotlin-native` job |
| Gradle or Cargo dependencies | `cargo deny check`; for Android, write locks with the debug and the release tasks, `./gradlew :apps:androidApp:assembleDebug :apps:androidApp:lintDebug :apps:androidApp:assembleDebugAndroidTest :apps:androidApp:assembleRelease :apps:androidApp:bundleRelease :apps:androidApp:lintRelease --write-locks` with the disposable signing key of the `android application` job, because the job's lockfile step resolves only the debug tasks |
| `[workspace.lints]` in `rust/Cargo.toml`, or `rust/rust-toolchain.toml` | the workspace gate in the `rust-lints` skill "Verification", from `rust/` |
| `.agents/`, `skills-lock.json`, `hooks-lock.json` | `check-vendored-skills.py` |

The full list, which CI runs on every pull request; release signing and job-specific setup remain in the workflow:

```text
./gradlew jvmTest
./gradlew testAndroidHostTest
./gradlew iosSimulatorArm64Test
./gradlew compileKotlinIosArm64
./gradlew linkDebugFrameworkIosSimulatorArm64
./gradlew :shared:feature-notes:churPublicShellIsolation
./gradlew :apps:androidApp:assembleDebug :apps:androidApp:lintDebug :apps:androidApp:assembleDebugAndroidTest

scripts/build-native-targets.sh all
python3 scripts/check-vendored-skills.py
python3 scripts/check-backup-rules.py

cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
(cd fuzz && cargo deny --config ../deny.toml check)
cargo run --locked -p chur-cli -- vectors verify --dir ../test-vectors/v1
cargo run --locked -p chur-cli -- vectors digest --dir ../test-vectors/v1
(cd fuzz && cargo +nightly fuzz run <target> -- -runs=20000)
```

The `cargo` commands run in `rust/`; `cargo fuzz` runs in `rust/fuzz/`. The Gradle commands and scripts run at the repository root. Both the ordinary `abi` job and the internal `test` build compile and run the C ABI harness against their own release library and header. Run `scripts/check-c-abi.sh` from the source tree for the selected profile.

### Mobile runtime and Swift checks

Android instrumentation requires a selected emulator or device. Build and run with:

```sh
./gradlew :apps:androidApp:connectedDebugAndroidTest --no-watch-fs
```

Use a test device with synthetic data. These tests include lifecycle, files, notes, archives, OCR, incoming shares, and public-shell flows. CI assembles the test APK but does not run it.

Use `--no-watch-fs` for local test builds when external tools edit the checkout. It makes Gradle scan the source files again. Check that the test APK contains the changed code before installing it; an unchanged APK does not validate a source change.

For the local API 37, 16 KiB AVD `ChurMediaFormatsApi3720261017`, use this startup command:

```sh
"$ANDROID_HOME/emulator/emulator" -avd ChurMediaFormatsApi3720261017 \
  -data "$HOME/.android/avd/ChurMediaFormatsApi3720261017.avd/userdata-qemu.img" \
  -port 5554 -no-snapshot -no-audio -no-boot-anim -no-window -gpu host \
  -feature -Vulkan -feature -HardwareDecoder -cores 4 -memory 4096
```

The installed API 37 image's Goldfish H.264 host decoder fails to transfer a `MessageQueue` memfd under SELinux Enforcing. The emulator's documented [`HardwareDecoder` feature](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android/data/advancedFeatures.ini) controls this host decoder. Disable it only for this AVD launch. The same APK and native Live Photo fixture then pass all three Live Photo tests through the production Media3 player, with the platform selecting `c2.android.avc.decoder` and `c2.android.aac.decoder`. Keep SELinux Enforcing, authentication, and secure windows enabled. Do not change the SDK's global feature files. After boot, unlock the synthetic device before instrumentation starts.

On macOS, run the host helpers and compile the full iOS app and embedded extension:

```sh
swift test --package-path apps/iosApp
xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur \
  -configuration Debug -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

The Swift package tests exclude `ChurApp.swift`; they do not replace the app build. For simulator Share Extension acceptance, use Xcode ad-hoc signing:
`CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=-`.
A distribution build needs the registered App Group for both bundle IDs. See
[`apps/iosApp/README.md`](apps/iosApp/README.md#incoming-system-shares).
Do not change an Apple Developer account or provisioning profile as part of a local compile check.

Test actual system Share delivery separately from direct importer tests: public notice,
normal unlock, destination confirmation, import/cancel, and no replay after completion.
For iOS, also verify encrypted queue cleanup and cold/foreground delivery. For Android,
use another UID's content provider and temporary URI grants.

### Private onboarding UI acceptance

`PrivateOnboardingTest` (Android) and `PrivateOnboardingTests` (iOS) use the
production entry point and native core. Run each on a disposable device with a
fresh Chur installation and English UI. The tests create a synthetic vault,
confirm its recovery words, import a local image, search, review settings, and
verify the discreet-mode trial through normal password authentication. The creation tests do not restore or export an archive, delete the source
image, or use a test bypass. The separate restore tests use the real file picker
and a CLI-produced encrypted backup; they do not export from the running app.
The iOS keyboard Go action submits authentication. The system icon confirmation
can lock the app; the test uses the normal code and password path again.
Test logs and XCTest results can contain synthetic input; keep them local.

Seed `apps/iosApp/Resources/chur_interactive_fallback.png` as
`/sdcard/Download/onboarding.png` on Android, or add it to the iOS Simulator Photos
library with `xcrun simctl addmedia`. Install the app and Android test APK. Clear
only the disposable app's data before each first-install run. On iOS, uninstall
only that disposable Chur app before the next run; wait for Xcode to exit first.

```sh
adb -s "$CHUR_TEST_SERIAL" shell am instrument -w \
  -e class dev.po4yka.chur.android.PrivateOnboardingTest#complete_private_tour_and_revoke_manual_replay_on_background \
  dev.po4yka.chur.test/androidx.test.runner.AndroidJUnitRunner
xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur \
  -configuration Debug -destination "platform=iOS Simulator,id=$CHUR_TEST_SIMULATOR" \
  CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=- \
  -only-testing:ChurUITests/PrivateOnboardingTests/testFullPrivateOnboarding test
```

Use `build-gate --` for the build commands on this workstation. Check the Android
instrumentation summary as well as the shell exit status: `am instrument` can
exit zero when tests fail. Clear the disposable app data again before the launcher
regression suite, which expects the default non-discreet state. UI tests do not replace physical-device, full screen
reader, or performance acceptance.

### Restore onboarding UI acceptance

Run each restore test on a fresh disposable installation. Reuse the same
synthetic backup on both platforms. Build the pinned `chur-cli`, then create the
fixture through its production commands:

```sh
CHUR_RESTORE_FIXTURE=$(mktemp -d)
export CHUR_PASSWORD='Onboarding-public-test-2026'
cp apps/iosApp/Resources/chur_interactive_fallback.png "$CHUR_RESTORE_FIXTURE/restored-onboarding.png"
chur-cli vault --root "$CHUR_RESTORE_FIXTURE/source" create
chur-cli vault --root "$CHUR_RESTORE_FIXTURE/source" import "$CHUR_RESTORE_FIXTURE/restored-onboarding.png" --content-type image/png
chur-cli backup --root "$CHUR_RESTORE_FIXTURE/source" create "$CHUR_RESTORE_FIXTURE/restore-onboarding.churbak"
head -c 32 "$CHUR_RESTORE_FIXTURE/restore-onboarding.churbak" > "$CHUR_RESTORE_FIXTURE/truncated.churbak"
unset CHUR_PASSWORD
```

Copy both `.churbak` files to Android Downloads. On the disposable iOS Simulator,
copy them to `File Provider Storage/Chur restore fixtures` in the
`group.com.apple.FileProvider.LocalStorage` container returned by
`xcrun simctl get_app_container "$CHUR_TEST_SIMULATOR" com.apple.DocumentsApp groups`.
This seeds Files only; it does not install vault data or bypass the picker.

Use the preceding instrumentation/Xcode commands with these test selectors:

- Android: `dev.po4yka.chur.android.PrivateOnboardingTest#restore_archive_cancel_retry_authenticate_and_continue_tour`.
- iOS: `ChurUITests/PrivateOnboardingTests/testRestoreArchiveOnboarding`.

Each method needs its own fresh installation. The tests cover Back, picker
cancel, incorrect archive credentials, a truncated package, retry with the valid
package, the separate authentication gate, restored content, continued guidance,
and removal of guidance on lock. Keep the synthetic archives and test logs local.

### OCR assets and native dependencies

English and Russian traineddata, hashes, and license notices are checked in under
`shared/feature-import/src/androidMain/assets/ocr/`. The app makes no runtime model
download. The restricted Tesseract4Android repository, exact AAR pin, and model
provenance are in [`docs/DEPENDENCY_POLICY.md`](docs/DEPENDENCY_POLICY.md#tesseract4android-490-and-bundled-englishrussian-models).
Changing the engine or models requires real recognition fixtures, decoder-custody
checks, native alignment checks, and license/advisory review. See
[`docs/product/CONTENT_SEARCH.md`](docs/product/CONTENT_SEARCH.md).

## Native targets

The build supports these four, and the `native-targets` job of the enforcing workflow builds every one on every pull request:

```text
Android:
  aarch64-linux-android
  x86_64-linux-android for emulator and testing

iOS:
  aarch64-apple-ios
  aarch64-apple-ios-sim
```

```text
scripts/build-native-targets.sh android
scripts/build-native-targets.sh apple
scripts/build-native-targets.sh all
```

The script builds `chur-ffi` for each target and then checks that the archive exports the nine handshake symbols of [`docs/interop/FFI_CONTRACT.md`](docs/interop/FFI_CONTRACT.md) §2. An archive with no `chur_` symbol is one a host loads and then fails to call, so the symbol check is the point rather than an extra.

Android needs an NDK. The script reads `ANDROID_NDK_HOME`, then `ANDROID_NDK_ROOT`, then the newest NDK under `ANDROID_HOME/ndk`, and passes the linker to Cargo through a per-target environment variable, so no machine-specific path enters a checked-in `.cargo/config.toml`. The API level is 29, the floor [ADR-0017](docs/adr/0017-freeze-the-supported-device-set.md) freezes. The Apple targets need Xcode and build on macOS only.

Additional ABIs require an explicit support and testing decision. Release artifacts must contain only intended architectures.

## Local development workflow

1. Pull the current default branch.
2. Read the applicable normative documents.
3. Create or update an ADR for a design decision.
4. Implement the smallest coherent change.
5. Add tests before changing stable bytes.
6. Run common, Rust, Android, and iOS checks relevant to the change.
7. Inspect logs and artifacts for private data.
8. Open a focused pull request using `CONTRIBUTING.md`.

## Test data

Use generated synthetic media and deterministic test keys. Never commit:

- real user media;
- production vaults;
- passwords or recovery phrases;
- platform signing identities;
- provisioning profiles;
- Keystore/Keychain exports;
- unredacted crash reports.

Deterministic keys are permitted only inside clearly marked test-vector material.

## Rust workflow

Security-critical crates should expose testable, platform-neutral APIs. Recommended checks include:

```text
unit tests
property tests
known-answer tests
corruption tests
fuzz targets
Miri where applicable
sanitizers for native/FFI paths
cargo-deny or equivalent policy checks
```

`chur-cli` supports synthetic vault creation, import/export, listing, integrity checks, recovery, backup, vectors, and benchmarks. Use its `--help` for the implemented commands; do not infer a general repair command from the architecture. Credential reveal is an explicit setup/recovery action.

## KMP workflow

Common code tests should cover:

- UDF reducers and effect routing;
- session state transitions;
- navigation graph isolation;
- error mapping;
- cancellation and process-restoration policy;
- public/private persistence boundaries.

Platform tests cover key invalidation, file descriptors, media players, backup policy, lifecycle races, and scratch cleanup.

## FFI development

The FFI contract is versioned in [`docs/interop/FFI_CONTRACT.md`](docs/interop/FFI_CONTRACT.md). During development:

- keep control-plane values small and structured;
- use handles and bounded buffers for media;
- define allocator ownership explicitly;
- contain panics inside Rust;
- test lock during every long-running operation;
- verify that stale handles return `SESSION_EXPIRED`.

## Logging

Development builds may emit additional diagnostics, but private values remain forbidden. Do not log filenames, EXIF, GPS, keys, salts, wrapped keys, passwords, recovery secrets, private search queries, or stable private object identifiers.

Use stable event codes such as:

```text
IMPORT_STARTED
IMPORT_COMMITTED
OBJECT_INTEGRITY_FAILED
SESSION_LOCKED
PLATFORM_KEY_INVALIDATED
```

## Code generation

Generated code must be reproducible from checked-in schemas/configuration. A pull request changing generated output must also change its source and state the generator version. Generated FFI bindings must not become the canonical protocol definition.

## Driving a vault from the command line

`chur-cli vault` is the whole Phase 1 flow without a device
([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §9). A password reaches the
process through `CHUR_PASSWORD` or `--password-file`, never through an
argument: an argument is in `/proc`, in the shell history, and in `ps` output
for every user on the machine.

```sh
export CHUR_PASSWORD='...'
chur-cli vault --root ./v create --recovery   # prints the phrase once
chur-cli vault --root ./v import photo.jpg --content-type image/jpeg
chur-cli vault --root ./v list
chur-cli vault --root ./v show <object>
chur-cli vault --root ./v export <object> out.jpg
chur-cli vault --root ./v verify
CHUR_RECOVERY_PHRASE='...' chur-cli vault --root ./v recover
```

Every command but `create` and `status` unlocks first, and an unlock runs the
journal reconciliation of
[`docs/format/OBJECT_CONTAINER_V1.md`](docs/format/OBJECT_CONTAINER_V1.md) §14.4
and the garbage collection of
[`docs/format/CATALOG_SCHEMA_V1.md`](docs/format/CATALOG_SCHEMA_V1.md) §14.1,
exactly as a session on a device does.

`chur-cli backup` is the portable package of
[`docs/format/BACKUP_FORMAT_V1.md`](docs/format/BACKUP_FORMAT_V1.md), and the
same implementation both hosts call:

```sh
chur-cli backup --root ./v create vault.churbak
chur-cli backup inspect vault.churbak          # no credential, public bytes only
chur-cli backup --root ./restored restore vault.churbak
```

`restore` does not unlock the destination first. A restore installs an identity
rather than operating one, and §8 there obtains the credential from the
package's own portable descriptor, so restoring into an empty root is the
ordinary case. `inspect` reads the 32-byte public preamble and stops: §10
requires decrypted metadata to appear only after authentication, so it prints
the record count and the length and nothing a credential would have unsealed.

## Measuring

Four benchmarks run through the same binary Android and iOS build, so the
device measurement [`docs/assurance/PERFORMANCE_BUDGETS.md`](docs/assurance/PERFORMANCE_BUDGETS.md)
§1 requires needs a device and no new code:

```sh
chur-cli bench chunk-sizes --object-bytes 16777216 --samples 8
chur-cli bench argon2 --samples 8
chur-cli bench random-seek --object-bytes 16777216 --samples 32
chur-cli bench lock-invalidation --samples 8
```

Each one closes by stating what its numbers do and do not settle. That is a
convention rather than decoration: §1 of the budgets forbids treating a host
number as a gate.

## Native catalog build

`chur-catalog` compiles vendored SQLCipher and OpenSSL through `rusqlite`
([ADR-0038](docs/adr/0038-adopt-sqlcipher-as-the-v1-catalog-engine.md)). Two
environment facts change whether that build succeeds.

- **A compiler cache breaks the OpenSSL build.** The `cc` crate treats a
  `RUSTC_WRAPPER` naming `sccache` as a C compiler wrapper as well, and
  `openssl-sys` probes its headers with `cc -E`, which `sccache` refuses.
  Setting `CC` explicitly, for example `CC=/usr/bin/cc cargo test`, keeps the
  wrapper off the probe. The Rust side still caches.
- **Android needs an NDK and Apple needs Xcode**, exactly as
  [Native targets](#native-targets) already requires, and now for every build of
  the catalog crate rather than only for the mobile artifacts.
- **The Android build needs the NDK's binutils on `PATH`.** The vendored
  OpenSSL configures itself for Android and then invokes `${CROSS_COMPILE}ranlib`
  through `make`, which resolves on `PATH` rather than through an environment
  variable. `scripts/build-native-targets.sh` sets it; a hand-run `cargo build`
  for an Android target needs it too, or the build fails at `install_dev` with
  "ranlib: command not found".
- **The Apple build needs `IPHONEOS_DEPLOYMENT_TARGET` pinned** to the version
  [ADR-0017](docs/adr/0017-freeze-the-supported-device-set.md) supports. The
  vendored C is compiled against the installed SDK, whose objects reference
  symbols Rust's default iOS 10 link target does not provide, and the link fails
  on `___chkstk_darwin`. The script and the Gradle tasks both set it.

## Troubleshooting principles

- fail rather than silently downgrade cryptographic behavior;
- verify exact tool versions before diagnosing compiler/linker errors;
- inspect native architectures and exported symbols;
- reproduce format failures with `chur-cli` and synthetic data;
- preserve ciphertext and journals when investigating crash recovery;
- never request a user's password or recovery secret for debugging.

## Security-sensitive debugging

If temporarily instrumenting key or plaintext paths:

1. use synthetic data;
2. keep instrumentation local and uncommitted;
3. disable crash upload and analytics;
4. clear simulator/emulator/device test storage afterward;
5. verify that no diagnostic artifact entered Git history.
