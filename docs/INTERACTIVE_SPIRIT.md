# Interactive Chur companion

> **Status:** Implemented locally. Physical-device acceptance remains open. See [validation](assurance/PET_ONBOARDING_VALIDATION_2026-10-22.md).

## Integration and controls

Chur is the fourth public application. Notes, Calculator, and Camera do not
create a spirit overlay. Choose Chur during first-launch onboarding or in
public-application preferences inside authenticated Settings.

The pet supports greeting, bounded dragging, a repeatable firefly treat, a
movable toy, sleep, and wake. It has no progression, needs, rewards, sound, or
background simulation. Leaving the scene resets the activity and position.
The 144dp touch target includes transparent margins. An undersized scene keeps
controls usable and does not create a renderer.

Tap the moon to change sleep. Hold it to enter the transition code, then use
normal authentication. The long press has an accessibility equivalent, labelled
neutrally ("More options") so it does not announce a hidden entry. Input
is transient and is cleared on background and dismissal. About's Version
fallback remains available. Public pet help does not explain private access.

The shared guide uses the existing character and fixed target identifiers.
It reserves layout space for its text instead of covering controls. The pet
scene supplies its own character during its tutorial. Other guide screens
create one compact renderer. Reduced Motion uses a static pose and direct
movement; the native clock stops after a successful static frame. Both native
adapters limit active rendering to 30fps and stop while inactive or hidden.

First-launch onboarding offers all four shells, explains public storage,
then accompanies creation or restore, recovery, library actions, and settings.
Existing installations keep their preferences and use manual tutorials.
Private tutorial status stays outside backup. No private route is restored.
Lock and session replacement revoke private guidance immediately.

## Ownership and privacy

Common Compose owns the pet interaction reducer and guide placement. Native adapters own renderer clocks, GLB decoding and GPU resources. Their only inputs are bundled artwork, clip names/serials, reduced-motion preference and normalized movement. No note, vault, controller, key, file path, telemetry or network request crosses this boundary. Existing Android/iOS native privacy covers are unchanged and remain above Compose.

No vault format, permission, account, cryptographic primitive, or FFI vault ABI changes. Only the public shell enum and local tutorial status gain new values. Private-state/logging invariants remain unchanged. The threat-model consideration is additional native parser code in the app process; it parses only one trusted, bundled asset, never imported/user-supplied glTF.

## Native implementations

Both standard application targets include Filament 1.77.3. Android uses TextureView/transparent swapchain. The iOS checked-in Xcode project and its `project.yml` compile Swift→Objective-C++→Filament Metal; its prebuild script prepares the checksum-pinned official SDK and stages the selected platform's static archives. A missing model or renderer initialization failure uses the transparent PNG fallback. Fallback does not provide 3D animation.

The adapters share authored coordinates (+Yup,+Zfront), origin camera, square orthographic safe bounds±1.125, warm100klux sunlight and no bloom/postprocessing. Narrow surfaces expand the frame rather than crop. They restore base transforms before sampling, snapshot the displayed authored pose for interruptions, apply a sole eye controller, then bounded tail offsets. The first two tail joints remain stiff. Native pixel parity is still a device gate, not established by matching constants.

## Dependency review

- **Capability/alternatives:** glTF skin/morph animation and transparent native rendering. Compose has no existing 3D renderer. RealityKit/USDZ needs a separate iOS asset/parity path; WebView/game engines introduce a larger integration surface.
- **Owner/license:** Google Filament, Apache 2.0; official release pinned to 1.77.3. License text is bundled on both platforms. No claim of independent security audit of this release.
- **Native surface:** Filament, backend, gltfio and its SDK static dependencies (including mesh/texture codecs). No runtime shader compiler, downloaded model or user-provided parser input. Android uses engine+gltfio AARs, without filament-utils.
- **Build network/reproducibility:** Android uses Maven artifacts and generated Gradle locks. iOS preparation downloads only the official release URL and checks SHA-256 `40bc8e5a51040cc4b0bf8aaff7bf339ce16e13485644f60dbe1cb023b284fde7`; an existing matching archive can be supplied through `FILAMENT_ARCHIVE`. SDK/cache files are ignored and not committed.
- **Targets/size:** Android arm64/x86_64 and iOS arm64/device+Simulator through the app's existing platform baselines. Downloaded Android AARs total about10.7MiB across all included ABIs; the official iOS SDK is much larger than the linked app delta. Current debug package size and a bounded simulator memory check are recorded in the validation report. Release-size delta, thermal behavior, and sustained physical-device frame times remain open.
- **Updates/removal:** keep SDK/runtime/tool versions in sync; recheck asset contract, locks, native builds, notices/advisories and device behavior. Removing the feature removes both native adapters/dependencies, prebuild staging, bundled art, pet screen, and guide presentation.

The GLB/PNG are intentional product artwork, not compiled application binaries or test recordings. GLB SHA-256: `feb2a8450932520e63673a4b07cc4d5c37f1170cb7bafe9a880683a6582fa429`. The adjacent manifest records clip/rig/eye/tail constraints. Nine authored clips are present; the pet also uses notice/sleep/wake. Heavy cinematic scenes are excluded.

## Verification and remaining gates

The current local check covers Kotlin interaction assertions, Kotlin/C++ numerical
parity, KMP and host tests, Android build/lint, native instrumentation, Swift
tests, and the full iOS Simulator app build. See the dated validation report for
commands, outcomes, and the exact remaining acceptance boundaries.

Android keeps the PNG until the TextureView publishes its first frame. iOS uses
[overlay placement](https://kotlinlang.org/docs/multiplatform/whats-new-compose-110.html#overlay-placement-for-interop-views)
for the transparent native surface. UIKit vault containers reserve the guide's
measured dock height; their controls publish target availability separately from
Compose scenes. Target registrations have independent owners so an outgoing
scene cannot remove the active scene's target.

The old Notes overlay is removed. Public-shell presentation tests cover its
continued absence, the pet controls, real gestures, visible pixels, and the
renderer lifecycle. Matching animation math does not establish native pixel
parity or physical-device acceptance.

Commands:

- `KOTLIN_COMPILER_LIB=/path/to/kotlin/lib python3 tests/spirit/check-native-parity.py`
- `./gradlew -I tests/spirit/verify-dependencies.gradle :shared:app:verifySpiritDependencies :apps:androidApp:verifySpiritDependencies`
- Standard project builds/tests from `DEVELOPMENT.md`; Apple setup in `apps/iosApp/SpiritRenderer/README.md`.

Official sources: https://github.com/google/filament/tree/v1.77.3 and https://repo.maven.apache.org/maven2/com/google/android/filament/filament-android/1.77.3/

### Distribution notices

Both applications bundle the Filament Apache-2.0 license and a conservative
runtime dependency notice inventory taken verbatim from the pinned upstream
v1.77.3 source (including codecs and material helpers). Each inventory entry
records its upstream path and source-content SHA-256. Review the inventory
when changing the SDK version or linked native archives.
