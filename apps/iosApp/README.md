# Chur for iOS

> **Status:** Accepted implementation contract; security release gates remain separate

`Chur.xcodeproj` is the UIKit host for the shared Compose application. The
checked-in project builds without XcodeGen; `project.yml` is its source for
future project changes. Regenerate it with:

```sh
xcodegen generate --spec apps/iosApp/project.yml --project apps/iosApp
```

## Build

Use Xcode 27.1 or later, the Rust targets `aarch64-apple-ios-sim` and
`aarch64-apple-ios`, and the repository's Gradle wrapper. Open
`apps/iosApp/Chur.xcodeproj` and select the `Chur` scheme, or run:

```sh
xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur \
  -configuration Debug -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build

xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur \
  -configuration Debug -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```

Run the Swift host tests with `apps/iosApp/test-host.sh`. The script builds the Rust inbox ABI for the host before it links the tests.

The first build phase selects the matching Gradle framework and Rust static
library for the Xcode platform and configuration. The application links one
Rust archive. Its deployment target is iOS 18.0, matching
`gradle/libs.versions.toml`. Local builds do not request signing or change an
Apple Developer account. Device installation needs the user's existing signing
setup supplied to Xcode at build time.

The unsigned commands check compilation. To run the incoming-share flow in
Simulator, replace `CODE_SIGNING_ALLOWED=NO` with
`CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=-`.
Xcode embeds the App Group entitlements for Simulator with ad-hoc signing.
This does not register capabilities or change an Apple Developer account.

## Host bindings

`AdaptiveScene.swift` observes active UIKit reserved regions in the
current container's logical coordinates. Reads in `updateConstraints` let
UIKit invalidate geometry when a fold or camera region changes even without
a window resize. The Kotlin root keeps authentication and public content in a
contiguous usable region. The private host displays collection and viewer
alongside each other when both fit, retaining their existing scene leases and
one shared route/session; compact layouts use the same controllers in the
navigation stack. Closing the viewer and locking retire the same owners in
either arrangement. Folding alone does not change the background-lock policy
or open an additional scene.

Build SDK 27.1 is required for the host; the iOS 18 deployment target remains.
Reserved-region queries run only on iOS 27.1 and later. Verify on the Duo
simulator in outer, open, book and tabletop poses, including an open modal,
keyboard, viewer playback and privacy cover. Simulator geometry checks do not
replace physical-device camera and privacy acceptance.

`AppDelegate` checks the native ABI before any runtime opens, creates one
controller, excludes the vault and sync-state directories from backup, and
registers the background refresh task. `SceneDelegate` presents
`ChurViewController`, covers the app-switcher snapshot before resigning active,
locks on backgrounding, and schedules refresh. A background launch can open the
runtime without opening a vault session; signed ciphertext is staged until
unlock.

The host presents PhotosUI and Files pickers. For backup restore and selective
archive import, the host opens the selected Files document in place. It holds
the security scope and coordinated read until native code finishes. A Files
pick is answered once. A PhotosUI
pick is loaded and answered one item at a time: the host reports the fetch of
each item and stops it on a cancel, and Kotlin deletes the copy after its
import, before it loads the next item. Export uses a protected
temporary file for the Files picker, the share sheet, or Photos. Completion and
the next launch remove abandoned plaintext copies. The host requests add-only
Photos access when the user saves an export there. The default PhotosUI import needs no
photo-library permission because it grants access only to selected items.
The separate **Full Live Photos (Photos access)** action requests read-write access,
then saves every resource of each accessible selected Live Photo in one `.churlive`
object. The **Live Photo packages** action opens a portable `.churlive` file
through a coordinated Files source lease and the same media pipeline. This lets
you restore a package from Android without first adding it to Photos.
Full import preserves original resource bytes, audio in the paired movie, filenames,
UTIs, and resource roles. Limited access must include the selected asset. Denied
access or any missing resource fails the full import. This path never offers
source deletion. Export to Photos restores all roles in one request and reports
unsupported combinations. Export to Files retains all resources inside the
complete portable bundle. It does not create separate resource files on iOS. See [`LIVE_PHOTO_BUNDLE_V1.md`](../../docs/format/LIVE_PHOTO_BUNDLE_V1.md).
After a default import, the host requests read-write Photos access if the user
chooses to review the deletion of the originals, `IOS.md` §15.4. iOS asks for local network access during an explicit direct peer connection. The system prompt is bracketed by the foreground session, and leaving the app still locks the vault. There is no account, service configuration, sync task registration, or background fetch mode. `NSLocalNetworkUsageDescription` in `project.yml` explains direct device sync. Both apps must remain open; see [the P2P protocol](../../docs/sync/SYNC_PROTOCOL_V1.md).

## App icon

`ChurMirror.icon` is a native Icon Composer document and a target source in
`project.yml`; `ASSETCATALOG_COMPILER_APPICON_NAME` selects `ChurMirror`. It contains
separate mirror, reflected spirit, and external spirit layers, plus a contrast
adaptation for Mono appearances. Default and Dark preserve the silver/charcoal
artwork. There is no legacy `AppIcon.appiconset`. Xcode generates the older-system
representations from the document; the deployment target remains iOS 18.0.
Open the `.icon` in Icon Composer to edit materials and appearance overrides.
Selected artwork and layer-generation prompts are in `art/app-icon/`.

## Incoming system shares

`ChurShare.appex` is embedded in the application. Its Share extension accepts
up to 64 files, images, movies, audio items, text items, or URLs per request.
The user selects **Save to Chur**, then opens Chur to unlock and choose a vault
and album. The extension returns to the source app. It does not use private
APIs to launch Chur. Links are stored as UTF-8 text and are never fetched.
Source files are never removed.

The application and extension declare only the App Group
`group.dev.po4yka.chur.incoming`. A signed device or distribution build must
register this group for both bundle IDs (`dev.po4yka.chur` and
`dev.po4yka.chur.share`) in the existing Apple signing setup. Local unsigned
builds do not register capabilities or change an Apple Developer account.
Open Chur once after installation to prepare the inbox. An unavailable group
or locked Keychain fails closed; the extension explains how to retry.

The app stores a separate 32-byte X-Wing receiving seed in its own Keychain,
with `WhenUnlockedThisDeviceOnly` accessibility. The extension receives only
its public key. No vault key, password, session, or catalog is shared. Each
item has a fresh AES-256-GCM key, sealed with X-Wing HPKE, HKDF-SHA256, and ChaCha20-Poly1305. The internal `CHURIN02` header carries an 1120-byte encapsulation and a 48-byte sealed item key. Encrypted,
bounded metadata contains the original name, MIME type, and byte length.
One MiB authenticated chunks bind the envelope header and chunk position.
Random batch names and numbered ciphertext filenames reveal no source names.
Only `.ready` batches are consumed; publication is an atomic directory rename
after every item is encrypted and synchronized. A POSIX lock coordinates
writers and readers. Completed ciphertext entries are immutable by contract.
The app authenticates every frame, exact byte length, order, and end of file
before exposing a source to Rust; a pipe end cannot commit a malformed prefix.

Inbox files have Complete file protection and are excluded from backup.
The encrypted queue has at most eight batches, 64 items per batch, 4 GiB per
item, and 8 GiB in total, including envelope overhead. Text and URL payloads
are limited to 1 MiB. Abandoned and completed encrypted batches expire after
24 hours and are removed when the inbox is next used. Storage exhaustion,
provider failure, cancellation, or timeout does not publish a partial batch.

No document or text import creates plaintext scratch: authenticated bytes
flow through a pipe to the existing file importer. ImageIO and AVFoundation
require file URLs for media probes and derivatives, so only images, movies,
and audio may use `chur-incoming-media` protected, random-named,
backup-excluded scratch. This directory shares the existing 4-entry, 4 GiB
per-entry, 8 GiB total budget with import and export scratch. A file outside
that budget is imported as an opaque file through the pipe. The existing
importer owns every descriptor and media scratch lease until native custody
drains; cancellation and lock stop production and remove plaintext. Launch
removes abandoned media scratch. Unsupported media retains its original bytes
as a file. Queued ciphertext may remain while locked; it contains no plaintext.

The public prompt contains only a count. Names and destination choices appear
only after unlock. Closing the source after an import attempt or selecting
Discard removes the encrypted batch, including failed items. A failed item
must be shared again; successful items are not silently duplicated by a retry.
No payload, URL, or filename is written to public Notes, preferences, saved UI
state, diagnostics, or notifications. Flash deletion and managed text buffers
do not provide a physical-erasure guarantee. An App Group peer belongs to the
same trusted signing team; this design does not defend against a malicious
replacement extension signed with that authority.

## Native Live Photo verification

`LivePhotoNativeTests.xcodeproj` has a small UIKit host for Photos permissions. It
has no vault or shared-framework build dependency. Grant Photos on a dedicated
simulator to `dev.po4yka.chur.livephototesthost`, then run:

```sh
xcodebuild -project apps/iosApp/LivePhotoNativeTests.xcodeproj \
  -scheme LivePhotoNativeTests -destination 'platform=iOS Simulator,id=SIMULATOR_ID' \
  -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO test
```

The tests verify native pairing, motion, an audio track, the timed still marker,
all-resource capture, Photos restoration, exact resource hashes, cancellation
cleanup, and rejection of an unsupported sidecar role. They use only the
procedural media in `tests/media/live-photo-native`. They leave test-created
Photos assets in that disposable simulator. They do not access the Mac library.
Real camera, edited, HDR, and cloud-backed assets need separate acceptance.
