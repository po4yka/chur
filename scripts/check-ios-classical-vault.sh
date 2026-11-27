#!/usr/bin/env bash
# Read a pre-existing vault through the ordinary Release UI on a disposable simulator.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
fixture=test-vectors/compatibility/classical-vault/vault.zip
test -f "$fixture"
build_dir=${CHUR_IOS_COMPAT_BUILD_DIR:-"$repo/apps/iosApp/.build/release-compatibility"}
args=(-project apps/iosApp/Chur.xcodeproj -scheme ChurCompatibility -configuration Release
      -derivedDataPath "$build_dir" -parallel-testing-enabled NO
      CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=-)
xcodebuild "${args[@]}" -destination 'generic/platform=iOS Simulator' build-for-testing

device=$(xcrun simctl create 'Chur Release compatibility' com.apple.CoreSimulator.SimDeviceType.iPhone-17)
trap 'xcrun simctl delete "$device"' EXIT
xcrun simctl bootstatus "$device" -b
app="$build_dir/Build/Products/Release-iphonesimulator/Chur.app"
xcrun simctl install "$device" "$app"
container=$(xcrun simctl get_app_container "$device" dev.po4yka.chur data)
mkdir "$container/Documents/chur"
unzip -q "$fixture" -d "$container/Documents/chur"
xcodebuild "${args[@]}" -destination "platform=iOS Simulator,id=$device" test-without-building
