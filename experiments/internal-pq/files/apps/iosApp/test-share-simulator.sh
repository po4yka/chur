#!/usr/bin/env bash
# Send a file from a separate app through the embedded extension, then open it in the vault.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
build="$root/build/xcode"
products="$build/Build/Products/Debug-iphonesimulator"
app="$products/Chur.app"
extension="$app/PlugIns/ChurShare.appex"
identifier=dev.po4yka.chur.pqinternal
group="group.$identifier.incoming"
work=$(mktemp -d)
result="$(mktemp -d "$build/share-test.XXXXXX")/result.xcresult"
device=$(xcrun simctl create 'Chur PQ share' com.apple.CoreSimulator.SimDeviceType.iPhone-17)
trap 'xcrun simctl delete "$device"; rm -rf -- "$work"' EXIT

for bundle in "$app" "$extension"; do
    expected=$identifier
    if [[ "$bundle" == "$extension" ]]; then expected="$identifier.share"; fi
    test "$(plutil -extract CFBundleIdentifier raw "$bundle/Info.plist")" = "$expected"
    codesign --verify --strict "$bundle"
    executable=$(plutil -extract CFBundleExecutable raw "$bundle/Info.plist")
    # CoreSimulator reads entitlements from the signed executable's Mach-O section.
    xcrun segedit "$bundle/$executable" -extract __TEXT __entitlements "$work/$executable.plist"
    python3 - "$work/$executable.plist" "$group" <<'PY'
import plistlib, sys
with open(sys.argv[1], "rb") as source:
    groups = plistlib.load(source).get("com.apple.security.application-groups")
if groups != [sys.argv[2]]:
    sys.exit(f"Unexpected simulator App Groups in {sys.argv[1]}: {groups}")
PY
done
xcrun simctl bootstatus "$device" -b
xcodebuild -project apps/iosApp/LivePhotoNativeTests.xcodeproj -scheme LivePhotoNativeTests \
    -destination "platform=iOS Simulator,id=$device" -derivedDataPath "$work/sender" \
    CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=- build-for-testing
xcrun simctl install "$device" "$work/sender/Build/Products/Debug-iphonesimulator/LivePhotoTestHost.app"
xcrun simctl install "$device" "$app"
container=$(xcrun simctl get_app_container "$device" "$identifier" data)
(cd rust && CHUR_PASSWORD='Chur simulator share test' cargo run --locked -p chur-cli -- \
    vault --root "$container/Documents/chur" create)
xcrun simctl launch "$device" "$identifier"
shared=$(xcrun simctl get_app_container "$device" "$identifier" "$group")
for ((i=0; i<60; i++)); do
    if [[ -s "$shared/ingress-public-key-v2" ]]; then break; fi
    sleep 1
done
test -s "$shared/ingress-public-key-v2"
xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur -configuration Debug \
    -destination "platform=iOS Simulator,id=$device" -derivedDataPath "$build" \
    -parallel-testing-enabled NO -resultBundlePath "$result" \
    -only-testing:ChurUITests/IncomingShareSystemTests/testImportsFileFromSystemShareSheet \
    CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=- test-without-building
xcrun xcresulttool get test-results summary --path "$result" | python3 -c '
import json, sys
result = json.load(sys.stdin)
if result["passedTests"] != 1 or result["totalTestCount"] != 1:
    sys.exit(f"Expected one passing system-share test: {result}")
'
