#!/usr/bin/env bash
# Run the ordinary, minified release package on a dedicated API 35 virtual device.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
umask 077
work="$(mktemp -d "${TMPDIR:-/tmp}/chur-release-vault.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
export CHUR_RELEASE_KEYSTORE="$work/smoke.p12"
export CHUR_RELEASE_PASSWORD=public-compatibility-test
keytool -genkeypair -alias chur-release -keyalg RSA -keysize 2048 -validity 2 \
    -dname 'CN=Disposable vault compatibility test' -storetype PKCS12 \
    -storepass:env CHUR_RELEASE_PASSWORD -keystore "$CHUR_RELEASE_KEYSTORE"

./gradlew -PchurReleaseVaultTest=true -Pandroid.testoptions.manageddevices.emulator.gpu=swiftshader_indirect \
    :apps:androidApp:classicalVaultApi35ReleaseAndroidTest "$@"

python3 - <<'PY'
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

outputs = Path("apps/androidApp/build/release-vault-test/outputs")
with ZipFile(outputs / "apk/release/androidApp-release.apk") as app:
    for abi in ("arm64-v8a", "x86_64"):
        app.getinfo(f"lib/{abi}/libchur_jni.so")
    if "assets/vault.zip" in app.namelist():
        raise SystemExit("The fixture was packaged in the release app")
with ZipFile(outputs / "apk/androidTest/release/androidApp-release-androidTest.apk") as tests:
    tests.getinfo("assets/vault.zip")
    if any(name.endswith("/libchur_jni.so") for name in tests.namelist()):
        raise SystemExit("The test APK supplied a second JNI library")

report = outputs / "androidTest-results/managedDevice/release/classicalVaultApi35/TEST-classicalVaultApi35.xml"
cases = list(ElementTree.parse(report).iter("testcase"))
if (len(cases) != 1 or cases[0].get("classname") != "dev.po4yka.chur.android.ClassicalVaultReleaseTest"
        or cases[0].get("name") != "releaseReadsClassicalVaultAndOriginal"
        or any(cases[0].find(tag) is not None for tag in ("failure", "error", "skipped"))):
    raise SystemExit(f"Historical release vault test did not pass. See {report}")
print("Ordinary Android release decrypted the historical vault and original.")
PY
