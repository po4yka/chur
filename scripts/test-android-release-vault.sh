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
    :apps:androidApp:classicalVaultApi35ReleaseAndroidTest

python3 - <<'PY'
from pathlib import Path
from xml.etree import ElementTree
results = Path("apps/androidApp/build/release-vault-test/outputs/androidTest-results/managedDevice")
for report in results.rglob("TEST-*.xml"):
    for case in ElementTree.parse(report).iter("testcase"):
        if (case.get("classname") == "dev.po4yka.chur.android.ClassicalVaultReleaseTest"
                and case.get("name") == "releaseReadsClassicalVaultAndOriginal"
                and all(case.find(tag) is None for tag in ("failure", "error", "skipped"))):
            print("Ordinary Android release decrypted the historical vault and original.")
            break
    else:
        continue
    break
else:
    raise SystemExit("Missing successful release vault instrumentation result")
PY
