#!/usr/bin/env python3
"""Check the signed Android release archives and their native symbol closure."""

import hashlib
import os
import platform
import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FILAMENT_NOTICE = "assets/licenses/filament-THIRD-PARTY-NOTICES"
ABIS = {"arm64-v8a": "aarch64-linux-android", "x86_64": "x86_64-linux-android"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release check failed: {message}")


def run(*command: str | Path) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout + result.stderr


def build_id(readelf: Path, binary: Path) -> str:
    match = re.search(r"Build ID: ([0-9a-f]+)", run(readelf, "-n", binary))
    require(match is not None, f"missing GNU build ID: {binary}")
    return match.group(1)


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_filament_notice(apk_zip: zipfile.ZipFile, aab_zip: zipfile.ZipFile) -> str:
    source = ROOT / "shared/app/src/androidMain" / FILAMENT_NOTICE
    require(source.is_file(), f"missing checked-in Filament notice: {source}")
    expected = source.read_bytes()
    for label, archive, entry in (("APK", apk_zip, FILAMENT_NOTICE),
                                  ("AAB", aab_zip, f"base/{FILAMENT_NOTICE}")):
        require(archive.namelist().count(entry) == 1, f"{label} must contain exactly one {entry}")
        require(archive.read(entry) == expected, f"{label} {entry} differs from the checked-in notice")
    return hashlib.sha256(expected).hexdigest()


def main() -> None:
    require(len(sys.argv) == 5, "usage: check-android-release.py APK AAB SYMBOLS CERT_SHA256")
    apk, aab, symbols = map(Path, sys.argv[1:4])
    expected_cert = sys.argv[4].lower().replace(":", "")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_cert) is not None, "invalid certificate digest")
    for path in (apk, aab, symbols):
        require(path.is_file(), f"missing artifact: {path}")

    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    require(bool(sdk_root), "set ANDROID_HOME to the Android SDK")
    sdk = Path(sdk_root)
    require(sdk.is_dir(), "ANDROID_HOME is not a directory")
    versions = [path for path in (sdk / "build-tools").iterdir()
                if re.fullmatch(r"\d+\.\d+\.\d+", path.name)]
    require(bool(versions), "no stable Android build-tools are installed")
    build_tools = max(
        versions,
        key=lambda path: tuple(map(int, path.name.split("."))),
    )
    ndk_version = tomllib.loads((ROOT / "gradle/libs.versions.toml").read_text())["versions"]["ndk"]
    host = "darwin-x86_64" if platform.system() == "Darwin" else "linux-x86_64"
    readelf = sdk / "ndk" / ndk_version / "toolchains/llvm/prebuilt" / host / "bin/llvm-readelf"
    require(readelf.is_file(), f"missing pinned NDK readelf: {readelf}")

    run(build_tools / "zipalign", "-c", "-P", "16", "-v", "4", apk)
    apk_signature = run(build_tools / "apksigner", "verify", "--verbose", "--print-certs", apk)
    apk_certs = re.findall(r"certificate SHA-256 digest: ([0-9a-f]{64})", apk_signature)
    require(apk_certs == [expected_cert], "APK signer differs from the release certificate")
    require("jar verified." in run("jarsigner", "-verify", aab), "AAB JAR signature is invalid")
    aab_cert = re.search(r"SHA256: ([0-9A-F:]{95})", run("keytool", "-printcert", "-jarfile", aab))
    require(aab_cert is not None and aab_cert.group(1).lower().replace(":", "") == expected_cert,
            "AAB signer differs from the release certificate")

    with zipfile.ZipFile(apk) as apk_zip, zipfile.ZipFile(aab) as aab_zip, zipfile.ZipFile(symbols) as symbol_zip:
        notice_sha256 = verify_filament_notice(apk_zip, aab_zip)
        apk_libs = {name.removeprefix("lib/") for name in apk_zip.namelist()
                    if name.startswith("lib/") and name.endswith(".so")}
        aab_libs = {name.removeprefix("base/lib/") for name in aab_zip.namelist()
                    if name.startswith("base/lib/") and name.endswith(".so")}
        require(apk_libs == aab_libs, "APK and AAB native libraries differ")
        require({name.split("/")[0] for name in apk_libs} == ABIS.keys(), "unexpected or missing ABI")
        require({f"{abi}/libchur_jni.so" for abi in ABIS} <= apk_libs, "missing JNI adapter")
        for abi in ABIS:
            symbol_name = f"{abi}/libchur_jni.so.dbg"
            require(symbol_name in symbol_zip.namelist(), f"missing native symbols: {symbol_name}")
            require(f"BUNDLE-METADATA/com.android.tools.build.debugsymbols/{symbol_name}" in aab_zip.namelist(),
                    f"missing AAB native symbols: {symbol_name}")

        with tempfile.TemporaryDirectory(prefix="chur-release-check-") as temporary:
            temporary_path = Path(temporary)
            for name in sorted(apk_libs):
                binary = temporary_path / name.replace("/", "-")
                packaged = apk_zip.read(f"lib/{name}")
                require(packaged == aab_zip.read(f"base/lib/{name}"), f"APK and AAB differ at {name}")
                binary.write_bytes(packaged)
                machine = run(readelf, "-h", binary)
                expected_machine = "AArch64" if name.startswith("arm64-v8a/") else "Advanced Micro Devices X86-64"
                require(re.search(r"Machine:\s+" + re.escape(expected_machine), machine) is not None,
                        f"{name} contains the wrong ELF architecture")
                segments = [line.split()[-1] for line in run(readelf, "-lW", binary).splitlines()
                            if line.split()[:1] == ["LOAD"]]
                require(segments and all(int(alignment, 16) >= 0x4000 and
                                         int(alignment, 16) & (int(alignment, 16) - 1) == 0
                                         for alignment in segments),
                        f"{name} has a LOAD segment below 16 KiB alignment")
                require(".debug_" not in run(readelf, "-SW", binary), f"debug sections ship in {name}")
                if name.endswith("/libchur_jni.so"):
                    abi = name.split("/")[0]
                    source = ROOT / "rust/target" / ABIS[abi] / "release/libchur_jni.so"
                    require(source.is_file(), f"missing unstripped input: {source}")
                    sidecar = temporary_path / f"{abi}-symbols.so"
                    sidecar.write_bytes(symbol_zip.read(f"{abi}/libchur_jni.so.dbg"))
                    require(".debug_line" in run(readelf, "-SW", sidecar), f"missing line tables for {abi}")
                    require(build_id(readelf, binary) == build_id(readelf, source) == build_id(readelf, sidecar),
                            f"shipped binary and symbols have different build IDs for {abi}")

    mapping = ROOT / "apps/androidApp/build/outputs/mapping/release/mapping.txt"
    require(mapping.is_file() and
            "dev.po4yka.chur.ffi.ChurJni -> dev.po4yka.chur.ffi.ChurJni:" in mapping.read_text(),
            "R8 mapping is absent or renamed the JNI class")
    print(f"release checks passed: {len(apk_libs)} native libraries, two ABIs, 16 KiB alignment, R8, matching symbols and signer")
    print(f"verified Filament notice in APK and AAB: sha256 {notice_sha256}")
    for path in (apk, aab, symbols, mapping):
        print(f"sha256 {digest(path)}  {path}")


if __name__ == "__main__":
    main()
