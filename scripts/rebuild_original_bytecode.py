#!/usr/bin/env python3
"""Reassemble decoded Android bytecode/resources and retain original native binaries.

This produces a debug-signed APK, NOT recovered Dart/Rust/Go source code.
No target code is executed, no device is modified, and no network is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk")))
    parser.add_argument("--build-tools", default="35.0.0")
    args = parser.parse_args()
    app = Path(__file__).resolve().parents[2]
    root = app / "reconstruction"
    work = root / "build/original-bytecode"
    logs = root / "build/logs"
    dist = root / "dist"
    evidence = app / "analysis/reconstruction_round/native"
    for directory in (work, logs, dist, evidence):
        directory.mkdir(parents=True, exist_ok=True)
    source = app / "apktool/decoded"
    if not source.is_dir():
        raise SystemExit(f"Missing decoded Smali/resources: {source}")
    decoded = work / "decoded"
    # Work only in the dedicated copy; preserve the original audit inputs.
    if decoded.exists():
        shutil.rmtree(decoded)
    shutil.copytree(source, decoded, ignore=shutil.ignore_patterns("build", "dist"))
    tool_dir = args.sdk / "build-tools" / args.build_tools
    java_path = shutil.which("java")
    apktool = shutil.which("apktool")
    if not apktool or not java_path:
        raise SystemExit("apktool and Java must be installed locally.")
    java_home = Path(java_path).resolve().parents[1]
    keytool = java_home / "bin/keytool"
    apksigner = tool_dir / "apksigner"
    zipalign = tool_dir / "zipalign"
    aapt = tool_dir / "aapt"
    for executable in (keytool, apksigner, zipalign, aapt):
        if not executable.is_file():
            raise SystemExit(f"Required local tool missing: {executable}")
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home)
    commands = []

    def run(name: str, command: list[str]) -> str:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        log = logs / f"original-bytecode-{name}.log"
        log.write_text(result.stdout)
        commands.append({"name": name, "argv": command, "returncode": result.returncode,
                         "log": str(log.relative_to(app))})
        if result.returncode:
            print(result.stdout, end="", flush=True)
        else:
            print(f"{name}: OK ({log})", flush=True)
        if result.returncode:
            (evidence / "build_commands.json").write_text(json.dumps(commands, ensure_ascii=False, indent=2) + "\n")
            raise SystemExit(f"{name} failed ({result.returncode}); see {log}")
        return result.stdout

    unsigned = work / "unsigned.apk"
    aligned = work / "aligned.apk"
    output = dist / "original-bytecode-rebuild.apk"
    run("apktool", [apktool, "b", str(decoded), "-p", str(app / "framework"), "-o", str(unsigned)])
    run("zipalign", [str(zipalign), "-f", "-p", "4", str(unsigned), str(aligned)])
    key = root / "local-signing/reconstruction-debug.p12"
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        run("keytool", [str(keytool), "-genkeypair", "-keystore", str(key), "-storetype", "PKCS12",
            "-storepass", "android", "-keypass", "android", "-alias", "reconstruction-debug",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650", "-dname",
            "CN=Local Reconstruction Debug,OU=Analysis,O=Local,L=Local,ST=Local,C=US"])
    run("sign", [str(apksigner), "sign", "--ks", str(key), "--ks-key-alias", "reconstruction-debug",
        "--ks-pass", "pass:android", "--key-pass", "pass:android", "--out", str(output), str(aligned)])
    signature = run("signature", [str(apksigner), "verify", "--verbose", "--print-certs", str(output)])
    alignment = run("alignment", [str(zipalign), "-c", "-v", "4", str(output)])
    badging = run("badging", [str(aapt), "dump", "badging", str(output)])
    original = app / "input/app_xcs.apk"
    preserved = []
    with zipfile.ZipFile(original) as original_zip, zipfile.ZipFile(output) as rebuilt_zip:
        entries = original_zip.namelist()
        names = [name for name in entries if name.startswith(("lib/", "assets/")) and not name.endswith("/")]
        for name in names:
            original_hash = sha256(original_zip.read(name))
            rebuilt_hash = sha256(rebuilt_zip.read(name))
            preserved.append({"path": name, "original_sha256": original_hash,
                              "rebuilt_sha256": rebuilt_hash, "identical": original_hash == rebuilt_hash})
        if not all(row["identical"] for row in preserved):
            raise SystemExit("An asset or native library changed unexpectedly.")
        # DEX is intentionally reassembled, so its bytes may differ.
        dex_changed = sha256(original_zip.read("classes.dex")) != sha256(rebuilt_zip.read("classes.dex"))
    result = {
        "status": "PASS", "artifact_kind": "smali_resources_rebuild_with_original_native_binaries",
        "original_source_recovered": False, "source_only_build": False,
        "target_executed": False, "device_installed": False, "business_server_contacted": False,
        "input_apk": str(original.relative_to(app)), "input_sha256": sha256(original.read_bytes()),
        "output_apk": str(output.relative_to(app)), "output_sha256": sha256(output.read_bytes()),
        "output_bytes": output.stat().st_size,
        "dex_reassembled_bytes_changed": dex_changed,
        "native_library_count": sum(row["path"].endswith(".so") for row in preserved),
        "preserved_asset_count": sum(row["path"].startswith("assets/") for row in preserved),
        "all_native_and_asset_bytes_identical": all(row["identical"] for row in preserved),
        "signature_verified": "Verifies" in signature, "zip_alignment_verified": True,
        "debug_signing_key": str(key.relative_to(app)),
        "signing_identity_matches_original": False,
        "limitations": [
            "Flutter AOT, Rust and Go remain original binary libraries; no original source is recovered by this build.",
            "Original signing key is unavailable; this local debug signature cannot update an original-signed installation.",
            "Runtime behavior has not been validated by this script; it does not install or launch the app.",
            "Resource compilation and DEX assembly can change bytes; app-level behavior equivalence requires separate tests."
        ],
        "preserved_files": preserved, "commands": commands,
    }
    (evidence / "build_commands.json").write_text(json.dumps(commands, ensure_ascii=False, indent=2) + "\n")
    report = evidence / "original_bytecode_rebuild_verification.json"
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"Built and verified: {output}\nEvidence: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
