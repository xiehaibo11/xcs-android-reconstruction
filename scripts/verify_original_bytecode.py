#!/usr/bin/env python3
"""Verify reassembled APK against original Smali and resource-ID inventory.

Does not install, execute, or contact any server. This verifies preserved code
representation, not recovered source or runtime equivalence.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def normalize_defaults(text: str) -> str:
    # DEX permits omitting trailing static values equal to the type default.
    # Only normalize the exact two changes observed after smali assembly.
    text = re.sub(r"^(\.field .*\bstatic\b[^\n]*:Z) = false$", r"\1", text, flags=re.M)
    return re.sub(r"^(\.field .*\bstatic\b[^\n]*:(?:L[^;\n]+;|\[[^\n ]+)) = null$", r"\1", text, flags=re.M)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=Path.home() / "Library/Android/sdk")
    parser.add_argument("--build-tools", default="35.0.0")
    args = parser.parse_args()
    app = Path(__file__).resolve().parents[2]
    work = app / "reconstruction/build/original-bytecode"
    out = app / "analysis/reconstruction_round/native"
    out.mkdir(parents=True, exist_ok=True)
    apk = app / "reconstruction/dist/original-bytecode-rebuild.apk"
    decoded = work / "redecoded"
    command = [shutil.which("apktool"), "d", "-f", "-r", str(apk), "-p", str(app / "framework"), "-o", str(decoded)]
    run = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "roundtrip_decode.log").write_text(run.stdout)
    run.check_returncode()
    first = {str(f.relative_to(app / "apktool/decoded/smali")): f.read_text()
             for f in (app / "apktool/decoded/smali").rglob("*.smali")}
    second = {str(f.relative_to(decoded / "smali")): f.read_text() for f in (decoded / "smali").rglob("*.smali")}
    changed = sorted(n for n in first.keys() & second.keys() if first[n] != second[n])
    unexplained = sorted(n for n in first.keys() & second.keys()
                         if normalize_defaults(first[n]) != normalize_defaults(second[n]))
    diff = []
    for name in changed:
        diff.extend(difflib.unified_diff(first[name].splitlines(), second[name].splitlines(),
                                        fromfile="original/" + name, tofile="rebuilt/" + name, lineterm=""))
    (out / "roundtrip_smali_changes.diff").write_text("\n".join(diff) + "\n")
    resources = {}
    aapt = args.sdk / "build-tools" / args.build_tools / "aapt"
    for name, path in [("original", app / "input/app_xcs.apk"), ("rebuilt", apk)]:
        result = subprocess.run([str(aapt), "dump", "resources", str(path)], check=True, text=True, stdout=subprocess.PIPE)
        (out / f"{name}_resources.txt").write_text(result.stdout)
        resources[name] = dict(re.findall(r"spec resource (0x[0-9a-f]+) (\S+): flags=", result.stdout))
    missing, extra = sorted(first.keys() - second.keys()), sorted(second.keys() - first.keys())
    equal_ids = resources["original"] == resources["rebuilt"]
    valid = not missing and not extra and not unexplained and equal_ids
    report = {
        "status": "PASS" if valid else "FAIL",
        "scope": "DEX Smali roundtrip and Android resource ID/name preservation; not source recovery or runtime equivalence",
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "original_classes": len(first), "rebuilt_classes": len(second),
        "original_method_count": sum(len(re.findall(r"^\.method ", t, re.M)) for t in first.values()),
        "rebuilt_method_count": sum(len(re.findall(r"^\.method ", t, re.M)) for t in second.values()),
        "missing_classes": missing, "extra_classes": extra,
        "changed_smali_files": changed, "all_smali_text_identical": first == second,
        "normalization": "Only static boolean = false and static reference = null defaults omitted by smali assembler",
        "unexplained_smali_changes": unexplained,
        "all_normalized_smali_identical": not missing and not extra and not unexplained,
        "resource_id_count": len(resources["original"]), "rebuilt_resource_id_count": len(resources["rebuilt"]),
        "all_resource_ids_and_names_identical": equal_ids,
        "resource_table_limitation": "Apktool publicizes resources and rewrites file paths/string-pool indexes; bytes differ.",
        "target_executed": False, "original_source_recovered": False,
    }
    path = out / "bytecode_resource_roundtrip.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
