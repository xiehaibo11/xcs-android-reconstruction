#!/usr/bin/env python3
"""Check artifact consistency and preserved APK hashes; no APK execution."""

from _paths import app_root, workspace_root
import csv
import hashlib
import json
import re
from pathlib import Path

APP = app_root()
ANALYSIS = APP / "analysis"
EXPECTED_APK = "8fd060966759990ab5ef90639e3376a2b6aea209f3f545d768a2fdc668dfeaa9"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


json_paths = sorted(p for folder in ANALYSIS.glob("deep_*") if folder.is_dir()
                    for p in folder.rglob("*.json"))
documents = {str(p): read(p) for p in json_paths}
hashes = {
    "original": digest(APP.parent / "app_xcs(新).apk.1.1"),
    "working_copy": digest(APP / "input/app_xcs.apk"),
}
assert all(value == EXPECTED_APK for value in hashes.values())

checked_proofs = 0
checked_source_hashes = 0
def validate_proofs(value):
    global checked_proofs, checked_source_hashes
    if isinstance(value, dict):
        if "file" in value and "sha256" in value:
            source = Path(value["file"])
            assert source.is_absolute() and source.is_file(), str(source)
            assert digest(source) == value["sha256"], str(source)
            checked_source_hashes += 1
            if value.get("line") is not None:
                assert 1 <= value["line"] <= len(source.read_text().splitlines()), str(source)
                checked_proofs += 1
        for child in value.values():
            validate_proofs(child)
    elif isinstance(value, list):
        for child in value:
            validate_proofs(child)


for doc in documents.values():
    validate_proofs(doc)

rust = read(ANALYSIS / "deep_rust/extraction_summary.json")
addresses = set()
for rel in ("decompile_status.tsv", "stage2/decompile_status.tsv", "lifecycle/decompile_status.tsv"):
    path = ANALYSIS / "deep_rust" / rel
    with path.open() as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    for row in rows:
        assert row["completed"] == "true"
        assert (path.parent / "functions" / (row["address"] + ".c")).is_file()
        addresses.add(row["address"])
assert len(addresses) == rust["unique_decompiled_functions"]

rsa = ANALYSIS / "deep_rsa"
operations, models = read(rsa / "operations.json"), read(rsa / "request_models.json")
checks = read(rsa / "dispatch_literal_checks.json")
assert len(operations) == len(checks) == 34
assert all(check["matches_handler"] for check in checks.values())
assert len(models) == 28
for operation in operations:
    assert operation["operation"] in checks
    for model in operation["request_models"]:
        assert model in models
fbs_tables = re.findall(r"^table (\w+) \{", (rsa / "request_models_reconstructed.fbs").read_text(), re.M)
assert set(fbs_tables) == set(models)

flutter = read(ANALYSIS / "deep_flutter/extraction_summary.json")
android = read(ANALYSIS / "deep_android/verification.json")
assert flutter["binary_bytes_verified_string_count"] == flutter["input_string_count"] == 23484
assert android["status"] == "passed"

uri = read(ANALYSIS / "deep_rust/uri_format_evidence.json")
rust_bytes = Path(uri["source_library"]).read_bytes()
assert hashlib.sha256(rust_bytes).hexdigest() == uri["source_sha256"]
for descriptor in uri["uri_format_descriptors"]:
    assert descriptor["template"] == "ws://{运行时地址}:18889"
    for piece in descriptor["pieces"]:
        start = int(piece["string_file_offset"], 16)
        assert rust_bytes[start:start + piece["byte_length"]].hex() == piece["string_bytes_hex"]

pem_paths = sorted({p for folder in (APP / "unpacked", APP / "apktool", APP / "jadx")
                    for p in folder.rglob("*.pem")})
assert all((p.stat().st_mode & 0o777) == 0o600 for p in pem_paths)

badging = (ANALYSIS / "aapt_badging.txt").read_text()
version = re.search(r"versionCode='(\d+)' versionName='([^']+)'", badging)
assert version and version.groups() == ("39", "2.1.6")
metadata = read(ANALYSIS / "apk_metadata.json")
metadata.update(version_name=version.group(2), version_code=int(version.group(1)),
                version_source=str(ANALYSIS / "aapt_badging.txt"),
                original_hash_rechecked=True, working_copy_hash_rechecked=True)
(ANALYSIS / "apk_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")

summary = {
    "status": "passed", "scope": "Static extraction artifact consistency; no runtime or backend validation",
    "apk_hashes": hashes, "parsed_deep_json_files": len(documents),
    "source_line_hash_evidence_checked": checked_proofs,
    "source_hash_evidence_checked": checked_source_hashes,
    "rust_unique_decompiled_functions": len(addresses),
    "go_pclntab_functions": read(rsa / "go_metadata.json")["function_count"],
    "rsa_operations_cross_checked": len(checks), "rsa_request_tables": len(models),
    "flutter_strings_byte_verified": flutter["binary_bytes_verified_string_count"],
    "android_target_channels": android["counts"]["target_channels"],
    "pem_files_permission_600": len(pem_paths),
    "version_name": version.group(2), "version_code": int(version.group(1)),
}
(ANALYSIS / "deep_verification.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
status = read(ANALYSIS / "analysis_status.json")
status.update(original_hash_valid=True, working_copy_hash_valid=True,
              deep_extraction={"verification_file": str(ANALYSIS / "deep_verification.json"),
                               "rust": rust, "flutter": flutter,
                               "android": android["counts"],
                               "rsa": read(rsa / "summary.json")})
(ANALYSIS / "analysis_status.json").write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(summary, ensure_ascii=False))
