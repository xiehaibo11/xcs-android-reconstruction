#!/usr/bin/env python3
"""Repeat the pure-JDK executable checks; never contacts an API or runs original code."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = _public_app_root()
PROJECT = ROOT / "reconstruction"
EVIDENCE = PROJECT / "evidence/logic"
CLASSES = EVIDENCE / "classes"
JAVA_HOME = _public_java_home()
CORE = PROJECT / "app/src/main/java/com/re/xcs/rebuild/core"
sources = [CORE / (name + ".java") for name in ["JsonCodec", "ApiContract", "Models", "SessionState", "SettingsLogic"]]
sources.append(EVIDENCE / "SettingsLogicTest.java")
CLASSES.mkdir(exist_ok=True, parents=True)
compile_args = [str(JAVA_HOME / "bin/javac"), "--release", "8", "-d", str(CLASSES), *map(str, sources)]
run_args = [str(JAVA_HOME / "bin/java"), "-cp", str(CLASSES), "com.re.xcs.rebuild.core.SettingsLogicTest"]
compile_result = subprocess.run(compile_args, capture_output=True, text=True)
run_result = subprocess.run(run_args, capture_output=True, text=True) if compile_result.returncode == 0 else None
logs = "COMPILE\n" + compile_result.stdout + compile_result.stderr + "\nTEST\n"
if run_result is not None:
    logs += run_result.stdout + run_result.stderr
(EVIDENCE / "settings_test.log").write_text(logs, encoding="utf-8")
match = re.search(r"PASS SettingsLogicTest: (\d+) assertions", run_result.stdout) if run_result is not None else None
ok = compile_result.returncode == 0 and run_result is not None and run_result.returncode == 0 and match is not None
record = {
    "status": "PASS" if ok else "FAIL",
    "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    "javac_release": "8",
    "compile_exit_code": compile_result.returncode,
    "test_exit_code": run_result.returncode if run_result else None,
    "assertions": int(match.group(1)) if match else 0,
    "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
    "scope": "Executable bounded settings behavior only; static fixture assertions are not dynamic equivalence against the original APK.",
    "network_used": False,
    "original_binary_executed": False,
    "original_source_recovered": False,
    "whole_methods_claimed_complete": False,
    "full_app_behavior_completed": False,
    "unresolved": [
        "WiFi original sort output for multiple items: comparator returns 0/1 and cannot be supplied to Java sort; parser explicitly returns input order with orderingRecovered=false",
        "Malformed WiFi record recovery branches and non-String dynamic response conversion are not ported; these inputs fail explicitly",
        "Dart int.parse formats outside signed decimal and values outside Java int range are not ported; these inputs fail explicitly",
        "Some Dart dynamic toString inputs other than null, String, bool and integer are not ported",
        "Full Flutter widget layout, lifecycle setState behavior and original navigation implementation are not recovered by this core test"
    ]
}
(EVIDENCE / "settings_test_result.json").write_text(json.dumps(record, indent=2, ensure_ascii=False)+"\n",encoding="utf-8")
print(json.dumps({"status":record["status"],"assertions":record["assertions"],"evidence":str(EVIDENCE / "settings_test_result.json")},ensure_ascii=False))
sys.exit(0 if ok else 1)
