#!/usr/bin/env python3
"""Offline replay using already downloaded official SDK and existing blutter library."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json,subprocess
ROOT=_public_app_root()
HERE=Path(__file__).resolve().parent
OUT=ROOT/'reconstruction/evidence/round3/numeric_json'
SDK=ROOT/'analysis/reconstruction_round3/datetime/reference/dart-sdk'
subprocess.run(['python3',str(HERE/'generate_cases.py')],check=True)
subprocess.run([str(SDK/'bin/dart'),'--disable-analytics',str(HERE/'reference.dart'),str(HERE/'cases.json'),str(OUT/'reference.tsv')],check=True)
for cmd in json.loads((HERE/'build_commands.json').read_text()):subprocess.run(cmd,check=True)
subprocess.run([str(HERE/'snapshot_numeric_targets'),str(ROOT/'unpacked/lib/arm64-v8a/libapp.so'),str(OUT/'snapshot_metadata.tsv')],check=True)
subprocess.run(['python3',str(HERE/'build_contracts.py')],check=True)
