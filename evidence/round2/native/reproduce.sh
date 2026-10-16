#!/bin/sh
# Run from the workspace root. No network or target application execution.
set -eu
python3 APP/analysis/reconstruction_round2/native/extract_native_gaps.py
python3 -u -X faulthandler APP/analysis/reconstruction_round2/native/emulate_native_gaps.py
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
JAVA_TOOL_OPTIONS=-Duser.home=/private/tmp/xcs_native_reconstruction_home \
/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless APP/ghidra xcs_native \
  -process librsa_bridge.so -readOnly -noanalysis \
  -scriptPath APP/analysis/reconstruction_round2/native \
  -postScript DiagnoseBytealg.java APP/analysis/reconstruction_round2/native/ghidra_diagnosis \
  > APP/analysis/reconstruction_round2/native/ghidra_diagnosis.log 2>&1
python3 APP/analysis/reconstruction_round2/native/build_report.py
python3 APP/analysis/reconstruction_round2/native/verify_evidence.py
python3 APP/analysis/reconstruction_round2/native/build_report.py
