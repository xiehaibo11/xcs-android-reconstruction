#!/bin/sh
# Historical analysis driver. Requires external original inputs and Ghidra.
set -eu
: "${XCS_REVERSE_APP_ROOT:?Set XCS_REVERSE_APP_ROOT to your external APP directory}"
native_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ghidra_cmd=${GHIDRA_ANALYZE_HEADLESS:-analyzeHeadless}
python3 "$native_dir/extract_native_gaps.py"
python3 -u -X faulthandler "$native_dir/emulate_native_gaps.py"
"$ghidra_cmd" "$XCS_REVERSE_APP_ROOT/ghidra" xcs_native \
  -process librsa_bridge.so -readOnly -noanalysis \
  -scriptPath "$native_dir" \
  -postScript DiagnoseBytealg.java "$native_dir/ghidra_diagnosis" \
  > "$native_dir/ghidra_diagnosis.log" 2>&1
python3 "$native_dir/build_report.py"
python3 "$native_dir/verify_evidence.py"
python3 "$native_dir/build_report.py"
