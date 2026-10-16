#!/bin/sh
# Portable source-package test. Requires a JDK; C is also tested if cc exists.
# Requires the original ARM64 fixture file retained outside this source-only folder.
# No network or credentials required.
set -eu
simd_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
recon_dir=$(CDPATH= cd -- "$simd_dir/../../../.." && pwd)
java_source="$recon_dir/app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java"
fixture_file="$recon_dir/evidence/round3/simd/original_arm64_cases.bin.gz"
if [ -n "${XCS_REVERSE_APP_ROOT:-}" ] && [ ! -f "$fixture_file" ]; then
    fixture_file="$XCS_REVERSE_APP_ROOT/reconstruction/evidence/round3/simd/original_arm64_cases.bin.gz"
fi
if [ ! -f "$fixture_file" ]; then
    printf '%s\n' 'ARM64 fixture absent. Supply it through XCS_REVERSE_APP_ROOT; see reverse/README.md.' >&2
    exit 1
fi
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    javac_cmd="$JAVA_HOME/bin/javac";java_cmd="$JAVA_HOME/bin/java"
elif [ -x /opt/homebrew/opt/openjdk@21/bin/javac ]; then
    javac_cmd=/opt/homebrew/opt/openjdk@21/bin/javac;java_cmd=/opt/homebrew/opt/openjdk@21/bin/java
else
    javac_cmd=javac;java_cmd=java
fi
simd_tmp=$(mktemp -d "${TMPDIR:-/tmp}/xcs-simd-tests.XXXXXX")
trap 'rm -rf "$simd_tmp"' EXIT HUP INT TERM
"$javac_cmd" -encoding UTF-8 -d "$simd_tmp" "$java_source" "$simd_dir/GoBytePrimitivesProbe.java" "$simd_dir/PortablePrimitiveTest.java"
"$java_cmd" -cp "$simd_tmp" PortablePrimitiveTest "$fixture_file" "$simd_tmp/original_cases.bin"
if command -v "${CC:-cc}" >/dev/null 2>&1; then
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror "$simd_dir/go_byte_primitives.c" "$simd_dir/portable_native_test.c" -o "$simd_tmp/native_test"
    "$simd_tmp/native_test" "$simd_tmp/original_cases.bin"
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -DXCS_FORCE_SCALAR "$simd_dir/go_byte_primitives.c" "$simd_dir/portable_native_test.c" -o "$simd_tmp/scalar_test"
    "$simd_tmp/scalar_test" "$simd_tmp/original_cases.bin"
else
    printf '%s\n' 'C compiler unavailable: C fixture test SKIPPED; Java test completed.'
fi
