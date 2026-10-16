#!/bin/sh
# Portable source-package test. Requires a JDK; C is also tested if cc exists.
# No SDK, Gradle, original APK, Python, Unicorn, network or credentials required.
set -eu
simd_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
recon_dir=$(CDPATH= cd -- "$simd_dir/../../.." && pwd)
java_source="$recon_dir/app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java"
if [ ! -f "$java_source" ]; then
    # Authoritative analysis location before packaging into reconstruction/evidence.
    java_source="$recon_dir/reconstruction/app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java"
fi
. "$recon_dir/scripts/java_env.sh"
simd_tmp=$(mktemp -d "${TMPDIR:-/tmp}/xcs-simd-tests.XXXXXX")
trap 'rm -rf "$simd_tmp"' EXIT HUP INT TERM
"$XCS_JAVAC" -encoding UTF-8 -d "$simd_tmp" "$java_source" "$simd_dir/GoBytePrimitivesProbe.java" "$simd_dir/PortablePrimitiveTest.java"
"$XCS_JAVA" -cp "$simd_tmp" PortablePrimitiveTest "$simd_dir/original_arm64_cases.bin.gz" "$simd_tmp/original_cases.bin"
if command -v "${CC:-cc}" >/dev/null 2>&1; then
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror "$simd_dir/go_byte_primitives.c" "$simd_dir/portable_native_test.c" -o "$simd_tmp/native_test"
    "$simd_tmp/native_test" "$simd_tmp/original_cases.bin"
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -DXCS_FORCE_SCALAR "$simd_dir/go_byte_primitives.c" "$simd_dir/portable_native_test.c" -o "$simd_tmp/scalar_test"
    "$simd_tmp/scalar_test" "$simd_tmp/original_cases.bin"
else
    printf '%s\n' 'C compiler unavailable: C fixture test SKIPPED; Java test completed.'
fi
