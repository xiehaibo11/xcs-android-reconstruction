#!/bin/sh
# Offline replay of captured Dart 3.5.2 VM-reference results against Java code.
set -eu
mint_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$mint_dir/../../.." && pwd)
. "$project_dir/scripts/java_env.sh"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-mint-tests.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -Xlint:-options -d "$classes_dir" "$project_dir/app/src/main/java/com/re/xcs/rebuild/core/DartIntegers.java" "$mint_dir/MintConversionTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.MintConversionTest "$mint_dir/reference.tsv"
