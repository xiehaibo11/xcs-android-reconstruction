#!/bin/sh
# Offline Java-only model checks; does not require the APK, Android SDK, C++ or Dart source.
set -eu
models_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$models_dir/../../.." && pwd)
. "$project_dir/scripts/java_env.sh"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-model-tests.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
core_dir="$project_dir/app/src/main/java/com/re/xcs/rebuild/core"
"$XCS_JAVAC" --release 8 -Xlint:-options -d "$classes_dir" "$core_dir"/*.java "$models_dir/ModelConversionTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.ModelConversionTest
