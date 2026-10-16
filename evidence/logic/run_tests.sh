#!/bin/sh
set -eu
logic_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$logic_dir/../.." && pwd)
. "$project_dir/scripts/java_env.sh"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-settings-tests.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -d "$classes_dir" "$project_dir"/app/src/main/java/com/re/xcs/rebuild/core/*.java "$logic_dir/SettingsLogicTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.SettingsLogicTest
