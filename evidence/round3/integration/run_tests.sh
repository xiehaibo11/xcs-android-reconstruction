#!/bin/sh
set -eu
suite_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$suite_dir/../../.." && pwd)
. "$project_dir/scripts/java_env.sh"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-round3-integration.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -d "$classes_dir" "$project_dir"/app/src/main/java/com/re/xcs/rebuild/core/*.java "$suite_dir/Round3IntegrationTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.Round3IntegrationTest
