#!/bin/sh
set -eu
callback_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$callback_dir/../../.." && pwd)
. "$project_dir/scripts/java_env.sh"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-callback-tests.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -Xlint:-options -d "$classes_dir" "$project_dir"/app/src/main/java/com/re/xcs/rebuild/core/*.java "$callback_dir/CallbackStateTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.CallbackStateTest
