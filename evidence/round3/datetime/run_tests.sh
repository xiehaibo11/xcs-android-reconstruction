#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../.." && pwd)
. "$ROOT/scripts/java_env.sh"
OUT=$(mktemp -d "${TMPDIR:-/tmp}/xcs-datetime-tests.XXXXXX")
trap 'rm -rf "$OUT"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -Xlint:-options -d "$OUT" "$ROOT/app/src/main/java/com/re/xcs/rebuild/core/DartDateTime.java" "$HERE/DateTimeTest.java"
"$XCS_JAVA" -cp "$OUT" com.re.xcs.rebuild.core.DateTimeTest fixtures "$HERE/reference-fixtures.zip"
