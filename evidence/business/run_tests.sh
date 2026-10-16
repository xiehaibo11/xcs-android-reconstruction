#!/bin/sh
set -eu
business_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$business_dir/../.." && pwd)
. "$project_dir/scripts/java_env.sh"
python3 "$project_dir/scripts/prepare_dev_assets.py"
classes_dir=$(mktemp -d "${TMPDIR:-/tmp}/xcs-business-tests.XXXXXX")
trap 'rm -rf "$classes_dir"' EXIT HUP INT TERM
"$XCS_JAVAC" --release 8 -Xlint:-options -d "$classes_dir" "$project_dir"/app/src/main/java/com/re/xcs/rebuild/core/*.java "$business_dir/BusinessCoreTest.java"
"$XCS_JAVA" -cp "$classes_dir" com.re.xcs.rebuild.core.BusinessCoreTest "$project_dir/app/src/main/assets/key/private_key.pem"
