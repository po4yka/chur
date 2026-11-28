#!/bin/sh
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$app_dir/build-inbox.sh" host >/dev/null
exec swift test --package-path "$app_dir" "$@"
