#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
[[ $EUID -ne 0 ]] || { echo 'Use the exp1a ordinary user to run the web service.'; exit 1; }
build_dir=${WIRELENS_BUILD_DIR:-"$project_root/build"}
exec "$build_dir/wirelens" --web-dir "$project_root/web" "$@"
