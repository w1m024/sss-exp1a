#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$project_root"
build_dir="${WIRELENS_BUILD_DIR:-$project_root/build}"

case "${1:-help}" in
    build)
        shift
        cmake -S . -B "$build_dir" "$@"
        cmake --build "$build_dir" -j2
        ;;
    install)
        exec sudo bash scripts/install-capture-helper.sh "$build_dir/wirelens-capture"
        ;;
    web)
        shift
        WIRELENS_BUILD_DIR="$build_dir" exec bash scripts/run.sh "$@"
        ;;
    help|-h|--help)
        cat <<'HELP'
Usage: bash scripts/quickstart.sh <command> [options]

  build [CMake options]   Configure and build the project
  install                Install the capture helper with sudo
  web [server options]   Start the web service as an ordinary user
HELP
        ;;
    *)
        printf 'Unknown command: %s\n' "$1" >&2
        exit 2
        ;;
esac
