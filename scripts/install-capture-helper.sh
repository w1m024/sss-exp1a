#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run this installer as root; the web service must run as an ordinary user.'; exit 1; }
project_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-"$project_root/build/wirelens-capture"}
[[ -f $binary ]] || { echo 'Build wirelens-capture first'; exit 1; }
install -d -o root -g root -m 0755 /opt/wirelens/libexec
install -o root -g root -m 0755 -- "$binary" /opt/wirelens/libexec/wirelens-capture
setcap cap_net_raw=ep /opt/wirelens/libexec/wirelens-capture
getcap /opt/wirelens/libexec/wirelens-capture
