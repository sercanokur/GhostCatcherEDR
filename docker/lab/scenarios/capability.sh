#!/bin/sh
# FILE_CAPABILITY_DELTA
# Doğrudan: sudo sh ./capability.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./capability.sh   veya   sudo sh ./capability.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
cp /bin/ls /usr/bin/gc-lab-caps
setcap cap_net_bind_service+ep /usr/bin/gc-lab-caps

gclab_scan_if_requested "$@"
