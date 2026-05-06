#!/bin/sh
# SUID_INVENTORY_DELTA
# Doğrudan: sudo sh ./suid.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./suid.sh   veya   sudo sh ./suid.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
cp /bin/ls /usr/bin/gc-lab-suid
chmod 4755 /usr/bin/gc-lab-suid

gclab_scan_if_requested "$@"
