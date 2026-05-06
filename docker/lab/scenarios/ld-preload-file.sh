#!/bin/sh
# LD_SO_PRELOAD_FILE
# Doğrudan: sudo sh ./ld-preload-file.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./ld-preload-file.sh   veya   sudo sh ./ld-preload-file.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
echo /tmp/lab-fake.so > /etc/ld.so.preload
: > /tmp/lab-fake.so

gclab_scan_if_requested "$@"
