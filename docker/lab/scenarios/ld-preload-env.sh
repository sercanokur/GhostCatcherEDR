#!/bin/sh
# PROC_LD_PRELOAD_ENV
# Doğrudan: sudo sh ./ld-preload-env.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./ld-preload-env.sh   veya   sudo sh ./ld-preload-env.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
: > /tmp/lab-ld.so
# Uzun süre yaşayan süreç (tarama sırasında hâlâ var olsun)
nohup env LD_PRELOAD=/tmp/lab-ld.so sh -c 'sleep 600' </dev/null >/dev/null 2>&1 &

gclab_scan_if_requested "$@"
