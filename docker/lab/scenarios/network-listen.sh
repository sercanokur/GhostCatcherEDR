#!/bin/sh
# NETWORK_UNEXPECTED_LISTEN
# Doğrudan: sudo sh ./network-listen.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./network-listen.sh   veya   sudo sh ./network-listen.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
nohup nc -l -p 4444 -s 0.0.0.0 </dev/null >/dev/null 2>&1 &

gclab_scan_if_requested "$@"
