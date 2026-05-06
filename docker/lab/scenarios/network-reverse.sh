#!/bin/sh
# NETWORK_REVERSE_SHELL — bash, özel ağa izin listesi dışı hedef
# Doğrudan: sudo sh ./network-reverse.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./network-reverse.sh   veya   sudo sh ./network-reverse.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
# Tarama penceresinde soket açık kalsın
( bash -c 'exec 3<>/dev/tcp/1.1.1.1/443; sleep 25' </dev/null >/dev/null 2>&1 & )

gclab_scan_if_requested "$@"
