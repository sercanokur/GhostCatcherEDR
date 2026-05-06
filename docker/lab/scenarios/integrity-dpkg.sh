#!/bin/sh
# BINARY_INTEGRITY_MD5_MISMATCH
# Doğrudan: sudo sh ./integrity-dpkg.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./integrity-dpkg.sh   veya   sudo sh ./integrity-dpkg.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
# coreutils: /usr/bin/yes
printf ' ' >>/usr/bin/yes

gclab_scan_if_requested "$@"
