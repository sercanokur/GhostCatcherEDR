#!/bin/sh
# LD_SO_CONF_CHANGED
# Doğrudan: sudo sh ./ldconf.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./ldconf.sh   veya   sudo sh ./ldconf.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
echo /tmp/ghostcatcher-lab > /etc/ld.so.conf.d/99-lab-ghostcatcher.conf
chmod 644 /etc/ld.so.conf.d/99-lab-ghostcatcher.conf

gclab_scan_if_requested "$@"
