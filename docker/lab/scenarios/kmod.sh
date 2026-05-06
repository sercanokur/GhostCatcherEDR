#!/bin/sh
# KERNEL_MODLOAD_PATH_CHANGED
# Doğrudan: sudo sh ./kmod.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./kmod.sh   veya   sudo sh ./kmod.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
echo "nf_conntrack" > /etc/modules-load.d/99-lab-ghostcatcher.conf
chmod 644 /etc/modules-load.d/99-lab-ghostcatcher.conf

gclab_scan_if_requested "$@"
