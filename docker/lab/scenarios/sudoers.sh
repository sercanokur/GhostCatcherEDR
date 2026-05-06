#!/bin/sh
# SUDOERS_PERSISTENCE
# Doğrudan: sudo sh ./sudoers.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./sudoers.sh   veya   sudo sh ./sudoers.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '%s\n' 'lab_user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-lab-ghostcatcher
chmod 440 /etc/sudoers.d/99-lab-ghostcatcher

gclab_scan_if_requested "$@"
