#!/bin/sh
# SSHD_CONFIG_ANOMALY
# Doğrudan: sudo sh ./sshd-config.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./sshd-config.sh   veya   sudo sh ./sshd-config.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '%s\n' 'PermitUserEnvironment yes' 'AuthorizedKeysCommand /bin/false' > /etc/ssh/sshd_config.d/99-lab-ghostcatcher.conf
chmod 644 /etc/ssh/sshd_config.d/99-lab-ghostcatcher.conf

gclab_scan_if_requested "$@"
