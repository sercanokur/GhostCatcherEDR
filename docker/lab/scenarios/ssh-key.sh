#!/bin/sh
# SSH_AUTHKEY_NEW
# Doğrudan: sudo sh ./ssh-key.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./ssh-key.sh   veya   sudo sh ./ssh-key.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '\n# lab\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0fakeLabKey= ghostcatcher-lab\n' >>/root/.ssh/authorized_keys

gclab_scan_if_requested "$@"
