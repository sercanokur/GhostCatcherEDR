#!/bin/sh
# SSH_AUTHKEY_INVALID_LINE
# Doğrudan: sudo sh ./ssh-auth-invalid.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./ssh-auth-invalid.sh   veya   sudo sh ./ssh-auth-invalid.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
printf '\nthis-is-not-a-valid-key-line-for-openssh\n' >>/root/.ssh/authorized_keys

gclab_scan_if_requested "$@"
