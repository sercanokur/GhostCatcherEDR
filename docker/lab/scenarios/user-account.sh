#!/bin/sh
# USER_ACCOUNT_ANOMALY
# Doğrudan: sudo sh ./user-account.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./user-account.sh   veya   sudo sh ./user-account.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
if ! id gc_lab_user >/dev/null 2>&1; then
	useradd -m -s /bin/bash gc_lab_user
fi

gclab_scan_if_requested "$@"
