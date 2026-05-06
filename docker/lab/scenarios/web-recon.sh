#!/bin/sh
# WEB_WORKER_RECON_CHILD
# Doğrudan: sudo sh ./web-recon.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./web-recon.sh   veya   sudo sh ./web-recon.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
# php-fpm altında whoami
curl -s -o /dev/null "http://127.0.0.1/recon.php" || true

gclab_scan_if_requested "$@"
