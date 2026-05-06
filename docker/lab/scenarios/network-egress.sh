#!/bin/sh
# NETWORK_WEB_WORKER_EGRESS (php-fpm, comm eşleşmesi hedefi)
# Doğrudan: sudo sh ./network-egress.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./network-egress.sh   veya   sudo sh ./network-egress.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
# Arka planda PHP uzun süreli dış HTTP açsın; hemen tarama yap
nohup runuser -u www-data -- /usr/bin/php /var/www/html/egress.php </dev/null >/dev/null 2>&1 &

gclab_scan_if_requested "$@"
