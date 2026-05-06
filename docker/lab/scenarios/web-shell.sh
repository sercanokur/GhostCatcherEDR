#!/bin/sh
# WEB_SHELL_PATTERN (örnek: eval/HTTP)
# Doğrudan: sudo sh ./web-shell.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./web-shell.sh   veya   sudo sh ./web-shell.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
cp "$GCLAB_SKEL/shell.php" /var/www/html/attack-shell.php
chmod 644 /var/www/html/attack-shell.php

gclab_scan_if_requested "$@"
