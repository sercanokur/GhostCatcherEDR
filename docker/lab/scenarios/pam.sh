#!/bin/sh
# PAM_PERSISTENCE
# Doğrudan: sudo sh ./pam.sh
# Tarama:    GCLAB_RUN_SCAN=1 sudo sh ./pam.sh   veya   sudo sh ./pam.sh scan
. "$(cd "$(dirname "$0")" && pwd)/lib-env.sh"
set -e
cat > /etc/pam.d/lab-ghostcatcher <<'EOF'
#%PAM-1.0
auth    optional   pam_exec.so /bin/true
account include    common-account
session include    common-session
EOF
chmod 644 /etc/pam.d/lab-ghostcatcher

gclab_scan_if_requested "$@"
