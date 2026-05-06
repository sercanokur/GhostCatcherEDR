#!/bin/bash
# =============================================================================
# GhostCatcher — KURBAN sanal makine kurulumu (Debian 12 / Ubuntu 22.04+)
# Root ile çalıştır:  sudo bash install-victim.sh
# Önkoşul: bu repo (GhostCatcher) klonu veya vmlab ile birlikte dağıtım
# =============================================================================
set -euo pipefail

VMLAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${VMLAB_ENV:=$VMLAB_ROOT/lab.env}"
if [ -f "$VMLAB_ENV" ]; then
	# shellcheck source=/dev/null
	source "$VMLAB_ENV"
fi
: "${GHOSTCATCHER_REPO:=}"
if [ -n "${GHOSTCATCHER_REPO}" ]; then
	REPO_ROOT="$GHOSTCATCHER_REPO"
else
	REPO_ROOT="$(cd "$VMLAB_ROOT/.." && pwd)"
fi

if [ "${EUID:-0}" -ne 0 ]; then
	echo "Root ile çalıştırın: sudo $0" >&2
	exit 1
fi

if [ ! -f "$REPO_ROOT/go.mod" ]; then
	echo "go.mod yok, REPO kökü yanlış: $REPO_ROOT (GHOSTCATCHER_REPO=...)" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
	ca-certificates git curl nginx \
	"php-fpm" "php-cli" "php-curl" \
	cron openssh-server netcat-openbsd procps \
	libcap2-bin util-linux

# PHP-FPM
systemctl enable --now "php8.2-fpm" 2>/dev/null || true
systemctl enable --now "php8.3-fpm" 2>/dev/null || true
systemctl enable --now "php-fpm" 2>/dev/null || true
PHPSOCK=$(ls /run/php/php*fpm.sock 2>/dev/null | head -1 || true)
if [ -z "$PHPSOCK" ]; then
	systemctl restart php*-fpm 2>/dev/null || true
	PHPSOCK=$(ls /run/php/php*fpm.sock 2>/dev/null | head -1)
fi
if [ -z "$PHPSOCK" ]; then
	echo "php-fpm soket bulunamadı" >&2
	exit 1
fi
echo "Kullanılan PHP-FPM soket: $PHPSOCK"

install -d -m 0755 /var/lib/ghostcatcher /etc/ghostcatcher
install -d -m 0700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Nginx
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/ghostcatcher-lab <<NGX
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.php index.html;
    server_name _;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location ~ \.php\$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:$PHPSOCK;
    }
}
NGX
ln -sf /etc/nginx/sites-available/ghostcatcher-lab /etc/nginx/sites-enabled/
nginx -t
systemctl enable --now nginx

# Web kökü
if [ -d "$REPO_ROOT/docker/lab/www" ]; then
	cp -a "$REPO_ROOT/docker/lab/www/." /var/www/html/
elif [ -d "$VMLAB_ROOT/www" ]; then
	cp -a "$VMLAB_ROOT/www/." /var/www/html/
fi
# shell.php şablonu
mkdir -p /opt/lab/skel
cp -f "$REPO_ROOT/testdata/webroot/shell.php" /opt/lab/skel/shell.php

# Senaryolar
install -d -m 0755 /opt/lab
cp -a "$REPO_ROOT/docker/lab/scenarios/." /opt/lab/scenarios/
cp -a "$REPO_ROOT/docker/lab/skel/." /opt/lab/skel/ 2>/dev/null || true
chmod +x /opt/lab/scenarios/*.sh
# reset + attackctl
cp -f "$VMLAB_ROOT/victim/reset-lab.sh" /opt/lab/reset-lab.sh
chmod +x /opt/lab/reset-lab.sh
cp -f "$VMLAB_ROOT/attackctl" /usr/local/bin/attackctl
chmod +x /usr/local/bin/attackctl
cp -f "$VMLAB_ROOT/victim/bench-all-scenarios.sh" /opt/lab/bench-all-scenarios.sh
cp -f "$VMLAB_ROOT/victim/run-quick-suspicious-demo.sh" /opt/lab/run-quick-suspicious-demo.sh
chmod +x /opt/lab/bench-all-scenarios.sh /opt/lab/run-quick-suspicious-demo.sh
tar -czf /opt/lab/golden.tgz -C / var/www/html 2>/dev/null || true

# sshd
cat > /etc/ssh/sshd_config.d/99-ghostcatcher-lab.conf <<'SSHD'
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
SSHD
if [ -f "$REPO_ROOT/docker/lab/sshd-99-lab.conf" ]; then
	cp -f "$REPO_ROOT/docker/lab/sshd-99-lab.conf" /etc/ssh/sshd_config.d/99-ghostcatcher-lab.conf
fi
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true

# cron
systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true

# Kural + config
cp -f "$REPO_ROOT/configs/lab_rule_pack.yaml" /etc/ghostcatcher/lab_rule_pack.yaml
cp -f "$VMLAB_ROOT/victim/ghostcatcher-lab.config.yaml" /etc/ghostcatcher/lab.config.yaml
CONFIG_DST=/etc/ghostcatcher/lab.config.yaml
# lab.env — SIEM (python3, Debian/Ubuntu’da var)
if [ -n "${SIEM_LOKI_URL:-}" ] && command -v python3 >/dev/null; then
	SIEM_LOKI_URL=$SIEM_LOKI_URL python3 -c "
import os, re
p = '/etc/ghostcatcher/lab.config.yaml'
c = open(p).read()
u = os.environ['SIEM_LOKI_URL'].rstrip('/')
c = re.sub(r'(?m)^(loki_push:\n)  enabled: false', r'\1  enabled: true', c, count=1)
c = re.sub(r'(?m)^  url: http://127.0.0.1:3100', f'  url: {u}', c, count=1)
open(p, 'w').write(c)
" || true
fi
if [ -n "${SIEM_SYSLOG_HOST:-}" ] && command -v python3 >/dev/null; then
	export SIEM_SYSLOG_HOST
	export SIEM_SYSLOG_UDP_PORT="${SIEM_SYSLOG_UDP_PORT:-5514}"
	python3 -c "
import os, re
p = '/etc/ghostcatcher/lab.config.yaml'
c = open(p).read()
h, port = os.environ['SIEM_SYSLOG_HOST'], os.environ['SIEM_SYSLOG_UDP_PORT']
c = re.sub(r'(?m)^(syslog_udp:\n)  enabled: false', r'\1  enabled: true', c, count=1)
c = re.sub(r'(?m)^  host: 127.0.0.1', f'  host: {h}', c, count=1)
c = re.sub(r'(?m)^  port: 5514', f'  port: {port}', c, count=1)
open(p, 'w').write(c)
" || true
fi

# Go 1.22+ ( bookworm: backports veya resmi go )
if ! command -v go >/dev/null; then
	apt-get install -y -qq golang-go
fi
if ! go version 2>&1 | grep -qE 'go1\.(2[2-9]|[3-9][0-9]|1[0-9])'; then
	echo "Go 1.22+ gerek. Şu an: $(go version 2>&1). https://go.dev/dl" >&2
	exit 1
fi
( cd "$REPO_ROOT" && go build -trimpath -o /usr/local/bin/ghostcatcher ./cmd/agent )
/usr/local/bin/ghostcatcher check-config -config /etc/ghostcatcher/lab.config.yaml

# (İsteğe bağlı) Kali SSH: KALI_SSH_PUB=pubkey dosyası veya KALI_SSH_PUB_KEY_LINE=tek satır
if [ -n "${KALI_SSH_PUB_KEY_LINE:-}" ]; then
	grep -qxF "$KALI_SSH_PUB_KEY_LINE" /root/.ssh/authorized_keys 2>/dev/null || echo "$KALI_SSH_PUB_KEY_LINE" >> /root/.ssh/authorized_keys
elif [ -n "${KALI_SSH_PUB:-}" ] && [ -f "${KALI_SSH_PUB}" ]; then
	grep -qxF "$(cat "$KALI_SSH_PUB")" /root/.ssh/authorized_keys 2>/dev/null || cat "$KALI_SSH_PUB" >> /root/.ssh/authorized_keys
fi

# hosts (isteğe bağlı)
if [ -n "${VICTIM_IP:-}" ] && [ -n "${VICTIM_HOSTNAME:-}" ]; then
	grep -q "$VICTIM_HOSTNAME" /etc/hosts || echo "$VICTIM_IP   $VICTIM_HOSTNAME" >> /etc/hosts
fi

echo "=== Kurban hazır ==="
echo "Lokal test:  attackctl check && attackctl baseline && attackctl apply web-shell && attackctl scan | head"
echo "Dışarıdan:   Kali’de  ./install-kali-attacker.sh  ve  ./run-all-remote-tests.sh"
