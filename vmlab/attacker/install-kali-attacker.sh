#!/bin/bash
# =============================================================================
# Kali Linux (veya Debian tabanlı saldırgan) — kurulum
# Olmak zorunda değil: root, sudo yeter. lab.env ile: ../lab.env
# =============================================================================
set -euo pipefail

VMLAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${VMLAB_ENV:=$VMLAB_ROOT/lab.env}"
if [ -f "$VMLAB_ENV" ]; then
	# shellcheck source=/dev/null
	source "$VMLAB_ENV"
fi
: "${VICTIM_IP:?lab.env: VICTIM_IP tanımlayın (ör. 192.168.56.10)}"
: "${VICTIM_HOSTNAME:=victim.lab}"

# Kali / Debian
if command -v apt-get >/dev/null; then
	APT="apt-get"
	command -v sudo >/dev/null && APT="sudo apt-get"
	$APT update -qq
	$APT install -y --no-install-recommends \
		curl wget openssh-client netcat-openbsd nmap \
		bash ca-certificates jq iputils-ping
fi

mkdir -p "$HOME/.config/ghostcatcher-lab"
cp -f "$VMLAB_ENV" "$HOME/.config/ghostcatcher-lab/lab.env" 2>/dev/null || {
	echo "export VMLAB_ROOT=$VMLAB_ROOT" > "$HOME/.config/ghostcatcher-lab/lab.env"
	echo "export VICTIM_IP=$VICTIM_IP" >> "$HOME/.config/ghostcatcher-lab/lab.env"
}

# /etc/hosts (isteğe bağlı)
SUDO=""
command -v sudo >/dev/null && SUDO="sudo"
if $SUDO test -w /etc/hosts; then
	$SUDO sed -i "/ $VICTIM_HOSTNAME\$/d" /etc/hosts
	echo "$VICTIM_IP  $VICTIM_HOSTNAME" | $SUDO tee -a /etc/hosts >/dev/null
fi

# SSH lab anahtarı
KEYDIR="$HOME/.config/ghostcatcher-lab/ssh"
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/id_ed25519" ]; then
	ssh-keygen -t ed25519 -N "" -f "$KEYDIR/id_ed25519" -C "ghostcatcher-lab"
fi
echo ""
echo "=== Kali hazır ==="
echo "Kurban root’a anahtar ekleyin (victim’te root ile):"
echo "  KALI_SSH_PUB_KEY_LINE='$(cat "$KEYDIR/id_ed25519.pub")'  # veya aşağıdaki satırı victim authorized_keys’e ekleyin"
cat "$KEYDIR/id_ed25519.pub"
echo ""
echo "Uzak test:  $VMLAB_ROOT/attacker/run-all-remote-tests.sh"
echo "SSH:        ssh -i $KEYDIR/id_ed25519 root@$VICTIM_IP   veya  ssh -i ... root@$VICTIM_HOSTNAME"
