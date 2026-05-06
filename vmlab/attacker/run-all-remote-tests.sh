#!/bin/bash
# =============================================================================
# Kali’dan KURBAN üzerine şüpheli dış hattı harekete geçir (HTTP/SSH/uzaktan sızma yok, trafik üret)
# lab.env: VICTIM_IP, VICTIM_HOSTNAME
# =============================================================================
set -euo pipefail
VMLAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$VMLAB_ROOT/lab.env" ] && source "$VMLAB_ROOT/lab.env"
: "${VICTIM_IP:?lab.env: VICTIM_IP}"
: "${VICTIM_HOSTNAME:=victim.lab}"
KEYDIR="$HOME/.config/ghostcatcher-lab/ssh/id_ed25519"
BASE="http://$VICTIM_IP"
# hosts kayıtlıysa
ping -c1 -W1 "$VICTIM_HOSTNAME" 2>/dev/null && BASE="http://$VICTIM_HOSTNAME"

echo "Hedef: $BASE (Kurban: $VICTIM_IP)"
echo "--- [1] Port tarama ---"
nmap -Pn -p 22,80,443 "$VICTIM_IP" || true

echo "--- [2] Web — recon (whoami altında php-fpm) ---"
curl -sS -m 10 "$BASE/recon.php" | head -c 200 || true
echo ""

echo "--- [3] Web — egress.php (Kali taramasından önce worker’ı uzun süre dışa aç) ---"
# Kurban: attackctl apply network-egress önce çalıştıysa zaten; yoksa bu istek fpm’yi dışa iter
curl -sS -m 5 "$BASE/egress.php" &
sleep 2

echo "--- [4] Web — bilinen kötü örnek shell (eval) — sadece dosya yoksa 404, önce victim’te: attackctl apply web-shell ---"
curl -sS -m 5 "$BASE/attack-shell.php" | head -c 120 || true
echo ""

echo "--- [5] SSH — anahtar varsa tekrar ---"
if [ -f "$KEYDIR" ]; then
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-i "$KEYDIR" -o ConnectTimeout=5 "root@$VICTIM_IP" "hostname; id" 2>&1 | head -5 || echo "(SSH yok: authorized_keys’e Kali pub eklendi mi?)"
else
	echo "Yok: $KEYDIR (install-kali-attacker.sh çalıştırın)"
fi

echo "--- Bitti. Kurban’da: attackctl scan (network-egress uygulandıysa web_worker_egress vb.)"
