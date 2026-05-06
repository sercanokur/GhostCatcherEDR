#!/bin/bash
# Hızlı demo: ağ dışı + web recon (yerel) — root
# Kullanım: sudo ./run-quick-suspicious-demo.sh
set -euo pipefail
[ "${EUID:-0}" -eq 0 ] || { echo "sudo ile çalıştırın"; exit 1; }
attackctl reset
attackctl baseline
# Paralel şüphe: egress + recon isteği
attackctl apply network-egress
curl -s -o /dev/null "http://127.0.0.1/recon.php" || true
attackctl apply web-recon
echo "=== tarama ==="
attackctl scan | head -20
