#!/bin/bash
# =============================================================================
# Tüm yerel senaryoları sırayla: reset → baseline → apply → JSON stdout
# UYARI: Uzun sürer; üretim makinesinde çalıştırmayın. Yalnızca izole lab VM.
# Root veya attackctl yoluna erişim.
# Kullanım: sudo ./bench-all-scenarios.sh 2>&1 | tee /tmp/bench.log
# =============================================================================
set -euo pipefail
if [ "${EUID:-0}" -ne 0 ] && [ ! -x /usr/local/bin/attackctl ]; then
	echo "root veya /usr/local/bin/attackctl gerekli" >&2
	exit 1
fi
ACT=attackctl
command -v attackctl >/dev/null || ACT="sudo /usr/local/bin/attackctl"

$ACT reset
$ACT baseline

for f in /opt/lab/scenarios/*.sh; do
	[ -f "$f" ] || continue
	s=$(basename "$f" .sh)
	echo "================ $s ================"
	$ACT reset
	$ACT baseline
	$ACT apply "$s" 2>&1 | tail -1
	$ACT scan 2>&1 | head -3 || true
	echo ""
done
echo "Bitti. Tam log için scan çıktısını arttırın (head kaldır)."
