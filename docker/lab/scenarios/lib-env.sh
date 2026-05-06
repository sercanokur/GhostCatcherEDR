# shellcheck shell=sh
# GhostCatcher lab: senaryo betiklerinin hepsi bunu "source" eder.
# Doğrudan çalıştırma:  sudo ./web-shell.sh
# Senaryo + tarama:    sudo GCLAB_RUN_SCAN=1 ./web-shell.sh  veya  sudo ./web-shell.sh scan
#
# GCLAB_BIN, GCLAB_CFG, LAB_ROOT ortam değişkeni ile override edilebilir.

SCE_DIR=$(cd "$(dirname "$0")" && pwd)
export LAB_ROOT="${LAB_ROOT:-$(dirname "$SCE_DIR")}"
GCLAB_BIN="${GCLAB_BIN:-/usr/local/bin/ghostcatcher}"
GCLAB_CFG="${GCLAB_CFG:-/etc/ghostcatcher/lab.config.yaml}"
export GCLAB_BIN GCLAB_CFG
if [ -f "$LAB_ROOT/skel/shell.php" ]; then
	GCLAB_SKEL="$LAB_ROOT/skel"
elif [ -f "$LAB_ROOT/../testdata/webroot/shell.php" ]; then
	# monorepoda docker/lab üstten testdata'ya
	GCLAB_SKEL="$LAB_ROOT/../testdata/webroot"
else
	GCLAB_SKEL="/opt/lab/skel"
fi
export GCLAB_SKEL

# İsteğe bağlı: senaryo sonrası bir kez tarama
gclab_scan_if_requested() {
	_run=
	if [ "${GCLAB_RUN_SCAN:-0}" = "1" ] || [ "${1:-}" = "scan" ] || [ "${2:-}" = "scan" ]; then
		_run=1
	fi
	[ -z "$_run" ] && return 0
	if [ -x "$GCLAB_BIN" ] && [ -f "$GCLAB_CFG" ]; then
		"$GCLAB_BIN" run -config "$GCLAB_CFG" -once
	else
		echo "gclab: ghostcatcher veya config yok, tarama atlandı" >&2
		return 0
	fi
}
