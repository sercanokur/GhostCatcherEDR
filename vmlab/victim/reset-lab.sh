#!/bin/sh
# VM kurban — lab saldırı yüzeyini temizle (root ile çalıştır)
set -e
if [ -f /opt/lab/golden.tgz ]; then
	tar -xzf /opt/lab/golden.tgz -C /
fi
rm -f /etc/cron.d/lab-attack
rm -f /etc/ld.so.preload
rm -f /tmp/lab-fake.so /tmp/lab-ld.so
rm -f /usr/bin/gc-lab-suid /usr/bin/gc-lab-caps
rm -f /etc/sudoers.d/99-lab-ghostcatcher
rm -f /etc/systemd/system/lab-ghostcatcher-inject.service
rm -f /etc/pam.d/lab-ghostcatcher
rm -f /etc/ssh/sshd_config.d/99-lab-ghostcatcher.conf
rm -f /etc/modules-load.d/99-lab-ghostcatcher.conf
rm -f /etc/ld.so.conf.d/99-lab-ghostcatcher.conf
userdel -f gc_lab_user 2>/dev/null || true
pkill -f "nc -l" 2>/dev/null || true
if command -v apt-get >/dev/null 2>&1; then
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -qq coreutils 2>/dev/null || true
fi
echo "OK: reset. Sonra: attackctl baseline && attackctl scan"
