#!/bin/sh
set -e
# SSH host keys (first boot)
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
	ssh-keygen -A
fi
mkdir -p /var/run/sshd
mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
