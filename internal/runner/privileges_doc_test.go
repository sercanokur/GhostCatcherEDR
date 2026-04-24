package runner

import "testing"

// Documents host privilege expectations (no assertions — onboarding / SOC reference).
func TestPrivilegeMatrix_documented(t *testing.T) {
	t.Log("root: full /proc/*/environ, maps, all users authorized_keys, cron.d, ld.so.preload — recommended in production.")
	t.Log("non-root: only own UID processes' environ/maps readable; getent may work; many false negatives for LD_PRELOAD and cross-user SSH paths.")
	t.Log("fsnotify watches need read access to each user's .ssh directory; root simplifies homedir coverage.")
	t.Log("dpkg integrity checks require /var/lib/dpkg (Debian/Ubuntu); skip elsewhere.")
	t.Log("eBPF sys_execve / NDR beaconing are out of scope for this agent; use external tools for kernel or network correlation.")
	t.Log("systemd unit ships as User=root in systemd/ghostcatcher.service for this reason.")
}
