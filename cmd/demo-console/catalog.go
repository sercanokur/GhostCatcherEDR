package main

// scenarioCmd builds a remote command for an attack-lab matrix script.
func scenarioCmd(name string) string {
	return "LAB_ROOT=/opt/ghostcatcher-lab/lab bash /opt/ghostcatcher-lab/lab/scenarios/" + name + ".sh"
}

func allStepDefs() []StepDef {
	i := 0
	next := func() int { n := i; i++; return n }

	var defs []StepDef

	// —— Kill-chain narrative ——
	defs = append(defs,
		StepDef{
			ID: "reset", Index: next(), Group: "Kill chain", Title: "Reset lab",
			Narration: "Clear kill-chain + matrix artifacts for a clean run.",
			RemoteCmd: "/opt/ghostcatcher-lab/demo-killchain.sh --reset-only; /opt/ghostcatcher-lab/lab/reset-matrix.sh",
		},
		StepDef{
			ID: "webshell", Index: next(), Group: "Kill chain", Title: "Act 0 — Webshell (wp2shell)",
			Narration: "WordPress Batch desync → PHP webshell on disk.",
			RuleIDs:   []string{"WEB_SHELL_PATTERN"},
			RemoteCmd: "bash /opt/ghostcatcher-lab/killchain/01-webshell.sh wp2shell",
			WaitSecs:  60, ExpectRules: true,
		},
		StepDef{
			ID: "sudden_root", Index: next(), Group: "Kill chain", Title: "Act 1 — Sudden root",
			Narration: "Unprivileged process flips to euid=0 (CAP_SETUID sim).",
			RuleIDs:   []string{"PROC_SUDDEN_ROOT"},
			RemoteCmd: "bash /opt/ghostcatcher-lab/killchain/02-sudden-root.sh sim",
			WaitSecs:  60, ExpectRules: true,
		},
		StepDef{
			ID: "persist", Index: next(), Group: "Kill chain", Title: "Act 2 — Persistence",
			Narration: "ld.so.preload + labuser authorized_keys after “root”.",
			RuleIDs:   []string{"LD_SO_PRELOAD_FILE", "SSH_AUTHKEY_NEW"},
			RemoteCmd: "bash /opt/ghostcatcher-lab/killchain/03-persist-evasion.sh",
			WaitSecs:  60, ExpectRules: true,
		},
		StepDef{
			ID: "reverse_shell", Index: next(), Group: "Kill chain", Title: "Act 3 — Reverse shell",
			Narration: "bash /dev/tcp reverse shell (self-listener).",
			RuleIDs:   []string{"PROC_SOCKET_STDIO"},
			RemoteCmd: "bash /opt/ghostcatcher-lab/killchain/04-reverse-shell.sh",
			WaitSecs:  90, ExpectRules: true,
		},
	)

	// —— Web ——
	defs = append(defs,
		StepDef{
			ID: "web-shell", Index: next(), Group: "Web", Title: "Web shell fixture",
			Narration: "Drop attack-shell.php under /var/www/html.",
			RuleIDs:   []string{"WEB_SHELL_PATTERN"},
			RemoteCmd: scenarioCmd("web-shell"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "web-recon", Index: next(), Group: "Web", Title: "Web worker recon child",
			Narration: "HTTP hit that spawns recon under the web worker.",
			RuleIDs:   []string{"WEB_WORKER_RECON_CHILD"},
			RemoteCmd: scenarioCmd("web-recon"),
			WaitSecs:  90, ExpectRules: true,
		},
	)

	// —— Persistence ——
	defs = append(defs,
		StepDef{
			ID: "cron", Index: next(), Group: "Persistence", Title: "High-risk cron",
			Narration: "Plant curl|bash style cron.d drop-in.",
			RuleIDs:   []string{"CRON_HIGH_RISK"},
			RemoteCmd: scenarioCmd("cron"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "ld-preload-file", Index: next(), Group: "Persistence", Title: "ld.so.preload file",
			Narration: "Non-empty /etc/ld.so.preload.",
			RuleIDs:   []string{"LD_SO_PRELOAD_FILE"},
			RemoteCmd: scenarioCmd("ld-preload-file"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "ld-preload-env", Index: next(), Group: "Persistence", Title: "LD_PRELOAD env",
			Narration: "Long-lived process with LD_PRELOAD set.",
			RuleIDs:   []string{"PROC_LD_PRELOAD_ENV"},
			RemoteCmd: scenarioCmd("ld-preload-env"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "ssh-key", Index: next(), Group: "Persistence", Title: "New SSH authorized key",
			Narration: "Append a new key fingerprint for a lab user.",
			RuleIDs:   []string{"SSH_AUTHKEY_NEW"},
			RemoteCmd: scenarioCmd("ssh-key"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "ssh-auth-invalid", Index: next(), Group: "Persistence", Title: "Invalid SSH key line",
			Narration: "Garbage line in authorized_keys.",
			RuleIDs:   []string{"SSH_AUTHKEY_INVALID_LINE"},
			RemoteCmd: scenarioCmd("ssh-auth-invalid"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "sudoers", Index: next(), Group: "Persistence", Title: "Sudoers persistence",
			Narration: "NOPASSWD / unrestricted sudoers drop-in.",
			RuleIDs:   []string{"SUDOERS_PERSISTENCE"},
			RemoteCmd: scenarioCmd("sudoers"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "systemd", Index: next(), Group: "Persistence", Title: "Systemd persistence",
			Narration: "Suspicious systemd unit ExecStart.",
			RuleIDs:   []string{"SYSTEMD_PERSISTENCE"},
			RemoteCmd: scenarioCmd("systemd"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "pam", Index: next(), Group: "Persistence", Title: "PAM persistence",
			Narration: "Suspicious PAM config / module path.",
			RuleIDs:   []string{"PAM_PERSISTENCE"},
			RemoteCmd: scenarioCmd("pam"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "shellrc", Index: next(), Group: "Persistence", Title: "Shell RC / profile hook",
			Narration: "Backdoor line in root .bashrc (PROFILE_HOOK).",
			RuleIDs:   []string{"PROFILE_HOOK"},
			RemoteCmd: scenarioCmd("shellrc"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "kmod", Index: next(), Group: "Persistence", Title: "Kernel modload path",
			Narration: "modules-load.d / modprobe.d change.",
			RuleIDs:   []string{"KERNEL_MODLOAD_PATH_CHANGED"},
			RemoteCmd: scenarioCmd("kmod"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "ldconf", Index: next(), Group: "Persistence", Title: "ld.so.conf change",
			Narration: "Extra path under ld.so.conf.d.",
			RuleIDs:   []string{"LD_SO_CONF_CHANGED"},
			RemoteCmd: scenarioCmd("ldconf"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "sshd-config", Index: next(), Group: "Persistence", Title: "sshd config anomaly",
			Narration: "High-risk sshd drop-in directive.",
			RuleIDs:   []string{"SSHD_CONFIG_ANOMALY"},
			RemoteCmd: scenarioCmd("sshd-config"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "user-account", Index: next(), Group: "Persistence", Title: "User account anomaly",
			Narration: "passwd/shadow change via lab user create.",
			RuleIDs:   []string{"USER_ACCOUNT_ANOMALY"},
			RemoteCmd: scenarioCmd("user-account"),
			WaitSecs:  90, ExpectRules: true,
		},
	)

	// —— Privilege / integrity ——
	defs = append(defs,
		StepDef{
			ID: "suid", Index: next(), Group: "Privilege", Title: "SUID inventory delta",
			Narration: "Create a lab SUID binary.",
			RuleIDs:   []string{"SUID_INVENTORY_DELTA"},
			RemoteCmd: scenarioCmd("suid"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "capability", Index: next(), Group: "Privilege", Title: "File capability delta",
			Narration: "setcap on a lab helper binary.",
			RuleIDs:   []string{"FILE_CAPABILITY_DELTA"},
			RemoteCmd: scenarioCmd("capability"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "integrity-dpkg", Index: next(), Group: "Privilege", Title: "Binary integrity mismatch",
			Narration: "Mutate /usr/bin/yes → LIB_HASH_MISMATCH.",
			RuleIDs:   []string{"LIB_HASH_MISMATCH"},
			RemoteCmd: scenarioCmd("integrity-dpkg"),
			WaitSecs:  120, ExpectRules: true,
		},
	)

	// —— Network ——
	defs = append(defs,
		StepDef{
			ID: "network-listen", Index: next(), Group: "Network", Title: "Unexpected listen",
			Narration: "Open a non-loopback listener.",
			RuleIDs:   []string{"NETWORK_LISTEN_NEW"},
			RemoteCmd: scenarioCmd("network-listen"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "network-reverse", Index: next(), Group: "Network", Title: "Reverse shell (matrix)",
			Narration: "bash /dev/tcp to a public IP (PROC_SOCKET_STDIO).",
			RuleIDs:   []string{"PROC_SOCKET_STDIO"},
			RemoteCmd: scenarioCmd("network-reverse"),
			WaitSecs:  90, ExpectRules: true,
		},
		StepDef{
			ID: "network-egress", Index: next(), Group: "Network", Title: "Web worker egress",
			Narration: "www-data PHP process opens outbound HTTP.",
			RuleIDs:   []string{"NETWORK_WEB_WORKER_EGRESS"},
			RemoteCmd: scenarioCmd("network-egress"),
			WaitSecs:  90, ExpectRules: true,
		},
	)

	return defs
}
