//go:build linux

package respond

import (
	"fmt"
	"os/exec"
	"strings"
)

// isolateHost applies a coarse host isolation via iptables INPUT/OUTPUT DROP
// with exceptions for loopback and configured management CIDRs. Requires
// CAP_NET_ADMIN; failures are returned to the caller.
func (eng *Engine) isolateHost() error {
	allow := []string{"127.0.0.0/8", "::1/128"}
	allow = append(allow, eng.cfg.IsolationAllowlistCIDRs...)
	// Flush custom chain attempts are avoided; append-only DROP rules.
	for _, tableArgs := range [][]string{
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
	} {
		if err := runIPTables(tableArgs...); err != nil {
			return err
		}
	}
	for _, cidr := range allow {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		for _, chain := range []string{"INPUT", "OUTPUT"} {
			args := []string{"-A", chain, "-d", cidr, "-j", "ACCEPT"}
			if chain == "OUTPUT" {
				args = []string{"-A", chain, "-d", cidr, "-j", "ACCEPT"}
			}
			if strings.Contains(cidr, ":") {
				args = []string{"-A", chain, "-d", cidr, "-j", "ACCEPT"}
			}
			_ = runIPTables(args...)
		}
	}
	if err := runIPTables("-A", "INPUT", "-j", "DROP"); err != nil {
		return err
	}
	if err := runIPTables("-A", "OUTPUT", "-j", "DROP"); err != nil {
		return err
	}
	return nil
}

func runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
