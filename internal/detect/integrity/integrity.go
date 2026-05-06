package integrity

import (
	"bufio"
	"os"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

const (
	RuleBinaryMD5Mismatch = "BINARY_INTEGRITY_MD5_MISMATCH"
	RuleSUIDAnomaly       = "SUID_INVENTORY_DELTA"
	RuleCapabilityAnomaly = "FILE_CAPABILITY_DELTA"
)

// distro describes the packaging backend to use for integrity verification.
type distro int

const (
	distroUnknown distro = iota
	distroDpkg
	distroRpm
)

// Scan runs every available integrity check against the current host.
// Each sub-check is best-effort: missing backends (e.g. rpm on Debian, or
// xattrs on non-Linux) are silently skipped rather than producing errors.
func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.IntegrityVerifyEnabled {
		return nil, nil
	}
	var out []event.Event
	now := time.Now().UTC()

	switch detectDistro() {
	case distroDpkg:
		ev := scanDpkg(cfg, snap, pack, agentVer, now)
		out = append(out, ev...)
	case distroRpm:
		ev := scanRPM(cfg, snap, pack, agentVer, now)
		out = append(out, ev...)
	}

	out = append(out, scanSUID(cfg, snap, pack, agentVer, now)...)
	out = append(out, scanCapabilities(cfg, snap, pack, agentVer, now)...)
	return out, nil
}

// detectDistro inspects /etc/os-release and the presence of package manager
// state directories to pick the right integrity backend.
func detectDistro() distro {
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		return distroDpkg
	}
	if _, err := os.Stat("/var/lib/rpm/Packages"); err == nil {
		return distroRpm
	}
	if _, err := os.Stat("/var/lib/rpm/rpmdb.sqlite"); err == nil {
		return distroRpm
	}
	// Secondary probe via /etc/os-release ID fields.
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return distroUnknown
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ID=") || strings.HasPrefix(line, "ID_LIKE=") {
			v := strings.ToLower(strings.Trim(strings.SplitN(line, "=", 2)[1], `"`))
			switch {
			case strings.Contains(v, "debian"), strings.Contains(v, "ubuntu"):
				return distroDpkg
			case strings.Contains(v, "rhel"), strings.Contains(v, "centos"), strings.Contains(v, "fedora"), strings.Contains(v, "rocky"), strings.Contains(v, "suse"), strings.Contains(v, "amzn"):
				return distroRpm
			}
		}
	}
	return distroUnknown
}

// BuildBaselineIntegrity captures the SUID inventory and file capabilities
// so deltas can be reported. Called during `baseline commit`.
func BuildBaselineIntegrity(cfg *config.Config, snap *baseline.Snapshot) error {
	if err := BuildBaselineSUID(cfg, snap); err != nil {
		return err
	}
	if err := BuildBaselineCapabilities(cfg, snap); err != nil {
		return err
	}
	return nil
}
