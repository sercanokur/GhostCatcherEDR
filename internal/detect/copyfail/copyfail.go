// Package copyfail implements detection coverage for CVE-2026-31431
// ("Copy Fail"), a Linux kernel privilege-escalation flaw in the
// algif_aead userspace crypto interface.
//
// Background: the flaw lets an unprivileged local user open an AF_ALG
// SOCK_SEQPACKET socket bound to "authencesn(hmac(sha256),cbc(aes))",
// splice() page-cache pages of a SUID binary into the AEAD scatterlist,
// and trigger a 4-byte scratch write that lands inside the spliced
// file's cached pages. Repeating the primitive corrupts /usr/bin/su in
// memory and hands the next invocation a root shell — without ever
// modifying the file on disk.
//
// Two detection legs cover the chain:
//
//  1. Live syscall observation (preferred). Any AF_ALG SOCK_SEQPACKET
//     socket() created by a process outside a small, well-known disk-
//     encryption / kTLS allowlist is the mandatory first step of every
//     known Copy Fail exploit. Routed in real time from the sensor.
//
//  2. Periodic page-cache vs on-disk integrity check on common SUID
//     binaries. Because page-cache poisoning leaves the filesystem
//     content untouched, a "page cache hash != O_DIRECT/dropped-cache
//     hash" delta is a strong post-condition signal even if syscall
//     telemetry is unavailable.
//
// References:
//   - https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds
//   - https://github.com/badsectorlabs/copyfail-go
package copyfail

import (
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

// Rule IDs emitted by this package.
const (
	RuleAFAlgAEAD     = "CVE_2026_31431_AF_ALG_AEAD"
	RulePageCachePois = "CVE_2026_31431_PAGE_CACHE_POISONING"
)

// Linux socket() argument constants relevant to the AEAD primitive.
//
// AF_ALG (38) is the kernel crypto userspace interface. SOCK_SEQPACKET
// (5) is the type the AEAD subsystem requires; symmetric and hash
// operations use SOCK_DGRAM and would not match. Real callers very
// often OR in SOCK_CLOEXEC (0x80000) and/or SOCK_NONBLOCK (0x800), so
// we mask those flags before comparing.
const (
	AFAlg            = 38
	SockSeqpacket    = 5
	sockTypeFlagMask = 0x80000 | 0x800 // SOCK_CLOEXEC | SOCK_NONBLOCK
)

// DefaultAllowedComms mirrors the Sysdig/Falco "known_af_alg_binaries"
// list: distro-shipped disk-encryption / integrity tooling that has a
// legitimate reason to open AF_ALG sockets. Process names from
// /proc/[pid]/comm are clipped to 15 characters by the kernel, so we
// add the truncated forms (e.g. "systemd-cryptse") explicitly.
var DefaultAllowedComms = []string{
	"cryptsetup",
	"systemd-cryptse",
	"systemd-cryptsetup",
	"veritysetup",
	"integritysetup",
	"cryptsetup-resh",
	"kcapi-enc",
	"kcapi-dgst",
	"kcapi-rng",
	"kcapi-sym",
	"kcapi-hasher",
	"kcapi-hasher-sha2",
	"kcapi-hasher-sha512",
}

// DefaultTargetSUIDBinaries is the watchlist for the page-cache vs
// on-disk drift check. These are the SUID/SGID root binaries the
// public Copy Fail PoCs corrupt to obtain a root shell.
var DefaultTargetSUIDBinaries = []string{
	"/usr/bin/su",
	"/bin/su",
	"/usr/bin/sudo",
	"/usr/bin/passwd",
	"/usr/bin/chsh",
	"/usr/bin/chfn",
	"/usr/bin/newgrp",
	"/usr/bin/gpasswd",
	"/usr/bin/mount",
	"/usr/bin/umount",
	"/bin/mount",
	"/bin/umount",
	"/usr/bin/pkexec",
	"/usr/lib/openssh/ssh-keysign",
}

// allowedCommSet returns the comm allowlist for the detector. Operator
// overrides from config are merged on top of the defaults so a
// stripped-down environment never accidentally drops the safe paths.
func allowedCommSet(extra []string) map[string]struct{} {
	out := make(map[string]struct{}, len(DefaultAllowedComms)+len(extra))
	for _, c := range DefaultAllowedComms {
		out[strings.ToLower(c)] = struct{}{}
	}
	for _, c := range extra {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		out[c] = struct{}{}
	}
	return out
}

// RouteSensorEvent inspects a sensor.Event and, when it is a
// successful AF_ALG SOCK_SEQPACKET socket() from a process outside the
// allowlist, returns a rule-pack-scored detection event. The boolean
// return tells callers whether the event was handled.
//
// The detector is intentionally conservative: only the AEAD shape
// (SEQPACKET) is alerted, because hashing/symmetric crypto callers
// (kTLS, dm-verity) use SOCK_DGRAM and would create severe noise.
func RouteSensorEvent(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	if ev.Kind != sensor.KindSocket {
		return event.Event{}, false
	}
	domain, ok := parseHexInt(ev.Extra["a0"])
	if !ok || domain != AFAlg {
		return event.Event{}, false
	}
	rawType, ok := parseHexInt(ev.Extra["a1"])
	if !ok {
		return event.Event{}, false
	}
	if rawType&^sockTypeFlagMask != SockSeqpacket {
		return event.Event{}, false
	}
	if !syscallSucceeded(ev.Extra) {
		return event.Event{}, false
	}

	allowed := allowedCommSet(cfg.CopyFail.AllowedCommExtras)
	comm := strings.ToLower(strings.TrimSpace(ev.Comm))
	if comm == "" && ev.PID > 0 {
		if c, err := procfs.Comm(ev.PID); err == nil {
			comm = strings.ToLower(strings.TrimSpace(c))
		}
	}
	if _, ok := allowed[comm]; ok {
		return event.Event{}, false
	}

	sigs := []string{
		"af_alg_aead_socket",
		"sock_seqpacket",
		"comm_outside_crypto_allowlist",
	}
	if ev.PID > 0 {
		// SUID-zero callers are particularly suspicious because the
		// exploit's whole purpose is to elevate an unprivileged user.
		if st, err := procfs.ReadStatus(ev.PID); err == nil && st.RealUID != 0 {
			sigs = append(sigs, "uid_unprivileged")
		}
	}

	conf, _ := rules.Score(pack, RuleAFAlgAEAD, sigs)
	if conf < 90 {
		conf = 90
	}
	learning := cfg.LearningMode
	out := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       time.Now().UTC(),
		RuleID:          RuleAFAlgAEAD,
		RulePackVersion: pack.Version,
		TechniqueIDs:    []string{"T1068"},
		Tactic:          "privilege-escalation",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity: event.Entity{
			Type: event.EntityProcess,
			ID:   strconv.Itoa(ev.PID),
			Path: procfs.ResolveExe(ev.PID),
		},
		Signals: sigs,
		Evidence: "AF_ALG SOCK_SEQPACKET socket() opened by comm=" + comm +
			" pid=" + strconv.Itoa(ev.PID) +
			" type=0x" + ev.Extra["a1"] +
			" — mandatory first step of CVE-2026-31431 (Copy Fail)",
		LearningOnly: learning,
	}
	out.NormalizeDedup()
	return out, true
}

// Scan performs the periodic, sensor-independent leg: for every
// configured SUID target binary it compares its hash as currently
// served from the kernel page cache against a fresh hash taken after
// dropping that file's cached pages. A mismatch indicates the page
// cache was poisoned without altering the on-disk content — the
// hallmark of CVE-2026-31431 exploitation.
func Scan(cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.CopyFail.Enabled || !cfg.CopyFail.PageCacheCheckEnabled {
		return nil, nil
	}
	targets := cfg.CopyFail.TargetSUIDBinaries
	if len(targets) == 0 {
		targets = DefaultTargetSUIDBinaries
	}
	now := time.Now().UTC()
	var events []event.Event
	for _, path := range targets {
		cacheHash, diskHash, ok, err := pageCacheVsDiskHash(path)
		if err != nil || !ok {
			// Missing files (e.g. /usr/lib/openssh/ssh-keysign on a
			// minimal image) and read errors are ignored to keep the
			// detector quiet on heterogeneous hosts.
			continue
		}
		if cacheHash == diskHash {
			continue
		}
		sigs := []string{
			"page_cache_disk_drift",
			"target_suid_binary",
		}
		conf, _ := rules.Score(pack, RulePageCachePois, sigs)
		if conf < 95 {
			conf = 95
		}
		learning := cfg.LearningMode
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RulePageCachePois,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1068", "T1014"},
			Tactic:          "privilege-escalation",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: diskHash, Path: path},
			Signals:         sigs,
			Evidence: "page_cache_sha256=" + cacheHash +
				" on_disk_sha256=" + diskHash +
				" — SUID binary diverges in memory only (CVE-2026-31431 page-cache poisoning)",
			LearningOnly: learning,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events, nil
}

// parseHexInt accepts either a hex string ("26", "5", "80005") or a
// 0x-prefixed form, mirroring how auditd records syscall arguments.
// Decimal-looking values (e.g. "5") are still parsed as hex to match
// audit conventions.
func parseHexInt(s string) (int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// syscallSucceeded reports whether the audit record indicates a
// successful socket(). Audit will record both successful and failing
// calls; alerting on EACCES failures from sandboxed callers would just
// add noise.
func syscallSucceeded(extra map[string]string) bool {
	if extra == nil {
		return true
	}
	if v, ok := extra["success"]; ok {
		return strings.EqualFold(v, "yes")
	}
	if v, ok := extra["exit"]; ok {
		// Audit exit codes are signed; a negative value means the call
		// returned an errno. Anything non-negative is a valid fd.
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n >= 0
		}
	}
	return true
}
