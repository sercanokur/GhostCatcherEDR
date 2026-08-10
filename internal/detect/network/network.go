// Package network provides a best-effort /proc/net-based sensor that
// correlates listening/connecting sockets to the process that owns them and
// emits reverse-shell / unexpected-listener style events.
package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

// knownListens tracks listen sockets seen on prior scans so NETWORK_LISTEN_NEW
// is a real delta (including 0.0.0.0 / :: binds) rather than every scan.
var (
	listenMu     sync.Mutex
	knownListens = map[string]struct{}{}
	listenPrimed bool
)

func listenKey(row procfs.SocketRow) string {
	ip := ""
	if row.Local != nil {
		ip = row.Local.String()
	}
	return row.Proto + "|" + ip + "|" + strconv.Itoa(row.LocalP)
}

const (
	RuleSocketStdio     = "PROC_SOCKET_STDIO"
	RuleListenNew       = "NETWORK_LISTEN_NEW"
	RuleWebWorkerEgress = "NETWORK_WEB_WORKER_EGRESS"
	RuleIMDSAccess      = "NETWORK_IMDS_ACCESS"
	RuleRawIPNoDNS      = "NETWORK_RAW_IP_NO_DNS"
	RuleBeaconPeriodic  = "NETWORK_BEACON_PERIODIC"
)

// suspiciousShellComms are interactive shells / scripting engines that, when
// observed in an ESTABLISHED outbound connection to a public IP, are almost
// always a reverse shell. These are the canonical "spawn shell to attacker"
// primitives.
var suspiciousShellComms = map[string]struct{}{
	"bash": {}, "sh": {}, "zsh": {}, "ksh": {}, "dash": {},
	"python": {}, "python2": {}, "python3": {},
	"perl": {}, "ruby": {},
	"nc": {}, "ncat": {}, "netcat": {}, "socat": {},
}

// Scan pulls every socket from /proc/net/{tcp,tcp6,udp,udp6}, matches the
// socket inodes back to the owning pid via /proc/*/fd, and classifies each
// connection. All three rule classes share the same event schema.
func Scan(cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.NetworkScanEnabled {
		return nil, nil
	}
	rows, err := procfs.ReadNetSockets()
	if err != nil {
		return nil, nil // non-linux host - silent no-op
	}
	pids, err := procfs.Processes()
	if err != nil {
		return nil, nil
	}
	// inode -> pid map
	owners := map[uint64]int{}
	for _, pid := range pids {
		inodes, err := procfs.SocketInodes(pid)
		if err != nil {
			continue
		}
		for in := range inodes {
			if _, dup := owners[in]; !dup {
				owners[in] = pid
			}
		}
	}

	allowNets, err := parseCIDRs(cfg.NetworkAllowlist)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}

	webWorkerPIDs := map[int]string{}
	for _, wpName := range cfg.TargetProcessNames {
		wpName = strings.ToLower(strings.TrimSpace(wpName))
		for _, pid := range pids {
			c, err := procfs.Comm(pid)
			if err != nil {
				continue
			}
			if strings.ToLower(c) == wpName {
				webWorkerPIDs[pid] = c
			}
		}
	}

	now := time.Now().UTC()
	var events []event.Event
	currentListens := map[string]struct{}{}
	type listenCand struct {
		row  procfs.SocketRow
		pid  int
		comm string
		sigs []string
	}
	var listenNew []listenCand

	for _, row := range rows {
		// Listen-delta: non-loopback listeners, including 0.0.0.0 / ::.
		if (row.Proto == "tcp" || row.Proto == "tcp6") && row.State == procfs.TCPListen {
			if row.Local != nil && !row.Local.IsLoopback() {
				key := listenKey(row)
				currentListens[key] = struct{}{}
				pid, comm := ownerInfo(row.Inode, owners)
				sigs := []string{"new_listening_socket"}
				if row.Local.IsUnspecified() {
					sigs = append(sigs, "bind_all_interfaces")
				}
				if pid != 0 {
					sigs = append(sigs, "comm:"+comm)
				}
				listenNew = append(listenNew, listenCand{row: row, pid: pid, comm: comm, sigs: sigs})
			}
			continue
		}

		// Established or SynSent: evaluate outbound.
		if row.State != procfs.TCPEstablished && row.State != procfs.TCPSynSent {
			continue
		}
		if row.Remote == nil || row.Remote.IsUnspecified() {
			continue
		}
		// Allowlisted RFC1918 / link-local: skip.
		if ipInAny(row.Remote, allowNets) {
			continue
		}
		pid, comm := ownerInfo(row.Inode, owners)
		if pid == 0 {
			continue
		}
		comm = strings.ToLower(comm)

		// Reverse shell: shell-ish process talking outbound.
		if _, ok := suspiciousShellComms[comm]; ok {
			sigs := []string{"shell_outbound_connection", "comm:" + comm, "remote:" + row.Remote.String() + ":" + strconv.Itoa(row.RemoteP)}
			events = append(events, buildEvent(RuleSocketStdio, pid, comm, row, sigs,
				[]string{"T1059.004", "T1571"}, now, cfg, pack, agentVer, false))
			continue
		}
		// Web worker egress: httpd/nginx/apache2 opening outbound connections.
		if _, ok := webWorkerPIDs[pid]; ok {
			remoteStr := row.Remote.String()
			if remoteStr == "169.254.169.254" || remoteStr == "fd00:ec2::254" {
				sigs := []string{"network_imds_access", "comm:" + comm, "remote:" + remoteStr}
				events = append(events, buildEvent(RuleIMDSAccess, pid, comm, row, sigs,
					[]string{"T1552.005"}, now, cfg, pack, agentVer, false))
				continue
			}
			sigs := []string{"web_worker_egress", "comm:" + comm, "remote:" + remoteStr + ":" + strconv.Itoa(row.RemoteP)}
			events = append(events, buildEvent(RuleWebWorkerEgress, pid, comm, row, sigs,
				[]string{"T1041", "T1071.001"}, now, cfg, pack, agentVer, false))
		}
	}

	listenMu.Lock()
	if !listenPrimed {
		// First scan after process start: seed baseline, do not alert.
		knownListens = currentListens
		listenPrimed = true
	} else {
		for _, cand := range listenNew {
			key := listenKey(cand.row)
			if _, seen := knownListens[key]; seen {
				continue
			}
			knownListens[key] = struct{}{}
			events = append(events, buildEvent(RuleListenNew, cand.pid, cand.comm, cand.row, cand.sigs,
				[]string{"T1571"}, now, cfg, pack, agentVer, true))
		}
		// Drop keys that disappeared so a re-bind can alert again later.
		for k := range knownListens {
			if _, ok := currentListens[k]; !ok {
				delete(knownListens, k)
			}
		}
	}
	listenMu.Unlock()

	return events, nil
}

func ownerInfo(inode uint64, owners map[uint64]int) (int, string) {
	pid, ok := owners[inode]
	if !ok {
		return 0, ""
	}
	comm, _ := procfs.Comm(pid)
	return pid, comm
}

func parseCIDRs(s []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(s))
	for _, c := range s {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("bad cidr %q: %w", c, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func buildEvent(rule string, pid int, comm string, row procfs.SocketRow, sigs, tech []string, now time.Time, cfg *config.Config, pack *rules.Pack, agentVer string, learning bool) event.Event {
	conf, _ := rules.Score(pack, rule, sigs)
	if conf < 60 {
		conf = 60
	}
	ev := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          rule,
		RulePackVersion: pack.Version,
		TechniqueIDs:    tech,
		Tactic:          "command-and-control",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity: event.Entity{
			Type: event.EntityProcess,
			ID:   strconv.Itoa(pid),
			Path: procfs.ResolveExe(pid),
		},
		Signals: sigs,
		Evidence: fmt.Sprintf("pid=%d comm=%s proto=%s local=%s:%d remote=%s:%d",
			pid, comm, row.Proto, row.Local, row.LocalP, row.Remote, row.RemoteP),
		LearningOnly: learning || conf < cfg.MinConfidenceAlert,
	}
	ev.NormalizeDedup()
	return ev
}
