package yara

import (
	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
	"time"
)

const (
	RuleYARADisk    = "YARA_DISK_MATCH"
	RuleYARAProcess = "YARA_PROCESS_MATCH"
)

// Scan runs the compiled scanner across configured document roots and
// every target process. It returns an event per match. The scanner is
// tolerant of a nil *Scanner (e.g. stub build with no rules): it simply
// returns an empty slice.
func Scan(scanner *Scanner, cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if scanner == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var events []event.Event
	// Disk scans: walk document roots.
	for _, root := range cfg.DocumentRoots {
		matches, err := scanTree(scanner, root)
		if err != nil {
			continue
		}
		for _, m := range matches {
			events = append(events, makeFileEvent(m, pack, agentVer, now, cfg.LearningMode))
		}
	}
	// Process scans: bounded to configured target comms to keep CPU cost low.
	if pids, err := procfs.Processes(); err == nil {
		want := map[string]struct{}{}
		for _, n := range cfg.TargetProcessNames {
			want[n] = struct{}{}
		}
		for _, n := range cfg.MapsWatchProcesses {
			want[n] = struct{}{}
		}
		for _, pid := range pids {
			comm, err := procfs.Comm(pid)
			if err != nil {
				continue
			}
			if _, ok := want[comm]; !ok {
				continue
			}
			ms, err := scanner.ScanProcess(pid)
			if err != nil {
				continue
			}
			for _, m := range ms {
				events = append(events, makeProcEvent(m, pack, agentVer, now, cfg.LearningMode))
			}
		}
	}
	return events, nil
}
