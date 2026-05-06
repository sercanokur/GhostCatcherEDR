package yara

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

func scanTree(scanner *Scanner, root string) ([]Match, error) {
	var out []Match
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return nil
		}
		ms, err := scanner.ScanFile(p)
		if err != nil {
			return nil
		}
		out = append(out, ms...)
		return nil
	})
	return out, err
}

func makeFileEvent(m Match, pack *rules.Pack, agentVer string, now time.Time, learning bool) event.Event {
	sigs := []string{"yara_rule:" + m.RuleID}
	for _, t := range m.Tags {
		sigs = append(sigs, "yara_tag:"+t)
	}
	conf, _ := rules.Score(pack, RuleYARADisk, sigs)
	if conf == 0 {
		conf = 80
	}
	return event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          RuleYARADisk,
		RulePackVersion: pack.Version,
		Tactic:          "discovery",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity:          event.Entity{Type: event.EntityFile, Path: m.Path, ID: strings.ToLower(m.RuleID)},
		Signals:         sigs,
		Evidence:        fmt.Sprintf("yara rule=%s tags=%v path=%s", m.RuleID, m.Tags, m.Path),
		LearningOnly:    learning,
	}
}

func makeProcEvent(m Match, pack *rules.Pack, agentVer string, now time.Time, learning bool) event.Event {
	sigs := []string{"yara_rule:" + m.RuleID, "memory_match"}
	for _, t := range m.Tags {
		sigs = append(sigs, "yara_tag:"+t)
	}
	conf, _ := rules.Score(pack, RuleYARAProcess, sigs)
	if conf == 0 {
		conf = 85
	}
	return event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          RuleYARAProcess,
		RulePackVersion: pack.Version,
		Tactic:          "defense-evasion",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity:          event.Entity{Type: event.EntityProcess, ID: fmt.Sprintf("%d", m.Pid)},
		Signals:         sigs,
		Evidence:        fmt.Sprintf("yara rule=%s pid=%d tags=%v", m.RuleID, m.Pid, m.Tags),
		LearningOnly:    learning,
	}
}
