// Package sensorlive routes high-fidelity live sensor events into scored
// detection events for the low-latency OODA fast path.
package sensorlive

import (
	"strconv"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

const (
	RulePtrace      = "SENSOR_PTRACE_ATTACH"
	RuleMemfdCreate = "SENSOR_MEMFD_CREATE"
	RuleInitModule  = "SENSOR_INIT_MODULE"
)

// FastKinds are sensor kinds handled inline (not via debounced RunOnce).
func FastKinds() map[sensor.Kind]struct{} {
	return map[sensor.Kind]struct{}{
		sensor.KindPtrace:      {},
		sensor.KindInitModule:  {},
		sensor.KindMemfdCreate: {},
		sensor.KindSocket:      {}, // copyfail handles socket separately
		sensor.KindExec:        {}, // privesc seeds credential tracker
	}
}

// RouteSensorEvent converts a live sensor event into a detection event when
// it matches a high-fidelity syscall pattern.
func RouteSensorEvent(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	var ruleID string
	var sigs []string
	var techniques []string
	var tactic string

	switch ev.Kind {
	case sensor.KindPtrace:
		ruleID = RulePtrace
		sigs = []string{"ptrace_attach", "comm:" + ev.Comm}
		techniques = []string{"T1055"}
		tactic = "defense-evasion"
	case sensor.KindMemfdCreate:
		ruleID = RuleMemfdCreate
		sigs = []string{"memfd_create", "comm:" + ev.Comm}
		techniques = []string{"T1055.001"}
		tactic = "execution"
	case sensor.KindInitModule:
		ruleID = RuleInitModule
		sigs = []string{"init_module", "comm:" + ev.Comm}
		techniques = []string{"T1547.006"}
		tactic = "persistence"
	default:
		return event.Event{}, false
	}

	conf, ok := rules.Score(pack, ruleID, sigs)
	if !ok {
		conf = 75
	}
	now := time.Now().UTC()
	if !ev.When.IsZero() {
		now = ev.When.UTC()
	}
	out := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          ruleID,
		RulePackVersion: pack.Version,
		TechniqueIDs:    techniques,
		Tactic:          tactic,
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, cfg.LearningMode),
		Entity: event.Entity{
			Type: event.EntityProcess,
			ID:   strconv.Itoa(ev.PID),
		},
		Signals:  sigs,
		Evidence: "live_sensor:" + string(ev.Kind),
		Process: &event.ProcessContext{
			PID:  ev.PID,
			PPID: ev.PPID,
			Comm: ev.Comm,
			Argv: append([]string(nil), ev.Argv...),
			UID:  int(ev.UID),
		},
	}
	if cfg.LearningMode {
		out.LearningOnly = true
	}
	return out, true
}
