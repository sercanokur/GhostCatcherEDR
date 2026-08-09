package privesc

import (
	"testing"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

func testPack() *rules.Pack {
	return &rules.Pack{
		Version: "test",
		Rules: []rules.Rule{
			{
				ID:          RuleSuddenRoot,
				Techniques:  []string{"T1068"},
				Tactic:      "privilege-escalation",
				MinSignals:  1,
				BaseScore:   80,
				PerSignal:   3,
				CapScore:    100,
			},
		},
	}
}

func TestTracker_FirstObserveNoAlert(t *testing.T) {
	tr := NewTracker(64)
	key := ProcessKey{PID: 42, StartTime: 100}
	got := tr.Observe(key, CredState{UID: 1000, EUID: 1000, Comm: "bash", SeenAt: time.Now().UTC()})
	if got != nil {
		t.Fatalf("first observe must not alert: %+v", got)
	}
}

func TestTracker_EUIDTransition(t *testing.T) {
	tr := NewTracker(64)
	key := ProcessKey{PID: 42, StartTime: 100}
	now := time.Now().UTC()
	_ = tr.Observe(key, CredState{UID: 1000, EUID: 1000, Comm: "evil", Exe: "/tmp/evil", SeenAt: now})
	got := tr.Observe(key, CredState{UID: 1000, EUID: 0, Comm: "evil", Exe: "/tmp/evil", CapEff: "000001ffffffffff", SeenAt: now.Add(time.Second)})
	if got == nil {
		t.Fatal("expected euid_root transition")
	}
	if got.Kind != "euid_root" {
		t.Fatalf("kind=%q", got.Kind)
	}
	// Second transition must not re-alert.
	if again := tr.Observe(key, CredState{UID: 0, EUID: 0, Comm: "evil", Exe: "/tmp/evil", SeenAt: now.Add(2 * time.Second)}); again != nil {
		t.Fatal("must not re-alert same instance")
	}
}

func TestTracker_PIDReuseDifferentStartTime(t *testing.T) {
	tr := NewTracker(64)
	now := time.Now().UTC()
	_ = tr.Observe(ProcessKey{PID: 7, StartTime: 1}, CredState{UID: 1000, EUID: 1000, SeenAt: now})
	// New process reuses PID 7 with different starttime; starts already root.
	got := tr.Observe(ProcessKey{PID: 7, StartTime: 2}, CredState{UID: 0, EUID: 0, SeenAt: now})
	if got != nil {
		t.Fatal("new instance born as root must not look like a transition")
	}
}

func TestTracker_CapEffJump(t *testing.T) {
	tr := NewTracker(64)
	key := ProcessKey{PID: 9, StartTime: 1}
	now := time.Now().UTC()
	_ = tr.Observe(key, CredState{UID: 1000, EUID: 1000, CapEff: "0000000000000000", SeenAt: now})
	got := tr.Observe(key, CredState{UID: 1000, EUID: 1000, CapEff: "000001ffffffffff", SeenAt: now.Add(time.Second)})
	if got == nil || got.Kind != "capeff_full" {
		t.Fatalf("expected capeff_full, got %+v", got)
	}
}

func TestBuildEvent_AllowsSudo(t *testing.T) {
	cfg := config.Default()
	cfg.SuddenRoot.Enabled = true
	tr := &Transition{
		Key:  ProcessKey{PID: 10, StartTime: 1},
		Kind: "euid_root",
		Prev: CredState{UID: 1000, EUID: 1000, Comm: "sudo", Exe: "/usr/bin/sudo"},
		Curr: CredState{UID: 1000, EUID: 0, Comm: "sudo", Exe: "/usr/bin/sudo"},
		SeenAt: time.Now().UTC(),
	}
	if _, hit := buildEvent(cfg, testPack(), "test", tr); hit {
		t.Fatal("sudo exe transition must be allowlisted")
	}
}

func TestBuildEvent_FlagsTempExe(t *testing.T) {
	cfg := config.Default()
	cfg.SuddenRoot.Enabled = true
	tr := &Transition{
		Key:  ProcessKey{PID: 11, StartTime: 1},
		Kind: "euid_root",
		Prev: CredState{UID: 1000, EUID: 1000, Comm: "pwn", Exe: "/tmp/pwn"},
		Curr: CredState{UID: 1000, EUID: 0, Comm: "pwn", Exe: "/tmp/pwn", CapEff: "000001ffffffffff", Container: "docker"},
		SeenAt: time.Now().UTC(),
	}
	ev, hit := buildEvent(cfg, testPack(), "test", tr)
	if !hit {
		t.Fatal("expected detection")
	}
	if ev.RuleID != RuleSuddenRoot {
		t.Fatalf("rule=%q", ev.RuleID)
	}
	if ev.Confidence < 90 {
		t.Fatalf("confidence=%d want >=90 for temp+container", ev.Confidence)
	}
	found := false
	for _, s := range ev.Signals {
		if s == "exe_temp_path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("signals missing exe_temp_path: %v", ev.Signals)
	}
}

func TestRouteSensorEvent_IgnoresNonExec(t *testing.T) {
	cfg := config.Default()
	cfg.SuddenRoot.Enabled = true
	tracker := NewTracker(16)
	_, hit := RouteSensorEvent(cfg, testPack(), "test", tracker, sensor.Event{Kind: sensor.KindPtrace, PID: 1})
	if hit {
		t.Fatal("non-exec must be ignored")
	}
}

func TestRetainOnly(t *testing.T) {
	tr := NewTracker(16)
	now := time.Now().UTC()
	k1 := ProcessKey{PID: 1, StartTime: 1}
	k2 := ProcessKey{PID: 2, StartTime: 2}
	_ = tr.Observe(k1, CredState{UID: 1, EUID: 1, SeenAt: now})
	_ = tr.Observe(k2, CredState{UID: 1, EUID: 1, SeenAt: now})
	tr.RetainOnly(map[ProcessKey]struct{}{k1: {}})
	if tr.Len() != 1 {
		t.Fatalf("len=%d want 1", tr.Len())
	}
}
