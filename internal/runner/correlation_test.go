package runner

import (
	"testing"
	"time"

	"ghostcatcher/internal/event"
	"ghostcatcher/internal/taxonomy"
)

func TestChainCorrelation(t *testing.T) {
	c := newCorrelator(64)
	c.setChains([]taxonomy.Chain{{
		ID:     "CHAIN-1",
		Window: "30m",
		Score:  "CRITICAL",
		Steps: [][]string{
			{"WEB_DOCROOT_EXEC_WRITE"},
			{"WEB_WORKER_SHELL_CHILD", "WEB_WORKER_INTERP_CHILD"},
			{"WEB_WORKER_DOWNLOADER_CHILD", "NETWORK_LISTEN_NEW"},
			{"CRON_HIGH_RISK", "SYSTEMD_PERSISTENCE", "SSH_AUTHKEY_NEW"},
		},
	}})
	now := time.Now()
	anchor := "nginx.service"
	c.addFull("WEB_DOCROOT_EXEC_WRITE", "1", anchor, "HIGH", now.Add(-2*time.Minute))
	c.addFull("WEB_WORKER_SHELL_CHILD", "2", anchor, "HIGH", now.Add(-1*time.Minute))
	c.addFull("NETWORK_LISTEN_NEW", "3", anchor, "HIGH", now.Add(-30*time.Second))

	e := &event.Event{
		RuleID:   "CRON_HIGH_RISK",
		Anchor:   anchor,
		ConfBand: "HIGH",
	}
	boost := c.matchChain(e, now)
	if boost <= 0 {
		t.Fatal("expected chain match")
	}
	if e.ChainID != "CHAIN-1" {
		t.Fatalf("chain=%q", e.ChainID)
	}
	if e.Severity != event.SeverityCritical {
		t.Fatalf("severity=%s", e.Severity)
	}
}
