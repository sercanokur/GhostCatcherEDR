package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type esHit struct {
	Source map[string]any `json:"_source"`
}

type esSearchResp struct {
	Hits struct {
		Total any     `json:"total"`
		Hits  []esHit `json:"hits"`
	} `json:"hits"`
}

type Evidence struct {
	Detected   bool     `json:"detected"`
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Timestamp  string   `json:"timestamp,omitempty"`
	Summary    string   `json:"summary"`
	Bullets    []string `json:"bullets"`
	RawPath    string   `json:"entity_path,omitempty"`
}

func parseESLatest(ruleID, rawJSON string) Evidence {
	ev := Evidence{
		RuleID:  ruleID,
		Title:   humanRuleTitle(ruleID),
		Summary: "No matching alert in Elasticsearch yet.",
		Bullets: nil,
	}
	var resp esSearchResp
	if err := json.Unmarshal([]byte(rawJSON), &resp); err != nil || len(resp.Hits.Hits) == 0 {
		return ev
	}
	src := resp.Hits.Hits[0].Source
	ev.Detected = true
	ev.Severity = str(src["severity"])
	ev.Confidence = intNum(src["confidence"])
	ev.Timestamp = str(src["timestamp"])
	ev.Summary = humanSummary(ruleID, src)
	ev.Bullets = humanBullets(ruleID, src)
	if ent, ok := src["entity"].(map[string]any); ok {
		ev.RawPath = str(ent["path"])
	}
	return ev
}

func humanRuleTitle(ruleID string) string {
	titles := map[string]string{
		"WEB_SHELL_PATTERN":           "Webshell on disk",
		"WEB_WORKER_RECON_CHILD":      "Web worker recon child",
		"PROC_SUDDEN_ROOT":            "Sudden root / privilege escalation",
		"LD_SO_PRELOAD_FILE":          "ld.so.preload persistence",
		"PROC_LD_PRELOAD_ENV":         "LD_PRELOAD in process env",
		"SSH_AUTHKEY_NEW":             "New SSH authorized key",
		"SSH_AUTHKEY_INVALID_LINE":    "Invalid SSH authorized_keys line",
		"PROC_SOCKET_STDIO":           "Reverse shell / C2",
		"CRON_HIGH_RISK":              "High-risk cron job",
		"SUDOERS_PERSISTENCE":         "Sudoers persistence",
		"SYSTEMD_PERSISTENCE":         "Systemd persistence",
		"PAM_PERSISTENCE":             "PAM persistence",
		"PROFILE_HOOK":                "Shell profile / RC hook",
		"KERNEL_MODLOAD_PATH_CHANGED": "Kernel module load path changed",
		"LD_SO_CONF_CHANGED":          "ld.so.conf changed",
		"SSHD_CONFIG_ANOMALY":         "sshd config anomaly",
		"USER_ACCOUNT_ANOMALY":        "User account anomaly",
		"SUID_INVENTORY_DELTA":        "SUID inventory delta",
		"FILE_CAPABILITY_DELTA":       "File capability delta",
		"LIB_HASH_MISMATCH":           "Binary / library hash mismatch",
		"NETWORK_LISTEN_NEW":          "Unexpected network listener",
		"NETWORK_WEB_WORKER_EGRESS":   "Web worker egress",
	}
	if t, ok := titles[ruleID]; ok {
		return t
	}
	return ruleID
}

func humanSummary(ruleID string, src map[string]any) string {
	evd := str(src["evidence"])
	path := ""
	if ent, ok := src["entity"].(map[string]any); ok {
		path = str(ent["path"])
	}
	switch ruleID {
	case "WEB_SHELL_PATTERN":
		return fmt.Sprintf("GhostCatcher flagged a PHP webshell at %s.", path)
	case "PROC_SUDDEN_ROOT":
		return fmt.Sprintf("Unprivileged process escalated to root: %s", firstLine(evd))
	case "LD_SO_PRELOAD_FILE":
		return fmt.Sprintf("Global library preload set: %s", firstLine(evd))
	case "SSH_AUTHKEY_NEW":
		user := ""
		if ent, ok := src["entity"].(map[string]any); ok {
			user = str(ent["user"])
		}
		return fmt.Sprintf("New SSH key added for user %s.", user)
	case "PROC_SOCKET_STDIO":
		return fmt.Sprintf("Shell process opened outbound C2-like connection: %s", firstLine(evd))
	default:
		return firstLine(evd)
	}
}

func humanBullets(ruleID string, src map[string]any) []string {
	var out []string
	if t := str(src["timestamp"]); t != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			out = append(out, "When: "+parsed.UTC().Format("2006-01-02 15:04:05 UTC"))
		} else {
			out = append(out, "When: "+t)
		}
	}
	out = append(out, fmt.Sprintf("Severity: %s · confidence %d", str(src["severity"]), intNum(src["confidence"])))
	if tech := stringSlice(src["technique_id"]); len(tech) > 0 {
		out = append(out, "MITRE: "+strings.Join(tech, ", "))
	}
	if ent, ok := src["entity"].(map[string]any); ok {
		if p := str(ent["path"]); p != "" {
			out = append(out, "Path: "+p)
		}
		if u := str(ent["user"]); u != "" {
			out = append(out, "User: "+u)
		}
	}
	if proc, ok := src["process"].(map[string]any); ok {
		if exe := str(proc["exe"]); exe != "" {
			out = append(out, "Process: "+exe)
		}
		if pid := intNum(proc["pid"]); pid > 0 {
			out = append(out, fmt.Sprintf("PID: %d", pid))
		}
	}
	if sigs := stringSlice(src["signals"]); len(sigs) > 0 {
		out = append(out, "Signals: "+strings.Join(sigs, ", "))
	}
	if evd := str(src["evidence"]); evd != "" {
		out = append(out, "Evidence: "+trim(evd, 220))
	}
	_ = ruleID
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
}

func intNum(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	default:
		return 0
	}
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return trim(s, 180)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
