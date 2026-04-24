package rules

import (
	"ghostcatcher/internal/event"
)

// Score applies pack rule to signal count and returns confidence 0-100.
func Score(p *Pack, ruleID string, signals []string) (confidence int, ok bool) {
	rule, found := p.ByID(ruleID)
	if !found {
		return 0, false
	}
	if len(signals) < rule.MinSignals {
		return rule.BaseScore, true
	}
	conf := rule.BaseScore + (len(signals)-rule.MinSignals+1)*rule.PerSignal
	if conf > rule.CapScore {
		conf = rule.CapScore
	}
	return conf, true
}

// SeverityFromConfidence maps numeric confidence to severity bucket.
func SeverityFromConfidence(c int, learning bool) event.Severity {
	if learning {
		return event.SeverityInfo
	}
	switch {
	case c >= 95:
		return event.SeverityCritical
	case c >= 85:
		return event.SeverityHigh
	case c >= 70:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}
