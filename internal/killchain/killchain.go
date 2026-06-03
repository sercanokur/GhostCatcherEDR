// Package killchain maps MITRE ATT&CK tactics to Lockheed Martin kill-chain
// phases for response prioritization and SIEM context.
package killchain

import "strings"

// Lockheed Martin kill-chain phases used in event.kill_chain_phase.
const (
	PhaseReconnaissance       = "reconnaissance"
	PhaseWeaponization        = "weaponization"
	PhaseDelivery             = "delivery"
	PhaseExploitation         = "exploitation"
	PhaseInstallation         = "installation"
	PhaseCommandAndControl    = "c2"
	PhaseActionsOnObjectives  = "actions-on-objectives"
)

// PhaseFor returns the kill-chain phase for a MITRE tactic. ruleOverride, when
// non-empty, wins over the tactic map (per-rule kill_chain_phase in the pack).
func PhaseFor(tactic, ruleOverride string) string {
	if o := strings.TrimSpace(ruleOverride); o != "" {
		return normalize(o)
	}
	return tacticToPhase(strings.ToLower(strings.TrimSpace(tactic)))
}

func normalize(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "recon", "reconnaissance":
		return PhaseReconnaissance
	case "weaponization":
		return PhaseWeaponization
	case "delivery":
		return PhaseDelivery
	case "exploit", "exploitation":
		return PhaseExploitation
	case "install", "installation":
		return PhaseInstallation
	case "c2", "c&c", "command-and-control", "command_and_control":
		return PhaseCommandAndControl
	case "actions", "actions-on-objectives", "actions_on_objectives", "ao":
		return PhaseActionsOnObjectives
	default:
		return s
	}
}

func tacticToPhase(tactic string) string {
	switch tactic {
	case "reconnaissance", "resource-development", "resource_development":
		return PhaseReconnaissance
	case "initial-access", "initial_access":
		return PhaseDelivery
	case "execution":
		return PhaseExploitation
	case "persistence", "privilege-escalation", "privilege_escalation",
		"defense-evasion", "defense_evasion":
		return PhaseInstallation
	case "command-and-control", "command_and_control":
		return PhaseCommandAndControl
	case "credential-access", "credential_access", "discovery",
		"lateral-movement", "lateral_movement", "collection",
		"exfiltration", "impact":
		return PhaseActionsOnObjectives
	default:
		return ""
	}
}

// EarlyPhase returns true when the phase is early enough to prefer stronger
// response actions (exploitation / installation).
func EarlyPhase(phase string) bool {
	switch phase {
	case PhaseExploitation, PhaseInstallation:
		return true
	default:
		return false
	}
}
