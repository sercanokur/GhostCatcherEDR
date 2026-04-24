package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ScanInterval        Duration `yaml:"scan_interval"`
	DocumentRoots       []string `yaml:"document_roots"`
	BaselinePath        string   `yaml:"baseline_path"`
	RulePackPath        string   `yaml:"rule_pack_path"`
	StateDir            string   `yaml:"state_dir"`
	MinConfidenceAlert  int      `yaml:"min_confidence_for_alert"`
	LearningMode        bool     `yaml:"learning_mode"`
	RequireRoot         bool     `yaml:"require_root"`
	WebRecentDays       int      `yaml:"web_recent_change_days"`
	PathAllowlist       []string `yaml:"path_allowlist_prefixes"`
	LDPreloadAllowlist  []string `yaml:"ld_preload_allowlist"`
	TargetProcessNames  []string `yaml:"ld_preload_target_processes"`
	FirstRunAllowAlerts bool     `yaml:"first_run_allow_alerts"`

	// Memory / fileless-style signals (see /proc/pid/maps rwx).
	MapsScanEnabled    bool     `yaml:"maps_scan_enabled"`
	MapsWatchProcesses []string `yaml:"maps_watch_processes"`
	MapsPathAllowlist  []string `yaml:"maps_path_allowlist_prefixes"`

	// Tripwire-style verification vs dpkg md5sums (Debian/Ubuntu).
	IntegrityVerifyEnabled bool     `yaml:"integrity_verify_enabled"`
	IntegrityPaths         []string `yaml:"integrity_paths"`

	// Web worker children running typical post-exploit recon argv (auditd-like signal without auditd).
	WebReconChildScanEnabled bool `yaml:"web_recon_child_scan_enabled"`

	// Real-time authorized_keys change detection (fsnotify / inotify).
	WatchAuthorizedKeys bool     `yaml:"watch_authorized_keys"`
	WatchDebounce       Duration `yaml:"watch_debounce"`

	// Syslog UDP (SIEM ingestion, e.g. UDP 514 / custom port).
	SyslogUDP SyslogUDPConfig `yaml:"syslog_udp"`
}

// SyslogUDPConfig configures RFC5424 or RFC3164 syslog over UDP.
type SyslogUDPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Format      string `yaml:"format"`   // rfc5424 (default) or rfc3164
	Facility    string `yaml:"facility"` // e.g. local0, or 0-23
	AppName     string `yaml:"app_name"`
	Hostname    string `yaml:"hostname"` // sender name in syslog header; empty = OS hostname
	ProcID      string `yaml:"proc_id"`  // RFC5424 PROCID; empty = agent PID
	MaxMsgBytes int    `yaml:"max_msg_bytes"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	pd, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(pd)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func Default() *Config {
	return &Config{
		ScanInterval:           Duration(5 * time.Minute),
		BaselinePath:           "/var/lib/ghostcatcher/baseline.json",
		RulePackPath:           "/etc/ghostcatcher/rule_pack.yaml",
		StateDir:               "/var/lib/ghostcatcher",
		MinConfidenceAlert:     70,
		WebRecentDays:          14,
		PathAllowlist:          []string{"/usr/share/nginx/html/", "/var/www/html/vendor/"},
		LDPreloadAllowlist:     []string{},
		TargetProcessNames:     []string{"nginx", "apache2", "httpd", "sshd", "cron", "CRON"},
		FirstRunAllowAlerts:    false,
		MapsScanEnabled:        false,
		MapsWatchProcesses:     []string{"nginx", "apache2", "httpd"},
		MapsPathAllowlist:      []string{},
		IntegrityVerifyEnabled: false,
		IntegrityPaths: []string{
			"/bin/ls", "/bin/ps", "/usr/bin/ls", "/usr/bin/ps", "/usr/bin/netstat", "/usr/bin/ss",
		},
		WebReconChildScanEnabled: true,
		WatchAuthorizedKeys:      false,
		WatchDebounce:            Duration(800 * time.Millisecond),
	}
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.BaselinePath == "" {
		return nil, fmt.Errorf("baseline_path required")
	}
	if c.RulePackPath == "" {
		return nil, fmt.Errorf("rule_pack_path required")
	}
	if c.WebRecentDays <= 0 {
		c.WebRecentDays = 14
	}
	return c, nil
}

func (c *Config) Validate() error {
	if !c.SyslogUDP.Enabled {
		return nil
	}
	if c.SyslogUDP.Host == "" {
		return fmt.Errorf("syslog_udp.host required when syslog_udp.enabled")
	}
	if c.SyslogUDP.Port <= 0 || c.SyslogUDP.Port > 65535 {
		return fmt.Errorf("syslog_udp.port must be 1-65535")
	}
	f := c.SyslogUDP.Format
	if f == "" {
		f = "rfc5424"
	}
	if f != "rfc5424" && f != "rfc3164" {
		return fmt.Errorf("syslog_udp.format must be rfc5424 or rfc3164")
	}
	return nil
}
