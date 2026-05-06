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

	// Broader fsnotify coverage: systemd units, sudoers, pam, sshd_config,
	// cron*, passwd/shadow, ld.so.preload, document_roots (recursive).
	WatchSensitivePaths bool `yaml:"watch_sensitive_paths"`

	// /proc/net/tcp[6] + /proc/*/fd correlation (network sensor).
	NetworkScanEnabled bool     `yaml:"network_scan_enabled"`
	NetworkAllowlist   []string `yaml:"network_ip_cidr_allowlist"`

	// IOC feed files loaded at boot (one line per indicator).
	IOCFeedHashFiles   []string `yaml:"ioc_hash_files"`
	IOCFeedIPFiles     []string `yaml:"ioc_ip_files"`
	IOCFeedDomainFiles []string `yaml:"ioc_domain_files"`

	// Per-rule emit rate limit in events/minute; 0 disables.
	RateLimitPerRulePerMin int    `yaml:"rate_limit_per_rule_per_min"`
	SpoolDir               string `yaml:"spool_dir"`
	SpoolMaxBytes          int64  `yaml:"spool_max_bytes"`

	// Rule pack signing (ed25519). RulePackPubKey is the base64 ed25519
	// public key file; RulePackSigPath points to the detached signature. If
	// both are set, LoadPack fails closed when verification fails.
	RulePackPubKey  string `yaml:"rule_pack_pubkey_file"`
	RulePackSigPath string `yaml:"rule_pack_signature_file"`

	// Additional Sigma-lite rule drop-ins to merge with the primary pack.
	SigmaLiteDir string `yaml:"sigma_lite_dir"`

	// Process ancestry scanner (PROC_RARE_ANCESTRY).
	AncestryScanEnabled bool `yaml:"ancestry_scan_enabled"`

	// YARA rule directory (only active when built with -tags with_yara).
	YARARulesDir      string `yaml:"yara_rules_dir"`
	YARAMemoryEnabled bool   `yaml:"yara_memory_enabled"`

	// Quarantine: copy high-confidence artifacts (web shells, memfd files)
	// to a tamper-resistant evidence vault. Leave QuarantineDir empty to
	// disable. MinConfidence gates which events trigger a copy.
	QuarantineDir           string `yaml:"quarantine_dir"`
	QuarantineMinConfidence int    `yaml:"quarantine_min_confidence"`

	// Baseline commit 2FA: if set, `ghostcatcher baseline commit` reads
	// the expected TOTP (or static token) from this env var and refuses
	// to overwrite the baseline unless the operator supplies a matching
	// --token flag. Empty disables 2FA.
	BaselineCommitTokenEnv string `yaml:"baseline_commit_token_env"`

	// Syslog UDP (SIEM ingestion, e.g. UDP 514 / custom port).
	SyslogUDP SyslogUDPConfig `yaml:"syslog_udp"`
	// Additional enterprise sinks (TCP/TLS syslog, Splunk HEC, Elastic bulk, Loki).
	SyslogTCP   SyslogTCPConfig   `yaml:"syslog_tcp"`
	SplunkHEC   SplunkHECConfig   `yaml:"splunk_hec"`
	ElasticBulk ElasticBulkConfig `yaml:"elastic_bulk"`
	LokiPush    LokiPushConfig    `yaml:"loki_push"`

	// Self-protection.
	SelfGuard SelfGuardConfig `yaml:"self_guard"`

	// CVE-2026-31431 ("Copy Fail") — algif_aead AEAD page-cache poisoning
	// detector. See internal/detect/copyfail.
	CopyFail CopyFailConfig `yaml:"copy_fail"`
}

// CopyFailConfig tunes the CVE-2026-31431 detector. Defaults err on the
// side of detection: the live AF_ALG socket() leg is enabled whenever
// the auditd / eBPF sensor produces socket events, and the periodic
// page-cache vs on-disk drift leg runs against a sane default
// SUID-binary watchlist.
type CopyFailConfig struct {
	Enabled               bool     `yaml:"enabled"`
	PageCacheCheckEnabled bool     `yaml:"page_cache_check_enabled"`
	AllowedCommExtras     []string `yaml:"allowed_comm_extras"`
	TargetSUIDBinaries    []string `yaml:"target_suid_binaries"`
}

// SyslogTCPConfig - RFC5424-framed syslog over TCP, optionally TLS.
type SyslogTCPConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	TLS           bool   `yaml:"tls"`
	TLSCACertFile string `yaml:"tls_ca_cert_file"`
	TLSServerName string `yaml:"tls_server_name"`
	Format        string `yaml:"format"`
	Facility      string `yaml:"facility"`
	AppName       string `yaml:"app_name"`
	Hostname      string `yaml:"hostname"`
	ProcID        string `yaml:"proc_id"`
	MaxMsgBytes   int    `yaml:"max_msg_bytes"`
}

// SplunkHECConfig - POST to Splunk HTTP Event Collector.
type SplunkHECConfig struct {
	Enabled    bool   `yaml:"enabled"`
	URL        string `yaml:"url"`
	Token      string `yaml:"token"`
	Index      string `yaml:"index"`
	SourceType string `yaml:"sourcetype"`
	Insecure   bool   `yaml:"insecure_tls"`
}

// ElasticBulkConfig - POST newline-delimited JSON to the _bulk endpoint.
type ElasticBulkConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Index    string `yaml:"index"`
	APIKey   string `yaml:"api_key"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Insecure bool   `yaml:"insecure_tls"`
}

// LokiPushConfig - Grafana Loki /loki/api/v1/push.
type LokiPushConfig struct {
	Enabled  bool              `yaml:"enabled"`
	URL      string            `yaml:"url"`
	Labels   map[string]string `yaml:"labels"`
	Username string            `yaml:"username"`
	Password string            `yaml:"password"`
	Insecure bool              `yaml:"insecure_tls"`
}

// SelfGuardConfig - agent self-protection.
type SelfGuardConfig struct {
	Enabled              bool   `yaml:"enabled"`
	BinaryPath           string `yaml:"binary_path"`
	ExpectedBinarySHA256 string `yaml:"expected_binary_sha256"`
	SystemdWatchdog      bool   `yaml:"systemd_watchdog"`
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
		WatchSensitivePaths:      true,
		NetworkScanEnabled:       true,
		NetworkAllowlist:         []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"},
		RateLimitPerRulePerMin:   120,
		SpoolDir:                 "/var/lib/ghostcatcher/spool",
		SpoolMaxBytes:            64 * 1024 * 1024,
		AncestryScanEnabled:      true,
		CopyFail: CopyFailConfig{
			Enabled:               true,
			PageCacheCheckEnabled: true,
		},
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
