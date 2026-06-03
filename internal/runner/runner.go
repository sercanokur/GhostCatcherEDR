package runner

import (
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"context"
	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/container"
	"ghostcatcher/internal/detect/ancestry"
	"ghostcatcher/internal/detect/copyfail"
	"ghostcatcher/internal/detect/integrity"
	"ghostcatcher/internal/detect/ldpreload"
	"ghostcatcher/internal/detect/memorymaps"
	"ghostcatcher/internal/detect/network"
	"ghostcatcher/internal/detect/persistence"
	"ghostcatcher/internal/detect/sensorlive"
	"ghostcatcher/internal/detect/web"
	"ghostcatcher/internal/detect/yara"
	"ghostcatcher/internal/killchain"
	"ghostcatcher/internal/respond"
	"ghostcatcher/internal/emit"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/export"
	"ghostcatcher/internal/export/elastic"
	"ghostcatcher/internal/export/loki"
	"ghostcatcher/internal/export/splunk"
	"ghostcatcher/internal/export/syslog"
	"ghostcatcher/internal/export/syslogtcp"
	"ghostcatcher/internal/ioc"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/quarantine"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/selfguard"
	"ghostcatcher/internal/sensor"
	"ghostcatcher/internal/watch"
)

const AgentVersion = "0.2.0"

// Runner orchestrates one full scan cycle: load baseline, fan out to each
// detector, enrich events (container/process/file/network/IOC), rate-limit,
// persist to spool, and emit to all configured sinks.
type Runner struct {
	cfg        *config.Config
	pack       *rules.Pack
	out        io.Writer
	syslog     *syslog.Client
	lastDedup  map[string]time.Time
	limiter    *emit.Limiter
	spool      *emit.Spool
	feed       *ioc.Feed
	correlator *correlator
	yaraScan   *yara.Scanner
	sinks      []export.Sink
	vault      *quarantine.Vault
	responder  *respond.Engine
}

func New(cfg *config.Config, pack *rules.Pack) *Runner {
	r := &Runner{
		cfg:        cfg,
		pack:       pack,
		out:        os.Stdout,
		lastDedup:  make(map[string]time.Time),
		limiter:    emit.NewLimiter(cfg.RateLimitPerRulePerMin),
		feed:       ioc.NewFeed(),
		correlator: newCorrelator(2048),
	}
	if cfg.SyslogUDP.Enabled {
		sc, err := syslog.NewUDP(syslog.Config{
			Enabled:     true,
			Host:        cfg.SyslogUDP.Host,
			Port:        cfg.SyslogUDP.Port,
			Format:      cfg.SyslogUDP.Format,
			Facility:    cfg.SyslogUDP.Facility,
			AppName:     cfg.SyslogUDP.AppName,
			Hostname:    cfg.SyslogUDP.Hostname,
			ProcID:      cfg.SyslogUDP.ProcID,
			MaxMsgBytes: cfg.SyslogUDP.MaxMsgBytes,
		})
		if err != nil {
			slog.Warn("syslog UDP disabled: init failed", "err", err)
		} else {
			r.syslog = sc
		}
	}
	if cfg.SpoolDir != "" {
		sp, err := emit.NewSpool(cfg.SpoolDir, cfg.SpoolMaxBytes)
		if err != nil {
			slog.Warn("spool disabled: init failed", "err", err)
		} else {
			r.spool = sp
		}
	}
	if err := r.feed.Load(cfg.IOCFeedHashFiles, cfg.IOCFeedIPFiles, cfg.IOCFeedDomainFiles); err != nil {
		slog.Warn("ioc feed load failed", "err", err)
	}
	if cfg.YARARulesDir != "" {
		sc, err := yara.New(cfg.YARARulesDir)
		if err != nil {
			slog.Warn("yara disabled", "err", err)
		} else {
			r.yaraScan = sc
			slog.Info("yara scanner ready", "rules_dir", cfg.YARARulesDir)
		}
	}
	h, ips, cidrs, doms := r.feed.Sizes()
	if h+ips+cidrs+doms > 0 {
		slog.Info("ioc feeds loaded", "hashes", h, "ips", ips, "cidrs", cidrs, "domains", doms)
	}
	r.initSinks()
	if cfg.QuarantineDir != "" {
		v, err := quarantine.New(cfg.QuarantineDir)
		if err != nil {
			slog.Warn("quarantine disabled", "err", err)
		} else {
			r.vault = v
		}
	}
	r.responder = respond.NewEngine(&cfg.Respond, r.vault)
	return r
}

// initSinks materializes every configured downstream sink. Failures here
// are non-fatal: the agent keeps running and the user can fix config
// and restart. stdout + spool + legacy syslog UDP are handled directly by emit.
func (r *Runner) initSinks() {
	if r.cfg.SyslogTCP.Enabled {
		s, err := syslogtcp.New(syslogtcp.Config{
			Enabled:       r.cfg.SyslogTCP.Enabled,
			Host:          r.cfg.SyslogTCP.Host,
			Port:          r.cfg.SyslogTCP.Port,
			TLS:           r.cfg.SyslogTCP.TLS,
			TLSCACertFile: r.cfg.SyslogTCP.TLSCACertFile,
			TLSServerName: r.cfg.SyslogTCP.TLSServerName,
			AppName:       r.cfg.SyslogTCP.AppName,
			Hostname:      r.cfg.SyslogTCP.Hostname,
			ProcID:        r.cfg.SyslogTCP.ProcID,
			Facility:      r.cfg.SyslogTCP.Facility,
			MaxMsgBytes:   r.cfg.SyslogTCP.MaxMsgBytes,
		})
		if err != nil {
			slog.Warn("syslog-tcp disabled", "err", err)
		} else {
			r.sinks = append(r.sinks, s)
		}
	}
	if r.cfg.SplunkHEC.Enabled {
		s, err := splunk.New(splunk.Config{
			Enabled:    r.cfg.SplunkHEC.Enabled,
			URL:        r.cfg.SplunkHEC.URL,
			Token:      r.cfg.SplunkHEC.Token,
			Index:      r.cfg.SplunkHEC.Index,
			SourceType: r.cfg.SplunkHEC.SourceType,
			Insecure:   r.cfg.SplunkHEC.Insecure,
		})
		if err != nil {
			slog.Warn("splunk-hec disabled", "err", err)
		} else {
			r.sinks = append(r.sinks, s)
		}
	}
	if r.cfg.ElasticBulk.Enabled {
		s, err := elastic.New(elastic.Config{
			Enabled:  r.cfg.ElasticBulk.Enabled,
			URL:      r.cfg.ElasticBulk.URL,
			Index:    r.cfg.ElasticBulk.Index,
			APIKey:   r.cfg.ElasticBulk.APIKey,
			Username: r.cfg.ElasticBulk.Username,
			Password: r.cfg.ElasticBulk.Password,
			Insecure: r.cfg.ElasticBulk.Insecure,
		})
		if err != nil {
			slog.Warn("elastic-bulk disabled", "err", err)
		} else {
			r.sinks = append(r.sinks, s)
		}
	}
	if r.cfg.LokiPush.Enabled {
		s, err := loki.New(loki.Config{
			Enabled:  r.cfg.LokiPush.Enabled,
			URL:      r.cfg.LokiPush.URL,
			Labels:   r.cfg.LokiPush.Labels,
			Username: r.cfg.LokiPush.Username,
			Password: r.cfg.LokiPush.Password,
			Insecure: r.cfg.LokiPush.Insecure,
		})
		if err != nil {
			slog.Warn("loki disabled", "err", err)
		} else {
			r.sinks = append(r.sinks, s)
		}
	}
}

func (r *Runner) WithOutput(w io.Writer) *Runner {
	r.out = w
	return r
}

func (r *Runner) RunOnce() error {
	snap, err := baseline.Load(r.cfg.BaselinePath)
	if err != nil {
		return err
	}
	var all []event.Event
	ev, err := persistence.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev...)

	ev2, err := ldpreload.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev2...)

	evInt, err := integrity.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evInt...)

	evMap, err := memorymaps.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evMap...)

	evNet, err := network.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evNet...)

	// CVE-2026-31431 ("Copy Fail") page-cache vs on-disk drift on watched
	// SUID binaries. Linux-only; on macOS dev builds the detector
	// returns nil silently.
	if r.cfg.CopyFail.Enabled {
		evCF, err := copyfail.Scan(r.cfg, snap, r.pack, AgentVersion)
		if err != nil {
			return err
		}
		all = append(all, evCF...)
	}

	if r.cfg.AncestryScanEnabled {
		evAnc, err := ancestry.Scan(r.cfg, snap, r.pack, AgentVersion)
		if err != nil {
			return err
		}
		all = append(all, evAnc...)
	}

	if r.yaraScan != nil {
		evY, err := yara.Scan(r.yaraScan, r.cfg, snap, r.pack, AgentVersion)
		if err == nil {
			all = append(all, evY...)
		}
	}

	evRecon, err := web.ScanReconChildren(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evRecon...)

	ev3, err := web.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev3...)

	now := time.Now().UTC()
	for i := range all {
		r.processEvent(&all[i], time.Time{}, now)
	}
	return nil
}

// processEvent runs Orient -> Decide -> Act -> emit gates for one event.
// observedAt is the sensor observe time for dwell-time metrics (zero for scans).
func (r *Runner) processEvent(e *event.Event, observedAt, now time.Time) {
	e.NormalizeDedup()
	r.orient(e)
	rule, hasRule := r.pack.ByID(e.RuleID)
	if hasRule {
		facts := factsFromEvent(e)
		ok, err := rule.CompiledExpr().Eval(facts)
		if err != nil {
			slog.Warn("expr eval failed", "rule", e.RuleID, "err", err)
		}
		if !ok && !e.LearningOnly {
			e.LearningOnly = true
		}
		if boost := r.correlator.matchBoost(e, rule, now); boost > 0 {
			if e.Confidence+boost > 100 {
				e.Confidence = 100
			} else {
				e.Confidence += boost
			}
			e.Signals = append(e.Signals, "correlation_boost")
		}
	}
	r.correlator.add(e.RuleID, e.Entity.ID, now)
	if r.responder != nil {
		plan := r.responder.Decide(e, rule)
		r.responder.Apply(plan, e, observedAt)
	}
	if e.LearningOnly {
		r.emit(e)
		return
	}
	if e.Confidence < r.cfg.MinConfidenceAlert {
		r.emit(e)
		return
	}
	if r.shouldDedup(e.DedupKey) {
		return
	}
	if !r.limiter.Allow(e.RuleID) {
		return
	}
	r.emit(e)
}

// orient applies doctrine context: enrich, kill-chain phase, defense layer.
func (r *Runner) orient(e *event.Event) {
	r.enrich(e)
	rule, ok := r.pack.ByID(e.RuleID)
	override := ""
	if ok {
		override = rule.KillChainPhase
	}
	e.KillChainPhase = killchain.PhaseFor(e.Tactic, override)
	e.DefenseLayer = event.DefenseLayerEndpoint
}

// factsFromEvent builds the EventFacts view that rule expressions evaluate
// against. The mapping is intentionally flat so CEL-like expressions are
// natural to write.
func factsFromEvent(e *event.Event) rules.EventFacts {
	f := rules.EventFacts{
		RuleID:         e.RuleID,
		Tactic:         e.Tactic,
		Confidence:     e.Confidence,
		Severity:       string(e.Severity),
		KillChainPhase: e.KillChainPhase,
		EntityPath:     e.Entity.Path,
		EntityID:       e.Entity.ID,
		Signals:        append([]string(nil), e.Signals...),
		Techniques:     append([]string(nil), e.TechniqueIDs...),
	}
	if e.Process != nil {
		f.Comm = e.Process.Comm
		f.UID = e.Process.UID
		f.EUID = e.Process.EUID
	}
	if e.Container != nil {
		f.ContainerRuntime = e.Container.Runtime
	}
	return f
}

// enrich adds container context, IOC matches, and process-level details
// when the event carries a pid in Entity.ID (EntityProcess).
func (r *Runner) enrich(e *event.Event) {
	// Container classification for process-scoped events.
	if e.Entity.Type == event.EntityProcess {
		if pid, err := strconv.Atoi(e.Entity.ID); err == nil && pid > 0 {
			if cg, err := procfs.ReadCgroup(pid); err == nil {
				info := container.Classify(cg)
				if !info.IsZero() {
					e.Container = &event.ContainerContext{
						Runtime: info.Runtime,
						ID:      info.ID,
						PodUID:  info.PodUID,
					}
				}
			}
			st, err := procfs.ReadStatus(pid)
			if err == nil {
				comm, _ := procfs.Comm(pid)
				argv, _ := procfs.Cmdline(pid)
				ppid, _ := procfs.PPid(pid)
				e.Process = &event.ProcessContext{
					PID:           pid,
					PPID:          ppid,
					Comm:          comm,
					Argv:          argv,
					Exe:           procfs.ResolveExe(pid),
					UID:           st.RealUID,
					EUID:          st.EffUID,
					AncestorComms: procfs.Ancestry(pid, 6),
				}
			}
		}
	}
	// IOC feed match enrichment. File hashes get a small bump, network IOCs
	// (IP/domain) get a larger one because they are much higher-fidelity.
	if e.Entity.Type == event.EntityFile && e.Entity.ID != "" {
		if r.feed.MatchHash(e.Entity.ID) {
			e.IOCMatches = append(e.IOCMatches, "hash:"+e.Entity.ID)
			e.Confidence = minInt(100, e.Confidence+10)
		}
	}
	if e.Network != nil && e.Network.RemoteIP != "" {
		if ip := netParseIP(e.Network.RemoteIP); ip != nil && r.feed.MatchIP(ip) {
			e.IOCMatches = append(e.IOCMatches, "ip:"+e.Network.RemoteIP)
			e.Confidence = minInt(100, e.Confidence+25)
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func netParseIP(s string) net.IP { return net.ParseIP(s) }

func (r *Runner) shouldDedup(key string) bool {
	if key == "" {
		return false
	}
	if t, ok := r.lastDedup[key]; ok && time.Since(t) < r.cfg.ScanInterval.Duration() {
		return true
	}
	r.lastDedup[key] = time.Now()
	return false
}

func (r *Runner) emit(e *event.Event) {
	e.DefenseLayer = event.DefenseLayerEndpoint
	e.SOCEscalate = shouldSOCEscalate(e)
	b, err := e.JSONLine()
	if err != nil {
		return
	}
	_, _ = r.out.Write(append(b, '\n'))
	if r.syslog != nil {
		if err := r.syslog.Send(e, b); err != nil {
			slog.Debug("syslog udp send failed", "err", err)
			if r.spool != nil {
				_ = r.spool.Append(b)
			}
		}
	}
	if len(r.sinks) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range r.sinks {
			if err := s.Send(ctx, e, b); err != nil {
				slog.Debug("sink send failed", "name", s.Name(), "err", err)
				if r.spool != nil {
					_ = r.spool.Append(b)
				}
			}
		}
	}
	// Legacy quarantine when the response engine is disabled.
	if !r.cfg.Respond.Enabled && r.vault != nil && e.Entity.Type == event.EntityFile && e.Entity.Path != "" &&
		!e.LearningOnly && e.Confidence >= r.cfg.QuarantineMinConfidence && r.cfg.QuarantineMinConfidence > 0 {
		if stored, err := r.vault.Store(e.Entity.Path, e); err == nil {
			slog.Info("quarantined", "path", e.Entity.Path, "stored", stored)
		} else {
			slog.Debug("quarantine failed", "err", err)
		}
	}
}

func shouldSOCEscalate(e *event.Event) bool {
	if e.Severity == event.SeverityHigh || e.Severity == event.SeverityCritical {
		return true
	}
	if e.Response != nil && e.Response.Action != "" && e.Response.Action != respond.ActionAlertOnly {
		return true
	}
	return false
}

// RunLoop blocks, running scans on interval until ctx cancelled - caller can use signal.
func (r *Runner) RunLoop(stop <-chan struct{}) {
	if r.cfg.WatchAuthorizedKeys {
		go watch.RunAuthorizedKeys(r.cfg.WatchDebounce.Duration(), func() error { return r.RunOnce() }, stop)
	}
	if r.cfg.WatchSensitivePaths {
		specs := watch.DefaultSensitivePaths(r.cfg.DocumentRoots)
		go watch.RunSensitive(specs, r.cfg.WatchDebounce.Duration(), func() error { return r.RunOnce() }, stop)
	}

	// Bring up the best available sensor (ebpf → auditd → /proc poll).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if src, err := sensor.Auto(ctx); err == nil && src != nil {
		slog.Info("sensor backend selected", "name", src.Name())
		ch := make(chan sensor.Event, 1024)
		go func() { _ = src.Start(ctx, ch) }()
		go r.consumeSensor(ctx, ch)
	} else if err != nil {
		slog.Warn("sensor backend unavailable", "err", err)
	}
	go func() {
		<-stop
		cancel()
	}()

	// systemd watchdog ping on its own cadence so scans never starve it.
	if r.cfg.SelfGuard.Enabled && r.cfg.SelfGuard.SystemdWatchdog {
		wd := selfguard.WatchdogInterval()
		if wd > 0 {
			go r.watchdogLoop(wd, ctx.Done())
		}
	}

	t := time.NewTicker(r.cfg.ScanInterval.Duration())
	defer t.Stop()
	_ = r.RunOnce()
	r.checkBinaryHash()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = r.RunOnce()
			r.checkBinaryHash()
		}
	}
}

// checkBinaryHash emits a critical AGENT_TAMPERED event when the agent
// binary on disk no longer matches the expected sha256. This is cheap
// and catches adversaries who drop a modified ghostcatcher alongside a
// persistence mechanism.
func (r *Runner) checkBinaryHash() {
	if !r.cfg.SelfGuard.Enabled || r.cfg.SelfGuard.BinaryPath == "" || r.cfg.SelfGuard.ExpectedBinarySHA256 == "" {
		return
	}
	if err := selfguard.BinaryMatches(r.cfg.SelfGuard.BinaryPath, r.cfg.SelfGuard.ExpectedBinarySHA256); err != nil {
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    AgentVersion,
			Timestamp:       time.Now().UTC(),
			RuleID:          "AGENT_TAMPERED",
			RulePackVersion: r.pack.Version,
			Tactic:          "defense-evasion",
			TechniqueIDs:    []string{"T1562.001"},
			Confidence:      100,
			Severity:        event.SeverityCritical,
			Entity:          event.Entity{Type: event.EntityFile, Path: r.cfg.SelfGuard.BinaryPath},
			Signals:         []string{"self_binary_hash_mismatch"},
			Evidence:        err.Error(),
		}
		r.processEvent(&ev, time.Time{}, time.Now().UTC())
	}
}

func (r *Runner) watchdogLoop(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = selfguard.NotifyWatchdog()
		}
	}
}

// consumeSensor drains the sensor channel. High-fidelity syscalls run the
// inline OODA fast path (milliseconds). Periodic RunOnce remains the
// safety net for at-rest state.
func (r *Runner) consumeSensor(ctx context.Context, ch <-chan sensor.Event) {
	fast := sensorlive.FastKinds()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if _, isFast := fast[ev.Kind]; !isFast {
				continue
			}
			observedAt := ev.When
			if observedAt.IsZero() {
				observedAt = time.Now()
			}
			if r.cfg.CopyFail.Enabled && ev.Kind == sensor.KindSocket {
				if cfEv, hit := copyfail.RouteSensorEvent(r.cfg, r.pack, AgentVersion, ev); hit {
					r.dispatchEvent(&cfEv, observedAt)
				}
				continue
			}
			if liveEv, hit := sensorlive.RouteSensorEvent(r.cfg, r.pack, AgentVersion, ev); hit {
				r.dispatchEvent(&liveEv, observedAt)
			}
		}
	}
}

// dispatchEvent runs the full OODA pipeline for a live-routed detection.
func (r *Runner) dispatchEvent(e *event.Event, observedAt time.Time) {
	r.processEvent(e, observedAt, time.Now().UTC())
}
