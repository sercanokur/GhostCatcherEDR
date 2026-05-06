package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/detect/ancestry"
	"ghostcatcher/internal/detect/integrity"
	"ghostcatcher/internal/detect/ldpreload"
	"ghostcatcher/internal/detect/persistence"
	"ghostcatcher/internal/detect/web"
	"ghostcatcher/internal/eval"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/runner"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})))

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "check-config":
		checkConfig(os.Args[2:])
	case "baseline":
		if len(os.Args) < 3 || os.Args[2] != "commit" {
			fmt.Fprintln(os.Stderr, "usage: ghostcatcher baseline commit -config <path>")
			os.Exit(2)
		}
		baselineCommit(os.Args[3:])
	case "eval":
		evalCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ghostcatcher <run|check-config|baseline commit|eval> [-config path]")
}

func evalCmd(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	corpus := fs.String("corpus", "testdata/eval", "path to labeled corpus (malicious/, benign/, cron/)")
	minF1 := fs.Float64("min-f1", 0.0, "exit 1 if F1 is below this value (for CI)")
	_ = fs.Parse(args)
	cfg := config.Default()
	cfg.LearningMode = false
	cfg.FirstRunAllowAlerts = true
	cfg.MinConfidenceAlert = 60
	res, err := eval.Run(*corpus, cfg, nil)
	if err != nil {
		slog.Error("eval run failed", "err", err)
		os.Exit(1)
	}
	fmt.Println(res.Report())
	if *minF1 > 0 && res.F1() < *minF1 {
		slog.Error("F1 regressed", "f1", res.F1(), "min_f1", *minF1)
		os.Exit(1)
	}
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.example.yaml", "config file")
	once := fs.Bool("once", false, "single scan then exit")
	_ = fs.Parse(args)

	cfg, pack := loadCfgAndPack(*cfgPath)
	if cfg.RequireRoot && os.Geteuid() != 0 {
		slog.Error("require_root set but not running as root")
		os.Exit(1)
	}
	r := runner.New(cfg, pack)
	if *once {
		if err := r.RunOnce(); err != nil {
			slog.Error("scan failed", "err", err)
			os.Exit(1)
		}
		return
	}
	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		close(stop)
	}()
	r.RunLoop(stop)
}

func checkConfig(args []string) {
	fs := flag.NewFlagSet("check-config", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.example.yaml", "config file")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("config invalid", "err", err)
		os.Exit(1)
	}
	if _, err := rules.LoadPack(cfg.RulePackPath); err != nil {
		slog.Error("rule pack invalid", "err", err)
		os.Exit(1)
	}
	slog.Info("config ok", "path", *cfgPath)
}

func baselineCommit(args []string) {
	fs := flag.NewFlagSet("baseline commit", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.example.yaml", "config file")
	token := fs.String("token", "", "2fa token (required when baseline_commit_token_env is set)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if cfg.BaselineCommitTokenEnv != "" {
		want := os.Getenv(cfg.BaselineCommitTokenEnv)
		if want == "" {
			slog.Error("2fa required but env var is empty", "env", cfg.BaselineCommitTokenEnv)
			os.Exit(1)
		}
		if *token != want {
			slog.Error("2fa token mismatch; refusing to commit baseline")
			os.Exit(1)
		}
	}
	if cfg.RequireRoot && os.Geteuid() != 0 {
		slog.Error("require_root set but not running as root")
		os.Exit(1)
	}
	snap, err := baseline.Load(cfg.BaselinePath)
	if err != nil {
		slog.Error("baseline load failed", "err", err)
		os.Exit(1)
	}
	if err := persistence.BuildBaselineAuthKeys(snap); err != nil {
		slog.Error("auth keys baseline failed", "err", err)
		os.Exit(1)
	}
	if err := persistence.BuildBaselineCron(snap); err != nil {
		slog.Error("cron baseline failed", "err", err)
		os.Exit(1)
	}
	if err := web.BuildBaselineWebFiles(cfg, snap); err != nil {
		slog.Error("web baseline failed", "err", err)
		os.Exit(1)
	}
	if err := ldpreload.BuildBaselineLDPreload(cfg, snap); err != nil {
		slog.Error("ld_preload baseline failed", "err", err)
		os.Exit(1)
	}
	// PersistenceFiles + integrity: delta taramalarının gürültüsüz çalışması için
	// host durumunun tamamı baseline'a yazılır.
	if err := persistence.BuildBaselineSystemd(snap); err != nil {
		slog.Warn("systemd baseline failed", "err", err)
	}
	if err := persistence.BuildBaselinePAM(snap); err != nil {
		slog.Warn("pam baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineShellRC(snap); err != nil {
		slog.Warn("shellrc baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineSudoers(snap); err != nil {
		slog.Warn("sudoers baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineSSHD(snap); err != nil {
		slog.Warn("sshd baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineUsers(snap); err != nil {
		slog.Warn("users baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineKernelModules(snap); err != nil {
		slog.Warn("kernel module baseline failed", "err", err)
	}
	if err := persistence.BuildBaselineLDConf(snap); err != nil {
		slog.Warn("ld.so.conf baseline failed", "err", err)
	}
	if err := integrity.BuildBaselineIntegrity(cfg, snap); err != nil {
		slog.Warn("integrity baseline failed", "err", err)
	}
	if pairs, err := ancestry.BuildBaselineAncestry(); err == nil {
		snap.ProcessAncestry = pairs
	} else {
		slog.Warn("ancestry baseline failed", "err", err)
	}
	snap.CommittedAt = time.Now().UTC()
	if err := snap.Save(cfg.BaselinePath); err != nil {
		slog.Error("baseline save failed", "err", err)
		os.Exit(1)
	}
	slog.Info("baseline committed", "path", cfg.BaselinePath)
}

func loadCfgAndPack(path string) (*config.Config, *rules.Pack) {
	cfg, err := config.Load(path)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("config invalid", "err", err)
		os.Exit(1)
	}
	if cfg.RulePackPubKey != "" && cfg.RulePackSigPath != "" {
		if err := rules.VerifyPackSignature(cfg.RulePackPath, cfg.RulePackSigPath, cfg.RulePackPubKey); err != nil {
			slog.Error("rule pack signature verification failed", "err", err)
			os.Exit(1)
		}
	}
	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		slog.Error("rule pack load failed", "err", err)
		os.Exit(1)
	}
	if cfg.SigmaLiteDir != "" {
		extra, err := rules.LoadSigmaLiteDir(cfg.SigmaLiteDir)
		if err != nil {
			slog.Warn("sigma-lite load skipped", "err", err)
		} else {
			pack.Merge(extra)
		}
	}
	return cfg, pack
}
