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
	"ghostcatcher/internal/detect/ldpreload"
	"ghostcatcher/internal/detect/persistence"
	"ghostcatcher/internal/detect/web"
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ghostcatcher <run|check-config|baseline commit> [-config path]")
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
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
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
	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		slog.Error("rule pack load failed", "err", err)
		os.Exit(1)
	}
	return cfg, pack
}
