package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/proxy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/vulndb"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/database"
	vulnsync "dependency-guardian/internal/vulndb/sync"
)

func main() {
	configPath := flag.String("config", "./config.yaml", "path to configuration file")
	policysDir := flag.String("policies", "", "override policies directory")
	vscodeMode := flag.Bool("vscode", false, "run in VS Code extension mode (SQLite, decision logging, API enabled)")
	listenAddr := flag.String("addr", "", "override listen address (e.g. :8080)")
	flag.Parse()

	// Load configuration.
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		// If no config file exists, use defaults.
		fmt.Fprintf(os.Stderr, "warning: %v – using defaults\n", err)
		cfg = config.DefaultConfig()
	}

	// In VS Code mode, override settings for local development use.
	if *vscodeMode {
		cfg.VulnDB.Enabled = true
		cfg.VulnDB.Driver = "sqlite"
		if cfg.VulnDB.DSN == "" || cfg.VulnDB.DSN == "host=localhost" {
			cfg.VulnDB.DSN = "./guardian-vscode.sqlite"
		}
		if *policysDir != "" {
			cfg.Policies.Directory = *policysDir
		} else if cfg.Policies.Directory == "./policies" {
			cfg.Policies.Directory = "./bin/policies"
		}
	}
	if *listenAddr != "" {
		cfg.Server.ListenAddr = *listenAddr
	}

	// Validate configuration.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Set up structured logger.
	var handler slog.Handler
	opts := &slog.HandlerOptions{}
	switch cfg.Logging.Level {
	case "debug":
		opts.Level = slog.LevelDebug
	case "warn":
		opts.Level = slog.LevelWarn
	case "error":
		opts.Level = slog.LevelError
	default:
		opts.Level = slog.LevelInfo
	}

	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(handler)

	// Initialise the OPA policy engine.
	engine, err := policy.NewEngine(cfg.Policies.Directory)
	if err != nil {
		logger.Error("failed to initialise policy engine", "error", err)
		os.Exit(1)
	}
	logger.Info("policy engine initialised", "directory", cfg.Policies.Directory)

	// Initialise the vulnerability database.
	var vulnDB registry.VulnerabilityDB
	var vulnStore *dal.Store
	if cfg.VulnDB.Enabled {
		db, err := database.Open(cfg.VulnDB, logger)
		if err != nil {
			logger.Error("failed to open vulnerability database", "error", err)
			os.Exit(1)
		}
		store := dal.NewStore(db)
		vulnStore = store
		osvDB := vulndb.NewOSVDatabase(store, logger)
		vulnDB = osvDB
		logger.Info("vulnerability database initialised", "driver", cfg.VulnDB.Driver)

		// Set up OSV sync if enabled.
		if cfg.Sync.Enabled {
			syncer := vulnsync.NewSyncer(store, cfg.Sync, logger)

			// Seed on start if requested.
			if cfg.Sync.SeedOnStart {
				logger.Info("running initial vulnerability data seed")
				go func() {
					if err := syncer.SeedAll(context.Background()); err != nil {
						logger.Error("initial seed failed", "error", err)
					}
				}()
			}

			// Start background sync scheduler.
			scheduler := vulnsync.NewScheduler(syncer, cfg.Sync, logger)
			scheduler.Start(context.Background())
			defer scheduler.Stop()
			logger.Info("vulnerability sync scheduler started")
		}
	} else {
		vulnDB = &registry.NoOpVulnerabilityDB{}
		logger.Info("vulnerability database: disabled (using no-op stub)")
	}

	// Create decision log if in VS Code mode.
	var serverOpts []proxy.ServerOption
	if *vscodeMode {
		decisionLog := decisions.NewLog(2000)
		serverOpts = append(serverOpts, proxy.WithDecisionLog(decisionLog))
		logger.Info("VS Code mode enabled: decision logging and API endpoints active")
	}
	if vulnStore != nil {
		serverOpts = append(serverOpts, proxy.WithVulnDBStore(vulnStore))
	}

	// Create and start the proxy server.
	server := proxy.NewServer(cfg, engine, vulnDB, logger, serverOpts...)
	logger.Info("proxy server starting",
		"addr", cfg.Server.ListenAddr,
		"npm_upstream", cfg.Upstreams.NPM,
		"pypi_upstream", cfg.Upstreams.PyPI,
		"go_upstream", cfg.Upstreams.Go,
	)

	// Start server in a goroutine so we can handle shutdown signals.
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for interrupt signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", "signal", sig.String())
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown with timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped gracefully")
}
