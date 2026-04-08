package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Server defaults
	if cfg.Server.ListenAddr != ":8080" {
		t.Errorf("expected listen addr :8080, got %s", cfg.Server.ListenAddr)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected read timeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 60*time.Second {
		t.Errorf("expected write timeout 60s, got %v", cfg.Server.WriteTimeout)
	}

	// Upstream defaults
	if cfg.Upstreams.NPM != "https://registry.npmjs.org" {
		t.Errorf("unexpected npm upstream: %s", cfg.Upstreams.NPM)
	}
	if cfg.Upstreams.PyPI != "https://pypi.org" {
		t.Errorf("unexpected pypi upstream: %s", cfg.Upstreams.PyPI)
	}
	if cfg.Upstreams.Go != "https://proxy.golang.org" {
		t.Errorf("unexpected go upstream: %s", cfg.Upstreams.Go)
	}

	// Policies defaults
	if cfg.Policies.Directory != "./policies" {
		t.Errorf("unexpected policies dir: %s", cfg.Policies.Directory)
	}

	// VulnDB defaults
	if cfg.VulnDB.Enabled {
		t.Error("vulndb should be disabled by default")
	}
	if cfg.VulnDB.Driver != "sqlite" {
		t.Errorf("expected sqlite driver, got %s", cfg.VulnDB.Driver)
	}

	// Sync defaults
	if cfg.Sync.Enabled {
		t.Error("sync should be disabled by default")
	}
	if cfg.Sync.BatchSize != 100 {
		t.Errorf("expected batch size 100, got %d", cfg.Sync.BatchSize)
	}
}

func TestLoadFromFile(t *testing.T) {
	t.Run("valid_yaml", func(t *testing.T) {
		yaml := `
server:
  listen_addr: ":9090"
  read_timeout: 10s
upstreams:
  npm: "https://npm.example.com"
  pypi: "https://pypi.example.com"
  go: "https://go.example.com"
policies:
  directory: "./custom-policies"
logging:
  level: "debug"
  format: "json"
vulndb:
  enabled: true
  driver: "postgres"
  dsn: "host=localhost dbname=test"
sync:
  enabled: true
  ecosystems:
    - npm
    - PyPI
  batch_size: 50
  seed_on_start: true
`
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Fatalf("LoadFromFile failed: %v", err)
		}

		if cfg.Server.ListenAddr != ":9090" {
			t.Errorf("expected :9090, got %s", cfg.Server.ListenAddr)
		}
		if cfg.Server.ReadTimeout != 10*time.Second {
			t.Errorf("expected 10s, got %v", cfg.Server.ReadTimeout)
		}
		// WriteTimeout should keep default since not specified
		if cfg.Server.WriteTimeout != 60*time.Second {
			t.Errorf("expected default 60s write timeout, got %v", cfg.Server.WriteTimeout)
		}
		if cfg.Upstreams.NPM != "https://npm.example.com" {
			t.Errorf("unexpected npm upstream: %s", cfg.Upstreams.NPM)
		}
		if cfg.Policies.Directory != "./custom-policies" {
			t.Errorf("unexpected policies dir: %s", cfg.Policies.Directory)
		}
		if cfg.Logging.Level != "debug" {
			t.Errorf("unexpected log level: %s", cfg.Logging.Level)
		}
		if cfg.Logging.Format != "json" {
			t.Errorf("unexpected log format: %s", cfg.Logging.Format)
		}
		if !cfg.VulnDB.Enabled {
			t.Error("vulndb should be enabled")
		}
		if cfg.VulnDB.Driver != "postgres" {
			t.Errorf("expected postgres driver, got %s", cfg.VulnDB.Driver)
		}
		if !cfg.Sync.Enabled {
			t.Error("sync should be enabled")
		}
		if len(cfg.Sync.Ecosystems) != 2 {
			t.Errorf("expected 2 ecosystems, got %d", len(cfg.Sync.Ecosystems))
		}
		if cfg.Sync.BatchSize != 50 {
			t.Errorf("expected batch size 50, got %d", cfg.Sync.BatchSize)
		}
		if !cfg.Sync.SeedOnStart {
			t.Error("seed_on_start should be true")
		}
	})

	t.Run("missing_file", func(t *testing.T) {
		_, err := LoadFromFile("/nonexistent/config.yaml")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(path, []byte("{{{{invalid yaml"), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFromFile(path)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})

	t.Run("partial_config_merges_defaults", func(t *testing.T) {
		yaml := `
server:
  listen_addr: ":3000"
`
		dir := t.TempDir()
		path := filepath.Join(dir, "partial.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Fatalf("LoadFromFile failed: %v", err)
		}

		if cfg.Server.ListenAddr != ":3000" {
			t.Errorf("expected :3000, got %s", cfg.Server.ListenAddr)
		}
		// Other defaults should be preserved
		if cfg.Upstreams.NPM != "https://registry.npmjs.org" {
			t.Errorf("expected default npm upstream, got %s", cfg.Upstreams.NPM)
		}
	})
}

func TestLoadFromFile_RewritesFile(t *testing.T) {
	t.Run("loads_rules_from_external_file", func(t *testing.T) {
		dir := t.TempDir()

		rewritesYAML := `
rules:
  - match:
      ecosystem: "npm"
      name: "lodash"
    rewrite:
      version:
        strategy: "pin"
        target: "4.17.21"
  - match:
      ecosystem: "pypi"
      name: "requests"
    rewrite:
      version:
        strategy: "min"
        target: "2.28.0"
`
		rwPath := filepath.Join(dir, "rewrites.yaml")
		if err := os.WriteFile(rwPath, []byte(rewritesYAML), 0644); err != nil {
			t.Fatal(err)
		}

		configYAML := `
server:
  listen_addr: ":8080"
rewrites_file: "rewrites.yaml"
`
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadFromFile(cfgPath)
		if err != nil {
			t.Fatalf("LoadFromFile failed: %v", err)
		}

		if len(cfg.Rewrites.Rules) != 2 {
			t.Fatalf("expected 2 rewrite rules, got %d", len(cfg.Rewrites.Rules))
		}
		if cfg.Rewrites.Rules[0].Match.Name != "lodash" {
			t.Errorf("expected first rule to match lodash, got %s", cfg.Rewrites.Rules[0].Match.Name)
		}
		if cfg.Rewrites.Rules[0].Rewrite.Version.Strategy != "pin" {
			t.Errorf("expected pin strategy, got %s", cfg.Rewrites.Rules[0].Rewrite.Version.Strategy)
		}
		if cfg.Rewrites.Rules[1].Match.Ecosystem != "pypi" {
			t.Errorf("expected pypi ecosystem, got %s", cfg.Rewrites.Rules[1].Match.Ecosystem)
		}
	})

	t.Run("missing_rewrites_file_returns_error", func(t *testing.T) {
		dir := t.TempDir()

		configYAML := `
server:
  listen_addr: ":8080"
rewrites_file: "nonexistent.yaml"
`
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := LoadFromFile(cfgPath)
		if err == nil {
			t.Error("expected error for missing rewrites file")
		}
	})

	t.Run("inline_rewrites_still_work", func(t *testing.T) {
		dir := t.TempDir()

		configYAML := `
server:
  listen_addr: ":8080"
rewrites:
  rules:
    - match:
        ecosystem: "npm"
        name: "express"
      rewrite:
        version:
          strategy: "pin"
          target: "4.18.0"
`
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadFromFile(cfgPath)
		if err != nil {
			t.Fatalf("LoadFromFile failed: %v", err)
		}

		if len(cfg.Rewrites.Rules) != 1 {
			t.Fatalf("expected 1 inline rewrite rule, got %d", len(cfg.Rewrites.Rules))
		}
		if cfg.Rewrites.Rules[0].Match.Name != "express" {
			t.Errorf("expected express, got %s", cfg.Rewrites.Rules[0].Match.Name)
		}
	})

	t.Run("external_file_overrides_inline", func(t *testing.T) {
		dir := t.TempDir()

		rewritesYAML := `
rules:
  - match:
      ecosystem: "go"
      name: "*"
    rewrite:
      version:
        strategy: "nearest-minor"
`
		rwPath := filepath.Join(dir, "rewrites.yaml")
		if err := os.WriteFile(rwPath, []byte(rewritesYAML), 0644); err != nil {
			t.Fatal(err)
		}

		// Both inline and file specified; file should win.
		configYAML := `
server:
  listen_addr: ":8080"
rewrites_file: "rewrites.yaml"
rewrites:
  rules:
    - match:
        ecosystem: "npm"
        name: "lodash"
      rewrite:
        version:
          strategy: "pin"
          target: "4.17.21"
`
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadFromFile(cfgPath)
		if err != nil {
			t.Fatalf("LoadFromFile failed: %v", err)
		}

		if len(cfg.Rewrites.Rules) != 1 {
			t.Fatalf("expected 1 rule from file, got %d", len(cfg.Rewrites.Rules))
		}
		if cfg.Rewrites.Rules[0].Match.Ecosystem != "go" {
			t.Errorf("expected go ecosystem from file, got %s", cfg.Rewrites.Rules[0].Match.Ecosystem)
		}
	})
}
