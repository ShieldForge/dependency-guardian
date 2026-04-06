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
