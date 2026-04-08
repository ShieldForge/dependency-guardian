package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the top-level application configuration.
type Config struct {
	Server       ServerConfig   `yaml:"server"`
	Upstreams    UpstreamConfig `yaml:"upstreams"`
	Policies     PoliciesConfig `yaml:"policies"`
	Logging      LoggingConfig  `yaml:"logging"`
	VulnDB       VulnDBConfig   `yaml:"vulndb"`
	Sync         SyncConfig     `yaml:"sync"`
	RewritesFile string         `yaml:"rewrites_file,omitempty"`
	Rewrites     RewriteConfig  `yaml:"rewrites"`
}

// RewriteConfig holds dependency rewrite rules.
type RewriteConfig struct {
	Rules []RewriteRule `yaml:"rules"`
}

// RewriteRule defines a single rewrite rule with match criteria and a rewrite action.
type RewriteRule struct {
	Match   RewriteMatch  `yaml:"match"`
	Rewrite RewriteAction `yaml:"rewrite"`
}

// RewriteMatch specifies the criteria for a rewrite rule to apply.
// All non-empty fields must match. Name supports glob patterns (e.g. "lodash*").
// Version supports glob patterns (e.g. "1.0.*").
type RewriteMatch struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
	Version   string `yaml:"version,omitempty"`
}

// RewriteAction specifies what to rewrite when a rule matches.
type RewriteAction struct {
	// Name replaces the package name (optional).
	Name string `yaml:"name,omitempty"`
	// Version controls version rewriting (optional).
	Version *VersionRewrite `yaml:"version,omitempty"`
	// Mode is "transparent" (default) or "redirect".
	// Transparent serves the rewritten version silently.
	// Redirect returns an HTTP redirect to the rewritten version URL.
	Mode string `yaml:"mode,omitempty"`
}

// VersionRewrite specifies how to transform a version.
// Supported strategies:
//   - "pin":           always use Target as the version
//   - "nearest-minor": snap to the minor release boundary (zero out patch)
//   - "nearest-major": snap to the major release boundary (zero out minor and patch)
//   - "min":           if version < Target, upgrade to Target
//   - "max":           if version > Target, downgrade to Target
//   - "replace-major": replace the major component with Target
//   - "replace-minor": replace the minor component with Target
//   - "replace-patch": replace the patch component with Target
type VersionRewrite struct {
	Strategy string `yaml:"strategy"`
	Target   string `yaml:"target,omitempty"`
}

// VulnDBConfig holds vulnerability database settings.
type VulnDBConfig struct {
	Enabled         bool          `yaml:"enabled"`
	Driver          string        `yaml:"driver"`
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	LogLevel        string        `yaml:"log_level"`
}

// SyncConfig holds OSV data synchronisation settings.
type SyncConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Ecosystems        []string      `yaml:"ecosystems"`
	FullSyncInterval  time.Duration `yaml:"full_sync_interval"`
	DeltaSyncInterval time.Duration `yaml:"delta_sync_interval"`
	MetricsInterval   time.Duration `yaml:"metrics_interval"`
	BatchSize         int           `yaml:"batch_size"`
	Workers           int           `yaml:"workers"`
	SeedOnStart       bool          `yaml:"seed_on_start"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	ListenAddr     string        `yaml:"listen_addr"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	MaxRequestBody int64         `yaml:"max_request_body"`
	AdminToken     string        `yaml:"admin_token"`
}

// UpstreamConfig holds the upstream registry URLs.
type UpstreamConfig struct {
	NPM   string `yaml:"npm"`
	PyPI  string `yaml:"pypi"`
	Go    string `yaml:"go"`
	Maven string `yaml:"maven"`
}

// PoliciesConfig holds OPA/Rego policy settings.
type PoliciesConfig struct {
	Directory string `yaml:"directory"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:     ":8080",
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   60 * time.Second,
			MaxRequestBody: 10 << 20, // 10 MB
		},
		Upstreams: UpstreamConfig{
			NPM:   "https://registry.npmjs.org",
			PyPI:  "https://pypi.org",
			Go:    "https://proxy.golang.org",
			Maven: "https://repo1.maven.org/maven2",
		},
		Policies: PoliciesConfig{
			Directory: "./policies",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		VulnDB: VulnDBConfig{
			Enabled:         false,
			Driver:          "sqlite",
			DSN:             "./vulndb.sqlite",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: time.Hour,
			LogLevel:        "warn",
		},
		Sync: SyncConfig{
			Enabled:           false,
			FullSyncInterval:  24 * time.Hour,
			DeltaSyncInterval: 15 * time.Minute,
			MetricsInterval:   1 * time.Hour,
			BatchSize:         100,
			Workers:           2,
			SeedOnStart:       false,
		},
	}
}

// LoadFromFile loads configuration from a YAML file, merging with defaults.
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	//check to see if the path is a directory, if so, look for config.yaml inside it
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config path: %w", err)
	}
	if info.IsDir() {
		path = fmt.Sprintf("%s/config.yaml", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Load rewrite rules from an external file if configured.
	if cfg.RewritesFile != "" {
		rwPath := cfg.RewritesFile
		if !filepath.IsAbs(rwPath) {
			rwPath = filepath.Join(filepath.Dir(path), rwPath)
		}
		rwCfg, err := loadRewritesFile(rwPath)
		if err != nil {
			return nil, fmt.Errorf("loading rewrites file: %w", err)
		}
		cfg.Rewrites = *rwCfg
	}

	return cfg, nil
}

// loadRewritesFile reads a standalone rewrite-rules YAML file.
func loadRewritesFile(path string) (*RewriteConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rewrites file %q: %w", path, err)
	}
	var rc RewriteConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("parsing rewrites file %q: %w", path, err)
	}
	return &rc, nil
}

// Validate checks the configuration for invalid or missing values.
func (c *Config) Validate() error {
	var errs []error

	// Server validation.
	if c.Server.ListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
			errs = append(errs, fmt.Errorf("server.listen_addr %q is not a valid host:port: %w", c.Server.ListenAddr, err))
		}
	}

	// VulnDB validation.
	if c.VulnDB.Enabled {
		if c.VulnDB.DSN == "" {
			errs = append(errs, fmt.Errorf("vulndb.dsn must be set when vulndb is enabled"))
		}
	}

	// Sync validation.
	if c.Sync.Enabled {
		if c.Sync.BatchSize < 1 {
			errs = append(errs, fmt.Errorf("sync.batch_size must be >= 1, got %d", c.Sync.BatchSize))
		}
		if c.Sync.Workers < 1 {
			errs = append(errs, fmt.Errorf("sync.workers must be >= 1, got %d", c.Sync.Workers))
		}
	}

	return errors.Join(errs...)
}
