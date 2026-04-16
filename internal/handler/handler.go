// Package handler defines shared types and logic for all ecosystem handlers.
package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/handler/upstream"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/rewrite"
)

// Handler is the interface that all ecosystem handlers implement.
type Handler interface {
	http.Handler
}

// Base contains shared dependencies used by all ecosystem handlers.
// Ecosystem-specific handlers embed this struct to reuse common fields
// and the EvaluateVersion method.
type Base struct {
	Upstream *upstream.Client
	Engine   *policy.Engine
	VulnDB   registry.VulnerabilityDB
	Logger   *slog.Logger
	Recorder decisions.Recorder
	Rewriter *rewrite.Engine
}

// NewBase creates a new Base with common handler dependencies.
func NewBase(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder, rewriter *rewrite.Engine, name string) Base {
	return Base{
		Upstream: upstream.NewClient(strings.TrimRight(upstreamURL, "/"), 30*time.Second),
		Engine:   engine,
		VulnDB:   vulnDB,
		Logger:   logger.With("handler", name),
		Recorder: recorder,
		Rewriter: rewriter,
	}
}

// EvaluateVersion looks up vulnerabilities, evaluates OPA policy,
// records the decision, and logs denials. Returns the policy result.
func (b *Base) EvaluateVersion(ctx context.Context, pv registry.PackageVersion) (registry.PolicyResult, error) {
	vulns, err := b.VulnDB.GetVulnerabilities(ctx, pv.Ecosystem, pv.Name, pv.Version)
	if err != nil {
		b.Logger.Warn("vulnerability lookup failed", "package", pv.Name, "version", pv.Version, "error", err)
	}

	input := registry.PolicyInput{
		Package:         pv,
		Vulnerabilities: vulns,
	}

	result, err := b.Engine.Evaluate(ctx, input)
	if err != nil {
		return registry.PolicyResult{}, err
	}

	if b.Recorder != nil {
		b.Recorder.Record(string(pv.Ecosystem), pv.Name, pv.Version, result.Allowed, result.Reasons, len(vulns))
	}

	if !result.Allowed {
		b.Logger.Info("version denied by policy",
			"package", pv.Name,
			"version", pv.Version,
			"reasons", result.Reasons,
		)
	}

	return result, nil
}
