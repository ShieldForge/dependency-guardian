// Package gomod implements the proxy handler for Go module proxy requests.
//
// Go module clients (go get) use the GOPROXY protocol:
//
//	GET /<module>/@v/list       -> list of available versions (newline-separated)
//	GET /<module>/@v/<ver>.info -> JSON with version info {"Version":"...","Time":"..."}
//	GET /<module>/@v/<ver>.mod  -> go.mod file (passed through)
//	GET /<module>/@v/<ver>.zip  -> module zip (passed through)
//	GET /<module>/@latest       -> latest version info
package gomod

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/handler/upstream"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
)

// Handler processes Go module proxy requests.
type Handler struct {
	upstream *upstream.Client
	engine   *policy.Engine
	vulnDB   registry.VulnerabilityDB
	logger   *slog.Logger
	recorder decisions.Recorder
}

// versionInfo is the JSON structure returned by @v/<ver>.info and @latest.
type versionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// NewHandler creates a new Go module proxy handler.
func NewHandler(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder) *Handler {
	return &Handler{
		upstream: upstream.NewClient(strings.TrimRight(upstreamURL, "/"), 30*time.Second),
		engine:   engine,
		vulnDB:   vulnDB,
		logger:   logger.With("handler", "gomod"),
		recorder: recorder,
	}
}

// ServeHTTP routes Go module proxy requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/@v/list"):
		h.handleVersionList(w, r)
	case strings.HasSuffix(path, "/@latest"):
		h.handleLatest(w, r)
	case strings.HasSuffix(path, ".info"):
		h.handleVersionInfo(w, r)
	default:
		// .mod and .zip files – pass through unmodified.
		h.upstream.Passthrough(w, r)
	}
}

// handleVersionList fetches the version list from upstream, evaluates
// each version against policy, and returns only allowed versions.
func (h *Handler) handleVersionList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modulePath := extractModulePath(r.URL.Path, "/@v/list")

	upstreamURL := h.upstream.BaseURL + r.URL.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	resp, err := h.upstream.HTTPClient.Do(req)
	if err != nil {
		h.logger.Error("upstream request failed", "url", upstreamURL, "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// Read all versions from the text response.
	var allowed []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ver := strings.TrimSpace(scanner.Text())
		if ver == "" {
			continue
		}

		ok, err := h.evaluateVersion(ctx, modulePath, ver)
		if err != nil {
			h.logger.Error("policy evaluation failed", "module", modulePath, "version", ver, "error", err)
			continue
		}
		if ok {
			allowed = append(allowed, ver)
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	for _, v := range allowed {
		fmt.Fprintln(w, v)
	}
}

// handleLatest fetches the @latest endpoint, evaluates the version,
// and returns 404 if the latest version is denied.
func (h *Handler) handleLatest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modulePath := extractModulePath(r.URL.Path, "/@latest")

	body, statusCode, err := h.upstream.Fetch(r, r.URL.Path)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		w.Write(body)
		return
	}

	var vi versionInfo
	if err := json.Unmarshal(body, &vi); err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	ok, err := h.evaluateVersionWithTime(ctx, modulePath, vi.Version, vi.Time)
	if err != nil {
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if !ok {
		h.logger.Info("latest version denied by policy", "module", modulePath, "version", vi.Version)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// handleVersionInfo fetches <ver>.info, evaluates the version, and
// returns 404 if denied.
func (h *Handler) handleVersionInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract module path and version from the URL.
	// Path format: /<module>/@v/<version>.info
	path := r.URL.Path
	atV := strings.LastIndex(path, "/@v/")
	if atV < 0 {
		h.upstream.Passthrough(w, r)
		return
	}
	modulePath := path[1:atV] // strip leading /
	versionFile := path[atV+4:]
	ver := strings.TrimSuffix(versionFile, ".info")

	body, statusCode, err := h.upstream.Fetch(r, path)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		w.Write(body)
		return
	}

	var vi versionInfo
	if err := json.Unmarshal(body, &vi); err != nil {
		// If parse fails, still evaluate with zero time.
		vi = versionInfo{Version: ver}
	}

	ok, err := h.evaluateVersionWithTime(ctx, modulePath, ver, vi.Time)
	if err != nil {
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if !ok {
		h.logger.Info("version denied by policy", "module", modulePath, "version", ver)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// evaluateVersion evaluates a Go module version against policy without
// a known publish time (will be fetched from .info if needed in future).
func (h *Handler) evaluateVersion(ctx context.Context, modulePath, version string) (bool, error) {
	return h.evaluateVersionWithTime(ctx, modulePath, version, time.Time{})
}

// evaluateVersionWithTime evaluates a Go module version against policy.
func (h *Handler) evaluateVersionWithTime(ctx context.Context, modulePath, version string, publishedAt time.Time) (bool, error) {
	pv := registry.PackageVersion{
		Name:        modulePath,
		Version:     version,
		Ecosystem:   registry.EcosystemGo,
		PublishedAt: publishedAt,
	}

	vulns, err := h.vulnDB.GetVulnerabilities(ctx, registry.EcosystemGo, modulePath, version)
	if err != nil {
		h.logger.Warn("vulnerability lookup failed", "module", modulePath, "version", version, "error", err)
	}

	input := registry.PolicyInput{
		Package:         pv,
		Vulnerabilities: vulns,
	}

	result, err := h.engine.Evaluate(ctx, input)
	if err != nil {
		return false, err
	}

	if !result.Allowed {
		h.logger.Info("version denied by policy",
			"module", modulePath,
			"version", version,
			"reasons", result.Reasons,
		)
	}

	if h.recorder != nil {
		h.recorder.Record("go", modulePath, version, result.Allowed, result.Reasons, len(vulns))
	}

	return result.Allowed, nil
}

// extractModulePath strips the suffix from the request path to get the module path.
func extractModulePath(path, suffix string) string {
	p := strings.TrimSuffix(path, suffix)
	return strings.TrimPrefix(p, "/")
}
