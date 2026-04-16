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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/handler"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/rewrite"
)

// Handler processes Go module proxy requests.
type Handler struct {
	handler.Base
}

// versionInfo is the JSON structure returned by @v/<ver>.info and @latest.
type versionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// NewHandler creates a new Go module proxy handler.
func NewHandler(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder, rewriter *rewrite.Engine) *Handler {
	return &Handler{
		Base: handler.NewBase(upstreamURL, engine, vulnDB, logger, recorder, rewriter, "gomod"),
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
		h.Upstream.Passthrough(w, r)
	}
}

// handleVersionList fetches the version list from upstream, evaluates
// each version against policy, and returns only allowed versions.
func (h *Handler) handleVersionList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	modulePath := extractModulePath(r.URL.Path, "/@v/list")

	upstreamURL := h.Upstream.BaseURL + r.URL.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	resp, err := h.Upstream.HTTPClient.Do(req)
	if err != nil {
		h.Logger.Error("upstream request failed", "url", upstreamURL, "error", err)
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
	var allVersions []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ver := strings.TrimSpace(scanner.Text())
		if ver == "" {
			continue
		}
		allVersions = append(allVersions, ver)
	}

	// Apply rewrite rules: remove versions that are rewritten to a different
	// version that also exists in the list.
	rewrittenAway := make(map[string]bool)
	if h.Rewriter != nil {
		versionSet := make(map[string]bool, len(allVersions))
		for _, v := range allVersions {
			versionSet[v] = true
		}
		for _, ver := range allVersions {
			rr := h.Rewriter.Apply("go", modulePath, ver)
			if rr.Matched && rr.Version != ver && versionSet[rr.Version] {
				h.Logger.Info("version rewritten",
					"module", modulePath,
					"from", ver,
					"to", rr.Version,
				)
				rewrittenAway[ver] = true
			}
		}
	}

	var allowed []string
	for _, ver := range allVersions {
		if rewrittenAway[ver] {
			continue
		}

		pv := registry.PackageVersion{
			Name:      modulePath,
			Version:   ver,
			Ecosystem: registry.EcosystemGo,
		}

		result, err := h.EvaluateVersion(ctx, pv)
		if err != nil {
			h.Logger.Error("policy evaluation failed", "module", modulePath, "version", ver, "error", err)
			continue
		}
		if result.Allowed {
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

	body, statusCode, err := h.Upstream.Fetch(r, r.URL.Path)
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

	pv := registry.PackageVersion{
		Name:        modulePath,
		Version:     vi.Version,
		Ecosystem:   registry.EcosystemGo,
		PublishedAt: vi.Time,
	}

	result, err := h.EvaluateVersion(ctx, pv)
	if err != nil {
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if !result.Allowed {
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
		h.Upstream.Passthrough(w, r)
		return
	}
	modulePath := path[1:atV] // strip leading /
	versionFile := path[atV+4:]
	ver := strings.TrimSuffix(versionFile, ".info")

	// Apply rewrite rules to the requested version.
	if h.Rewriter != nil {
		rr := h.Rewriter.Apply("go", modulePath, ver)
		if rr.Matched && rr.Version != ver {
			h.Logger.Info("version rewritten",
				"module", modulePath,
				"from", ver,
				"to", rr.Version,
			)
			if rr.Mode == "redirect" {
				newPath := fmt.Sprintf("/%s/@v/%s.info", modulePath, rr.Version)
				http.Redirect(w, r, newPath, http.StatusFound)
				return
			}
			// Transparent mode: fetch the rewritten version instead.
			ver = rr.Version
			path = fmt.Sprintf("/%s/@v/%s.info", modulePath, ver)
		}
	}

	body, statusCode, err := h.Upstream.Fetch(r, path)
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

	pv := registry.PackageVersion{
		Name:        modulePath,
		Version:     ver,
		Ecosystem:   registry.EcosystemGo,
		PublishedAt: vi.Time,
	}

	result, err := h.EvaluateVersion(ctx, pv)
	if err != nil {
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	if !result.Allowed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// extractModulePath strips the suffix from the request path to get the module path.
func extractModulePath(path, suffix string) string {
	p := strings.TrimSuffix(path, suffix)
	return strings.TrimPrefix(p, "/")
}
