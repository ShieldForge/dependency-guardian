// Package pypi implements the proxy handler for PyPI registry requests.
//
// PyPI clients (pip) request:
//
//	GET /simple/<package>/       -> package index page (HTML with links to files)
//	GET /pypi/<package>/json     -> JSON metadata for the package
//	GET /packages/...            -> actual package file downloads (passed through)
package pypi

import (
	"context"
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

// Handler processes PyPI registry requests.
type Handler struct {
	handler.Base
}

// NewHandler creates a new PyPI proxy handler.
func NewHandler(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder, rewriter *rewrite.Engine) *Handler {
	return &Handler{
		Base: handler.NewBase(upstreamURL, engine, vulnDB, logger, recorder, rewriter, "pypi"),
	}
}

// ServeHTTP routes PyPI requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case strings.HasPrefix(path, "/simple/"):
		// Simple API – HTML index of package files.
		// We pass this through; the JSON API is richer for filtering.
		h.Upstream.Passthrough(w, r)
	case isJSONMetadataRequest(path):
		h.handleJSONMetadata(w, r)
	default:
		// Package file downloads and everything else – pass through.
		h.Upstream.Passthrough(w, r)
	}
}

// handleJSONMetadata fetches /pypi/<pkg>/json from upstream, filters
// releases through OPA, and returns the modified JSON.
func (h *Handler) handleJSONMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	upstreamURL := h.Upstream.BaseURL + r.URL.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	filtered, err := h.filterMetadata(ctx, body)
	if err != nil {
		h.Logger.Error("filtering metadata failed", "error", err)
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered)
}

// filterMetadata parses PyPI JSON metadata, evaluates each release version
// against OPA policies, and removes disallowed versions.
func (h *Handler) filterMetadata(ctx context.Context, body []byte) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing pypi metadata: %w", err)
	}

	info, _ := doc["info"].(map[string]interface{})
	pkgName, _ := info["name"].(string)

	releases, ok := doc["releases"].(map[string]interface{})
	if !ok {
		return body, nil
	}

	var removed []string

	for ver, files := range releases {
		// Check rewrite rules before policy evaluation.
		if h.Rewriter != nil {
			rr := h.Rewriter.Apply("pypi", pkgName, ver)
			if rr.Matched && rr.Version != ver {
				if _, targetExists := releases[rr.Version]; targetExists {
					h.Logger.Info("version rewritten",
						"package", pkgName,
						"from", ver,
						"to", rr.Version,
					)
					delete(releases, ver)
					removed = append(removed, ver)
					continue
				}
			}
		}

		publishedAt := extractPyPIPublishTime(files)
		yanked := isYanked(files)

		pv := registry.PackageVersion{
			Name:        pkgName,
			Version:     ver,
			Ecosystem:   registry.EcosystemPyPI,
			PublishedAt: publishedAt,
			Yanked:      yanked,
		}

		result, err := h.EvaluateVersion(ctx, pv)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy for %s==%s: %w", pkgName, ver, err)
		}

		if !result.Allowed {
			delete(releases, ver)
			removed = append(removed, ver)
		}
	}

	// If the "info.version" (current release) was removed, clear it.
	if info != nil {
		if currentVer, ok := info["version"].(string); ok {
			for _, rv := range removed {
				if rv == currentVer {
					info["version"] = ""
					break
				}
			}
		}
	}

	return json.Marshal(doc)
}

// isJSONMetadataRequest returns true for paths like /pypi/<package>/json.
func isJSONMetadataRequest(path string) bool {
	return strings.HasPrefix(path, "/pypi/") && strings.HasSuffix(path, "/json")
}

// extractPyPIPublishTime gets the upload_time from the first file entry in a release.
func extractPyPIPublishTime(files interface{}) time.Time {
	fileList, ok := files.([]interface{})
	if !ok || len(fileList) == 0 {
		return time.Time{}
	}
	first, ok := fileList[0].(map[string]interface{})
	if !ok {
		return time.Time{}
	}

	// Try upload_time_iso_8601 first, then upload_time.
	for _, field := range []string{"upload_time_iso_8601", "upload_time"} {
		if ts, ok := first[field].(string); ok {
			for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04:05Z"} {
				if t, err := time.Parse(layout, ts); err == nil {
					return t
				}
			}
		}
	}
	return time.Time{}
}

// isYanked checks whether a release's files are all yanked.
func isYanked(files interface{}) bool {
	fileList, ok := files.([]interface{})
	if !ok || len(fileList) == 0 {
		return false
	}
	for _, f := range fileList {
		fm, ok := f.(map[string]interface{})
		if !ok {
			continue
		}
		if yanked, ok := fm["yanked"].(bool); ok && yanked {
			return true
		}
	}
	return false
}
