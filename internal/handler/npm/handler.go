// Package npm implements the proxy handler for npm registry requests.
//
// npm clients request:
//
//	GET /<package>              -> package metadata (JSON document with all versions)
//	GET /<@scope>/<package>     -> scoped package metadata
//	GET /<package>/-/<tarball>  -> package tarball (passed through unmodified)
package npm

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
	"dependency-guardian/internal/handler/upstream"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/rewrite"
)

// Handler processes npm registry requests.
type Handler struct {
	upstream *upstream.Client
	engine   *policy.Engine
	vulnDB   registry.VulnerabilityDB
	logger   *slog.Logger
	recorder decisions.Recorder
	rewriter *rewrite.Engine
}

// NewHandler creates a new npm proxy handler.
func NewHandler(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder, rewriter *rewrite.Engine) *Handler {
	return &Handler{
		upstream: upstream.NewClient(strings.TrimRight(upstreamURL, "/"), 30*time.Second),
		engine:   engine,
		vulnDB:   vulnDB,
		logger:   logger.With("handler", "npm"),
		recorder: recorder,
		rewriter: rewriter,
	}
}

// ServeHTTP routes npm requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Tarball downloads are proxied through without filtering.
	if isTarballRequest(path) {
		h.upstream.Passthrough(w, r)
		return
	}

	// Everything else is treated as a metadata request.
	h.handleMetadata(w, r)
}

// handleMetadata fetches package metadata from the upstream, filters
// versions through OPA, and returns the modified metadata.
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	upstreamURL := h.upstream.BaseURL + r.URL.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}
	// npm clients send Accept: application/json or abbreviated metadata headers.
	req.Header.Set("Accept", "application/json")

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	filtered, err := h.filterMetadata(ctx, body)
	if err != nil {
		h.logger.Error("filtering metadata failed", "error", err)
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered)
}

// filterMetadata parses the npm metadata JSON, evaluates each version
// against OPA policies, and removes disallowed versions.
func (h *Handler) filterMetadata(ctx context.Context, body []byte) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing npm metadata: %w", err)
	}

	pkgName, _ := doc["name"].(string)

	versions, ok := doc["versions"].(map[string]interface{})
	if !ok {
		// No versions to filter – return as-is.
		return body, nil
	}

	// Collect the time map so we can extract publish dates.
	timesMap, _ := doc["time"].(map[string]interface{})

	var removed []string

	for ver := range versions {
		// Check rewrite rules before policy evaluation.
		if h.rewriter != nil {
			rr := h.rewriter.Apply("npm", pkgName, ver)
			if rr.Matched && rr.Version != ver {
				if _, targetExists := versions[rr.Version]; targetExists {
					h.logger.Info("version rewritten",
						"package", pkgName,
						"from", ver,
						"to", rr.Version,
					)
					delete(versions, ver)
					removed = append(removed, ver)
					continue
				}
			}
		}

		publishedAt := extractPublishTime(timesMap, ver)

		pv := registry.PackageVersion{
			Name:        pkgName,
			Version:     ver,
			Ecosystem:   registry.EcosystemNPM,
			PublishedAt: publishedAt,
			Deprecated:  isDeprecated(versions[ver]),
		}

		vulns, err := h.vulnDB.GetVulnerabilities(ctx, registry.EcosystemNPM, pkgName, ver)
		if err != nil {
			h.logger.Warn("vulnerability lookup failed", "package", pkgName, "version", ver, "error", err)
		}

		input := registry.PolicyInput{
			Package:         pv,
			Vulnerabilities: vulns,
		}

		result, err := h.engine.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy for %s@%s: %w", pkgName, ver, err)
		}

		if h.recorder != nil {
			h.recorder.Record("npm", pkgName, ver, result.Allowed, result.Reasons, len(vulns))
		}

		if !result.Allowed {
			h.logger.Info("version denied by policy",
				"package", pkgName,
				"version", ver,
				"reasons", result.Reasons,
			)
			delete(versions, ver)
			removed = append(removed, ver)
		}
	}

	// Clean up dist-tags pointing to removed versions.
	if distTags, ok := doc["dist-tags"].(map[string]interface{}); ok {
		cleanDistTags(distTags, versions, removed)
	}

	// Remove filtered versions from the time map.
	if timesMap != nil {
		for _, ver := range removed {
			delete(timesMap, ver)
		}
	}

	return json.Marshal(doc)
}

// isTarballRequest returns true if the path looks like a tarball download.
// npm tarball URLs contain /-/ (e.g. /lodash/-/lodash-4.17.21.tgz).
func isTarballRequest(path string) bool {
	return strings.Contains(path, "/-/")
}

// extractPublishTime extracts the publish timestamp for a version from
// the npm "time" map.
func extractPublishTime(timesMap map[string]interface{}, version string) time.Time {
	if timesMap == nil {
		return time.Time{}
	}
	if ts, ok := timesMap[version].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

// isDeprecated checks whether a version entry has a deprecation notice.
func isDeprecated(versionEntry interface{}) bool {
	m, ok := versionEntry.(map[string]interface{})
	if !ok {
		return false
	}
	_, exists := m["deprecated"]
	return exists
}

// cleanDistTags removes dist-tag entries that point to versions that
// have been filtered out, and tries to retarget "latest" to the
// highest remaining version.
func cleanDistTags(distTags map[string]interface{}, versions map[string]interface{}, removed []string) {
	removedSet := make(map[string]struct{}, len(removed))
	for _, v := range removed {
		removedSet[v] = struct{}{}
	}

	for tag, ver := range distTags {
		verStr, _ := ver.(string)
		if _, wasRemoved := removedSet[verStr]; wasRemoved {
			delete(distTags, tag)
		}
	}
}
