// Package proxy provides the top-level HTTP server that routes requests
// to the appropriate ecosystem handler based on request path or
// configuration.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/handler/gomod"
	"dependency-guardian/internal/handler/maven"
	"dependency-guardian/internal/handler/npm"
	"dependency-guardian/internal/handler/pypi"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/vulndb"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/models"
)

// Server is the main proxy server.
type Server struct {
	cfg    *config.Config
	engine *policy.Engine
	vulnDB registry.VulnerabilityDB
	logger *slog.Logger
	mux    *http.ServeMux
	srv    *http.Server

	// Decision log for VS Code extension mode.
	decisionLog *decisions.Log

	// Vulnerability database store for API endpoints.
	vulnStore *dal.Store

	// Ecosystem handlers stored for header-based routing.
	npmHandler   http.Handler
	pypiHandler  http.Handler
	goHandler    http.Handler
	mavenHandler http.Handler
}

// NewServer creates a new proxy server with all ecosystem handlers wired up.
func NewServer(cfg *config.Config, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, opts ...ServerOption) *Server {
	s := &Server{
		cfg:    cfg,
		engine: engine,
		vulnDB: vulnDB,
		logger: logger,
		mux:    http.NewServeMux(),
	}

	for _, opt := range opts {
		opt(s)
	}

	s.registerHandlers()

	s.srv = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      s.loggingMiddleware(s.mux),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	return s
}

// ServerOption configures optional server features.
type ServerOption func(*Server)

// WithDecisionLog enables decision logging for the VS Code extension mode.
func WithDecisionLog(log *decisions.Log) ServerOption {
	return func(s *Server) {
		s.decisionLog = log
	}
}

// WithVulnDBStore enables vulnerability database API endpoints.
func WithVulnDBStore(store *dal.Store) ServerOption {
	return func(s *Server) {
		s.vulnStore = store
	}
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	s.logger.Info("starting proxy server", "addr", s.cfg.Server.ListenAddr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// registerHandlers sets up routes for each ecosystem.
//
// Routing strategy:
//
//	/npm/...   -> npm handler   (strip /npm prefix)
//	/pypi/...  -> pypi handler  (strip /pypi prefix)
//	/go/...    -> go handler    (strip /go prefix)
//	/health    -> health check
//	/policy/reload -> reload Rego policies
//
// When a client points directly at this proxy (e.g. npm registry = http://proxy:8080/npm/),
// the path prefix indicates the ecosystem.
func (s *Server) registerHandlers() {
	// Avoid passing a typed-nil *Log as an interface - it would appear non-nil
	// to the handler's nil check and cause a nil-pointer dereference.
	var recorder decisions.Recorder
	if s.decisionLog != nil {
		recorder = s.decisionLog
	}

	s.npmHandler = npm.NewHandler(s.cfg.Upstreams.NPM, s.engine, s.vulnDB, s.logger, recorder)
	s.pypiHandler = pypi.NewHandler(s.cfg.Upstreams.PyPI, s.engine, s.vulnDB, s.logger, recorder)
	s.goHandler = gomod.NewHandler(s.cfg.Upstreams.Go, s.engine, s.vulnDB, s.logger, recorder)
	s.mavenHandler = maven.NewHandler(s.cfg.Upstreams.Maven, s.engine, s.vulnDB, s.logger, recorder)

	// Explicit path-prefix routes (highest priority).
	s.mux.Handle("/npm/", http.StripPrefix("/npm", s.npmHandler))
	s.mux.Handle("/pypi/", http.StripPrefix("/pypi", s.pypiHandler))
	s.mux.Handle("/go/", http.StripPrefix("/go", s.goHandler))
	s.mux.Handle("/maven/", http.StripPrefix("/maven", s.mavenHandler))

	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/policy/reload", s.requireAdmin(s.handlePolicyReload))

	// API endpoints for VS Code extension.
	if s.decisionLog != nil {
		s.mux.HandleFunc("/api/decisions", s.decisionLog.HandleDecisions)
		s.mux.HandleFunc("/api/stats", s.decisionLog.HandleStats)
	}
	if s.vulnStore != nil {
		s.mux.HandleFunc("/api/vulndb", s.handleVulnDBStatus)
		s.mux.HandleFunc("/api/lookup", s.handleLookup)
	}

	// Catch-all: detect ecosystem from request headers / query params.
	s.mux.HandleFunc("/", s.handleAutoDetect)
}

// handleHealth returns a simple health check.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// requireAdmin wraps an HTTP handler with bearer-token authentication.
// If no admin_token is configured, the handler is called without auth
// (suitable for localhost / VS Code mode).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.cfg.Server.AdminToken
		if token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// handlePolicyReload reloads Rego policies from disk.
func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.engine.Reload(s.cfg.Policies.Directory); err != nil {
		s.logger.Error("policy reload failed", "error", err)
		http.Error(w, fmt.Sprintf("policy reload failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.logger.Info("policies reloaded successfully")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"reloaded"}`)
}

// handleAutoDetect inspects request headers and query parameters to
// determine which package manager client is making the request, and
// routes to the appropriate ecosystem handler. If the ecosystem cannot
// be determined and the path is "/", a usage page is returned.
func (s *Server) handleAutoDetect(w http.ResponseWriter, r *http.Request) {
	eco := detectEcosystemFromRequest(r)

	switch eco {
	case "npm":
		s.logger.Debug("auto-detected npm client from headers", "user_agent", r.UserAgent())
		s.npmHandler.ServeHTTP(w, r)
	case "pypi":
		s.logger.Debug("auto-detected pypi client from headers", "user_agent", r.UserAgent())
		s.pypiHandler.ServeHTTP(w, r)
	case "go":
		s.logger.Debug("auto-detected go client from headers", "user_agent", r.UserAgent())
		s.goHandler.ServeHTTP(w, r)
	case "maven":
		s.logger.Debug("auto-detected maven client from headers", "user_agent", r.UserAgent())
		s.mavenHandler.ServeHTTP(w, r)
	default:
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
  "service": "dependency-guardian",
  "endpoints": {
    "npm":    "/npm/<package>",
    "pypi":   "/pypi/pypi/<package>/json",
    "go":     "/go/<module>/@v/list",
    "maven":  "/maven/<group-path>/<artifact>/maven-metadata.xml",
    "health": "/health",
    "reload": "POST /policy/reload"
  },
  "note": "Ecosystem can also be auto-detected from client User-Agent headers"
}`)
			return
		}
		s.logger.Warn("could not detect ecosystem", "path", r.URL.Path, "user_agent", r.UserAgent())
		http.Error(w, "could not determine package ecosystem from request headers or path; use /npm/, /pypi/, /go/, or /maven/ prefix", http.StatusBadRequest)
	}
}

// loggingMiddleware logs each request.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		ecosystem := detectEcosystemFromRequest(r)
		if ecosystem == "" {
			ecosystem = detectEcosystemFromPath(r.URL.Path)
		}
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"ecosystem", ecosystem,
			"status", rw.statusCode,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleVulnDBStatus returns vulnerability database metrics and sync state.
func (s *Server) handleVulnDBStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	globalStats, err := s.vulnStore.GetGlobalStats(ctx)
	if err != nil {
		s.logger.Error("failed to get global vulndb stats", "error", err)
		globalStats = map[string]interface{}{"error": err.Error()}
	}

	syncStates, err := s.vulnStore.ListSyncStates(ctx)
	if err != nil {
		s.logger.Error("failed to list sync states", "error", err)
	}

	type ecosystemInfo struct {
		Ecosystem            string  `json:"ecosystem"`
		Status               string  `json:"status"`
		LastFullSync         *string `json:"last_full_sync"`
		LastDeltaSync        *string `json:"last_delta_sync"`
		LastError            string  `json:"last_error,omitempty"`
		TotalVulnerabilities int64   `json:"total_vulnerabilities"`
		TotalAffectedEntries int64   `json:"total_affected_entries"`
	}

	ecosystems := make([]ecosystemInfo, 0, len(syncStates))
	for _, st := range syncStates {
		info := ecosystemInfo{
			Ecosystem:            st.Ecosystem,
			Status:               st.Status,
			LastError:            st.LastError,
			TotalVulnerabilities: st.TotalVulnerabilities,
			TotalAffectedEntries: st.TotalAffectedEntries,
		}
		if st.LastFullSync != nil {
			s := st.LastFullSync.Format(time.RFC3339)
			info.LastFullSync = &s
		}
		if st.LastDeltaSync != nil {
			s := st.LastDeltaSync.Format(time.RFC3339)
			info.LastDeltaSync = &s
		}
		ecosystems = append(ecosystems, info)
	}

	result := map[string]interface{}{
		"global":     globalStats,
		"ecosystems": ecosystems,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleLookup returns known vulnerabilities for a given package.
// Query parameters: ecosystem (required), name (required), version (optional).
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.URL.Query().Get("ecosystem")
	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")
	if ecosystem == "" || name == "" {
		http.Error(w, `{"error":"ecosystem and name query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Map proxy-facing ecosystem names to OSV ecosystem names stored in the DB.
	osvEcosystem := mapLookupEcosystem(ecosystem)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var records []models.AffectedPackageIndex
	var err error
	if version != "" {
		records, err = s.vulnStore.FindVulnerabilitiesByPackageVersion(ctx, osvEcosystem, name, version)
	} else {
		records, err = s.vulnStore.FindVulnerabilitiesByPackage(ctx, osvEcosystem, name)
	}
	if err != nil {
		s.logger.Error("lookup failed", "ecosystem", ecosystem, "name", name, "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	type vulnEntry struct {
		OsvID       string `json:"osv_id"`
		MaxSeverity string `json:"max_severity"`
		IsMalicious bool   `json:"is_malicious"`
		Version     string `json:"version,omitempty"`
	}

	// Deduplicate by OsvID and filter range-based constraints.
	seen := make(map[string]bool, len(records))
	entries := make([]vulnEntry, 0, len(records))
	for _, rec := range records {
		if seen[rec.OsvID] {
			continue
		}

		// When a specific version was requested, filter out range-based
		// records that don't actually cover that version.
		if version != "" && rec.ExactVersion == "" && rec.VersionConstraint != "" {
			if !vulndb.VersionMatchesConstraint(version, rec.VersionConstraint, osvEcosystem) {
				continue
			}
		}

		seen[rec.OsvID] = true
		entries = append(entries, vulnEntry{
			OsvID:       rec.OsvID,
			MaxSeverity: rec.MaxSeverity,
			IsMalicious: rec.IsMalicious,
			Version:     rec.ExactVersion,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ecosystem":       ecosystem,
		"name":            name,
		"vulnerabilities": entries,
		"total":           len(entries),
	})
}

// mapLookupEcosystem converts the proxy-facing ecosystem identifiers
// (lowercase) to the OSV ecosystem names stored in the database.
func mapLookupEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	case "maven":
		return "Maven"
	default:
		return eco
	}
}

// detectEcosystemFromPath returns the ecosystem from the URL path prefix.
func detectEcosystemFromPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/npm/"):
		return "npm"
	case strings.HasPrefix(path, "/pypi/"):
		return "pypi"
	case strings.HasPrefix(path, "/go/"):
		return "go"
	case strings.HasPrefix(path, "/maven/"):
		return "maven"
	default:
		return "unknown"
	}
}

// detectEcosystemFromRequest inspects the User-Agent header, Accept
// headers, query parameters, and other request signals to determine
// which package ecosystem the client belongs to.
//
// Known client signatures:
//
//	npm:     User-Agent starts with "npm/", "yarn/", "pnpm/", "bun/"
//	         or contains "node" / "npm".
//	PyPI:    User-Agent starts with "pip/", "poetry/", "pdm/", "twine/",
//	         "bandersnatch/", "uv/", or contains "python".
//	         Accept header contains "application/vnd.pypi.simple".
//	Go:      User-Agent starts with "Go-http-client/" or "Go/".
//	         Query string contains "go-get=1".
//	Artifactory: X-Artifactory headers or User-Agent containing
//	         "Artifactory" – combined with Accept or path heuristics.
func detectEcosystemFromRequest(r *http.Request) string {
	ua := strings.ToLower(r.UserAgent())
	accept := strings.ToLower(r.Header.Get("Accept"))

	// ── Go module clients ────────────────────────────────────────
	// Go toolchain sends ?go-get=1 for discovery and uses
	// "Go-http-client" as the user-agent.
	if r.URL.Query().Get("go-get") == "1" {
		return "go"
	}
	for _, prefix := range []string{"go-http-client/", "go/", "golang"} {
		if strings.HasPrefix(ua, prefix) || strings.Contains(ua, prefix) {
			return "go"
		}
	}

	// ── npm clients ──────────────────────────────────────────────
	for _, prefix := range []string{"npm/", "yarn/", "pnpm/", "bun/", "cnpm/", "verdaccio/"} {
		if strings.HasPrefix(ua, prefix) {
			return "npm"
		}
	}
	if strings.Contains(ua, "node") || strings.Contains(ua, "npm") {
		return "npm"
	}
	// npm clients typically request application/json or application/vnd.npm.install-v1+json.
	if strings.Contains(accept, "vnd.npm") {
		return "npm"
	}

	// ── PyPI clients ─────────────────────────────────────────────
	for _, prefix := range []string{"pip/", "poetry/", "pdm/", "twine/", "bandersnatch/", "uv/", "setuptools/"} {
		if strings.HasPrefix(ua, prefix) {
			return "pypi"
		}
	}
	if strings.Contains(ua, "python") || strings.Contains(ua, "pypi") {
		return "pypi"
	}
	if strings.Contains(accept, "vnd.pypi.simple") {
		return "pypi"
	}

	// ── Maven / Gradle clients ──────────────────────────────────
	for _, prefix := range []string{"apache-maven/", "gradle/", "mvn/", "ivy/", "sbt/", "leiningen/", "buildr/"} {
		if strings.HasPrefix(ua, prefix) {
			return "maven"
		}
	}
	if strings.Contains(ua, "maven") || strings.Contains(ua, "gradle") {
		return "maven"
	}

	// ── Artifactory ──────────────────────────────────────────────
	// Artifactory proxies set X-Artifactory-* headers. We look at
	// the repo type header or fall back to path/accept heuristics.
	if artType := r.Header.Get("X-Artifactory-Repo-Type"); artType != "" {
		switch strings.ToLower(artType) {
		case "npm":
			return "npm"
		case "pypi":
			return "pypi"
		case "go", "gomod":
			return "go"
		case "maven", "maven2", "gradle":
			return "maven"
		}
	}
	if strings.Contains(ua, "artifactory") {
		// Try to guess from path heuristics.
		return detectEcosystemFromArtifactoryPath(r.URL.Path)
	}

	return ""
}

// detectEcosystemFromArtifactoryPath tries to infer the ecosystem from
// path patterns when the request comes from Artifactory but has no
// explicit repo-type header.
func detectEcosystemFromArtifactoryPath(path string) string {
	switch {
	case strings.Contains(path, "/@v/") || strings.Contains(path, "/@latest"):
		return "go"
	case strings.Contains(path, "/simple/") || strings.HasSuffix(path, "/json"):
		return "pypi"
	case strings.Contains(path, "/-/"):
		return "npm"
	case strings.HasSuffix(path, "/maven-metadata.xml") || strings.HasSuffix(path, ".jar") || strings.HasSuffix(path, ".pom"):
		return "maven"
	default:
		// Default Artifactory to npm since it's the most common.
		return "npm"
	}
}
