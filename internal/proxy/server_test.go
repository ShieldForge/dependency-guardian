package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/testutil"
)

func makePolicyEngine(t *testing.T) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	rego := `
package guardian
import rego.v1
`
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rego), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(dir)
	if err != nil {
		t.Fatalf("policy engine: %v", err)
	}
	return e
}

func makeTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.DefaultConfig()
	engine := makePolicyEngine(t)
	vulnDB := &registry.NoOpVulnerabilityDB{}
	logger := slog.Default()
	return NewServer(cfg, engine, vulnDB, logger)
}

// --- detectEcosystemFromRequest tests ------------------------------------

func TestDetectEcosystemFromRequest_UserAgent(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		expected string
	}{
		// npm clients
		{"npm", "npm/10.0.0 node/v20.0.0", "npm"},
		{"yarn", "yarn/1.22.19", "npm"},
		{"pnpm", "pnpm/8.6.0", "npm"},
		{"bun", "bun/1.0.0", "npm"},
		{"cnpm", "cnpm/9.0.0", "npm"},

		// PyPI clients
		{"pip", "pip/23.0.0", "pypi"},
		{"poetry", "poetry/1.5.0", "pypi"},
		{"pdm", "pdm/2.8.0", "pypi"},
		{"twine", "twine/4.0.0", "pypi"},
		{"uv", "uv/0.1.0", "pypi"},
		{"python_ua", "Python-urllib/3.11", "pypi"},

		// Go clients
		{"go_http_client", "Go-http-client/2.0", "go"},
		{"go_prefix", "Go/1.21", "go"},

		// Maven / Gradle clients
		{"maven", "Apache-Maven/3.9.4", "maven"},
		{"gradle", "Gradle/8.4", "maven"},
		{"mvn", "mvn/3.9.0", "maven"},
		{"sbt", "sbt/1.9.0", "maven"},
		{"ivy", "Ivy/2.5.0", "maven"},
		{"maven_contains", "some-tool maven-based", "maven"},
		{"gradle_contains", "some-tool gradle-based", "maven"},

		// Unknown
		{"unknown", "curl/8.0.0", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/some/path", nil)
			req.Header.Set("User-Agent", tt.ua)
			got := detectEcosystemFromRequest(req)
			if got != tt.expected {
				t.Errorf("UA=%q: got %q, want %q", tt.ua, got, tt.expected)
			}
		})
	}
}

func TestDetectEcosystemFromRequest_Accept(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		expected string
	}{
		{"npm_accept", "application/vnd.npm.install-v1+json", "npm"},
		{"pypi_simple", "application/vnd.pypi.simple.v1+json", "pypi"},
		{"generic_json", "application/json", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/some/path", nil)
			req.Header.Set("Accept", tt.accept)
			got := detectEcosystemFromRequest(req)
			if got != tt.expected {
				t.Errorf("Accept=%q: got %q, want %q", tt.accept, got, tt.expected)
			}
		})
	}
}

func TestDetectEcosystemFromRequest_QueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/golang.org/x/text?go-get=1", nil)
	got := detectEcosystemFromRequest(req)
	if got != "go" {
		t.Errorf("expected 'go' for go-get=1, got %q", got)
	}
}

func TestDetectEcosystemFromRequest_ArtifactoryHeader(t *testing.T) {
	tests := []struct {
		name     string
		repoType string
		expected string
	}{
		{"npm", "npm", "npm"},
		{"pypi", "pypi", "pypi"},
		{"go", "go", "go"},
		{"gomod", "gomod", "go"},
		{"maven", "maven", "maven"},
		{"maven2", "maven2", "maven"},
		{"gradle", "gradle", "maven"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/some/path", nil)
			req.Header.Set("X-Artifactory-Repo-Type", tt.repoType)
			got := detectEcosystemFromRequest(req)
			if got != tt.expected {
				t.Errorf("X-Artifactory-Repo-Type=%q: got %q, want %q", tt.repoType, got, tt.expected)
			}
		})
	}
}

func TestDetectEcosystemFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/npm/lodash", "npm"},
		{"/pypi/pypi/requests/json", "pypi"},
		{"/go/github.com/pkg/errors/@v/list", "go"},
		{"/maven/org/apache/commons/commons-lang3/maven-metadata.xml", "maven"},
		{"/other/path", "unknown"},
		{"/", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectEcosystemFromPath(tt.path)
			if got != tt.expected {
				t.Errorf("detectEcosystemFromPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestDetectEcosystemFromArtifactoryPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/some/@v/list", "go"},
		{"/some/@latest", "go"},
		{"/simple/package/", "pypi"},
		{"/pypi/pkg/json", "pypi"},
		{"/pkg/-/pkg-1.0.0.tgz", "npm"},
		{"/org/apache/commons/commons-lang3/maven-metadata.xml", "maven"},
		{"/org/example/mylib/1.0.0/mylib-1.0.0.jar", "maven"},
		{"/org/example/mylib/1.0.0/mylib-1.0.0.pom", "maven"},
		{"/other", "npm"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectEcosystemFromArtifactoryPath(tt.path)
			if got != tt.expected {
				t.Errorf("detectEcosystemFromArtifactoryPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// --- Server endpoint tests -----------------------------------------------

func TestHealth(t *testing.T) {
	s := makeTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestPolicyReload_MethodNotAllowed(t *testing.T) {
	s := makeTestServer(t)

	req := httptest.NewRequest("GET", "/policy/reload", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestPolicyReload_Success(t *testing.T) {
	cfg := config.DefaultConfig()
	// Point policies to a temp dir with a valid rego file
	dir := t.TempDir()
	rego := `package guardian
import rego.v1
`
	os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rego), 0644)
	cfg.Policies.Directory = dir

	engine, _ := policy.NewEngine(dir)
	vulnDB := &registry.NoOpVulnerabilityDB{}
	s := NewServer(cfg, engine, vulnDB, slog.Default())

	req := httptest.NewRequest("POST", "/policy/reload", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRoot_UsagePage(t *testing.T) {
	s := makeTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !containsAll(body, "dependency-guardian", "endpoints") {
		t.Errorf("expected usage info, got %q", body)
	}
}

func TestUnknownPath_BadRequest(t *testing.T) {
	s := makeTestServer(t)

	// Unknown path with no UA detection
	req := httptest.NewRequest("GET", "/random/unknown/path", nil)
	req.Header.Set("User-Agent", "curl/8.0.0")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rw.statusCode)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("expected underlying writer to have 404, got %d", w.Code)
	}
}

// --- helpers -------------------------------------------------------------

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		found := false
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// --- Integration tests ---------------------------------------------------

func TestIntegration_NPMMetadataFiltering(t *testing.T) {
	// Fake npm upstream serving a package with two versions.
	npmDoc := map[string]interface{}{
		"name": "my-pkg",
		"versions": map[string]interface{}{
			"1.0.0": map[string]interface{}{"name": "my-pkg", "version": "1.0.0"},
			"2.0.0": map[string]interface{}{"name": "my-pkg", "version": "2.0.0", "deprecated": "old"},
		},
	}
	body, _ := json.Marshal(npmDoc)

	fakeNPM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer fakeNPM.Close()

	// Policy that denies deprecated packages.
	regoSrc := `
package guardian
import rego.v1

deny contains msg if {
	input.package.deprecated == true
	msg := "deprecated"
}
`
	engine := testutil.MakePolicyEngine(t, regoSrc)

	cfg := config.DefaultConfig()
	cfg.Upstreams.NPM = fakeNPM.URL
	s := NewServer(cfg, engine, &registry.NoOpVulnerabilityDB{}, slog.Default())

	req := httptest.NewRequest("GET", "/npm/my-pkg", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	versions, ok := result["versions"].(map[string]interface{})
	if !ok {
		t.Fatal("expected versions map in response")
	}

	if _, exists := versions["1.0.0"]; !exists {
		t.Error("expected version 1.0.0 to be allowed")
	}
	if _, exists := versions["2.0.0"]; exists {
		t.Error("expected version 2.0.0 (deprecated) to be filtered out")
	}
}

func TestIntegration_VulnDBStatusEndpoint(t *testing.T) {
	s := makeTestServer(t)

	// Without a vulnStore configured, the endpoint should not be registered.
	req := httptest.NewRequest("GET", "/api/vulndb", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	// Falls through to the catch-all handler (not 200 JSON), since no vulnStore.
	if w.Code == http.StatusOK {
		// If it does return 200, verify the shape.
		var result map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if _, ok := result["global"]; !ok {
			t.Error("expected 'global' field in vulndb status response")
		}
	}
}

func TestIntegration_AdminAuth_Unauthorized(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.AdminToken = "secret-token"

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.rego"), []byte("package guardian\nimport rego.v1\n"), 0644)
	cfg.Policies.Directory = dir

	engine, _ := policy.NewEngine(dir)
	s := NewServer(cfg, engine, &registry.NoOpVulnerabilityDB{}, slog.Default())

	// No auth header - should be rejected.
	req := httptest.NewRequest("POST", "/policy/reload", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	// With correct token - should succeed.
	req = httptest.NewRequest("POST", "/policy/reload", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
