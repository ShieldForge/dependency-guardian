package gomod

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/testutil"
)

// --- Test helpers --------------------------------------------------------

const denyAllRego = `
package guardian
import rego.v1

deny contains "denied by policy" if { true }
`

const denyMaliciousRego = `
package guardian
import rego.v1

deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.is_malicious == true
	msg := sprintf("malicious: %s", [vuln.id])
}
`

// --- Unit tests ----------------------------------------------------------

func TestExtractModulePath(t *testing.T) {
	tests := []struct {
		path     string
		suffix   string
		expected string
	}{
		{"/github.com/pkg/errors/@v/list", "/@v/list", "github.com/pkg/errors"},
		{"/golang.org/x/text/@latest", "/@latest", "golang.org/x/text"},
		{"/example.com/mod/@v/list", "/@v/list", "example.com/mod"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractModulePath(tt.path, tt.suffix)
			if got != tt.expected {
				t.Errorf("extractModulePath(%q, %q) = %q, want %q", tt.path, tt.suffix, got, tt.expected)
			}
		})
	}
}

// --- Integration tests ---------------------------------------------------

func TestHandler_VersionList_AllAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("v1.0.0\nv1.1.0\nv2.0.0\n"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@v/list", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 versions, got %d: %v", len(lines), lines)
	}
}

func TestHandler_VersionList_SomeFiltered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("v1.0.0\nv1.1.0\nv2.0.0\n"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@v/list", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := strings.TrimSpace(w.Body.String())
	if body != "" {
		t.Errorf("expected empty version list, got %q", body)
	}
}

func TestHandler_Latest_Allowed(t *testing.T) {
	vi := versionInfo{
		Version: "v2.0.0",
		Time:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	body, _ := json.Marshal(vi)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@latest", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result versionInfo
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Version != "v2.0.0" {
		t.Errorf("expected v2.0.0, got %s", result.Version)
	}
}

func TestHandler_Latest_Denied(t *testing.T) {
	vi := versionInfo{
		Version: "v2.0.0",
		Time:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	body, _ := json.Marshal(vi)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@latest", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandler_VersionInfo_Allowed(t *testing.T) {
	vi := versionInfo{
		Version: "v1.0.0",
		Time:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	body, _ := json.Marshal(vi)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@v/v1.0.0.info", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandler_VersionInfo_Denied(t *testing.T) {
	vi := versionInfo{
		Version: "v1.0.0",
		Time:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	body, _ := json.Marshal(vi)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/pkg/errors/@v/v1.0.0.info", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandler_ModFile_Passthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("module example.com/mod\n\ngo 1.21\n"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego) // policy denied, but .mod passthrough
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/example.com/mod/@v/v1.0.0.mod", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "module example.com/mod") {
		t.Error("expected mod file content")
	}
}

func TestHandler_ZipFile_Passthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write([]byte("zip-bytes"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/example.com/mod/@v/v1.0.0.zip", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandler_Upstream404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/nonexistent/@v/list", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandler_MaliciousVersionFiltered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("v1.0.0\nv1.1.0\n"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyMaliciousRego)
	vulnDB := testutil.NewMockVulnDB()
	vulnDB.AddVuln("github.com/evil/mod", "v1.0.0", registry.VulnerabilityRecord{
		ID: "MAL-2024-001", IsMalicious: true,
	})

	h := NewHandler(upstream.URL, engine, vulnDB, slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/github.com/evil/mod/@v/list", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	for _, line := range lines {
		if line == "v1.0.0" {
			t.Error("v1.0.0 (malicious) should be filtered out")
		}
	}
}

func TestNewHandler_TrimsTrailingSlash(t *testing.T) {
	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler("https://proxy.golang.org/", engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	if h.upstream.BaseURL != "https://proxy.golang.org" {
		t.Errorf("expected trimmed upstream, got %s", h.upstream.BaseURL)
	}
	if h.upstream.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", h.upstream.HTTPClient.Timeout)
	}
}
