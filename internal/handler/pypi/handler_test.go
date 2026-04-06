package pypi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/testutil"
)

// --- Test helpers --------------------------------------------------------

const denyYankedRego = `
package guardian
import rego.v1

deny contains msg if {
	input.package.yanked == true
	msg := "yanked"
}
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

func TestIsJSONMetadataRequest(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/pypi/requests/json", true},
		{"/pypi/django/json", true},
		{"/pypi/flask/json", true},
		{"/simple/requests/", false},
		{"/packages/requests-2.28.0.tar.gz", false},
		{"/pypi/requests/", false},
		{"/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isJSONMetadataRequest(tt.path); got != tt.expected {
				t.Errorf("isJSONMetadataRequest(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtractPyPIPublishTime(t *testing.T) {
	tests := []struct {
		name     string
		files    interface{}
		wantZero bool
	}{
		{
			"valid_iso_8601",
			[]interface{}{
				map[string]interface{}{"upload_time_iso_8601": "2024-06-15T12:00:00Z"},
			},
			false,
		},
		{
			"valid_upload_time",
			[]interface{}{
				map[string]interface{}{"upload_time": "2024-06-15T12:00:00"},
			},
			false,
		},
		{
			"nil_files",
			nil,
			true,
		},
		{
			"empty_array",
			[]interface{}{},
			true,
		},
		{
			"non_map_entry",
			[]interface{}{"not-a-map"},
			true,
		},
		{
			"invalid_time",
			[]interface{}{
				map[string]interface{}{"upload_time": "invalid"},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPyPIPublishTime(tt.files)
			if tt.wantZero && !result.IsZero() {
				t.Errorf("expected zero time, got %v", result)
			}
			if !tt.wantZero && result.IsZero() {
				t.Error("expected non-zero time")
			}
		})
	}
}

func TestIsYanked(t *testing.T) {
	tests := []struct {
		name     string
		files    interface{}
		expected bool
	}{
		{
			"yanked_file",
			[]interface{}{map[string]interface{}{"yanked": true}},
			true,
		},
		{
			"not_yanked",
			[]interface{}{map[string]interface{}{"yanked": false}},
			false,
		},
		{
			"no_yanked_field",
			[]interface{}{map[string]interface{}{"filename": "test.tar.gz"}},
			false,
		},
		{
			"nil_files",
			nil,
			false,
		},
		{
			"empty_files",
			[]interface{}{},
			false,
		},
		{
			"non_map_entry",
			[]interface{}{"string"},
			false,
		},
		{
			"mixed_yanked_and_not",
			[]interface{}{
				map[string]interface{}{"yanked": false},
				map[string]interface{}{"yanked": true},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isYanked(tt.files); got != tt.expected {
				t.Errorf("isYanked() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- Integration tests ---------------------------------------------------

func TestHandler_SimpleAPIPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>simple index</html>"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/simple/requests/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "<html>simple index</html>" {
		t.Errorf("simple API should be passed through, got %q", w.Body.String())
	}
}

func TestHandler_PackageDownloadPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("package-data"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/packages/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandler_AllReleasesAllowed(t *testing.T) {
	pypiDoc := map[string]interface{}{
		"info": map[string]interface{}{
			"name":    "requests",
			"version": "2.28.0",
		},
		"releases": map[string]interface{}{
			"2.27.0": []interface{}{
				map[string]interface{}{"filename": "requests-2.27.0.tar.gz", "upload_time_iso_8601": "2024-01-01T00:00:00Z"},
			},
			"2.28.0": []interface{}{
				map[string]interface{}{"filename": "requests-2.28.0.tar.gz", "upload_time_iso_8601": "2024-06-01T00:00:00Z"},
			},
		},
	}
	body, _ := json.Marshal(pypiDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/pypi/requests/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	releases := result["releases"].(map[string]interface{})

	if len(releases) != 2 {
		t.Errorf("expected 2 releases, got %d", len(releases))
	}
}

func TestHandler_YankedVersionFiltered(t *testing.T) {
	pypiDoc := map[string]interface{}{
		"info": map[string]interface{}{
			"name":    "test-pkg",
			"version": "1.0.0",
		},
		"releases": map[string]interface{}{
			"0.9.0": []interface{}{
				map[string]interface{}{"filename": "test-0.9.0.tar.gz"},
			},
			"1.0.0": []interface{}{
				map[string]interface{}{"filename": "test-1.0.0.tar.gz", "yanked": true},
			},
		},
	}
	body, _ := json.Marshal(pypiDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyYankedRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/pypi/test-pkg/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	releases := result["releases"].(map[string]interface{})

	if _, ok := releases["0.9.0"]; !ok {
		t.Error("v0.9.0 should remain")
	}
	if _, ok := releases["1.0.0"]; ok {
		t.Error("v1.0.0 (yanked) should be removed")
	}

	// info.version should be cleared since it pointed to removed version
	info := result["info"].(map[string]interface{})
	if info["version"] != "" {
		t.Errorf("info.version should be cleared, got %v", info["version"])
	}
}

func TestHandler_MaliciousPyPIPackage(t *testing.T) {
	pypiDoc := map[string]interface{}{
		"info": map[string]interface{}{
			"name":    "evil-pkg",
			"version": "1.0.0",
		},
		"releases": map[string]interface{}{
			"1.0.0": []interface{}{
				map[string]interface{}{"filename": "evil-1.0.0.tar.gz"},
			},
		},
	}
	body, _ := json.Marshal(pypiDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyMaliciousRego)
	vulnDB := testutil.NewMockVulnDB()
	vulnDB.AddVuln("evil-pkg", "1.0.0", registry.VulnerabilityRecord{
		ID: "MAL-2024-001", IsMalicious: true,
	})

	h := NewHandler(upstream.URL, engine, vulnDB, slog.Default(), nil)

	req := httptest.NewRequest("GET", "/pypi/evil-pkg/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	releases := result["releases"].(map[string]interface{})

	if len(releases) != 0 {
		t.Errorf("expected 0 releases (malicious filtered), got %d", len(releases))
	}
}

func TestHandler_Upstream404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/pypi/nonexistent/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandler_NoReleasesKey(t *testing.T) {
	pypiDoc := map[string]interface{}{
		"info": map[string]interface{}{"name": "test"},
	}
	body, _ := json.Marshal(pypiDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/pypi/test/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestNewHandler_TrimsTrailingSlash(t *testing.T) {
	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler("https://pypi.org/", engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	if h.upstream.BaseURL != "https://pypi.org" {
		t.Errorf("expected trimmed upstream, got %s", h.upstream.BaseURL)
	}
	if h.upstream.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", h.upstream.HTTPClient.Timeout)
	}
}
