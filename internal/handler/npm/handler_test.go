package npm

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

const denyDeprecatedRego = `
package guardian
import rego.v1

deny contains msg if {
	input.package.deprecated == true
	msg := "deprecated"
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

func TestIsTarballRequest(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/lodash/-/lodash-4.17.21.tgz", true},
		{"/@scope/pkg/-/pkg-1.0.0.tgz", true},
		{"/lodash", false},
		{"/@scope/pkg", false},
		{"/-/all", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isTarballRequest(tt.path); got != tt.expected {
				t.Errorf("isTarballRequest(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtractPublishTime(t *testing.T) {
	tests := []struct {
		name     string
		timesMap map[string]interface{}
		version  string
		wantZero bool
	}{
		{"nil_map", nil, "1.0.0", true},
		{"version_missing", map[string]interface{}{"2.0.0": "2024-01-01T00:00:00Z"}, "1.0.0", true},
		{"valid_rfc3339", map[string]interface{}{"1.0.0": "2024-06-15T12:00:00Z"}, "1.0.0", false},
		{"invalid_format", map[string]interface{}{"1.0.0": "not-a-date"}, "1.0.0", true},
		{"non_string", map[string]interface{}{"1.0.0": 12345}, "1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPublishTime(tt.timesMap, tt.version)
			if tt.wantZero && !result.IsZero() {
				t.Errorf("expected zero time, got %v", result)
			}
			if !tt.wantZero && result.IsZero() {
				t.Error("expected non-zero time")
			}
		})
	}
}

func TestIsDeprecated(t *testing.T) {
	tests := []struct {
		name     string
		entry    interface{}
		expected bool
	}{
		{"deprecated_string", map[string]interface{}{"deprecated": "Use v2"}, true},
		{"not_deprecated", map[string]interface{}{"version": "1.0.0"}, false},
		{"nil_entry", nil, false},
		{"non_map", "string", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeprecated(tt.entry); got != tt.expected {
				t.Errorf("isDeprecated() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCleanDistTags(t *testing.T) {
	t.Run("removes_tags_for_removed_versions", func(t *testing.T) {
		distTags := map[string]interface{}{
			"latest": "2.0.0",
			"next":   "3.0.0-beta",
			"old":    "1.0.0",
		}
		versions := map[string]interface{}{
			"2.0.0":      map[string]interface{}{},
			"3.0.0-beta": map[string]interface{}{},
		}
		removed := []string{"1.0.0"}

		cleanDistTags(distTags, versions, removed)

		if _, ok := distTags["old"]; ok {
			t.Error("'old' tag should be removed")
		}
		if _, ok := distTags["latest"]; !ok {
			t.Error("'latest' tag should remain")
		}
	})

	t.Run("no_removed_versions", func(t *testing.T) {
		distTags := map[string]interface{}{"latest": "1.0.0"}
		versions := map[string]interface{}{"1.0.0": map[string]interface{}{}}

		cleanDistTags(distTags, versions, nil)

		if _, ok := distTags["latest"]; !ok {
			t.Error("'latest' should remain")
		}
	})
}

// --- Integration tests ---------------------------------------------------

func TestHandler_TarballPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("tarball-bytes"))
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/lodash/-/lodash-4.17.21.tgz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "tarball-bytes" {
		t.Errorf("expected tarball data, got %q", w.Body.String())
	}
}

func TestHandler_Upstream404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandler_AllVersionsAllowed(t *testing.T) {
	npmDoc := map[string]interface{}{
		"name": "test-pkg",
		"versions": map[string]interface{}{
			"1.0.0": map[string]interface{}{"name": "test-pkg", "version": "1.0.0"},
			"2.0.0": map[string]interface{}{"name": "test-pkg", "version": "2.0.0"},
		},
		"dist-tags": map[string]interface{}{"latest": "2.0.0"},
	}
	body, _ := json.Marshal(npmDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/test-pkg", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	versions := result["versions"].(map[string]interface{})

	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}
}

func TestHandler_DeprecatedVersionFiltered(t *testing.T) {
	npmDoc := map[string]interface{}{
		"name": "test-pkg",
		"versions": map[string]interface{}{
			"1.0.0": map[string]interface{}{"name": "test-pkg", "version": "1.0.0"},
			"2.0.0": map[string]interface{}{
				"name": "test-pkg", "version": "2.0.0",
				"deprecated": "Use v3 instead",
			},
		},
		"dist-tags": map[string]interface{}{"latest": "2.0.0"},
		"time": map[string]interface{}{
			"1.0.0": "2024-01-01T00:00:00Z",
			"2.0.0": "2024-06-15T00:00:00Z",
		},
	}
	body, _ := json.Marshal(npmDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyDeprecatedRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/test-pkg", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	versions := result["versions"].(map[string]interface{})

	if _, ok := versions["1.0.0"]; !ok {
		t.Error("v1.0.0 should remain")
	}
	if _, ok := versions["2.0.0"]; ok {
		t.Error("v2.0.0 (deprecated) should be removed")
	}

	distTags, _ := result["dist-tags"].(map[string]interface{})
	if _, ok := distTags["latest"]; ok {
		t.Error("latest dist-tag should be removed (pointed to filtered version)")
	}

	timeMap, _ := result["time"].(map[string]interface{})
	if _, ok := timeMap["2.0.0"]; ok {
		t.Error("time entry for 2.0.0 should be removed")
	}
}

func TestHandler_MaliciousPackageFiltered(t *testing.T) {
	npmDoc := map[string]interface{}{
		"name": "evil-pkg",
		"versions": map[string]interface{}{
			"1.0.0": map[string]interface{}{"name": "evil-pkg", "version": "1.0.0"},
		},
	}
	body, _ := json.Marshal(npmDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyMaliciousRego)
	vulnDB := testutil.NewMockVulnDB()
	vulnDB.AddVuln("evil-pkg", "1.0.0", registry.VulnerabilityRecord{
		ID: "MAL-2024-001", Severity: "critical", IsMalicious: true,
	})

	h := NewHandler(upstream.URL, engine, vulnDB, slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/evil-pkg", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	versions := result["versions"].(map[string]interface{})

	if _, ok := versions["1.0.0"]; ok {
		t.Error("malicious version should be filtered out")
	}
}

func TestHandler_NoVersionsKey(t *testing.T) {
	npmDoc := map[string]interface{}{"name": "pkg", "description": "no versions"}
	body, _ := json.Marshal(npmDoc)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	req := httptest.NewRequest("GET", "/pkg", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestNewHandler_TrimsTrailingSlash(t *testing.T) {
	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler("https://registry.npmjs.org/", engine, testutil.NewMockVulnDB(), slog.Default(), nil, nil)

	if h.upstream.BaseURL != "https://registry.npmjs.org" {
		t.Errorf("expected trimmed upstream, got %s", h.upstream.BaseURL)
	}
	if h.upstream.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", h.upstream.HTTPClient.Timeout)
	}
}
