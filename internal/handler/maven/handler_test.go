package maven

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/testutil"
)

// --- Test Rego policies --------------------------------------------------

const denyAllRego = `package guardian
import rego.v1
deny contains "denied by policy" if { true }
`

const denyMaliciousRego = `package guardian
import rego.v1
deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.is_malicious == true
	msg := sprintf("malicious: %s", [vuln.id])
}
`

// --- Unit tests ----------------------------------------------------------

func TestIsMetadataRequest(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/org/apache/commons/commons-lang3/maven-metadata.xml", true},
		{"/com/google/guava/guava/maven-metadata.xml", true},
		{"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar", false},
		{"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isMetadataRequest(tt.path); got != tt.expected {
				t.Errorf("isMetadataRequest(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestMavenCoordinate(t *testing.T) {
	tests := []struct {
		groupID    string
		artifactID string
		expected   string
	}{
		{"org.apache.commons", "commons-lang3", "org.apache.commons:commons-lang3"},
		{"com.google.guava", "guava", "com.google.guava:guava"},
		{"", "artifact", "artifact"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := mavenCoordinate(tt.groupID, tt.artifactID); got != tt.expected {
				t.Errorf("mavenCoordinate(%q, %q) = %q, want %q", tt.groupID, tt.artifactID, got, tt.expected)
			}
		})
	}
}

func TestExtractGroupAndArtifact(t *testing.T) {
	tests := []struct {
		path       string
		groupID    string
		artifactID string
	}{
		{"/org/apache/commons/commons-lang3/maven-metadata.xml", "org.apache.commons", "commons-lang3"},
		{"/com/google/guava/guava/maven-metadata.xml", "com.google.guava", "guava"},
		{"/single/maven-metadata.xml", "", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			g, a := ExtractGroupAndArtifact(tt.path)
			if g != tt.groupID || a != tt.artifactID {
				t.Errorf("ExtractGroupAndArtifact(%q) = (%q, %q), want (%q, %q)", tt.path, g, a, tt.groupID, tt.artifactID)
			}
		})
	}
}

// --- Integration tests ---------------------------------------------------

func sampleMetadataXML(groupID, artifactID string, versions []string) []byte {
	meta := mavenMetadata{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Versioning: &mavenVersioning{
			Latest:  versions[len(versions)-1],
			Release: versions[len(versions)-1],
			Versions: mavenVersionList{
				Version: versions,
			},
			LastUpdated: "20240101000000",
		},
	}
	output, _ := xml.MarshalIndent(meta, "", "  ")
	return append([]byte(xml.Header), output...)
}

func TestHandler_Metadata_AllAllowed(t *testing.T) {
	metadataXML := sampleMetadataXML("org.example", "mylib", []string{"1.0.0", "2.0.0", "3.0.0"})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataXML)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	handler := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/mylib/maven-metadata.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta mavenMetadata
	if err := xml.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to parse response XML: %v", err)
	}

	if len(meta.Versioning.Versions.Version) != 3 {
		t.Errorf("expected 3 versions, got %d", len(meta.Versioning.Versions.Version))
	}
}

func TestHandler_Metadata_SomeFiltered(t *testing.T) {
	metadataXML := sampleMetadataXML("org.example", "mylib", []string{"1.0.0", "2.0.0", "3.0.0"})

	mockVuln := testutil.NewMockVulnDB()
	mockVuln.AddVuln("org.example:mylib", "2.0.0", registry.VulnerabilityRecord{
		ID:          "MAL-001",
		IsMalicious: true,
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataXML)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyMaliciousRego)
	handler := NewHandler(upstream.URL, engine, mockVuln, slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/mylib/maven-metadata.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta mavenMetadata
	if err := xml.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to parse response XML: %v", err)
	}

	if len(meta.Versioning.Versions.Version) != 2 {
		t.Errorf("expected 2 versions after filtering, got %d: %v",
			len(meta.Versioning.Versions.Version), meta.Versioning.Versions.Version)
	}

	for _, v := range meta.Versioning.Versions.Version {
		if v == "2.0.0" {
			t.Error("version 2.0.0 should have been filtered out (malicious)")
		}
	}

	// Release/latest should be updated to last allowed version.
	if meta.Versioning.Release != "3.0.0" {
		t.Errorf("expected release to be 3.0.0, got %q", meta.Versioning.Release)
	}
}

func TestHandler_Metadata_AllDenied(t *testing.T) {
	metadataXML := sampleMetadataXML("org.example", "mylib", []string{"1.0.0", "2.0.0"})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataXML)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	handler := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/mylib/maven-metadata.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta mavenMetadata
	if err := xml.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to parse response XML: %v", err)
	}

	if len(meta.Versioning.Versions.Version) != 0 {
		t.Errorf("expected 0 versions, got %d", len(meta.Versioning.Versions.Version))
	}

	if meta.Versioning.Release != "" {
		t.Errorf("expected empty release, got %q", meta.Versioning.Release)
	}
}

func TestHandler_ArtifactPassthrough(t *testing.T) {
	jarContent := []byte("fake-jar-content")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/java-archive")
		w.Write(jarContent)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, denyAllRego)
	handler := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/mylib/1.0.0/mylib-1.0.0.jar", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if w.Body.String() != string(jarContent) {
		t.Error("jar content was not passed through correctly")
	}
}

func TestHandler_Upstream404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	handler := NewHandler(upstream.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/nonexistent/maven-metadata.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestNewHandler_TrimsTrailingSlash(t *testing.T) {
	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	h := NewHandler("https://repo1.maven.org/maven2/", engine, testutil.NewMockVulnDB(), slog.Default(), nil)
	if h.upstream.BaseURL != "https://repo1.maven.org/maven2" {
		t.Errorf("expected trailing slash trimmed, got %q", h.upstream.BaseURL)
	}
}
