package maven

import (
	"context"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dependency-guardian/internal/handler/upstream"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/testutil"
)

// --- POM property resolution tests ---------------------------------------

func TestResolveVersion_NoPlaceholder(t *testing.T) {
	props := map[string]string{"foo": "1.0"}
	if got := resolveVersion("3.2.1", props); got != "3.2.1" {
		t.Errorf("expected 3.2.1, got %q", got)
	}
}

func TestResolveVersion_Simple(t *testing.T) {
	props := map[string]string{"spring.version": "5.3.20"}
	got := resolveVersion("${spring.version}", props)
	if got != "5.3.20" {
		t.Errorf("expected 5.3.20, got %q", got)
	}
}

func TestResolveVersion_Transitive(t *testing.T) {
	props := map[string]string{
		"base.version": "1.0.0",
		"lib.version":  "${base.version}",
	}
	got := resolveVersion("${lib.version}", props)
	if got != "1.0.0" {
		t.Errorf("expected 1.0.0, got %q", got)
	}
}

func TestResolveVersion_Unresolvable(t *testing.T) {
	props := map[string]string{}
	got := resolveVersion("${unknown.version}", props)
	if got != "${unknown.version}" {
		t.Errorf("expected unresolved placeholder, got %q", got)
	}
}

func TestResolveVersion_ProjectVersion(t *testing.T) {
	props := map[string]string{"project.version": "2.0.0"}
	got := resolveVersion("${project.version}", props)
	if got != "2.0.0" {
		t.Errorf("expected 2.0.0, got %q", got)
	}
}

func TestResolveVersion_Mixed(t *testing.T) {
	// Uncommon but technically possible: "${prefix}-${suffix}"
	props := map[string]string{"major": "1", "minor": "2"}
	got := resolveVersion("${major}.${minor}.0", props)
	if got != "1.2.0" {
		t.Errorf("expected 1.2.0, got %q", got)
	}
}

// --- POM parsing tests ---------------------------------------------------

func TestParsePOM_Basic(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
  </dependencies>
</project>`

	pom, err := parsePOM([]byte(raw))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	if *pom.GroupID != "com.example" {
		t.Errorf("expected groupId com.example, got %q", *pom.GroupID)
	}
	if pom.Properties.Entries["spring.version"] != "5.3.20" {
		t.Errorf("expected spring.version=5.3.20, got %q", pom.Properties.Entries["spring.version"])
	}
	if len(pom.Dependencies.Dependency) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(pom.Dependencies.Dependency))
	}

	// Resolve versions.
	props := collectProperties(context.Background(), pom, nil)
	deps := resolvedDependencies(pom, props)

	if len(deps) != 2 {
		t.Fatalf("expected 2 resolved deps, got %d", len(deps))
	}

	for _, d := range deps {
		if strings.Contains(d.Version, "${") {
			t.Errorf("version %q still contains unresolved property", d.Version)
		}
	}

	verify := map[string]string{
		"org.springframework:spring-core": "5.3.20",
		"com.google.guava:guava":          "31.1-jre",
	}
	for _, d := range deps {
		coord := d.GroupID + ":" + d.ArtifactID
		if want, ok := verify[coord]; ok && d.Version != want {
			t.Errorf("expected %s version %s, got %s", coord, want, d.Version)
		}
	}
}

func TestParsePOM_DependencyManagement(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <jackson.version>2.14.0</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`

	pom, err := parsePOM([]byte(raw))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	props := collectProperties(context.Background(), pom, nil)
	deps := resolvedDependencies(pom, props)

	if len(deps) != 1 {
		t.Fatalf("expected 1 resolved dep from dependencyManagement, got %d", len(deps))
	}
	if deps[0].Version != "2.14.0" {
		t.Errorf("expected 2.14.0, got %q", deps[0].Version)
	}
}

func TestParsePOM_ProjectVersionInherited(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>3.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>mylib-core</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>`

	pom, err := parsePOM([]byte(raw))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	props := collectProperties(context.Background(), pom, nil)
	deps := resolvedDependencies(pom, props)

	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "3.0.0" {
		t.Errorf("expected version 3.0.0 from project.version, got %q", deps[0].Version)
	}
}

func TestParsePOM_NoProperties(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>simple</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>`

	pom, err := parsePOM([]byte(raw))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	props := collectProperties(context.Background(), pom, nil)
	deps := resolvedDependencies(pom, props)

	if len(deps) != 1 || deps[0].Version != "4.13.2" {
		t.Errorf("expected junit 4.13.2, got %v", deps)
	}
}

func TestParsePOM_EmptyVersion_Skipped(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>no-version</artifactId>
    </dependency>
  </dependencies>
</project>`

	pom, err := parsePOM([]byte(raw))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	props := collectProperties(context.Background(), pom, nil)
	deps := resolvedDependencies(pom, props)

	if len(deps) != 0 {
		t.Errorf("expected 0 resolved deps (empty version skipped), got %d", len(deps))
	}
}

// --- Parent POM resolution tests -----------------------------------------

func TestCollectProperties_WithParentPOM(t *testing.T) {
	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
    <common.encoding>UTF-8</common.encoding>
  </properties>
</project>`

	childPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <properties>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
  </dependencies>
</project>`

	// Serve the parent POM from a test server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "parent-1.0.0.pom") {
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(parentPOM))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pom, err := parsePOM([]byte(childPOM))
	if err != nil {
		t.Fatalf("parsePOM failed: %v", err)
	}

	client := newTestUpstreamClient(srv.URL)
	props := collectProperties(context.Background(), pom, client)

	// Parent property should be available.
	if props["spring.version"] != "5.3.20" {
		t.Errorf("expected spring.version=5.3.20 from parent, got %q", props["spring.version"])
	}

	// Child property should be available.
	if props["guava.version"] != "31.1-jre" {
		t.Errorf("expected guava.version=31.1-jre, got %q", props["guava.version"])
	}

	deps := resolvedDependencies(pom, props)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	verify := map[string]string{
		"org.springframework:spring-core": "5.3.20",
		"com.google.guava:guava":          "31.1-jre",
	}
	for _, d := range deps {
		coord := d.GroupID + ":" + d.ArtifactID
		if want, ok := verify[coord]; ok && d.Version != want {
			t.Errorf("expected %s version %s, got %s", coord, want, d.Version)
		}
	}
}

func TestCollectProperties_ChildOverridesParent(t *testing.T) {
	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.2.0</spring.version>
  </properties>
</project>`

	childPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "parent-1.0.0.pom") {
			w.Write([]byte(parentPOM))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pom, err := parsePOM([]byte(childPOM))
	if err != nil {
		t.Fatal(err)
	}

	client := newTestUpstreamClient(srv.URL)
	props := collectProperties(context.Background(), pom, client)

	// Child overrides parent's spring.version.
	if props["spring.version"] != "5.3.20" {
		t.Errorf("expected child override 5.3.20, got %q", props["spring.version"])
	}
}

func TestCollectProperties_GrandparentChain(t *testing.T) {
	grandparentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>grandparent</artifactId>
  <version>1.0.0</version>
  <properties>
    <deep.version>0.1.0</deep.version>
  </properties>
</project>`

	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>grandparent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>parent</artifactId>
  <version>2.0.0</version>
  <properties>
    <mid.version>1.0.0</mid.version>
  </properties>
</project>`

	childPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>deep-lib</artifactId>
      <version>${deep.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>mid-lib</artifactId>
      <version>${mid.version}</version>
    </dependency>
  </dependencies>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "grandparent-1.0.0.pom"):
			w.Write([]byte(grandparentPOM))
		case strings.HasSuffix(r.URL.Path, "parent-2.0.0.pom"):
			w.Write([]byte(parentPOM))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pom, err := parsePOM([]byte(childPOM))
	if err != nil {
		t.Fatal(err)
	}

	client := newTestUpstreamClient(srv.URL)
	props := collectProperties(context.Background(), pom, client)

	if props["deep.version"] != "0.1.0" {
		t.Errorf("expected deep.version=0.1.0 from grandparent, got %q", props["deep.version"])
	}
	if props["mid.version"] != "1.0.0" {
		t.Errorf("expected mid.version=1.0.0 from parent, got %q", props["mid.version"])
	}

	deps := resolvedDependencies(pom, props)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	for _, d := range deps {
		if strings.Contains(d.Version, "${") {
			t.Errorf("version %q still unresolved", d.Version)
		}
	}
}

// --- POM path tests ------------------------------------------------------

func TestPomPath(t *testing.T) {
	tests := []struct {
		groupID    string
		artifactID string
		version    string
		expected   string
	}{
		{
			"org.apache.commons", "commons-lang3", "3.12.0",
			"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
		},
		{
			"com.google.guava", "guava", "31.1-jre",
			"/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := pomPath(tt.groupID, tt.artifactID, tt.version); got != tt.expected {
				t.Errorf("pomPath(%q, %q, %q) = %q, want %q",
					tt.groupID, tt.artifactID, tt.version, got, tt.expected)
			}
		})
	}
}

func TestIsPomRequest(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom", true},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom", true},
		{"/org/example/mylib/maven-metadata.xml", false},
		{"/org/example/mylib/1.0.0/mylib-1.0.0.jar", false},
		{"/org/example/mylib/1.0.0/mylib-1.0.0.pom.sha1", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isPomRequest(tt.path); got != tt.expected {
				t.Errorf("isPomRequest(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// --- Handler integration tests for POM -----------------------------------

func samplePOMXML(groupID, artifactID, version string, props map[string]string, deps []pomDependency) []byte {
	pom := pomProject{
		GroupID:    &groupID,
		ArtifactID: &artifactID,
		Version:    &version,
	}
	pom.Properties.Entries = props
	if len(deps) > 0 {
		pom.Dependencies = &pomDeps{Dependency: deps}
	}

	output, _ := xml.MarshalIndent(pom, "", "  ")
	return append([]byte(xml.Header), output...)
}

func TestHandler_POM_Passthrough(t *testing.T) {
	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>org.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <properties>
    <dep.version>2.0.0</dep.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>dep</artifactId>
      <version>${dep.version}</version>
    </dependency>
  </dependencies>
</project>`

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(pomXML))
	}))
	defer upstreamSrv.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	handler := NewHandler(upstreamSrv.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/mylib/1.0.0/mylib-1.0.0.pom", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// POM should be passed through as-is.
	if w.Body.String() != pomXML {
		t.Error("POM content was modified; expected passthrough")
	}
}

func TestHandler_POM_WithParentResolution(t *testing.T) {
	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
</project>`

	childPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <version>2.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>`

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case strings.HasSuffix(r.URL.Path, "parent-1.0.0.pom"):
			w.Write([]byte(parentPOM))
		case strings.HasSuffix(r.URL.Path, "child-2.0.0.pom"):
			w.Write([]byte(childPOM))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstreamSrv.Close()

	engine := testutil.MakePolicyEngine(t, testutil.AllowAllRego)
	handler := NewHandler(upstreamSrv.URL, engine, testutil.NewMockVulnDB(), slog.Default(), nil)

	req := httptest.NewRequest("GET", "/org/example/child/2.0.0/child-2.0.0.pom", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandler_POM_DeniedDependencyLogged(t *testing.T) {
	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>org.example</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.malicious</groupId>
      <artifactId>evil-lib</artifactId>
      <version>0.1.0</version>
    </dependency>
  </dependencies>
</project>`

	mockVuln := testutil.NewMockVulnDB()
	mockVuln.AddVuln("com.malicious:evil-lib", "0.1.0", registry.VulnerabilityRecord{
		ID:          "MAL-100",
		IsMalicious: true,
	})

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(pomXML))
	}))
	defer upstreamSrv.Close()

	engine := testutil.MakePolicyEngine(t, denyMaliciousRego)

	// Use a recorder to verify the denied dependency is recorded.
	rec := &mockRecorder{}
	handler := NewHandler(upstreamSrv.URL, engine, mockVuln, slog.Default(), rec)

	req := httptest.NewRequest("GET", "/org/example/mylib/1.0.0/mylib-1.0.0.pom", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// POM is still served (passthrough).
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (passthrough), got %d", w.Code)
	}

	// Verify the denied dependency was recorded.
	if len(rec.entries) == 0 {
		t.Fatal("expected at least one recorded decision")
	}

	found := false
	for _, e := range rec.entries {
		if e.pkg == "com.malicious:evil-lib" && !e.allowed {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected denied decision for com.malicious:evil-lib")
	}
}

// --- Test helpers --------------------------------------------------------

func newTestUpstreamClient(baseURL string) *upstream.Client {
	return upstream.NewClient(baseURL, 5*time.Second)
}

type recordEntry struct {
	ecosystem string
	pkg       string
	version   string
	allowed   bool
	reasons   []string
	vulnCount int
}

type mockRecorder struct {
	entries []recordEntry
}

func (r *mockRecorder) Record(ecosystem, pkg, version string, allowed bool, reasons []string, vulnCount int) {
	r.entries = append(r.entries, recordEntry{
		ecosystem: ecosystem,
		pkg:       pkg,
		version:   version,
		allowed:   allowed,
		reasons:   reasons,
		vulnCount: vulnCount,
	})
}
