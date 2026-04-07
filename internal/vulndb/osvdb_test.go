package vulndb

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/vercmp"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func setupTestDB(t *testing.T) *dal.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	return dal.NewStore(db)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// seedVuln inserts a vulnerability with one affected package and a SEMVER range.
func seedVuln(t *testing.T, store *dal.Store, osvID, ecosystem, pkg, introduced, fixed string, severity string, isMalicious bool) {
	t.Helper()
	ctx := context.Background()

	now := time.Now()
	vuln := &models.Vulnerability{
		OsvID:           osvID,
		Summary:         "Test vuln " + osvID,
		SourceEcosystem: ecosystem,
		Modified:        now,
	}

	// If malicious, prefix ID accordingly
	if isMalicious {
		vuln.OsvID = osvID // keep as-is, but set the prefix pattern
	}

	vuln.Affected = []models.Affected{{
		PackageEcosystem: ecosystem,
		PackageName:      pkg,
		Ranges: []models.AffectedRange{{
			Type: "SEMVER",
			Events: []models.RangeEvent{
				{Introduced: introduced},
				{Fixed: fixed},
			},
		}},
	}}

	if severity != "" {
		vuln.Severities = []models.Severity{{
			Type:  "CVSS_V3",
			Score: severity,
		}}
	}

	_, _, err := store.BulkUpsertVulnerabilities(ctx, []*models.Vulnerability{vuln}, 10)
	if err != nil {
		t.Fatalf("failed to seed vuln: %v", err)
	}
	if err := store.RebuildPackageIndex(ctx, vuln); err != nil {
		t.Fatalf("failed to rebuild index: %v", err)
	}
}

// --------------------------------------------------------------------------
// mapEcosystem
// --------------------------------------------------------------------------

func TestMapEcosystem(t *testing.T) {
	tests := []struct {
		input    registry.Ecosystem
		expected string
	}{
		{registry.EcosystemNPM, "npm"},
		{registry.EcosystemPyPI, "PyPI"},
		{registry.EcosystemGo, "Go"},
		{"custom", "custom"},
	}

	for _, tt := range tests {
		got := mapEcosystem(tt.input)
		if got != tt.expected {
			t.Errorf("mapEcosystem(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --------------------------------------------------------------------------
// findFixedVersion
// --------------------------------------------------------------------------

func TestFindFixedVersion(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				PackageEcosystem: "npm",
				PackageName:      "lodash",
				Ranges: []models.AffectedRange{
					{
						Type: "SEMVER",
						Events: []models.RangeEvent{
							{Introduced: "0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
			{
				PackageEcosystem: "PyPI",
				PackageName:      "otherpkg",
				Ranges: []models.AffectedRange{
					{
						Type: "SEMVER",
						Events: []models.RangeEvent{
							{Introduced: "1.0.0"},
							{Fixed: "2.0.0"},
						},
					},
				},
			},
		},
	}

	// Match first affected.
	if got := findFixedVersion(vuln, "npm", "lodash"); got != "4.17.21" {
		t.Errorf("expected 4.17.21, got %s", got)
	}

	// Match second affected.
	if got := findFixedVersion(vuln, "PyPI", "otherpkg"); got != "2.0.0" {
		t.Errorf("expected 2.0.0, got %s", got)
	}

	// No match.
	if got := findFixedVersion(vuln, "npm", "nonexistent"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestFindFixedVersion_NoRanges(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				PackageEcosystem: "npm",
				PackageName:      "pkg",
				Ranges:           nil,
			},
		},
	}
	if got := findFixedVersion(vuln, "npm", "pkg"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestFindFixedVersion_NoFixedEvent(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				PackageEcosystem: "npm",
				PackageName:      "pkg",
				Ranges: []models.AffectedRange{
					{
						Type: "SEMVER",
						Events: []models.RangeEvent{
							{Introduced: "0"},
						},
					},
				},
			},
		},
	}
	if got := findFixedVersion(vuln, "npm", "pkg"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

// --------------------------------------------------------------------------
// versionMatchesConstraint
// --------------------------------------------------------------------------

func TestVersionMatchesConstraint(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		ecosystem  string
		expected   bool
	}{
		{
			name:    "introduced_at_0_no_fix",
			version: "1.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"}
			]}`,
			ecosystem: "npm",
			expected:  true,
		},
		{
			name:    "introduced_at_0_with_fix_before",
			version: "1.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"fixed":"2.0.0"}
			]}`,
			ecosystem: "npm",
			expected:  true,
		},
		{
			name:    "introduced_at_0_with_fix_at_version",
			version: "2.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"fixed":"2.0.0"}
			]}`,
			ecosystem: "npm",
			expected:  false,
		},
		{
			name:    "introduced_at_0_version_after_fix",
			version: "3.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"fixed":"2.0.0"}
			]}`,
			ecosystem: "npm",
			expected:  false,
		},
		{
			name:    "git_type_returns_false",
			version: "abc123",
			constraint: `{"type":"GIT","events":[
				{"introduced":"abc123"}
			]}`,
			ecosystem: "npm",
			expected:  false,
		},
		{
			name:       "invalid_json",
			version:    "1.0.0",
			constraint: `{invalid}`,
			ecosystem:  "npm",
			expected:   false,
		},
		{
			name:    "last_affected",
			version: "3.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"last_affected":"2.0.0"}
			]}`,
			ecosystem: "npm",
			expected:  false,
		},
		{
			name:    "last_affected_within",
			version: "1.5.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"last_affected":"2.0.0"}
			]}`,
			ecosystem: "npm",
			expected:  true,
		},
		{
			name:    "specific_introduced",
			version: "2.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"1.5.0"}
			]}`,
			ecosystem: "npm",
			expected:  true,
		},
		{
			name:    "version_before_introduced",
			version: "1.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"1.5.0"}
			]}`,
			ecosystem: "npm",
			expected:  false,
		},
		{
			name:    "maven_numeric_comparison_high_major_after_fix",
			version: "42.7.2",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"0"},
				{"fixed":"8.2"}
			]}`,
			ecosystem: "Maven",
			expected:  false,
		},
		{
			name:    "maven_numeric_comparison_low_major_before_fix",
			version: "7.9.0",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"0"},
				{"fixed":"8.2"}
			]}`,
			ecosystem: "Maven",
			expected:  true,
		},
		{
			name:    "maven_numeric_comparison_equal_to_fix",
			version: "8.2",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"0"},
				{"fixed":"8.2"}
			]}`,
			ecosystem: "Maven",
			expected:  false,
		},
		{
			name:    "maven_numeric_comparison_introduced_higher_major",
			version: "2.0.0",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"10.0.0"}
			]}`,
			ecosystem: "Maven",
			expected:  false,
		},
		{
			name:    "semver_v_prefix_stripped",
			version: "v2.0.0",
			constraint: `{"type":"SEMVER","events":[
				{"introduced":"0"},
				{"fixed":"v1.5.0"}
			]}`,
			ecosystem: "Go",
			expected:  false,
		},
		{
			name:    "pypi_version_comparison",
			version: "1.2.3",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"0"},
				{"fixed":"2.0.0"}
			]}`,
			ecosystem: "PyPI",
			expected:  true,
		},
		{
			name:    "pypi_version_after_fix",
			version: "2.1.0",
			constraint: `{"type":"ECOSYSTEM","events":[
				{"introduced":"0"},
				{"fixed":"2.0.0"}
			]}`,
			ecosystem: "PyPI",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VersionMatchesConstraint(tt.version, tt.constraint, tt.ecosystem)
			if got != tt.expected {
				t.Errorf("VersionMatchesConstraint(%q, ..., %q) = %v, want %v", tt.version, tt.ecosystem, got, tt.expected)
			}
		})
	}
}

func TestComparerFor(t *testing.T) {
	tests := []struct {
		name      string
		a, b      string
		ecosystem string
		want      int
	}{
		// semver via go-version
		{"semver_equal", "1.0.0", "1.0.0", "npm", 0},
		{"semver_greater", "2.0.0", "1.0.0", "npm", 1},
		{"semver_less", "1.0.0", "2.0.0", "npm", -1},
		{"semver_v_prefix", "v1.2.3", "1.2.3", "Go", 0},
		{"semver_prerelease", "1.0.0-rc1", "1.0.0", "npm", -1},

		// Maven via go-mvn-version
		{"maven_numeric", "42.7.2", "8.2", "Maven", 1},
		{"maven_reverse", "8.2", "42.7.2", "Maven", -1},
		{"maven_equal", "1.0.0", "1.0.0", "Maven", 0},
		{"maven_snapshot", "1.0.0-SNAPSHOT", "1.0.0", "Maven", -1},

		// PyPI via go-pep440-version
		{"pypi_greater", "2.0.0", "1.0.0", "PyPI", 1},
		{"pypi_less", "1.0.0", "2.0.0", "PyPI", -1},
		{"pypi_equal", "1.0.0", "1.0.0", "PyPI", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp := vercmp.ComparerFor("ECOSYSTEM", tt.ecosystem)
			got := cmp(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("vercmp.ComparerFor(ECOSYSTEM, %q)(%q, %q) = %d, want %d", tt.ecosystem, tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// NewOSVDatabase
// --------------------------------------------------------------------------

func TestNewOSVDatabase(t *testing.T) {
	store := setupTestDB(t)
	db := NewOSVDatabase(store, testLogger())
	if db == nil {
		t.Fatal("expected non-nil OSVDatabase")
	}
	if db.Store() != store {
		t.Error("Store() should return the underlying store")
	}
}

// --------------------------------------------------------------------------
// GetVulnerabilities integration
// --------------------------------------------------------------------------

func TestGetVulnerabilities_NoMatches(t *testing.T) {
	store := setupTestDB(t)
	db := NewOSVDatabase(store, testLogger())

	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemNPM, "nonexistent", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results, got %d", len(results))
	}
}

func TestGetVulnerabilities_WithMatch(t *testing.T) {
	store := setupTestDB(t)
	seedVuln(t, store, "GHSA-test-0001", "npm", "lodash", "0", "4.17.21", "9.8", false)

	db := NewOSVDatabase(store, testLogger())
	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemNPM, "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].ID != "GHSA-test-0001" {
		t.Errorf("expected GHSA-test-0001, got %s", results[0].ID)
	}
}

func TestGetVulnerabilities_MaliciousFlag(t *testing.T) {
	store := setupTestDB(t)
	seedVuln(t, store, "MAL-2024-0001", "npm", "evil-pkg", "0", "", "", true)

	db := NewOSVDatabase(store, testLogger())
	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemNPM, "evil-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if !results[0].IsMalicious {
		t.Error("expected IsMalicious to be true")
	}
}

func TestGetVulnerabilities_PyPI(t *testing.T) {
	store := setupTestDB(t)
	seedVuln(t, store, "PYSEC-2024-0001", "PyPI", "flask", "0", "3.0.0", "", false)

	db := NewOSVDatabase(store, testLogger())
	// Proxy uses "pypi" but OSV uses "PyPI" – mapEcosystem handles this.
	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemPyPI, "flask", "2.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result for flask 2.3.0")
	}
}

func TestGetVulnerabilities_Go(t *testing.T) {
	store := setupTestDB(t)
	seedVuln(t, store, "GO-2024-0001", "Go", "golang.org/x/net", "0", "0.23.0", "", false)

	db := NewOSVDatabase(store, testLogger())
	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemGo, "golang.org/x/net", "0.22.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result for golang.org/x/net 0.22.0")
	}
}

func TestGetVulnerabilities_DeduplicatesResults(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create a vuln with multiple affected entries for the same package
	vuln := &models.Vulnerability{
		OsvID:           "GHSA-dup-0001",
		Summary:         "Test dedup",
		SourceEcosystem: "npm",
		Modified:        time.Now(),
		Affected: []models.Affected{
			{
				PackageEcosystem: "npm",
				PackageName:      "dup-pkg",
				Versions:         models.StringSlice{"1.0.0", "1.0.1"},
			},
		},
	}

	store.BulkUpsertVulnerabilities(ctx, []*models.Vulnerability{vuln}, 10)
	store.RebuildPackageIndex(ctx, vuln)

	db := NewOSVDatabase(store, testLogger())
	results, err := db.GetVulnerabilities(context.Background(), registry.EcosystemNPM, "dup-pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	// Should only appear once even if multiple index entries exist.
	seenIDs := make(map[string]int)
	for _, r := range results {
		seenIDs[r.ID]++
	}
	for id, count := range seenIDs {
		if count > 1 {
			t.Errorf("vulnerability %s appeared %d times", id, count)
		}
	}
}
