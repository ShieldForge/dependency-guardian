package dal

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"dependency-guardian/internal/vulndb/models"
)

func setupTestDB(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatalf("auto-migrate failed: %v", err)
	}
	return NewStore(db)
}

func makeTestVuln(osvID string) *models.Vulnerability {
	now := time.Now()
	return &models.Vulnerability{
		OsvID:           osvID,
		SchemaVersion:   "1.6.0",
		Modified:        now,
		Published:       &now,
		Summary:         "Test vulnerability " + osvID,
		Details:         "Detailed description for " + osvID,
		SourceEcosystem: "npm",
		Aliases: []models.VulnerabilityAlias{
			{Alias: "CVE-2024-0001"},
		},
		Severities: []models.Severity{
			{Type: "CVSS_V3", Score: "high"},
		},
		Affected: []models.Affected{
			{
				PackageEcosystem: "npm",
				PackageName:      "test-package",
				Versions:         models.StringSlice{"1.0.0", "1.1.0"},
				Ranges: []models.AffectedRange{
					{
						Type: "SEMVER",
						Events: []models.RangeEvent{
							{Introduced: "1.0.0", Fixed: "1.2.0"},
						},
					},
				},
			},
		},
		References: []models.Reference{
			{Type: "WEB", URL: "https://example.com"},
		},
		Credits: []models.Credit{
			{Name: "Researcher"},
		},
	}
}

// --- CRUD tests ----------------------------------------------------------

func TestUpsertVulnerability_Insert(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-test-0001")
	if err := store.UpsertVulnerability(ctx, vuln); err != nil {
		t.Fatalf("UpsertVulnerability failed: %v", err)
	}

	// Verify it was inserted
	found, err := store.GetVulnerabilityByOsvID(ctx, "GHSA-test-0001")
	if err != nil {
		t.Fatalf("GetVulnerabilityByOsvID failed: %v", err)
	}
	if found.Summary != "Test vulnerability GHSA-test-0001" {
		t.Errorf("unexpected summary: %s", found.Summary)
	}
	if len(found.Aliases) != 1 {
		t.Errorf("expected 1 alias, got %d", len(found.Aliases))
	}
	if len(found.Affected) != 1 {
		t.Errorf("expected 1 affected, got %d", len(found.Affected))
	}
	if len(found.Affected[0].Ranges) != 1 {
		t.Errorf("expected 1 range, got %d", len(found.Affected[0].Ranges))
	}
	if len(found.Affected[0].Ranges[0].Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(found.Affected[0].Ranges[0].Events))
	}
}

func TestUpsertVulnerability_Update(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-test-0002")
	store.UpsertVulnerability(ctx, vuln)

	// Update with new summary
	vuln2 := makeTestVuln("GHSA-test-0002")
	vuln2.Summary = "Updated summary"
	vuln2.Aliases = []models.VulnerabilityAlias{
		{Alias: "CVE-2024-9999"},
	}

	if err := store.UpsertVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("UpsertVulnerability update failed: %v", err)
	}

	found, err := store.GetVulnerabilityByOsvID(ctx, "GHSA-test-0002")
	if err != nil {
		t.Fatal(err)
	}
	if found.Summary != "Updated summary" {
		t.Errorf("expected updated summary, got %s", found.Summary)
	}
	if len(found.Aliases) != 1 || found.Aliases[0].Alias != "CVE-2024-9999" {
		t.Error("aliases not updated correctly")
	}
}

func TestBulkUpsertVulnerabilities(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vulns := []*models.Vulnerability{
		makeTestVuln("GHSA-bulk-0001"),
		makeTestVuln("GHSA-bulk-0002"),
		makeTestVuln("GHSA-bulk-0003"),
	}

	inserted, updated, err := store.BulkUpsertVulnerabilities(ctx, vulns, 2)
	if err != nil {
		t.Fatalf("BulkUpsert failed: %v", err)
	}
	if inserted != 3 {
		t.Errorf("expected 3 inserted, got %d", inserted)
	}
	if updated != 0 {
		t.Errorf("expected 0 updated, got %d", updated)
	}

	// Update one
	vulns[0].Summary = "updated"
	inserted, updated, err = store.BulkUpsertVulnerabilities(ctx, vulns[:1], 10)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 0 {
		t.Errorf("expected 0 inserted, got %d", inserted)
	}
	if updated != 1 {
		t.Errorf("expected 1 updated, got %d", updated)
	}
}

func TestGetVulnerabilityByOsvID_NotFound(t *testing.T) {
	store := setupTestDB(t)
	_, err := store.GetVulnerabilityByOsvID(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestDeleteVulnerabilityByOsvID(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-delete-001")
	store.UpsertVulnerability(ctx, vuln)

	if err := store.DeleteVulnerabilityByOsvID(ctx, "GHSA-delete-001"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := store.GetVulnerabilityByOsvID(ctx, "GHSA-delete-001")
	if err == nil {
		t.Error("vulnerability should be deleted")
	}
}

func TestDeleteVulnerabilityByOsvID_NotFound(t *testing.T) {
	store := setupTestDB(t)
	err := store.DeleteVulnerabilityByOsvID(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

// --- Package index tests -------------------------------------------------

func TestRebuildPackageIndex(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-idx-001")
	store.UpsertVulnerability(ctx, vuln)

	if err := store.RebuildPackageIndex(ctx, vuln); err != nil {
		t.Fatalf("RebuildPackageIndex failed: %v", err)
	}

	// Check exact version entries
	results, err := store.FindVulnerabilitiesByPackageVersion(ctx, "npm", "test-package", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if len(results) == 0 {
		t.Error("expected at least one index entry for version 1.0.0")
	}

	// Check that range entries also exist
	allResults, err := store.FindVulnerabilitiesByPackage(ctx, "npm", "test-package")
	if err != nil {
		t.Fatal(err)
	}
	// Should have exact version entries (2) + range entry (1)
	if len(allResults) < 3 {
		t.Errorf("expected at least 3 index entries, got %d", len(allResults))
	}
}

func TestFindVulnerabilitiesByPackage(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-find-001")
	store.UpsertVulnerability(ctx, vuln)
	store.RebuildPackageIndex(ctx, vuln)

	results, err := store.FindVulnerabilitiesByPackage(ctx, "npm", "test-package")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Error("expected results for test-package")
	}

	// Non-existent package
	results, err = store.FindVulnerabilitiesByPackage(ctx, "npm", "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for nonexistent, got %d", len(results))
	}
}

func TestFindVulnerabilitiesByPackageVersion(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-ver-001")
	store.UpsertVulnerability(ctx, vuln)
	store.RebuildPackageIndex(ctx, vuln)

	// Exact version match
	results, err := store.FindVulnerabilitiesByPackageVersion(ctx, "npm", "test-package", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Error("expected results for version 1.0.0")
	}

	// Version not in explicit list but should still get range entries
	results, err = store.FindVulnerabilitiesByPackageVersion(ctx, "npm", "test-package", "1.0.5")
	if err != nil {
		t.Fatal(err)
	}
	// Should get range-based entries
	if len(results) == 0 {
		t.Error("expected range-based results for version 1.0.5")
	}
}

// --- Sync state tests ----------------------------------------------------

func TestGetOrCreateSyncState(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	state, err := store.GetOrCreateSyncState(ctx, "npm")
	if err != nil {
		t.Fatalf("GetOrCreateSyncState failed: %v", err)
	}
	if state.Ecosystem != "npm" {
		t.Errorf("expected npm, got %s", state.Ecosystem)
	}
	if state.Status != "pending" {
		t.Errorf("expected pending, got %s", state.Status)
	}

	// Second call should return the same state
	state2, err := store.GetOrCreateSyncState(ctx, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if state2.ID != state.ID {
		t.Error("expected same state on second call")
	}
}

func TestUpdateSyncState(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	state, _ := store.GetOrCreateSyncState(ctx, "PyPI")
	state.Status = "syncing"
	now := time.Now()
	state.LastFullSync = &now

	if err := store.UpdateSyncState(ctx, state); err != nil {
		t.Fatalf("UpdateSyncState failed: %v", err)
	}

	updated, _ := store.GetOrCreateSyncState(ctx, "PyPI")
	if updated.Status != "syncing" {
		t.Errorf("expected syncing, got %s", updated.Status)
	}
}

func TestListSyncStates(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	store.GetOrCreateSyncState(ctx, "Go")
	store.GetOrCreateSyncState(ctx, "npm")
	store.GetOrCreateSyncState(ctx, "PyPI")

	states, err := store.ListSyncStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 {
		t.Errorf("expected 3 states, got %d", len(states))
	}
	// Should be ordered by ecosystem ASC
	if states[0].Ecosystem != "Go" {
		t.Errorf("expected first state Go, got %s", states[0].Ecosystem)
	}
}

// --- Sync log tests ------------------------------------------------------

func TestCreateAndCompleteSyncLog(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	log := &models.SyncLog{
		Ecosystem:        "npm",
		SyncType:         "full",
		Status:           "started",
		StartedAt:        time.Now(),
		RecordsProcessed: 100,
	}

	if err := store.CreateSyncLog(ctx, log); err != nil {
		t.Fatalf("CreateSyncLog failed: %v", err)
	}
	if log.ID == 0 {
		t.Error("expected non-zero ID")
	}

	log.Status = "completed"
	log.RecordsInserted = 50
	log.RecordsUpdated = 50

	if err := store.CompleteSyncLog(ctx, log); err != nil {
		t.Fatalf("CompleteSyncLog failed: %v", err)
	}
	if log.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
}

func TestGetRecentSyncLogs(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		log := &models.SyncLog{
			Ecosystem: "npm",
			SyncType:  "delta",
			Status:    "completed",
			StartedAt: time.Now().Add(time.Duration(i) * time.Minute),
		}
		store.CreateSyncLog(ctx, log)
	}

	logs, err := store.GetRecentSyncLogs(ctx, "npm", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 {
		t.Errorf("expected 3 logs, got %d", len(logs))
	}
}

// --- Metrics tests -------------------------------------------------------

func TestUpdateEcosystemMetrics(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-met-001")
	store.UpsertVulnerability(ctx, vuln)
	store.RebuildPackageIndex(ctx, vuln)

	if err := store.UpdateEcosystemMetrics(ctx, "npm"); err != nil {
		t.Fatalf("UpdateEcosystemMetrics failed: %v", err)
	}

	state, _ := store.GetOrCreateSyncState(ctx, "npm")
	if state.TotalVulnerabilities == 0 {
		t.Error("expected non-zero vulnerability count")
	}
	if state.TotalAffectedEntries == 0 {
		t.Error("expected non-zero affected entries count")
	}
}

func TestGetGlobalStats(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	vuln := makeTestVuln("GHSA-stats-001")
	store.UpsertVulnerability(ctx, vuln)
	store.RebuildPackageIndex(ctx, vuln)

	stats, err := store.GetGlobalStats(ctx)
	if err != nil {
		t.Fatal(err)
	}

	totalVulns, _ := stats["total_vulnerabilities"].(int64)
	if totalVulns == 0 {
		t.Error("expected non-zero total_vulnerabilities")
	}

	totalAffected, _ := stats["total_affected"].(int64)
	if totalAffected == 0 {
		t.Error("expected non-zero total_affected")
	}
}

// --- Helper function tests -----------------------------------------------

func TestComputeMaxSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severities []models.Severity
		expected   string
	}{
		{"critical", []models.Severity{{Score: "critical"}}, "critical"},
		{"high", []models.Severity{{Score: "high"}}, "high"},
		{"medium", []models.Severity{{Score: "medium"}}, "medium"},
		{"low", []models.Severity{{Score: "low"}}, "low"},
		{"mixed_critical_wins", []models.Severity{{Score: "low"}, {Score: "critical"}, {Score: "medium"}}, "critical"},
		{"empty", []models.Severity{}, ""},
		{"unknown_score", []models.Severity{{Score: "CVSS:3.1/AV:N"}}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeMaxSeverity(tt.severities)
			if got != tt.expected {
				t.Errorf("computeMaxSeverity() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCvssToSeverityLevel(t *testing.T) {
	tests := []struct {
		score    string
		expected string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"negligible", "low"},
		{"CVSS:3.1/AV:N", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			got := cvssToSeverityLevel(tt.score)
			if got != tt.expected {
				t.Errorf("cvssToSeverityLevel(%q) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

func TestCheckMalicious(t *testing.T) {
	t.Run("MAL_alias", func(t *testing.T) {
		vuln := &models.Vulnerability{
			Aliases: []models.VulnerabilityAlias{{Alias: "MAL-2024-0001"}},
		}
		if !checkMalicious(vuln) {
			t.Error("expected malicious for MAL- alias")
		}
	})

	t.Run("MAL_osv_id", func(t *testing.T) {
		vuln := &models.Vulnerability{OsvID: "MAL-2024-0001"}
		if !checkMalicious(vuln) {
			t.Error("expected malicious for MAL- OSV ID")
		}
	})

	t.Run("database_specific_flag", func(t *testing.T) {
		vuln := &models.Vulnerability{
			DatabaseSpecific: models.JSONMap{"is_malicious": true},
		}
		if !checkMalicious(vuln) {
			t.Error("expected malicious for database_specific flag")
		}
	})

	t.Run("not_malicious", func(t *testing.T) {
		vuln := &models.Vulnerability{
			OsvID:   "GHSA-test-0001",
			Aliases: []models.VulnerabilityAlias{{Alias: "CVE-2024-0001"}},
		}
		if checkMalicious(vuln) {
			t.Error("expected not malicious")
		}
	})

	t.Run("short_alias", func(t *testing.T) {
		vuln := &models.Vulnerability{
			Aliases: []models.VulnerabilityAlias{{Alias: "MAL"}},
		}
		if checkMalicious(vuln) {
			t.Error("short aliases should not be treated as malicious")
		}
	})
}

func TestRangeToConstraint(t *testing.T) {
	r := models.AffectedRange{
		Type: "SEMVER",
		Events: []models.RangeEvent{
			{Introduced: "1.0.0", Fixed: "1.2.0"},
		},
	}

	constraint := rangeToConstraint(r)
	if constraint == "" {
		t.Error("expected non-empty constraint")
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(constraint), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["type"] != "SEMVER" {
		t.Errorf("expected type SEMVER, got %v", parsed["type"])
	}
}

func TestNewStore(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	store := NewStore(db)
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
	if store.DB() != db {
		t.Error("DB() should return the same gorm.DB")
	}
}
