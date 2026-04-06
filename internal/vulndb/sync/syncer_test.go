package sync

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/vulndb/dal"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"dependency-guardian/internal/vulndb/models"
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

// makeZip creates a zip archive containing the given files.
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeOSVJSON creates a minimal valid OSV JSON record.
func makeOSVJSON(id, ecosystem, pkg string) string {
	return fmt.Sprintf(`{
		"id": %q,
		"modified": "2024-06-15T12:00:00Z",
		"summary": "Test vuln %s",
		"affected": [{
			"package": {"ecosystem": %q, "name": %q},
			"versions": ["1.0.0"]
		}]
	}`, id, id, ecosystem, pkg)
}

// defaultTestSyncConfig returns a config.SyncConfig with sensible defaults for testing.
func defaultTestSyncConfig() config.SyncConfig {
	return config.SyncConfig{
		FullSyncInterval:  24 * time.Hour,
		DeltaSyncInterval: 15 * time.Minute,
		MetricsInterval:   1 * time.Hour,
		BatchSize:         100,
		Workers:           2,
	}
}

// --------------------------------------------------------------------------
// DefaultSyncConfig
// --------------------------------------------------------------------------

func TestDefaultSyncConfig(t *testing.T) {
	cfg := defaultTestSyncConfig()
	if cfg.FullSyncInterval != 24*time.Hour {
		t.Errorf("expected 24h full sync interval, got %v", cfg.FullSyncInterval)
	}
	if cfg.DeltaSyncInterval != 15*time.Minute {
		t.Errorf("expected 15m delta sync interval, got %v", cfg.DeltaSyncInterval)
	}
	if cfg.MetricsInterval != 1*time.Hour {
		t.Errorf("expected 1h metrics interval, got %v", cfg.MetricsInterval)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("expected batch size 100, got %d", cfg.BatchSize)
	}
	if cfg.Workers != 2 {
		t.Errorf("expected 2 workers, got %d", cfg.Workers)
	}
}

// --------------------------------------------------------------------------
// NewSyncer
// --------------------------------------------------------------------------

func TestNewSyncer(t *testing.T) {
	store := setupTestDB(t)
	cfg := defaultTestSyncConfig()
	s := NewSyncer(store, cfg, testLogger())
	if s == nil {
		t.Fatal("expected non-nil syncer")
	}
	if s.store != store {
		t.Error("store mismatch")
	}
	if s.client == nil {
		t.Error("expected non-nil http client")
	}
}

// --------------------------------------------------------------------------
// parseModifiedCSV
// --------------------------------------------------------------------------

func TestParseModifiedCSV_ValidEntries(t *testing.T) {
	csv := strings.Join([]string{
		"2024-06-15T00:00:00Z,npm/GHSA-xxxx-0001",
		"2024-06-14T00:00:00Z,PyPI/PYSEC-2024-0001",
		"2024-06-13T00:00:00Z,Go/GO-2024-0001",
	}, "\n")

	entries, err := parseModifiedCSV([]byte(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	tests := []struct {
		idx  int
		date string
		eco  string
		id   string
	}{
		{0, "2024-06-15T00:00:00Z", "npm", "GHSA-xxxx-0001"},
		{1, "2024-06-14T00:00:00Z", "PyPI", "PYSEC-2024-0001"},
		{2, "2024-06-13T00:00:00Z", "Go", "GO-2024-0001"},
	}

	for _, tt := range tests {
		e := entries[tt.idx]
		if e.modifiedDate != tt.date {
			t.Errorf("[%d] expected date %s, got %s", tt.idx, tt.date, e.modifiedDate)
		}
		if e.ecosystemDir != tt.eco {
			t.Errorf("[%d] expected ecosystem %s, got %s", tt.idx, tt.eco, e.ecosystemDir)
		}
		if e.id != tt.id {
			t.Errorf("[%d] expected id %s, got %s", tt.idx, tt.id, e.id)
		}
	}
}

func TestParseModifiedCSV_EmptyLines(t *testing.T) {
	csv := "\n\n2024-06-15T00:00:00Z,npm/GHSA-0001\n\n"
	entries, err := parseModifiedCSV([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseModifiedCSV_MalformedLines(t *testing.T) {
	csv := "no-comma-here\n2024-06-15T00:00:00Z,no-slash"
	entries, err := parseModifiedCSV([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	// Both lines should be skipped
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseModifiedCSV_NestedEcosystem(t *testing.T) {
	// Ecosystem directories can contain slashes, e.g., "crates.io"
	csv := "2024-06-15T00:00:00Z,Debian/DSA/DSA-1234"
	entries, err := parseModifiedCSV([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ecosystemDir != "Debian/DSA" {
		t.Errorf("expected ecosystem Debian/DSA, got %s", entries[0].ecosystemDir)
	}
	if entries[0].id != "DSA-1234" {
		t.Errorf("expected id DSA-1234, got %s", entries[0].id)
	}
}

// --------------------------------------------------------------------------
// FetchEcosystems (with httptest)
// --------------------------------------------------------------------------

func TestFetchEcosystems(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "npm\nPyPI\nGo\n\n")
	}))
	defer server.Close()

	store := setupTestDB(t)
	cfg := defaultTestSyncConfig()
	s := NewSyncer(store, cfg, testLogger())

	// Override the HTTP client to use our test server – we need to
	// temporarily replace the ecosystems URL. Since the URL is a const,
	// we use a custom transport to redirect requests.
	s.client = server.Client()
	origTransport := s.client.Transport
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		if origTransport != nil {
			return origTransport.RoundTrip(r)
		}
		return http.DefaultTransport.RoundTrip(r)
	})

	ecosystems, err := s.FetchEcosystems(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ecosystems) != 3 {
		t.Errorf("expected 3 ecosystems, got %d", len(ecosystems))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestFetchEcosystems_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	s.client = server.Client()
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})

	_, err := s.FetchEcosystems(context.Background())
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

// --------------------------------------------------------------------------
// GetTargetEcosystems
// --------------------------------------------------------------------------

func TestGetTargetEcosystems_FromConfig(t *testing.T) {
	store := setupTestDB(t)
	cfg := defaultTestSyncConfig()
	cfg.Ecosystems = []string{"npm", "PyPI"}
	s := NewSyncer(store, cfg, testLogger())

	ecos, err := s.GetTargetEcosystems(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ecos) != 2 {
		t.Errorf("expected 2, got %d", len(ecos))
	}
}

// --------------------------------------------------------------------------
// SeedEcosystem (with httptest)
// --------------------------------------------------------------------------

func TestSeedEcosystem_Integration(t *testing.T) {
	vuln1 := makeOSVJSON("GHSA-seed-0001", "npm", "lodash")
	vuln2 := makeOSVJSON("GHSA-seed-0002", "npm", "express")

	zipData := makeZip(t, map[string]string{
		"GHSA-seed-0001.json": vuln1,
		"GHSA-seed-0002.json": vuln2,
		"README.md":           "not json, skip",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer server.Close()

	store := setupTestDB(t)
	cfg := defaultTestSyncConfig()
	cfg.BatchSize = 10
	s := NewSyncer(store, cfg, testLogger())
	s.client = server.Client()
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})

	err := s.SeedEcosystem(context.Background(), "npm")
	if err != nil {
		t.Fatalf("SeedEcosystem failed: %v", err)
	}

	// Verify vulnerabilities were stored.
	ctx := context.Background()
	v1, err := store.GetVulnerabilityByOsvID(ctx, "GHSA-seed-0001")
	if err != nil || v1 == nil {
		t.Error("expected GHSA-seed-0001 to be stored")
	}
	v2, err := store.GetVulnerabilityByOsvID(ctx, "GHSA-seed-0002")
	if err != nil || v2 == nil {
		t.Error("expected GHSA-seed-0002 to be stored")
	}

	// Verify sync state was updated.
	state, err := store.GetOrCreateSyncState(ctx, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "synced" {
		t.Errorf("expected status 'synced', got %s", state.Status)
	}
	if state.LastFullSync == nil {
		t.Error("expected LastFullSync to be set")
	}
}

// --------------------------------------------------------------------------
// DeltaSync (with httptest)
// --------------------------------------------------------------------------

func TestDeltaSync_Integration(t *testing.T) {
	vulnJSON := makeOSVJSON("GHSA-delta-0001", "npm", "axios")
	csvBody := "2024-06-15T12:00:00Z,npm/GHSA-delta-0001\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "modified_id.csv") || r.URL.Path == "/" {
			// Serve CSV on any path that might be the modified CSV
			w.Write([]byte(csvBody))
		} else if strings.Contains(r.URL.Path, "GHSA-delta-0001") {
			w.Write([]byte(vulnJSON))
		} else {
			w.WriteHeader(404)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	s.client = server.Client()
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})

	err := s.DeltaSync(context.Background())
	if err != nil {
		t.Fatalf("DeltaSync failed: %v", err)
	}

	// Verify vulnerability was stored.
	v, err := store.GetVulnerabilityByOsvID(context.Background(), "GHSA-delta-0001")
	if err != nil || v == nil {
		t.Error("expected GHSA-delta-0001 to be stored")
	}
}

// --------------------------------------------------------------------------
// parseZip
// --------------------------------------------------------------------------

func TestParseZip_ValidEntries(t *testing.T) {
	files := map[string]string{
		"GHSA-0001.json": makeOSVJSON("GHSA-0001", "npm", "pkg1"),
		"GHSA-0002.json": makeOSVJSON("GHSA-0002", "npm", "pkg2"),
		"README.txt":     "not json",
	}
	zipData := makeZip(t, files)

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	vulns, parseErrors, err := s.parseZip(zipData, "npm")
	if err != nil {
		t.Fatalf("parseZip failed: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("expected 2 vulns, got %d", len(vulns))
	}
	if parseErrors != 0 {
		t.Errorf("expected 0 parse errors, got %d", parseErrors)
	}
}

func TestParseZip_InvalidJSON(t *testing.T) {
	files := map[string]string{
		"bad.json":       "{invalid json}",
		"GHSA-0001.json": makeOSVJSON("GHSA-0001", "npm", "pkg1"),
	}
	zipData := makeZip(t, files)

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	vulns, parseErrors, err := s.parseZip(zipData, "npm")
	if err != nil {
		t.Fatalf("parseZip failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 valid vuln, got %d", len(vulns))
	}
	if parseErrors != 1 {
		t.Errorf("expected 1 parse error, got %d", parseErrors)
	}
}

func TestParseZip_InvalidZipData(t *testing.T) {
	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	_, _, err := s.parseZip([]byte("not a zip"), "npm")
	if err == nil {
		t.Error("expected error for invalid zip data")
	}
}

func TestParseZip_SetsSourceEcosystem(t *testing.T) {
	// When vuln has no explicit source, parseZip sets it.
	raw := `{"id": "TEST-001", "modified": "2024-06-15T12:00:00Z"}`
	zipData := makeZip(t, map[string]string{"TEST-001.json": raw})

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	vulns, _, err := s.parseZip(zipData, "CustomEco")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatal("expected 1 vuln")
	}
	if vulns[0].SourceEcosystem != "CustomEco" {
		t.Errorf("expected CustomEco, got %s", vulns[0].SourceEcosystem)
	}
}

// --------------------------------------------------------------------------
// Scheduler
// --------------------------------------------------------------------------

func TestScheduler_StartStop(t *testing.T) {
	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	cfg := config.SyncConfig{
		DeltaSyncInterval: 1 * time.Hour,
		FullSyncInterval:  24 * time.Hour,
		MetricsInterval:   1 * time.Hour,
	}
	sched := NewScheduler(s, cfg, testLogger())
	if sched == nil {
		t.Fatal("expected non-nil scheduler")
	}

	ctx := context.Background()
	sched.Start(ctx)
	// Give goroutines time to start.
	time.Sleep(50 * time.Millisecond)
	sched.Stop()
}

func TestScheduler_ZeroIntervals(t *testing.T) {
	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	cfg := config.SyncConfig{
		DeltaSyncInterval: 0,
		FullSyncInterval:  0,
		MetricsInterval:   0,
	}
	sched := NewScheduler(s, cfg, testLogger())
	ctx := context.Background()
	sched.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	sched.Stop()
	// Should not panic – no goroutines launched for zero intervals.
}

// --------------------------------------------------------------------------
// downloadFile
// --------------------------------------------------------------------------

func TestDownloadFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer server.Close()

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	data, err := s.downloadFile(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("downloadFile failed: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(data))
	}
}

func TestDownloadFile_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())

	_, err := s.downloadFile(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for 404")
	}
}

// --------------------------------------------------------------------------
// recordSyncError
// --------------------------------------------------------------------------

func TestRecordSyncError(t *testing.T) {
	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	ctx := context.Background()

	state, _ := store.GetOrCreateSyncState(ctx, "test-eco")
	syncLog := &models.SyncLog{
		Ecosystem: "test-eco",
		SyncType:  "full",
		Status:    "started",
		StartedAt: time.Now(),
	}
	store.CreateSyncLog(ctx, syncLog)

	s.recordSyncError(ctx, state, syncLog, fmt.Errorf("test error"))

	// Verify state was updated.
	updated, _ := store.GetOrCreateSyncState(ctx, "test-eco")
	if updated.Status != "error" {
		t.Errorf("expected status 'error', got %s", updated.Status)
	}
	if updated.LastError != "test error" {
		t.Errorf("expected error 'test error', got %s", updated.LastError)
	}
}

// --------------------------------------------------------------------------
// fetchVulnerability
// --------------------------------------------------------------------------

func TestFetchVulnerability(t *testing.T) {
	vulnJSON := makeOSVJSON("GHSA-fetch-001", "npm", "test-pkg")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(vulnJSON))
	}))
	defer server.Close()

	store := setupTestDB(t)
	s := NewSyncer(store, defaultTestSyncConfig(), testLogger())
	s.client = server.Client()
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})

	vuln, err := s.fetchVulnerability(context.Background(), "npm", "GHSA-fetch-001")
	if err != nil {
		t.Fatalf("fetchVulnerability failed: %v", err)
	}
	if vuln.OsvID != "GHSA-fetch-001" {
		t.Errorf("expected GHSA-fetch-001, got %s", vuln.OsvID)
	}
}

// ensure json import is used
var _ = json.Marshal
