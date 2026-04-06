// Package sync implements the OSV vulnerability data synchronisation
// logic. It handles:
//   - Fetching the list of ecosystems from osv.dev
//   - Seeding/re-seeding from bulk zip downloads
//   - Delta updates from the modified_id.csv feed
//   - Periodic metrics recalculation
//   - Background scheduling
package sync

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/models"
	"dependency-guardian/internal/vulndb/osvparser"
)

const (
	// OSV data source URLs.
	ecosystemsListURL = "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt"
	ecosystemZipURL   = "https://storage.googleapis.com/osv-vulnerabilities/%s/all.zip"
	modifiedCSVURL    = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"

	defaultBatchSize = 100

	// maxDownloadSize caps the size of any single HTTP download to prevent
	// out-of-memory conditions from malformed or unexpectedly large responses.
	maxDownloadSize = 4 << 30 // 4 GB

	// Retry settings for HTTP downloads.
	maxRetries     = 3
	retryBaseDelay = 2 * time.Second
)

// Syncer orchestrates vulnerability data synchronisation.
type Syncer struct {
	store  *dal.Store
	cfg    config.SyncConfig
	client *http.Client
	logger *slog.Logger
}

// NewSyncer creates a new vulnerability data syncer.
func NewSyncer(store *dal.Store, cfg config.SyncConfig, logger *slog.Logger) *Syncer {
	return &Syncer{
		store:  store,
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Minute},
		logger: logger.With("component", "vulndb-sync"),
	}
}

// --------------------------------------------------------------------------
// Ecosystem discovery
// --------------------------------------------------------------------------

// FetchEcosystems downloads the list of supported ecosystems from osv.dev.
func (s *Syncer) FetchEcosystems(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ecosystemsListURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching ecosystems list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ecosystems list returned HTTP %d", resp.StatusCode)
	}

	var ecosystems []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		eco := strings.TrimSpace(scanner.Text())
		if eco != "" {
			ecosystems = append(ecosystems, eco)
		}
	}
	return ecosystems, scanner.Err()
}

// DefaultEcosystems are the ecosystems matching the proxy's built-in
// handlers. Used when no explicit list is configured.
var DefaultEcosystems = []string{"npm", "PyPI", "Go"}

// GetTargetEcosystems returns the ecosystems to sync – either from
// config or the default set that matches the proxy's handlers.
func (s *Syncer) GetTargetEcosystems(ctx context.Context) ([]string, error) {
	if len(s.cfg.Ecosystems) > 0 {
		return s.cfg.Ecosystems, nil
	}
	return DefaultEcosystems, nil
}

// --------------------------------------------------------------------------
// Full sync (seed / re-seed)
// --------------------------------------------------------------------------

// SeedEcosystem downloads all.zip for an ecosystem and upserts every
// vulnerability into the database.
func (s *Syncer) SeedEcosystem(ctx context.Context, ecosystem string) error {
	s.logger.Info("starting full sync", "ecosystem", ecosystem)

	// Update sync state.
	state, err := s.store.GetOrCreateSyncState(ctx, ecosystem)
	if err != nil {
		return err
	}
	state.Status = "syncing"
	s.store.UpdateSyncState(ctx, state)

	// Create sync log.
	syncLog := &models.SyncLog{
		Ecosystem: ecosystem,
		SyncType:  "full",
		Status:    "started",
		StartedAt: time.Now(),
	}
	s.store.CreateSyncLog(ctx, syncLog)

	// Download the zip.
	url := fmt.Sprintf(ecosystemZipURL, ecosystem)
	zipData, err := s.downloadFile(ctx, url)
	if err != nil {
		s.recordSyncError(ctx, state, syncLog, fmt.Errorf("downloading %s: %w", url, err))
		return err
	}

	s.logger.Info("downloaded ecosystem data", "ecosystem", ecosystem, "size_bytes", len(zipData))

	// Parse all JSON files from the zip.
	vulns, parseErrors, err := s.parseZip(zipData, ecosystem)
	if err != nil {
		s.recordSyncError(ctx, state, syncLog, err)
		return err
	}
	if parseErrors > 0 {
		s.logger.Warn("some records failed to parse", "ecosystem", ecosystem, "errors", parseErrors)
	}

	s.logger.Info("parsed vulnerabilities from zip", "ecosystem", ecosystem, "count", len(vulns))

	// Bulk upsert.
	batchSize := s.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	inserted, updated, err := s.store.BulkUpsertVulnerabilities(ctx, vulns, batchSize)
	if err != nil {
		s.recordSyncError(ctx, state, syncLog, err)
		return err
	}

	// Rebuild package index in batches.
	for i := 0; i < len(vulns); i += batchSize {
		end := i + batchSize
		if end > len(vulns) {
			end = len(vulns)
		}
		if err := s.store.BulkRebuildPackageIndex(ctx, vulns[i:end], 500); err != nil {
			s.logger.Warn("failed to rebuild index batch", "offset", i, "error", err)
		}
	}

	// Update sync state.
	now := time.Now()
	state.Status = "synced"
	state.LastFullSync = &now
	state.LastError = ""
	state.LastErrorAt = nil
	s.store.UpdateSyncState(ctx, state)

	// Complete sync log.
	syncLog.Status = "completed"
	syncLog.RecordsProcessed = int64(len(vulns))
	syncLog.RecordsInserted = inserted
	syncLog.RecordsUpdated = updated
	s.store.CompleteSyncLog(ctx, syncLog)

	s.logger.Info("full sync complete",
		"ecosystem", ecosystem,
		"inserted", inserted,
		"updated", updated,
		"total", len(vulns),
	)

	// Update metrics.
	s.store.UpdateEcosystemMetrics(ctx, ecosystem)

	return nil
}

// SeedAll syncs all target ecosystems concurrently using a worker pool.
// Returns a multi-error collecting all ecosystem failures.
func (s *Syncer) SeedAll(ctx context.Context) error {
	ecosystems, err := s.GetTargetEcosystems(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("starting full sync for all ecosystems", "count", len(ecosystems))

	workers := s.cfg.Workers
	if workers < 1 {
		workers = 1
	}

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		sem  = make(chan struct{}, workers)
	)

	for _, eco := range ecosystems {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(ecosystem string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := s.SeedEcosystem(ctx, ecosystem); err != nil {
				s.logger.Error("ecosystem sync failed", "ecosystem", ecosystem, "error", err)
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", ecosystem, err))
				mu.Unlock()
			}
		}(eco)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("seed failed for %d ecosystem(s): %w", len(errs), errors.Join(errs...))
	}
	return nil
}

// --------------------------------------------------------------------------
// Delta sync
// --------------------------------------------------------------------------

// DeltaSync downloads modified_id.csv and applies changes for records
// modified since the last delta cursor.
func (s *Syncer) DeltaSync(ctx context.Context) error {
	s.logger.Info("starting delta sync")

	targets, err := s.GetTargetEcosystems(ctx)
	if err != nil {
		return fmt.Errorf("resolving target ecosystems: %w", err)
	}
	targetSet := make(map[string]bool, len(targets))
	for _, t := range targets {
		targetSet[t] = true
	}

	csvData, err := s.downloadFile(ctx, modifiedCSVURL)
	if err != nil {
		return fmt.Errorf("downloading modified_id.csv: %w", err)
	}

	entries, err := parseModifiedCSV(csvData)
	if err != nil {
		return err
	}

	s.logger.Info("parsed modified_id.csv", "total_entries", len(entries))

	// Group entries by ecosystem directory, filtering to target ecosystems.
	byEcosystem := make(map[string][]modifiedEntry)
	for _, e := range entries {
		if targetSet[e.ecosystemDir] {
			byEcosystem[e.ecosystemDir] = append(byEcosystem[e.ecosystemDir], e)
		}
	}

	for eco, ecoEntries := range byEcosystem {
		if err := s.applyDeltaForEcosystem(ctx, eco, ecoEntries); err != nil {
			s.logger.Error("delta sync failed for ecosystem", "ecosystem", eco, "error", err)
		}
	}

	return nil
}

// applyDeltaForEcosystem processes delta updates for a single ecosystem.
func (s *Syncer) applyDeltaForEcosystem(ctx context.Context, ecosystem string, entries []modifiedEntry) error {
	state, err := s.store.GetOrCreateSyncState(ctx, ecosystem)
	if err != nil {
		return err
	}

	// Filter entries newer than our last delta cursor.
	var newEntries []modifiedEntry
	for _, e := range entries {
		if state.LastDeltaCursor == "" || e.modifiedDate > state.LastDeltaCursor {
			newEntries = append(newEntries, e)
		}
	}

	if len(newEntries) == 0 {
		s.logger.Debug("no new delta entries", "ecosystem", ecosystem)
		return nil
	}

	s.logger.Info("applying delta updates",
		"ecosystem", ecosystem,
		"entries", len(newEntries),
	)

	syncLog := &models.SyncLog{
		Ecosystem: ecosystem,
		SyncType:  "delta",
		Status:    "started",
		StartedAt: time.Now(),
	}
	s.store.CreateSyncLog(ctx, syncLog)

	var inserted, updated int64
	var latestCursor string

	// Fetch all delta vulnerabilities first, then batch-process.
	var fetched []*models.Vulnerability
	for _, entry := range newEntries {
		vuln, err := s.fetchVulnerability(ctx, entry.ecosystemDir, entry.id)
		if err != nil {
			s.logger.Warn("failed to fetch vulnerability", "id", entry.id, "error", err)
			continue
		}
		fetched = append(fetched, vuln)
		if entry.modifiedDate > latestCursor {
			latestCursor = entry.modifiedDate
		}
	}

	// Batch upsert.
	if len(fetched) > 0 {
		batchSize := 100
		ins, upd, err := s.store.BulkUpsertVulnerabilities(ctx, fetched, batchSize)
		if err != nil {
			s.logger.Error("delta batch upsert failed", "ecosystem", ecosystem, "error", err)
		} else {
			inserted = ins
			updated = upd
		}

		// Batch rebuild index.
		if err := s.store.BulkRebuildPackageIndex(ctx, fetched, 500); err != nil {
			s.logger.Warn("delta index rebuild failed", "ecosystem", ecosystem, "error", err)
		}
	}

	// Update cursor.
	if latestCursor != "" {
		state.LastDeltaCursor = latestCursor
	}
	now := time.Now()
	state.LastDeltaSync = &now
	s.store.UpdateSyncState(ctx, state)

	syncLog.Status = "completed"
	syncLog.RecordsProcessed = int64(len(newEntries))
	syncLog.RecordsInserted = inserted
	syncLog.RecordsUpdated = updated
	s.store.CompleteSyncLog(ctx, syncLog)

	s.logger.Info("delta sync complete",
		"ecosystem", ecosystem,
		"inserted", inserted,
		"updated", updated,
	)

	return nil
}

// fetchVulnerability fetches a single vulnerability JSON from osv.dev.
// The URL pattern is: https://api.osv.dev/v1/vulns/<ID>
func (s *Syncer) fetchVulnerability(ctx context.Context, ecosystemDir, id string) (*models.Vulnerability, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", id)
	data, err := s.downloadFile(ctx, url)
	if err != nil {
		return nil, err
	}
	vuln, err := osvparser.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	if vuln.SourceEcosystem == "" {
		vuln.SourceEcosystem = ecosystemDir
	}
	return vuln, nil
}

// --------------------------------------------------------------------------
// CSV parsing
// --------------------------------------------------------------------------

type modifiedEntry struct {
	modifiedDate string // ISO date string
	ecosystemDir string // ecosystem directory name
	id           string // vulnerability ID
}

// parseModifiedCSV parses the modified_id.csv content.
// Format: <iso modified date>,<ecosystem_dir>/<id>
func parseModifiedCSV(data []byte) ([]modifiedEntry, error) {
	var entries []modifiedEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split on first comma.
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}

		modDate := strings.TrimSpace(parts[0])
		ecoAndID := strings.TrimSpace(parts[1])

		// Split ecosystem_dir/id on last slash.
		slashIdx := strings.LastIndex(ecoAndID, "/")
		if slashIdx < 0 {
			continue
		}
		ecosystemDir := ecoAndID[:slashIdx]
		id := ecoAndID[slashIdx+1:]

		entries = append(entries, modifiedEntry{
			modifiedDate: modDate,
			ecosystemDir: ecosystemDir,
			id:           id,
		})
	}

	return entries, scanner.Err()
}

// --------------------------------------------------------------------------
// Zip parsing
// --------------------------------------------------------------------------

// parseZip extracts all .json files from a zip archive and converts
// them to vulnerability models.
func (s *Syncer) parseZip(data []byte, ecosystem string) ([]*models.Vulnerability, int, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, 0, fmt.Errorf("opening zip: %w", err)
	}

	var vulns []*models.Vulnerability
	parseErrors := 0

	for _, f := range reader.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			s.logger.Warn("failed to open zip entry", "file", f.Name, "error", err)
			parseErrors++
			continue
		}

		jsonData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			s.logger.Warn("failed to read zip entry", "file", f.Name, "error", err)
			parseErrors++
			continue
		}

		vuln, err := osvparser.ParseJSON(jsonData)
		if err != nil {
			s.logger.Warn("failed to parse vulnerability", "file", f.Name, "error", err)
			parseErrors++
			continue
		}

		if vuln.SourceEcosystem == "" {
			vuln.SourceEcosystem = ecosystem
		}

		vulns = append(vulns, vuln)
	}

	return vulns, parseErrors, nil
}

// --------------------------------------------------------------------------
// HTTP helpers
// --------------------------------------------------------------------------

func (s *Syncer) downloadFile(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay * time.Duration(1<<(attempt-1)) // exponential: 2s, 4s, 8s
			s.logger.Warn("retrying download", "url", url, "attempt", attempt, "delay", delay)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
			// Only retry on 5xx or 429 (rate limit).
			if resp.StatusCode >= 500 || resp.StatusCode == 429 {
				continue
			}
			return nil, lastErr
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("download failed after %d attempts: %w", maxRetries+1, lastErr)
}

// --------------------------------------------------------------------------
// Sync error recording
// --------------------------------------------------------------------------

func (s *Syncer) recordSyncError(ctx context.Context, state *models.EcosystemSyncState, syncLog *models.SyncLog, syncErr error) {
	now := time.Now()
	state.Status = "error"
	state.LastError = syncErr.Error()
	state.LastErrorAt = &now
	s.store.UpdateSyncState(ctx, state)

	syncLog.Status = "failed"
	syncLog.ErrorMessage = syncErr.Error()
	s.store.CompleteSyncLog(ctx, syncLog)
}
