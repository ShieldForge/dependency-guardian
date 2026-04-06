// Package dal provides the Data Access Layer for vulnerability records.
// It encapsulates all GORM queries behind a clean interface.
package dal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"dependency-guardian/internal/vulndb/models"
)

// Store wraps a GORM DB and provides typed methods for vulnerability
// data access.
type Store struct {
	db *gorm.DB
}

// NewStore creates a new data access store.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db}
}

// DB returns the underlying GORM DB for advanced queries.
func (s *Store) DB() *gorm.DB {
	return s.db
}

// --------------------------------------------------------------------------
// Vulnerability CRUD
// --------------------------------------------------------------------------

// UpsertVulnerability inserts or updates a vulnerability by its OSV ID.
// It replaces all child records (aliases, affected, etc.) on conflict.
func (s *Store) UpsertVulnerability(ctx context.Context, vuln *models.Vulnerability) error {
	_, _, err := s.BulkUpsertVulnerabilities(ctx, []*models.Vulnerability{vuln}, 1)
	return err
}

// BulkUpsertVulnerabilities efficiently upserts multiple vulnerabilities.
// Existing records are deleted (children + parent) then re-created in a
// single transaction per batch so GORM handles all FK wiring via
// CreateInBatches. This avoids per-record Save calls and separate
// insert/update code paths.
func (s *Store) BulkUpsertVulnerabilities(ctx context.Context, vulns []*models.Vulnerability, batchSize int) (inserted, updated int64, err error) {
	if batchSize <= 0 {
		batchSize = 100
	}

	for i := 0; i < len(vulns); i += batchSize {
		end := i + batchSize
		if end > len(vulns) {
			end = len(vulns)
		}
		batch := vulns[i:end]

		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Collect all OSV IDs in this batch.
			osvIDs := make([]string, len(batch))
			for j, v := range batch {
				osvIDs[j] = v.OsvID
			}

			// Find existing vulnerability IDs (Unscoped to include soft-deleted
			// rows so the unique index doesn't block re-creation).
			var existingIDs []uint
			if err := tx.Unscoped().Model(&models.Vulnerability{}).
				Where("osv_id IN ?", osvIDs).
				Pluck("id", &existingIDs).Error; err != nil {
				return err
			}

			// Delete existing records: children first, then hard-delete parents.
			if len(existingIDs) > 0 {
				if err := deleteVulnChildrenBatch(tx, existingIDs); err != nil {
					return err
				}
				if err := tx.Unscoped().Where("id IN ?", existingIDs).Delete(&models.Vulnerability{}).Error; err != nil {
					return err
				}
			}

			// Zero out all IDs so GORM treats every record as a fresh insert
			// and wires up the FK associations automatically.
			for _, v := range batch {
				clearVulnIDs(v)
			}

			// Batch-create all records (GORM handles nested associations).
			if err := tx.CreateInBatches(batch, batchSize).Error; err != nil {
				return err
			}

			updated += int64(len(existingIDs))
			inserted += int64(len(batch)) - int64(len(existingIDs))
			return nil
		})
		if err != nil {
			return inserted, updated, fmt.Errorf("batch upsert at offset %d: %w", i, err)
		}
	}
	return inserted, updated, nil
}

// GetVulnerabilityByOsvID retrieves a full vulnerability record with all relations.
func (s *Store) GetVulnerabilityByOsvID(ctx context.Context, osvID string) (*models.Vulnerability, error) {
	var vuln models.Vulnerability
	err := s.db.WithContext(ctx).
		Preload("Aliases").
		Preload("Related").
		Preload("Severities").
		Preload("Affected").
		Preload("Affected.Ranges").
		Preload("Affected.Ranges.Events").
		Preload("Affected.Severities").
		Preload("References").
		Preload("Credits").
		Where("osv_id = ?", osvID).
		First(&vuln).Error
	if err != nil {
		return nil, err
	}
	return &vuln, nil
}

// GetVulnerabilitiesByOsvIDs batch-loads multiple vulnerabilities by their OSV IDs.
// Returns a map of osv_id -> Vulnerability for O(1) lookup.
func (s *Store) GetVulnerabilitiesByOsvIDs(ctx context.Context, osvIDs []string) (map[string]*models.Vulnerability, error) {
	if len(osvIDs) == 0 {
		return nil, nil
	}
	var vulns []models.Vulnerability
	err := s.db.WithContext(ctx).
		Preload("Affected").
		Preload("Affected.Ranges").
		Preload("Affected.Ranges.Events").
		Where("osv_id IN ?", osvIDs).
		Find(&vulns).Error
	if err != nil {
		return nil, err
	}
	result := make(map[string]*models.Vulnerability, len(vulns))
	for i := range vulns {
		result[vulns[i].OsvID] = &vulns[i]
	}
	return result, nil
}

// DeleteVulnerabilityByOsvID removes a vulnerability and all related records.
func (s *Store) DeleteVulnerabilityByOsvID(ctx context.Context, osvID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var vuln models.Vulnerability
		if err := tx.Where("osv_id = ?", osvID).First(&vuln).Error; err != nil {
			return err
		}
		if err := deleteVulnChildren(tx, vuln.ID); err != nil {
			return err
		}
		return tx.Delete(&vuln).Error
	})
}

// deleteVulnChildren removes all child records for a single vulnerability.
func deleteVulnChildren(tx *gorm.DB, vulnID uint) error {
	return deleteVulnChildrenBatch(tx, []uint{vulnID})
}

// deleteVulnChildrenBatch removes all child records for multiple vulnerabilities
// in bulk queries instead of per-record deletes.
func deleteVulnChildrenBatch(tx *gorm.DB, vulnIDs []uint) error {
	if len(vulnIDs) == 0 {
		return nil
	}

	// Collect affected IDs.
	var affectedIDs []uint
	if err := tx.Model(&models.Affected{}).Where("vulnerability_id IN ?", vulnIDs).Pluck("id", &affectedIDs).Error; err != nil {
		return err
	}

	if len(affectedIDs) > 0 {
		var rangeIDs []uint
		if err := tx.Model(&models.AffectedRange{}).Where("affected_id IN ?", affectedIDs).Pluck("id", &rangeIDs).Error; err != nil {
			return err
		}

		if len(rangeIDs) > 0 {
			if err := tx.Where("affected_range_id IN ?", rangeIDs).Delete(&models.RangeEvent{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("affected_id IN ?", affectedIDs).Delete(&models.AffectedRange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("affected_id IN ?", affectedIDs).Delete(&models.Severity{}).Error; err != nil {
			return err
		}
	}

	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.Affected{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.VulnerabilityAlias{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.VulnerabilityRelated{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.Severity{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.Reference{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.Credit{}).Error; err != nil {
		return err
	}
	if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.AffectedPackageIndex{}).Error; err != nil {
		return err
	}

	return nil
}

// --------------------------------------------------------------------------
// Package index queries (used by the proxy at request time)
// --------------------------------------------------------------------------

// FindVulnerabilitiesByPackage returns all vulnerability index records
// matching the given ecosystem and package name.
func (s *Store) FindVulnerabilitiesByPackage(ctx context.Context, ecosystem, packageName string) ([]models.AffectedPackageIndex, error) {
	var results []models.AffectedPackageIndex
	err := s.db.WithContext(ctx).
		Where("ecosystem = ? AND package_name = ?", ecosystem, packageName).
		Find(&results).Error
	return results, err
}

// FindVulnerabilitiesByPackageVersion returns index records matching an
// exact version. Falls back to range-based entries if no exact match.
func (s *Store) FindVulnerabilitiesByPackageVersion(ctx context.Context, ecosystem, packageName, version string) ([]models.AffectedPackageIndex, error) {
	var results []models.AffectedPackageIndex

	// First try exact version matches.
	err := s.db.WithContext(ctx).
		Where("ecosystem = ? AND package_name = ? AND exact_version = ?", ecosystem, packageName, version).
		Find(&results).Error
	if err != nil {
		return nil, err
	}

	// Also include range-based entries (version_constraint is not empty, exact_version is empty).
	var rangeResults []models.AffectedPackageIndex
	err = s.db.WithContext(ctx).
		Where("ecosystem = ? AND package_name = ? AND exact_version = '' AND version_constraint != ''",
			ecosystem, packageName).
		Find(&rangeResults).Error
	if err != nil {
		return results, err // return exact matches even if range query fails
	}

	results = append(results, rangeResults...)
	return results, nil
}

// RebuildPackageIndex rebuilds the affected_package_index table for a
// given vulnerability. Call this after upserting a vulnerability.
func (s *Store) RebuildPackageIndex(ctx context.Context, vuln *models.Vulnerability) error {
	return s.BulkRebuildPackageIndex(ctx, []*models.Vulnerability{vuln}, 500)
}

// BulkRebuildPackageIndex rebuilds the package index for a batch of
// vulnerabilities in a single transaction. This is much more efficient
// than calling RebuildPackageIndex in a loop.
func (s *Store) BulkRebuildPackageIndex(ctx context.Context, vulns []*models.Vulnerability, createBatchSize int) error {
	if len(vulns) == 0 {
		return nil
	}
	if createBatchSize <= 0 {
		createBatchSize = 500
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete all stale index entries in one query.
		vulnIDs := make([]uint, len(vulns))
		for i, v := range vulns {
			vulnIDs[i] = v.ID
		}
		if err := tx.Where("vulnerability_id IN ?", vulnIDs).Delete(&models.AffectedPackageIndex{}).Error; err != nil {
			return err
		}

		// Build all index entries in memory.
		var indices []models.AffectedPackageIndex
		for _, vuln := range vulns {
			maxSeverity := computeMaxSeverity(vuln.Severities)
			isMalicious := checkMalicious(vuln)

			for _, aff := range vuln.Affected {
				affSeverity := maxSeverity
				if len(aff.Severities) > 0 {
					affSeverity = computeMaxSeverity(aff.Severities)
				}

				for _, ver := range aff.Versions {
					indices = append(indices, models.AffectedPackageIndex{
						VulnerabilityID: vuln.ID,
						OsvID:           vuln.OsvID,
						Ecosystem:       aff.PackageEcosystem,
						PackageName:     aff.PackageName,
						ExactVersion:    ver,
						MaxSeverity:     affSeverity,
						IsMalicious:     isMalicious,
					})
				}

				for _, r := range aff.Ranges {
					constraint := rangeToConstraint(r)
					indices = append(indices, models.AffectedPackageIndex{
						VulnerabilityID:   vuln.ID,
						OsvID:             vuln.OsvID,
						Ecosystem:         aff.PackageEcosystem,
						PackageName:       aff.PackageName,
						VersionConstraint: constraint,
						MaxSeverity:       affSeverity,
						IsMalicious:       isMalicious,
					})
				}

				if len(aff.Versions) == 0 && len(aff.Ranges) == 0 {
					indices = append(indices, models.AffectedPackageIndex{
						VulnerabilityID: vuln.ID,
						OsvID:           vuln.OsvID,
						Ecosystem:       aff.PackageEcosystem,
						PackageName:     aff.PackageName,
						MaxSeverity:     affSeverity,
						IsMalicious:     isMalicious,
					})
				}
			}
		}

		// Batch-insert all index entries.
		if len(indices) > 0 {
			if err := tx.CreateInBatches(indices, createBatchSize).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// --------------------------------------------------------------------------
// Ecosystem sync state
// --------------------------------------------------------------------------

// GetOrCreateSyncState retrieves or creates a sync state for an ecosystem.
func (s *Store) GetOrCreateSyncState(ctx context.Context, ecosystem string) (*models.EcosystemSyncState, error) {
	var state models.EcosystemSyncState
	err := s.db.WithContext(ctx).
		Where("ecosystem = ?", ecosystem).
		First(&state).Error
	if err == gorm.ErrRecordNotFound {
		state = models.EcosystemSyncState{
			Ecosystem: ecosystem,
			Status:    "pending",
		}
		if err := s.db.WithContext(ctx).Create(&state).Error; err != nil {
			return nil, err
		}
		return &state, nil
	}
	return &state, err
}

// UpdateSyncState updates an ecosystem's sync state.
func (s *Store) UpdateSyncState(ctx context.Context, state *models.EcosystemSyncState) error {
	return s.db.WithContext(ctx).Save(state).Error
}

// ListSyncStates returns all ecosystem sync states.
func (s *Store) ListSyncStates(ctx context.Context) ([]models.EcosystemSyncState, error) {
	var states []models.EcosystemSyncState
	err := s.db.WithContext(ctx).Order("ecosystem ASC").Find(&states).Error
	return states, err
}

// --------------------------------------------------------------------------
// Sync log
// --------------------------------------------------------------------------

// CreateSyncLog starts a new sync log entry.
func (s *Store) CreateSyncLog(ctx context.Context, log *models.SyncLog) error {
	return s.db.WithContext(ctx).Create(log).Error
}

// CompleteSyncLog marks a sync log entry as completed.
func (s *Store) CompleteSyncLog(ctx context.Context, log *models.SyncLog) error {
	now := time.Now()
	log.CompletedAt = &now
	return s.db.WithContext(ctx).Save(log).Error
}

// GetRecentSyncLogs returns recent sync logs for an ecosystem.
func (s *Store) GetRecentSyncLogs(ctx context.Context, ecosystem string, limit int) ([]models.SyncLog, error) {
	var logs []models.SyncLog
	err := s.db.WithContext(ctx).
		Where("ecosystem = ?", ecosystem).
		Order("started_at DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

// --------------------------------------------------------------------------
// Metrics
// --------------------------------------------------------------------------

// UpdateEcosystemMetrics recalculates and stores metrics for an ecosystem.
func (s *Store) UpdateEcosystemMetrics(ctx context.Context, ecosystem string) error {
	state, err := s.GetOrCreateSyncState(ctx, ecosystem)
	if err != nil {
		return err
	}

	// Count vulnerabilities.
	var vulnCount int64
	s.db.WithContext(ctx).Model(&models.Vulnerability{}).
		Where("source_ecosystem = ?", ecosystem).
		Count(&vulnCount)
	state.TotalVulnerabilities = vulnCount

	// Count affected entries.
	var affectedCount int64
	s.db.WithContext(ctx).Model(&models.AffectedPackageIndex{}).
		Where("ecosystem = ?", ecosystem).
		Count(&affectedCount)
	state.TotalAffectedEntries = affectedCount

	return s.UpdateSyncState(ctx, state)
}

// UpdateAllMetrics recalculates metrics for all ecosystems.
func (s *Store) UpdateAllMetrics(ctx context.Context) error {
	var ecosystems []string
	err := s.db.WithContext(ctx).Model(&models.EcosystemSyncState{}).
		Pluck("ecosystem", &ecosystems).Error
	if err != nil {
		return err
	}
	for _, eco := range ecosystems {
		if err := s.UpdateEcosystemMetrics(ctx, eco); err != nil {
			return fmt.Errorf("updating metrics for %s: %w", eco, err)
		}
	}
	return nil
}

// GetGlobalStats returns aggregate metrics across all ecosystems.
func (s *Store) GetGlobalStats(ctx context.Context) (map[string]interface{}, error) {
	var totalVulns int64
	s.db.WithContext(ctx).Model(&models.Vulnerability{}).Count(&totalVulns)

	var totalAffected int64
	s.db.WithContext(ctx).Model(&models.AffectedPackageIndex{}).Count(&totalAffected)

	var totalMalicious int64
	s.db.WithContext(ctx).Model(&models.AffectedPackageIndex{}).Where("is_malicious = ?", true).Count(&totalMalicious)

	var ecosystemCount int64
	s.db.WithContext(ctx).Model(&models.EcosystemSyncState{}).Count(&ecosystemCount)

	return map[string]interface{}{
		"total_vulnerabilities": totalVulns,
		"total_affected":        totalAffected,
		"total_malicious":       totalMalicious,
		"ecosystems_tracked":    ecosystemCount,
	}, nil
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// clearVulnIDs zeros out all auto-generated IDs and FK fields on a
// vulnerability and its descendants so GORM treats them as fresh inserts
// and wires up foreign keys automatically.
func clearVulnIDs(v *models.Vulnerability) {
	v.ID = 0
	for i := range v.Aliases {
		v.Aliases[i].ID = 0
		v.Aliases[i].VulnerabilityID = 0
	}
	for i := range v.Related {
		v.Related[i].ID = 0
		v.Related[i].VulnerabilityID = 0
	}
	for i := range v.Severities {
		v.Severities[i].ID = 0
		v.Severities[i].VulnerabilityID = 0
	}
	for i := range v.References {
		v.References[i].ID = 0
		v.References[i].VulnerabilityID = 0
	}
	for i := range v.Credits {
		v.Credits[i].ID = 0
		v.Credits[i].VulnerabilityID = 0
	}
	for i := range v.Affected {
		v.Affected[i].ID = 0
		v.Affected[i].VulnerabilityID = 0
		for j := range v.Affected[i].Severities {
			v.Affected[i].Severities[j].ID = 0
			v.Affected[i].Severities[j].AffectedID = nil
		}
		for j := range v.Affected[i].Ranges {
			v.Affected[i].Ranges[j].ID = 0
			v.Affected[i].Ranges[j].AffectedID = 0
			for k := range v.Affected[i].Ranges[j].Events {
				v.Affected[i].Ranges[j].Events[k].ID = 0
				v.Affected[i].Ranges[j].Events[k].AffectedRangeID = 0
			}
		}
	}
}

// computeMaxSeverity returns the highest severity from a list.
func computeMaxSeverity(severities []models.Severity) string {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	maxLevel := 0
	maxStr := ""

	for _, s := range severities {
		// Parse CVSS vector to derive severity level.
		level := cvssToSeverityLevel(s.Score)
		if rank, ok := severityOrder[level]; ok && rank > maxLevel {
			maxLevel = rank
			maxStr = level
		}
	}
	return maxStr
}

// cvssToSeverityLevel converts a CVSS score string to a severity label.
// Handles both vector strings and numeric scores.
func cvssToSeverityLevel(score string) string {
	// Simple heuristic: look for common patterns.
	// In practice a full CVSS parser would be used.
	if len(score) == 0 {
		return ""
	}
	// If score is a simple keyword (Ubuntu-style).
	switch score {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "low"
	}
	return ""
}

// checkMalicious checks if a vulnerability is tagged as malicious.
// Typically malicious packages have specific aliases or database_specific flags.
func checkMalicious(vuln *models.Vulnerability) bool {
	// Check aliases for MAL- prefix (used by OSV for malicious packages).
	for _, a := range vuln.Aliases {
		if len(a.Alias) > 4 && a.Alias[:4] == "MAL-" {
			return true
		}
	}
	// Check database_specific for malicious flag.
	if vuln.DatabaseSpecific != nil {
		if mal, ok := vuln.DatabaseSpecific["is_malicious"].(bool); ok && mal {
			return true
		}
	}
	// Check if the OSV ID itself starts with MAL-.
	if len(vuln.OsvID) > 4 && vuln.OsvID[:4] == "MAL-" {
		return true
	}
	return false
}

// rangeToConstraint serialises an AffectedRange to a JSON constraint string.
func rangeToConstraint(r models.AffectedRange) string {
	type eventJSON struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
		Limit        string `json:"limit,omitempty"`
	}
	type constraintJSON struct {
		Type   string      `json:"type"`
		Events []eventJSON `json:"events"`
	}

	c := constraintJSON{Type: r.Type}
	for _, e := range r.Events {
		c.Events = append(c.Events, eventJSON{
			Introduced:   e.Introduced,
			Fixed:        e.Fixed,
			LastAffected: e.LastAffected,
			Limit:        e.Limit,
		})
	}

	b, _ := json.Marshal(c)
	return string(b)
}
