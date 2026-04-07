// Package vulndb provides the concrete VulnerabilityDB implementation
// backed by the GORM-based OSV data store.
package vulndb

import (
	"context"
	"encoding/json"
	"log/slog"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/vercmp"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/models"
)

// OSVDatabase implements registry.VulnerabilityDB using the local
// GORM-backed OSV vulnerability store.
type OSVDatabase struct {
	store  *dal.Store
	logger *slog.Logger
}

// NewOSVDatabase creates a new OSV-backed vulnerability database.
func NewOSVDatabase(store *dal.Store, logger *slog.Logger) *OSVDatabase {
	return &OSVDatabase{
		store:  store,
		logger: logger.With("component", "vulndb"),
	}
}

// GetVulnerabilities implements registry.VulnerabilityDB.
// It queries the affected_package_index for matching records and
// converts them to the registry.VulnerabilityRecord format.
func (db *OSVDatabase) GetVulnerabilities(ctx context.Context, ecosystem registry.Ecosystem, name, version string) ([]registry.VulnerabilityRecord, error) {
	// Map proxy ecosystem names to OSV ecosystem names.
	osvEcosystem := mapEcosystem(ecosystem)

	// Query the package index.
	indexRecords, err := db.store.FindVulnerabilitiesByPackageVersion(ctx, osvEcosystem, name, version)
	if err != nil {
		return nil, err
	}

	if len(indexRecords) == 0 {
		return nil, nil
	}

	// Deduplicate and filter index records.
	seen := make(map[string]struct{})
	var uniqueIDs []string
	type indexInfo struct {
		idx models.AffectedPackageIndex
	}
	var matched []indexInfo

	for _, idx := range indexRecords {
		if _, ok := seen[idx.OsvID]; ok {
			continue
		}

		// Check version match for range-based constraints.
		if idx.ExactVersion == "" && idx.VersionConstraint != "" {
			if !VersionMatchesConstraint(version, idx.VersionConstraint, osvEcosystem) {
				continue
			}
		}

		seen[idx.OsvID] = struct{}{}
		uniqueIDs = append(uniqueIDs, idx.OsvID)
		matched = append(matched, indexInfo{idx: idx})
	}

	if len(uniqueIDs) == 0 {
		return nil, nil
	}

	// Batch-load full vulnerability records in a single query.
	vulnMap, err := db.store.GetVulnerabilitiesByOsvIDs(ctx, uniqueIDs)
	if err != nil {
		db.logger.Warn("batch vulnerability lookup failed", "error", err)
		vulnMap = nil // fall through with empty map
	}

	var results []registry.VulnerabilityRecord
	for _, m := range matched {
		severity := m.idx.MaxSeverity
		if severity == "" {
			severity = "unknown"
		}

		summary := ""
		fixedIn := ""
		if vuln, ok := vulnMap[m.idx.OsvID]; ok {
			summary = vuln.Summary
			fixedIn = findFixedVersion(vuln, osvEcosystem, name)
		}

		results = append(results, registry.VulnerabilityRecord{
			ID:          m.idx.OsvID,
			Severity:    severity,
			Summary:     summary,
			FixedIn:     fixedIn,
			IsMalicious: m.idx.IsMalicious,
		})
	}

	return results, nil
}

// Store returns the underlying DAL store for direct access if needed.
func (db *OSVDatabase) Store() *dal.Store {
	return db.store
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// mapEcosystem converts proxy ecosystem identifiers to OSV ecosystem names.
func mapEcosystem(eco registry.Ecosystem) string {
	switch eco {
	case registry.EcosystemNPM:
		return "npm"
	case registry.EcosystemPyPI:
		return "PyPI"
	case registry.EcosystemGo:
		return "Go"
	default:
		return string(eco)
	}
}

// findFixedVersion looks through a vulnerability's affected records to
// find the "fixed" version for the given package.
func findFixedVersion(vuln *models.Vulnerability, ecosystem, name string) string {
	for _, aff := range vuln.Affected {
		if aff.PackageEcosystem != ecosystem || aff.PackageName != name {
			continue
		}
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// VersionMatchesConstraint checks if a version falls within a JSON-encoded
// range constraint. Handles introduced/fixed/last_affected ranges for
// SEMVER and ECOSYSTEM types using ecosystem-specific version comparison.
func VersionMatchesConstraint(version, constraintJSON, ecosystem string) bool {
	type eventJSON struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
		Limit        string `json:"limit,omitempty"`
	}
	type constraintData struct {
		Type   string      `json:"type"`
		Events []eventJSON `json:"events"`
	}

	var c constraintData
	if err := json.Unmarshal([]byte(constraintJSON), &c); err != nil {
		return false
	}

	// For GIT type ranges, we can't do version comparison.
	if c.Type == "GIT" {
		return false
	}

	// Pick comparison based on constraint type and ecosystem.
	cmp := vercmp.ComparerFor(c.Type, ecosystem)

	introduced := false
	for _, e := range c.Events {
		if e.Introduced != "" {
			if e.Introduced == "0" {
				introduced = true
			} else if cmp(version, e.Introduced) >= 0 {
				introduced = true
			}
		}
		if e.Fixed != "" && cmp(version, e.Fixed) >= 0 {
			introduced = false
		}
		if e.LastAffected != "" && cmp(version, e.LastAffected) > 0 {
			introduced = false
		}
	}

	return introduced
}
