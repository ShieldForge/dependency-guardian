// Package vulndb provides the concrete VulnerabilityDB implementation
// backed by the GORM-based OSV data store.
package vulndb

import (
	"context"
	"encoding/json"
	"log/slog"

	goversion "github.com/hashicorp/go-version"
	mvnversion "github.com/masahiro331/go-mvn-version"

	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/vulndb/dal"
	"dependency-guardian/internal/vulndb/models"

	pepversion "github.com/aquasecurity/go-pep440-version"
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
	cmp := comparerFor(c.Type, ecosystem)

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

// comparerFor returns a version comparison function appropriate for the
// given constraint type and ecosystem. SEMVER constraints always use
// hashicorp/go-version. ECOSYSTEM constraints dispatch to the
// ecosystem-specific library (Maven, PyPI, or go-version as fallback).
func comparerFor(constraintType, ecosystem string) func(a, b string) int {
	if constraintType == "SEMVER" {
		return compareSemver
	}
	switch ecosystem {
	case "Maven":
		return compareMaven
	case "PyPI":
		return comparePyPI
	default:
		return compareSemver
	}
}

// compareSemver compares versions using hashicorp/go-version (semver).
func compareSemver(a, b string) int {
	va, errA := goversion.NewVersion(a)
	vb, errB := goversion.NewVersion(b)
	if errA != nil || errB != nil {
		return fallbackCompare(a, b)
	}
	return va.Compare(vb)
}

// compareMaven compares versions using masahiro331/go-mvn-version.
func compareMaven(a, b string) int {
	va, errA := mvnversion.NewVersion(a)
	vb, errB := mvnversion.NewVersion(b)
	if errA != nil || errB != nil {
		return fallbackCompare(a, b)
	}
	return va.Compare(vb)
}

// comparePyPI compares versions using aquasecurity/go-pep440-version.
func comparePyPI(a, b string) int {
	va, errA := pepversion.Parse(a)
	vb, errB := pepversion.Parse(b)
	if errA != nil || errB != nil {
		return fallbackCompare(a, b)
	}
	return va.Compare(vb)
}

// fallbackCompare is a simple lexicographic comparison used when the
// ecosystem-specific parser fails to parse a version string.
func fallbackCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
