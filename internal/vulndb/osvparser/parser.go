// Package osvparser converts raw OSV JSON records into GORM model structs.
package osvparser

import (
	"encoding/json"
	"fmt"
	"time"

	"dependency-guardian/internal/vulndb/models"
)

// --------------------------------------------------------------------------
// Raw OSV JSON structures (mirrors the ossf/osv-schema)
// --------------------------------------------------------------------------

// RawVulnerability is the top-level OSV JSON record.
type RawVulnerability struct {
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published,omitempty"`
	Withdrawn        string                 `json:"withdrawn,omitempty"`
	Aliases          []string               `json:"aliases,omitempty"`
	Related          []string               `json:"related,omitempty"`
	Summary          string                 `json:"summary,omitempty"`
	Details          string                 `json:"details,omitempty"`
	Severity         []RawSeverity          `json:"severity,omitempty"`
	Affected         []RawAffected          `json:"affected,omitempty"`
	References       []RawReference         `json:"references,omitempty"`
	Credits          []RawCredit            `json:"credits,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// RawSeverity represents a severity entry.
type RawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// RawAffected represents an affected package entry.
type RawAffected struct {
	Package           *RawPackage            `json:"package,omitempty"`
	Severity          []RawSeverity          `json:"severity,omitempty"`
	Ranges            []RawRange             `json:"ranges,omitempty"`
	Versions          []string               `json:"versions,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
}

// RawPackage identifies an affected package.
type RawPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// RawRange represents a version range.
type RawRange struct {
	Type             string                 `json:"type"`
	Repo             string                 `json:"repo,omitempty"`
	Events           []RawEvent             `json:"events,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// RawEvent represents a single range event.
type RawEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// RawReference represents a reference URL.
type RawReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// RawCredit represents a credit entry.
type RawCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// --------------------------------------------------------------------------
// Parsing
// --------------------------------------------------------------------------

// ParseJSON parses a single JSON-encoded OSV record into a GORM model.
func ParseJSON(data []byte) (*models.Vulnerability, error) {
	var raw RawVulnerability
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing OSV JSON: %w", err)
	}
	return Convert(&raw)
}

// Convert converts a parsed RawVulnerability to a GORM Vulnerability model.
func Convert(raw *RawVulnerability) (*models.Vulnerability, error) {
	modified, err := parseTime(raw.Modified)
	if err != nil {
		return nil, fmt.Errorf("parsing modified time for %s: %w", raw.ID, err)
	}

	vuln := &models.Vulnerability{
		OsvID:            raw.ID,
		SchemaVersion:    raw.SchemaVersion,
		Modified:         modified,
		Published:        parseOptionalTime(raw.Published),
		Withdrawn:        parseOptionalTime(raw.Withdrawn),
		Summary:          raw.Summary,
		Details:          raw.Details,
		DatabaseSpecific: models.JSONMap(raw.DatabaseSpecific),
	}

	// Aliases
	for _, a := range raw.Aliases {
		vuln.Aliases = append(vuln.Aliases, models.VulnerabilityAlias{Alias: a})
	}

	// Related
	for _, r := range raw.Related {
		vuln.Related = append(vuln.Related, models.VulnerabilityRelated{RelatedID: r})
	}

	// Top-level severity
	for _, s := range raw.Severity {
		vuln.Severities = append(vuln.Severities, models.Severity{
			Type:  s.Type,
			Score: s.Score,
		})
	}

	// Affected
	for _, a := range raw.Affected {
		affected := models.Affected{
			Versions:          models.StringSlice(a.Versions),
			EcosystemSpecific: models.JSONMap(a.EcosystemSpecific),
			DatabaseSpecific:  models.JSONMap(a.DatabaseSpecific),
		}

		if a.Package != nil {
			affected.PackageEcosystem = a.Package.Ecosystem
			affected.PackageName = a.Package.Name
			affected.PackagePURL = a.Package.PURL
		}

		// Per-affected severity
		for _, s := range a.Severity {
			affected.Severities = append(affected.Severities, models.Severity{
				Type:  s.Type,
				Score: s.Score,
			})
		}

		// Ranges
		for _, r := range a.Ranges {
			ar := models.AffectedRange{
				Type:             r.Type,
				Repo:             r.Repo,
				DatabaseSpecific: models.JSONMap(r.DatabaseSpecific),
			}
			for _, e := range r.Events {
				ar.Events = append(ar.Events, models.RangeEvent{
					Introduced:   e.Introduced,
					Fixed:        e.Fixed,
					LastAffected: e.LastAffected,
					Limit:        e.Limit,
				})
			}
			affected.Ranges = append(affected.Ranges, ar)
		}

		vuln.Affected = append(vuln.Affected, affected)
	}

	// References
	for _, r := range raw.References {
		vuln.References = append(vuln.References, models.Reference{
			Type: r.Type,
			URL:  r.URL,
		})
	}

	// Credits
	for _, c := range raw.Credits {
		vuln.Credits = append(vuln.Credits, models.Credit{
			Name:    c.Name,
			Type:    c.Type,
			Contact: models.StringSlice(c.Contact),
		})
	}

	// Derive source ecosystem from the first affected package.
	if len(raw.Affected) > 0 && raw.Affected[0].Package != nil {
		vuln.SourceEcosystem = raw.Affected[0].Package.Ecosystem
	}

	return vuln, nil
}

// --------------------------------------------------------------------------
// Time helpers
// --------------------------------------------------------------------------

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp: %s", s)
}

func parseOptionalTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := parseTime(s)
	if err != nil {
		return nil
	}
	return &t
}
