// Package models defines the GORM database models for storing OSV
// vulnerability data. The schema closely follows the OSS Vulnerability
// (OSV) specification from https://github.com/ossf/osv-schema, with
// additional tables for sync state tracking and metrics.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

// --------------------------------------------------------------------------
// JSON helper type – stores arbitrary JSON in TEXT/JSONB columns.
// --------------------------------------------------------------------------

// JSONMap is a map[string]interface{} that serialises to/from JSON in the DB.
type JSONMap map[string]interface{}

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func (j *JSONMap) Scan(src interface{}) error {
	if src == nil {
		*j = nil
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("JSONMap: unsupported scan source")
	}
	return json.Unmarshal(data, j)
}

// StringSlice stores a slice of strings as JSON in the database.
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

func (s *StringSlice) Scan(src interface{}) error {
	if src == nil {
		*s = nil
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("StringSlice: unsupported scan source")
	}
	return json.Unmarshal(data, s)
}

// --------------------------------------------------------------------------
// Core OSV models
// --------------------------------------------------------------------------

// Vulnerability is the top-level OSV record.
type Vulnerability struct {
	// Internal surrogate key.
	ID uint `gorm:"primaryKey;autoIncrement"`

	// OSV fields
	OsvID            string     `gorm:"column:osv_id;uniqueIndex;size:255;not null"`
	SchemaVersion    string     `gorm:"size:20"`
	Modified         time.Time  `gorm:"index;not null"`
	Published        *time.Time `gorm:"index"`
	Withdrawn        *time.Time
	Summary          string  `gorm:"type:text"`
	Details          string  `gorm:"type:text"`
	DatabaseSpecific JSONMap `gorm:"type:text"`

	// Relations
	Aliases    []VulnerabilityAlias   `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`
	Related    []VulnerabilityRelated `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`
	Severities []Severity             `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`
	Affected   []Affected             `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`
	References []Reference            `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`
	Credits    []Credit               `gorm:"foreignKey:VulnerabilityID;constraint:OnDelete:CASCADE"`

	// Sync metadata
	SourceEcosystem string    `gorm:"index;size:100"` // ecosystem from which this was synced
	SyncedAt        time.Time `gorm:"autoUpdateTime"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (Vulnerability) TableName() string { return "vulnerabilities" }

// VulnerabilityAlias stores the aliases array (e.g. CVE-2021-xxxx).
type VulnerabilityAlias struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint   `gorm:"index;not null"`
	Alias           string `gorm:"size:255;not null"`
}

func (VulnerabilityAlias) TableName() string { return "vulnerability_aliases" }

// VulnerabilityRelated stores the related IDs.
type VulnerabilityRelated struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint   `gorm:"index;not null"`
	RelatedID       string `gorm:"size:255;not null"`
}

func (VulnerabilityRelated) TableName() string { return "vulnerability_related" }

// Severity stores top-level or per-affected severity entries.
type Severity struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint   `gorm:"index"`
	AffectedID      *uint  `gorm:"index"`            // non-nil if this is per-affected severity
	Type            string `gorm:"size:20;not null"` // CVSS_V2, CVSS_V3, CVSS_V4
	Score           string `gorm:"size:255;not null"`
}

func (Severity) TableName() string { return "severities" }

// --------------------------------------------------------------------------
// Affected package models
// --------------------------------------------------------------------------

// Affected represents one entry in the "affected" array of an OSV record.
type Affected struct {
	ID              uint `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint `gorm:"index;not null"`

	// Package identification
	PackageEcosystem string `gorm:"index;size:100"`
	PackageName      string `gorm:"index;size:500"`
	PackagePURL      string `gorm:"size:1000"`

	// Explicit version list (stored as JSON for simplicity)
	Versions StringSlice `gorm:"type:text"`

	EcosystemSpecific JSONMap `gorm:"type:text"`
	DatabaseSpecific  JSONMap `gorm:"type:text"`

	// Relations
	Ranges     []AffectedRange `gorm:"foreignKey:AffectedID;constraint:OnDelete:CASCADE"`
	Severities []Severity      `gorm:"foreignKey:AffectedID;constraint:OnDelete:CASCADE"`
}

func (Affected) TableName() string { return "affected" }

// AffectedRange represents a version range within an Affected entry.
type AffectedRange struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	AffectedID uint   `gorm:"index;not null"`
	Type       string `gorm:"size:20;not null"` // SEMVER, ECOSYSTEM, GIT
	Repo       string `gorm:"size:1000"`

	DatabaseSpecific JSONMap `gorm:"type:text"`

	Events []RangeEvent `gorm:"foreignKey:AffectedRangeID;constraint:OnDelete:CASCADE"`
}

func (AffectedRange) TableName() string { return "affected_ranges" }

// RangeEvent represents a single event in a version range (introduced,
// fixed, last_affected, limit).
type RangeEvent struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	AffectedRangeID uint   `gorm:"index;not null"`
	Introduced      string `gorm:"size:255"`
	Fixed           string `gorm:"size:255"`
	LastAffected    string `gorm:"size:255"`
	Limit           string `gorm:"size:255"`
}

func (RangeEvent) TableName() string { return "range_events" }

// --------------------------------------------------------------------------
// Reference & credit models
// --------------------------------------------------------------------------

// Reference stores entries from the "references" array.
type Reference struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint   `gorm:"index;not null"`
	Type            string `gorm:"size:20;not null"`
	URL             string `gorm:"type:text;not null"`
}

func (Reference) TableName() string { return "references" }

// Credit stores entries from the "credits" array.
type Credit struct {
	ID              uint        `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint        `gorm:"index;not null"`
	Name            string      `gorm:"size:500;not null"`
	Type            string      `gorm:"size:50"`
	Contact         StringSlice `gorm:"type:text"`
}

func (Credit) TableName() string { return "credits" }

// --------------------------------------------------------------------------
// Ecosystem sync tracking
// --------------------------------------------------------------------------

// EcosystemSyncState tracks the sync status for each ecosystem.
type EcosystemSyncState struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	Ecosystem string `gorm:"uniqueIndex;size:100;not null"`

	// Sync state
	Status          string     `gorm:"size:20;not null;default:'pending'"` // pending, syncing, synced, error
	LastFullSync    *time.Time // last time a full seed/reseed was completed
	LastDeltaSync   *time.Time // last time a delta update was applied
	LastDeltaCursor string     `gorm:"size:255"` // ISO timestamp of last processed delta
	LastError       string     `gorm:"type:text"`
	LastErrorAt     *time.Time

	// Metrics (updated periodically)
	TotalVulnerabilities int64
	TotalAffectedEntries int64

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (EcosystemSyncState) TableName() string { return "ecosystem_sync_states" }

// SyncLog records individual sync operations for audit trail.
type SyncLog struct {
	ID               uint      `gorm:"primaryKey;autoIncrement"`
	Ecosystem        string    `gorm:"index;size:100;not null"`
	SyncType         string    `gorm:"size:20;not null"` // full, delta
	Status           string    `gorm:"size:20;not null"` // started, completed, failed
	StartedAt        time.Time `gorm:"not null"`
	CompletedAt      *time.Time
	RecordsProcessed int64
	RecordsInserted  int64
	RecordsUpdated   int64
	RecordsDeleted   int64
	ErrorMessage     string `gorm:"type:text"`
}

func (SyncLog) TableName() string { return "sync_logs" }

// --------------------------------------------------------------------------
// Materialised lookup table for fast queries
// --------------------------------------------------------------------------

// AffectedPackageIndex is a denormalised index table that maps
// (ecosystem, package_name, version) to vulnerability IDs for fast
// lookup during proxy request processing.
type AffectedPackageIndex struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	VulnerabilityID uint   `gorm:"index;not null"`
	OsvID           string `gorm:"index;size:255;not null"`
	Ecosystem       string `gorm:"index:idx_pkg_lookup;size:100;not null"`
	PackageName     string `gorm:"index:idx_pkg_lookup;size:500;not null"`
	// VersionConstraint stores a JSON representation of ranges or a
	// specific version for exact-match lookups.
	VersionConstraint string `gorm:"type:text"`
	// ExactVersion is populated when the affected entry lists explicit versions.
	ExactVersion string `gorm:"index:idx_pkg_version;size:255"`
	// Severity caches the highest severity for quick filtering.
	MaxSeverity string `gorm:"size:20"`
	IsMalicious bool   `gorm:"index"`
}

func (AffectedPackageIndex) TableName() string { return "affected_package_index" }

// --------------------------------------------------------------------------
// AllModels returns all model types for auto-migration.
// --------------------------------------------------------------------------

func AllModels() []interface{} {
	return []interface{}{
		&Vulnerability{},
		&VulnerabilityAlias{},
		&VulnerabilityRelated{},
		&Severity{},
		&Affected{},
		&AffectedRange{},
		&RangeEvent{},
		&Reference{},
		&Credit{},
		&EcosystemSyncState{},
		&SyncLog{},
		&AffectedPackageIndex{},
	}
}
