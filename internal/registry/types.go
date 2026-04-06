// Package registry defines the common types and interfaces used across
// all registry handlers (npm, PyPI, Go modules).
package registry

import "time"

// Ecosystem represents a supported package ecosystem.
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "pypi"
	EcosystemGo    Ecosystem = "go"
	EcosystemMaven Ecosystem = "maven"
)

// PackageVersion is a normalised representation of a single version
// of a package, regardless of the source registry.
type PackageVersion struct {
	// Name is the fully-qualified package name.
	Name string `json:"name"`
	// Version is the semver (or PEP-440 etc.) string.
	Version string `json:"version"`
	// Ecosystem indicates which registry the package comes from.
	Ecosystem Ecosystem `json:"ecosystem"`
	// PublishedAt is when this version was published.
	PublishedAt time.Time `json:"published_at"`
	// Deprecated indicates whether the upstream has marked this version deprecated.
	Deprecated bool `json:"deprecated"`
	// Yanked indicates whether the upstream has yanked/unpublished this version.
	Yanked bool `json:"yanked"`
}

// PolicyInput is the structure passed to OPA for policy evaluation.
// It contains the version under evaluation and any enrichment data
// such as vulnerability information.
type PolicyInput struct {
	Package         PackageVersion         `json:"package"`
	Vulnerabilities []VulnerabilityRecord  `json:"vulnerabilities"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyResult is the outcome of evaluating a single version against policy.
type PolicyResult struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`
}

// VulnerabilityRecord is a single vulnerability associated with a
// package version. The concrete implementation will be supplied later
// via the VulnerabilityDB interface.
type VulnerabilityRecord struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	FixedIn     string `json:"fixed_in,omitempty"`
	IsMalicious bool   `json:"is_malicious"`
}
