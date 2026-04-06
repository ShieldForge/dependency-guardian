// Package testutil provides shared test helpers for handler tests.
package testutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
)

// MockVulnDB is a test double for registry.VulnerabilityDB.
type MockVulnDB struct {
	Vulns map[string][]registry.VulnerabilityRecord
}

// NewMockVulnDB creates a MockVulnDB with an empty vulnerability map.
func NewMockVulnDB() *MockVulnDB {
	return &MockVulnDB{Vulns: make(map[string][]registry.VulnerabilityRecord)}
}

// GetVulnerabilities implements registry.VulnerabilityDB.
func (m *MockVulnDB) GetVulnerabilities(_ context.Context, _ registry.Ecosystem, name, version string) ([]registry.VulnerabilityRecord, error) {
	return m.Vulns[name+"@"+version], nil
}

// AddVuln adds a vulnerability record for a given package name and version.
func (m *MockVulnDB) AddVuln(name, version string, v registry.VulnerabilityRecord) {
	m.Vulns[name+"@"+version] = append(m.Vulns[name+"@"+version], v)
}

// MakePolicyEngine creates a policy engine from a Rego string for testing.
func MakePolicyEngine(t *testing.T, rego string) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rego), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(dir)
	if err != nil {
		t.Fatalf("failed to create policy engine: %v", err)
	}
	return e
}

// AllowAllRego is a Rego policy that allows all packages.
const AllowAllRego = `
package guardian
import rego.v1
`
