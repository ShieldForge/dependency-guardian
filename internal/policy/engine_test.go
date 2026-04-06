package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dependency-guardian/internal/registry"
)

// writeTestPolicy writes a rego file into a temp directory and returns the dir.
func writeTestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.rego")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const allowAllPolicy = `
package guardian
import rego.v1
`

const denyMaliciousPolicy = `
package guardian
import rego.v1

deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.is_malicious == true
	msg := sprintf("malicious: %s", [vuln.id])
}
`

const denyDeprecatedPolicy = `
package guardian
import rego.v1

deny contains msg if {
	input.package.deprecated == true
	msg := "package is deprecated"
}
`

const denyYankedPolicy = `
package guardian
import rego.v1

deny contains msg if {
	input.package.yanked == true
	msg := "package is yanked"
}
`

const denyCriticalPolicy = `
package guardian
import rego.v1

deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.severity == "critical"
	msg := sprintf("critical vuln: %s", [vuln.id])
}

deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.severity == "high"
	msg := sprintf("high vuln: %s", [vuln.id])
}
`

func TestNewEngine(t *testing.T) {
	t.Run("valid_policy", func(t *testing.T) {
		dir := writeTestPolicy(t, allowAllPolicy)
		engine, err := NewEngine(dir)
		if err != nil {
			t.Fatalf("NewEngine failed: %v", err)
		}
		if engine == nil {
			t.Fatal("engine is nil")
		}
	})

	t.Run("empty_dir", func(t *testing.T) {
		dir := t.TempDir()
		_, err := NewEngine(dir)
		if err == nil {
			t.Error("expected error for empty directory")
		}
	})

	t.Run("invalid_rego", func(t *testing.T) {
		dir := writeTestPolicy(t, "invalid { rego syntax ~~~}")
		_, err := NewEngine(dir)
		if err == nil {
			t.Error("expected error for invalid rego")
		}
	})

	t.Run("nonexistent_dir", func(t *testing.T) {
		_, err := NewEngine("/nonexistent/policies")
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})
}

func TestEvaluate_AllowAll(t *testing.T) {
	dir := writeTestPolicy(t, allowAllPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "lodash",
			Version:   "4.17.21",
			Ecosystem: registry.EcosystemNPM,
		},
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %v", result.Reasons)
	}
	if len(result.Reasons) != 0 {
		t.Errorf("expected no reasons, got %v", result.Reasons)
	}
}

func TestEvaluate_DenyMalicious(t *testing.T) {
	dir := writeTestPolicy(t, denyMaliciousPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	t.Run("malicious_denied", func(t *testing.T) {
		input := registry.PolicyInput{
			Package: registry.PackageVersion{
				Name:      "evil-pkg",
				Version:   "1.0.0",
				Ecosystem: registry.EcosystemNPM,
			},
			Vulnerabilities: []registry.VulnerabilityRecord{
				{ID: "MAL-2024-001", Severity: "critical", IsMalicious: true},
			},
		}

		result, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for malicious package")
		}
		if len(result.Reasons) == 0 {
			t.Error("expected at least one reason")
		}
	})

	t.Run("non_malicious_allowed", func(t *testing.T) {
		input := registry.PolicyInput{
			Package: registry.PackageVersion{
				Name:      "safe-pkg",
				Version:   "1.0.0",
				Ecosystem: registry.EcosystemNPM,
			},
			Vulnerabilities: []registry.VulnerabilityRecord{
				{ID: "CVE-2024-001", Severity: "low", IsMalicious: false},
			},
		}

		result, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected allowed, got denied: %v", result.Reasons)
		}
	})
}

func TestEvaluate_DenyCriticalVulnerabilities(t *testing.T) {
	dir := writeTestPolicy(t, denyCriticalPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	tests := []struct {
		name     string
		severity string
		allowed  bool
	}{
		{"critical_denied", "critical", false},
		{"high_denied", "high", false},
		{"medium_allowed", "medium", true},
		{"low_allowed", "low", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := registry.PolicyInput{
				Package: registry.PackageVersion{
					Name:      "some-pkg",
					Version:   "1.0.0",
					Ecosystem: registry.EcosystemNPM,
				},
				Vulnerabilities: []registry.VulnerabilityRecord{
					{ID: "CVE-2024-001", Severity: tt.severity},
				},
			}

			result, err := engine.Evaluate(context.Background(), input)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if result.Allowed != tt.allowed {
				t.Errorf("expected allowed=%v, got allowed=%v reasons=%v", tt.allowed, result.Allowed, result.Reasons)
			}
		})
	}
}

func TestEvaluate_DenyDeprecated(t *testing.T) {
	dir := writeTestPolicy(t, denyDeprecatedPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	t.Run("deprecated_denied", func(t *testing.T) {
		input := registry.PolicyInput{
			Package: registry.PackageVersion{
				Name:       "old-pkg",
				Version:    "1.0.0",
				Ecosystem:  registry.EcosystemNPM,
				Deprecated: true,
			},
		}

		result, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if result.Allowed {
			t.Error("expected denied for deprecated")
		}
	})

	t.Run("not_deprecated_allowed", func(t *testing.T) {
		input := registry.PolicyInput{
			Package: registry.PackageVersion{
				Name:      "good-pkg",
				Version:   "2.0.0",
				Ecosystem: registry.EcosystemNPM,
			},
		}

		result, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if !result.Allowed {
			t.Error("expected allowed")
		}
	})
}

func TestEvaluate_DenyYanked(t *testing.T) {
	dir := writeTestPolicy(t, denyYankedPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "yanked-pkg",
			Version:   "0.1.0",
			Ecosystem: registry.EcosystemPyPI,
			Yanked:    true,
		},
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for yanked package")
	}
}

func TestEvaluate_NoVulnerabilities(t *testing.T) {
	dir := writeTestPolicy(t, denyMaliciousPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "clean-pkg",
			Version:   "1.0.0",
			Ecosystem: registry.EcosystemGo,
		},
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed with no vulns, got denied: %v", result.Reasons)
	}
}

func TestEvaluate_MultipleVulnerabilities(t *testing.T) {
	dir := writeTestPolicy(t, denyCriticalPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "multi-vuln-pkg",
			Version:   "1.0.0",
			Ecosystem: registry.EcosystemNPM,
		},
		Vulnerabilities: []registry.VulnerabilityRecord{
			{ID: "CVE-2024-001", Severity: "critical"},
			{ID: "CVE-2024-002", Severity: "high"},
			{ID: "CVE-2024-003", Severity: "low"},
		},
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("expected denied for multiple vulnerabilities")
	}
	// Should have at least 2 reasons (critical + high)
	if len(result.Reasons) < 2 {
		t.Errorf("expected at least 2 reasons, got %d: %v", len(result.Reasons), result.Reasons)
	}
}

func TestReload(t *testing.T) {
	dir := writeTestPolicy(t, allowAllPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Initially allow everything
	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:       "test-pkg",
			Version:    "1.0.0",
			Ecosystem:  registry.EcosystemNPM,
			Deprecated: true,
		},
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed before reload")
	}

	// Write a new policy that denies deprecated
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(denyDeprecatedPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	// Reload
	if err := engine.Reload(dir); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Now should be denied
	result, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Error("expected denied after reload")
	}
}

func TestReload_InvalidPolicy(t *testing.T) {
	dir := writeTestPolicy(t, allowAllPolicy)
	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Reload with bad rego should fail but engine should keep old policy
	badDir := writeTestPolicy(t, "package guardian { bad syntax }")
	err = engine.Reload(badDir)
	if err == nil {
		t.Error("expected error for invalid rego on reload")
	}

	// Engine should still work with old policy
	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "test-pkg",
			Version:   "1.0.0",
			Ecosystem: registry.EcosystemNPM,
		},
	}
	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate after bad reload failed: %v", err)
	}
	if !result.Allowed {
		t.Error("engine should still use old policy after failed reload")
	}
}

func TestToMap(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:        "test-pkg",
			Version:     "1.0.0",
			Ecosystem:   registry.EcosystemNPM,
			PublishedAt: now,
			Deprecated:  true,
			Yanked:      false,
		},
		Vulnerabilities: []registry.VulnerabilityRecord{
			{ID: "CVE-2024-001", Severity: "high", Summary: "test", FixedIn: "1.0.1", IsMalicious: false},
		},
		Metadata: map[string]interface{}{"custom": "value"},
	}

	m := toMap(input)

	pkg, ok := m["package"].(map[string]interface{})
	if !ok {
		t.Fatal("package key not found or wrong type")
	}
	if pkg["name"] != "test-pkg" {
		t.Errorf("expected name test-pkg, got %v", pkg["name"])
	}
	if pkg["version"] != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %v", pkg["version"])
	}
	if pkg["ecosystem"] != "npm" {
		t.Errorf("expected ecosystem npm, got %v", pkg["ecosystem"])
	}
	if pkg["deprecated"] != true {
		t.Errorf("expected deprecated true, got %v", pkg["deprecated"])
	}

	vulns, ok := m["vulnerabilities"].([]interface{})
	if !ok || len(vulns) != 1 {
		t.Fatal("vulnerabilities key not found or wrong length")
	}

	meta, ok := m["metadata"]
	if !ok || meta == nil {
		t.Error("metadata should be present")
	}
}

func TestToMap_NoMetadata(t *testing.T) {
	input := registry.PolicyInput{
		Package: registry.PackageVersion{
			Name:      "test",
			Version:   "1.0.0",
			Ecosystem: registry.EcosystemPyPI,
		},
	}

	m := toMap(input)
	if _, ok := m["metadata"]; ok {
		t.Error("metadata should not be present when nil")
	}
}
