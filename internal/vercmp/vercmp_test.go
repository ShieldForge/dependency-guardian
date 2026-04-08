package vercmp

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a         string
		b         string
		ecosystem string
		want      int
	}{
		// Semver (npm / go / default)
		{"1.0.0", "2.0.0", "npm", -1},
		{"2.0.0", "1.0.0", "npm", 1},
		{"1.0.0", "1.0.0", "npm", 0},
		{"1.2.3", "1.2.4", "npm", -1},
		{"1.0.0-alpha", "1.0.0", "npm", -1},
		{"1.0.0", "1.0.0-beta", "npm", 1},
		{"v1.2.3", "v1.3.0", "go", -1},
		{"v0.1.0", "v0.1.0", "go", 0},
		// PyPI (PEP 440)
		{"1.0", "2.0", "pypi", -1},
		{"2.0", "1.0", "pypi", 1},
		{"1.0", "1.0", "pypi", 0},
		{"1.0a1", "1.0", "pypi", -1},
		{"1.0.post1", "1.0", "pypi", 1},
		{"1.0rc1", "1.0", "pypi", -1},
		// Maven
		{"1.0.0", "2.0.0", "maven", -1},
		{"2.0.0", "1.0.0", "maven", 1},
		{"1.0.0", "1.0.0", "maven", 0},
		{"1.0.0-SNAPSHOT", "1.0.0", "maven", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b+"_"+tt.ecosystem, func(t *testing.T) {
			if got := Compare(tt.a, tt.b, tt.ecosystem); got != tt.want {
				t.Errorf("Compare(%q, %q, %q) = %d, want %d", tt.a, tt.b, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestComparerFor(t *testing.T) {
	tests := []struct {
		name      string
		a, b      string
		ecosystem string
		want      int
	}{
		{"semver_equal", "1.0.0", "1.0.0", "npm", 0},
		{"semver_greater", "2.0.0", "1.0.0", "npm", 1},
		{"semver_less", "1.0.0", "2.0.0", "npm", -1},
		{"semver_v_prefix", "v1.2.3", "1.2.3", "Go", 0},
		{"semver_prerelease", "1.0.0-rc1", "1.0.0", "npm", -1},
		{"maven_numeric", "42.7.2", "8.2", "Maven", 1},
		{"maven_reverse", "8.2", "42.7.2", "Maven", -1},
		{"maven_equal", "1.0.0", "1.0.0", "Maven", 0},
		{"maven_snapshot", "1.0.0-SNAPSHOT", "1.0.0", "Maven", -1},
		{"pypi_greater", "2.0.0", "1.0.0", "PyPI", 1},
		{"pypi_less", "1.0.0", "2.0.0", "PyPI", -1},
		{"pypi_equal", "1.0.0", "1.0.0", "PyPI", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp := ComparerFor("ECOSYSTEM", tt.ecosystem)
			got := cmp(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("ComparerFor(ECOSYSTEM, %q)(%q, %q) = %d, want %d", tt.ecosystem, tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestComparerFor_SEMVER(t *testing.T) {
	cmp := ComparerFor("SEMVER", "Maven")
	// SEMVER constraint type always uses semver regardless of ecosystem.
	got := cmp("1.0.0", "2.0.0")
	if got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestFallback(t *testing.T) {
	if Fallback("a", "b") != -1 {
		t.Error("expected -1")
	}
	if Fallback("b", "a") != 1 {
		t.Error("expected 1")
	}
	if Fallback("a", "a") != 0 {
		t.Error("expected 0")
	}
}
