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

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input     string
		ecosystem string
		wantOk    bool
		major     int
		minor     int
		patch     int
		prefix    string
		preRel    string
		segs      int
	}{
		// Semver (npm/go)
		{"1.2.3", "npm", true, 1, 2, 3, "", "", 3},
		{"v1.2.3", "npm", true, 1, 2, 3, "v", "", 3},
		{"0.0.1", "npm", true, 0, 0, 1, "", "", 3},
		{"1.2.3-beta.1", "npm", true, 1, 2, 3, "", "-beta.1", 3},
		{"v2.0.0-rc1", "npm", true, 2, 0, 0, "v", "-rc1", 3},
		{"10.20.30", "npm", true, 10, 20, 30, "", "", 3},
		{"", "npm", false, 0, 0, 0, "", "", 0},
		{"abc", "npm", false, 0, 0, 0, "", "", 0},
		// PyPI
		{"1.2.3", "pypi", true, 1, 2, 3, "", "", 3},
		{"1.0a1", "pypi", true, 1, 0, 0, "", "a1", 2},
		{"1.0.post1", "pypi", true, 1, 0, 0, "", ".post1", 2},
		{"not-a-version", "pypi", false, 0, 0, 0, "", "", 0},
		// Maven
		{"1.2.3", "maven", true, 1, 2, 3, "", "", 3},
		{"1.0.0-SNAPSHOT", "maven", true, 1, 0, 0, "", "-SNAPSHOT", 3},
		// Go
		{"v1.2.3", "go", true, 1, 2, 3, "v", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.input+"_"+tt.ecosystem, func(t *testing.T) {
			pv, ok := ParseVersion(tt.input, tt.ecosystem)
			if ok != tt.wantOk {
				t.Fatalf("ParseVersion(%q, %q) ok = %v, want %v", tt.input, tt.ecosystem, ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if pv.Major != tt.major || pv.Minor != tt.minor || pv.Patch != tt.patch {
				t.Errorf("got %d.%d.%d, want %d.%d.%d", pv.Major, pv.Minor, pv.Patch, tt.major, tt.minor, tt.patch)
			}
			if pv.Prefix != tt.prefix {
				t.Errorf("prefix = %q, want %q", pv.Prefix, tt.prefix)
			}
			if pv.PreRelease != tt.preRel {
				t.Errorf("preRelease = %q, want %q", pv.PreRelease, tt.preRel)
			}
			if pv.Segments != tt.segs {
				t.Errorf("segments = %d, want %d", pv.Segments, tt.segs)
			}
		})
	}
}

func TestParsedVersionFormat(t *testing.T) {
	tests := []struct {
		pv   ParsedVersion
		want string
	}{
		{ParsedVersion{Major: 1, Minor: 2, Patch: 3, Segments: 3}, "1.2.3"},
		{ParsedVersion{Prefix: "v", Major: 1, Minor: 2, Patch: 3, Segments: 3}, "v1.2.3"},
		{ParsedVersion{Major: 1, Minor: 2, Patch: 3, PreRelease: "-beta.1", Segments: 3}, "1.2.3-beta.1"},
		{ParsedVersion{Major: 1, Minor: 2, Segments: 2}, "1.2"},
		{ParsedVersion{Major: 1, Segments: 1}, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.pv.Format(); got != tt.want {
				t.Errorf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}
