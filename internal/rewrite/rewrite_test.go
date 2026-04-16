package rewrite

import (
	"log/slog"
	"testing"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/vercmp"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input  string
		wantOk bool
		major  int
		minor  int
		patch  int
		prefix string
		preRel string
		segs   int
	}{
		{"1.2.3", true, 1, 2, 3, "", "", 3},
		{"v1.2.3", true, 1, 2, 3, "v", "", 3},
		{"0.0.1", true, 0, 0, 1, "", "", 3},
		{"1.2.3-beta.1", true, 1, 2, 3, "", "-beta.1", 3},
		{"v2.0.0-rc1", true, 2, 0, 0, "v", "-rc1", 3},
		{"1.2", true, 1, 2, 0, "", "", 3},
		{"1", true, 1, 0, 0, "", "", 3},
		{"10.20.30", true, 10, 20, 30, "", "", 3},
		{"", false, 0, 0, 0, "", "", 0},
		{"abc", false, 0, 0, 0, "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pv, ok := vercmp.ParseVersion(tt.input, "npm")
			if ok != tt.wantOk {
				t.Fatalf("ParseVersion(%q) ok = %v, want %v", tt.input, ok, tt.wantOk)
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

func TestSnapToMinor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3", "1.2.0"},
		{"v1.2.3", "v1.2.0"},
		{"1.0.1", "1.0.0"},
		{"2.3.4-beta.1", "2.3.0"},
		{"1.2", "1.2.0"},
		{"0.0.5", "0.0.0"},
		{"abc", "abc"}, // unparseable: returned as-is
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := snapToMinor(tt.input, "npm"); got != tt.want {
				t.Errorf("snapToMinor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSnapToMajor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3", "1.0.0"},
		{"v2.5.3", "v2.0.0"},
		{"3.4.5-rc1", "3.0.0"},
		{"0.1.2", "0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := snapToMajor(tt.input, "npm"); got != tt.want {
				t.Errorf("snapToMajor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestApplyMin(t *testing.T) {
	tests := []struct {
		version   string
		target    string
		ecosystem string
		want      string
	}{
		{"1.0.0", "1.2.0", "npm", "1.2.0"},   // below min -> upgrade
		{"1.5.0", "1.2.0", "npm", "1.5.0"},   // above min -> keep
		{"1.2.0", "1.2.0", "npm", "1.2.0"},   // equal -> keep
		{"1.0", "1.2", "pypi", "1.2"},        // PyPI: below min -> upgrade
		{"1.5", "1.2", "pypi", "1.5"},        // PyPI: above min -> keep
		{"1.0.0", "1.2.0", "maven", "1.2.0"}, // Maven: below min -> upgrade
	}

	for _, tt := range tests {
		t.Run(tt.version+"_min_"+tt.target+"_"+tt.ecosystem, func(t *testing.T) {
			if got := applyMin(tt.version, tt.target, tt.ecosystem); got != tt.want {
				t.Errorf("applyMin(%q, %q, %q) = %q, want %q", tt.version, tt.target, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestApplyMax(t *testing.T) {
	tests := []struct {
		version   string
		target    string
		ecosystem string
		want      string
	}{
		{"2.0.0", "1.5.0", "npm", "1.5.0"},   // above max -> downgrade
		{"1.0.0", "1.5.0", "npm", "1.0.0"},   // below max -> keep
		{"1.5.0", "1.5.0", "npm", "1.5.0"},   // equal -> keep
		{"2.0", "1.5", "pypi", "1.5"},        // PyPI: above max -> downgrade
		{"2.0.0", "1.5.0", "maven", "1.5.0"}, // Maven: above max -> downgrade
	}

	for _, tt := range tests {
		t.Run(tt.version+"_max_"+tt.target+"_"+tt.ecosystem, func(t *testing.T) {
			if got := applyMax(tt.version, tt.target, tt.ecosystem); got != tt.want {
				t.Errorf("applyMax(%q, %q, %q) = %q, want %q", tt.version, tt.target, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestReplaceMajor(t *testing.T) {
	tests := []struct {
		version string
		target  string
		want    string
	}{
		{"1.2.3", "2", "2.2.3"},
		{"v1.2.3", "3", "v3.2.3"},
		{"0.5.1", "1", "1.5.1"},
	}

	for _, tt := range tests {
		t.Run(tt.version+"->"+tt.target, func(t *testing.T) {
			if got := replaceMajor(tt.version, tt.target, "npm"); got != tt.want {
				t.Errorf("replaceMajor(%q, %q) = %q, want %q", tt.version, tt.target, got, tt.want)
			}
		})
	}
}

func TestReplaceMinor(t *testing.T) {
	tests := []struct {
		version string
		target  string
		want    string
	}{
		{"1.2.3", "5", "1.5.3"},
		{"v1.0.3", "3", "v1.3.3"},
	}

	for _, tt := range tests {
		t.Run(tt.version+"->"+tt.target, func(t *testing.T) {
			if got := replaceMinor(tt.version, tt.target, "npm"); got != tt.want {
				t.Errorf("replaceMinor(%q, %q) = %q, want %q", tt.version, tt.target, got, tt.want)
			}
		})
	}
}

func TestReplacePatch(t *testing.T) {
	tests := []struct {
		version string
		target  string
		want    string
	}{
		{"1.2.3", "0", "1.2.0"},
		{"v1.2.5", "1", "v1.2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.version+"->"+tt.target, func(t *testing.T) {
			if got := replacePatch(tt.version, tt.target, "npm"); got != tt.want {
				t.Errorf("replacePatch(%q, %q) = %q, want %q", tt.version, tt.target, got, tt.want)
			}
		})
	}
}

func TestEngineApply(t *testing.T) {
	rules := []config.RewriteRule{
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "lodash",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "pin",
					Target:   "4.17.21",
				},
			},
		},
		{
			Match: config.RewriteMatch{
				Ecosystem: "go",
				Name:      "*",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "nearest-minor",
				},
			},
		},
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "moment",
			},
			Rewrite: config.RewriteAction{
				Name: "dayjs",
			},
		},
	}

	engine := New(rules, slog.Default())

	t.Run("pin_lodash", func(t *testing.T) {
		r := engine.Apply("npm", "lodash", "4.17.20")
		if !r.Matched {
			t.Fatal("expected match")
		}
		if r.Version != "4.17.21" {
			t.Errorf("version = %q, want 4.17.21", r.Version)
		}
		if r.Name != "lodash" {
			t.Errorf("name = %q, want lodash", r.Name)
		}
	})

	t.Run("nearest_minor_go", func(t *testing.T) {
		r := engine.Apply("go", "github.com/foo/bar", "v1.2.3")
		if !r.Matched {
			t.Fatal("expected match")
		}
		if r.Version != "v1.2.0" {
			t.Errorf("version = %q, want v1.2.0", r.Version)
		}
	})

	t.Run("name_rewrite", func(t *testing.T) {
		r := engine.Apply("npm", "moment", "2.29.4")
		if !r.Matched {
			t.Fatal("expected match")
		}
		if r.Name != "dayjs" {
			t.Errorf("name = %q, want dayjs", r.Name)
		}
		if r.Version != "2.29.4" {
			t.Errorf("version should be unchanged, got %q", r.Version)
		}
	})

	t.Run("no_match", func(t *testing.T) {
		r := engine.Apply("pypi", "requests", "2.28.0")
		if r.Matched {
			t.Error("expected no match")
		}
		if r.Version != "2.28.0" {
			t.Errorf("version should be unchanged, got %q", r.Version)
		}
	})

	t.Run("first_match_wins", func(t *testing.T) {
		// "lodash" matches the first rule (pin), not the wildcard go rule
		r := engine.Apply("npm", "lodash", "4.0.0")
		if r.Version != "4.17.21" {
			t.Errorf("version = %q, want 4.17.21 (first match wins)", r.Version)
		}
	})
}

func TestEngineApply_Mode(t *testing.T) {
	rules := []config.RewriteRule{
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "express",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "min",
					Target:   "4.18.0",
				},
				Mode: "redirect",
			},
		},
	}

	engine := New(rules, slog.Default())

	r := engine.Apply("npm", "express", "4.17.0")
	if r.Mode != "redirect" {
		t.Errorf("mode = %q, want redirect", r.Mode)
	}
	if r.Version != "4.18.0" {
		t.Errorf("version = %q, want 4.18.0", r.Version)
	}
}

func TestEngineApply_DefaultMode(t *testing.T) {
	rules := []config.RewriteRule{
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "express",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "pin",
					Target:   "4.18.0",
				},
			},
		},
	}

	engine := New(rules, slog.Default())

	r := engine.Apply("npm", "express", "4.17.0")
	if r.Mode != "transparent" {
		t.Errorf("mode = %q, want transparent", r.Mode)
	}
}

func TestEngineApplyWithAvailable(t *testing.T) {
	rules := []config.RewriteRule{
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "*",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "nearest-minor",
				},
			},
		},
	}

	engine := New(rules, slog.Default())

	t.Run("exact_match_available", func(t *testing.T) {
		r := engine.ApplyWithAvailable("npm", "lodash", "4.17.3", []string{"4.17.0", "4.17.1", "4.17.2", "4.17.3"})
		if r.Version != "4.17.0" {
			t.Errorf("version = %q, want 4.17.0", r.Version)
		}
	})

	t.Run("closest_match", func(t *testing.T) {
		// nearest-minor of 4.17.3 = 4.17.0, which doesn't exist -> closest is 4.17.1
		r := engine.ApplyWithAvailable("npm", "lodash", "4.17.3", []string{"4.17.1", "4.17.2"})
		if r.Version != "4.17.1" {
			t.Errorf("version = %q, want 4.17.1 (closest to 4.17.0)", r.Version)
		}
	})

	t.Run("no_match_available", func(t *testing.T) {
		r := engine.ApplyWithAvailable("npm", "lodash", "4.17.3", []string{"5.0.0", "6.0.0"})
		// Target 4.17.0 not available, closest would be 5.0.0
		if r.Version != "5.0.0" {
			t.Errorf("version = %q, want 5.0.0 (closest available)", r.Version)
		}
	})

	t.Run("empty_available", func(t *testing.T) {
		r := engine.ApplyWithAvailable("npm", "lodash", "4.17.3", nil)
		// No available versions -> revert to original
		if r.Version != "4.17.3" {
			t.Errorf("version = %q, want 4.17.3 (original, nothing available)", r.Version)
		}
		if r.Matched {
			t.Error("expected Matched=false when reverting")
		}
	})
}

func TestEngineApply_VersionGlob(t *testing.T) {
	rules := []config.RewriteRule{
		{
			Match: config.RewriteMatch{
				Ecosystem: "npm",
				Name:      "express",
				Version:   "3.*",
			},
			Rewrite: config.RewriteAction{
				Version: &config.VersionRewrite{
					Strategy: "pin",
					Target:   "4.18.0",
				},
			},
		},
	}

	engine := New(rules, slog.Default())

	t.Run("matching_version_glob", func(t *testing.T) {
		r := engine.Apply("npm", "express", "3.21.0")
		if !r.Matched {
			t.Fatal("expected match for version 3.21.0")
		}
		if r.Version != "4.18.0" {
			t.Errorf("version = %q, want 4.18.0", r.Version)
		}
	})

	t.Run("non_matching_version_glob", func(t *testing.T) {
		r := engine.Apply("npm", "express", "4.17.0")
		if r.Matched {
			t.Error("expected no match for version 4.17.0")
		}
	})
}

func TestFindClosestVersion(t *testing.T) {
	tests := []struct {
		target    string
		available []string
		ecosystem string
		want      string
	}{
		{"1.2.0", []string{"1.2.0", "1.2.1", "1.3.0"}, "npm", "1.2.0"},
		{"1.2.0", []string{"1.2.1", "1.2.2", "1.3.0"}, "npm", "1.2.1"},
		{"1.2.0", []string{"1.3.0", "1.4.0"}, "npm", "1.3.0"},
		{"2.0.0", []string{"1.9.0", "3.0.0"}, "npm", "1.9.0"},
		{"1.0.0", []string{}, "npm", ""},
		{"1.2.0", []string{"1.2.1", "1.2.2"}, "pypi", "1.2.1"},
		{"1.2.0", []string{"1.2.1", "1.2.2"}, "maven", "1.2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.target+"_"+tt.ecosystem, func(t *testing.T) {
			got := findClosestVersion(tt.target, tt.available, tt.ecosystem)
			if got != tt.want {
				t.Errorf("findClosestVersion(%q, %v, %q) = %q, want %q", tt.target, tt.available, tt.ecosystem, got, tt.want)
			}
		})
	}
}
