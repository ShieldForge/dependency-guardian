// Package maven implements the proxy handler for Maven repository requests.
//
// Maven clients (mvn, Gradle, sbt, Ivy) request:
//
//	GET /<group-path>/<artifact>/maven-metadata.xml  -> version listing (XML)
//	GET /<group-path>/<artifact>/<ver>/<file>         -> artifact files (jar, pom, etc.)
//
// The handler intercepts maven-metadata.xml requests, evaluates each
// version against OPA policies, and removes disallowed versions from
// the metadata. All other requests (JARs, POMs, checksums) are passed
// through to the upstream unmodified.
package maven

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"dependency-guardian/internal/decisions"
	"dependency-guardian/internal/handler"
	"dependency-guardian/internal/policy"
	"dependency-guardian/internal/registry"
	"dependency-guardian/internal/rewrite"
)

// Handler processes Maven repository requests.
type Handler struct {
	handler.Base
}

// mavenMetadata represents the maven-metadata.xml structure.
type mavenMetadata struct {
	XMLName    xml.Name         `xml:"metadata"`
	GroupID    string           `xml:"groupId"`
	ArtifactID string           `xml:"artifactId"`
	Versioning *mavenVersioning `xml:"versioning"`
}

// mavenVersioning holds the versioning block of maven-metadata.xml.
type mavenVersioning struct {
	Latest      string           `xml:"latest"`
	Release     string           `xml:"release"`
	Versions    mavenVersionList `xml:"versions"`
	LastUpdated string           `xml:"lastUpdated"`
}

// mavenVersionList wraps the list of <version> elements.
type mavenVersionList struct {
	Version []string `xml:"version"`
}

// NewHandler creates a new Maven proxy handler.
func NewHandler(upstreamURL string, engine *policy.Engine, vulnDB registry.VulnerabilityDB, logger *slog.Logger, recorder decisions.Recorder, rewriter *rewrite.Engine) *Handler {
	return &Handler{
		Base: handler.NewBase(upstreamURL, engine, vulnDB, logger, recorder, rewriter, "maven"),
	}
}

// ServeHTTP routes Maven requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if isMetadataRequest(path) {
		h.handleMetadata(w, r)
		return
	}

	if isPomRequest(path) {
		h.handlePom(w, r)
		return
	}

	// Artifact files (jar, war, aar, checksums, signatures) –
	// pass through unmodified.
	h.Upstream.Passthrough(w, r)
}

// handleMetadata fetches maven-metadata.xml from upstream, filters
// versions through OPA, and returns the modified metadata.
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, statusCode, err := h.Upstream.Fetch(r, r.URL.Path)
	if err != nil {
		h.Logger.Error("upstream request failed", "path", r.URL.Path, "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}

	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		w.Write(body)
		return
	}

	filtered, err := h.filterMetadata(ctx, body)
	if err != nil {
		h.Logger.Error("filtering metadata failed", "error", err)
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered)
}

// filterMetadata parses the maven-metadata.xml, evaluates each version
// against OPA policies, and removes disallowed versions.
func (h *Handler) filterMetadata(ctx context.Context, body []byte) ([]byte, error) {
	var meta mavenMetadata
	if err := xml.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("parsing maven metadata: %w", err)
	}

	if meta.Versioning == nil || len(meta.Versioning.Versions.Version) == 0 {
		return body, nil
	}

	// Build the Maven coordinate: groupId:artifactId
	pkgName := mavenCoordinate(meta.GroupID, meta.ArtifactID)

	// Apply rewrite rules: build a set of versions to skip.
	rewrittenAway := make(map[string]bool)
	if h.Rewriter != nil {
		versionSet := make(map[string]bool, len(meta.Versioning.Versions.Version))
		for _, v := range meta.Versioning.Versions.Version {
			versionSet[v] = true
		}
		for _, ver := range meta.Versioning.Versions.Version {
			rr := h.Rewriter.Apply("maven", pkgName, ver)
			if rr.Matched && rr.Version != ver && versionSet[rr.Version] {
				h.Logger.Info("version rewritten",
					"package", pkgName,
					"from", ver,
					"to", rr.Version,
				)
				rewrittenAway[ver] = true
			}
		}
	}

	var allowed []string

	for _, ver := range meta.Versioning.Versions.Version {
		if rewrittenAway[ver] {
			continue
		}

		pv := registry.PackageVersion{
			Name:      pkgName,
			Version:   ver,
			Ecosystem: registry.EcosystemMaven,
		}

		result, err := h.EvaluateVersion(ctx, pv)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy for %s@%s: %w", pkgName, ver, err)
		}

		if result.Allowed {
			allowed = append(allowed, ver)
		}
	}

	// Update the metadata with only allowed versions.
	meta.Versioning.Versions.Version = allowed

	// Update latest/release to point to the last allowed version.
	if len(allowed) > 0 {
		last := allowed[len(allowed)-1]
		if meta.Versioning.Release != "" {
			meta.Versioning.Release = last
		}
		if meta.Versioning.Latest != "" {
			meta.Versioning.Latest = last
		}
	} else {
		meta.Versioning.Release = ""
		meta.Versioning.Latest = ""
	}

	output, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling filtered metadata: %w", err)
	}

	// Prepend XML declaration.
	return append([]byte(xml.Header), output...), nil
}

// isMetadataRequest returns true if the path requests maven-metadata.xml.
func isMetadataRequest(path string) bool {
	return strings.HasSuffix(path, "/maven-metadata.xml")
}

// mavenCoordinate builds the standard Maven coordinate string from
// groupId and artifactId (e.g. "org.apache.commons:commons-lang3").
func mavenCoordinate(groupID, artifactID string) string {
	if groupID == "" {
		return artifactID
	}
	return groupID + ":" + artifactID
}

// ExtractGroupAndArtifact parses a Maven metadata path to extract
// the groupId and artifactId. The path format is:
// /<group-parts...>/<artifact>/maven-metadata.xml
func ExtractGroupAndArtifact(path string) (groupID, artifactID string) {
	// Remove leading / and trailing /maven-metadata.xml
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/maven-metadata.xml")

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", path
	}

	artifactID = parts[len(parts)-1]
	groupID = strings.Join(parts[:len(parts)-1], ".")
	return groupID, artifactID
}

// handlePom fetches a .pom file from upstream, resolves property
// variables in dependency versions, evaluates each dependency against
// policy, and passes the POM through to the client. Denied
// dependencies are logged and recorded but the POM itself is still
// served (actual blocking happens at the metadata level).
func (h *Handler) handlePom(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, statusCode, err := h.Upstream.Fetch(r, r.URL.Path)
	if err != nil {
		h.Logger.Error("upstream POM fetch failed", "path", r.URL.Path, "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}

	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		w.Write(body)
		return
	}

	// Best-effort inspection: parse the POM, resolve versions, evaluate.
	// Failures here are logged but do not block the response.
	h.inspectPOM(ctx, body)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// inspectPOM parses a POM file, resolves property references in
// dependency versions (including parent POM properties), and evaluates
// each dependency against OPA policies. Results are logged and recorded.
func (h *Handler) inspectPOM(ctx context.Context, data []byte) {
	pom, err := parsePOM(data)
	if err != nil {
		h.Logger.Warn("failed to parse POM for inspection", "error", err)
		return
	}

	props := collectProperties(ctx, pom, h.Upstream)
	deps := resolvedDependencies(pom, props)

	for _, dep := range deps {
		pkgName := mavenCoordinate(dep.GroupID, dep.ArtifactID)

		pv := registry.PackageVersion{
			Name:      pkgName,
			Version:   dep.Version,
			Ecosystem: registry.EcosystemMaven,
		}

		if _, err := h.EvaluateVersion(ctx, pv); err != nil {
			h.Logger.Warn("policy evaluation failed for POM dependency",
				"package", pkgName, "version", dep.Version, "error", err)
			continue
		}
	}
}
