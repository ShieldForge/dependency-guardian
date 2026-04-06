package maven

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"dependency-guardian/internal/handler/upstream"
)

// maxParentDepth limits the number of parent POM levels to resolve,
// preventing infinite loops if there is a cycle in parent references.
const maxParentDepth = 10

// propertyRefRE matches Maven property references like ${some.version}.
var propertyRefRE = regexp.MustCompile(`\$\{([^}]+)\}`)

// pomProject represents a Maven POM file.
type pomProject struct {
	XMLName                *xml.Name                  `xml:"project,omitempty"`
	ModelVersion           *string                    `xml:"modelVersion,omitempty"`
	Parent                 *pomParent                 `xml:"parent,omitempty"`
	GroupID                *string                    `xml:"groupId,omitempty"`
	ArtifactID             *string                    `xml:"artifactId,omitempty"`
	Version                *string                    `xml:"version,omitempty"`
	Packaging              *string                    `xml:"packaging,omitempty"`
	Name                   *string                    `xml:"name,omitempty"`
	Description            *string                    `xml:"description,omitempty"`
	URL                    *string                    `xml:"url,omitempty"`
	InceptionYear          *string                    `xml:"inceptionYear,omitempty"`
	Organization           *pomOrganization           `xml:"organization,omitempty"`
	Licenses               *pomLicenses               `xml:"licenses,omitempty"`
	Developers             *pomDevelopers             `xml:"developers,omitempty"`
	Contributors           *pomContributors           `xml:"contributors,omitempty"`
	MailingLists           *pomMailingLists           `xml:"mailingLists,omitempty"`
	Prerequisites          *pomPrerequisites          `xml:"prerequisites,omitempty"`
	Modules                *[]string                  `xml:"modules>module,omitempty"`
	SCM                    *pomScm                    `xml:"scm,omitempty"`
	IssueManagement        *pomIssueManagement        `xml:"issueManagement,omitempty"`
	CIManagement           *pomCIManagement           `xml:"ciManagement,omitempty"`
	DistributionManagement *pomDistributionManagement `xml:"distributionManagement,omitempty"`
	DependencyManagement   *pomDepMgmt                `xml:"dependencyManagement,omitempty"`
	Dependencies           *pomDeps                   `xml:"dependencies,omitempty"`
	Repositories           *pomRepositories           `xml:"repositories,omitempty"`
	PluginRepositories     *pomPluginRepositories     `xml:"pluginRepositories,omitempty"`
	Build                  *pomBuild                  `xml:"build,omitempty"`
	Reporting              *pomReporting              `xml:"reporting,omitempty"`
	Profiles               *pomProfiles               `xml:"profiles>profile,omitempty"`
	Properties             *pomProperties             `xml:"properties,omitempty"`
}

// pomParent is the <parent> element, pointing to a parent POM.
type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// pomDeps wraps a list of dependency elements.
type pomDeps struct {
	Dependency []pomDependency `xml:"dependency"`
}

// pomDepMgmt wraps the <dependencyManagement> section.
type pomDepMgmt struct {
	Dependencies *pomDeps `xml:"dependencies"`
}

// pomDependency represents a single <dependency> in a POM.
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

type pomOrganization struct {
	Name *string `xml:"name,omitempty"`
	URL  *string `xml:"url,omitempty"`
}

type pomLicenses struct {
	License []pomLicense `xml:"license"`
}

type pomLicense struct {
	Name         *string `xml:"name,omitempty"`
	URL          *string `xml:"url,omitempty"`
	Distribution *string `xml:"distribution,omitempty"`
	Comments     *string `xml:"comments,omitempty"`
}

type pomDevelopers struct {
	Developer []pomDeveloper `xml:"developer"`
}

type pomDeveloper struct {
	ID              *string        `xml:"id,omitempty"`
	Name            *string        `xml:"name,omitempty"`
	Email           *string        `xml:"email,omitempty"`
	URL             *string        `xml:"url,omitempty"`
	Organization    *string        `xml:"organization,omitempty"`
	OrganizationURL *string        `xml:"organizationUrl,omitempty"`
	Roles           *[]string      `xml:"roles>role,omitempty"`
	Timezone        *string        `xml:"timezone,omitempty"`
	Properties      *pomProperties `xml:"properties,omitempty"`
}

type pomContributors struct {
	Contributor []pomContributor `xml:"contributor"`
}

type pomContributor struct {
	Name            *string        `xml:"name,omitempty"`
	Email           *string        `xml:"email,omitempty"`
	URL             *string        `xml:"url,omitempty"`
	Organization    *string        `xml:"organization,omitempty"`
	OrganizationURL *string        `xml:"organizationUrl,omitempty"`
	Roles           *[]string      `xml:"roles>role,omitempty"`
	Timezone        *string        `xml:"timezone,omitempty"`
	Properties      *pomProperties `xml:"properties,omitempty"`
}

type pomMailingLists struct {
	MailingList []pomMailingList `xml:"mailingList"`
}

type pomMailingList struct {
	Name          *string   `xml:"name,omitempty"`
	Subscribe     *string   `xml:"subscribe,omitempty"`
	Unsubscribe   *string   `xml:"unsubscribe,omitempty"`
	Post          *string   `xml:"post,omitempty"`
	Archive       *string   `xml:"archive,omitempty"`
	OtherArchives *[]string `xml:"otherArchives>otherArchive,omitempty"`
}

type pomPrerequisites struct {
	Maven *string `xml:"maven,omitempty"`
}

type pomScm struct {
	Connection          *string `xml:"connection,omitempty"`
	DeveloperConnection *string `xml:"developerConnection,omitempty"`
	Tag                 *string `xml:"tag,omitempty"`
	URL                 *string `xml:"url,omitempty"`
}

type pomIssueManagement struct {
	System *string `xml:"system,omitempty"`
	URL    *string `xml:"url,omitempty"`
}

type pomCIManagement struct {
	System    *string        `xml:"system,omitempty"`
	URL       *string        `xml:"url,omitempty"`
	Notifiers *[]pomNotifier `xml:"notifiers>notifier,omitempty"`
}

type pomNotifier struct {
	Type          *string        `xml:"type,omitempty"`
	SendOnError   *bool          `xml:"sendOnError,omitempty"`
	SendOnFailure *bool          `xml:"sendOnFailure,omitempty"`
	SendOnSuccess *bool          `xml:"sendOnSuccess,omitempty"`
	SendOnWarning *bool          `xml:"sendOnWarning,omitempty"`
	Address       *string        `xml:"address,omitempty"`
	Configuration *pomProperties `xml:"configuration,omitempty"`
}

type pomDistributionManagement struct {
	Repository         *pomRepository `xml:"repository,omitempty"`
	SnapshotRepository *pomRepository `xml:"snapshotRepository,omitempty"`
	Site               *pomSite       `xml:"site,omitempty"`
	DownloadURL        *string        `xml:"downloadUrl,omitempty"`
	Relocation         *pomRelocation `xml:"relocation,omitempty"`
	Status             *string        `xml:"status,omitempty"`
}

type pomSite struct {
	ID   *string `xml:"id,omitempty"`
	Name *string `xml:"name,omitempty"`
	URL  *string `xml:"url,omitempty"`
}

type pomRelocation struct {
	GroupID    *string `xml:"groupId,omitempty"`
	ArtifactID *string `xml:"artifactId,omitempty"`
	Version    *string `xml:"version,omitempty"`
	Message    *string `xml:"message,omitempty"`
}

type pomExclusion struct {
	ArtifactID *string `xml:"artifactId,omitempty"`
	GroupID    *string `xml:"groupId,omitempty"`
}

type pomRepositories struct {
	Repository []pomRepository `xml:"repository"`
}

type pomRepository struct {
	UniqueVersion *bool                `xml:"uniqueVersion,omitempty"`
	Releases      *pomRepositoryPolicy `xml:"releases,omitempty"`
	Snapshots     *pomRepositoryPolicy `xml:"snapshots,omitempty"`
	ID            *string              `xml:"id,omitempty"`
	Name          *string              `xml:"name,omitempty"`
	URL           *string              `xml:"url,omitempty"`
	Layout        *string              `xml:"layout,omitempty"`
}

type pomRepositoryPolicy struct {
	Enabled        *string `xml:"enabled,omitempty"`
	UpdatePolicy   *string `xml:"updatePolicy,omitempty"`
	ChecksumPolicy *string `xml:"checksumPolicy,omitempty"`
}

type pomPluginRepositories struct {
	PluginRepository []pomPluginRepository `xml:"pluginRepository"`
}

type pomPluginRepository struct {
	Releases  *pomRepositoryPolicy `xml:"releases,omitempty"`
	Snapshots *pomRepositoryPolicy `xml:"snapshots,omitempty"`
	ID        *string              `xml:"id,omitempty"`
	Name      *string              `xml:"name,omitempty"`
	URL       *string              `xml:"url,omitempty"`
	Layout    *string              `xml:"layout,omitempty"`
}

type pomBuildBase struct {
	DefaultGoal      *string              `xml:"defaultGoal,omitempty"`
	Resources        *[]pomResource       `xml:"resources>resource,omitempty"`
	TestResources    *[]pomResource       `xml:"testResources>testResource,omitempty"`
	Directory        *string              `xml:"directory,omitempty"`
	FinalName        *string              `xml:"finalName,omitempty"`
	Filters          *[]string            `xml:"filters>filter,omitempty"`
	PluginManagement *pomPluginManagement `xml:"pluginManagement,omitempty"`
	Plugins          *[]pomPlugin         `xml:"plugins>plugin,omitempty"`
}

type pomBuild struct {
	SourceDirectory       *string         `xml:"sourceDirectory,omitempty"`
	ScriptSourceDirectory *string         `xml:"scriptSourceDirectory,omitempty"`
	TestSourceDirectory   *string         `xml:"testSourceDirectory,omitempty"`
	OutputDirectory       *string         `xml:"outputDirectory,omitempty"`
	TestOutputDirectory   *string         `xml:"testOutputDirectory,omitempty"`
	Extensions            *[]pomExtension `xml:"extensions>extension,omitempty"`
	pomBuildBase
}

type pomExtension struct {
	GroupID    *string `xml:"groupId,omitempty"`
	ArtifactID *string `xml:"artifactId,omitempty"`
	Version    *string `xml:"version,omitempty"`
}

type pomResource struct {
	TargetPath *string   `xml:"targetPath,omitempty"`
	Filtering  *string   `xml:"filtering,omitempty"`
	Directory  *string   `xml:"directory,omitempty"`
	Includes   *[]string `xml:"includes>include,omitempty"`
	Excludes   *[]string `xml:"excludes>exclude,omitempty"`
}

type pomPluginManagement struct {
	Plugins *[]pomPlugin `xml:"plugins>plugin,omitempty"`
}

type pomPlugin struct {
	GroupID       *string               `xml:"groupId,omitempty"`
	ArtifactID    *string               `xml:"artifactId,omitempty"`
	Version       *string               `xml:"version,omitempty"`
	Extensions    *string               `xml:"extensions,omitempty"`
	Executions    *[]pomPluginExecution `xml:"executions>execution,omitempty"`
	Dependencies  *[]pomDependency      `xml:"dependencies>dependency,omitempty"`
	Inherited     *string               `xml:"inherited,omitempty"`
	Configuration *pomProperties        `xml:"configuration,omitempty"`
}

type pomPluginExecution struct {
	ID            *string        `xml:"id,omitempty"`
	Phase         *string        `xml:"phase,omitempty"`
	Goals         *[]string      `xml:"goals>goal,omitempty"`
	Inherited     *string        `xml:"inherited,omitempty"`
	Configuration *pomProperties `xml:"configuration,omitempty"`
}

type pomReporting struct {
	ExcludeDefaults *string               `xml:"excludeDefaults,omitempty"`
	OutputDirectory *string               `xml:"outputDirectory,omitempty"`
	Plugins         *[]pomReportingPlugin `xml:"plugins>plugin,omitempty"`
}

type pomReportingPlugin struct {
	GroupID       *string         `xml:"groupId,omitempty"`
	ArtifactID    *string         `xml:"artifactId,omitempty"`
	Version       *string         `xml:"version,omitempty"`
	Inherited     *string         `xml:"inherited,omitempty"`
	ReportSets    *[]pomReportSet `xml:"reportSets>reportSet,omitempty"`
	Configuration *pomProperties  `xml:"configuration,omitempty"`
}

type pomReportSet struct {
	ID            *string        `xml:"id,omitempty"`
	Reports       *[]string      `xml:"reports>report,omitempty"`
	Inherited     *string        `xml:"inherited,omitempty"`
	Configuration *pomProperties `xml:"configuration,omitempty"`
}

type pomProfiles struct {
	Profile []pomProfile `xml:"profile"`
}

type pomProfile struct {
	ID                     *string                    `xml:"id,omitempty"`
	Activation             *pomActivation             `xml:"activation,omitempty"`
	Build                  *pomBuildBase              `xml:"build,omitempty"`
	Modules                *[]string                  `xml:"modules>module,omitempty"`
	DistributionManagement *pomDistributionManagement `xml:"distributionManagement,omitempty"`
	Properties             *pomProperties             `xml:"properties,omitempty"`
	DependencyManagement   *pomDepMgmt                `xml:"dependencyManagement,omitempty"`
	Dependencies           *pomDeps                   `xml:"dependencies>dependency,omitempty"`
	Repositories           *[]pomRepository           `xml:"repositories>repository,omitempty"`
	PluginRepositories     *[]pomPluginRepository     `xml:"pluginRepositories>pluginRepository,omitempty"`
	Reporting              *pomReporting              `xml:"reporting,omitempty"`
}

type pomActivation struct {
	ActiveByDefault *bool                  `xml:"activeByDefault,omitempty"`
	JDK             *string                `xml:"jdk,omitempty"`
	OS              *pomActivationOS       `xml:"os,omitempty"`
	Property        *pomActivationProperty `xml:"property,omitempty"`
	File            *pomActivationFile     `xml:"file,omitempty"`
}

type pomActivationOS struct {
	Name    *string `xml:"name,omitempty"`
	Family  *string `xml:"family,omitempty"`
	Arch    *string `xml:"arch,omitempty"`
	Version *string `xml:"version,omitempty"`
}

type pomActivationProperty struct {
	Name  *string `xml:"name,omitempty"`
	Value *string `xml:"value,omitempty"`
}

type pomActivationFile struct {
	Missing *string `xml:"missing,omitempty"`
	Exists  *string `xml:"exists,omitempty"`
}

// pomProperties handles the dynamic <properties> block where each
// child element name is a property key and its text is the value.
type pomProperties struct {
	Entries map[string]string
}

// UnmarshalXML implements custom XML unmarshalling for <properties>,
// collecting each child element as a key-value pair.
func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = value
		case xml.EndElement:
			return nil
		}
	}
}

// parsePOM parses raw XML bytes into a pomProject.
func parsePOM(data []byte) (*pomProject, error) {
	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}
	if pom.Properties == nil {
		pom.Properties = &pomProperties{Entries: make(map[string]string)}
	} else if pom.Properties.Entries == nil {
		pom.Properties.Entries = make(map[string]string)
	}
	return &pom, nil
}

// collectProperties gathers the full property map for a POM by
// walking the parent POM chain (up to maxParentDepth levels).
// Parent properties are fetched from the upstream Maven repository.
func collectProperties(ctx context.Context, pom *pomProject, client *upstream.Client) map[string]string {
	props := make(map[string]string)

	// Walk the parent chain, collecting properties from outermost first.
	chain := parentChain(ctx, pom, client, maxParentDepth)
	for _, ancestor := range chain {
		if ancestor.Properties != nil {
			for k, v := range ancestor.Properties.Entries {
				props[k] = v
			}
		}
	}

	// Current POM's properties override parents.
	if pom.Properties != nil {
		for k, v := range pom.Properties.Entries {
			props[k] = v
		}
	}

	// Add implicit project.* properties.
	if pom.GroupID != nil {
		props["project.groupId"] = *pom.GroupID
	}
	if pom.ArtifactID != nil {
		props["project.artifactId"] = *pom.ArtifactID
	}
	if pom.Version != nil {
		props["project.version"] = *pom.Version
	} else if pom.Parent != nil && pom.Parent.Version != "" {
		// Maven inherits version from parent if not set.
		props["project.version"] = pom.Parent.Version
	}

	return props
}

// parentChain fetches the ancestor POM chain via <parent> references.
// Returns the chain from outermost ancestor to the direct parent.
func parentChain(ctx context.Context, pom *pomProject, client *upstream.Client, depth int) []*pomProject {
	if depth <= 0 || pom.Parent == nil {
		return nil
	}

	parentData, err := fetchPOMFromUpstream(ctx, client, pom.Parent.GroupID, pom.Parent.ArtifactID, pom.Parent.Version)
	if err != nil {
		// Can't fetch parent; stop walking.
		return nil
	}

	parentPOM, err := parsePOM(parentData)
	if err != nil {
		return nil
	}

	// Recurse to grandparent first so the chain is ordered outermost-first.
	ancestors := parentChain(ctx, parentPOM, client, depth-1)
	return append(ancestors, parentPOM)
}

// fetchPOMFromUpstream constructs the Maven repository path for a POM
// and fetches it from the upstream.
func fetchPOMFromUpstream(ctx context.Context, client *upstream.Client, groupID, artifactID, version string) ([]byte, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("incomplete parent coordinates: %s:%s:%s", groupID, artifactID, version)
	}

	path := pomPath(groupID, artifactID, version)

	// Build a minimal request with the context for upstream.Fetch.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://dummy"+path, nil)
	if err != nil {
		return nil, err
	}

	body, status, err := client.Fetch(req, path)
	if err != nil {
		return nil, fmt.Errorf("fetching parent POM %s:%s:%s: %w", groupID, artifactID, version, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("parent POM %s:%s:%s returned HTTP %d", groupID, artifactID, version, status)
	}
	return body, nil
}

// pomPath constructs the Maven repository path for a POM file.
// e.g. groupID="org.apache.commons", artifactID="commons-lang3", version="3.12.0"
// -> "/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
func pomPath(groupID, artifactID, version string) string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	return fmt.Sprintf("/%s/%s/%s/%s-%s.pom", groupPath, artifactID, version, artifactID, version)
}

// resolveVersion replaces ${property} references in a version string
// with values from the property map. Handles nested references up to
// a small depth to avoid infinite expansion.
func resolveVersion(version string, props map[string]string) string {
	if !strings.Contains(version, "${") {
		return version
	}

	resolved := version
	// Iterate a few times to handle transitive references (${a} -> ${b} -> "1.0").
	for i := 0; i < 5; i++ {
		prev := resolved
		resolved = propertyRefRE.ReplaceAllStringFunc(resolved, func(match string) string {
			key := match[2 : len(match)-1] // strip ${ and }
			if val, ok := props[key]; ok {
				return val
			}
			return match // leave unresolved
		})
		if resolved == prev {
			break
		}
	}
	return resolved
}

// resolvedDependencies returns all dependencies from the POM with their
// versions resolved against the property map. Dependencies from
// <dependencyManagement> are included as well. Dependencies with
// unresolvable or empty versions are skipped.
func resolvedDependencies(pom *pomProject, props map[string]string) []pomDependency {
	var deps []pomDependency
	seen := make(map[string]bool)

	addDeps := func(list []pomDependency) {
		for _, d := range list {
			d.Version = resolveVersion(d.Version, props)
			d.GroupID = resolveVersion(d.GroupID, props)
			d.ArtifactID = resolveVersion(d.ArtifactID, props)

			// Skip if version is still unresolved or empty.
			if d.Version == "" || strings.Contains(d.Version, "${") {
				continue
			}

			key := d.GroupID + ":" + d.ArtifactID + ":" + d.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			deps = append(deps, d)
		}
	}

	if pom.Dependencies != nil {
		addDeps(pom.Dependencies.Dependency)
	}
	if pom.DependencyManagement != nil && pom.DependencyManagement.Dependencies != nil {
		addDeps(pom.DependencyManagement.Dependencies.Dependency)
	}

	return deps
}

// isPomRequest returns true if the path is a request for a .pom file.
func isPomRequest(path string) bool {
	return strings.HasSuffix(path, ".pom")
}
