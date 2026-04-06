import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";

// ── Types ────────────────────────────────────────────────────────

/** A dependency extracted from a manifest file. */
interface ManifestDependency {
    name: string;
    version: string; // The resolved version (or raw if no resolution needed)
    ecosystem: string; // "npm" | "pypi" | "go" | "maven"
    range: vscode.Range; // Location in the document (for diagnostics + hover)
    nameRange: vscode.Range; // Just the package name span
    rawVersion?: string; // The original version string if it contained a property reference (e.g. "${spring.version}")
}

/** A recent decision from the proxy. */
export interface DecisionEntry {
    id: number;
    timestamp: string;
    ecosystem: string;
    package: string;
    version: string;
    allowed: boolean;
    reasons?: string[];
    vulnerabilities: number;
}

/** A vulnerability record from /api/lookup. */
interface LookupVuln {
    osv_id: string;
    max_severity: string;
    is_malicious: boolean;
    version?: string;
}

interface LookupResult {
    ecosystem: string;
    name: string;
    vulnerabilities: LookupVuln[];
    total: number;
}

// ── ManifestAnalyzer ─────────────────────────────────────────────

/**
 * Parses package manager manifest files, cross-references with proxy
 * decision data, and provides diagnostics (Problems tab) and hover
 * tooltips.
 */
export class ManifestAnalyzer implements vscode.Disposable {
    private diagnostics: vscode.DiagnosticCollection;
    private disposables: vscode.Disposable[] = [];
    private decisions: DecisionEntry[] = [];
    private baseUrl = "";

    // Cache lookup results for a short time to avoid hammering the API on
    // every keystroke.
    private lookupCache = new Map<string, { data: LookupResult; ts: number }>();
    private static CACHE_TTL = 60_000; // 1 minute

    constructor() {
        this.diagnostics =
            vscode.languages.createDiagnosticCollection("dependencyGuardian");

        // Register hover providers for manifest file types.
        this.disposables.push(
            vscode.languages.registerHoverProvider(
                { language: "json", pattern: "**/package.json" },
                { provideHover: (doc, pos) => this.provideHover(doc, pos) },
            ),
            vscode.languages.registerHoverProvider(
                { pattern: "**/go.mod" },
                { provideHover: (doc, pos) => this.provideHover(doc, pos) },
            ),
            vscode.languages.registerHoverProvider(
                { pattern: "**/requirements*.txt" },
                { provideHover: (doc, pos) => this.provideHover(doc, pos) },
            ),
            vscode.languages.registerHoverProvider(
                { language: "xml", pattern: "**/pom.xml" },
                { provideHover: (doc, pos) => this.provideHover(doc, pos) },
            ),
        );

        // Analyze open manifest documents and re-analyze on changes.
        this.disposables.push(
            vscode.workspace.onDidOpenTextDocument((doc) =>
                this.analyzeIfManifest(doc),
            ),
            vscode.workspace.onDidChangeTextDocument((e) =>
                this.analyzeIfManifest(e.document),
            ),
            vscode.workspace.onDidCloseTextDocument((doc) =>
                this.diagnostics.delete(doc.uri),
            ),
        );

        // Analyze any already-open manifest files.
        for (const doc of vscode.workspace.textDocuments) {
            this.analyzeIfManifest(doc);
        }
    }

    /** Update the base URL used for API calls (e.g. `http://127.0.0.1:8080`). */
    setBaseUrl(url: string) {
        this.baseUrl = url;
    }

    /** Feed fresh decision data from the extension's polling loop. */
    updateDecisions(entries: DecisionEntry[]) {
        this.decisions = entries;
        // Re-analyze all open manifest files with new decision data.
        for (const doc of vscode.workspace.textDocuments) {
            this.analyzeIfManifest(doc);
        }
    }

    dispose() {
        this.diagnostics.dispose();
        for (const d of this.disposables) {
            d.dispose();
        }
    }

    // ── Analysis ─────────────────────────────────────────────────

    private analyzeIfManifest(doc: vscode.TextDocument) {
        const deps = this.parseDependencies(doc);
        if (!deps) {
            return;
        } // Not a manifest file.

        const diags: vscode.Diagnostic[] = [];

        for (const dep of deps) {
            // Check against recent decisions for this package.
            const denied = this.decisions.filter(
                (d) =>
                    d.package === dep.name && d.ecosystem === dep.ecosystem && !d.allowed,
            );

            if (denied.length > 0) {
                const reasons = [...new Set(denied.flatMap((d) => d.reasons ?? []))];
                const msg = `Blocked by Dependency Guardian: ${reasons.join("; ") || "policy violation"}`;
                const diag = new vscode.Diagnostic(
                    dep.range,
                    msg,
                    vscode.DiagnosticSeverity.Error,
                );
                diag.source = "Dependency Guardian";
                diags.push(diag);
            }
        }

        this.diagnostics.set(doc.uri, diags);
    }

    // ── Hover ────────────────────────────────────────────────────

    private async provideHover(
        doc: vscode.TextDocument,
        pos: vscode.Position,
    ): Promise<vscode.Hover | undefined> {
        const deps = this.parseDependencies(doc);
        if (!deps) {
            return;
        }

        const dep = deps.find((d) => d.range.contains(pos));
        if (!dep) {
            return;
        }

        const sections: string[] = [];
        if (dep.rawVersion && dep.rawVersion !== dep.version) {
            sections.push(
                `**${dep.name}** \`${dep.version}\` *(from \`${dep.rawVersion}\`)*  *(${dep.ecosystem})*`,
            );
        } else {
            sections.push(`**${dep.name}** \`${dep.version}\`  *(${dep.ecosystem})*`);
        }

        // Decision info from cache.
        const related = this.decisions.filter(
            (d) => d.package === dep.name && d.ecosystem === dep.ecosystem,
        );
        if (related.length > 0) {
            const allowed = related.filter((d) => d.allowed).length;
            const denied = related.filter((d) => !d.allowed);
            sections.push(`---`);
            sections.push(
                `**Recent proxy decisions:** ${allowed} allowed, ${denied.length} denied`,
            );
            if (denied.length > 0) {
                const reasons = [...new Set(denied.flatMap((d) => d.reasons ?? []))];
                for (const r of reasons.slice(0, 5)) {
                    sections.push(`- $(error) ${r}`);
                }
            }
        }

        // Lookup vulnerability data from the API (pass resolved version for precision).
        const lookup = await this.lookupPackage(
            dep.ecosystem,
            dep.name,
            dep.version,
        );
        if (lookup && lookup.total > 0) {
            sections.push(`---`);
            const malicious = lookup.vulnerabilities.filter(
                (v) => v.is_malicious,
            ).length;
            const critical = lookup.vulnerabilities.filter(
                (v) => v.max_severity === "critical",
            ).length;
            const high = lookup.vulnerabilities.filter(
                (v) => v.max_severity === "high",
            ).length;
            const other = lookup.total - malicious - critical - high;

            sections.push(`**Known vulnerabilities:** ${lookup.total}`);
            if (malicious > 0) {
                sections.push(`- $(warning) **Malicious:** ${malicious}`);
            }
            if (critical > 0) {
                sections.push(`- $(error) **Critical:** ${critical}`);
            }
            if (high > 0) {
                sections.push(`- $(error) **High:** ${high}`);
            }
            if (other > 0) {
                sections.push(`- $(info) **Other:** ${other}`);
            }

            // Show first few IDs.
            const ids = lookup.vulnerabilities.slice(0, 5).map((v) => v.osv_id);
            if (ids.length > 0) {
                sections.push("");
                sections.push(
                    ids.join(", ") +
                    (lookup.total > 5 ? `, … (+${lookup.total - 5} more)` : ""),
                );
            }
        } else if (lookup && lookup.total === 0) {
            sections.push(`---`);
            sections.push(`$(check) No known vulnerabilities`);
        }

        const md = new vscode.MarkdownString(sections.join("\n\n"), true);
        md.isTrusted = true;
        return new vscode.Hover(md, dep.range);
    }

    // ── API lookup ───────────────────────────────────────────────

    private async lookupPackage(
        ecosystem: string,
        name: string,
        version?: string,
    ): Promise<LookupResult | null> {
        if (!this.baseUrl) {
            return null;
        }

        const key = `${ecosystem}:${name}:${version ?? "*"}`;
        const cached = this.lookupCache.get(key);
        if (cached && Date.now() - cached.ts < ManifestAnalyzer.CACHE_TTL) {
            return cached.data;
        }

        try {
            let url = `${this.baseUrl}/api/lookup?ecosystem=${encodeURIComponent(ecosystem)}&name=${encodeURIComponent(name)}`;
            if (version && version !== "*") {
                url += `&version=${encodeURIComponent(version)}`;
            }
            const res = await fetch(url);
            if (!res.ok) {
                return null;
            }
            const data = (await res.json()) as LookupResult;
            this.lookupCache.set(key, { data, ts: Date.now() });
            return data;
        } catch {
            return null;
        }
    }

    // ── Manifest Parsers ─────────────────────────────────────────

    private parseDependencies(
        doc: vscode.TextDocument,
    ): ManifestDependency[] | null {
        const fileName = doc.uri.path.split("/").pop() ?? "";

        if (fileName === "package.json" && doc.languageId === "json") {
            return this.parsePackageJson(doc);
        }
        if (fileName === "go.mod") {
            return this.parseGoMod(doc);
        }
        if (/^requirements.*\.txt$/.test(fileName)) {
            return this.parseRequirementsTxt(doc);
        }
        if (fileName === "pom.xml" && doc.languageId === "xml") {
            return this.parsePomXml(doc);
        }
        return null;
    }

    /** Parse npm package.json dependencies. */
    private parsePackageJson(doc: vscode.TextDocument): ManifestDependency[] {
        const deps: ManifestDependency[] = [];
        const text = doc.getText();

        // Regex-based approach to find dependency lines within dependency objects.
        // We look for the well-known keys then scan their contents.
        const depSections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        for (const section of depSections) {
            // Find the section key in the JSON.
            const sectionRegex = new RegExp(`"${section}"\\s*:\\s*\\{`, "g");
            const sectionMatch = sectionRegex.exec(text);
            if (!sectionMatch) {
                continue;
            }

            // Find the matching closing brace.
            const startIdx = sectionMatch.index + sectionMatch[0].length;
            let braceCount = 1;
            let endIdx = startIdx;
            while (endIdx < text.length && braceCount > 0) {
                if (text[endIdx] === "{") {
                    braceCount++;
                }
                if (text[endIdx] === "}") {
                    braceCount--;
                }
                endIdx++;
            }

            const sectionText = text.substring(startIdx, endIdx - 1);
            const sectionOffset = startIdx;

            // Match each "name": "version" pair.
            const entryRegex = /"([^"]+)"\s*:\s*"([^"]*)"/g;
            let entry;
            while ((entry = entryRegex.exec(sectionText)) !== null) {
                const nameStart = sectionOffset + entry.index + 1; // skip opening "
                const nameEnd = nameStart + entry[1].length;
                const fullStart = sectionOffset + entry.index;
                const fullEnd = sectionOffset + entry.index + entry[0].length;

                deps.push({
                    name: entry[1],
                    version: entry[2],
                    ecosystem: "npm",
                    range: new vscode.Range(
                        doc.positionAt(fullStart),
                        doc.positionAt(fullEnd),
                    ),
                    nameRange: new vscode.Range(
                        doc.positionAt(nameStart),
                        doc.positionAt(nameEnd),
                    ),
                });
            }
        }

        return deps;
    }

    /** Parse Go module dependencies from go.mod. */
    private parseGoMod(doc: vscode.TextDocument): ManifestDependency[] {
        const deps: ManifestDependency[] = [];
        const text = doc.getText();

        // Match require blocks: require ( ... )
        const blockRegex = /require\s*\(\s*([\s\S]*?)\)/g;
        let blockMatch;
        while ((blockMatch = blockRegex.exec(text)) !== null) {
            const blockContent = blockMatch[1];
            const blockOffset =
                blockMatch.index + blockMatch[0].indexOf(blockContent);
            this.parseGoRequireLines(doc, blockContent, blockOffset, deps);
        }

        // Match single-line require: require github.com/foo/bar v1.2.3
        const singleRegex = /^require\s+([\w./-]+)\s+(v[\w.+-]+)/gm;
        let singleMatch;
        while ((singleMatch = singleRegex.exec(text)) !== null) {
            const lineStart = singleMatch.index;
            const lineEnd = lineStart + singleMatch[0].length;
            const nameStart = lineStart + singleMatch[0].indexOf(singleMatch[1]);
            const nameEnd = nameStart + singleMatch[1].length;

            deps.push({
                name: singleMatch[1],
                version: singleMatch[2],
                ecosystem: "go",
                range: new vscode.Range(
                    doc.positionAt(lineStart),
                    doc.positionAt(lineEnd),
                ),
                nameRange: new vscode.Range(
                    doc.positionAt(nameStart),
                    doc.positionAt(nameEnd),
                ),
            });
        }

        return deps;
    }

    private parseGoRequireLines(
        doc: vscode.TextDocument,
        content: string,
        offset: number,
        deps: ManifestDependency[],
    ) {
        const lineRegex = /^\s*([\w./-]+)\s+(v[\w.+-]+)/gm;
        let match;
        while ((match = lineRegex.exec(content)) !== null) {
            const nameStart = offset + match.index + match[0].indexOf(match[1]);
            const nameEnd = nameStart + match[1].length;

            // Use the trimmed content range.
            const fullStart =
                offset + match.index + (match[0].length - match[0].trimStart().length);
            const fullEnd = offset + match.index + match[0].length;

            deps.push({
                name: match[1],
                version: match[2],
                ecosystem: "go",
                range: new vscode.Range(
                    doc.positionAt(fullStart),
                    doc.positionAt(fullEnd),
                ),
                nameRange: new vscode.Range(
                    doc.positionAt(nameStart),
                    doc.positionAt(nameEnd),
                ),
            });
        }
    }

    /** Parse Python requirements.txt files. */
    private parseRequirementsTxt(doc: vscode.TextDocument): ManifestDependency[] {
        const deps: ManifestDependency[] = [];

        for (let i = 0; i < doc.lineCount; i++) {
            const line = doc.lineAt(i);
            const text = line.text.trim();

            // Skip comments and empty lines.
            if (!text || text.startsWith("#") || text.startsWith("-")) {
                continue;
            }

            // Match patterns like: package==1.0.0, package>=1.0, package~=1.0, package
            const match = text.match(/^([A-Za-z0-9_][\w.-]*)\s*(.*)$/);
            if (!match) {
                continue;
            }

            const name = match[1];
            const versionPart = match[2].trim();

            // Find position of the name in the line.
            const nameIdx = line.text.indexOf(name);
            const nameRange = new vscode.Range(
                new vscode.Position(i, nameIdx),
                new vscode.Position(i, nameIdx + name.length),
            );

            deps.push({
                name: name.toLowerCase(), // PyPI normalises to lowercase
                version: versionPart || "*",
                ecosystem: "pypi",
                range: new vscode.Range(line.range.start, line.range.end),
                nameRange,
            });
        }

        return deps;
    }

    /** Parse Maven dependencies from pom.xml. */
    private parsePomXml(doc: vscode.TextDocument): ManifestDependency[] {
        const deps: ManifestDependency[] = [];
        const text = doc.getText();

        // Collect Maven properties from this POM and its parent chain.
        const props = this.collectMavenProperties(text, doc.uri);

        // Match <dependency> blocks containing groupId, artifactId, and optional version.
        const depRegex = /<dependency>\s*([\s\S]*?)<\/dependency>/g;
        let depMatch;
        while ((depMatch = depRegex.exec(text)) !== null) {
            const block = depMatch[1];
            const blockOffset = depMatch.index;

            const groupMatch = /<groupId>\s*([^<]+?)\s*<\/groupId>/.exec(block);
            const artifactMatch = /<artifactId>\s*([^<]+?)\s*<\/artifactId>/.exec(
                block,
            );
            const versionMatch = /<version>\s*([^<]+?)\s*<\/version>/.exec(block);

            if (!groupMatch || !artifactMatch) {
                continue;
            }

            const groupId = groupMatch[1];
            const artifactId = artifactMatch[1];
            const rawVersion = versionMatch ? versionMatch[1] : "*";
            const version = this.resolveMavenProperties(rawVersion, props);
            const name = `${groupId}:${artifactId}`;

            // Range covers the entire <dependency> block.
            const fullStart = blockOffset;
            const fullEnd = blockOffset + depMatch[0].length;

            // Name range covers the <artifactId> value for hover targeting.
            const artifactValueStart =
                blockOffset +
                artifactMatch.index +
                artifactMatch[0].indexOf(artifactId);
            const artifactValueEnd = artifactValueStart + artifactId.length;

            deps.push({
                name,
                version,
                ecosystem: "maven",
                range: new vscode.Range(
                    doc.positionAt(fullStart),
                    doc.positionAt(fullEnd),
                ),
                nameRange: new vscode.Range(
                    doc.positionAt(artifactValueStart),
                    doc.positionAt(artifactValueEnd),
                ),
                rawVersion: rawVersion !== version ? rawVersion : undefined,
            });
        }

        return deps;
    }

    // ── Maven property resolution ────────────────────────────────

    /**
     * Collects Maven properties from the current POM text and its parent
     * POM chain (resolved via `<relativePath>` or the default `../pom.xml`).
     * Parent properties are loaded first so child properties override them.
     */
    private collectMavenProperties(
        text: string,
        docUri: vscode.Uri,
    ): Map<string, string> {
        const props = new Map<string, string>();

        // Walk the parent chain first (outermost ancestor properties loaded first).
        const parentProps = this.resolveParentMavenProperties(text, docUri, 10);
        for (const [k, v] of parentProps) {
            props.set(k, v);
        }

        // Current file properties override parents.
        const localProps = this.parseMavenProperties(text);
        for (const [k, v] of localProps) {
            props.set(k, v);
        }

        // Add implicit project.* properties.
        const projectVersion = this.extractXmlElement(text, "version");
        const projectGroupId = this.extractXmlElement(text, "groupId");
        const projectArtifactId = this.extractXmlElement(text, "artifactId");

        if (projectVersion) {
            props.set("project.version", projectVersion);
        }
        if (projectGroupId) {
            props.set("project.groupId", projectGroupId);
        }
        if (projectArtifactId) {
            props.set("project.artifactId", projectArtifactId);
        }

        // If project.version is not set but parent version is, inherit it.
        if (!projectVersion && !props.has("project.version")) {
            const parentVersion = this.extractPomParentField(text, "version");
            if (parentVersion) {
                props.set("project.version", parentVersion);
            }
        }

        return props;
    }

    /**
     * Walks the parent POM chain by reading files from the filesystem.
     * Uses `<relativePath>` from the `<parent>` block, defaulting to
     * `../pom.xml` per Maven convention.
     */
    private resolveParentMavenProperties(
        text: string,
        docUri: vscode.Uri,
        maxDepth: number,
    ): Map<string, string> {
        const props = new Map<string, string>();
        if (maxDepth <= 0) {
            return props;
        }

        // Check if this POM has a <parent> block.
        const parentBlock = /<parent>\s*([\s\S]*?)<\/parent>/.exec(text);
        if (!parentBlock) {
            return props;
        }

        // Determine the relative path to the parent POM.
        const relativePathMatch =
            /<relativePath>\s*([^<]+?)\s*<\/relativePath>/.exec(parentBlock[1]);
        const relativePath = relativePathMatch
            ? relativePathMatch[1]
            : "../pom.xml";

        // Resolve the parent POM path relative to the current document.
        const currentDir = path.dirname(docUri.fsPath);
        let parentPomPath = path.resolve(currentDir, relativePath);

        // If relativePath points to a directory, append pom.xml.
        try {
            if (fs.statSync(parentPomPath).isDirectory()) {
                parentPomPath = path.join(parentPomPath, "pom.xml");
            }
        } catch {
            // File doesn't exist; nothing to resolve.
            return props;
        }

        // Read the parent POM.
        let parentText: string;
        try {
            parentText = fs.readFileSync(parentPomPath, "utf-8");
        } catch {
            return props;
        }

        // Recurse into grandparent first so outermost properties come first.
        const parentUri = vscode.Uri.file(parentPomPath);
        const ancestorProps = this.resolveParentMavenProperties(
            parentText,
            parentUri,
            maxDepth - 1,
        );
        for (const [k, v] of ancestorProps) {
            props.set(k, v);
        }

        // Then apply this parent's properties (overriding grandparent).
        const parentProps = this.parseMavenProperties(parentText);
        for (const [k, v] of parentProps) {
            props.set(k, v);
        }

        return props;
    }

    /** Extracts key-value pairs from the `<properties>` block of a POM. */
    private parseMavenProperties(text: string): Map<string, string> {
        const props = new Map<string, string>();
        const propsBlock = /<properties>\s*([\s\S]*?)<\/properties>/.exec(text);
        if (!propsBlock) {
            return props;
        }

        // Match each <key>value</key> within the properties block.
        const entryRegex = /<([a-zA-Z][\w.-]*)>\s*([^<]*?)\s*<\/\1>/g;
        let match;
        while ((match = entryRegex.exec(propsBlock[1])) !== null) {
            props.set(match[1], match[2]);
        }
        return props;
    }

    /**
     * Resolves `${property}` references in a version string using the
     * given property map. Handles transitive references (up to 5 levels).
     */
    private resolveMavenProperties(
        version: string,
        props: Map<string, string>,
    ): string {
        if (!version.includes("${")) {
            return version;
        }

        let resolved = version;
        for (let i = 0; i < 5; i++) {
            const prev = resolved;
            resolved = resolved.replace(/\$\{([^}]+)}/g, (match, key) => {
                return props.get(key) ?? match;
            });
            if (resolved === prev) {
                break;
            }
        }
        return resolved;
    }

    /** Extracts the text of a top-level XML element (first match directly under <project>). */
    private extractXmlElement(text: string, element: string): string | undefined {
        // Match the element at the project level (not nested inside <parent>, <dependencies>, etc.).
        // We look for the element outside known nested blocks.
        const regex = new RegExp(`<${element}>\\s*([^<]+?)\\s*</${element}>`, "g");
        let match;
        while ((match = regex.exec(text)) !== null) {
            // Skip if inside a <parent> block.
            const before = text.substring(0, match.index);
            const openParent = (before.match(/<parent>/g) || []).length;
            const closeParent = (before.match(/<\/parent>/g) || []).length;
            if (openParent > closeParent) {
                continue;
            }

            // Skip if inside <dependencies> or <dependencyManagement>.
            const openDeps = (before.match(/<dependencies>/g) || []).length;
            const closeDeps = (before.match(/<\/dependencies>/g) || []).length;
            if (openDeps > closeDeps) {
                continue;
            }

            return match[1];
        }
        return undefined;
    }

    /** Extracts a field from the `<parent>` block. */
    private extractPomParentField(
        text: string,
        field: string,
    ): string | undefined {
        const parentBlock = /<parent>\s*([\s\S]*?)<\/parent>/.exec(text);
        if (!parentBlock) {
            return undefined;
        }
        const regex = new RegExp(`<${field}>\\s*([^<]+?)\\s*</${field}>`);
        const match = regex.exec(parentBlock[1]);
        return match ? match[1] : undefined;
    }
}
