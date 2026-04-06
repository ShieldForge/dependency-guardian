# Dependency Guardian

A security-focused HTTP proxy that sits between package manager clients and upstream registries. It intercepts package metadata requests, evaluates every version against configurable [OPA/Rego](https://www.openpolicyagent.org/) policies and a local vulnerability database, and strips out versions that violate policy - before the client ever sees them.

Supports **npm**, **PyPI**, **Go modules**, and **Maven** out of the box.

**Why?** Supply-chain attacks are one of the fastest-growing threat vectors in software. Typosquatted packages, hijacked maintainer accounts, and known-vulnerable releases are published to public registries every day. Dependency Guardian gives organisations and individual developers a policy-enforcement layer that prevents dangerous packages from entering projects at install time, rather than relying solely on after-the-fact auditing.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Deployment Modes](#deployment-modes)
  - [Standalone Server (Artifactory / CI)](#mode-1-standalone-server--artifactory--ci-gateway)
  - [VS Code Extension - Local Binary](#mode-2-vs-code-extension--local-developer-proxy)
  - [VS Code Extension - Hosted Service](#mode-3-vs-code-extension--hosted-service)
- [Configuration Reference](#configuration-reference)
- [Policy Authoring](#policy-authoring)
- [Vulnerability Database](#vulnerability-database)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Project Structure](#project-structure)

---

## Features

| Category | Capabilities |
|---|---|
| **Multi-ecosystem** | npm, PyPI, Go module, and Maven proxy protocols supported natively |
| **Policy engine** | Declarative OPA/Rego rules - block by severity, age, deprecation, malware flags, or any custom criteria |
| **Vulnerability database** | Local OSV.dev mirror with automatic background sync (full seed + delta updates) |
| **Default policies** | Minimum package age (7 days), malicious package blocking, critical/high vulnerability blocking, yanked version filtering |
| **Live reload** | Update Rego files on disk and reload without restarting the server |
| **Auto-detection** | Routes requests to the correct ecosystem handler based on User-Agent, Accept headers, or path prefix |
| **Artifactory-aware** | Detects `X-Artifactory-Repo-Type` headers and Artifactory User-Agents for seamless integration |
| **Dual database** | PostgreSQL for production / team deployments, SQLite for local / VS Code use |
| **VS Code extension** | Start/stop the proxy from VS Code, view live allow/deny decisions, get per-ecosystem stats, configure package managers with one click, hover tooltips with vulnerability data in manifest files |
| **Transparent downloads** | Tarballs, wheels, zips, and `.mod` files pass through unmodified - only metadata is filtered |

---

## Architecture

```
┌──────────────────┐         ┌──────────────────────────┐         ┌──────────────────┐
│  Developer tools │         │  Dependency Guardian      │         │  Upstream         │
│  ─────────────── │         │  ──────────────────────── │         │  Registries       │
│  npm / yarn      │────────▶│                          │────────▶│  registry.npmjs   │
│  pip / poetry    │         │  ┌────────────────────┐  │         │  pypi.org         │
│  go get          │◀────────│  │ OPA/Rego Policies  │  │◀────────│  proxy.golang.org │
│  mvn / gradle    │         │  └────────────────────┘  │         │  repo1.maven.org  │
│  Artifactory     │         │                          │         └──────────────────┘
└──────────────────┘         │  ┌────────────────────┐  │
                             │  │ OSV Vulnerability   │  │
                             │  │ Database (SQLite/PG)│  │
                             │  └────────────────────┘  │
                             │  ┌────────────────────┐  │
                             │  │ Decision Log & API  │  │  ◀── VS Code extension
                             │  └────────────────────┘  │       polls these endpoints
                             └──────────────────────────┘
```

**How it works:**

1. A package manager (npm, pip, go, mvn/gradle) sends a metadata request to Guardian instead of the upstream registry.
2. Guardian fetches the full metadata from the real upstream.
3. Each version in the response is evaluated against OPA policies. The policy engine receives the package metadata *and* any known vulnerabilities from the local database.
4. Versions that produce a non-empty `deny` set are removed from the response.
5. The modified metadata is returned to the client - it only sees allowed versions.
6. Actual package file downloads (tarballs, wheels, zips) are proxied through without modification.

---

## Quick Start

```bash
# Build the binary
go build -o ./bin/guardian.exe ./cmd/guardian

# Run with the default config
./bin/guardian.exe --config config.yaml
```

The proxy starts on `:8080` by default. Point any package manager at it and install packages as usual - policy-violating versions will be invisible.

---

## Deployment Modes

### Mode 1: Standalone Server - Artifactory / CI Gateway

Use this mode when you want a centralised policy-enforcement proxy for your organisation. It sits between Artifactory (or developer machines) and the public registries.

#### Setup

1. **Build and deploy** the `guardian` binary to a server.

2. **Create a config file** (`config.yaml`):

```yaml
server:
  listen_addr: ":8080"
  read_timeout: 30s
  write_timeout: 60s

upstreams:
  npm:  "https://registry.npmjs.org"
  pypi: "https://pypi.org"
  go:   "https://proxy.golang.org"
  maven: "https://repo1.maven.org/maven2"

policies:
  directory: "./policies"

logging:
  level: "info"
  format: "json"           # JSON logs for production log aggregation

# Enable the vulnerability database for policy decisions
vulndb:
  enabled: true
  driver: "postgres"       # Use Postgres for team/production deployments
  dsn: "host=db.internal user=guardian password=secret dbname=guardian sslmode=require"
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 1h

# Enable background sync from OSV.dev
sync:
  enabled: true
  seed_on_start: true      # Populate the database on first launch
  ecosystems:              # Only sync what you use (empty = all)
    - "npm"
    - "PyPI"
    - "Go"
    - "Maven"
  full_sync_interval: 24h
  delta_sync_interval: 15m
  batch_size: 200
  workers: 4
```

3. **Start the server:**

```bash
./guardian --config config.yaml
```

#### Configuring Artifactory

Configure each Artifactory **remote repository** to use Guardian as its upstream URL instead of the public registry:

| Artifactory Repo Type | URL to set as remote upstream |
|---|---|
| npm | `http://guardian-host:8080/npm/` |
| PyPI | `http://guardian-host:8080/pypi/` |
| Go | `http://guardian-host:8080/go/` |
| Maven | `http://guardian-host:8080/maven/` |

Guardian automatically detects Artifactory requests via `X-Artifactory-Repo-Type` headers and User-Agent patterns, so no additional client-side configuration is needed once Artifactory points at the proxy.

#### Configuring Developer Machines Directly

If developers connect directly to the proxy (without Artifactory), configure each package manager:

**npm / yarn / pnpm:**
```bash
npm config set registry http://guardian-host:8080/npm/
```

**pip / poetry:**
```bash
pip config set global.index-url http://guardian-host:8080/pypi/simple/
pip config set global.trusted-host guardian-host
```

**Go modules:**
```bash
go env -w GOPROXY=http://guardian-host:8080/go/,direct
```

**Maven (settings.xml):**

Add a mirror in your `~/.m2/settings.xml`:
```xml
<settings>
  <mirrors>
    <mirror>
      <id>guardian</id>
      <mirrorOf>central</mirrorOf>
      <url>http://guardian-host:8080/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

#### Auto-detection mode

Alternatively, configure all package managers to point at the root URL (`http://guardian-host:8080/`). Guardian inspects the `User-Agent` and `Accept` headers to automatically route requests to the correct ecosystem handler:

| Client | Detection signal |
|---|---|
| npm, yarn, pnpm, bun | User-Agent starts with `npm/`, `yarn/`, `pnpm/`, `bun/` |
| pip, poetry, uv, pdm | User-Agent starts with `pip/`, `poetry/`, `uv/`, `pdm/`; or Accept contains `vnd.pypi.simple` |
| go get | User-Agent `Go-http-client/`; or `?go-get=1` query parameter |
| Maven, Gradle, sbt | User-Agent starts with `apache-maven/`, `gradle/`, `mvn/`, `ivy/`, `sbt/`, `leiningen/`; or contains `maven`/`gradle` |
| Artifactory | `X-Artifactory-Repo-Type` header |

---

### Mode 2: VS Code Extension - Local Developer Proxy

Use this mode for individual developers who want to run the proxy locally with full visibility into what's being allowed and blocked.

#### What's different in VS Code mode

| Aspect | Standalone | VS Code mode |
|---|---|---|
| Database | PostgreSQL (production) or SQLite | SQLite only (auto-configured) |
| Decision logging | Log output only | In-memory decision log + REST API |
| API endpoints | `/health`, `/policy/reload` | All of the above + `/api/decisions`, `/api/stats` |
| Lifecycle | systemd / Docker / manual | Managed by the extension (start/stop from command palette) |
| Visibility | Server logs | Live tree views, dashboard webview, per-ecosystem stats |

#### Installation

1. **Build the guardian binary:**
```bash
cd dependency-guardian
```

2. **Install the VS Code extension:**
```bash
cd vscode-extension
npm install
npm run compile
```
   Then install from VS Code: *Extensions > Install from VSIX* or *Developer: Install Extension from Location*.

3. **Configure the extension** (optional - all have sensible defaults):

   Open VS Code Settings and search for "Dependency Guardian":

   | Setting | Default | Description |
   |---|---|---|
   | `dependencyGuardian.connectionMode` | `local` | `local` - launch & manage a binary; `hosted` - connect to an existing service. |
   | `dependencyGuardian.hostedUrl` | *(empty)* | URL of the hosted guardian service (e.g. `http://guardian.internal:8080`). Hosted mode only. |
   | `dependencyGuardian.binaryPath` | *(auto-detect)* | Path to the `guardian` binary. Searched in the workspace root, `bin/`, and `cmd/guardian/` if not set. Local mode only. |
   | `dependencyGuardian.listenPort` | `8080` | Port for the proxy to listen on. Local mode only. |
   | `dependencyGuardian.configDirectory` | *(empty)* | Path to the configuration directory. Local mode only. |
   | `dependencyGuardian.policiesDirectory` | *(bundled defaults)* | Path to your `.rego` policy files directory. Local mode only. |
   | `dependencyGuardian.autoStart` | `false` | Start the proxy (local) or connect to the hosted service automatically when VS Code opens. |
   | `dependencyGuardian.autoStopOnClose` | `true` | Stop the local guardian process when VS Code closes. Set to `false` to keep it running in the background. Local mode only. |
   | `dependencyGuardian.vulndbEnabled` | `true` | Enable the local SQLite vulnerability database. |
   | `dependencyGuardian.refreshInterval` | `3` | How often (seconds) to poll for new decisions. |

#### Usage

1. **Start the proxy:** Open the Command Palette (`Ctrl+Shift+P`) and run **Dependency Guardian: Start Proxy**.

2. **Configure your package manager:** Use one of the built-in commands - each shows a confirmation dialog and runs the required shell commands:
   - **Dependency Guardian: Configure npm to Use Proxy** - runs `npm config set registry http://127.0.0.1:8080/npm/`
   - **Dependency Guardian: Configure pip to Use Proxy** - runs `pip config set global.index-url ...` and `pip config set global.trusted-host 127.0.0.1`
   - **Dependency Guardian: Configure Go to Use Proxy** - runs `go env -w GOPROXY=http://127.0.0.1:8080/go/,direct` and `go env -w GONOSUMDB=*`
   - **Dependency Guardian: Configure Maven to Use Proxy** - shows instructions for configuring `~/.m2/settings.xml`

3. **Install packages as usual.** The proxy sits transparently between your tool and the registry.

4. **View decisions** in the Activity Bar:
   - **Proxy Status** - running/stopped indicator, uptime, request counts, per-ecosystem breakdown.
   - **Recent Decisions** - live-updating list of every package version evaluated, with allow/deny icons and expandable details (reasons, vulnerability count).
   - **Blocked Packages** - filtered view showing only denied versions with denial reasons.

   **Manifest hover tooltips:** Open any `package.json`, `go.mod`, `requirements.txt`, or `pom.xml` and hover over a dependency to see live proxy decisions and known vulnerabilities for that package.

5. **Open the Dashboard** (`Dependency Guardian: Show Dashboard`) for a full-page webview with stats cards, ecosystem charts, and a scrollable decision table.

6. **Stop the proxy:** Command Palette > **Dependency Guardian: Stop Proxy**. The extension also stops the proxy when VS Code closes.

---

### Mode 3: VS Code Extension - Hosted Service

Use this mode when your team already runs a Dependency Guardian server (or you run one elsewhere on your machine) and you want VS Code to connect to it instead of spawning a local process.

#### Setup

1. **Set the connection mode to `hosted`:**

   Open VS Code Settings (`Ctrl+,`), search for "Dependency Guardian", and set:
   - **Connection Mode** -> `hosted`
   - **Hosted URL** -> the base URL of the running service, e.g. `http://guardian.internal:8080` or `http://localhost:9090`

   Or in `settings.json`:
   ```json
   {
     "dependencyGuardian.connectionMode": "hosted",
     "dependencyGuardian.hostedUrl": "http://guardian.internal:8080"
   }
   ```

2. **Start the connection:** Command Palette (`Ctrl+Shift+P`) -> **Dependency Guardian: Start Proxy**.

   In hosted mode this validates that the remote service is reachable (via its `/health` endpoint) and then begins polling the API. No local binary is spawned.

3. **Use the extension as normal.** The Proxy Status, Recent Decisions, Blocked Packages tree views, and the Dashboard all work exactly as they do in local mode - the data just comes from the hosted service.

4. **Configure package managers** using the built-in commands (they will use the hosted URL instead of `127.0.0.1`):
   - **Dependency Guardian: Configure npm to Use Proxy**
   - **Dependency Guardian: Configure pip to Use Proxy**
   - **Dependency Guardian: Configure Go to Use Proxy**
   - **Dependency Guardian: Configure Maven to Use Proxy**

5. **Stop the connection:** Command Palette -> **Dependency Guardian: Stop Proxy** (disconnects polling; does not stop the remote server).

#### What's different in hosted mode

| Aspect | Local mode | Hosted mode |
|---|---|---|
| Binary | Spawned & managed by extension | Not used - connects to existing service |
| Start command | Spawns process, waits for health | Validates remote `/health` endpoint |
| Stop command | Sends SIGTERM to child process | Stops polling (remote service keeps running) |
| Package manager config | Points to `127.0.0.1:<port>` | Points to the hosted URL |
| Settings used | `binaryPath`, `listenPort`, `configDirectory`, `policiesDirectory` | `hostedUrl` only |
| Dashboard / tree views | Identical | Identical |

#### Undoing package manager configuration

When you're done, restore your package manager to its defaults:

```bash
# npm
npm config delete registry

# pip
pip config unset global.index-url
pip config unset global.trusted-host

# Go
go env -w GOPROXY=https://proxy.golang.org,direct
go env -u GONOSUMDB

# Maven
# Remove the <mirror> block from ~/.m2/settings.xml
```

---

## Configuration Reference

All configuration is in `config.yaml`. Every field has a sensible default - the file is optional.

```yaml
# ─── HTTP Server ─────────────────────────────────────────────────
server:
  listen_addr: ":8080"          # Address to bind (host:port or :port)
  read_timeout: 30s             # Max time to read request headers + body
  write_timeout: 60s            # Max time to write the response
  max_request_body: 10485760    # Max request body size in bytes (10 MB)
  admin_token: ""               # Bearer token for POST /policy/reload (empty = open)

# ─── Upstream Registries ─────────────────────────────────────────
# The real registries that Guardian proxies requests to.
upstreams:
  npm:  "https://registry.npmjs.org"
  pypi: "https://pypi.org"
  go:   "https://proxy.golang.org"
  maven: "https://repo1.maven.org/maven2"

# ─── OPA/Rego Policies ──────────────────────────────────────────
policies:
  directory: "./policies"       # Directory containing .rego files

# ─── Logging ─────────────────────────────────────────────────────
logging:
  level: "info"                 # debug | info | warn | error
  format: "text"                # text | json

# ─── Vulnerability Database ─────────────────────────────────────
vulndb:
  enabled: false                # Set to true to activate
  driver: "sqlite"              # "sqlite" or "postgres"
  dsn: "./vulndb.sqlite"        # File path (sqlite) or connection string (postgres)
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_lifetime: 1h
  log_level: "warn"             # silent | error | warn | info

# ─── OSV Sync ───────────────────────────────────────────────────
sync:
  enabled: false                # Background sync from osv.dev
  seed_on_start: false          # Full sync on startup
  ecosystems: []                # Empty = all ecosystems; or ["npm", "PyPI", "Go"]
  full_sync_interval: 24h       # Full reseed frequency
  delta_sync_interval: 15m      # Incremental update frequency
  metrics_interval: 1h          # Metrics recalculation frequency
  batch_size: 100               # Records per DB transaction
  workers: 2                    # Concurrent download workers
```

### CLI Flags

```
./guardian [flags]

  --config <path>   Path to config.yaml (default: "config.yaml")
  --vscode          VS Code extension mode: forces SQLite, enables decision
                    logging and /api/* endpoints
  --addr <addr>     Override listen address (e.g. ":9090")
```

---

## Policy Authoring

Policies are [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) files in the `policies/` directory. The proxy evaluates `data.guardian.deny` for every package version - if the resulting set contains any strings, the version is blocked. Each string is a human-readable reason.

### Input Schema

Every policy evaluation receives this input:

```json
{
  "package": {
    "name": "lodash",
    "version": "4.17.21",
    "ecosystem": "npm",
    "published_at": "2021-02-20T15:42:12Z",
    "deprecated": false,
    "yanked": false
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "severity": "high",
      "summary": "Prototype pollution in lodash",
      "fixed_in": "4.17.21",
      "is_malicious": false
    }
  ]
}
```

### Built-in Policies

The default policy file (`policies/default.rego`) enforces:

| Rule | Description |
|---|---|
| **Malicious packages** | Deny any version flagged `is_malicious` by the vulnerability database |
| **Critical vulnerabilities** | Deny versions with `severity == "critical"` |
| **High vulnerabilities** | Deny versions with `severity == "high"` |
| **Minimum age (7 days)** | Deny versions published less than 7 days ago |
| **Yanked versions** | Deny versions marked as yanked/unpublished |

### Custom Policy Examples

**Block all deprecated npm packages:**
```rego
package guardian

import rego.v1

deny contains msg if {
    input.package.ecosystem == "npm"
    input.package.deprecated == true
    msg := sprintf("%s@%s is deprecated", [input.package.name, input.package.version])
}
```

**Require packages to be at least 30 days old:**
```rego
package guardian

import rego.v1

deny contains msg if {
    input.package.published_at != "0001-01-01T00:00:00Z"
    published := time.parse_rfc3339_ns(input.package.published_at)
    now := time.now_ns()
    age_days := (now - published) / (24 * 60 * 60 * 1000000000)
    age_days < 30
    msg := sprintf("%s@%s is less than 30 days old", [input.package.name, input.package.version])
}
```

**Allowlist specific packages (bypass all other rules):**
```rego
package guardian

import rego.v1

allowlist := {"lodash", "express", "react"}

deny contains msg if {
    not allowlist[input.package.name]
    # ... your normal deny rules here
}
```

### Live Reload

Update `.rego` files on disk, then reload without restarting:

```bash
curl -X POST http://localhost:8080/policy/reload
# -> {"status":"reloaded"}
```

---

## Vulnerability Database

Guardian includes a local vulnerability database backed by [OSV.dev](https://osv.dev/) data, stored in PostgreSQL or SQLite via GORM.

### Data Flow

```
osv.dev bulk download (all.zip per ecosystem)
    │
    ▼
┌───────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│ osvparser      │────▶│ DAL (data access     │────▶│ Database            │
│ JSON -> models  │     │ layer)               │     │ (Postgres / SQLite) │
└───────────────┘     └──────────────────────┘     └─────────────────────┘
                                                            │
osv.dev delta feed (modified_id.csv)                        │
    │                                                       ▼
    └───────────────────────────────────────────▶ affected_package_index
                                                   (fast proxy lookups)
```

### Database Tables

| Table | Purpose |
|---|---|
| `vulnerabilities` | Top-level OSV records (ID, summary, details, modified date) |
| `vulnerability_aliases` | CVE and other cross-references |
| `affected` | Affected package entries with ecosystem, name, version lists |
| `affected_ranges` / `range_events` | Version ranges (SEMVER, ECOSYSTEM, GIT) |
| `severities` | CVSS scores (top-level and per-affected) |
| `references` / `credits` | Advisory links and attribution |
| `affected_package_index` | Denormalised lookup table for fast proxy-time queries |
| `ecosystem_sync_states` | Per-ecosystem sync status, cursors, and metrics |
| `sync_logs` | Audit trail of all sync operations |

### Pluggable Interface

The `VulnerabilityDB` interface is pluggable - set `vulndb.enabled: false` and provide your own implementation:

```go
type VulnerabilityDB interface {
    GetVulnerabilities(ctx context.Context, ecosystem Ecosystem, name, version string) ([]VulnerabilityRecord, error)
}
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check - returns `{"status":"ok"}` |
| `/policy/reload` | POST | Reload Rego policies from disk (requires admin token if configured) |
| `/npm/<package>` | GET | Proxied npm metadata (versions filtered by policy) |
| `/pypi/pypi/<package>/json` | GET | Proxied PyPI JSON metadata (filtered) |
| `/go/<module>/@v/list` | GET | Proxied Go version list (filtered) |
| `/maven/<group>/<artifact>/maven-metadata.xml` | GET | Proxied Maven metadata (versions filtered by policy) |
| `/api/decisions?limit=N&filter=denied` | GET | Recent policy decisions *(VS Code mode only)* |
| `/api/stats` | GET | Aggregate statistics *(VS Code mode only)* |
| `/api/vulndb` | GET | Vulnerability database metrics and sync state *(requires vulndb enabled)* |
| `/api/lookup?ecosystem=E&name=N&version=V` | GET | Vulnerability lookup for a specific package *(requires vulndb enabled)* |

### Decision API Response

```json
[
  {
    "id": 42,
    "timestamp": "2026-03-24T14:30:00Z",
    "ecosystem": "npm",
    "package": "lodash",
    "version": "4.17.20",
    "allowed": false,
    "reasons": ["package lodash@4.17.20 has high-severity vulnerability CVE-2021-23337: Prototype pollution"],
    "vulnerabilities": 1
  }
]
```

### Stats API Response

```json
{
  "total_requests": 1547,
  "total_allowed": 1502,
  "total_denied": 45,
  "by_ecosystem": { "npm": 1200, "pypi": 300, "go": 47 },
  "denied_by_ecosystem": { "npm": 38, "pypi": 5, "go": 2 },
  "recent_denied": [ ... ],
  "uptime": "2h15m30s"
}
```

### VulnDB Status API Response

```json
{
  "global": {
    "total_vulnerabilities": 45230,
    "total_affected_entries": 128400,
    "ecosystems_synced": 3
  },
  "ecosystems": [
    {
      "ecosystem": "npm",
      "status": "synced",
      "last_full_sync": "2026-03-24T02:00:00Z",
      "last_delta_sync": "2026-03-24T14:15:00Z",
      "total_vulnerabilities": 28100,
      "total_affected_entries": 82000
    }
  ]
}
```

### Lookup API Response

```
GET /api/lookup?ecosystem=maven&name=org.postgresql:postgresql&version=42.7.2
```

```json
{
  "ecosystem": "Maven",
  "name": "org.postgresql:postgresql",
  "vulnerabilities": [
    {
      "osv_id": "GHSA-xxxx-yyyy-zzzz",
      "max_severity": "high",
      "is_malicious": false,
      "version": "42.7.2"
    }
  ],
  "total": 1
}
```

The `version` parameter is optional. When provided, results are filtered to only vulnerabilities that affect that specific version using ecosystem-aware version comparison (semver for npm/Go, Maven version ordering for Maven, PEP 440 for PyPI).
```

### Authentication

The `POST /policy/reload` endpoint can be protected with a bearer token. Set `server.admin_token` in the config:

```yaml
server:
  admin_token: "my-secret-token"
```

Then include the token in the `Authorization` header:

```bash
curl -X POST -H "Authorization: Bearer my-secret-token" http://localhost:8080/policy/reload
```

When no `admin_token` is configured, the endpoint is open (suitable for local / VS Code mode).

---

## Testing

```bash
# All tests
go test ./...

# Verbose
go test -v ./...

# Single package
go test ./internal/handler/npm/...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

All tests are self-contained - no external services required. Handlers use `httptest.NewServer` with fake upstreams; the database layer uses in-memory SQLite.

---

## Project Structure

```
cmd/guardian/                  CLI entry point
internal/
  config/                      YAML configuration loading
  decisions/                   In-memory decision log (VS Code mode)
  handler/
    npm/                       npm registry proxy handler
    pypi/                      PyPI registry proxy handler
    gomod/                     Go module proxy handler
    maven/                     Maven repository proxy handler
    upstream/                  Shared upstream HTTP client
  policy/                      OPA/Rego policy engine
  proxy/                       HTTP server, routing, auto-detection
  registry/                    Shared types (PackageVersion, PolicyInput, VulnerabilityDB)
  vulndb/
    models/                    GORM models (OSV schema + sync tracking)
    database/                  Connection setup (Postgres / SQLite)
    dal/                       Data access layer (queries, upserts, indexing)
    osvparser/                 OSV JSON -> GORM model converter
    sync/                      Bulk seed, delta updates, scheduler
    osvdb.go                   VulnerabilityDB implementation
policies/                      Rego policy files
config.yaml                    Default configuration
vscode-extension/              VS Code extension source
  src/
    extension.ts               Extension entry point
    proxy.ts                   Guardian binary lifecycle manager
    decisions.ts               Recent Decisions tree view
    denied.ts                  Blocked Packages tree view
    statusTree.ts              Proxy Status tree view
    dashboard.ts               Full-page dashboard webview
    configHelper.ts            Package manager configuration commands
    manifest.ts                Manifest hover tooltips and diagnostics
```
