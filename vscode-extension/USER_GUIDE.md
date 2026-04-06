# Dependency Guardian - VS Code Extension User Guide

Dependency Guardian is a security proxy that sits between your package manager (npm, pip, go, Maven) and the public registry. It evaluates every package version against OPA/Rego policies and a local vulnerability database, and blocks versions that violate policy - before they reach your project.

This guide covers everything you need to get started and make the most of the VS Code extension.

---

## Table of Contents

- [Installation](#installation)
- [Choosing a Connection Mode](#choosing-a-connection-mode)
  - [Local Mode](#local-mode-default)
  - [Hosted Mode](#hosted-mode)
- [Getting Started](#getting-started)
- [Configuring Your Package Manager](#configuring-your-package-manager)
- [Manifest Hover Tooltips](#manifest-hover-tooltips)
- [The Activity Bar](#the-activity-bar)
  - [Proxy Status](#proxy-status)
  - [Recent Decisions](#recent-decisions)
  - [Blocked Packages](#blocked-packages)
- [The Dashboard](#the-dashboard)
- [Settings Reference](#settings-reference)
- [Command Reference](#command-reference)
- [Understanding Decisions](#understanding-decisions)
- [Default Policies](#default-policies)
- [Working with Custom Policies](#working-with-custom-policies)
- [Vulnerability Database](#vulnerability-database)
- [Undoing Package Manager Configuration](#undoing-package-manager-configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **VS Code** 1.85 or later
- **Local mode only:** The `guardian` binary. Build it from the project root:
  ```bash
  go build -o ./bin/guardian ./cmd/guardian     # Linux / macOS
  go build -o ./bin/guardian.exe ./cmd/guardian  # Windows
  ```

### Installing the extension

**From a VSIX file:**

1. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run **Extensions: Install from VSIX…** and select the `.vsix` file.

**From source (development):**

```bash
cd vscode-extension
npm install
npm run compile
```

Then use **Developer: Install Extension from Location…** and point to the `vscode-extension` directory.

---

## Choosing a Connection Mode

The extension supports two ways to connect to the Guardian proxy. Pick the one that fits your setup.

### Local Mode (default)

**Use this when** you want the extension to manage everything for you - it spawns a Guardian process, configures it, and shuts it down when you're done.

Good for:

- Individual developers working on a single machine
- Quick evaluation without any server infrastructure
- Offline / air-gapped environments (with a pre-seeded vulnerability database)

The extension automatically discovers the `guardian` binary by searching:

1. The path set in `dependencyGuardian.binaryPath` (if configured)
2. The workspace root and `bin/` subdirectory
3. The extension's bundled `bin/` directory

It can take awhile to perform the initial vulnerability database sync. Please be patient

### Hosted Mode

**Use this when** a Guardian service is already running - either elsewhere on your machine, on a team server, or in your CI/CD infrastructure.

Good for:

- Teams sharing a single Guardian instance with centralised policies
- Connecting to a service that a platform team operates
- Avoiding duplicate vulnerability database downloads across many developer machines

To switch to hosted mode:

1. Open **Settings** (`Ctrl+,` / `Cmd+,`) and search for **Dependency Guardian**.
2. Set **Connection Mode** to `hosted`.
3. Set **Hosted URL** to the base URL of the service (e.g. `http://guardian.internal:8080`).

Or add to your `settings.json`:

```json
{
  "dependencyGuardian.connectionMode": "hosted",
  "dependencyGuardian.hostedUrl": "http://guardian.internal:8080"
}
```

In hosted mode the **Start Proxy** command validates that the remote service is reachable via its `/health` endpoint and begins polling. No local binary is launched or stopped.

---

## Getting Started

1. **Start the proxy.**
   Open the Command Palette (`Ctrl+Shift+P`) and run:

   > **Dependency Guardian: Start Proxy**

   In local mode the extension spawns the binary and waits for it to become healthy. In hosted mode it connects to the configured URL. Either way, you will see a notification confirming the port or URL.

2. **Configure your package manager** (see [next section](#configuring-your-package-manager)).

3. **Install packages as usual.** Every package version flows through the proxy, which evaluates it against policy. Allowed versions install normally; blocked versions are silently removed from the metadata so the client never sees them.

4. **Watch the Activity Bar** for live decision data.

5. **Stop the proxy** when finished:

   > **Dependency Guardian: Stop Proxy**

   In local mode this terminates the process. In hosted mode it stops polling (the remote service keeps running). The proxy is also stopped automatically when VS Code closes.

---

## Configuring Your Package Manager

After starting the proxy, you need to tell your package manager to route requests through it. The extension provides one-click commands for each ecosystem.

### npm / yarn / pnpm

Run:

> **Dependency Guardian: Configure npm to Use Proxy**

This executes:

```bash
npm config set registry http://127.0.0.1:<port>/npm/
```

A modal dialog shows the exact command and its undo counterpart. You can choose **Apply** (runs it in a terminal) or **Copy Commands** (copies to clipboard for manual use).

### pip / poetry / uv

Run:

> **Dependency Guardian: Configure pip to Use Proxy**

This executes:

```bash
pip config set global.index-url http://127.0.0.1:<port>/pypi/simple/
pip config set global.trusted-host 127.0.0.1
```

### Go modules

Run:

> **Dependency Guardian: Configure Go to Use Proxy**

This executes:

```bash
go env -w GOPROXY=http://127.0.0.1:<port>/go/,direct
go env -w GONOSUMDB=*
```

### Maven / Gradle

Run:

> **Dependency Guardian: Configure Maven to Use Proxy**

This shows instructions to add a mirror to your `~/.m2/settings.xml`:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>guardian</id>
      <mirrorOf>central</mirrorOf>
      <url>http://127.0.0.1:<port>/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

For Gradle, add the proxy URL to your `build.gradle` or `build.gradle.kts` repositories block.

> **Tip:** These configuration commands are global. If you only want to use the proxy for specific projects, set the environment variables in your shell for that session instead of running the commands globally.

---

## Manifest Hover Tooltips

The extension provides **hover tooltips** for dependency declarations in your manifest files. Open any of the following files and hover over a dependency name or version:

- `package.json` (npm)
- `go.mod` (Go)
- `requirements.txt` / `requirements*.txt` (PyPI)
- `pom.xml` (Maven)

The tooltip shows:

- **Package name**, version, and ecosystem
- **Proxy decisions** - how many times the version was allowed or denied, with denial reasons
- **Known vulnerabilities** - sourced from the local OSV database via the `/api/lookup` endpoint. Shows counts by severity (malicious, critical, high, other) and individual OSV advisory IDs
- **Resolved version** - for Maven `pom.xml` files, if a version uses a property reference like `${spring.version}`, the tooltip shows the resolved value alongside the original variable

Tooltip data is cached for 1 minute per package to avoid excessive API calls.

The extension also publishes **diagnostics** (visible in the Problems tab) for any dependencies that have been blocked by the proxy.

---

## The Activity Bar

Click the **shield icon** in the Activity Bar to open the Dependency Guardian sidebar. It contains three tree views.

### Proxy Status

The top view shows:

- **Connection state** - a green dot (🟢 Running, with port number) or a grey circle (⭕ Stopped).
- **Uptime** - how long the proxy has been running.
- **Total Requests** - the number of package metadata requests processed.
- **Allowed / Denied** - aggregate counts with colour-coded icons (green ✓ / red ✗).
- **By Ecosystem** - per-ecosystem breakdown (e.g. npm: 120 total, 3 denied).
- **Vulnerability DB** - if enabled, shows total vulnerability count, affected entries, malicious packages, and per-ecosystem sync status.

Expanding an ecosystem under Vulnerability DB reveals:

- Sync status (synced / syncing / error)
- Vulnerability and affected entry counts
- Last full sync and delta sync timestamps (relative, e.g. "5m ago")
- Error details, if any

### Recent Decisions

A live stream of the last 100 policy decisions. Each entry shows:

- `package@version` with a green ✓ (allowed) or red ✗ (denied) icon
- The ecosystem badge as a description

Click to expand and see:

- Ecosystem
- Timestamp
- Vulnerability count
- Individual denial reasons (if denied)

Use the **refresh button** (⟳) in the view title bar to fetch immediately, or let the auto-poll handle it (default: every 3 seconds).

### Blocked Packages

A filtered view showing **only denied** packages (the most recent 50). Each entry displays the denial reasons in the description. Expand for the same detail fields as Recent Decisions.

This view is useful when you want to quickly answer: _"What's being blocked right now, and why?"_

---

## The Dashboard

For a richer overview, open the full-page dashboard:

> **Dependency Guardian: Show Dashboard**

The dashboard is a webview panel that auto-refreshes every 5 seconds. It displays:

1. **Stats cards** - Total Requests, Allowed, Denied, Uptime.
2. **Ecosystem cards** - per-ecosystem request and denial counts.
3. **Vulnerability Database** - global vulnerability stats and per-ecosystem sync details.
4. **Recent Decisions table** - the last 50 decisions with columns for Time, Ecosystem, Package, Version, Status (allowed/denied badge), and Reasons.

The dashboard adapts to your VS Code theme (light or dark).

> **When to use the dashboard vs. the sidebar:**
>
> - Use the **sidebar** for a quick glance while coding - it's always visible without switching tabs.
> - Use the **dashboard** during an audit, a dependency upgrade session, or when presenting findings to your team - it provides more detail in a layout designed for reading.

---

## Settings Reference

Open VS Code Settings (`Ctrl+,`) and search for "Dependency Guardian" to see all options.

| Setting             | Default         | Applies to | Description                                                                                               |
| ------------------- | --------------- | ---------- | --------------------------------------------------------------------------------------------------------- |
| `connectionMode`    | `local`         | Both       | `local` - manage a local binary; `hosted` - connect to an existing service.                               |
| `hostedUrl`         | _(empty)_       | Hosted     | Base URL of the running Guardian service (e.g. `http://guardian.internal:8080`).                          |
| `binaryPath`        | _(auto-detect)_ | Local      | Absolute path to the `guardian` binary. Leave empty to auto-discover.                                     |
| `listenPort`        | `8080`          | Local      | Port the local proxy listens on.                                                                          |
| `configDirectory`   | _(empty)_       | Local      | Path to a `config.yaml` file. Leave empty for built-in defaults.                                          |
| `policiesDirectory` | _(empty)_       | Local      | Path to a directory of `.rego` policy files. Leave empty for bundled defaults.                            |
| `autoStart`         | `false`         | Both       | Automatically start the proxy (or connect, in hosted mode) when VS Code opens.                            |
| `autoStopOnClose`   | `true`          | Local      | Stop the local guardian process when VS Code closes. Set to `false` to keep it running in the background. |
| `vulndbEnabled`     | `true`          | Local      | Enable the local SQLite vulnerability database.                                                           |
| `refreshInterval`   | `3`             | Both       | Seconds between polls for new decision/stats data.                                                        |

All settings are prefixed with `dependencyGuardian.` in `settings.json`. For example:

```json
{
  "dependencyGuardian.connectionMode": "local",
  "dependencyGuardian.listenPort": 9090,
  "dependencyGuardian.autoStart": true,
  "dependencyGuardian.refreshInterval": 5
}
```

---

## Command Reference

All commands are available from the Command Palette (`Ctrl+Shift+P`).

| Command                          | What it does                                                                                                |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Start Proxy**                  | Launches the local binary (local mode) or validates the remote connection (hosted mode) and begins polling. |
| **Stop Proxy**                   | Stops the local process (local mode) or disconnects polling (hosted mode). Clears the decision views.       |
| **Show Dashboard**               | Opens the full-page dashboard webview. Requires the proxy to be running.                                    |
| **Configure npm to Use Proxy**   | Shows a dialog to set `npm config set registry` to route through the proxy.                                 |
| **Configure pip to Use Proxy**   | Shows a dialog to set `pip config set global.index-url` and `trusted-host`.                                 |
| **Configure Go to Use Proxy**    | Shows a dialog to set `GOPROXY` and `GONOSUMDB` environment variables.                                      |
| **Configure Maven to Use Proxy** | Shows instructions to add a mirror in `~/.m2/settings.xml`.                                                 |
| **Refresh Decisions**            | Immediately polls the proxy for fresh data (also available as the ⟳ icon on the tree views).                |
| **Clear Decision View**          | Clears the Recent Decisions and Blocked Packages views without stopping the proxy.                          |

---

## Understanding Decisions

Every time a package manager asks for metadata (e.g. `npm install lodash`), the proxy:

1. Fetches the full metadata from the upstream registry.
2. Evaluates **each version** against the loaded OPA/Rego policies.
3. Records a **decision** for each version - allowed or denied.
4. Returns modified metadata to the client with denied versions removed.

A single `npm install lodash` can produce dozens of decisions (one per version in the registry response). The extension shows the most recent 200 decisions and the most recent 50 blocked packages.

> **Note:** For Maven, the proxy intercepts `maven-metadata.xml` requests and filters versions. It also inspects POM files to evaluate transitive dependencies, resolving property references (like `${spring.version}`) through parent POM chains.

### What "denied" means in practice

When a version is denied, it is **removed from the metadata**. The package manager never sees it. This means:

- If all versions of a package are denied, the install fails with a "package not found"-style error from the package manager.
- If only some versions are denied, the package manager picks the best remaining version that satisfies the semver constraint.

### Denial reasons

Each denial carries one or more **reasons** - human-readable strings produced by the Rego policy. Common reasons include:

- `package X@Y is flagged as malicious (advisory GHSA-…)`
- `package X@Y has critical vulnerability CVE-2024-…: description`
- `package X@Y is less than 7 days old`
- `package X@Y is yanked`

Expand a decision in the Recent Decisions or Blocked Packages view to see its reasons.

---

## Default Policies

Out of the box, the proxy enforces these rules:

| Rule                         | What it blocks                                                   | Why                                                                             |
| ---------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **Malicious packages**       | Any version flagged `is_malicious` by the vulnerability database | Protects against typosquatting, maintainer account takeovers, and known malware |
| **Critical vulnerabilities** | Versions with `severity == "critical"`                           | Prevents installing the most dangerous known vulnerabilities                    |
| **High vulnerabilities**     | Versions with `severity == "high"`                               | Catches serious (but not critical) vulnerabilities                              |
| **Minimum age (7 days)**     | Versions published less than 7 days ago                          | Gives the community time to discover issues in new releases                     |
| **Yanked versions**          | Versions marked as yanked or unpublished                         | Respects upstream maintainer decisions to retract versions                      |

These policies are defined in `.rego` files in the policies directory. You can edit, remove, or add policies as needed.

---

## Working with Custom Policies

If you need rules beyond the defaults, create `.rego` files in a directory and point the extension at them.

### Setup

1. Create a directory for your policies (e.g. `my-policies/`).
2. Set **Policies Directory** in settings:
   ```json
   { "dependencyGuardian.policiesDirectory": "./my-policies" }
   ```
3. Add `.rego` files to that directory. Every file must use the `package guardian` namespace and add strings to the `deny` set.

### Example: Block deprecated npm packages

```rego
package guardian

import rego.v1

deny contains msg if {
    input.package.ecosystem == "npm"
    input.package.deprecated == true
    msg := sprintf("%s@%s is deprecated", [input.package.name, input.package.version])
}
```

### Example: Extend the minimum age to 30 days

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

### Example: Allowlist specific packages

```rego
package guardian

import rego.v1

allowlist := {"lodash", "express", "react"}

deny contains msg if {
    not allowlist[input.package.name]
    # ... your deny rules
}
```

### Live reload

After editing policy files, you can reload them without restarting the proxy:

```bash
curl -X POST http://localhost:8080/policy/reload
```

If an `admin_token` is configured in your `config.yaml`, include it:

```bash
curl -X POST -H "Authorization: Bearer <token>" http://localhost:8080/policy/reload
```

---

## Vulnerability Database

When `vulndbEnabled` is `true` (the default), the proxy maintains a local SQLite database of known vulnerabilities sourced from [OSV.dev](https://osv.dev/). This data feeds into the policy engine - every version evaluation includes any known vulnerabilities for that package.

### How sync works

- **Full sync:** Downloads the complete vulnerability archive for each configured ecosystem. Runs on first start and periodically (default: every 24 hours).
- **Delta sync:** Downloads only changes since the last sync. Runs frequently (default: every 15 minutes).
- **Metrics recalculation:** Updates aggregate counts (total vulnerabilities, affected entries). Runs hourly.

### Monitoring sync status

The **Proxy Status** view in the sidebar shows sync state per ecosystem:

- ✓ **synced** - up to date
- ⟳ **syncing** - download/import in progress
- ✗ **error** - last sync failed (expand for details)

The **Dashboard** shows the same information with timestamps for the last full and delta sync.

### Hosted mode note

In hosted mode the vulnerability database runs on the remote server. The extension displays its status from the API but does not manage the database locally.

---

## Undoing Package Manager Configuration

When you no longer want to route through the proxy, restore the defaults:

**npm:**

```bash
npm config delete registry
```

**pip:**

```bash
pip config unset global.index-url
pip config unset global.trusted-host
```

**Go:**

```bash
go env -w GOPROXY=https://proxy.golang.org,direct
go env -u GONOSUMDB
```

**Maven:**

Remove the `<mirror>` block from your `~/.m2/settings.xml`.

---

## Troubleshooting

### "Cannot find guardian binary"

The extension could not locate the `guardian` executable. Solutions:

1. Build it: `go build -o ./bin/guardian.exe ./cmd/guardian`
2. Set `dependencyGuardian.binaryPath` to the full path of your binary.
3. If using the VSIX package, ensure it was built with a bundled binary for your platform.

### "Proxy did not become healthy within 10000ms"

The binary started but didn't respond to health checks. Possible causes:

- **Port conflict:** Another process is using the configured port. Change `dependencyGuardian.listenPort` to an unused port.
- **Config error:** Open the **Dependency Guardian** output channel (View -> Output -> select "Dependency Guardian" from the dropdown) to see the binary's logs.
- **Firewall:** On some systems, firewall rules may block localhost connections. Ensure `127.0.0.1:<port>` is allowed.

### Decisions are not updating

- Check that the proxy is running (Proxy Status should show 🟢 Running).
- Try **Refresh Decisions** from the Command Palette.
- Lower the `refreshInterval` if you need faster updates.
- Open the **Dependency Guardian** output channel for errors.

### A package I need is being blocked

Expand the entry in **Blocked Packages** to see why. Common fixes:

- **Minimum age:** Wait for the package to age past the threshold, or lower the minimum age in your policy.
- **Vulnerability:** Check if a newer version exists that resolves the vulnerability.
- **Allowlist:** Add the package to a policy allowlist if the risk is accepted (see [Working with Custom Policies](#working-with-custom-policies)).

### All versions of a package are blocked

This usually means every published version has an active vulnerability or the package is flagged as malicious. Check the OSV database at [osv.dev](https://osv.dev/) for details. If you still need the package, add an allowlist rule to your policy.

### Hosted mode: "Failed to start proxy"

- Verify the URL in `dependencyGuardian.hostedUrl` is correct and includes the scheme (`http://` or `https://`).
- Confirm the remote service is running: `curl <hostedUrl>/health` should return `{"status":"ok"}`.
- Check for network/firewall issues between your machine and the service.

### Output channel

The **Dependency Guardian** output channel (View -> Output -> "Dependency Guardian") shows all proxy process logs. This is the first place to look when something unexpected happens.
