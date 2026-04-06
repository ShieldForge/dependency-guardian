import * as vscode from "vscode";

export class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private readonly port: number;
  private disposables: vscode.Disposable[] = [];
  private refreshTimer: ReturnType<typeof setInterval> | undefined;

  private constructor(panel: vscode.WebviewPanel, port: number) {
    this.panel = panel;
    this.port = port;

    this.panel.webview.html = this.getHtmlContent();
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

    // Refresh the webview periodically.
    this.refreshTimer = setInterval(() => this.sendUpdate(), 5000);
    this.sendUpdate();
  }

  public static createOrShow(extensionUri: vscode.Uri, port: number) {
    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.panel.reveal(vscode.ViewColumn.One);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      "dependencyGuardianDashboard",
      "Dependency Guardian Dashboard",
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true },
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel, port);
  }

  private async sendUpdate() {
    try {
      const [statsRes, decisionsRes, vulndbRes] = await Promise.all([
        fetch(`http://127.0.0.1:${this.port}/api/stats`),
        fetch(`http://127.0.0.1:${this.port}/api/decisions?limit=50`),
        fetch(`http://127.0.0.1:${this.port}/api/vulndb`).catch(() => null),
      ]);
      const stats = statsRes.ok ? await statsRes.json() : null;
      const decisions = decisionsRes.ok ? await decisionsRes.json() : [];
      const vulndb = vulndbRes && vulndbRes.ok ? await vulndbRes.json() : null;
      this.panel.webview.postMessage({
        type: "update",
        stats,
        decisions,
        vulndb,
      });
    } catch {
      // transient
    }
  }

  private dispose() {
    DashboardPanel.currentPanel = undefined;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }
    this.panel.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
  }

  private getHtmlContent(): string {
    return /*html*/ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Guardian Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
            padding: 20px;
            margin: 0;
        }
        h1 { margin-top: 0; font-size: 1.5em; }
        h2 { font-size: 1.2em; margin-top: 24px; border-bottom: 1px solid var(--vscode-widget-border); padding-bottom: 4px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        .stat-card {
            background: var(--vscode-editorWidget-background);
            border: 1px solid var(--vscode-widget-border);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            display: block;
        }
        .stat-label {
            font-size: 0.85em;
            opacity: 0.8;
            margin-top: 4px;
        }
        .stat-value.allowed { color: var(--vscode-testing-iconPassed); }
        .stat-value.denied { color: var(--vscode-testing-iconFailed); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 0.9em;
        }
        th, td {
            text-align: left;
            padding: 6px 10px;
            border-bottom: 1px solid var(--vscode-widget-border);
        }
        th {
            background: var(--vscode-editorWidget-background);
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
            font-weight: 600;
        }
        .badge.allowed { background: var(--vscode-testing-iconPassed); color: #fff; }
        .badge.denied { background: var(--vscode-testing-iconFailed); color: #fff; }
        .eco-badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
        }
        .empty { opacity: 0.6; font-style: italic; }
    </style>
</head>
<body>
    <h1>🛡️ Dependency Guardian Dashboard</h1>

    <div class="stats-grid" id="stats">
        <div class="stat-card"><span class="stat-value" id="totalRequests">-</span><div class="stat-label">Total Requests</div></div>
        <div class="stat-card"><span class="stat-value allowed" id="totalAllowed">-</span><div class="stat-label">Allowed</div></div>
        <div class="stat-card"><span class="stat-value denied" id="totalDenied">-</span><div class="stat-label">Denied</div></div>
        <div class="stat-card"><span class="stat-value" id="uptime">-</span><div class="stat-label">Uptime</div></div>
    </div>

    <h2>By Ecosystem</h2>
    <div class="stats-grid" id="ecosystemStats"></div>

    <h2>Vulnerability Database</h2>
    <div class="stats-grid" id="vulndbStats"></div>
    <div id="vulndbEcosystems" style="margin-top: 12px;"></div>

    <h2>Recent Decisions</h2>
    <table>
        <thead>
            <tr><th>Time</th><th>Ecosystem</th><th>Package</th><th>Version</th><th>Status</th><th>Reasons</th></tr>
        </thead>
        <tbody id="decisionsBody">
            <tr><td colspan="6" class="empty">Waiting for data…</td></tr>
        </tbody>
    </table>

    <script>
        const vscode = acquireVsCodeApi();

        window.addEventListener('message', event => {
            const msg = event.data;
            if (msg.type === 'update') {
                updateStats(msg.stats);
                updateDecisions(msg.decisions);
                updateVulnDB(msg.vulndb);
            }
        });

        function updateStats(stats) {
            if (!stats) return;
            document.getElementById('totalRequests').textContent = stats.total_requests ?? 0;
            document.getElementById('totalAllowed').textContent = stats.total_allowed ?? 0;
            document.getElementById('totalDenied').textContent = stats.total_denied ?? 0;
            document.getElementById('uptime').textContent = stats.uptime ?? '-';

            const ecoDiv = document.getElementById('ecosystemStats');
            ecoDiv.innerHTML = '';
            const ecos = stats.by_ecosystem || {};
            const deniedEcos = stats.denied_by_ecosystem || {};
            for (const [eco, count] of Object.entries(ecos)) {
                const denied = deniedEcos[eco] || 0;
                ecoDiv.innerHTML += '<div class="stat-card">'
                    + '<span class="stat-value">' + count + '</span>'
                    + '<div class="stat-label">' + eco + ' (' + denied + ' denied)</div>'
                    + '</div>';
            }
        }

        function updateDecisions(decisions) {
            const tbody = document.getElementById('decisionsBody');
            if (!decisions || decisions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty">No decisions recorded yet.</td></tr>';
                return;
            }
            tbody.innerHTML = decisions.map(d => {
                const time = new Date(d.timestamp).toLocaleTimeString();
                const status = d.allowed
                    ? '<span class="badge allowed">Allowed</span>'
                    : '<span class="badge denied">Denied</span>';
                const reasons = (d.reasons || []).join(', ') || '-';
                return '<tr>'
                    + '<td>' + time + '</td>'
                    + '<td><span class="eco-badge">' + d.ecosystem + '</span></td>'
                    + '<td>' + d.package + '</td>'
                    + '<td>' + d.version + '</td>'
                    + '<td>' + status + '</td>'
                    + '<td>' + reasons + '</td>'
                    + '</tr>';
            }).join('');
        }

        function updateVulnDB(vulndb) {
            const statsDiv = document.getElementById('vulndbStats');
            const ecoDiv = document.getElementById('vulndbEcosystems');
            if (!vulndb) {
                statsDiv.innerHTML = '<div class="stat-card"><span class="stat-value">-</span><div class="stat-label">Not available</div></div>';
                ecoDiv.innerHTML = '';
                return;
            }
            const g = vulndb.global || {};
            statsDiv.innerHTML = ''
                + '<div class="stat-card"><span class="stat-value">' + (g.total_vulnerabilities || 0).toLocaleString() + '</span><div class="stat-label">Vulnerabilities</div></div>'
                + '<div class="stat-card"><span class="stat-value">' + (g.total_affected || 0).toLocaleString() + '</span><div class="stat-label">Affected Entries</div></div>'
                + '<div class="stat-card"><span class="stat-value denied">' + (g.total_malicious || 0).toLocaleString() + '</span><div class="stat-label">Malicious Packages</div></div>'
                + '<div class="stat-card"><span class="stat-value">' + (g.ecosystems_tracked || 0) + '</span><div class="stat-label">Ecosystems Tracked</div></div>';

            const ecosystems = vulndb.ecosystems || [];
            if (ecosystems.length === 0) {
                ecoDiv.innerHTML = '<p class="empty">No ecosystem sync data available.</p>';
                return;
            }
            let html = '<table><thead><tr><th>Ecosystem</th><th>Status</th><th>Vulnerabilities</th><th>Affected</th><th>Last Full Sync</th><th>Last Delta</th></tr></thead><tbody>';
            for (const eco of ecosystems) {
                const statusBadge = eco.status === 'synced'
                    ? '<span class="badge allowed">' + eco.status + '</span>'
                    : eco.status === 'syncing'
                        ? '<span class="eco-badge">' + eco.status + '</span>'
                        : eco.status === 'error'
                            ? '<span class="badge denied">' + eco.status + '</span>'
                            : '<span class="eco-badge">' + eco.status + '</span>';
                const fullSync = eco.last_full_sync ? formatRelative(eco.last_full_sync) : '-';
                const deltaSync = eco.last_delta_sync ? formatRelative(eco.last_delta_sync) : '-';
                html += '<tr>'
                    + '<td><strong>' + eco.ecosystem + '</strong></td>'
                    + '<td>' + statusBadge + '</td>'
                    + '<td>' + eco.total_vulnerabilities.toLocaleString() + '</td>'
                    + '<td>' + eco.total_affected_entries.toLocaleString() + '</td>'
                    + '<td>' + fullSync + '</td>'
                    + '<td>' + deltaSync + '</td>'
                    + '</tr>';
                if (eco.last_error) {
                    html += '<tr><td colspan="6" style="color: var(--vscode-testing-iconFailed); font-size: 0.85em;">⚠ ' + eco.last_error + '</td></tr>';
                }
            }
            html += '</tbody></table>';
            ecoDiv.innerHTML = html;
        }

        function formatRelative(iso) {
            const d = new Date(iso);
            const diffMs = Date.now() - d.getTime();
            const diffMin = Math.floor(diffMs / 60000);
            if (diffMin < 1) return 'just now';
            if (diffMin < 60) return diffMin + 'm ago';
            const diffHrs = Math.floor(diffMin / 60);
            if (diffHrs < 24) return diffHrs + 'h ago';
            return d.toLocaleDateString();
        }
    </script>
</body>
</html>`;
  }
}
