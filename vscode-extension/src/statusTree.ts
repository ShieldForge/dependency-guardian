import * as vscode from "vscode";
import { ProxyManager } from "./proxy";

interface ProxyStats {
  total_requests: number;
  total_allowed: number;
  total_denied: number;
  by_ecosystem: Record<string, number>;
  denied_by_ecosystem: Record<string, number>;
  uptime: string;
}

interface VulnDBEcosystem {
  ecosystem: string;
  status: string;
  last_full_sync: string | null;
  last_delta_sync: string | null;
  last_error?: string;
  total_vulnerabilities: number;
  total_affected_entries: number;
}

interface VulnDBStatus {
  global: {
    total_vulnerabilities: number;
    total_affected: number;
    total_malicious: number;
    ecosystems_tracked: number;
  };
  ecosystems: VulnDBEcosystem[];
}

export class StatusTreeProvider implements vscode.TreeDataProvider<StatusItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    StatusItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private stats: ProxyStats | undefined;
  private vulndb: VulnDBStatus | undefined;
  private proxy: ProxyManager;

  constructor(proxy: ProxyManager) {
    this.proxy = proxy;
  }

  updateStats(stats: ProxyStats) {
    this.stats = stats;
    this._onDidChangeTreeData.fire(undefined);
  }

  updateVulnDB(vulndb: VulnDBStatus) {
    this.vulndb = vulndb;
    this._onDidChangeTreeData.fire(undefined);
  }

  refresh() {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: StatusItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: StatusItem): StatusItem[] {
    if (element && element.children) {
      return element.children;
    }
    if (element) {
      return [];
    }

    const items: StatusItem[] = [];

    // Proxy status.
    if (this.proxy.isRunning) {
      const running = new StatusItem("Proxy: Running");
      running.iconPath = new vscode.ThemeIcon(
        "circle-filled",
        new vscode.ThemeColor("testing.iconPassed"),
      );
      running.description = `port ${this.proxy.port}`;
      items.push(running);
    } else {
      const stopped = new StatusItem("Proxy: Stopped");
      stopped.iconPath = new vscode.ThemeIcon(
        "circle-outline",
        new vscode.ThemeColor("testing.iconSkipped"),
      );
      stopped.description = 'Click "Start Proxy" to begin';
      items.push(stopped);
      return items;
    }

    if (!this.stats) {
      items.push(new StatusItem("Waiting for data..."));
      return items;
    }

    // Uptime.
    const uptime = new StatusItem(`Uptime: ${this.stats.uptime}`);
    uptime.iconPath = new vscode.ThemeIcon("clock");
    items.push(uptime);

    // Total stats.
    const total = new StatusItem(
      `Total Requests: ${this.stats.total_requests}`,
    );
    total.iconPath = new vscode.ThemeIcon("graph");
    items.push(total);

    const allowed = new StatusItem(`Allowed: ${this.stats.total_allowed}`);
    allowed.iconPath = new vscode.ThemeIcon(
      "pass",
      new vscode.ThemeColor("testing.iconPassed"),
    );
    items.push(allowed);

    const denied = new StatusItem(`Denied: ${this.stats.total_denied}`);
    denied.iconPath = new vscode.ThemeIcon(
      "error",
      new vscode.ThemeColor("testing.iconFailed"),
    );
    items.push(denied);

    // Per-ecosystem breakdown.
    if (
      this.stats.by_ecosystem &&
      Object.keys(this.stats.by_ecosystem).length > 0
    ) {
      items.push(new StatusItem("─── By Ecosystem ───"));
      for (const [eco, count] of Object.entries(this.stats.by_ecosystem)) {
        const deniedCount = this.stats.denied_by_ecosystem?.[eco] ?? 0;
        const ecoItem = new StatusItem(
          `${eco}: ${count} total, ${deniedCount} denied`,
        );
        ecoItem.iconPath = new vscode.ThemeIcon("package");
        items.push(ecoItem);
      }
    }

    // Vulnerability database section.
    if (this.vulndb) {
      items.push(new StatusItem("─── Vulnerability DB ───"));

      const g = this.vulndb.global;
      const vulns = new StatusItem(
        `Vulnerabilities: ${g.total_vulnerabilities.toLocaleString()}`,
      );
      vulns.iconPath = new vscode.ThemeIcon("bug");
      items.push(vulns);

      const affected = new StatusItem(
        `Affected Entries: ${g.total_affected.toLocaleString()}`,
      );
      affected.iconPath = new vscode.ThemeIcon("list-tree");
      items.push(affected);

      if (g.total_malicious > 0) {
        const mal = new StatusItem(
          `Malicious Packages: ${g.total_malicious.toLocaleString()}`,
        );
        mal.iconPath = new vscode.ThemeIcon(
          "warning",
          new vscode.ThemeColor("testing.iconFailed"),
        );
        items.push(mal);
      }

      for (const eco of this.vulndb.ecosystems) {
        const statusIcon =
          eco.status === "synced"
            ? new vscode.ThemeIcon(
                "check",
                new vscode.ThemeColor("testing.iconPassed"),
              )
            : eco.status === "syncing"
              ? new vscode.ThemeIcon("sync~spin")
              : eco.status === "error"
                ? new vscode.ThemeIcon(
                    "error",
                    new vscode.ThemeColor("testing.iconFailed"),
                  )
                : new vscode.ThemeIcon("circle-outline");

        const children: StatusItem[] = [];
        children.push(new StatusItem(`Status: ${eco.status}`));
        children.push(
          new StatusItem(
            `Vulnerabilities: ${eco.total_vulnerabilities.toLocaleString()}`,
          ),
        );
        children.push(
          new StatusItem(
            `Affected entries: ${eco.total_affected_entries.toLocaleString()}`,
          ),
        );
        if (eco.last_full_sync) {
          children.push(
            new StatusItem(`Last full sync: ${formatTime(eco.last_full_sync)}`),
          );
        }
        if (eco.last_delta_sync) {
          children.push(
            new StatusItem(
              `Last delta sync: ${formatTime(eco.last_delta_sync)}`,
            ),
          );
        }
        if (eco.last_error) {
          const errItem = new StatusItem(`Error: ${eco.last_error}`);
          errItem.iconPath = new vscode.ThemeIcon(
            "error",
            new vscode.ThemeColor("testing.iconFailed"),
          );
          children.push(errItem);
        }

        const ecoItem = new StatusItem(
          `${eco.ecosystem}`,
          vscode.TreeItemCollapsibleState.Collapsed,
          children,
        );
        ecoItem.iconPath = statusIcon;
        ecoItem.description = `${eco.total_vulnerabilities.toLocaleString()} vulns`;
        items.push(ecoItem);
      }
    }

    return items;
  }
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) {
    return "just now";
  }
  if (diffMin < 60) {
    return `${diffMin}m ago`;
  }
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) {
    return `${diffHrs}h ago`;
  }
  return d.toLocaleDateString();
}

class StatusItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState = vscode
      .TreeItemCollapsibleState.None,
    public readonly children?: StatusItem[],
  ) {
    super(label, collapsibleState);
  }
}
