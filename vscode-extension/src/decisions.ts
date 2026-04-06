import * as vscode from "vscode";

interface DecisionEntry {
  id: number;
  timestamp: string;
  ecosystem: string;
  package: string;
  version: string;
  allowed: boolean;
  reasons?: string[];
  vulnerabilities: number;
}

export class DecisionTreeProvider implements vscode.TreeDataProvider<DecisionItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    DecisionItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: DecisionEntry[] = [];
  private lastSeenId = 0;

  update(entries: DecisionEntry[]) {
    if (entries.length > 0 && entries[0].id !== this.lastSeenId) {
      this.entries = entries;
      this.lastSeenId = entries[0].id;
      this._onDidChangeTreeData.fire(undefined);
    }
  }

  clear() {
    this.entries = [];
    this.lastSeenId = 0;
    this._onDidChangeTreeData.fire(undefined);
  }

  refresh() {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: DecisionItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: DecisionItem): DecisionItem[] {
    if (element && element.entry) {
      // Show details for a single decision.
      const items: DecisionItem[] = [];
      const e = element.entry;
      items.push(
        new DecisionItem(
          `Ecosystem: ${e.ecosystem}`,
          vscode.TreeItemCollapsibleState.None,
        ),
      );
      items.push(
        new DecisionItem(
          `Time: ${new Date(e.timestamp).toLocaleTimeString()}`,
          vscode.TreeItemCollapsibleState.None,
        ),
      );
      if (e.vulnerabilities > 0) {
        items.push(
          new DecisionItem(
            `Vulnerabilities: ${e.vulnerabilities}`,
            vscode.TreeItemCollapsibleState.None,
          ),
        );
      }
      if (e.reasons && e.reasons.length > 0) {
        for (const reason of e.reasons) {
          items.push(
            new DecisionItem(
              `Reason: ${reason}`,
              vscode.TreeItemCollapsibleState.None,
            ),
          );
        }
      }
      return items;
    }

    if (this.entries.length === 0) {
      return [
        new DecisionItem(
          "No decisions yet. Install packages to see activity.",
          vscode.TreeItemCollapsibleState.None,
        ),
      ];
    }

    return this.entries.slice(0, 100).map((e) => {
      const icon = e.allowed ? "$(pass)" : "$(error)";
      const label = `${icon} ${e.package}@${e.version}`;
      const item = new DecisionItem(
        label,
        vscode.TreeItemCollapsibleState.Collapsed,
        e,
      );
      item.description = e.ecosystem;
      item.tooltip = e.allowed
        ? `Allowed: ${e.package}@${e.version}`
        : `Blocked: ${e.package}@${e.version} - ${(e.reasons ?? []).join(", ")}`;
      item.iconPath = e.allowed
        ? new vscode.ThemeIcon(
            "pass",
            new vscode.ThemeColor("testing.iconPassed"),
          )
        : new vscode.ThemeIcon(
            "error",
            new vscode.ThemeColor("testing.iconFailed"),
          );
      return item;
    });
  }
}

class DecisionItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly entry?: DecisionEntry,
  ) {
    super(label, collapsibleState);
  }
}
