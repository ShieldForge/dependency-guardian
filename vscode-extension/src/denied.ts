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

export class DeniedTreeProvider implements vscode.TreeDataProvider<DeniedItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    DeniedItem | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: DecisionEntry[] = [];

  update(denied: DecisionEntry[]) {
    this.entries = denied;
    this._onDidChangeTreeData.fire(undefined);
  }

  clear() {
    this.entries = [];
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: DeniedItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: DeniedItem): DeniedItem[] {
    if (element) {
      const items: DeniedItem[] = [];
      const e = element.entry!;
      items.push(
        new DeniedItem(
          `Ecosystem: ${e.ecosystem}`,
          vscode.TreeItemCollapsibleState.None,
        ),
      );
      items.push(
        new DeniedItem(
          `Time: ${new Date(e.timestamp).toLocaleTimeString()}`,
          vscode.TreeItemCollapsibleState.None,
        ),
      );
      if (e.vulnerabilities > 0) {
        items.push(
          new DeniedItem(
            `Vulnerabilities: ${e.vulnerabilities}`,
            vscode.TreeItemCollapsibleState.None,
          ),
        );
      }
      for (const reason of e.reasons ?? []) {
        items.push(
          new DeniedItem(
            `Reason: ${reason}`,
            vscode.TreeItemCollapsibleState.None,
          ),
        );
      }
      return items;
    }

    if (this.entries.length === 0) {
      return [
        new DeniedItem(
          "No blocked packages.",
          vscode.TreeItemCollapsibleState.None,
        ),
      ];
    }

    return this.entries.slice(0, 50).map((e) => {
      const item = new DeniedItem(
        `${e.package}@${e.version}`,
        vscode.TreeItemCollapsibleState.Collapsed,
        e,
      );
      item.description = (e.reasons ?? []).join(", ");
      item.iconPath = new vscode.ThemeIcon(
        "error",
        new vscode.ThemeColor("testing.iconFailed"),
      );
      item.tooltip = `Blocked: ${e.package}@${e.version}\n${(e.reasons ?? []).join("\n")}`;
      return item;
    });
  }
}

class DeniedItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly entry?: DecisionEntry,
  ) {
    super(label, collapsibleState);
  }
}
