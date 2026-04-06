import { describe, it, expect } from "vitest";
import { StatusTreeProvider } from "./statusTree";
import { TreeItemCollapsibleState } from "vscode";

// Minimal ProxyManager-like object for testing.
function makeProxy(overrides: { isRunning?: boolean; port?: number } = {}) {
  return {
    isRunning: overrides.isRunning ?? false,
    port: overrides.port ?? 8080,
  } as any;
}

function makeStats(
  overrides: Partial<{
    total_requests: number;
    total_allowed: number;
    total_denied: number;
    by_ecosystem: Record<string, number>;
    denied_by_ecosystem: Record<string, number>;
    uptime: string;
  }> = {},
) {
  return {
    total_requests: 100,
    total_allowed: 90,
    total_denied: 10,
    by_ecosystem: { npm: 60, pypi: 40 },
    denied_by_ecosystem: { npm: 5, pypi: 5 },
    uptime: "1h 30m",
    ...overrides,
  };
}

function makeVulnDB() {
  return {
    global: {
      total_vulnerabilities: 50000,
      total_affected: 120000,
      total_malicious: 500,
      ecosystems_tracked: 4,
    },
    ecosystems: [
      {
        ecosystem: "npm",
        status: "synced",
        last_full_sync: new Date().toISOString(),
        last_delta_sync: new Date().toISOString(),
        total_vulnerabilities: 20000,
        total_affected_entries: 50000,
      },
      {
        ecosystem: "pypi",
        status: "syncing",
        last_full_sync: null,
        last_delta_sync: null,
        total_vulnerabilities: 10000,
        total_affected_entries: 30000,
      },
    ],
  };
}

describe("StatusTreeProvider", () => {
  it("shows stopped status when proxy is not running", () => {
    const provider = new StatusTreeProvider(makeProxy({ isRunning: false }));
    const items = provider.getChildren();
    expect(items).toHaveLength(1);
    expect(items[0].label).toContain("Stopped");
  });

  it("shows running status when proxy is running", () => {
    const proxy = makeProxy({ isRunning: true, port: 8080 });
    const provider = new StatusTreeProvider(proxy);
    const items = provider.getChildren();
    expect(items[0].label).toContain("Running");
    expect(items[0].description).toContain("8080");
  });

  it('shows "Waiting for data" when running but no stats', () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    const items = provider.getChildren();
    expect(items.length).toBeGreaterThanOrEqual(2);
    expect(items[1].label).toContain("Waiting for data");
  });

  it("shows stats after updateStats", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());

    const items = provider.getChildren();
    const labels = items.map((i) => i.label as string);

    expect(labels.some((l) => l.includes("Uptime"))).toBe(true);
    expect(labels.some((l) => l.includes("Total Requests: 100"))).toBe(true);
    expect(labels.some((l) => l.includes("Allowed: 90"))).toBe(true);
    expect(labels.some((l) => l.includes("Denied: 10"))).toBe(true);
  });

  it("shows per-ecosystem breakdown", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());

    const items = provider.getChildren();
    const labels = items.map((i) => i.label as string);

    expect(labels.some((l) => l.includes("npm") && l.includes("60"))).toBe(
      true,
    );
    expect(labels.some((l) => l.includes("pypi") && l.includes("40"))).toBe(
      true,
    );
  });

  it("shows vulnerability database section", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());
    provider.updateVulnDB(makeVulnDB());

    const items = provider.getChildren();
    const labels = items.map((i) => i.label as string);

    expect(labels.some((l) => l.includes("Vulnerability DB"))).toBe(true);
    expect(labels.some((l) => l.includes("Vulnerabilities"))).toBe(true);
    expect(labels.some((l) => l.includes("Affected Entries"))).toBe(true);
    expect(labels.some((l) => l.includes("Malicious Packages"))).toBe(true);
  });

  it("shows ecosystem details as collapsible items", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());
    provider.updateVulnDB(makeVulnDB());

    const items = provider.getChildren();
    const ecoItems = items.filter(
      (i) => i.collapsibleState === TreeItemCollapsibleState.Collapsed,
    );
    expect(ecoItems.length).toBeGreaterThanOrEqual(2);
  });

  it("ecosystem children contain status and vulnerability counts", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());
    provider.updateVulnDB(makeVulnDB());

    const items = provider.getChildren();
    const ecoItem = items.find(
      (i) =>
        i.collapsibleState === TreeItemCollapsibleState.Collapsed &&
        (i.label as string) === "npm",
    );
    expect(ecoItem).toBeDefined();

    const children = provider.getChildren(ecoItem!);
    const childLabels = children.map((c) => c.label as string);
    expect(childLabels.some((l) => l.includes("Status: synced"))).toBe(true);
    expect(childLabels.some((l) => l.includes("Vulnerabilities"))).toBe(true);
  });

  it("refresh fires change event", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    let fired = false;
    provider.onDidChangeTreeData(() => {
      fired = true;
    });
    provider.refresh();
    expect(fired).toBe(true);
  });

  it("getTreeItem returns the element", () => {
    const proxy = makeProxy({ isRunning: false });
    const provider = new StatusTreeProvider(proxy);
    const items = provider.getChildren();
    expect(provider.getTreeItem(items[0])).toBe(items[0]);
  });

  it("hides malicious count when zero", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());
    const vulndb = makeVulnDB();
    vulndb.global.total_malicious = 0;
    provider.updateVulnDB(vulndb);

    const items = provider.getChildren();
    const labels = items.map((i) => i.label as string);
    expect(labels.every((l) => !l.includes("Malicious"))).toBe(true);
  });

  it("shows error for ecosystem with error status", () => {
    const proxy = makeProxy({ isRunning: true });
    const provider = new StatusTreeProvider(proxy);
    provider.updateStats(makeStats());
    const vulndb = makeVulnDB();
    vulndb.ecosystems.push({
      ecosystem: "go",
      status: "error",
      last_full_sync: null,
      last_delta_sync: null,
      last_error: "timeout",
      total_vulnerabilities: 0,
      total_affected_entries: 0,
    } as any);
    provider.updateVulnDB(vulndb);

    const items = provider.getChildren();
    const goItem = items.find(
      (i) =>
        i.collapsibleState === TreeItemCollapsibleState.Collapsed &&
        (i.label as string) === "go",
    );
    expect(goItem).toBeDefined();

    const children = provider.getChildren(goItem!);
    const childLabels = children.map((c) => c.label as string);
    expect(childLabels.some((l) => l.includes("Error: timeout"))).toBe(true);
  });
});
