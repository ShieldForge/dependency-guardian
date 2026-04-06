import { describe, it, expect, beforeEach } from "vitest";
import { DecisionTreeProvider } from "./decisions";
import { TreeItemCollapsibleState } from "vscode";

function makeEntry(
  overrides: Partial<{
    id: number;
    timestamp: string;
    ecosystem: string;
    package: string;
    version: string;
    allowed: boolean;
    reasons: string[];
    vulnerabilities: number;
  }> = {},
) {
  return {
    id: 1,
    timestamp: new Date().toISOString(),
    ecosystem: "npm",
    package: "lodash",
    version: "4.17.21",
    allowed: true,
    reasons: [],
    vulnerabilities: 0,
    ...overrides,
  };
}

describe("DecisionTreeProvider", () => {
  let provider: DecisionTreeProvider;

  beforeEach(() => {
    provider = new DecisionTreeProvider();
  });

  it("shows placeholder when no decisions exist", () => {
    const children = provider.getChildren();
    expect(children).toHaveLength(1);
    expect(children[0].label).toContain("No decisions yet");
    expect(children[0].collapsibleState).toBe(TreeItemCollapsibleState.None);
  });

  it("shows entries after update", () => {
    const entries = [
      makeEntry({
        id: 1,
        package: "lodash",
        version: "4.17.21",
        allowed: true,
      }),
      makeEntry({
        id: 2,
        package: "event-stream",
        version: "3.3.6",
        allowed: false,
        reasons: ["malicious"],
      }),
    ];
    provider.update(entries);

    const children = provider.getChildren();
    expect(children).toHaveLength(2);
    expect(children[0].collapsibleState).toBe(
      TreeItemCollapsibleState.Collapsed,
    );
  });

  it("does not update when first id matches last seen", () => {
    const entries = [makeEntry({ id: 5 })];
    provider.update(entries);
    const first = provider.getChildren();

    // Same entries again – should be a no-op.
    provider.update(entries);
    const second = provider.getChildren();
    expect(second).toEqual(first);
  });

  it("updates when new id appears", () => {
    provider.update([makeEntry({ id: 5, package: "a" })]);
    expect(provider.getChildren()).toHaveLength(1);

    provider.update([
      makeEntry({ id: 6, package: "b" }),
      makeEntry({ id: 5, package: "a" }),
    ]);
    expect(provider.getChildren()).toHaveLength(2);
  });

  it("clear resets to placeholder", () => {
    provider.update([makeEntry({ id: 1 })]);
    expect(provider.getChildren()).toHaveLength(1);

    provider.clear();
    const children = provider.getChildren();
    expect(children).toHaveLength(1);
    expect(children[0].label).toContain("No decisions yet");
  });

  it("getChildren returns detail items for a decision element", () => {
    const entry = makeEntry({
      id: 1,
      ecosystem: "npm",
      vulnerabilities: 3,
      reasons: ["critical vuln"],
    });
    provider.update([entry]);

    const topLevel = provider.getChildren();
    const details = provider.getChildren(topLevel[0]);

    const labels = details.map((d) => d.label as string);
    expect(labels).toContain("Ecosystem: npm");
    expect(labels.some((l) => l.startsWith("Time:"))).toBe(true);
    expect(labels).toContain("Vulnerabilities: 3");
    expect(labels).toContain("Reason: critical vuln");
  });

  it("getTreeItem returns the element itself", () => {
    provider.update([makeEntry({ id: 1 })]);
    const items = provider.getChildren();
    expect(provider.getTreeItem(items[0])).toBe(items[0]);
  });

  it("allowed items have pass icon", () => {
    provider.update([makeEntry({ id: 1, allowed: true })]);
    const items = provider.getChildren();
    expect(items[0].iconPath).toBeDefined();
    expect((items[0].iconPath as any).id).toBe("pass");
  });

  it("denied items have error icon", () => {
    provider.update([
      makeEntry({ id: 1, allowed: false, reasons: ["blocked"] }),
    ]);
    const items = provider.getChildren();
    expect(items[0].iconPath).toBeDefined();
    expect((items[0].iconPath as any).id).toBe("error");
  });

  it("limits display to 100 items", () => {
    const entries = Array.from({ length: 150 }, (_, i) =>
      makeEntry({ id: i + 1, package: `pkg-${i}` }),
    );
    // Need first id to differ from last seen (0) so update takes effect.
    provider.update(entries);
    const items = provider.getChildren();
    expect(items.length).toBeLessThanOrEqual(100);
  });

  it("sets description to ecosystem", () => {
    provider.update([makeEntry({ id: 1, ecosystem: "pypi" })]);
    const items = provider.getChildren();
    expect(items[0].description).toBe("pypi");
  });

  it("sets tooltip for allowed item", () => {
    provider.update([
      makeEntry({ id: 1, allowed: true, package: "foo", version: "1.0.0" }),
    ]);
    const items = provider.getChildren();
    expect(items[0].tooltip).toContain("Allowed");
  });

  it("sets tooltip for denied item with reasons", () => {
    provider.update([
      makeEntry({
        id: 1,
        allowed: false,
        package: "bar",
        version: "2.0.0",
        reasons: ["vuln", "policy"],
      }),
    ]);
    const items = provider.getChildren();
    expect(items[0].tooltip).toContain("Blocked");
    expect(items[0].tooltip).toContain("vuln");
  });
});
