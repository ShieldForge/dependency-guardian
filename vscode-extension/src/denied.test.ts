import { describe, it, expect, beforeEach } from "vitest";
import { DeniedTreeProvider } from "./denied";
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
    package: "event-stream",
    version: "3.3.6",
    allowed: false,
    reasons: ["malicious package"],
    vulnerabilities: 1,
    ...overrides,
  };
}

describe("DeniedTreeProvider", () => {
  let provider: DeniedTreeProvider;

  beforeEach(() => {
    provider = new DeniedTreeProvider();
  });

  it("shows placeholder when no denied entries exist", () => {
    const children = provider.getChildren();
    expect(children).toHaveLength(1);
    expect(children[0].label).toContain("No blocked packages");
  });

  it("shows denied entries after update", () => {
    const entries = [
      makeEntry({ id: 1, package: "evil-pkg", version: "1.0.0" }),
      makeEntry({
        id: 2,
        package: "bad-pkg",
        version: "2.0.0",
        reasons: ["vulnerability"],
      }),
    ];
    provider.update(entries);

    const children = provider.getChildren();
    expect(children).toHaveLength(2);
    expect(children[0].label).toBe("evil-pkg@1.0.0");
    expect(children[1].label).toBe("bad-pkg@2.0.0");
  });

  it("shows entries as collapsible", () => {
    provider.update([makeEntry()]);
    const children = provider.getChildren();
    expect(children[0].collapsibleState).toBe(
      TreeItemCollapsibleState.Collapsed,
    );
  });

  it("sets description to reasons joined by comma", () => {
    provider.update([makeEntry({ reasons: ["vuln", "policy"] })]);
    const children = provider.getChildren();
    expect(children[0].description).toBe("vuln, policy");
  });

  it("sets error icon", () => {
    provider.update([makeEntry()]);
    const children = provider.getChildren();
    expect((children[0].iconPath as any).id).toBe("error");
  });

  it("sets tooltip with blocked info and reasons", () => {
    provider.update([
      makeEntry({ package: "foo", version: "1.0", reasons: ["critical vuln"] }),
    ]);
    const children = provider.getChildren();
    expect(children[0].tooltip).toContain("Blocked");
    expect(children[0].tooltip).toContain("foo@1.0");
    expect(children[0].tooltip).toContain("critical vuln");
  });

  it("clear resets to placeholder", () => {
    provider.update([makeEntry()]);
    expect(provider.getChildren()).toHaveLength(1);

    provider.clear();
    const children = provider.getChildren();
    expect(children).toHaveLength(1);
    expect(children[0].label).toContain("No blocked packages");
  });

  it("getChildren with element returns detail items", () => {
    const entry = makeEntry({
      ecosystem: "pypi",
      vulnerabilities: 5,
      reasons: ["known malware"],
    });
    provider.update([entry]);

    const topLevel = provider.getChildren();
    const details = provider.getChildren(topLevel[0]);

    const labels = details.map((d) => d.label as string);
    expect(labels).toContain("Ecosystem: pypi");
    expect(labels.some((l) => l.startsWith("Time:"))).toBe(true);
    expect(labels).toContain("Vulnerabilities: 5");
    expect(labels).toContain("Reason: known malware");
  });

  it("getChildren with element omits vuln line when zero", () => {
    provider.update([makeEntry({ vulnerabilities: 0, reasons: ["policy"] })]);
    const topLevel = provider.getChildren();
    const details = provider.getChildren(topLevel[0]);
    const labels = details.map((d) => d.label as string);
    expect(labels.every((l) => !l.startsWith("Vulnerabilities:"))).toBe(true);
  });

  it("getTreeItem returns the element itself", () => {
    provider.update([makeEntry()]);
    const items = provider.getChildren();
    expect(provider.getTreeItem(items[0])).toBe(items[0]);
  });

  it("limits display to 50 items", () => {
    const entries = Array.from({ length: 80 }, (_, i) =>
      makeEntry({ id: i + 1, package: `bad-${i}` }),
    );
    provider.update(entries);
    const items = provider.getChildren();
    expect(items.length).toBeLessThanOrEqual(50);
  });
});
