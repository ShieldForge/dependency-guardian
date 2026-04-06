import { describe, it, expect, vi } from "vitest";

// We test that the config helper functions produce the right command strings.
// Since their implementations call vscode.window.showInformationMessage (mocked to return
// undefined), they won't execute branches that need user interaction, but we can verify
// the functions don't throw and exercise their logic paths.

// Spy on the mock clipboard to verify Maven snippet content.
import * as vscode from "vscode";

import {
  configureNpm,
  configurePip,
  configureGo,
  configureMaven,
} from "./configHelper";

describe("configureNpm", () => {
  it("does not throw", async () => {
    await expect(configureNpm(8080)).resolves.toBeUndefined();
  });
});

describe("configurePip", () => {
  it("does not throw", async () => {
    await expect(configurePip(9090)).resolves.toBeUndefined();
  });
});

describe("configureGo", () => {
  it("does not throw", async () => {
    await expect(configureGo(8080)).resolves.toBeUndefined();
  });
});

describe("configureMaven", () => {
  it("does not throw", async () => {
    await expect(configureMaven(8080)).resolves.toBeUndefined();
  });

  it("copies snippet when user selects Copy Snippet", async () => {
    const clipboardSpy = vi.spyOn(vscode.env.clipboard, "writeText");
    // Mock showInformationMessage to simulate user clicking "Copy Snippet".
    const msgSpy = vi
      .spyOn(vscode.window, "showInformationMessage")
      .mockResolvedValueOnce("Copy Snippet" as any);

    await configureMaven(8080);

    expect(clipboardSpy).toHaveBeenCalledOnce();
    const snippet = clipboardSpy.mock.calls[0][0];
    expect(snippet).toContain("dependency-guardian");
    expect(snippet).toContain("8080");
    expect(snippet).toContain("<mirror>");

    msgSpy.mockRestore();
    clipboardSpy.mockRestore();
  });
});
