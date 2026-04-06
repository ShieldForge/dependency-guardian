import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";

export class ProxyManager {
  private process: cp.ChildProcess | undefined;
  private outputChannel: vscode.OutputChannel;
  private _port = 8080;
  private _isRunning = false;
  private context: vscode.ExtensionContext;

  constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.outputChannel = vscode.window.createOutputChannel(
      "Dependency Guardian",
    );
  }

  get port(): number {
    return this._port;
  }

  get isRunning(): boolean {
    return this._isRunning;
  }

  async start(): Promise<void> {
    if (this._isRunning) {
      return;
    }

    const config = vscode.workspace.getConfiguration("dependencyGuardian");
    this._port = config.get<number>("listenPort") ?? 8080;

    const binaryPath = this.resolveBinaryPath();
    if (!binaryPath) {
      throw new Error(
        "Cannot find guardian binary. Build it with `go build -o guardian ./cmd/guardian` " +
          "or set dependencyGuardian.binaryPath in settings.",
      );
    }

    const args = ["--vscode", "--addr", `:${this._port}`];

    const configDir = config.get<string>("configDirectory");
    if (configDir) {
      args.push("--config", configDir);
    }

    const policiesDir = config.get<string>("policiesDirectory");
    if (policiesDir) {
      args.push("--policies", policiesDir);
    }

    this.outputChannel.appendLine(
      `Starting guardian: ${binaryPath} ${args.join(" ")}`,
    );
    this.outputChannel.show(true);

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

    this.process = cp.spawn(binaryPath, args, {
      cwd: workspaceFolder ?? path.dirname(binaryPath),
      env: { ...process.env },
    });

    this.process.stdout?.on("data", (data: Buffer) => {
      this.outputChannel.appendLine(data.toString().trimEnd());
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      this.outputChannel.appendLine(`[stderr] ${data.toString().trimEnd()}`);
    });

    this.process.on("error", (err) => {
      this.outputChannel.appendLine(`Process error: ${err.message}`);
      this._isRunning = false;
    });

    this.process.on("exit", (code) => {
      this.outputChannel.appendLine(`Guardian exited with code ${code}`);
      this._isRunning = false;
    });

    // Wait for the proxy to become healthy.
    await this.waitForHealth();
    this._isRunning = true;
  }

  async stop(): Promise<void> {
    if (this.process) {
      this.process.kill("SIGTERM");
      this.process = undefined;
    }
    this._isRunning = false;
  }

  /** Mark as disconnected without killing any process. */
  disconnect(): void {
    this._isRunning = false;
  }

  private resolveBinaryPath(): string | undefined {
    const config = vscode.workspace.getConfiguration("dependencyGuardian");
    const configured = config.get<string>("binaryPath");

    if (configured && fs.existsSync(configured)) {
      return configured;
    }

    // Look for the binary relative to the workspace.
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceFolder) {
      const suffixes = process.platform === "win32" ? [".exe", ""] : [""];
      const dirs = [
        workspaceFolder,
        path.join(workspaceFolder, "bin"),
        path.join(workspaceFolder, "cmd", "guardian"),
      ];
      for (const dir of dirs) {
        for (const suffix of suffixes) {
          const candidate = path.join(dir, `guardian${suffix}`);
          if (fs.existsSync(candidate)) {
            return candidate;
          }
        }
      }
    }

    // Look in the extension's bundled directory.
    const bundledSuffixes = process.platform === "win32" ? [".exe", ""] : [""];
    for (const suffix of bundledSuffixes) {
      const bundled = path.join(
        this.context.extensionPath,
        "bin",
        `guardian${suffix}`,
      );
      if (fs.existsSync(bundled)) {
        return bundled;
      }
    }

    return undefined;
  }

  private async waitForHealth(timeout = 10000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const res = await fetch(`http://127.0.0.1:${this._port}/health`);
        if (res.ok) {
          return;
        }
      } catch {
        // Not ready yet.
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error(`Proxy did not become healthy within ${timeout}ms`);
  }
}
