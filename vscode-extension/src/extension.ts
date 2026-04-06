import * as vscode from "vscode";
import { ProxyManager } from "./proxy";
import { DecisionTreeProvider } from "./decisions";
import { DeniedTreeProvider } from "./denied";
import { StatusTreeProvider } from "./statusTree";
import { DashboardPanel } from "./dashboard";
import {
  configureNpm,
  configurePip,
  configureGo,
  configureMaven,
} from "./configHelper";
import { ManifestAnalyzer } from "./manifest";

let proxyManager: ProxyManager;
let decisionProvider: DecisionTreeProvider;
let deniedProvider: DeniedTreeProvider;
let statusProvider: StatusTreeProvider;
let manifestAnalyzer: ManifestAnalyzer;
let pollTimer: ReturnType<typeof setInterval> | undefined;

export function activate(context: vscode.ExtensionContext) {
  proxyManager = new ProxyManager(context);
  decisionProvider = new DecisionTreeProvider();
  deniedProvider = new DeniedTreeProvider();
  statusProvider = new StatusTreeProvider(proxyManager);
  manifestAnalyzer = new ManifestAnalyzer();
  context.subscriptions.push(manifestAnalyzer);

  vscode.window.registerTreeDataProvider(
    "dependencyGuardian.decisions",
    decisionProvider,
  );
  vscode.window.registerTreeDataProvider(
    "dependencyGuardian.denied",
    deniedProvider,
  );
  vscode.window.registerTreeDataProvider(
    "dependencyGuardian.status",
    statusProvider,
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("dependencyGuardian.start", async () => {
      try {
        await proxyManager.start();
        statusProvider.refresh();
        manifestAnalyzer.setBaseUrl(`http://127.0.0.1:${proxyManager.port}`);
        startPolling();
        vscode.window.showInformationMessage(
          `Dependency Guardian proxy started on port ${proxyManager.port}`,
        );
      } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to start proxy: ${e.message}`);
      }
    }),

    vscode.commands.registerCommand("dependencyGuardian.stop", async () => {
      const cfg = vscode.workspace.getConfiguration("dependencyGuardian");
      const mode = cfg.get<string>("connectionMode") ?? "local";

      stopPolling();
      if (mode !== "hosted") {
        await proxyManager.stop();
      } else {
        proxyManager.disconnect();
      }
      statusProvider.refresh();
      decisionProvider.clear();
      deniedProvider.clear();
      manifestAnalyzer.setBaseUrl("");
      manifestAnalyzer.updateDecisions([]);
      vscode.window.showInformationMessage(
        "Dependency Guardian proxy stopped.",
      );
    }),

    vscode.commands.registerCommand("dependencyGuardian.showDashboard", () => {
      if (!proxyManager.isRunning) {
        vscode.window.showWarningMessage("Start the proxy first.");
        return;
      }
      DashboardPanel.createOrShow(context.extensionUri, proxyManager.port);
    }),

    vscode.commands.registerCommand("dependencyGuardian.configureNpm", () =>
      configureNpm(proxyManager.port),
    ),
    vscode.commands.registerCommand("dependencyGuardian.configurePip", () =>
      configurePip(proxyManager.port),
    ),
    vscode.commands.registerCommand("dependencyGuardian.configureGo", () =>
      configureGo(proxyManager.port),
    ),

    vscode.commands.registerCommand("dependencyGuardian.configureMaven", () =>
      configureMaven(proxyManager.port),
    ),

    vscode.commands.registerCommand(
      "dependencyGuardian.refreshDecisions",
      () => {
        if (proxyManager.isRunning) {
          refreshData();
        }
      },
    ),

    vscode.commands.registerCommand("dependencyGuardian.clearDecisions", () => {
      decisionProvider.clear();
      deniedProvider.clear();
    }),
  );

  // Auto-start if configured.
  const config = vscode.workspace.getConfiguration("dependencyGuardian");
  if (config.get<boolean>("autoStart")) {
    vscode.commands.executeCommand("dependencyGuardian.start");
  }
}

function startPolling() {
  stopPolling();
  const config = vscode.workspace.getConfiguration("dependencyGuardian");
  const interval = (config.get<number>("refreshInterval") ?? 3) * 1000;
  pollTimer = setInterval(() => refreshData(), interval);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

async function refreshData() {
  if (!proxyManager.isRunning) {
    return;
  }

  try {
    const base = `http://127.0.0.1:${proxyManager.port}`;

    const [decisionsRes, statsRes, vulndbRes] = await Promise.all([
      fetch(`${base}/api/decisions?limit=200`),
      fetch(`${base}/api/stats`),
      fetch(`${base}/api/vulndb`).catch(() => null),
    ]);

    if (decisionsRes.ok) {
      const entries = (await decisionsRes.json()) as any[];
      decisionProvider.update(entries);
      manifestAnalyzer.updateDecisions(entries);
    }

    if (statsRes.ok) {
      const stats = (await statsRes.json()) as any;
      statusProvider.updateStats(stats);
      // Use recent_denied from stats – it scans the full ring buffer,
      // so it won't miss denied entries that scrolled out of the
      // limited /api/decisions response.
      deniedProvider.update(stats.recent_denied ?? []);
    }

    if (vulndbRes && vulndbRes.ok) {
      const vulndb = (await vulndbRes.json()) as any;
      statusProvider.updateVulnDB(vulndb);
    }
  } catch {
    // Proxy might be restarting; ignore transient errors.
  }
}

export function deactivate() {
  stopPolling();
  const cfg = vscode.workspace.getConfiguration("dependencyGuardian");
  const mode = cfg.get<string>("connectionMode") ?? "local";
  const autoStop = cfg.get<boolean>("autoStopOnClose") ?? true;

  if (mode === "hosted") {
    proxyManager?.disconnect();
  } else if (autoStop) {
    proxyManager?.stop();
  }
}
