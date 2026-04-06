import * as vscode from "vscode";

export async function configureNpm(port: number) {
  const commands = [`npm config set registry http://127.0.0.1:${port}/npm/`];
  const undoCommands = [`npm config delete registry`];

  await showConfigDialog("npm", commands, undoCommands);
}

export async function configurePip(port: number) {
  const commands = [
    `pip config set global.index-url http://127.0.0.1:${port}/pypi/simple/`,
    `pip config set global.trusted-host 127.0.0.1`,
  ];
  const undoCommands = [
    `pip config unset global.index-url`,
    `pip config unset global.trusted-host`,
  ];

  await showConfigDialog("pip", commands, undoCommands);
}

export async function configureGo(port: number) {
  const commands = [
    `go env -w GOPROXY=http://127.0.0.1:${port}/go/,direct`,
    `go env -w GONOSUMDB=*`,
  ];
  const undoCommands = [
    `go env -w GOPROXY=https://proxy.golang.org,direct`,
    `go env -u GONOSUMDB`,
  ];

  await showConfigDialog("Go", commands, undoCommands);
}

export async function configureMaven(port: number) {
  const settingsSnippet = `
<!-- Add to ~/.m2/settings.xml inside <mirrors> -->
<mirror>
  <id>dependency-guardian</id>
  <mirrorOf>central</mirrorOf>
  <url>http://127.0.0.1:${port}/maven/</url>
</mirror>`.trim();

  const undoSnippet =
    'Remove the <mirror id="dependency-guardian"> block from ~/.m2/settings.xml';

  const action = await vscode.window.showInformationMessage(
    "Configure Maven to use the Dependency Guardian proxy?",
    {
      modal: true,
      detail: `Add the following mirror to your ~/.m2/settings.xml:\n\n${settingsSnippet}\n\nTo undo:\n${undoSnippet}`,
    },
    "Copy Snippet",
  );

  if (action === "Copy Snippet") {
    await vscode.env.clipboard.writeText(settingsSnippet);
    vscode.window.showInformationMessage(
      "Maven mirror snippet copied to clipboard.",
    );
  }
}

async function showConfigDialog(
  ecosystem: string,
  commands: string[],
  undoCommands: string[],
) {
  const action = await vscode.window.showInformationMessage(
    `Configure ${ecosystem} to use the Dependency Guardian proxy?`,
    {
      modal: true,
      detail: `This will run:\n\n${commands.join("\n")}\n\nTo undo later:\n${undoCommands.join("\n")}`,
    },
    "Apply",
    "Copy Commands",
  );

  if (action === "Apply") {
    const terminal = vscode.window.createTerminal(
      `Guardian: Configure ${ecosystem}`,
    );
    terminal.show();
    for (const cmd of commands) {
      terminal.sendText(cmd);
    }
    vscode.window.showInformationMessage(
      `${ecosystem} configured to use the proxy.`,
    );
  } else if (action === "Copy Commands") {
    await vscode.env.clipboard.writeText(commands.join("\n"));
    vscode.window.showInformationMessage("Commands copied to clipboard.");
  }
}
