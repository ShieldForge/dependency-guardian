// Minimal mock of the VS Code API for unit testing.

export enum TreeItemCollapsibleState {
    None = 0,
    Collapsed = 1,
    Expanded = 2,
}

export enum DiagnosticSeverity {
    Error = 0,
    Warning = 1,
    Information = 2,
    Hint = 3,
}

export class TreeItem {
    label: string;
    collapsibleState: TreeItemCollapsibleState;
    description?: string;
    tooltip?: string;
    iconPath?: any;

    constructor(
        label: string,
        collapsibleState: TreeItemCollapsibleState = TreeItemCollapsibleState.None,
    ) {
        this.label = label;
        this.collapsibleState = collapsibleState;
    }
}

export class EventEmitter<T> {
    private listeners: Array<(e: T) => void> = [];
    event = (listener: (e: T) => void) => {
        this.listeners.push(listener);
        return {
            dispose: () => {
                this.listeners = this.listeners.filter((l) => l !== listener);
            },
        };
    };
    fire(data: T) {
        for (const l of this.listeners) {
            l(data);
        }
    }
    dispose() {
        this.listeners = [];
    }
}

export class ThemeIcon {
    constructor(
        public readonly id: string,
        public readonly color?: ThemeColor,
    ) { }
}

export class ThemeColor {
    constructor(public readonly id: string) { }
}

export class Range {
    constructor(
        public readonly start: Position,
        public readonly end: Position,
    ) { }
    contains(pos: Position): boolean {
        if (pos.line < this.start.line || pos.line > this.end.line) {
            return false;
        }
        if (pos.line === this.start.line && pos.character < this.start.character) {
            return false;
        }
        if (pos.line === this.end.line && pos.character > this.end.character) {
            return false;
        }
        return true;
    }
}

export class Position {
    constructor(
        public readonly line: number,
        public readonly character: number,
    ) { }
}

export class Uri {
    static file(path: string) {
        return new Uri(path);
    }
    constructor(public readonly fsPath: string) { }
    get path() {
        return this.fsPath;
    }
}

export class Diagnostic {
    source?: string;
    constructor(
        public readonly range: Range,
        public readonly message: string,
        public readonly severity: DiagnosticSeverity = DiagnosticSeverity.Error,
    ) { }
}

export class MarkdownString {
    constructor(
        public value: string = "",
        public supportThemeIcons = false,
    ) { }
    isTrusted = false;
}

export class Hover {
    constructor(
        public contents: MarkdownString,
        public range?: Range,
    ) { }
}

export const window = {
    createOutputChannel: () => ({
        appendLine: () => { },
        show: () => { },
        dispose: () => { },
    }),
    showInformationMessage: async (..._args: any[]) => undefined,
    showWarningMessage: async (..._args: any[]) => undefined,
    showErrorMessage: async (..._args: any[]) => undefined,
    createTerminal: () => ({
        show: () => { },
        sendText: () => { },
        dispose: () => { },
    }),
    registerTreeDataProvider: () => ({ dispose: () => { } }),
};

export const workspace = {
    getConfiguration: (_section?: string) => ({
        get: <T>(_key: string, defaultValue?: T) => defaultValue,
    }),
    workspaceFolders: undefined as any,
    textDocuments: [] as any[],
    onDidOpenTextDocument: () => ({ dispose: () => { } }),
    onDidChangeTextDocument: () => ({ dispose: () => { } }),
    onDidCloseTextDocument: () => ({ dispose: () => { } }),
};

export const languages = {
    createDiagnosticCollection: () => ({
        set: () => { },
        delete: () => { },
        dispose: () => { },
    }),
    registerHoverProvider: () => ({ dispose: () => { } }),
};

export const commands = {
    registerCommand: (_cmd: string, _cb: (...args: unknown[]) => unknown) => ({
        dispose: () => { },
    }),
    executeCommand: async () => { },
};

export const env = {
    clipboard: {
        writeText: async (_text: string) => { },
        readText: async () => "",
    },
};
