const vscode = require("vscode");
const http = require("http");

let timer = null;

function activate(context) {
  const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.command = "devguard.openStatusEndpoint";
  statusItem.text = "$(shield) DevGuard: connecting...";
  statusItem.show();

  const diagnostics = vscode.languages.createDiagnosticCollection("devguard");
  context.subscriptions.push(statusItem, diagnostics);

  const refresh = async () => {
    const data = await fetchStatus();
    if (!data) {
      statusItem.text = "$(shield) DevGuard: offline";
      statusItem.backgroundColor = undefined;
      diagnostics.clear();
      return;
    }
    const role = data.active_role || "none";
    const pending = Number(data.pending_approvals_count || 0);
    const budget = data.budget_remaining && data.budget_remaining.tokens_remaining !== undefined
      ? data.budget_remaining.tokens_remaining
      : "-";
    const blocked = data.last_blocked_action || "none";
    statusItem.text = `$(shield) Role:${role} Budget:${budget} Pending:${pending}`;
    statusItem.tooltip = `DevGuard\nSession: ${data.current_session || "none"}\nLast blocked: ${blocked}`;
    if (pending > 0) {
      statusItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
      publishPendingDiagnostic(diagnostics, pending);
    } else {
      statusItem.backgroundColor = undefined;
      diagnostics.clear();
    }
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("devguard.openStatusEndpoint", () => {
      vscode.env.openExternal(vscode.Uri.parse("http://127.0.0.1:7788/devguard/status"));
    })
  );

  timer = setInterval(refresh, 2000);
  refresh();
}

function deactivate() {
  if (timer) clearInterval(timer);
}

function fetchStatus() {
  return new Promise((resolve) => {
    const req = http.get("http://127.0.0.1:7788/devguard/status", (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk.toString()));
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (_e) {
          resolve(null);
        }
      });
    });
    req.on("error", () => resolve(null));
    req.setTimeout(1200, () => {
      req.destroy();
      resolve(null);
    });
  });
}

function publishPendingDiagnostic(collection, pending) {
  const d = new vscode.Diagnostic(
    new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 1)),
    `DevGuard: ${pending} approval(s) pending`,
    vscode.DiagnosticSeverity.Warning
  );
  collection.set(vscode.Uri.file("devguard://status"), [d]);
}

module.exports = { activate, deactivate };
