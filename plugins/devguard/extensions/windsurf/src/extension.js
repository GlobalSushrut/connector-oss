const vscode = require("vscode");
const http = require("http");

let timer = null;

function activate(context) {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 101);
  item.text = "$(shield) DevGuard WS: starting...";
  item.show();
  context.subscriptions.push(item);

  const refresh = async () => {
    const status = await fetchStatus();
    if (!status) {
      item.text = "$(shield) DevGuard WS: offline";
      item.backgroundColor = undefined;
      return;
    }
    const role = status.active_role || "none";
    const pending = Number(status.pending_approvals_count || 0);
    const budget = status.budget_remaining && status.budget_remaining.tokens_remaining !== undefined
      ? status.budget_remaining.tokens_remaining
      : "-";
    item.text = `$(shield) ${role} | budget ${budget} | pending ${pending}`;
    item.tooltip = `Session: ${status.current_session || "none"}\nLast blocked: ${status.last_blocked_action || "none"}`;
    item.backgroundColor = pending > 0
      ? new vscode.ThemeColor("statusBarItem.errorBackground")
      : undefined;
  };

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

module.exports = { activate, deactivate };
