#!/usr/bin/env python3
"""Write index.html for a cargo-leptos CSR build (no server shell at build time)."""
import pathlib
import sys

dist = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("dist/.leptos-stage")

js = next(dist.glob("connector-ui*.js"), None)
wasm = next(dist.glob("connector-ui*.wasm"), None)
if not js or not wasm:
    # cargo-leptos may emit connector_ui.js before rename — try underscore form.
    js = js or next(dist.glob("connector_ui*.js"), None)
    wasm = wasm or next(dist.glob("connector_ui*.wasm"), None)
if not js or not wasm:
    raise SystemExit(f"leptos_index: missing connector-ui js/wasm in {dist}")

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <meta name="color-scheme" content="dark" />
  <meta name="theme-color" content="#09090b" />
  <title>Connector</title>
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="stylesheet" href="/tailwind.out.css" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" media="print" onload="this.media='all'" />
  <noscript><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" /></noscript>
  <style>
    html, body {{ background-color: #09090b; color: #fafafa; font-family: 'Inter', system-ui, -apple-system, sans-serif; }}
    .boot-splash {{
      position: fixed; inset: 0;
      display: flex; align-items: center; justify-content: center;
      flex-direction: column; gap: 0.75rem;
      color: #71717a; font-family: 'Inter', system-ui, sans-serif;
    }}
    .boot-spinner {{
      width: 1.5rem; height: 1.5rem;
      border: 2px solid #27272a; border-top-color: #6366f1;
      border-radius: 9999px; animation: boot-spin 0.8s linear infinite;
    }}
    @keyframes boot-spin {{ to {{ transform: rotate(360deg); }} }}
    #root:has(> :not(.boot-splash)) .boot-splash {{ display: none !important; }}
  </style>
  <link rel="modulepreload" href="/{js.name}" crossorigin />
</head>
<body class="bg-zinc-950 text-zinc-50 antialiased">
  <div id="root">
    <div class="boot-splash" role="status" aria-live="polite" aria-busy="true">
      <img src="/logo.png" alt="cnktros" width="180" height="48" style="height:40px;width:auto;" />
      <div class="boot-spinner" aria-hidden="true"></div>
      <div style="font-size: 0.875rem;">Loading Connector…</div>
      <div id="boot-err" style="display:none;max-width:32rem;margin-top:1rem;padding:0.75rem 1rem;border-radius:8px;border:1px solid #7f1d1d;background:#1c0a0a;color:#fca5a5;font-size:0.75rem;font-family:monospace;white-space:pre-wrap;word-break:break-all;"></div>
    </div>
  </div>
  <script type="module">
import init, * as bindings from '/{js.name}';
(async function() {{
  try {{
    await init('/{wasm.name}');
    window.wasmBindings = bindings;
  }} catch (e) {{
    var el = document.getElementById('boot-err');
    if (el) {{ el.style.display='block'; el.textContent = String(e); }}
    console.error(e);
  }}
}})();
  </script>
</body>
</html>
"""
(dist / "index.html").write_text(html)
print(f"leptos_index: wrote {dist / 'index.html'} ({js.name}, {wasm.name})")
