#!/usr/bin/env python3
"""
Patch Trunk-generated index.html for maximum WASM loading performance.
Also runs wasm-opt -Oz to shrink the binary.

Pipeline (same approach as Vite/esbuild for production builds):
  1. wasm-opt -Oz  — 40-50% binary size reduction, better JIT tiering
  2. Async IIFE    — no browser script-timeout, returns immediately
  3. Streaming     — fetch() piped to init() so JIT compiles while downloading
  4. SW register   — Service Worker caches assets for instant repeat loads
  5. Progress      — boot splash shows "Fetching…" / "Compiling…" feedback
"""
import re, sys, pathlib, subprocess, shutil, hashlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playground_auth_gate import PLAYGROUND_META, PLAYGROUND_AUTH_GATE, TRIAL_SW_UNREGISTER, patch_trial_asset_paths

path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("dist/playground/index.html")
profile = sys.argv[2] if len(sys.argv) > 2 else None
html = path.read_text()
dist_dir = path.parent


def content_version(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def prepare_dashboard_assets(dist_dir: pathlib.Path) -> tuple[str, str] | tuple[None, None]:
    """Align split-loader paths with flattened cargo-leptos output."""
    ui_wasm = dist_dir / "connector-ui.wasm"
    ui_js = dist_dir / "connector-ui.js"
    if not ui_wasm.exists() or not ui_js.exists():
        return None, None

    bg = dist_dir / "connector-ui_bg.wasm"
    shutil.copy2(ui_wasm, bg)

    pkg = dist_dir / "pkg"
    pkg.mkdir(exist_ok=True)
    for name in ("connector-ui.js", "connector-ui.wasm", "connector-ui_bg.wasm"):
        shutil.copy2(dist_dir / name, pkg / name)

    for split in dist_dir.glob("__wasm_split*.js"):
        text = split.read_text()
        text = text.replace('from "/pkg/connector-ui.js"', 'from "/connector-ui.js"')
        text = text.replace("from '/pkg/connector-ui.js'", "from '/connector-ui.js'")
        split.write_text(text)

    return content_version(ui_js), content_version(ui_wasm)


SW_UNREGISTER = """
    if ('serviceWorker' in navigator) {
      var regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map(function (r) { return r.unregister(); }));
    }"""

# ── 1. wasm-opt ──────────────────────────────────────────────────────────────
# DISABLED for all builds. The split dashboard (`cargo leptos build --split`)
# emits a main module + split_*/chunk_* modules that share one indirect
# function table; running wasm-opt on any of them independently renumbers
# table indices and breaks cross-module calls at runtime. The trial bundle
# was likewise broken by wasm-opt (stale closure exports). cargo-leptos
# already applies its own wasm-opt pass coherently across the module graph.
WASM_OPT_FLAGS = []

def collect_wasm_files(dist_dir):
    patterns = [
        "connector-ui*.wasm",
        "connector-ui-*_bg.wasm",
        "connector-ui_bg.wasm",
        "split_*.wasm",
        "chunk_*.wasm",
    ]
    seen = set()
    files = []
    for pat in patterns:
        for p in dist_dir.glob(pat):
            if p.suffix == ".wasm" and p not in seen:
                seen.add(p)
                files.append(p)
    return files

if WASM_OPT_FLAGS:
    for wasm_path in collect_wasm_files(dist_dir):
        try:
            result = subprocess.run(
                ["npx", "--yes", "wasm-opt@latest"] + WASM_OPT_FLAGS + [str(wasm_path), "-o", str(wasm_path)],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print(f"wasm-opt (npx): optimised {wasm_path.name} → {wasm_path.stat().st_size//1024//1024}MB")
            else:
                print(f"wasm-opt (npx) failed (skipping): {result.stderr[:300]}")
        except Exception as e:
            print(f"wasm-opt unavailable ({e}), skipping optimisation")
else:
    print("patch_wasm_init: wasm-opt disabled (split modules share a function table)")

# ── 2. Patch the module script ───────────────────────────────────────────────
old = re.search(r'<script type="module">.*?</script>', html, re.DOTALL)
if not old:
    print("patch_wasm_init: no <script type=module> found, skipping")
    sys.exit(0)

block = old.group()
if "instantiateStreaming" in block:
    print("patch_wasm_init: script already patched")
else:
    wasm_m = re.search(r'connector-(?:ui|trial)[\w-]*\.wasm|connector-(?:ui|trial)-\w+_bg\.wasm', block)
    js_m   = re.search(r'connector-(?:ui|trial)[\w-]*\.js', block)
    if not wasm_m or not js_m:
        print("patch_wasm_init: could not find asset filenames, skipping script patch")
    else:
        wasm_f = wasm_m.group()
        js_f   = js_m.group()
        js_url = f"/{js_f}"
        wasm_url = f"/{wasm_f}"
        # NOTE: no explicit bindings.hydrate() — #[wasm_bindgen(start)] already
        # runs hydrate()/main() inside init(); calling it again double-mounts.
        patched_script = f"""<script type="module">
import init, * as bindings from '{js_url}';
// Async IIFE — module returns immediately, no browser script-timeout watchdog.
(async function() {{{SW_UNREGISTER}
  function splash(msg) {{
    var el = document.getElementById('boot-msg');
    if (el) el.textContent = msg;
  }}
  function showErr(msg) {{
    var el = document.getElementById('boot-err');
    if (el) {{ el.textContent = msg; el.style.display = 'block'; }}
    console.error('WASM init failed:', msg);
  }}
  window.addEventListener('error', function (e) {{
    if (e && e.message) {{
      var m = e.message;
      if (m.indexOf('timeout') >= 0 || m.indexOf('terminated') >= 0) {{
        m += ' — Hard-refresh (Ctrl+Shift+R) to load the latest build, or clear site data for try.cnktros.com.';
      }}
      showErr(m);
    }}
  }});
  var compileMs = 0;
  var compileTimer = setInterval(function () {{
    compileMs += 5;
    if (compileMs >= 15) {{
      splash('Compiling WebAssembly\u2026 (first visit can take 1\u20132 min \u2014 please wait)');
    }}
  }}, 5000);
  try {{
    splash('Downloading runtime\u2026');
    const resp = fetch('{wasm_url}', {{ cache: 'no-store' }});
    splash('Compiling WebAssembly\u2026');
    const wasm = await Promise.race([
      init({{ module_or_path: resp }}),
      new Promise(function (_, reject) {{
        setTimeout(function () {{
          reject(new Error('WASM compile timed out after 3 minutes. Hard-refresh (Ctrl+Shift+R) or clear site data for try.cnktros.com, then open /login first.'));
        }}, 180000);
      }}),
    ]);
    clearInterval(compileTimer);
    window.wasmBindings = bindings;
    dispatchEvent(new CustomEvent('TrunkApplicationStarted', {{ detail: {{ wasm }} }}));
  }} catch (e) {{
    clearInterval(compileTimer);
    showErr('Load error: ' + (e && e.message ? e.message : String(e)));
  }}
}})();
</script>"""
        html = html[:old.start()] + patched_script + html[old.end():]
        print(f"patch_wasm_init: patched script in {path.name} ({wasm_f})")

# ── 2.5 Playground auth gate + trial SW cleanup ───────────────────────────────
is_playground_dist = (
    profile == "playground"
    or "playground" in str(dist_dir)
    or "playground" in str(path)
)
is_trial_page = bool(re.search(r"from '/connector-trial", html))
is_dashboard_page = bool(re.search(r"from '/connector-ui", html))

if is_playground_dist and is_dashboard_page:
    if PLAYGROUND_META not in html:
        html = html.replace("<head>", "<head>\n  " + PLAYGROUND_META, 1)
    if 'id="boot-msg"' not in html:
        html = html.replace(
            '<div style="font-size: 0.875rem;">Loading Connector…</div>',
            '<div id="boot-msg" style="font-size: 0.875rem;">Loading Connector…</div>',
        )
    if 'id="playground-auth-gate"' not in html:
        html = html.replace('<script type="module">', PLAYGROUND_AUTH_GATE + '\n<script type="module">', 1)
        print("patch_wasm_init: injected playground auth gate")

    jv, wv = prepare_dashboard_assets(dist_dir)
    if jv and wv:
        # One build version for the whole module graph (avoids circular content
        # hashes: HTML → connector-ui.js → split loader → connector-ui.js).
        build_v = content_version(dist_dir / "connector-ui.wasm")
        js_url = f"/connector-ui.js?v={build_v}"
        wasm_url = f"/connector-ui.wasm?v={build_v}"

        split = next(dist_dir.glob("__wasm_split*.js"), None)
        if split:
            split_spec = f"./{split.name}?v={build_v}"
            for js_path in (dist_dir / "connector-ui.js",):
                text = js_path.read_text()
                # Version the import SPECIFIERS (cache-bust at CDN level)…
                text = re.sub(
                    rf'from"\./{re.escape(split.name)}(?:\?[^"]*)?"',
                    f'from"{split_spec}"',
                    text,
                )
                text = re.sub(
                    rf"from'\./{re.escape(split.name)}(?:\?[^']*)?'",
                    f"from'{split_spec}'",
                    text,
                )
                # …but the import-OBJECT keys must stay exactly the module name
                # the WASM binary declares (no query string), or instantiation
                # fails with "import object field ... is not an Object".
                text = re.sub(
                    rf'"\./{re.escape(split.name)}\?[^"]*":',
                    f'"./{split.name}":',
                    text,
                )
                js_path.write_text(text)
            for split_file in dist_dir.glob("__wasm_split*.js"):
                text = split_file.read_text()
                text = re.sub(
                    r'from "(?:/pkg)?/connector-ui\.js(?:\?[^"]*)?"',
                    f'from "{js_url}"',
                    text,
                )
                text = re.sub(
                    r"from '(?:/pkg)?/connector-ui\.js(?:\?[^']*)?'",
                    f"from '{js_url}'",
                    text,
                )
                # Split chunks are not content-hashed (`chunk_8.wasm`,
                # `split___route.wasm`). Version their request URLs so a
                # browser/CDN cannot pair the current main module with a
                # cached chunk from a previous release. Keep the filename
                # itself stable because cargo-leptos references it by name.
                text = re.sub(
                    r'new URL\("(\./(?:chunk_\d+|split_[^"]+)\.wasm)(?:\?[^"]*)?", import\.meta\.url\)',
                    f'new URL("\\1?v={build_v}", import.meta.url)',
                    text,
                )
                text = re.sub(
                    r"new URL\('(\./(?:chunk_\d+|split_[^']+)\.wasm)(?:\?[^']*)?', import\.meta\.url\)",
                    f"new URL('\\1?v={build_v}', import.meta.url)",
                    text,
                )
                split_file.write_text(text)
            # Refresh pkg/ copy so both paths serve identical bytes.
            shutil.copy2(dist_dir / "connector-ui.js", dist_dir / "pkg" / "connector-ui.js")

        html = re.sub(
            r"from '/connector-ui\.js(?:\?[^']*)?'",
            f"from '{js_url}'",
            html,
        )
        html = re.sub(
            r"fetch\('/connector-ui\.wasm(?:\?[^']*)?'",
            f"fetch('{wasm_url}'",
            html,
        )
        html = re.sub(
            r'href="/connector-ui\.js(?:\?[^"]*)?"',
            f'href="{js_url}"',
            html,
        )
        html = re.sub(
            r'href="/tailwind\.out\.css(?:\?[^"]*)?"',
            f'href="/tailwind.out.css?v={build_v}"',
            html,
        )
        print(f"patch_wasm_init: dashboard cache-bust v={build_v}")

if is_trial_page and 'id="trial-sw-unregister"' not in html:
    html = html.replace('<script type="module">', TRIAL_SW_UNREGISTER + '\n<script type="module">', 1)
    print("patch_wasm_init: injected trial SW unregister")

if is_trial_page:
    html = patch_trial_asset_paths(html)
    js_p = dist_dir / "connector-trial.js"
    wasm_p = dist_dir / "connector-trial_bg.wasm"
    if js_p.exists() and wasm_p.exists():
        jv = hashlib.sha256(js_p.read_bytes()).hexdigest()[:12]
        wv = hashlib.sha256(wasm_p.read_bytes()).hexdigest()[:12]
        html = html.replace("from '/connector-trial.js'", f"from '/connector-trial.js?v={jv}'")
        html = html.replace(
            "fetch('/connector-trial_bg.wasm'",
            f"fetch('/connector-trial_bg.wasm?v={wv}'",
        )
        html = re.sub(
            r'href="/connector-trial\.js(?:\?[^"]*)?"',
            f'href="/connector-trial.js?v={jv}"',
            html,
        )
        html = re.sub(
            r'href="/connector-trial_bg\.wasm(?:\?[^"]*)?"',
            f'href="/connector-trial_bg.wasm?v={wv}"',
            html,
        )
        print(f"patch_wasm_init: trial cache-bust v={jv}/{wv}")
    print("patch_wasm_init: trial assets → /trial-app/*")

# ── 3. Inject SW cache-bust meta if not present ──────────────────────────────
if 'sw.js' not in html:
    html = html.replace('</head>', '  <link rel="prefetch" href="/sw.js" as="script" />\n</head>', 1)

path.write_text(html)

# ── 3.5 Update integrity hashes (wasm-opt changes file contents) ─────────────
# Trial pages strip SRI in patch_trial_asset_paths — skip hash injection there.
if not is_trial_page:
    import hashlib
    import base64

    def sha384_base64(path):
        h = hashlib.sha384()
        with open(path, "rb") as f:
            h.update(f.read())
        return base64.b64encode(h.digest()).decode("ascii")

    # Update integrity hashes for all assets that might have been modified
    for asset_path in dist_dir.glob("connector-*.js"):
        integrity_val = f"sha384-{sha384_base64(asset_path)}"
        old_hash = re.search(rf'<link[^>]*href="/{asset_path.name}"[^>]*integrity="sha384-[^"]+"', html)
        if old_hash:
            html = re.sub(rf'(<link[^>]*href="/{asset_path.name}"[^>]*?)integrity="sha384-[^"]+"', rf'\1integrity="{integrity_val}"', html)
            print(f"updated integrity: {asset_path.name}")
        # Also update modulepreload integrity
        old_mod = re.search(rf'<link[^>]*href="/{asset_path.name}"[^>]*integrity="sha384-[^"]+"', html)
        if old_mod:
            html = re.sub(rf'(<link[^>]*href="/{asset_path.name}"[^>]*?)integrity="sha384-[^"]+"', rf'\1integrity="{integrity_val}"', html)

    for wasm_path in dist_dir.glob("connector-*_bg.wasm"):
        integrity_val = f"sha384-{sha384_base64(wasm_path)}"
        # Update preload integrity
        if f"href=\"/{wasm_path.name}\"" in html:
            html = re.sub(rf'(<link[^>]*href="/{wasm_path.name}"[^>]*?)integrity="sha384-[^"]+"', rf'\1integrity="{integrity_val}"', html)
            print(f"updated integrity: {wasm_path.name}")

    path.write_text(html)

# ── 4. Re-gzip optimised WASM (wasm-opt changes bytes, old .gz is stale) ─────
# Trial uses Trunk `data-no-wasm-opt` — wasm-opt breaks wasm-bindgen closure exports.
# Re-gzip trial WASM only (no wasm-opt pass above).
trial_wasm = list(dist_dir.glob("connector-trial-*_bg.wasm")) + list(dist_dir.glob("connector-trial_bg.wasm"))
all_wasm = list(dist_dir.glob("connector-ui*.wasm")) + trial_wasm
for wasm_path in all_wasm:
    gz = wasm_path.with_suffix('.wasm.gz')
    result = subprocess.run(
        ["gzip", "-9", "-f", "-k", str(wasm_path)],
        capture_output=True
    )
    if result.returncode == 0 and gz.exists():
        print(f"re-gzipped {wasm_path.name} → {gz.stat().st_size//1024}KB")
