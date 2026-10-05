#!/usr/bin/env python3
"""Inline scripts injected into playground dashboard index.html before WASM load."""

PLAYGROUND_META = '<meta name="connector-distribution" content="playground" />'

# Runs synchronously before the WASM module graph is fetched. Sends anonymous
# visitors to the lightweight trial-app (/login) instead of compiling the
# full dashboard shell first.
PLAYGROUND_AUTH_GATE = """<script id="playground-auth-gate">
(function () {
  var path = location.pathname;
  if (path === '/login' || path.indexOf('/login/') === 0) return;
  if (path === '/trial' || path.indexOf('/trial/') === 0) return;
  if (path === '/connect' || path.indexOf('/connect/') === 0) return;
  function validKey(k) {
    return k && k.trim().indexOf('cpk_') === 0;
  }
  function validJwt(t) {
    return t && t.trim().indexOf('.') > 0;
  }
  try {
    var key = localStorage.getItem('api_key') || localStorage.getItem('trial_api_key');
    if (validKey(key)) return;
    // Fresh JWT from trial login — allow dashboard load (fetch_me validates).
    var token = localStorage.getItem('access_token');
    if (validJwt(token)) return;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    var next = path + (location.search || '');
    if (next && next !== '/') {
      location.replace('/login?next=' + encodeURIComponent(next));
    } else {
      location.replace('/login');
    }
  } catch (e) {
    location.replace('/login');
  }
})();
</script>"""

# Trial bundle must not inherit the dashboard service worker (stale 8MB cache).
TRIAL_SW_UNREGISTER = """<script id="trial-sw-unregister">
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(function (regs) {
    regs.forEach(function (r) { r.unregister(); });
  });
}
</script>"""


def patch_trial_asset_paths(html: str) -> str:
    """Use a dedicated CSS path so trial styles never collide with dashboard tailwind.out.css."""
    import re

    html = html.replace('href="/tailwind.out.css"', 'href="/trial-tailwind.css"')
    # CSS integrity goes stale when tailwind is rebuilt — drop SRI on the trial stylesheet.
    html = re.sub(
        r'(<link rel="stylesheet" href="/trial-tailwind\.css") integrity="[^"]+"',
        r"\1",
        html,
    )
    # JS/WASM SRI also goes stale after wasm-opt — drop on trial preloads.
    html = re.sub(
        r'(<link[^>]*(?:modulepreload|preload)[^>]*href="/connector-trial[^"]*"[^>]*?) integrity="[^"]+"',
        r"\1",
        html,
    )
    return html
