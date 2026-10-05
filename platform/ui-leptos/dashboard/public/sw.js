// Connector Dashboard — Service Worker
// WASM releases are manifest-versioned; do NOT cache JS/WASM/CSS here until
// the service worker pre-cache list is generated from asset-manifest.json.
// This worker only provides offline shell hints and clears legacy caches.

const CACHE_NAME = '__RELEASE_ID__';
const NO_CACHE_PATTERNS = [/\.wasm$/, /\.js$/, /\.css$/, /^\/__wasm_split/, /^\/split_/, /^\/chunk_/];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(Promise.resolve());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  const skipCache = NO_CACHE_PATTERNS.some((p) => p.test(url.pathname));
  if (skipCache) {
    event.respondWith(fetch(event.request));
    return;
  }

  // HTML: network-first only (no cache write for now)
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
