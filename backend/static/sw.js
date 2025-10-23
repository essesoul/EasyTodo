/* eslint-disable no-restricted-globals */
const STATIC_CACHE = 'easytodo-static-v2';
const PAGES_CACHE = 'easytodo-pages-v1';
const OFFLINE_URL = '/static/offline.html';
const PRECACHE_URLS = [
  OFFLINE_URL,
  '/static/css/global.css',
  '/static/js/theme.js',
  '/static/js/pwa.js',
  '/static/favicon.svg',
  '/static/manifest.webmanifest',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(PRECACHE_URLS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => {
      if (k !== STATIC_CACHE && k !== PAGES_CACHE) return caches.delete(k);
    }))).then(() => self.clients.claim())
  );
});

function isSameOrigin(url) {
  try { const u = new URL(url, self.location.href); return u.origin === self.location.origin; } catch { return false; }
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle GET
  if (req.method !== 'GET') return;

  // Navigation handling
  if (req.mode === 'navigate') {
    // Special case: homepage supports offline app shell
    if (url.origin === location.origin && url.pathname === '/') {
      event.respondWith((async () => {
        try {
          const net = await fetch(req);
          if (net && net.ok) {
            const copy = net.clone();
            caches.open(PAGES_CACHE).then((c) => c.put('/', copy)).catch(() => {});
            // Notify clients that page cache is refreshed
            try {
              const all = await self.clients.matchAll();
              all.forEach((cl) => cl.postMessage({ type: 'PAGE_CACHE_REFRESHED', at: Date.now() }));
            } catch (_) {}
          }
          return net;
        } catch (_) {
          const cached = await caches.open(PAGES_CACHE).then((c) => c.match('/'));
          return cached || caches.match(OFFLINE_URL);
        }
      })());
      return;
    }
    // Other navigations: network-first, fallback offline page
    event.respondWith(
      fetch(req).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }

  // Same-origin static assets: cache-first
  if (isSameOrigin(url) && (url.pathname.startsWith('/static/'))) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const fetchPromise = fetch(req).then((resp) => {
          const clone = resp.clone();
          if (resp && resp.ok) {
            caches.open(STATIC_CACHE).then((cache) => cache.put(req, clone)).catch(() => {});
          }
          return resp;
        }).catch(() => cached);
        return cached || fetchPromise;
      })
    );
    return;
  }

  // Default: pass through (API/cross-origin)
});

// Allow the app to request clearing cached home page after logout
self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data && data.type === 'CLEAR_PAGE_CACHE') {
    event.waitUntil((async () => {
      try {
        const cache = await caches.open(PAGES_CACHE);
        await cache.delete('/');
      } catch (_) {}
    })());
  } else if (data && data.type === 'LOGOUT_CLEAR_CACHES_KEEP_OFFLINE') {
    // Clear all runtime caches except keep the offline page in static cache
    event.waitUntil((async () => {
      try {
        // 1) Clear page shell cache entirely
        try {
          const pc = await caches.open(PAGES_CACHE);
          const keys = await pc.keys();
          await Promise.all(keys.map((req) => pc.delete(req)));
        } catch (_) {}

        // 2) In static cache, keep only OFFLINE_URL and minimal style for readable offline page
        try {
          const sc = await caches.open(STATIC_CACHE);
          const keys = await sc.keys();
          await Promise.all(keys.map(async (req) => {
            // Keep the offline document only
            const url = new URL(req.url);
            const keep = (url.pathname === OFFLINE_URL) || (url.pathname === '/static/css/global.css');
            if (!keep) {
              await sc.delete(req);
            }
          }));
          // Ensure offline page exists (re-add if missing)
          const hasOffline = await sc.match(OFFLINE_URL);
          if (!hasOffline) {
            try { await sc.add(OFFLINE_URL); } catch (_) {}
          }
          // Ensure minimal CSS exists (re-add if missing)
          const hasCss = await sc.match('/static/css/global.css');
          if (!hasCss) {
            try { await sc.add('/static/css/global.css'); } catch (_) {}
          }
        } catch (_) {}
      } catch (_) {}
    })());
  } else if (data && data.type === 'REFRESH_PAGE_CACHE') {
    // Force refresh of homepage shell and core static assets
    event.waitUntil((async () => {
      try {
        // Refresh homepage shell
        try {
          const resp = await fetch('/', { cache: 'reload' });
          if (resp && resp.ok) {
            const pc = await caches.open(PAGES_CACHE);
            await pc.put('/', resp.clone());
          }
        } catch (_) {}

        // Refresh core static assets
        try {
          const sc = await caches.open(STATIC_CACHE);
          for (const url of PRECACHE_URLS) {
            try {
              const r = await fetch(url, { cache: 'reload' });
              if (r && r.ok) await sc.put(url, r.clone());
            } catch (_) {}
          }
        } catch (_) {}

        // Notify clients
        try {
          const all = await self.clients.matchAll();
          all.forEach((cl) => cl.postMessage({ type: 'PAGE_CACHE_REFRESHED', at: Date.now() }));
        } catch (_) {}
      } catch (_) {}
    })());
  }
});
