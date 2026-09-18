// ---------------------------------------------------------------------------
// Find My Friend — Service Worker
//
// Strategy per resource type:
//   - App shell (/, map.html, login.html, manifest.json, icon.svg):
//       network-first, falling back to cache.
//   - Static libraries (Leaflet CSS/JS, Socket.IO client JS):
//       cache-first, refreshed in the background.
//   - /api/*, /socket.io/*, account routes: NEVER cached (private/live data).
//   - Reverse geocoding (Nominatim): NEVER cached here — map.html already
//       keeps its own localStorage address cache, which is a better fit
//       than the Cache API for small, per-coordinate lookups.
//   - Map tiles (Esri): bounded, evicted runtime cache (see note below).
// ---------------------------------------------------------------------------
//
// CHANGED THIS PASS: the previous version deliberately did NOT cache map
// tiles at all, citing Esri's terms of service around redistributing/
// caching their imagery. That's a real consideration, but it also meant
// the map went completely blank the moment the network dropped — a bad
// outcome for an app whose whole point is working on a flaky university
// network. The trade-off made here: cache tiles the device has ALREADY
// downloaded, capped at a small number of entries (roughly enough to cover
// the campus at the zoom levels people actually use), evicted oldest-first.
// This keeps storage bounded and only ever serves tiles that were fetched
// live in the first place — but it does not make this fully compliant with
// every possible tile-provider license. If this app is ever deployed
// beyond a single small campus, replace the Esri layer with a self-hosted
// tile server (e.g. from downloaded MBTiles) instead of relying on this
// cache.
// ---------------------------------------------------------------------------

const CACHE_VERSION = 'fmf-cache-v3';
const TILE_CACHE = 'fmf-tiles-v1';
const MAX_TILE_ENTRIES = 300; // enough for the campus area across a few zoom levels

const APP_SHELL = [
  '/',
  '/map.html',
  '/login.html',
  '/manifest.json',
  '/icon.svg'
];
const STATIC_LIB_HOSTS = ['cdnjs.cloudflare.com'];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => {
      return Promise.all(
        APP_SHELL.map((url) =>
          cache.add(url).catch((err) => console.warn('SW: could not precache', url, err.message))
        )
      );
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_VERSION && key !== TILE_CACHE)
          .map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

function isApiOrAccountRoute(url) {
  return url.pathname.startsWith('/api/') ||
         url.pathname.startsWith('/socket.io/') ||
         url.pathname === '/update-account' ||
         url.pathname === '/delete-account';
}

function isMapTile(url) {
  return url.hostname.endsWith('arcgisonline.com');
}

function isReverseGeocode(url) {
  return url.hostname.endsWith('nominatim.openstreetmap.org');
}

function isStaticLib(url) {
  return STATIC_LIB_HOSTS.includes(url.hostname);
}

function isNavigation(request) {
  return request.mode === 'navigate' ||
         (request.method === 'GET' && request.headers.get('accept')?.includes('text/html'));
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE_VERSION);
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) cache.put(request, fresh.clone());
    return fresh;
  } catch (err) {
    const cached = await cache.match(request);
    if (cached) return cached;
    if (isNavigation(request)) {
      const shell = await cache.match('/map.html');
      if (shell) return shell;
    }
    throw err;
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_VERSION);
  const cached = await cache.match(request);
  const networkPromise = fetch(request)
    .then((response) => {
      if (response && response.ok) cache.put(request, response.clone());
      return response;
    })
    .catch(() => null);

  return cached || (await networkPromise) || Response.error();
}

// Bounded, FIFO-evicted cache for map tiles: serve fresh when online (and
// remember it), fall back to whatever was previously cached when offline.
async function tileNetworkFirst(request) {
  const cache = await caches.open(TILE_CACHE);
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) {
      cache.put(request, fresh.clone());
      const keys = await cache.keys();
      if (keys.length > MAX_TILE_ENTRIES) {
        await cache.delete(keys[0]); // oldest entry first
      }
    }
    return fresh;
  } catch (err) {
    const cached = await cache.match(request);
    if (cached) return cached;
    throw err;
  }
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  if (isApiOrAccountRoute(url)) {
    event.respondWith(
      fetch(request).catch(() =>
        new Response(
          JSON.stringify({ error: 'offline', message: 'Server unreachable — check your connection' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );
    return;
  }

  if (isReverseGeocode(url)) {
    event.respondWith(fetch(request)); // deliberately not cached here — see note above
    return;
  }

  if (isMapTile(url)) {
    event.respondWith(tileNetworkFirst(request));
    return;
  }

  if (isStaticLib(url)) {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  if (url.origin === self.location.origin) {
    event.respondWith(networkFirst(request));
    return;
  }

  event.respondWith(fetch(request).catch(() => caches.match(request)));
});
