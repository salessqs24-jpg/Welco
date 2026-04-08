const CACHE_NAME = 'welco-v3';
const OFFLINE_ASSETS = [
  '/staff.html',
  '/guest.html',
  '/hod.html',
  '/admin.html',
  '/manifest.json',
  '/manifest-admin.json',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
  'https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.page.js'
];

// Install — cache all key assets
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(OFFLINE_ASSETS.filter(function(url) {
        return !url.includes('onesignal'); // skip external that may block
      }));
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// Activate — clean old caches
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k){ return k !== CACHE_NAME; })
          .map(function(k){ return caches.delete(k); })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch strategy:
// - HTML pages: Network first, fallback to cache (so staff always get fresh data if online)
// - API requests: Network only (no caching live data)
// - Static assets: Cache first (fast loading)
self.addEventListener('fetch', function(e) {
  var url = e.request.url;

  // Skip non-GET requests
  if (e.request.method !== 'GET') return;

  // Skip API calls — always need live data
  if (url.includes('/requests') || url.includes('/staff') || url.includes('/hotels') ||
      url.includes('/rooms') || url.includes('/announcements') || url.includes('/hod') ||
      url.includes('/maintenance')) {
    e.respondWith(
      fetch(e.request).catch(function() {
        // Return empty array for API calls when offline
        return new Response(JSON.stringify([]), {
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // HTML pages — Network first, fallback to cache
  if (url.includes('.html') || url.endsWith('/')) {
    e.respondWith(
      fetch(e.request)
        .then(function(response) {
          // Cache the fresh version
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(e.request, clone);
          });
          return response;
        })
        .catch(function() {
          // Offline — serve from cache
          return caches.match(e.request).then(function(cached) {
            if (cached) return cached;
            // Return offline page
            return new Response(getOfflinePage(), {
              headers: { 'Content-Type': 'text/html' }
            });
          });
        })
    );
    return;
  }

  // Static assets (JS, CSS, images) — Cache first
  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;
      return fetch(e.request).then(function(response) {
        var clone = response.clone();
        caches.open(CACHE_NAME).then(function(cache) {
          cache.put(e.request, clone);
        });
        return response;
      }).catch(function() {
        return new Response('', { status: 404 });
      });
    })
  );
});

// Push notification handler (OneSignal)
self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data.json(); } catch(err) { data = { title: '🔔 New Request', body: 'A guest needs help!' }; }
  e.waitUntil(
    self.registration.showNotification(data.title || '🔔 New Request', {
      body: data.body || 'A guest needs help!',
      icon: '/favicon.ico',
      badge: '/favicon.ico',
      vibrate: [200, 100, 200],
      tag: 'welco-request',
      renotify: true,
      data: { url: '/staff.html' }
    })
  );
});

// Notification click — open staff dashboard
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then(function(clientList) {
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.includes('staff.html') && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow('/staff.html');
    })
  );
});

function getOfflinePage() {
  return '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welco — Offline</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;min-height:100vh;background:linear-gradient(160deg,#005f73,#0a9396);display:flex;align-items:center;justify-content:center;color:white;text-align:center;padding:24px}.wrap{max-width:320px}.icon{font-size:64px;margin-bottom:16px}.title{font-size:24px;font-weight:700;margin-bottom:8px}.sub{font-size:14px;opacity:.7;line-height:1.6;margin-bottom:24px}.btn{padding:14px 28px;background:white;color:#005f73;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer}';
  }