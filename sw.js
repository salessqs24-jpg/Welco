const CACHE_NAME = 'welco-v4';

const OFFLINE_ASSETS = [
  '/staff.html',
  '/guest.html',
  '/hod.html',
  '/admin.html',
  '/index.html',
  '/manifest.json',
  '/manifest-admin.json'
];

// Install — pre-cache all key pages
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return Promise.allSettled(
        OFFLINE_ASSETS.map(function(url) {
          return cache.add(url).catch(function(err) {
            console.log('Failed to cache:', url, err);
          });
        })
      );
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// Activate — delete old caches
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE_NAME; })
            .map(function(k) { return caches.delete(k); })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch — smart caching strategy
self.addEventListener('fetch', function(e) {
  var url = e.request.url;

  // Only handle GET requests
  if (e.request.method !== 'GET') return;

  // Skip cross-origin except CDN
  if (!url.startsWith(self.location.origin) && !url.includes('cdn.jsdelivr') && !url.includes('fonts.googleapis')) return;

  // API calls — network only, return empty array if offline
  var apiPaths = ['/requests', '/staff', '/hotels', '/rooms', '/announcements', '/hod', '/maintenance'];
  var isApi = apiPaths.some(function(p) { return url.includes(p); });
  if (isApi) {
    e.respondWith(
      fetch(e.request).catch(function() {
        return new Response('[]', { headers: { 'Content-Type': 'application/json' } });
      })
    );
    return;
  }

  // HTML pages — Network first, cache fallback
  if (url.includes('.html') || url.endsWith('/')) {
    e.respondWith(
      fetch(e.request)
        .then(function(response) {
          if (response && response.status === 200) {
            var clone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) { cache.put(e.request, clone); });
          }
          return response;
        })
        .catch(function() {
          return caches.match(e.request).then(function(cached) {
            if (cached) return cached;
            // Show Welco offline page
            return new Response(OFFLINE_HTML, { headers: { 'Content-Type': 'text/html' } });
          });
        })
    );
    return;
  }

  // Everything else — Cache first, network fallback
  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;
      return fetch(e.request).then(function(response) {
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) { cache.put(e.request, clone); });
        }
        return response;
      }).catch(function() {
        return new Response('', { status: 408 });
      });
    })
  );
});

// Push notification
self.addEventListener('push', function(e) {
  var data = { title: '🔔 New Request', body: 'A guest needs help!' };
  try { data = e.data.json(); } catch(err) {}
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/favicon.ico',
      vibrate: [200, 100, 200],
      tag: 'welco-request',
      renotify: true
    })
  );
});

// Notification click
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then(function(list) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].url.includes('staff.html') && 'focus' in list[i]) return list[i].focus();
      }
      if (clients.openWindow) return clients.openWindow('/staff.html');
    })
  );
});

var OFFLINE_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welco \u2014 Offline</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:sans-serif;min-height:100vh;background:linear-gradient(160deg,#005f73,#0a9396);display:flex;align-items:center;justify-content:center;color:white;text-align:center;padding:24px}.wrap{max-width:320px}.icon{font-size:64px;margin-bottom:20px}.title{font-size:26px;font-weight:700;margin-bottom:10px}.sub{font-size:14px;opacity:.75;line-height:1.7;margin-bottom:28px}.btn{padding:14px 32px;background:white;color:#005f73;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;transition:opacity .2s}.btn:hover{opacity:.9}.note{font-size:12px;opacity:.55;margin-top:20px}</style></head><body><div class="wrap"><div class="icon">📶</div><h1 class="title">You\'re offline</h1><p class="sub">No internet connection. Please check your WiFi or mobile data and try again.</p><button class="btn" onclick="window.location.reload()">Try Again</button><p class="note">Welco \u00b7 Hotel Guest Services</p></div></body></html>';