/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — Service Worker
 *  
 *  전략:
 *  - index.html: Network-First (항상 최신 받음 → 새 버전 즉시 반영)
 *  - 아이콘·정적 자산: Cache-First (빠른 로드)
 *  - 새 SW 감지 시: 자동 즉시 갱신 (사용자 새로고침 불필요)
 * ════════════════════════════════════════════════════════════════
 */

const CACHE_VERSION = 'mufe-c33-v1.27.0';

// 캐시할 정적 자산만 (index.html은 *제외* — 항상 네트워크)
const STATIC_ASSETS = [
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './icon-180.png',
  './favicon-32.png'
];

// 설치 — 정적 자산만 캐시 + 즉시 활성
self.addEventListener('install', event => {
  console.log('[MUFE SW] 설치:', CACHE_VERSION);
  event.waitUntil(
    caches.open(CACHE_VERSION).then(cache => {
      return cache.addAll(STATIC_ASSETS).catch(err => {
        console.warn('[MUFE SW] 일부 자산 캐시 실패:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// 활성화 — 옛 캐시 모두 정리 + 즉시 모든 페이지 제어
self.addEventListener('activate', event => {
  console.log('[MUFE SW] 활성화:', CACHE_VERSION);
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key.startsWith('mufe-') && key !== CACHE_VERSION)
          .map(oldKey => {
            console.log('[MUFE SW] 옛 캐시 삭제:', oldKey);
            return caches.delete(oldKey);
          })
      ))
      .then(() => self.clients.claim())
      .then(() => {
        // 모든 활성 클라이언트에 새 버전 알림
        return self.clients.matchAll({ type: 'window' }).then(clients => {
          clients.forEach(client => {
            client.postMessage({ type: 'SW_UPDATED', version: CACHE_VERSION });
          });
        });
      })
  );
});

// fetch — Network-First (HTML) / Cache-First (정적)
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  
  const url = new URL(event.request.url);
  if (url.origin !== location.origin) return;
  
  // Netlify Functions는 절대 캐시하지 않음 — 항상 네트워크
  if (url.pathname.includes('/.netlify/functions/')) return;
  
  // HTML 페이지 — Network-First
  if (event.request.mode === 'navigate' || 
      event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // 성공 시 응답 그대로 반환 (캐시 안 함)
          return response;
        })
        .catch(() => {
          // 오프라인일 때만 캐시 fallback
          return caches.match('./index.html').then(c => c || new Response('오프라인'));
        })
    );
    return;
  }
  
  // 정적 자산 — Cache-First
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_VERSION).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});

self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
