// MUFE 백신 Service Worker — 캐시 박힘 X 자리
// 옛 캐시 박힌 자리 = 영원히 자기 정리 박음

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    // 모든 옛 캐시 통째로 박힘 X
    const keys = await caches.keys();
    await Promise.all(keys.map(k => caches.delete(k)));
    // 자기 자신도 박힘 X (다음 박힘에서 SW 새로 박음)
    const regs = await self.registration.unregister();
    await self.clients.claim();
  })());
});

// fetch 박힘 X = 네트워크 박은 자리 그대로 (캐시 박힘 X)
self.addEventListener('fetch', (event) => {
  // 박지 않음 - 브라우저가 직접 박음
});
