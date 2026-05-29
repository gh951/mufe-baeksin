// MUFE 백신 Service Worker — 완전 자가 해제
// 옛 캐시 + 옛 SW 모두 박힘 X 처리

self.addEventListener('install', (event) => {
  // skipWaiting 박음 → 즉시 activate
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      try {
        // 1. 모든 캐시 박힘 X
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(name => caches.delete(name)));
        
        // 2. claim 박음 (활성화 *직후* — 박힘 X 박지 않음)
        await self.clients.claim();
        
        // 3. 모든 클라이언트에 새로고침 신호 박음
        const clients = await self.clients.matchAll({ 
          type: 'window',
          includeUncontrolled: true 
        });
        clients.forEach(client => {
          try {
            client.postMessage({ type: 'SW_CLEARED' });
          } catch (e) {}
        });
        
        // 4. SW 자체 해제 (다음 페이지 로드 시 SW 없음)
        // claim 박은 *후* unregister 박음 (순서 중요)
        await self.registration.unregister();
        
      } catch (e) {
        // 박힘 X — 다음 로드에서 재시도
      }
    })()
  );
});

// fetch 핸들러 박지 않음 — no-op 경고 박힘 X
// 브라우저가 네트워크 직접 박음 (캐시 우회)

// message 핸들러 — 클라이언트에서 강제 정리 요청 박는 자리
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'FORCE_CLEAR') {
    event.waitUntil(
      (async () => {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(name => caches.delete(name)));
        await self.registration.unregister();
      })()
    );
  }
});
