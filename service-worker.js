/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 서비스 워커 (네트워크 우선 + 자가 치유)
 *
 *  핵심: 새 SW가 잡히면 옛날 캐시를 싹 지우고, 열린 화면을 즉시
 *        강제 새로고침한다. → "옛날 화면이 계속 뜨는" 문제를 끝낸다.
 *  온라인이면 항상 서버에서 최신 화면. 오프라인일 때만 마지막 캐시.
 *  ※ 이 파일을 바꿔서 배포해야 폰의 옛날 SW가 새 걸로 교체된다.
 * ════════════════════════════════════════════════════════════════
 */

const CACHE = 'mufe-net-first-0611o';

// 설치 — 바로 대기 끝내고 새 워커 활성화
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// 활성화 — 옛날 캐시 전부 삭제 → 즉시 제어 → 열린 화면 강제 새로고침
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));   // 캐시 전부 비움
    } catch (e) { /* 무시 */ }
    await self.clients.claim();
    try {
      const cs = await self.clients.matchAll({ type: 'window' });
      cs.forEach((c) => { try { c.navigate(c.url); } catch (e) {} });  // 자동 새로고침
    } catch (e) { /* 무시 */ }
  })());
});

// 클라이언트가 SKIP_WAITING 보내면 즉시 활성화
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// 요청 처리 — 네트워크 우선, 실패(오프라인) 시에만 캐시
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  // API는 절대 캐시하지 않음 — 항상 서버로 직접
  try {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) return;
  } catch (e) { /* 무시 */ }

  event.respondWith((async () => {
    try {
      const fresh = await fetch(req);
      try {
        if (fresh && fresh.status === 200 && fresh.type === 'basic') {
          const cache = await caches.open(CACHE);
          cache.put(req, fresh.clone());
        }
      } catch (e) { /* 무시 */ }
      return fresh;
    } catch (err) {
      const cached = await caches.match(req);
      if (cached) return cached;
      throw err;
    }
  })());
});
