/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 서비스 워커 (네트워크 우선)
 *
 *  핵심: 온라인이면 *항상 서버에서 최신 화면*을 가져온다.
 *        → 새로 배포하면 정상 경로(앱·일반 브라우저)에서 바로 반영됨.
 *        → "옛날 화면이 계속 뜨는" 캐시 문제 해결. (시크릿 탭 불필요)
 *  오프라인일 때만 마지막으로 받은 화면을 캐시에서 보여준다.
 * ════════════════════════════════════════════════════════════════
 */

const CACHE = 'mufe-net-first-0610k';

// 설치 — 바로 대기 끝내고 새 워커 활성화
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// 활성화 — 옛날 캐시 싹 비우고, 즉시 모든 탭 제어
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => (k !== CACHE ? caches.delete(k) : Promise.resolve())));
    } catch (e) { /* 무시 */ }
    await self.clients.claim();
  })());
});

// 클라이언트가 SKIP_WAITING 보내면 즉시 활성화 (index.html의 업데이트 로직과 호응)
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// 요청 처리 — 네트워크 우선, 실패(오프라인) 시에만 캐시
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // GET만 다룬다. API(POST 등)·다른 메서드는 건드리지 않음 (서버 인증·금고 흐름 보호)
  if (req.method !== 'GET') return;

  // API 호출은 절대 캐시하지 않음 — 항상 서버로 직접
  try {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) return;
  } catch (e) { /* 무시 */ }

  event.respondWith((async () => {
    try {
      // 1) 네트워크에서 최신 가져오기
      const fresh = await fetch(req);
      // 2) 성공하면 캐시에 사본 저장 (오프라인 대비)
      try {
        if (fresh && fresh.status === 200 && fresh.type === 'basic') {
          const cache = await caches.open(CACHE);
          cache.put(req, fresh.clone());
        }
      } catch (e) { /* 캐시 실패해도 무시 */ }
      return fresh;
    } catch (err) {
      // 3) 네트워크 안 되면(오프라인) 마지막 캐시
      const cached = await caches.match(req);
      if (cached) return cached;
      throw err;
    }
  })());
});
