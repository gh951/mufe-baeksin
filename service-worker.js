/* ════════════════════════════════════════════════════════════
 *  MUFE 백신 — 서비스 워커 (PWA)
 *  · index.html 과 같은 폴더(웹 루트)에 올리면 됩니다.
 *  · 오프라인에서도 앱이 열리도록 핵심 파일을 캐시합니다.
 *  · 새 버전이 올라오면 자동으로 감지·갱신합니다.
 * ════════════════════════════════════════════════════════════ */

const MUFE_CACHE = 'mufe-baeksin-v1';

// 캐시할 핵심 파일 (있는 것만 — 없어도 등록 실패 안 함)
const CORE_ASSETS = [
  './',
  './index.html',
  './mufe_bridge.js',
  './mufe_core.js',
  './mufe_core.wasm',
];

// 설치 — 핵심 파일 캐시 (개별 실패는 무시)
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(MUFE_CACHE).then((cache) =>
      Promise.all(
        CORE_ASSETS.map((url) =>
          cache.add(url).catch(() => {
            /* 파일이 아직 없어도 등록은 성공시킴 */
          })
        )
      )
    )
  );
  // 새 워커 즉시 대기 해제 (index.html의 SKIP_WAITING과 연동)
  self.skipWaiting();
});

// 활성화 — 옛 캐시 정리
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== MUFE_CACHE).map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// fetch — 네트워크 우선, 실패 시 캐시 (항상 최신 우선, 오프라인 대비)
self.addEventListener('fetch', (event) => {
  const req = event.request;
  // GET 요청만 처리 (POST 인증 요청 등은 그대로 통과)
  if (req.method !== 'GET') return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        // 성공 시 캐시 갱신 (동일 출처만)
        if (res && res.status === 200 && req.url.startsWith(self.location.origin)) {
          const copy = res.clone();
          caches.open(MUFE_CACHE).then((cache) => cache.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req)) // 오프라인이면 캐시에서
  );
});

// index.html에서 SKIP_WAITING 메시지 받으면 즉시 활성화
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
