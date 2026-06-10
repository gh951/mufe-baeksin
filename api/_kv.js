/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — Vercel KV 박음 (Upstash Redis)
 *
 *  무료 자리:
 *   - 위임 토큰 1회용 추적 박힘
 *   - 격리 통계 영구 박힘
 *   - 사용자 비번 기기 간 동기화 (선택)
 *   - 서버 금고(vault) · 양자 도장(proof) 저장
 *
 *  Vercel 대시보드:
 *   1. Storage → Upstash for Redis 연결 (프로젝트에 Connect)
 *   2. 환경 변수 자동 박힘 — 이름이 둘 중 하나일 수 있음:
 *        · KV_REST_API_URL / KV_REST_API_TOKEN          (예전 Vercel KV 식)
 *        · UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN (새 Upstash 마켓플레이스 식)
 *      → [수정] 아래에서 두 이름을 *모두* 인식하게 함. 연결 후 재배포 1회 필요.
 *
 *  KV 없으면 조용히 없음 — 작동에 영향 X
 * ════════════════════════════════════════════════════════════════
 */

// [수정] Vercel(KV_REST_API_*) 이름과 Upstash 마켓플레이스(UPSTASH_REDIS_REST_*) 이름 둘 다 인식
const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

const isKVAvailable = () => Boolean(KV_URL && KV_TOKEN);

/**
 * KV에 값 박음
 * @param {string} key
 * @param {any} value
 * @param {number} ttlSeconds — 만료 시간 (선택)
 */
async function kvSet(key, value, ttlSeconds = null) {
  if (!isKVAvailable()) return { ok: false, reason: 'no-kv' };

  try {
    const url = ttlSeconds
      ? `${KV_URL}/set/${encodeURIComponent(key)}?EX=${ttlSeconds}`
      : `${KV_URL}/set/${encodeURIComponent(key)}`;

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${KV_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(value),
    });

    if (!res.ok) return { ok: false, reason: `http-${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/**
 * KV에서 값 박음
 * @param {string} key
 * @returns {any|null}
 */
async function kvGet(key) {
  if (!isKVAvailable()) return null;

  try {
    const res = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
      headers: { 'Authorization': `Bearer ${KV_TOKEN}` },
    });

    if (!res.ok) return null;
    const data = await res.json();
    if (!data.result) return null;

    // Upstash JSON parse
    try { return JSON.parse(data.result); }
    catch { return data.result; }
  } catch {
    return null;
  }
}

/**
 * KV에서 키 박힘 X
 */
async function kvDel(key) {
  if (!isKVAvailable()) return { ok: false };

  try {
    const res = await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${KV_TOKEN}` },
    });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}

/**
 * KV 카운터 박음 (통계용)
 * @param {string} key
 * @returns {number} 새 값
 */
async function kvIncr(key) {
  if (!isKVAvailable()) return -1;

  try {
    const res = await fetch(`${KV_URL}/incr/${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${KV_TOKEN}` },
    });

    if (!res.ok) return -1;
    const data = await res.json();
    return data.result || 0;
  } catch {
    return -1;
  }
}

module.exports = {
  isKVAvailable,
  kvSet,
  kvGet,
  kvDel,
  kvIncr,
};
