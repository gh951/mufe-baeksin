/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 서버 금고 (금고 A / 로드맵 적용순서 3번)
 *
 *  원리: "민감 내용은 폰에 두지 않는다. 서버가 인증 확인 후에만 내려준다."
 *
 *   - verify.js 가 인증 성공 시 내주는 *서버 HMAC 서명 토큰*(mufe.<...>.<sig>,
 *     type:'real') 을 그대로 증표로 씀. 위조 불가(서버 SECRET 없이는 서명 못 함).
 *   - 진짜 토큰  → 진짜 금고 내용 내려줌 / 저장 받음
 *   - 미끼 토큰  → *가짜 금고* 내려줌 (차단 X, 기만 격리 — 모토 그대로)
 *   - 토큰 없음/위조/만료 → 잠김 (아무것도 안 내려줌)
 *
 *   ⚠ 절대 안전이 아니라 "서버가 인증 전에는 내용을 주지 않는다" 한 겹.
 *     하드웨어급 봉인은 Phase 2(네이티브·TEE).
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const { kvGet, kvSet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET;   // [C-53] 기본키 fallback 제거 — 없으면 거부(조용한 약화 방지)
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;   // 세션 토큰 신선도 24시간
const MAX_CONTENT  = 16384;                  // 금고 내용 최대 16KB (E2E 암호화 블롭 여유 포함)

// verify.js 와 *완전히 동일한* 서명 (절대 바꾸면 안 됨 — 토큰 호환)
function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

// verify.js 의 verifyToken 과 동일 — 서명/형식 검증 후 페이로드 반환
function verifyToken(token, prefix) {
  if (!token || typeof token !== 'string' || !token.startsWith(prefix + '.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payloadB64, signature] = parts;
  if (sign(payloadB64) !== signature) return null;
  try {
    return JSON.parse(Buffer.from(payloadB64, 'base64').toString());
  } catch {
    return null;
  }
}

// 사용자별 *안정* 금고 키 — 비번을 그대로 키에 쓰지 않고 HMAC 으로 가림
function vaultKeyFor(userData) {
  const basis = (userData.passcode || '') + '|' + (userData.format || userData.spacing || '');
  return 'vault:' + sign('vault-user|' + basis);
}

// 미끼 토큰 보유자에게 내려줄 *가짜 금고* (진짜처럼 보이지만 무의미한 잡음)
function decoyVault() {
  return {
    content: '',
    items: Array.from({ length: 3 }, () => ({
      id: crypto.randomBytes(6).toString('hex'),
      v: crypto.randomBytes(48).toString('base64'),
    })),
    updatedAt: Date.now() - Math.floor(Math.random() * 1e7),
  };
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ status: 'locked', error: 'Method not allowed' });
  if (!SECRET) return res.status(500).json({ status: 'error', error: 'server-misconfigured' });

  try {
    const { token, userToken, action, content } = req.body || {};

    // ① 이번 세션 인증 증표 = verify.js 가 내준 진짜 토큰
    const auth = verifyToken(token, 'mufe');

    // 토큰 없음/위조 → 잠김 (금고는 아무것도 안 내려줌)
    if (!auth) {
      if (isKVAvailable()) await kvIncr('stats:vault:locked-no-token');
      return res.status(200).json({ status: 'locked', message: '금고 잠김 — 인증이 필요합니다' });
    }

    // 세션 만료
    if (!auth.issuedAt || (Date.now() - auth.issuedAt) > TOKEN_TTL_MS) {
      return res.status(200).json({ status: 'locked', message: '금고 잠김 — 세션이 만료됐어요. 다시 인증하세요' });
    }

    // ② 미끼 토큰 보유자 → 가짜 금고 내려줌 (차단 X, 기만)
    if (auth.type !== 'real') {
      if (isKVAvailable()) await kvIncr('stats:vault:decoy-served');
      return res.status(200).json({ status: 'unlocked', vault: decoyVault(), decoy: true });
    }

    // ③ 진짜 인증 통과 — 금고 키 정하기
    let key;
    if (auth.vk) {
      // 고보안(양자 도장): 토큰에 *서명되어 박힌* 기준으로 금고 키 — 위조 불가(서버 SECRET 서명).
      //   신원 토큰(mufe-u) 없이도 동작 → 비번 서버 미전송 철학 유지.
      key = 'vault:' + sign('vault-pq|' + auth.vk);
    } else {
      // 간편: 신원 토큰(mufe-u)에서 안정적 키
      const userData = verifyToken(userToken, 'mufe-u');
      if (!userData) {
        return res.status(200).json({ status: 'locked', message: '금고 잠김 — 신원 확인 실패' });
      }
      key = vaultKeyFor(userData);
    }

    // ── 저장 ──
    if (action === 'set') {
      const c = typeof content === 'string' ? content.slice(0, MAX_CONTENT) : '';
      if (!isKVAvailable()) {
        return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결 — 저장 불가' });
      }
      const record = { content: c, updatedAt: Date.now() };
      await kvSet(key, record);
      await kvIncr('stats:vault:set');
      return res.status(200).json({ status: 'saved', updatedAt: record.updatedAt });
    }

    // ── 읽기 (기본) ──
    if (!isKVAvailable()) {
      return res.status(200).json({ status: 'unlocked', vault: { content: '', updatedAt: null }, message: '서버 저장소(KV) 미연결' });
    }
    await kvIncr('stats:vault:get');
    const record = await kvGet(key);
    return res.status(200).json({ status: 'unlocked', vault: record || { content: '', updatedAt: null } });

  } catch (err) {
    return res.status(500).json({ status: 'error', detail: err.message });
  }
};
