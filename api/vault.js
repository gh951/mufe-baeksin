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
// [#7 at-rest] 서버 저장 시 한 겹 더 암호화 — DB(KV)가 탈취돼도 서버 SECRET 없으면 내용을 못 봄.
//   E2E와는 별개 층: E2E는 서버도 못 봄(#8까지), at-rest는 외부 DB탈취 방어(#7). 옛 평문·가짜 금고는 접두 없으면 그대로 통과.
function atRestKey() { return crypto.createHash('sha256').update('vault-atrest|v1|' + SECRET).digest(); }
function encContent(plain) {
  try {
    if (typeof plain !== 'string' || plain === '') return plain;
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', atRestKey(), iv);
    const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return 'v1g:' + Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
  } catch (e) { return plain; }
}
function decContent(stored) {
  try {
    if (typeof stored !== 'string' || !stored.startsWith('v1g:')) return stored;
    const buf = Buffer.from(stored.slice(4), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', atRestKey(), buf.slice(0, 12));
    d.setAuthTag(buf.slice(12, 28));
    return Buffer.concat([d.update(buf.slice(28)), d.final()]).toString('utf8');
  } catch (e) { return stored; }
}
// [은닉 마커 검증] verify.js 와 동일 — payload.m 이 'decoy' 마커인지 서버 SECRET만으로 판별(KV 불필요)
function isDecoyToken(p) {
  return !!(p && p.sessionId && p.m && p.m === sign(p.sessionId + ':decoy'));
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
  // 진짜 금고처럼 보이는 가짜. 해커가 항목을 풀어보면(base64 디코드) 끝에 C-55의 흔적을 본다.
  const items = Array.from({ length: 4 }, () => ({
    id: crypto.randomBytes(6).toString('hex'),
    v: crypto.randomBytes(48).toString('base64'),
  }));
  // 함정 서명 — 겉 목록에선 다른 항목과 구별 안 되지만, 풀어보면 'C-55의 덫'이 드러남
  items.push({
    id: crypto.randomBytes(6).toString('hex'),
    v: Buffer.from(JSON.stringify({ trapped: true, by: 'C-55', note: 'MUFE honeypot — this vault is fake. Your access is logged.' })).toString('base64'),
  });
  return {
    content: '',
    items: items,
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

    // ② 미끼 토큰 보유자 → 가짜 금고 내려줌 (차단 X, 연산지옥 기만)
    //   [허니토큰] type이 위장돼도 잡게: 서버 금고(honey KV)도 조회. 둘 중 하나라도 덫이면 가짜.
    let _isHoney = isDecoyToken(auth) || (auth.type !== 'real');   // 은닉 마커(KV독립) 우선 + 옛 type 폴백
    if (!_isHoney && auth.sessionId && isKVAvailable()) {
      try { if (await kvGet('honey:' + auth.sessionId)) _isHoney = true; } catch (e) {}
    }
    if (_isHoney) {
      if (isKVAvailable()) {
        await kvIncr('stats:vault:decoy-served');
        if (auth.sessionId) await kvIncr('honey-hits:' + auth.sessionId);   // 점진 차단용 — 찌른 횟수
      }
      // decoy:true 표식 제거 — 진짜 unlocked 와 형식 동일(해커가 응답 까봐도 구별 못 함)
      return res.status(200).json({ status: 'unlocked', vault: decoyVault() });
    }

    // ③ 진짜 인증 통과 — 금고 키 정하기
    let key;
    let legacyKey = null;   // [D] 옛 슬롯 읽기 폴백용(자동 이전은 안 함)
    if (auth.vk) {
      // 고보안(양자 도장): 토큰에 *서명되어 박힌* 기준으로 금고 키 — 위조 불가(서버 SECRET 서명).
      //   신원 토큰(mufe-u) 없이도 동작 → 비번 서버 미전송 철학 유지.
      key = 'vault:' + sign('vault-pq|' + auth.vk);
    } else {
      // [D] 간편: 금고를 *userId*로 격리 — 비번 평문을 키에 쓰지 않는다(토큰엔 비번 없음).
      //   userId는 진짜 토큰에 서명되어 박혀 있어(verify/register) 사용자마다 유일.
      const userData = verifyToken(userToken, 'mufe-u');
      const uid = auth.userId || (userData && userData.userId) || null;
      if (!uid && !userData) {
        return res.status(200).json({ status: 'locked', message: '금고 잠김 — 신원 확인 실패' });
      }
      if (uid) {
        key = 'vault:' + sign('vault-uid|' + uid);                  // 새 격리 키(사용자별 유일)
        legacyKey = userData ? vaultKeyFor(userData) : null;        // 옛 키 — 읽기만 폴백
      } else {
        key = vaultKeyFor(userData);                                // uid 없는 아주 옛 토큰만
      }
    }

    // [#7·#8] 분할 금고 — 서버 조각(마스터키의 절반). 폰 조각과 둘 다 있어야 K 복원.
    if (action === 'share-init') {
      if (!isKVAvailable()) return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결' });
      const shareKey = key + ':share';
      let s = await kvGet(shareKey);
      if (!s || !s.share) {
        const mode = (req.body && req.body.mode === 'B') ? 'B' : 'A';   // A=랜덤+24단어, B=본비번 파생
        s = { share: crypto.randomBytes(32).toString('base64'), mode, createdAt: Date.now() };
        await kvSet(shareKey, s);
        await kvIncr('stats:vault:share-init');
      }
      return res.status(200).json({ status: 'ok', share: s.share, mode: s.mode });
    }
    if (action === 'share-get') {
      if (!isKVAvailable()) return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결' });
      const s = await kvGet(key + ':share');
      if (!s || !s.share) return res.status(200).json({ status: 'no-share', message: '분할 금고 미설정' });
      return res.status(200).json({ status: 'ok', share: s.share, mode: s.mode });
    }

    // ── 저장 ──
    if (action === 'set') {
      const c = typeof content === 'string' ? content.slice(0, MAX_CONTENT) : '';
      if (!isKVAvailable()) {
        return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결 — 저장 불가' });
      }
      // [#11] 덮어쓰기 전에 직전 내용을 백업(최근 1부) — 실수/삭제 복구용. 실패해도 저장엔 영향 없음.
      try {
        const prev = await kvGet(key);
        if (prev && prev.content) await kvSet(key + '::bak', { content: prev.content, updatedAt: prev.updatedAt, backedAt: Date.now() });
      } catch (e) {}
      const record = { content: encContent(c), updatedAt: Date.now() };   // [#7 at-rest] 서버키로 한 겹 더 암호화
      await kvSet(key, record);
      await kvIncr('stats:vault:set');
      return res.status(200).json({ status: 'saved', updatedAt: record.updatedAt });
    }

    // [#11] 직전 백업으로 복구 (덮어쓰기·삭제 되돌리기). 현재 내용은 백업에 swap 보관 → 복구 취소도 가능.
    if (action === 'restore') {
      if (!isKVAvailable()) return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결' });
      const bak = await kvGet(key + '::bak');
      if (!bak || !bak.content) return res.status(200).json({ status: 'no-backup', message: '복구할 직전 백업이 없습니다' });
      try {
        const cur = await kvGet(key);
        if (cur && cur.content) await kvSet(key + '::bak', { content: cur.content, updatedAt: cur.updatedAt, backedAt: Date.now() });
      } catch (e) {}
      const record = { content: bak.content, updatedAt: Date.now(), restoredFrom: bak.backedAt || null };
      await kvSet(key, record);
      await kvIncr('stats:vault:restore');
      return res.status(200).json({ status: 'restored', updatedAt: record.updatedAt });
    }

    // ── 읽기 (기본) ──
    if (!isKVAvailable()) {
      return res.status(200).json({ status: 'unlocked', vault: { content: '', updatedAt: null }, message: '서버 저장소(KV) 미연결' });
    }
    await kvIncr('stats:vault:get');
    let record = await kvGet(key);
    if (!record && legacyKey) {
      // [D] 새 격리 슬롯이 비어 있으면 옛 슬롯을 '읽기만' 시도(자동 복사 안 함 — 공유슬롯 오염 방지).
      //   한 번 저장(set)하면 새 격리 슬롯으로 들어가 이후 완전 격리된다.
      const legacy = await kvGet(legacyKey);
      if (legacy) record = legacy;
    }
    // [#7 at-rest] 저장 때 서버키로 암호화한 내용을 복호해 내려줌 (옛 평문·가짜 금고는 접두 없으면 그대로)
    if (record && typeof record.content === 'string') {
      record = Object.assign({}, record, { content: decContent(record.content) });
    }
    return res.status(200).json({ status: 'unlocked', vault: record || { content: '', updatedAt: null } });

  } catch (err) {
    console.error('[vault] error:', err && err.message);
    return res.status(500).json({ status: 'error' });
  }
};
