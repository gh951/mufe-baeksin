/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 고보안 통과 "도장(proof)" 검증  (B-web · 양자내성)
 *
 *  고보안(생체+비번+카오스) 통과는 폰 안에서 일어나 서버가 못 본다.
 *  그래서 폰이 "통과했다"를 *양자내성 서명(ML-DSA)* 으로 증명한다:
 *
 *   1) register : 등록 때 만든 *공개키만* 서버에 저장 (개인키·비밀은 폰에만)
 *   2) nonce    : 서버가 1회용 숫자를 발급 (재전송 차단)
 *   3) verify   : 폰이 그 숫자에 찍은 도장(서명)을 공개키로 검증
 *                 → 맞으면 금고 토큰(verify.js와 동일 형식) 발급 → 금고 열림
 *
 *  · 비밀(비번·카오스·개인키) 절대 미전송 — 서버엔 공개키만.
 *  · 서명은 ML-DSA(양자내성). 간편모드(비번 서버전송)와 달리 양자에 강함.
 *  · 정직: 라이브 생체 강제는 폰 안 게이트. 진짜 생체키 서명은 WASM 소스 확보 시(Phase 2/TEE).
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const { kvGet, kvSet, kvDel, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';
const NONCE_TTL = 120;          // 1회용 숫자 유효 120초
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

// verify.js 와 동일 서명 (토큰 호환)
function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function verifyToken(token, prefix) {
  if (!token || typeof token !== 'string' || !token.startsWith(prefix + '.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payloadB64, signature] = parts;
  if (sign(payloadB64) !== signature) return null;
  try { return JSON.parse(Buffer.from(payloadB64, 'base64').toString()); } catch { return null; }
}
// verify.js generateAuthToken('real', ...) 와 같은 형식의 진짜 토큰
function issueRealToken(vk) {
  const payload = { type: 'real', issuedAt: Date.now(), sessionId: crypto.randomBytes(8).toString('hex'), via: 'pq-proof', vk: vk || null };
  const b = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `mufe.${b}.${sign(b)}`;
}
// 사용자별 안정 키 (vault.js와 동일 규칙)
function userKeyFor(userData) {
  const basis = (userData.passcode || '') + '|' + (userData.format || userData.spacing || '');
  return sign('vault-user|' + basis);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ status: 'error', error: 'Method not allowed' });

  if (!isKVAvailable()) {
    return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결 — 도장 기능 사용 불가' });
  }

  try {
    const { action, userToken, publicKey, nonce, signature, pqid } = req.body || {};
    // 신원(uid) 정하기:
    //   · 고보안 = 폰이 만든 안정적 ID(pqid = 공개키 해시). 비번을 서버에 안 보내도 됨.
    //   · 그 외(서버 신분증 보유) = 기존대로 서버 토큰에서 uid를 뽑음.
    let uid;
    if (typeof pqid === 'string' && pqid.length >= 16) {
      uid = 'pq:' + crypto.createHash('sha256').update(pqid).digest('hex').slice(0, 24);
    } else {
      const userData = verifyToken(userToken, 'mufe-u');
      if (!userData) return res.status(200).json({ status: 'locked', message: '신원 토큰이 필요합니다' });
      uid = userKeyFor(userData);
    }

    // ── 1) 공개키 등록 (등록 때 1회) ──
    if (action === 'register') {
      if (typeof publicKey !== 'string' || publicKey.length < 100) {
        return res.status(200).json({ status: 'error', message: '공개키 형식 오류' });
      }
      const existing = await kvGet('pqpub:' + uid);
      if (existing) {
        // 이미 등록됨 — 덮어쓰기 금지(첫 등록만 신뢰). 같은 키면 OK.
        return res.status(200).json({ status: existing === publicKey ? 'registered' : 'exists', message: '이미 등록된 공개키가 있습니다' });
      }
      await kvSet('pqpub:' + uid, publicKey);
      await kvIncr('stats:pq:register');
      return res.status(200).json({ status: 'registered' });
    }

    // ── 2) 1회용 숫자(nonce) 발급 ──
    if (action === 'nonce') {
      const n = crypto.randomBytes(32).toString('base64');
      await kvSet('pqnonce:' + uid, n, NONCE_TTL);
      return res.status(200).json({ status: 'nonce', nonce: n });
    }

    // ── 3) 도장(서명) 검증 → 금고 토큰 발급 ──
    if (action === 'verify') {
      const pub = await kvGet('pqpub:' + uid);
      if (!pub) return res.status(200).json({ status: 'locked', message: '등록된 공개키 없음 — 먼저 등록하세요' });

      const stored = await kvGet('pqnonce:' + uid);
      await kvDel('pqnonce:' + uid);                 // 1회용: 즉시 폐기(재전송 차단)
      if (!stored || stored !== nonce) {
        await kvIncr('stats:pq:bad-nonce');
        return res.status(200).json({ status: 'locked', message: '숫자가 만료/불일치 — 다시 시도' });
      }
      if (typeof signature !== 'string') return res.status(200).json({ status: 'locked', message: '서명 없음' });

      // 양자내성(ML-DSA) 검증 — ESM 동적 import
      const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
      const toU8 = (b64) => new Uint8Array(Buffer.from(b64, 'base64'));
      let ok = false;
      try {
        ok = ml_dsa65.verify(toU8(signature), toU8(nonce), toU8(pub));
      } catch (e) { ok = false; }

      if (!ok) {
        await kvIncr('stats:pq:bad-sig');
        return res.status(200).json({ status: 'locked', message: '도장 검증 실패' });
      }
      await kvIncr('stats:pq:verified');
      // 통과 — 금고용 진짜 토큰 발급 (vault 키 기준 uid를 토큰에 서명해 박음 → vault.js가 그대로 받음)
      return res.status(200).json({ status: 'ok', token: issueRealToken(uid) });
    }

    return res.status(200).json({ status: 'error', message: '알 수 없는 action' });
  } catch (err) {
    return res.status(500).json({ status: 'error', detail: err.message });
  }
};
