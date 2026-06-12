/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 위임 답 검증 (수신자 통과)
 *  
 *  POST /.netlify/functions/verify-delegate
 *  body: { delegateAnswer, recipientId? }
 *  
 *  마스터가 위임 발급 시 받은 답을 수신자가 입력 → 통과
 *  
 *  검증:
 *  1. 위임 답 풀에 있는 답인가
 *  2. 만료되지 않았나 (서명된 토큰의 expiresAt)
 *  3. 1회용이면 이미 사용했나 (메모리 추적)
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const { kvSet, kvGet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

// [C-53] 답 → 창고 키 (delegate.js의 answerKey와 *완전히 동일한* 규칙이어야 함)
function answerKey(ans) {
  return 'delans:' + crypto.createHash('sha256').update(String(ans).trim()).digest('hex').slice(0, 24);
}

// 1회용 토큰 추적 — Netlify Functions는 stateless라 메모리 한계
// 실전: Redis/DynamoDB 사용
// 데모: 짧은 시간 내 같은 토큰 재사용 막음 (서명에 시간 박힘)

function generateAuthToken(type, data) {
  const payload = {
    type,
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    delegated: true,
    fromMaster: data?.fromMaster || null,
    recipientId: data?.recipientId || null,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = sign(payloadB64);
  return `mufe-r.${payloadB64}.${sig}`;  // recipient 토큰 prefix
}

// [C-53 rate-limit] 무차별 위임답 스캔 차단. 같은 IP가 1분에 20회 초과 → 거부 벽 없이 미끼로.
//   정상 위임 통과는 그대로(정상 사용자는 1분에 몇 번 안 함). KV 없거나 에러면 제한 안 함(정상 흐름 보호).
const RL_MAX = 20;
async function rateLimited(req) {
  if (!isKVAvailable()) return false;
  try {
    const fwd = (req.headers['x-forwarded-for'] || '');
    const ip = fwd.split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown';
    const bucket = Math.floor(Date.now() / 60000);   // 1분 버킷 — 매 분 자동 초기화
    const n = await kvIncr(`rl:delegate:${ip}:${bucket}`);
    return (typeof n === 'number' && n > RL_MAX);
  } catch (e) {
    return false;   // 에러나면 막지 않음(가용성 우선)
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // [C-53] 무차별 위임답 스캔 → 거부 벽 없이 미끼(연산지옥)로. 정상 위임은 그대로 통과.
  if (await rateLimited(req)) {
    if (isKVAvailable()) { try { await kvIncr('stats:delegate:rate-limited'); } catch (e) {} }
    const fakeToken = `mufe-r.${Buffer.from(JSON.stringify({
      type: 'decoy', issuedAt: Date.now(),
      sessionId: crypto.randomBytes(8).toString('hex'), trapped: true, reason: 'rate-limited',
    })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
    return res.status(200).json({ status: 'decoy', token: fakeToken, message: '정답입니다. 통과 다음 단계로', detail: '' });
  }

  try {
    const { delegateAnswer, recipientId } = req.body || {};

    if (!delegateAnswer) {
      return res.status(400).json({ error: '위임 답을 입력해주세요' });
    }
    const ans = delegateAnswer.trim();

    // 미끼 응답 — 진짜와 겉보기 완전히 동일(내부표식 없음)
    function sendDecoy(stat) {
      if (isKVAvailable() && stat) { kvIncr(stat).catch(() => {}); }
      const fakeToken = `mufe-r.${Buffer.from(JSON.stringify({
        type: 'decoy', issuedAt: Date.now(), sessionId: crypto.randomBytes(8).toString('hex'), trapped: true,
      })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
      return res.status(200).json({ status: 'decoy', token: fakeToken, message: '정답입니다. 통과 다음 단계로', detail: '' });
    }

    // [C-53] 위임은 서버 창고가 있어야 검증 가능 — 창고 없으면 미끼(기만 격리)
    if (!isKVAvailable()) return sendDecoy(null);

    // [C-53] '진짜 발급된 답'인지 창고에서 확인 — 코드의 고정 답은 더이상 통하지 않음
    const rec = await kvGet(answerKey(ans));
    if (!rec) return sendDecoy('stats:delegate:trapped');                         // 발급된 적 없는 답

    // 만료된 위임
    if (rec.expiresAt && Date.now() > rec.expiresAt) return sendDecoy('stats:delegate:expired');

    // 1회용인데 이미 쓴 위임
    if (rec.oneTime && rec.used) return sendDecoy('stats:delegate:reused');

    // 통과 — 1회용이면 '사용함'으로 박아 재사용 차단
    if (rec.oneTime) {
      const ttl = Math.max(1, Math.ceil(((rec.expiresAt || Date.now()) - Date.now()) / 1000));
      try {
        await kvSet(answerKey(ans), { ...rec, used: true, usedAt: Date.now(), usedBy: recipientId || 'unknown' }, ttl);
      } catch (e) {}
    }

    const recipientToken = generateAuthToken('delegate-recipient', {
      recipientId: recipientId || 'unknown',
    });
    await kvIncr('stats:delegate:success');
    await kvIncr(`stats:delegate:by-day:${new Date().toISOString().slice(0, 10)}`);

    return res.status(200).json({
        status: 'success',
        token: recipientToken,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
        permissions: ['view', 'limited-access'],
        expiresIn: '위임 시 설정한 기간',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '검증 실패', detail: err.message });
  }
};
