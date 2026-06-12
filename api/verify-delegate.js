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

// 위임 답 풀 (delegate.js와 동일 — 검증용)
const DELEGATE_POOL = [
  '바클로드보', '클로드보바', '보바클로드', '드바클로보',
  '바보클로드', '보클로바드', '드보바클로'
];

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
    const { delegateAnswer, recipientId, delegateToken } = req.body || {};
    
    if (!delegateAnswer) {
      return res.status(400).json({ error: '위임 답을 입력해주세요' });
    }
    
    const ans = delegateAnswer.trim();
    
    // 위임 답 풀 박힘 X = decoy (모토: "차단 없음, 기만 격리만")
    if (!DELEGATE_POOL.includes(ans)) {
      if (isKVAvailable()) await kvIncr('stats:delegate:trapped');
      
      const fakeToken = `mufe-r.${Buffer.from(JSON.stringify({
        type: 'decoy', issuedAt: Date.now(),
        sessionId: crypto.randomBytes(8).toString('hex'),
        trapped: true,
      })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
      
      return res.status(200).json({
          status: 'decoy',
          token: fakeToken,
          message: '정답입니다. 통과 다음 단계로',
          detail: '',
        });
    }
    
    // KV에서 1회용 박힘 확인
    if (isKVAvailable() && delegateToken) {
      const delegateId = crypto.createHash('sha256').update(delegateToken).digest('hex').slice(0, 16);
      const delegateData = await kvGet(`del:${delegateId}`);
      
      if (delegateData) {
        // 이미 박힌 자리 = decoy
        if (delegateData.used && delegateData.oneTime) {
          await kvIncr('stats:delegate:reused');
          
          const fakeToken = `mufe-r.${Buffer.from(JSON.stringify({
            type: 'decoy', issuedAt: Date.now(),
            sessionId: crypto.randomBytes(8).toString('hex'),
            trapped: true, reason: 'reused',
          })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
          
          return res.status(200).json({
              status: 'decoy',
              token: fakeToken,
              message: '정답입니다. 통과 다음 단계로',
              detail: '',
            });
        }
        
        // 만료 자리 = decoy
        if (delegateData.expiresAt && Date.now() > delegateData.expiresAt) {
          await kvIncr('stats:delegate:expired');
          
          const fakeToken = `mufe-r.${Buffer.from(JSON.stringify({
            type: 'decoy', issuedAt: Date.now(),
            sessionId: crypto.randomBytes(8).toString('hex'),
            trapped: true, reason: 'expired',
          })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
          
          return res.status(200).json({
              status: 'decoy',
              token: fakeToken,
              message: '정답입니다. 통과 다음 단계로',
              detail: '',
            });
        }
        
        // 사용 박음 (1회용 표시)
        if (delegateData.oneTime) {
          await kvSet(`del:${delegateId}`, {
            ...delegateData,
            used: true,
            usedAt: Date.now(),
            usedBy: recipientId || 'unknown',
          }, 86400); // 24시간 박힘 (감사 로그용)
        }
      }
    }
    
    // 통과 → 수신자 토큰 발급
    const recipientToken = generateAuthToken('delegate-recipient', {
      recipientId: recipientId || 'unknown',
      delegateAnswer: ans,
    });
    
    // 통계 — 성공 카운터
    if (isKVAvailable()) {
      await kvIncr('stats:delegate:success');
      await kvIncr(`stats:delegate:by-day:${new Date().toISOString().slice(0,10)}`);
    }
    
    return res.status(200).json({
        status: 'success',
        token: recipientToken,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
        subdetail: isKVAvailable()
          ? `위임 박은 자리 + 1회용 진짜 추적 박힘`
          : `위임받은 답으로 통과 — 마스터 사용자가 부여한 일시 권한`,
        permissions: ['view', 'limited-access'],
        expiresIn: '24시간 (또는 위임 시 설정한 기간)',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '검증 실패', detail: err.message });
  }
};
