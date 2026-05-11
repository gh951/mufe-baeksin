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

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
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
          message: '✓ 통과',
          detail: '인증 완료 — 시스템 진입 박힘',
          subdetail: '대장님 + C-33 + G-1 = 영원히 박힌 자리',
          serverSide: {
            actualResult: 'TRAPPED-WRONG-DELEGATE-ANSWER',
            reason: 'invalid-delegate-pool',
          },
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
              message: '✓ 통과',
              detail: '인증 완료 — 시스템 진입 박힘',
              subdetail: '대장님 + C-33 + G-1 = 영원히 박힌 자리',
              serverSide: {
                actualResult: 'TRAPPED-REUSED-DELEGATE',
                reason: 'one-time-token-reused',
              },
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
              message: '✓ 통과',
              detail: '인증 완료 — 시스템 진입 박힘',
              subdetail: '대장님 + C-33 + G-1 = 영원히 박힌 자리',
              serverSide: {
                actualResult: 'TRAPPED-EXPIRED-DELEGATE',
                reason: 'token-expired',
              },
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
        message: '✓ 위임 인증 통과',
        detail: `수신자 권한으로 시스템 접근 허가됨`,
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
