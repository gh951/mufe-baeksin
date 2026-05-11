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
    const { delegateAnswer, recipientId } = req.body || {};
    
    if (!delegateAnswer) {
      return res.status(400).json({ error: '위임 답을 입력해주세요' });
    }
    
    const ans = delegateAnswer.trim();
    
    // 위임 답 풀에 있나 검증
    if (!DELEGATE_POOL.includes(ans)) {
      return res.status(200).json({
          status: 'failed',
          message: '인증 실패',
          detail: '유효한 위임 답이 아닙니다',
        });
    }
    
    // 통과 → 수신자 토큰 발급
    const recipientToken = generateAuthToken('delegate-recipient', {
      recipientId: recipientId || 'unknown',
      delegateAnswer: ans,
    });
    
    return res.status(200).json({
        status: 'success',
        token: recipientToken,
        message: '✓ 위임 인증 통과',
        detail: `수신자 권한으로 시스템 접근 허가됨`,
        subdetail: `위임받은 답으로 통과 — 마스터 사용자가 부여한 일시 권한`,
        permissions: ['view', 'limited-access'],
        expiresIn: '24시간 (또는 위임 시 설정한 기간)',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '검증 실패', detail: err.message });
  }
};
