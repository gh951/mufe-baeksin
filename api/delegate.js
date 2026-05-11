/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 위임 인증 함수
 *  
 *  POST /.netlify/functions/delegate
 *  
 *  대장님이 던지신 *바클로드보* 패턴 — 1차 인증자가
 *  2차 사용자에게 위임할 수 있는 별도 암호 발급
 *  
 *  body: { masterToken, recipientId }
 *  → 수신자별 *동적 위임 답* 발급
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

function verifyToken(token) {
  if (!token || !token.startsWith('mufe.')) return null;
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

// 위임 답 풀 — 수신자별 다르게
const DELEGATE_POOL = [
  '바클로드보', '클로드보바', '보바클로드', '드바클로보',
  '바보클로드', '보클로바드', '드보바클로'
];

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { masterToken, recipientId, duration } = req.body || {};
    
    if (!masterToken || !recipientId) {
      return res.status(400).json({ error: '마스터 토큰과 수신자 ID가 필요합니다' });
    }
    
    // 마스터 토큰 검증 — 진짜 인증된 사용자만 위임 가능
    const tokenData = verifyToken(masterToken);
    if (!tokenData) {
      return res.status(401).json({ 
          error: '유효하지 않은 마스터 토큰',
          detail: '진짜 인증된 사용자만 위임할 수 있습니다',
        });
    }
    
    if (tokenData.type !== 'real') {
      // 미끼 토큰으로는 위임 불가 (진짜로는 허락하는 척하면서 격리)
      return res.status(403).json({ 
          error: '권한 없음',
          detail: '진짜 인증된 사용자만 위임 가능',
          serverSide: { trapped: true, reason: 'decoy-master-token' },
        });
    }
    
    // 수신자별 동적 위임 답 결정
    const recipientHash = crypto.createHash('sha256')
      .update(`${recipientId}|${tokenData.sessionId}|${Date.now()}`)
      .digest('hex');
    const delegateIdx = parseInt(recipientHash.slice(0, 4), 16) % DELEGATE_POOL.length;
    const delegateAnswer = DELEGATE_POOL[delegateIdx];
    
    // 유효 기간 계산
    const durationMap = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      'once': 60 * 60 * 1000, // 1시간 안에 1회만
    };
    const expiresIn = durationMap[duration] || durationMap['24h'];
    const validForLabels = {
      '1h': '1시간',
      '24h': '24시간',
      '7d': '7일',
      'once': '1회만 (1시간 내)',
    };
    
    // 위임 토큰 발급 — 수신자가 사용할 인증 키
    const delegatePayload = {
      type: 'delegate',
      issuedAt: Date.now(),
      issuedBy: tokenData.sessionId,
      recipientId,
      delegateAnswer,  // 이 답으로 인증 가능
      duration: duration || '24h',
      oneTime: duration === 'once',
      expiresAt: Date.now() + expiresIn,
    };
    const payloadB64 = Buffer.from(JSON.stringify(delegatePayload)).toString('base64');
    const sig = sign(payloadB64);
    const delegateToken = `mufe-d.${payloadB64}.${sig}`;
    
    return res.status(200).json({
        status: 'success',
        delegateToken,
        delegateAnswer,        // 수신자에게 알려줄 답
        recipientId,
        validFor: validForLabels[duration] || '24시간',
        message: '위임 인증 발급 완료',
        detail: `수신자(${recipientId})는 다음 답으로 인증 가능: "${delegateAnswer}"`,
        subdetail: '수신자별 동적 — 다른 수신자는 다른 답 받음',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '위임 발급 실패', detail: err.message });
  }
};
