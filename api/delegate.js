/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 위임 인증 함수
 *  
 *  POST /.netlify/functions/delegate
 *  
 *  1차 인증자(마스터)가 2차 사용자에게 위임할 수 있는 별도 암호 발급
 *  
 *  body: { masterToken, recipientId }
 *  → 수신자별 *동적 위임 답* 발급
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const { kvSet, kvGet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET;   // [C-53] 기본키 fallback 제거 — 없으면 거부(조용한 약화 방지)

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

// [C-53] 위임 답을 '발급할 때마다 다른 랜덤'으로 — 코드에 답이 없으니 읽어도 못 뚫음.
//   입력하기 쉬운 한글 음절 30개에서 6음절 무작위(약 7억 조합). 답 자체는 KV에만 기록된다.
const SYLLABLES = ['바','클','로','드','보','무','페','신','카','오','스','양','자','광','반','사','심','박','코','믿','해','달','별','산','강','들','꽃','빛','숲','람'];
function randomAnswer() {
  const b = crypto.randomBytes(6);
  let s = '';
  for (let i = 0; i < 6; i++) s += SYLLABLES[b[i] % SYLLABLES.length];
  return s;
}
// 답 → 창고 키 (발급/검증이 *완전히 동일한* 규칙을 써야 함 — verify-delegate.js와 일치)
function answerKey(ans) {
  return 'delans:' + crypto.createHash('sha256').update(String(ans).trim()).digest('hex').slice(0, 24);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!SECRET) return res.status(500).json({ error: 'server-misconfigured' });
  
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
        });
    }
    
    // [C-53] 매번 다른 랜덤 답 — 창고에 이미 있으면(드묾) 다시 뽑아 충돌 회피
    let delegateAnswer = randomAnswer();
    if (isKVAvailable()) {
      for (let tries = 0; tries < 5; tries++) {
        const dup = await kvGet(answerKey(delegateAnswer));
        if (!dup) break;
        delegateAnswer = randomAnswer();
      }
    }
    
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
    
    // KV에 위임 박음 (1회용 추적 + 통계용)
    const delegateId = crypto.createHash('sha256').update(delegateToken).digest('hex').slice(0, 16);
    const ttlSec = Math.ceil(expiresIn / 1000);
    
    if (isKVAvailable()) {
      const record = {
        used: false,
        issuedAt: Date.now(),
        recipientId,
        oneTime: duration === 'once',
        expiresAt: Date.now() + expiresIn,
      };
      // 위임 자리 박힘(기존 — 토큰 기반 추적 유지)
      await kvSet(`del:${delegateId}`, record, ttlSec);
      // [C-53] 답 기반 검증용 — 검증측이 '이 답이 진짜 발급된 것인지' 확인
      await kvSet(answerKey(delegateAnswer), record, ttlSec);
      
      // 통계 — 위임 발급 카운터 박음
      await kvIncr('stats:delegates:issued');
      await kvIncr(`stats:delegates:by-day:${new Date().toISOString().slice(0,10)}`);
    }
    
    return res.status(200).json({
        status: 'success',
        delegateToken,
        delegateAnswer,
        recipientId,
        validFor: validForLabels[duration] || '24시간',
        message: '위임 인증 발급 완료',
        detail: `수신자(${recipientId})는 다음 답으로 인증 가능: "${delegateAnswer}"`,
        subdetail: isKVAvailable() 
          ? '수신자별 동적 + 1회용 진짜 추적 박힘 (Vercel KV)'
          : '수신자별 동적 — 다른 수신자는 다른 답 받음',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '위임 발급 실패', detail: err.message });
  }
};
