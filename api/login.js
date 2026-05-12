/**
 * MUFE 백신 — 기존 비번 로그인
 * 
 * POST /api/login
 * body: { passcode }
 * 
 * - KV에 박힌 해시 박힘 확인
 * - 같으면 토큰 발급 (format도 박혀있음)
 * - 모토: 박힘 X도 "통과 박는 자리" (decoy)
 */
const crypto = require('crypto');
const { kvGet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function hashPasscode(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`pass:${passcode}`).digest('hex');
}
function getUserId(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`uid:${passcode}`).digest('hex').slice(0, 16);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { passcode } = req.body || {};
    if (!passcode) return res.status(400).json({ error: '비번을 박아주세요' });

    if (!isKVAvailable()) {
      return res.status(503).json({ 
        status: 'no-server-storage',
        message: '서버 저장소 박혀있지 않음',
        detail: '이 사이트는 *처음 등록* 자리만 박힘. KV 박힌 자리에서 박아주세요.',
      });
    }

    const passHash = hashPasscode(passcode);
    const userId = getUserId(passcode);
    const user = await kvGet(`user:${userId}`);

    if (!user || user.passHash !== passHash) {
      // 모토 그대로 — 박힘 X도 decoy 박음
      await kvIncr('stats:login:trapped');
      
      const fakeToken = `mufe-u.${Buffer.from(JSON.stringify({
        type: 'decoy',
        issuedAt: Date.now(),
        sessionId: crypto.randomBytes(8).toString('hex'),
        trapped: true,
      })).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
      
      return res.status(200).json({
        status: 'decoy',
        token: fakeToken,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
        subdetail: '비번 박힘 X — 모토 그대로 *격리 + 자기 자원 소진*',
        serverSide: {
          actualResult: 'TRAPPED-WRONG-LOGIN',
          reason: 'no-matching-user',
        },
      });
    }

    // 박힌 비번 — 진짜 통과
    await kvIncr('stats:login:success');
    
    const payload = {
      type: 'user-registration',
      issuedAt: Date.now(),
      sessionId: crypto.randomBytes(8).toString('hex'),
      userId,
      passcode,
      format: user.format,
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    const token = `mufe-u.${payloadB64}.${sign(payloadB64)}`;

    return res.status(200).json({
      status: 'success',
      token,
      format: user.format,
      message: '정답입니다. 통과 다음 단계로',
      detail: '',
    });
  } catch (err) {
    return res.status(500).json({ error: '로그인 박힘 X', detail: err.message });
  }
};
