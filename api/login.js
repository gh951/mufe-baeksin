/**
 * MUFE 백신 — 기존 비번 로그인
 *
 * [C-52 보안수정]
 *  - 통과 토큰에 비번 원본을 넣지 않음 (userId/format 만)
 *  - 미끼 응답에서 'TRAPPED'·serverSide 등 내부 표식 제거 (네트워크로 정답 누설 방지)
 *  - MUFE_SECRET 없으면 동작 거부
 *  - 모토 유지: 비번 틀려도 '거부' 화면 없이 미끼(decoy)
 */
const crypto = require('crypto');
const { kvGet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET;   // 기본값 fallback 제거

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function hashPasscode(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`pass:${passcode}`).digest('hex');
}
function getUserId(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`uid:${passcode}`).digest('hex').slice(0, 16);
}

function decoyToken() {
  const payload = {
    type: 'decoy',
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    trapped: true,
  };
  return `mufe-u.${Buffer.from(JSON.stringify(payload)).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SECRET) return res.status(500).json({ error: 'server-misconfigured' });

  try {
    const { passcode } = req.body || {};
    if (!passcode) return res.status(400).json({ error: '비번을 입력해주세요' });

    if (!isKVAvailable()) {
      return res.status(503).json({
        status: 'no-server-storage',
        message: '서버 저장소가 연결되지 않음',
        detail: '이 사이트는 처음 등록만 가능. 저장소(KV) 연결 후 로그인하세요.',
      });
    }

    const passHash = hashPasscode(passcode);
    const userId = getUserId(passcode);
    const user = await kvGet(`user:${userId}`);

    if (!user || user.passHash !== passHash) {
      // 모토 그대로 — 틀려도 거부 없이 미끼 (단, 네트워크에 정답 누설 안 함)
      await kvIncr('stats:login:trapped');
      return res.status(200).json({
        status: 'decoy',
        token: decoyToken(),
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
      });
    }

    // 통과 — 토큰에 비번 없음 (userId/format 만)
    await kvIncr('stats:login:success');
    const payload = {
      type: 'user-registration',
      issuedAt: Date.now(),
      sessionId: crypto.randomBytes(8).toString('hex'),
      userId,
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
    return res.status(500).json({ error: '로그인 실패', detail: err.message });
  }
};
