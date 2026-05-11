/**
 * MUFE 백신 — 사용자 등록 (해시 박는 자리)
 * - 비번 원본은 서버 박힘 X (모토 그대로)
 * - 해시만 KV에 박음
 * - 같은 비번 = 어떤 기기·PC에서도 통과
 */
const crypto = require('crypto');
const { kvSet, kvGet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';
const VALID_FORMATS = ['joined-after', 'spaced-after', 'joined-before', 'spaced-before'];

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
    const { passcode, format } = req.body || {};
    if (!passcode || passcode.length < 1) return res.status(400).json({ error: '비번을 박아주세요' });
    if (!VALID_FORMATS.includes(format)) return res.status(400).json({ error: '유효한 형식을 박아주세요' });

    const passHash = hashPasscode(passcode);
    const userId = getUserId(passcode);

    let existingUser = null;
    if (isKVAvailable()) existingUser = await kvGet(`user:${userId}`);

    if (existingUser) {
      if (existingUser.passHash !== passHash) {
        return res.status(409).json({ error: '이 비번은 다른 자리에서 박혀있어요. 다른 비번을 박아주세요.' });
      }
      const payload = {
        type: 'user-registration', issuedAt: Date.now(),
        sessionId: crypto.randomBytes(8).toString('hex'),
        userId, passcode, format: format || existingUser.format,
      };
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
      const token = `mufe-u.${payloadB64}.${sign(payloadB64)}`;
      if (isKVAvailable()) await kvIncr('stats:user:reauth');
      return res.status(200).json({
        status: 'success', token,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
      });
    }

    if (isKVAvailable()) {
      await kvSet(`user:${userId}`, { passHash, format, createdAt: Date.now() });
      await kvIncr('stats:user:registered');
    }
    const payload = {
      type: 'user-registration', issuedAt: Date.now(),
      sessionId: crypto.randomBytes(8).toString('hex'),
      userId, passcode, format,
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    const token = `mufe-u.${payloadB64}.${sign(payloadB64)}`;
    return res.status(200).json({
      status: 'success', token,
      message: '정답입니다. 통과 다음 단계로',
      detail: isKVAvailable() ? '비번 박힘 (해시) — 어떤 기기·PC에서도 같은 비번으로 박힘'
                              : '비번 박힘 (이 브라우저만) — KV 박혀있지 않음',
    });
  } catch (err) {
    return res.status(500).json({ error: '등록 박힘 X', detail: err.message });
  }
};
