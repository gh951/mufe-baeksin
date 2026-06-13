/**
 * MUFE 백신 — 사용자 등록 (해시 저장)
 *
 * [C-52 보안수정]
 *  - 토큰에 비번 원본을 절대 넣지 않음 (userId/format 만)
 *  - 비번은 해시(passHash)만 KV(창고)에 저장
 *  - MUFE_SECRET 없으면 동작 거부 (공개 기본값 서명 금지)
 *  - 신규/재인증 응답을 동일하게 (어떤 비번이 이미 쓰이는지 못 엿보게)
 */
const crypto = require('crypto');
const { kvSet, kvGet, kvIncr, isKVAvailable } = require('./_kv');
const { argon2id } = require('@noble/hashes/argon2.js');   // [#9] 메모리-하드 비번 해시(Argon2id)

const SECRET = process.env.MUFE_SECRET;   // 기본값 fallback 제거
const VALID_FORMATS = ['joined-after', 'spaced-after', 'joined-before', 'spaced-before'];

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function hashPasscode(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`pass:${passcode}`).digest('hex');
}
// [#9] PBKDF2 20만회 — verify.js의 hashPasscodeV2와 *완전히 동일한* 규칙이어야 함(salt=userId 기반).
const KDF_ITER = 200000;
function hashPasscodeV2(passcode, userId) {
  const salt = crypto.createHash('sha256').update(SECRET + '|' + (userId || '')).digest();
  return 'p2:' + crypto.pbkdf2Sync(String(passcode), salt, KDF_ITER, 32, 'sha256').toString('hex');
}
// [#9] Argon2id — verify.js의 hashPasscodeV3와 *완전히 동일한* 규칙이어야 함(salt 'v3' 태그·파라미터 동일).
const ARGON = { t: 2, m: 19456, p: 1, dkLen: 32 };
function hashPasscodeV3(passcode, userId) {
  const salt = crypto.createHash('sha256').update(SECRET + '|v3|' + (userId || '')).digest();
  return 'p3:' + Buffer.from(argon2id(String(passcode), salt, ARGON)).toString('hex');
}
function getUserId(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`uid:${passcode}`).digest('hex').slice(0, 16);
}

// 인증 토큰 — 비번은 절대 담지 않음
function makeUserToken(userId, format) {
  const payload = {
    type: 'user-registration',
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    userId,
    format,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `mufe-u.${payloadB64}.${sign(payloadB64)}`;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // [보안] 비밀 도장 없으면 거부
  if (!SECRET) return res.status(500).json({ error: 'server-misconfigured' });

  try {
    const { passcode, format } = req.body || {};
    if (!passcode || passcode.length < 1) return res.status(400).json({ error: '비번을 입력해주세요' });
    if (!VALID_FORMATS.includes(format)) return res.status(400).json({ error: '유효한 형식을 입력해주세요' });

    const userId = getUserId(passcode);
    const passHash = hashPasscodeV3(passcode, userId);   // [#9] 새 가입은 처음부터 Argon2id

    let existingUser = null;
    if (isKVAvailable()) existingUser = await kvGet(`user:${userId}`);

    if (existingUser) {
      // 같은 비번 = 같은 userId/해시. 재인증으로 통과.
      const fmt = format || existingUser.format;
      if (isKVAvailable() && fmt !== existingUser.format) {
        await kvSet(`user:${userId}`, { ...existingUser, format: fmt, updatedAt: Date.now() });
      }
      if (isKVAvailable()) await kvIncr('stats:user:reauth');
      return res.status(200).json({
        status: 'success',
        token: makeUserToken(userId, fmt),
        format: fmt,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
      });
    }

    if (isKVAvailable()) {
      await kvSet(`user:${userId}`, { passHash, format, createdAt: Date.now() });
      await kvIncr('stats:user:registered');
    }

    return res.status(200).json({
      status: 'success',
      token: makeUserToken(userId, format),
      format,
      message: '정답입니다. 통과 다음 단계로',
      detail: '',
    });
  } catch (err) {
    console.error('[register] error:', err && err.message);
    return res.status(500).json({ error: '등록 실패' });
  }
};
