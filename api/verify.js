/**
 * MUFE 백신 — 답 검증 (서버)
 *
 * [C-52 보안수정]
 *  - 비번을 토큰/응답에 절대 넣지 않음
 *  - KV(창고)에 저장된 비번 해시로 검증 (답에서 단어를 떼어 비번 후보를 해시 비교)
 *  - 등록한 형식만 success / 다른 3형식 = 미끼 / 비번 틀림 = 미끼
 *  - 응답에서 'TRAPPED'·serverSide 등 내부 표식 제거
 *  - 이행기 폴백: 창고에 아직 없는 옛 사용자는 옛 토큰으로 1회 통과시키고 해시를 창고로 옮김
 *  - MUFE_SECRET 없으면 동작 거부
 */
const crypto = require('crypto');
const { kvGet, kvSet, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET;   // 기본값 fallback 제거

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function hashPasscode(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`pass:${passcode}`).digest('hex');
}

function verifyToken(token, prefix) {
  if (!token || !token.startsWith(prefix + '.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payloadB64, signature] = parts;
  if (sign(payloadB64) !== signature) return null;
  try { return JSON.parse(Buffer.from(payloadB64, 'base64').toString()); }
  catch { return null; }
}

function verifyChallengeId(challengeId) {
  if (!challengeId || !challengeId.includes('.')) return null;
  const [dataB64, signature] = challengeId.split('.');
  if (signature !== sign(dataB64)) return null;
  try {
    const data = JSON.parse(Buffer.from(dataB64, 'base64').toString());
    if (Date.now() - data.t > 600 * 1000) return null;
    return data;
  } catch { return null; }
}

// 진짜 인증 토큰 — 비번 없음 (userId/format 만)
function generateAuthToken(type, userId, format) {
  const payload = {
    type,
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    userId: userId || null,
    format: format || null,
    ...(type === 'decoy' ? { sandbox: true, trapId: crypto.randomBytes(4).toString('hex') } : {}),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `mufe.${payloadB64}.${sign(payloadB64)}`;
}

// 형식 오류(토큰X·챌린지X·단어X)용 미끼 토큰
function looseDecoyToken() {
  const payload = {
    type: 'decoy',
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    trapped: true,
  };
  return `mufe-r.${Buffer.from(JSON.stringify(payload)).toString('base64')}.${crypto.randomBytes(8).toString('hex')}`;
}

function sendDecoy(res, token) {
  return res.status(200).json({
    status: 'decoy',
    token: token || looseDecoyToken(),
    message: '정답입니다. 통과 다음 단계로',
    detail: '',
  });
}

// [C-52 rate-limit] 무차별 대입 속도 제한.
//   같은 IP가 1분에 RL_MAX번 넘게 시도하면 → 미끼(연산지옥)로. 거부 벽 없음(MUFE 철학).
//   정상 사용자는 1분에 몇 번 안 하므로 안 걸림. 시간(분) 버킷 키라 매 분 자동 초기화.
//   KV 없거나 에러면 제한하지 않음(안전 쪽 = 정상 로그인 안 깨지게).
const RL_MAX = 20;
async function rateLimited(req) {
  if (!isKVAvailable()) return false;
  try {
    const fwd = (req.headers['x-forwarded-for'] || '');
    const ip = fwd.split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown';
    const bucket = Math.floor(Date.now() / 60000);   // 1분 버킷
    const n = await kvIncr(`rl:verify:${ip}:${bucket}`);
    return (typeof n === 'number' && n > RL_MAX);
  } catch (e) {
    return false;   // 에러나면 막지 않음(가용성 우선)
  }
}

const ALL_FORMATS = ['joined-after', 'spaced-after', 'joined-before', 'spaced-before'];

// 답에서 단어를 떼어 비번 후보 복원 (등록 형식의 역연산)
function extractPasscode(answer, word, format) {
  if (!word) return null;
  switch (format) {
    case 'joined-after':  return answer.endsWith(word) ? answer.slice(0, answer.length - word.length) : null;
    case 'spaced-after':  return answer.endsWith(' ' + word) ? answer.slice(0, answer.length - word.length - 1) : null;
    case 'joined-before': return answer.startsWith(word) ? answer.slice(word.length) : null;
    case 'spaced-before': return answer.startsWith(word + ' ') ? answer.slice(word.length + 1) : null;
    default: return null;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SECRET) return res.status(500).json({ error: 'server-misconfigured' });

  // [C-52 rate-limit] 너무 빠른 무차별 시도 → 거부 벽 없이 미끼(연산지옥)로
  if (await rateLimited(req)) {
    if (isKVAvailable()) { try { await kvIncr('stats:auth:rate-limited'); } catch (e) {} }
    return sendDecoy(res);
  }

  try {
    const { userToken, challengeId, caughtWord, answer } = req.body || {};
    if (!userToken || !challengeId || !caughtWord || !answer) {
      return res.status(400).json({ error: '모든 필드가 필요합니다' });
    }

    // 형식 오류 = 미끼 (거부 화면 없음)
    const userData = verifyToken(userToken, 'mufe-u');
    if (!userData) {
      if (isKVAvailable()) await kvIncr('stats:auth:trapped-no-token');
      return sendDecoy(res);
    }
    const challenge = verifyChallengeId(challengeId);
    if (!challenge) {
      if (isKVAvailable()) await kvIncr('stats:auth:trapped-no-challenge');
      return sendDecoy(res);
    }
    if (!challenge.words || !challenge.words.includes(caughtWord)) {
      if (isKVAvailable()) await kvIncr('stats:auth:trapped-wrong-word');
      return sendDecoy(res);
    }

    const userAnswer = (answer || '').trim();
    const userId = userData.userId || null;

    // 저장된 비번 해시 + 형식 — 우선 창고(KV)에서, 없으면 옛 토큰에서(이행기)
    let storedPassHash = null;
    let userFormat = userData.format || null;

    if (userId && isKVAvailable()) {
      const u = await kvGet(`user:${userId}`);
      if (u && u.passHash) {
        storedPassHash = u.passHash;
        userFormat = u.format || userFormat;
      }
    }

    // 이행기 폴백: 창고에 없고 옛 토큰이 비번을 품고 있으면 그걸로 통과시키고 해시를 창고로 옮김
    if (!storedPassHash && userData.passcode) {
      storedPassHash = hashPasscode(userData.passcode);
      try {
        if (isKVAvailable() && userId) {
          await kvSet(`user:${userId}`, { passHash: storedPassHash, format: userFormat, migratedAt: Date.now() });
        }
      } catch (e) {}
    }

    // 옛 spacing 호환
    if (!userFormat && userData.spacing) {
      userFormat = userData.spacing === 'joined' ? 'joined-after' : 'spaced-after';
    }

    // 검증 재료가 없으면 미끼
    if (!storedPassHash || !userFormat) {
      if (isKVAvailable()) await kvIncr('stats:auth:trapped-no-record');
      return sendDecoy(res);
    }

    // 어떤 형식으로 입력했는지 — 비번 후보를 형식별로 떼어 해시 비교
    let matchedFormat = null;
    for (const fmt of ALL_FORMATS) {
      const cand = extractPasscode(userAnswer, caughtWord, fmt);
      if (cand == null) continue;
      if (hashPasscode(cand) === storedPassHash) { matchedFormat = fmt; break; }
    }

    // 등록한 형식과 일치 = 진짜 통과
    if (matchedFormat && matchedFormat === userFormat) {
      const realToken = generateAuthToken('real', userId, userFormat);
      if (isKVAvailable()) {
        await kvIncr('stats:auth:success');
        await kvIncr(`stats:auth:by-day:${new Date().toISOString().slice(0, 10)}`);
      }
      return res.status(200).json({
        status: 'success',
        token: realToken,
        message: '정답입니다. 통과 다음 단계로',
        detail: '',
      });
    }

    // 비번은 맞지만 다른 형식 / 비번 자체가 틀림 = 미끼
    if (isKVAvailable()) {
      await kvIncr(matchedFormat ? 'stats:auth:decoy' : 'stats:auth:trapped-wrong-pass');
    }
    return sendDecoy(res, generateAuthToken('decoy', userId, userFormat));

  } catch (err) {
    return res.status(500).json({ error: '검증 실패', detail: err.message });
  }
};
