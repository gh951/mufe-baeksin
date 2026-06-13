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
const { argon2id } = require('@noble/hashes/argon2.js');   // [#9] 메모리-하드 비번 해시(Argon2id)

const SECRET = process.env.MUFE_SECRET;   // 기본값 fallback 제거

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
function hashPasscode(passcode) {
  return crypto.createHmac('sha256', SECRET).update(`pass:${passcode}`).digest('hex');
}
// [#9] PBKDF2 20만회 — 비번 대입 비용 격상(HMAC 1회 대비 수십만배). 의존성 0(crypto 내장).
const KDF_ITER = 200000;
function hashPasscodeV2(passcode, userId) {
  const salt = crypto.createHash('sha256').update(SECRET + '|' + (userId || '')).digest();
  return 'p2:' + crypto.pbkdf2Sync(String(passcode), salt, KDF_ITER, 32, 'sha256').toString('hex');
}
// [#9] Argon2id — 메모리-하드(GPU/ASIC 대입 저항). 보고서의 'Argon2id' 주장과 서버 정합.
//   m=19MB·t=2 (서버 ~0.8s/회). 추가형: 기존 p2(PBKDF2)·HMAC 그대로 검증되고, 통과 시 p3로 자동 격상.
const ARGON = { t: 2, m: 19456, p: 1, dkLen: 32 };
function hashPasscodeV3(passcode, userId) {
  const salt = crypto.createHash('sha256').update(SECRET + '|v3|' + (userId || '')).digest();
  return 'p3:' + Buffer.from(argon2id(String(passcode), salt, ARGON)).toString('hex');
}
// 저장형식 자동 판별 — p3:=Argon2id(최신), p2:=PBKDF2, 그 외=HMAC(구). 일정시간 비교(타이밍 누출 줄임).
function verifyPass(passcode, userId, stored) {
  if (!stored || typeof stored !== 'string') return false;
  let cand;
  if (stored.startsWith('p3:')) cand = hashPasscodeV3(passcode, userId);
  else if (stored.startsWith('p2:')) cand = hashPasscodeV2(passcode, userId);
  else cand = hashPasscode(passcode);
  if (cand.length !== stored.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(cand), Buffer.from(stored)); } catch (e) { return false; }
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
  const sessionId = crypto.randomBytes(8).toString('hex');
  const payload = {
    type: 'real',   // [완벽위장] 진짜·미끼 모두 'real' — 해커는 토큰만으론 절대 구별 못 함
    issuedAt: Date.now(),
    sessionId: sessionId,
    userId: userId || null,
    format: format || null,
    // [은닉 마커] 서버 SECRET으로만 해독 — KV 없이도 미끼 판별(약점 0). 해커 눈엔 랜덤 16진수일 뿐.
    m: sign(sessionId + ':' + (type === 'decoy' ? 'decoy' : 'real')),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `mufe.${payloadB64}.${sign(payloadB64)}`;
}

// [은닉 마커 검증] payload.m 이 'decoy' 마커인지 — 서버 SECRET만으로 판별(KV 불필요). 옛 토큰(m 없음)은 false.
function isDecoyToken(p) {
  return !!(p && p.sessionId && p.m && p.m === sign(p.sessionId + ':decoy'));
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

async function sendDecoy(res, token, reason) {
  // 모든 미끼는 '진짜 형식'(mufe. + 서명)으로 발급 → 금고·위임 API가 가드로 잡아 연산지옥으로 보냄.
  //   (옛 looseDecoyToken은 mufe-r. 형식이라 금고가 '거부'해버려 연산지옥이 안 됐음 → 진짜 형식으로 통일)
  const t = token || generateAuthToken('decoy', null, null);
  await writeHoney(t, reason || 'decoy');   // 서버 금고(KV)에 'C-55의 덫' 표식
  return res.status(200).json({
    status: 'decoy',
    token: t,
    message: '정답입니다. 통과 다음 단계로',
    detail: '',
  });
}

// [허니토큰] 미끼 토큰을 발급할 때 — 토큰 겉엔 아무 표식도 안 남기고(진짜와 구별 불가),
//   서버 금고(KV)에만 'C-55의 덫'이라 기록한다. 금고 API가 나중에 이 sessionId를 보고
//   거부가 아니라 연산지옥(가짜 성공+가짜 데이터)으로 보낸다. 미끼 문 자는 끝에 가서야 C-55를 본다.
async function writeHoney(token, reason) {
  try {
    const pl = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64').toString());
    if (pl && pl.sessionId) {
      await kvSet('honey:' + pl.sessionId, JSON.stringify({ by: 'C-55', reason: reason || 'decoy', ts: Date.now() }));
    }
  } catch (e) {}
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
      storedPassHash = hashPasscodeV3(userData.passcode, userId);
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

    // 어떤 형식으로 입력했는지 — 비번 후보를 형식별로 떼어 (버전 자동판별) 비교
    let matchedFormat = null;
    let matchedCand = null;
    // [#9] 등록 형식(userFormat)을 가장 먼저 — 정상 로그인은 해시 1회로 끝남(Argon2id 비용 절감)
    const fmtOrder = [userFormat].concat(ALL_FORMATS.filter(f => f !== userFormat));
    for (const fmt of fmtOrder) {
      const cand = extractPasscode(userAnswer, caughtWord, fmt);
      if (cand == null) continue;
      if (verifyPass(cand, userId, storedPassHash)) { matchedFormat = fmt; matchedCand = cand; break; }
    }

    // 등록한 형식과 일치 = 진짜 통과
    if (matchedFormat && matchedFormat === userFormat) {
      // [#9] 옛 HMAC 해시면 → PBKDF2로 자동 격상 저장(1회). 실패해도 통과엔 영향 없음.
      if (matchedCand != null && isKVAvailable() && userId && !(typeof storedPassHash === 'string' && storedPassHash.startsWith('p3:'))) {
        try {
          await kvSet(`user:${userId}`, { passHash: hashPasscodeV3(matchedCand, userId), format: userFormat, upgradedAt: Date.now() });
        } catch (e) {}
      }
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
    return await sendDecoy(res, generateAuthToken('decoy', userId, userFormat), matchedFormat ? 'wrong-format' : 'wrong-pass');

  } catch (err) {
    console.error('[verify] error:', err && err.message);
    return res.status(500).json({ error: '검증 실패' });
  }
};
