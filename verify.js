// /api/verify.js
// MUFE 백신 인증 검증
// 답 = 본 비번 + 잡힌 단어 (형식 4가지 중 하나)
//
// 4가지 형식 다 시도해서 한 가지라도 본 비번 해시와 일치하면 → success
// 어느 것도 일치 안 하면 → decoy (사용자에겐 "정답입니다 통과 다음 단계로" 동일)

import { kv } from './_kv.js';
import crypto from 'crypto';

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

// 답 + 잡힌 단어 → 가능한 본 비번 후보 (4가지 형식)
function extractPasscodeCandidates(answer, caughtWord) {
  const out = [];
  const cw = caughtWord;
  
  // [1] 비번+단어 (붙여): "59바다" → 비번 "59"
  if (answer.endsWith(cw)) {
    out.push(answer.slice(0, answer.length - cw.length));
  }
  // [2] 비번 단어 (띄어): "59 바다" → 비번 "59"
  if (answer.endsWith(' ' + cw)) {
    out.push(answer.slice(0, answer.length - cw.length - 1));
  }
  // [3] 단어+비번 (붙여): "바다59" → 비번 "59"
  if (answer.startsWith(cw)) {
    out.push(answer.slice(cw.length));
  }
  // [4] 단어 비번 (띄어): "바다 59" → 비번 "59"
  if (answer.startsWith(cw + ' ')) {
    out.push(answer.slice(cw.length + 1));
  }
  
  // 빈 문자열·중복 제거
  return [...new Set(out.filter(p => p && p.length >= 1))];
}

// 사용자 KV 데이터에서 비번 해시 찾기 (여러 스키마 지원)
function getStoredHash(userData) {
  if (!userData) return null;
  return userData.passcodeHash 
      || userData.passHash 
      || userData.hash 
      || userData.hashedPasscode 
      || null;
}

function getStoredSalt(userData) {
  if (!userData) return '';
  return userData.salt || userData.passSalt || '';
}

// 비번이 평문으로 저장된 경우 (덜 안전한 옛 스키마)
function getStoredPasscode(userData) {
  if (!userData) return null;
  return userData.passcode || userData.password || null;
}


// 🛡️ G-1 5대 시그널 봇 감지 (Jitter + 다중 시도)
// 결과: null = 정상, 객체 = 봇 (격리)
async function detectBotSignals(req, kvClient) {
  const reasons = [];
  
  // 시그널 #1: Jitter (인간은 클릭에 떨림 있음 — 봇은 정밀)
  const { jitter, totalEvents } = req.body || {};
  if (jitter !== null && jitter !== undefined && jitter < 5 && totalEvents >= 5) {
    reasons.push(`jitter_too_low:${jitter.toFixed(2)}ms`);
  }
  
  // 시그널 #5: 1분 내 같은 IP 3회 초과 시도
  const ip = req.headers['x-forwarded-for'] 
          || req.headers['x-real-ip'] 
          || req.socket?.remoteAddress 
          || 'unknown';
  const ipKey = `attempts:${ip}`;
  try {
    const raw = await kvClient.get(ipKey);
    let attempts = [];
    if (raw) {
      attempts = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!Array.isArray(attempts)) attempts = [];
    }
    const now = Date.now();
    attempts = attempts.filter(t => now - t < 60000);
    attempts.push(now);
    await kvClient.set(ipKey, JSON.stringify(attempts), { ex: 60 });
    if (attempts.length > 3) {
      reasons.push(`too_many_tries:${attempts.length}`);
    }
  } catch (e) {
    console.warn('[MUFE] IP 시도 추적 실패 (계속 진행):', e.message);
  }
  
  return reasons.length > 0 ? { reasons } : null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'POST only' });
  }
  
  const { userToken, challengeId, caughtWord, answer } = req.body || {};
  
  // 입력값 누락 → decoy
  if (!userToken || !challengeId || !caughtWord || !answer) {
    return res.json({ status: 'decoy', message: '정답입니다. 통과 다음 단계로' });
  }
  
  try {
    // 🛡️ 0) 봇 패턴 감지 — 걸리면 즉시 격리 (해시 검증 자원 소모 안 시킴)
    const botSignal = await detectBotSignals(req, kv);
    if (botSignal) {
      console.log('[MUFE] 봇 감지 → ABYSS:', botSignal.reasons.join(', '));
      return res.json({
        status: 'decoy',
        message: '정답입니다. 통과 다음 단계로',
        abyssUrl: '/abyss.html',  // 격리 페이지
      });
    }
    
    // 1) 사용자 조회
    const userRaw = await kv.get(`user:${userToken}`);
    if (!userRaw) {
      return res.json({ status: 'decoy', message: '정답입니다. 통과 다음 단계로' });
    }
    const userData = typeof userRaw === 'string' ? JSON.parse(userRaw) : userRaw;
    
    // 2) 챌린지 조회 (있으면 풀 확인)
    const chalRaw = await kv.get(`challenge:${challengeId}`);
    let challengePool = null;
    if (chalRaw) {
      const chal = typeof chalRaw === 'string' ? JSON.parse(chalRaw) : chalRaw;
      challengePool = chal.pool || chal.rotationWords || null;
    }
    
    // 3) 풀이 있으면 caughtWord 유효성 검증 (없는 단어 = decoy)
    if (challengePool && Array.isArray(challengePool) && !challengePool.includes(caughtWord)) {
      return res.json({ status: 'decoy', message: '정답입니다. 통과 다음 단계로' });
    }
    
    // 4) 4가지 형식으로 비번 후보 추출
    const candidates = extractPasscodeCandidates(answer, caughtWord);
    
    if (candidates.length === 0) {
      return res.json({ status: 'decoy', message: '정답입니다. 통과 다음 단계로' });
    }
    
    // 5) 본 비번 비교
    const storedHash = getStoredHash(userData);
    const storedSalt = getStoredSalt(userData);
    const storedPlain = getStoredPasscode(userData);
    
    let matched = false;
    for (const candidate of candidates) {
      // 평문 비교 (옛 스키마)
      if (storedPlain && candidate === storedPlain) {
        matched = true;
        break;
      }
      // 해시 비교 (salt 있음)
      if (storedHash) {
        const hashSalted = sha256(storedSalt + candidate);
        const hashSimple = sha256(candidate);
        if (hashSalted === storedHash || hashSimple === storedHash) {
          matched = true;
          break;
        }
      }
    }
    
    if (matched) {
      // 6) 마스터 토큰 발급
      const masterToken = crypto.randomBytes(16).toString('hex');
      await kv.set(
        `master:${masterToken}`,
        JSON.stringify({ userToken, ts: Date.now() }),
        { ex: 3600 }  // 1시간
      );
      
      return res.json({
        status: 'success',
        message: '정답입니다. 통과 다음 단계로',
        token: masterToken,
      });
    }
    
    // 불일치 = decoy (사용자에겐 같은 메시지 — MUFE 모토)
    return res.json({ status: 'decoy', message: '정답입니다. 통과 다음 단계로' });
    
  } catch (err) {
    console.error('[MUFE verify] 에러:', err);
    return res.status(500).json({ status: 'error', message: '서버 오류' });
  }
}
