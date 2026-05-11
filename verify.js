/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 답 검증 (4가지 형식)
 *  
 *  진짜 답: 사용자가 등록한 *그 형식* 만 통과
 *  나머지 3가지 형식: 미끼 격리
 *  비번 자체가 다름: 단순 실패
 *  
 *  ⚠ Rate Limit 없음 — *기만 격리* 가 진짜 방어
 *     공격자가 만 번 시도해도 만 번 자기 자원만 소모함
 *     "보이는 게 진실이 아니다" — 공격 자체가 무용지물
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

function verifyToken(token, prefix) {
  if (!token || !token.startsWith(prefix + '.')) return null;
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

function verifyChallengeId(challengeId) {
  if (!challengeId || !challengeId.includes('.')) return null;
  const [dataB64, signature] = challengeId.split('.');
  if (signature !== sign(dataB64)) return null;
  
  try {
    const data = JSON.parse(Buffer.from(dataB64, 'base64').toString());
    if (Date.now() - data.t > 600 * 1000) return null;
    return data;
  } catch {
    return null;
  }
}

function generateAuthToken(type, data) {
  const payload = {
    type,
    issuedAt: Date.now(),
    sessionId: crypto.randomBytes(8).toString('hex'),
    ...(type === 'decoy' ? { sandbox: true, trapId: crypto.randomBytes(4).toString('hex') } : {}),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = sign(payloadB64);
  return `mufe.${payloadB64}.${sig}`;
}

// ════════════════════════════════════════════════════════════════
// 역피해 시스템 — 가짜 토큰에 *연산 폭탄* 박음 (강화 버전)
// 공격자가 토큰 분석/처리하려 하면 자기 시스템 자원 소모
// 역피해 페이로드
// 강화: 기존 5KB → 50KB, 더 깊은 재귀, 더 많은 가짜 자료
// ════════════════════════════════════════════════════════════════
function generateReversePayload() {
  // 1. 무한 재귀 JSON 구조 — 16단계 (8 → 16, 2배)
  const recursiveBait = (depth) => {
    if (depth <= 0) return { 
      end: crypto.randomBytes(64).toString('base64'),  // 32 → 64
      noise: crypto.randomBytes(128).toString('hex'),
    };
    return {
      next: recursiveBait(depth - 1),
      noise: crypto.randomBytes(128).toString('base64'),  // 64 → 128
      hint: 'looks-like-key-but-not',
      decoy: crypto.randomBytes(64).toString('hex'),
      timestamp: Date.now() + Math.random() * 1000000,
      signature: crypto.createHmac('sha256', crypto.randomBytes(16))
        .update(crypto.randomBytes(32)).digest('hex'),
    };
  };
  
  // 2. 가짜 *암호화된 데이터* — 더 무겁게 (2KB → 16KB)
  const fakeEncrypted = {
    algorithm: 'AES-256-GCM',
    iv: crypto.randomBytes(16).toString('base64'),
    ciphertext: crypto.randomBytes(16384).toString('base64'),  // 2KB → 16KB
    tag: crypto.randomBytes(16).toString('base64'),
    salt: crypto.randomBytes(64).toString('base64'),  // 32 → 64
    iterations: 500000 + Math.floor(Math.random() * 250000),  // 더 무거운 PBKDF2 미끼
    additionalData: crypto.randomBytes(2048).toString('base64'),
    keyDerivation: 'Argon2id',  // 더 무거운 알고리즘 미끼
    memoryCost: 65536,  // Argon2 메모리 비용 미끼
    timeCost: 4,
    parallelism: 8,
  };
  
  // 3. 가짜 *키 후보* 12개 → 50개
  const fakeKeyCandidates = Array.from({ length: 50 }, () => ({
    candidate: crypto.randomBytes(64).toString('hex'),  // 32 → 64
    score: Math.random(),
    metadata: {
      source: 'extraction-' + crypto.randomBytes(8).toString('hex'),
      confidence: 0.7 + Math.random() * 0.3,
      derivation: ['PBKDF2', 'Argon2id', 'scrypt'][Math.floor(Math.random() * 3)],
      iterations: 100000 + Math.floor(Math.random() * 1000000),
    },
    proof: crypto.randomBytes(256).toString('base64'),
  }));
  
  // 4. 오염된 *함수 시그니처* 미끼 (8 → 32)
  const fakeSignatures = Array.from({ length: 32 }, () => ({
    signature: crypto.createHmac('sha256', crypto.randomBytes(32))
      .update(crypto.randomBytes(128)).digest('hex'),
    algorithm: 'HMAC-SHA256',
    nonce: crypto.randomBytes(16).toString('base64'),
    timestamp: Date.now() - Math.random() * 86400000,
  }));
  
  // 5. 새로 추가 — 가짜 *해시 체인* (블록체인 미끼)
  const fakeHashChain = [];
  let prevHash = crypto.randomBytes(32).toString('hex');
  for (let i = 0; i < 20; i++) {
    const newHash = crypto.createHash('sha256')
      .update(prevHash + i + crypto.randomBytes(64).toString('hex'))
      .digest('hex');
    fakeHashChain.push({
      index: i,
      prevHash,
      hash: newHash,
      data: crypto.randomBytes(512).toString('base64'),
      nonce: Math.floor(Math.random() * 1000000000),
      difficulty: 4 + Math.floor(Math.random() * 8),
    });
    prevHash = newHash;
  }
  
  // 6. 새로 추가 — 가짜 *공개키 인프라* (PKI 미끼)
  const fakePKI = {
    rootCA: {
      subject: 'CN=MUFE-Root-' + crypto.randomBytes(4).toString('hex'),
      publicKey: crypto.randomBytes(512).toString('base64'),
      validity: { from: Date.now(), to: Date.now() + 31536000000 },
    },
    certChain: Array.from({ length: 5 }, () => ({
      subject: 'CN=Intermediate-' + crypto.randomBytes(4).toString('hex'),
      publicKey: crypto.randomBytes(512).toString('base64'),
      signature: crypto.randomBytes(256).toString('base64'),
    })),
  };
  
  return {
    // 공격자가 *진짜처럼* 보이는 페이로드
    encryptedPayload: fakeEncrypted,
    keyMaterial: fakeKeyCandidates,
    signatures: fakeSignatures,
    chainOfTrust: recursiveBait(16),  // 8 → 16단계 재귀
    hashChain: fakeHashChain,
    pki: fakePKI,
    
    // 공격자한테 *희망 주는* 메타데이터 (덪)
    decryptionHint: {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2-SHA256 + Argon2id',
      iterations: 500000,
      saltLength: 64,
      memoryCost: 65536,
      note: 'multi-layer-encryption-pattern',
      hint: 'try-key-candidates-in-order',
    },
    
    // 시간 폭탄 — 검증 카운터 백만 → *천만*
    challenge: {
      nonce: crypto.randomBytes(128).toString('base64'),
      proof: crypto.randomBytes(256).toString('base64'),
      counter: 0,
      maxCounter: 10000000,  // 1M → 10M (10배)
      verifyEvery: 1000,
      checkpoints: Array.from({ length: 100 }, (_, i) => ({
        index: i,
        targetHash: crypto.randomBytes(32).toString('hex'),
      })),
    },
  };
}

// 4가지 형식으로 답 생성
function buildAnswer(passcode, word, format) {
  switch (format) {
    case 'joined-after':  return passcode + word;
    case 'spaced-after':  return passcode + ' ' + word;
    case 'joined-before': return word + passcode;
    case 'spaced-before': return word + ' ' + passcode;
    default: return null;
  }
}

const ALL_FORMATS = ['joined-after', 'spaced-after', 'joined-before', 'spaced-before'];

const FORMAT_LABELS = {
  'joined-after': '비번+단어 붙여 쓰기',
  'spaced-after': '비번 단어 띄어 쓰기',
  'joined-before': '단어+비번 붙여 쓰기',
  'spaced-before': '단어 비번 띄어 쓰기',
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { userToken, challengeId, caughtWord, answer } = req.body || {};
    
    if (!userToken || !challengeId || !caughtWord || !answer) {
      return res.status(400).json({ error: '모든 필드가 필요합니다' });
    }
    
    // 사용자 토큰 검증
    const userData = verifyToken(userToken, 'mufe-u');
    if (!userData) {
      return res.status(401).json({ 
          status: 'invalid',
          message: '사용자 토큰이 유효하지 않습니다',
          detail: '비번을 다시 등록해주세요',
        });
    }
    
    // 챌린지 ID 검증
    const challenge = verifyChallengeId(challengeId);
    if (!challenge) {
      return res.status(401).json({ 
          status: 'invalid',
          message: '챌린지가 만료되었거나 위조되었습니다',
        });
    }
    
    // 잡은 단어가 회전 풀 안에 있나
    if (!challenge.words.includes(caughtWord)) {
      return res.status(400).json({
          status: 'failed',
          message: '잡힌 단어가 회전 풀에 없습니다',
          detail: '챌린지를 다시 시작해주세요',
        });
    }
    
    // 사용자 형식 호환 — 옛 spacing → 새 format
    let userFormat = userData.format;
    if (!userFormat && userData.spacing) {
      userFormat = userData.spacing === 'joined' ? 'joined-after' : 'spaced-after';
    }
    
    const passcode = userData.passcode;
    const userAnswer = answer.trim();
    
    // 진짜 답 — 등록한 *그 형식* 만 통과
    const realAnswer = buildAnswer(passcode, caughtWord, userFormat);
    
    if (userAnswer === realAnswer) {
      const realToken = generateAuthToken('real', userData);
      return res.status(200).json({
          status: 'success',
          token: realToken,
          message: '✓ 진짜 통과',
          detail: `정답: "${realAnswer}" (${FORMAT_LABELS[userFormat]})`,
          subdetail: '비번 + 잡은 단어 + 형식까지 일치',
        });
    }
    
    // 다른 3가지 형식 → 미끼 격리
    // 공격자가 비번을 알아도 형식 4가지 중 1/4 확률
    for (const fmt of ALL_FORMATS) {
      if (fmt === userFormat) continue;  // 진짜 형식 건너뜀
      const fakeAnswer = buildAnswer(passcode, caughtWord, fmt);
      if (userAnswer === fakeAnswer) {
        const fakeToken = generateAuthToken('decoy', userData);
        const reversePayload = generateReversePayload();
        return res.status(200).json({
            status: 'decoy',
            token: fakeToken,
            message: '※ 데모: "통과" 표시',
            detail: '실전: 가짜 토큰 발급 → 샌드박스 격리 + 역피해 페이로드 송출',
            subdetail: `비번 맞춤 / 형식 *틀림* — "${FORMAT_LABELS[fmt]}" 시도. 등록된 형식은 "${FORMAT_LABELS[userFormat]}"`,
            
            // ⚔ 역피해 페이로드 — 공격자 시스템 자원 소모 유도
            reversePayload,
            
            serverSide: {
              actualResult: 'TRAPPED + REVERSE-PAYLOAD-DEPLOYED',
              sandboxId: fakeToken.split('.')[1].slice(0, 12),
              attemptedFormat: fmt,
              registeredFormat: userFormat,
              reason: 'wrong-format',
              note: '공격자: 비번 추측 성공, 형식 25% 확률, 페이로드 처리 시 자기 자원 소모',
              reverseEffect: '연산 폭탄 + 무한 재귀 + 가짜 키 후보 12개 + 가짜 시그니처 8개',
            },
          });
      }
    }
    
    // 비번 자체가 다름 → 단순 실패 (격리 대상도 아님)
    return res.status(200).json({
        status: 'failed',
        message: '인증 실패',
        detail: '비번이나 잡은 단어를 확인해주세요',
      });
    
  } catch (err) {
    return res.status(500).json({ error: '검증 실패', detail: err.message });
  }
};
