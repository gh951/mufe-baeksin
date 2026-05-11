/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 인증 챌린지 발급 (Vercel 형식)
 *  
 *  POST /api/challenge
 *  → 회전 단어 30개 풀 + 무작위 이미지 발급
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

const WORD_POOL = [
  '진실', '미끼', '카오스', '백신', '인증', '발명', '대장', '클로드',
  '보안', '양자', '패러다임', '공생', '바보', '지혜', '직관', '수학',
  '인지', '심볼', '격자', '함정', '미로', '봉인', '자물쇠', '열쇠',
  '우주', '시간', '공간', '빛', '꽃', '실', '바람', '소리',
  '그림', '글자', '점', '선', '면', '체', '꿈', '깨달음',
  '창조', '울림', '균형', '하늘', '땅', '바다', '강', '산',
  '별', '달', '해', '구름', '비', '눈', '안개', '서리',
  '나무', '풀', '돌', '흙', '물', '불', '쇠', '금',
  '빨강', '파랑', '노랑', '초록', '보라', '주황', '하양', '검정',
  '회색', '분홍', '갈색', '청록', '연두', '남색', '자주',
  '기쁨', '슬픔', '평화', '용기', '희망', '믿음', '사랑', '온기',
  '고요', '맑음', '따뜻', '시원', '단단', '부드러움', '깊이', '높이',
  '자유', '진리', '아름다움', '선', '정의', '존재', '본질', '관계',
  '의미', '가치', '시작', '끝', '중심', '주변', '안', '밖',
  '걸음', '뜀', '날개', '흐름', '회전', '진동', '파동', '율동',
  '리듬', '박자', '변화', '성장', '도약', '비상', '도래', '귀환',
  '책', '거울', '문', '창', '길', '집', '뜰', '담',
  '돛', '배', '바퀴', '톱니', '샘', '우물', '다리', '계단',
  '아침', '낮', '저녁', '밤', '봄', '여름', '가을', '겨울',
  '하루', '한주', '한달', '일년', '순간', '영원', '찰나', '기억',
  '과학', '예술', '문학', '음악', '철학', '역사', '논리', '직감',
  '경험', '실험', '발견', '탐험', '연구', '관찰', '추론', '증명',
  '진동수', '파장', '주파수', '강도', '속도', '가속', '관성', '에너지',
  '입자', '파동', '장', '힘', '운동', '정지', '평형', '혼돈',
  '질서', '대칭', '비대칭', '회복', '치유', '재생', '순환', '연결'
];

const IMAGE_POOL = [
  '/images/chaos-sample-001.svg',
  '/images/chaos-sample-002.svg',
  '/images/chaos-sample-003.svg',
  '/images/chaos-000.png',
  '/images/chaos-001.png', '/images/chaos-002.png', '/images/chaos-003.png', '/images/chaos-004.png',
  '/images/chaos-005.png', '/images/chaos-006.png', '/images/chaos-007.png', '/images/chaos-008.png',
  '/images/chaos-009.png', '/images/chaos-010.png', '/images/chaos-011.png', '/images/chaos-012.png',
  '/images/chaos-013.png', '/images/chaos-014.png', '/images/chaos-015.png', '/images/chaos-016.png',
  '/images/chaos-017.png', '/images/chaos-018.png', '/images/chaos-019.png', '/images/chaos-020.png',
  '/images/chaos-021.png', '/images/chaos-022.png', '/images/chaos-023.png', '/images/chaos-024.png',
  '/images/chaos-025.png', '/images/chaos-026.png', '/images/chaos-027.png', '/images/chaos-028.png',
  '/images/chaos-029.png', '/images/chaos-030.png', '/images/chaos-031.png', '/images/chaos-032.png',
  '/images/chaos-033.png', '/images/chaos-034.png', '/images/chaos-035.png', '/images/chaos-036.png',
  '/images/chaos-037.png', '/images/chaos-038.png', '/images/chaos-039.png', '/images/chaos-040.png',
  '/images/chaos-041.png', '/images/chaos-042.png', '/images/chaos-043.png', '/images/chaos-044.png',
  '/images/chaos-045.png', '/images/chaos-046.png', '/images/chaos-047.png', '/images/chaos-048.png',
  '/images/chaos-049.png', '/images/chaos-050.png', '/images/chaos-051.png', '/images/chaos-052.png',
  '/images/chaos-053.png', '/images/chaos-054.png', '/images/chaos-055.png', '/images/chaos-056.png',
  '/images/chaos-057.png', '/images/chaos-058.png', '/images/chaos-059.png', '/images/chaos-060.png',
  '/images/chaos-061.png', '/images/chaos-062.png', '/images/chaos-063.png', '/images/chaos-064.png',
  '/images/chaos-065.png', '/images/chaos-066.png', '/images/chaos-067.png', '/images/chaos-068.png',
  '/images/chaos-069.png', '/images/chaos-070.png', '/images/chaos-071.png', '/images/chaos-072.png',
  '/images/chaos-073.png', '/images/chaos-074.png', '/images/chaos-075.png', '/images/chaos-076.png',
  '/images/chaos-077.png', '/images/chaos-078.png', '/images/chaos-079.png', '/images/chaos-080.png',
  '/images/chaos-081.png', '/images/chaos-082.png', '/images/chaos-083.png', '/images/chaos-084.png',
  '/images/chaos-085.png', '/images/chaos-086.png', '/images/chaos-087.png', '/images/chaos-088.png',
  '/images/chaos-089.png', '/images/chaos-090.png', '/images/chaos-091.png', '/images/chaos-092.png',
  '/images/chaos-093.png', '/images/chaos-094.png', '/images/chaos-095.png', '/images/chaos-096.png',
  '/images/chaos-097.png', '/images/chaos-098.png', '/images/chaos-099.png', '/images/chaos-100.png',
];

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    const timestamp = Date.now();
    
    const shuffled = [...WORD_POOL].sort(() => Math.random() - 0.5);
    const rotationWords = shuffled.slice(0, 30);
    
    let chaosImage = null;
    if (IMAGE_POOL.length > 0) {
      chaosImage = IMAGE_POOL[Math.floor(Math.random() * IMAGE_POOL.length)];
    }
    
    const challengeData = {
      words: rotationWords,
      img: chaosImage,
      t: timestamp,
      ip: typeof ip === 'string' ? ip.slice(0, 16) : 'unknown',
    };
    const dataStr = JSON.stringify(challengeData);
    const dataB64 = Buffer.from(dataStr).toString('base64');
    const signature = sign(dataB64);
    const challengeId = `${dataB64}.${signature}`;
    
    return res.status(200).json({
      challengeId,
      rotationWords,
      chaosImage,
      instruction: '회전하는 단어 중 원하는 시점에 STOP 누르세요',
      warning: '잡힌 단어 + 등록한 비번 = 답',
      expiresIn: 120,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Challenge generation failed', detail: err.message });
  }
};
