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
  '/무폐 이미지/chaos-sample-001.svg',
  '/무폐 이미지/chaos-sample-002.svg',
  '/무폐 이미지/chaos-sample-003.svg',
  '/무폐 이미지/chaos-000.png.jpeg',
  '/무폐 이미지/chaos-001.png.jpeg', '/무폐 이미지/chaos-002.png.jpeg', '/무폐 이미지/chaos-003.png.jpeg', '/무폐 이미지/chaos-004.png.jpeg',
  '/무폐 이미지/chaos-005.png.jpeg', '/무폐 이미지/chaos-006.png.jpeg', '/무폐 이미지/chaos-007.png.jpeg', '/무폐 이미지/chaos-008.png.jpeg',
  '/무폐 이미지/chaos-009.png.jpeg', '/무폐 이미지/chaos-010.png.jpeg', '/무폐 이미지/chaos-011.png.jpeg', '/무폐 이미지/chaos-012.png.jpeg',
  '/무폐 이미지/chaos-013.png.jpeg', '/무폐 이미지/chaos-014.png.jpeg', '/무폐 이미지/chaos-015.png.jpeg', '/무폐 이미지/chaos-016.png.jpeg',
  '/무폐 이미지/chaos-017.png.jpeg', '/무폐 이미지/chaos-018.png.jpeg', '/무폐 이미지/chaos-019.png.jpeg', '/무폐 이미지/chaos-020.png.jpeg',
  '/무폐 이미지/chaos-021.png.jpeg', '/무폐 이미지/chaos-022.png.jpeg', '/무폐 이미지/chaos-023.png.jpeg', '/무폐 이미지/chaos-024.png.jpeg',
  '/무폐 이미지/chaos-025.png.jpeg', '/무폐 이미지/chaos-026.png.jpeg', '/무폐 이미지/chaos-027.png.jpeg', '/무폐 이미지/chaos-028.png.jpeg',
  '/무폐 이미지/chaos-029.png.jpeg', '/무폐 이미지/chaos-030.png.jpeg', '/무폐 이미지/chaos-031.png.jpeg', '/무폐 이미지/chaos-032.png.jpeg',
  '/무폐 이미지/chaos-033.png.jpeg', '/무폐 이미지/chaos-034.png.jpeg', '/무폐 이미지/chaos-035.png.jpeg', '/무폐 이미지/chaos-036.png.jpeg',
  '/무폐 이미지/chaos-037.png.jpeg', '/무폐 이미지/chaos-038.png.jpeg', '/무폐 이미지/chaos-039.png.jpeg', '/무폐 이미지/chaos-040.png.jpeg',
  '/무폐 이미지/chaos-041.png.jpeg', '/무폐 이미지/chaos-042.png.jpeg', '/무폐 이미지/chaos-043.png.jpeg', '/무폐 이미지/chaos-044.png.jpeg',
  '/무폐 이미지/chaos-045.png.jpeg', '/무폐 이미지/chaos-046.png.jpeg', '/무폐 이미지/chaos-047.png.jpeg', '/무폐 이미지/chaos-048.png.jpeg',
  '/무폐 이미지/chaos-049.png.jpeg', '/무폐 이미지/chaos-050.png.jpeg', '/무폐 이미지/chaos-051.png.jpeg', '/무폐 이미지/chaos-052.png.jpeg',
  '/무폐 이미지/chaos-053.png.jpeg', '/무폐 이미지/chaos-054.png.jpeg', '/무폐 이미지/chaos-055.png.jpeg', '/무폐 이미지/chaos-056.png.jpeg',
  '/무폐 이미지/chaos-057.png.jpeg', '/무폐 이미지/chaos-058.png.jpeg', '/무폐 이미지/chaos-059.png.jpeg', '/무폐 이미지/chaos-060.png.jpeg',
  '/무폐 이미지/chaos-061.png.jpeg', '/무폐 이미지/chaos-062.png.jpeg', '/무폐 이미지/chaos-063.png.jpeg', '/무폐 이미지/chaos-064.png.jpeg',
  '/무폐 이미지/chaos-065.png.jpeg', '/무폐 이미지/chaos-066.png.jpeg', '/무폐 이미지/chaos-067.png.jpeg', '/무폐 이미지/chaos-068.png.jpeg',
  '/무폐 이미지/chaos-069.png.jpeg', '/무폐 이미지/chaos-070.png.jpeg', '/무폐 이미지/chaos-071.png.jpeg', '/무폐 이미지/chaos-072.png.jpeg',
  '/무폐 이미지/chaos-073.png.jpeg', '/무폐 이미지/chaos-074.png.jpeg', '/무폐 이미지/chaos-075.png.jpeg', '/무폐 이미지/chaos-076.png.jpeg',
  '/무폐 이미지/chaos-077.png.jpeg', '/무폐 이미지/chaos-078.png.jpeg', '/무폐 이미지/chaos-079.png.jpeg', '/무폐 이미지/chaos-080.png.jpeg',
  '/무폐 이미지/chaos-081.png.jpeg', '/무폐 이미지/chaos-082.png.jpeg', '/무폐 이미지/chaos-083.png.jpeg', '/무폐 이미지/chaos-084.png.jpeg',
  '/무폐 이미지/chaos-085.png.jpeg', '/무폐 이미지/chaos-086.png.jpeg', '/무폐 이미지/chaos-087.png.jpeg', '/무폐 이미지/chaos-088.png.jpeg',
  '/무폐 이미지/chaos-089.png.jpeg', '/무폐 이미지/chaos-090.png.jpeg', '/무폐 이미지/chaos-091.png.jpeg', '/무폐 이미지/chaos-092.png.jpeg',
  '/무폐 이미지/chaos-093.png.jpeg', '/무폐 이미지/chaos-094.png.jpeg', '/무폐 이미지/chaos-095.png.jpeg', '/무폐 이미지/chaos-096.png.jpeg',
  '/무폐 이미지/chaos-097.png.jpeg', '/무폐 이미지/chaos-098.png.jpeg', '/무폐 이미지/chaos-099.png.jpeg', '/무폐 이미지/chaos-100.png.jpeg',
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
      expiresIn: 600,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Challenge generation failed', detail: err.message });
  }
};
