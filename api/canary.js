// ════════════════════════════════════════════════════════════════════════
//  MUFE 백신 — 미끼(canary) 알림 받는 서버 함수
//  파일 위치: 깃허브 무폐-백신 저장소의  /api/canary.js  (Vercel가 자동으로 /api/canary 주소로 배포)
//
//  하는 일: 미끼가 건드려졌다는 신호(POST)를 받아서
//    1) Firebase(Firestore)에 기록  2) 이메일로 알림  3) 기록은 3일 후 자동 삭제
//
//  ── 설치 (한 번만) ──────────────────────────────────────────────
//  1) 깃허브 무폐-백신 저장소에  package.json 의 dependencies 에 추가:
//         "firebase-admin": "^12.0.0"
//     (package.json 이 없으면 { "dependencies": { "firebase-admin": "^12.0.0" } } 로 만드세요)
//  2) 이 파일을 저장소  /api/canary.js  로 올리기 (Add file → Upload → commit)
//  3) Vercel 프로젝트 → Settings → Environment Variables 에 아래를 넣기:
//        FB_PROJECT_ID      = (Firebase 프로젝트 ID, 예: cgo-life)
//        FB_CLIENT_EMAIL    = (Firebase 서비스계정 이메일)
//        FB_PRIVATE_KEY     = (서비스계정 비공개 키 — \n 포함된 긴 문자열 통째로)
//        CANARY_ALERT_EMAIL = (알림 받을 메일 주소)   ← 본인 메일. 코드에 박지 말고 여기에!
//        RESEND_API_KEY     = (이메일 발송용 Resend API 키 — resend.com 가입 후 발급)
//        CANARY_ALLOW_ORIGIN= (선택) 앱 주소. 예: https://무폐-백신.vercel.app  (없으면 * )
//     · Firebase 서비스계정 키: Firebase 콘솔 → 프로젝트 설정 → 서비스 계정 → "새 비공개 키 생성"
//     · 이메일이 당장 힘들면 RESEND_API_KEY 만 빼세요 → 저장(Firestore)만 되고, 콘솔에서 확인 가능.
//  4) 클라이언트(index.html) 쪽 2줄 켜기 (스캐폴드에 이미 자리 있음):
//        window.MUFE_CANARY.endpoint = 'https://무폐-백신.vercel.app/api/canary';
//        window.MUFE_CANARY.enabled  = true;
//  5) 3일 휘발: Firebase 콘솔 → Firestore → canary_alerts 컬렉션 → TTL 정책을  expireAt  필드에 설정.
//
//  ※ 정직: 이 함수는 "신호를 받는 쪽"입니다. "누가 미끼를 실제로 열었는지"를 알려면,
//    미끼 파일 안에 이 주소로 핑(beacon)을 보내는 토큰을 심어야 합니다(다음 단계). 받는 함수만으론 덫이 완성 안 됩니다.
//  ※ 이건 시작용 함수입니다 — 실제 운영 전엔 속도제한·남용방지를 더 붙이세요.
// ════════════════════════════════════════════════════════════════════════

let admin = null;
try { admin = require('firebase-admin'); } catch (e) { /* 미설치면 저장은 건너뜀 */ }

// Firebase 1회 초기화 (환경변수 있을 때만)
let db = null;
if (admin && process.env.FB_PROJECT_ID && process.env.FB_CLIENT_EMAIL && process.env.FB_PRIVATE_KEY) {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FB_PROJECT_ID,
        clientEmail: process.env.FB_CLIENT_EMAIL,
        privateKey: (process.env.FB_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
      }),
    });
  }
  try { db = admin.firestore(); } catch (e) { db = null; }
}

module.exports = async (req, res) => {
  // 앱(브라우저)에서 호출 허용 (CORS)
  res.setHeader('Access-Control-Allow-Origin', process.env.CANARY_ALLOW_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const now = Date.now();
    const THREE_DAYS = 3 * 24 * 60 * 60 * 1000;

    const record = {
      decoyId: String(body.decoyId || 'unknown').slice(0, 120),
      meta: body.meta || {},
      ua: String(body.ua || '').slice(0, 200),
      ts: now,
      iso: new Date(now).toISOString(),
    };

    // 1) Firestore 저장 (설정돼 있을 때만) — expireAt 으로 3일 후 자동 삭제(TTL 정책 필요)
    if (db) {
      try {
        await db.collection('canary_alerts').add(Object.assign({}, record, {
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          expireAt: admin.firestore.Timestamp.fromMillis(now + THREE_DAYS),
        }));
      } catch (e) { /* 저장 실패해도 응답은 계속 */ }
    }

    // 2) 이메일 알림 (Resend 설정돼 있을 때만) — 실패해도 저장은 유지
    if (process.env.RESEND_API_KEY && process.env.CANARY_ALERT_EMAIL) {
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: process.env.CANARY_FROM || 'onboarding@resend.dev',
            to: process.env.CANARY_ALERT_EMAIL,
            subject: '🚨 MUFE 미끼 접근 감지',
            text:
              '미끼 파일 접근 신호가 감지되었습니다.\n\n' +
              'decoyId: ' + record.decoyId + '\n' +
              '시각: ' + record.iso + '\n' +
              'UA: ' + record.ua + '\n\n' +
              '(이 기록은 3일 후 자동 삭제됩니다)',
          }),
        });
      } catch (e) { /* 이메일 실패 무시 */ }
    } else {
      console.log('[canary] 신호 수신(이메일 미설정 — 저장만):', record.decoyId);
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }
};
