// ════════════════════════════════════════════════════════════════════════
//  MUFE 백신 — 미끼(canary) 신호 받는 서버 함수
//  파일 위치: 깃허브 무폐-백신 저장소의  /api/canary.js
//
//  이 버전의 특징
//   · 저장 = Firebase(Firestore). 무료 Spark 플랜은 한도를 넘으면 "청구 없이 멈춤"
//     → 해커가 디도스로 퍼부어도 과금 폭탄이 날 수 없음(돈 0원, 그날 기록만 잠시 멈춤).
//   · 속도 제한 내장: 짧은 시간에 폭주해도 60초에 한 번만 실제 기록/알림
//     → 평소엔 DB를 거의 안 건드림 = 비용 보호 1차벽.
//   · 3일 휘발: expireAt 필드 + Firestore TTL 정책으로 자동 삭제.
//   · 이메일: 기본 꺼짐(비용 우려로 보류). 나중에 켜도 같은 속도제한이 적용됨.
//   · "실시간 글로벌 IP 차단벽" 같은 건 넣지 않음(효과 약하고 위험만 추가).
//
//  ── 환경변수 (Vercel → Settings → Environment Variables) ──
//   FB_PROJECT_ID    = Firebase 프로젝트 ID (예: cgo-life)
//   FB_CLIENT_EMAIL  = 서비스계정 이메일 (다운받은 키 JSON 안의 client_email)
//   FB_PRIVATE_KEY   = 서비스계정 비공개 키 (키 JSON 안의 private_key, \n 포함 통째로)
//   (선택) CANARY_ALLOW_ORIGIN = 앱 주소. 예: https://mufe-sin.vercel.app  (없으면 * )
//   (선택, 이메일 켤 때만) RESEND_API_KEY, CANARY_ALERT_EMAIL
//
//  ── 3일 휘발 켜기 ──
//   Firebase 콘솔 → Firestore → TTL 정책 → 컬렉션 canary_alerts, 필드 expireAt 지정.
//
//  ※ 정직: 이 함수는 "신호를 받는 쪽"입니다. "누가 미끼를 실제로 열었는지"까지 잡으려면
//    미끼 파일 안에 이 주소로 핑 보내는 토큰을 심어야 합니다(다음 단계).
//  ※ 이건 곁가지(데모) 기능입니다. 핵심 보안 아님 — 가볍게 두세요.
// ════════════════════════════════════════════════════════════════════════

let admin = null;
try { admin = require('firebase-admin'); } catch (e) { /* 미설치면 저장 건너뜀 */ }

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

// ── 속도 제한 (1차벽) ──
// 이 함수 인스턴스 기준 최소 간격. 웜 상태에서 폭주를 흡수해 DB·비용을 지킨다.
// (인스턴스마다·콜드스타트마다 초기화되므로 완벽한 전역 제한은 아니지만,
//  진짜 최종 방어는 Firebase Spark의 "한도 초과 시 청구 없이 멈춤"이다.)
const THROTTLE_MS = 60 * 1000;   // 60초에 한 번만 실제 처리
let _lastHandledTs = 0;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.CANARY_ALLOW_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false });

  const now = Date.now();

  // 1) 속도 제한: 최근에 처리했으면 그냥 통과(기록·알림 안 함) → DB 안 건드림 = 비용 0
  if (now - _lastHandledTs < THROTTLE_MS) {
    return res.status(200).json({ ok: true, throttled: true });
  }
  _lastHandledTs = now;

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const THREE_DAYS = 3 * 24 * 60 * 60 * 1000;
    const record = {
      decoyId: String(body.decoyId || 'unknown').slice(0, 120),
      ua: String(body.ua || '').slice(0, 200),
      ts: now,
      iso: new Date(now).toISOString(),
    };

    // 2) Firestore 저장 (설정돼 있을 때만). expireAt → TTL 정책으로 3일 후 자동 삭제.
    if (db) {
      try {
        await db.collection('canary_alerts').add(Object.assign({}, record, {
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          expireAt: admin.firestore.Timestamp.fromMillis(now + THREE_DAYS),
        }));
      } catch (e) { /* 저장 실패해도 응답은 계속 */ }
    } else {
      console.log('[canary] 신호 수신(저장 미설정):', record.decoyId);
    }

    // 3) 이메일 — 기본 꺼짐. RESEND_API_KEY 와 CANARY_ALERT_EMAIL 둘 다 있을 때만 동작.
    //    (위 속도제한을 이미 통과한 뒤라서 메일도 60초에 한 통 이하로 제한됨 = 폭탄 불가)
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
              '미끼 접근 신호가 감지되었습니다.\n\n' +
              'decoyId: ' + record.decoyId + '\n' +
              '시각: ' + record.iso + '\n' +
              'UA: ' + record.ua + '\n\n' +
              '(속도제한 적용 / 기록은 3일 후 자동 삭제)',
          }),
        });
      } catch (e) { /* 이메일 실패 무시 */ }
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }
};
