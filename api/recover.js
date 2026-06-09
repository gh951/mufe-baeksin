/**
 * MUFE 백신 — 미끼(허니토큰) 덫 엔드포인트  [C-52]
 *
 *  목적: 이 엔드포인트(/api/recover)와 그 키(MUFE_MASTER_RECOVERY_KEY)는 '코드에만' 존재한다.
 *        정상 사용자·정상 흐름은 절대 호출하지 않는다.
 *        → 누군가 호출하면 = 코드를 읽고 캐낸 공격자(또는 자동 분석 도구)다.
 *        호출 사실을 창고(KV)에 기록(카나리)하고, 클라는 이 응답을 받아 연산지옥(늪)으로 간다.
 *
 *  안전: 더하기 전용. 기존 인증/검증 로직과 완전히 무관. 실패해도 앱에 영향 없음.
 *  주의: 진짜 키·진짜 복구 기능은 여기 없다(전부 가짜). 진짜 비밀이 코드에 없을수록 이 덫이 강해진다.
 */
const { kvIncr, kvSet, isKVAvailable } = require('./_kv');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // 어떤 방식(GET/POST)으로 들어와도 = 미끼를 건드린 것 = 공격자
  let hits = null;
  try {
    const fwd = (req.headers['x-forwarded-for'] || '');
    const ip = fwd.split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '';
    const ua = req.headers['user-agent'] || '';
    const day = new Date().toISOString().slice(0, 10);
    if (isKVAvailable()) {
      hits = await kvIncr('stats:honeytoken:hit');         // 누적 +1 (새 값 반환)
      await kvIncr(`stats:honeytoken:by-day:${day}`);
      // 마지막으로 미끼를 문 흔적 (운영자 확인용)
      await kvSet('honeytoken:last', { at: Date.now(), ip, ua, method: req.method });
    }
  } catch (e) { /* 기록이 실패해도 덫 자체는 작동한다 */ }

  // 공격자에겐 '성공처럼' 보이는 미끼 응답 — 실제로는 연산지옥行 신호(status:'decoy')
  // hits: 서버가 센 미끼 물림 누적 (서버 기록 확인용)
  return res.status(200).json({
    status: 'decoy',
    message: '정답입니다. 통과 다음 단계로',
    trap: true,
    hits: (typeof hits === 'number') ? hits : undefined,
    detail: '',
  });
};
