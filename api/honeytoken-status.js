/**
 * MUFE 백신 — 미끼(허니토큰) 상태 읽기 (서버, 읽기 전용)  [C-52]
 *
 *  /api/recover(덫)와 달리 여기는 '읽기만' 한다 — 카운트를 올리지 않는다.
 *  대시보드가 "서버가 센 미끼 물림 누적 / 마지막 물린 시각"을 보여주려고 호출한다.
 *  민감정보(IP·UA)는 내보내지 않는다(요약만).
 *  안전: 더하기 전용. 기존 로직과 무관. 실패해도 0으로 응답.
 */
const { kvGet, isKVAvailable } = require('./_kv');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let hits = 0;
  let lastAt = null;
  let lastMethod = null;

  try {
    if (isKVAvailable()) {
      const raw = await kvGet('stats:honeytoken:hit');
      hits = (typeof raw === 'number') ? raw : (parseInt(raw, 10) || 0);
      const last = await kvGet('honeytoken:last');
      if (last && typeof last === 'object') {
        lastAt = last.at || null;
        lastMethod = last.method || null;
      }
    }
  } catch (e) { /* 읽기 실패해도 0으로 응답 */ }

  return res.status(200).json({ hits, lastAt, lastMethod });
};
