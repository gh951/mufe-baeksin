/**
 * MUFE 백신 — 서버 금고 (Stage 1)
 *
 * [C-52] 인증(서버 검증)된 사용자에게만 보호 구역 HTML을 내려준다.
 *   - 진짜(real) 마스터 토큰만 통과. 미끼/없음/위조 → 빈 응답(거부 신호 없음).
 *   - 보호 구역은 index.html DOM에 없음 → 게이트를 우회해도 텅 빈 슬롯만 남는다.
 *   - 토큰은 /api/verify 성공 시 발급된 'real' 마스터 토큰(mufe.<payload>.<sig>).
 */
const crypto = require('crypto');
const SECRET = process.env.MUFE_SECRET;

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

// 진짜(real) 마스터 토큰만 통과 — 미끼/등록만 한 토큰은 거절
function verifyRealToken(token) {
  if (!token || !token.startsWith('mufe.')) return null;   // mufe-u./mufe-r. 는 startsWith('mufe.')=false
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payloadB64, signature] = parts;
  if (sign(payloadB64) !== signature) return null;
  try {
    const p = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
    return p.type === 'real' ? p : null;
  } catch { return null; }
}

// 보호 구역들 — 인증된 사용자에게만 내려간다. (구역을 늘리면 여기에 추가)
const VAULT_SECTIONS = {
  security: `    <div class="panel panel-security" data-panel="security">
      <div class="panel-content">
        <div class="panel-header">
          <h2>보안 정책</h2>
          <p>현재 시스템에 적용된 보안 원칙을 확인하세요.</p>
        </div>

        <div class="policy-grid">
          <div class="policy-card" data-policy="decoy">
            <div class="policy-icon">🛡️</div>
            <div class="policy-title">미끼 트랩 (Decoy)</div>
            <div class="policy-desc">표면에 보이는 답은 가짜입니다. 시도하면 샌드스로 격리됩니다.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="decoy" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>

          <div class="policy-card" data-policy="dynamic">
            <div class="policy-icon">🔄</div>
            <div class="policy-title">시도자별 동적 답</div>
            <div class="policy-desc">매 시도마다 다른 답이 생성됩니다. 답을 외워둘 수 없습니다.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="dynamic" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>

          <div class="policy-card" data-policy="cognitive">
            <div class="policy-icon">🧠</div>
            <div class="policy-title">인지 비대칭</div>
            <div class="policy-desc">사람은 즉시 인지하나, AI/봇은 분석할수록 더 깊이 빠집니다.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="cognitive" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>

          <div class="policy-card" data-policy="quantum">
            <div class="policy-icon">⚛️</div>
            <div class="policy-title">양자 내성</div>
            <div class="policy-desc">RSA·ECC·PQC가 모두 깨져도 작동 — 양자·AI 시대 카오스 인증.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="quantum" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>

          <div class="policy-card" data-policy="delegate">
            <div class="policy-icon">🎭</div>
            <div class="policy-title">위임 인증</div>
            <div class="policy-desc">사용자가 별도 암호로 다른 사람에게 인증을 위임할 수 있습니다.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="delegate" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>

          <div class="policy-card" data-policy="autorenew">
            <div class="policy-icon">♾️</div>
            <div class="policy-title">자가 갱신</div>
            <div class="policy-desc">카오스 시드와 미끼 파일이 자동으로 회전·갱신됩니다.</div>
            <label class="policy-toggle">
              <input type="checkbox" data-policy-key="autorenew" checked onchange="togglePolicy(this)">
              <span class="policy-slider"></span>
            </label>
          </div>
        </div>

        <div class="panel-info">
          <div class="info-icon">🔐</div>
          <div class="info-text">
            <strong>"보이는 게 진실이 아니다"</strong>
            모든 보안 정책은 위 명제 위에서 설계되었습니다.
          </div>
        </div>
      </div>
    </div>`,
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!SECRET) return res.status(500).json({ error: 'server-misconfigured' });

  try {
    const { token } = req.body || {};
    const real = verifyRealToken(token);
    if (!real) {
      // 인증 안 됨 — '거부' 신호 없이 빈 금고 (우회자는 아무것도 못 얻음)
      return res.status(200).json({ sections: {} });
    }
    return res.status(200).json({ sections: VAULT_SECTIONS });
  } catch (err) {
    return res.status(500).json({ error: 'vault error', detail: err.message });
  }
};
