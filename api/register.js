/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 사용자 등록 (Vercel 형식)
 *  
 *  POST /api/register
 *  body: { passcode, format }
 *  → mufe-u 토큰 발급 (HMAC 서명)
 * ════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

const SECRET = process.env.MUFE_SECRET || 'mufe-c33-default-secret-change-in-production';
const VALID_FORMATS = ['joined-after', 'spaced-after', 'joined-before', 'spaced-before'];

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { passcode, format } = req.body || {};
    
    if (!passcode || passcode.length < 1) {
      return res.status(400).json({ error: '비번을 입력해주세요' });
    }
    
    if (!VALID_FORMATS.includes(format)) {
      return res.status(400).json({ error: '유효한 형식을 선택해주세요' });
    }
    
    const payload = {
      type: 'user-registration',
      issuedAt: Date.now(),
      sessionId: crypto.randomBytes(8).toString('hex'),
      passcode,
      format,
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    const sig = sign(payloadB64);
    const token = `mufe-u.${payloadB64}.${sig}`;
    
    return res.status(200).json({
      status: 'success',
      token,
      message: '✓ 등록 완료',
      detail: `${format} 형식으로 등록됨. 다음 인증부터 이 형식 그대로 답해주세요.`,
    });
  } catch (err) {
    return res.status(500).json({ error: '등록 실패', detail: err.message });
  }
};
