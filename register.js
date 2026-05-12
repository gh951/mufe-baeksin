// /api/register.js
// MUFE 백신 비번 등록
// verify.js와 정확히 같은 스키마 사용 — sha256(salt + passcode)

import { kv } from './_kv.js';
import crypto from 'crypto';

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'POST only' });
  }
  
  const { passcode, format } = req.body || {};
  
  if (!passcode || passcode.length < 2) {
    return res.status(400).json({ 
      status: 'error', 
      message: '비번은 2자 이상' 
    });
  }
  
  try {
    // 옛 사용자 (같은 비번) 존재 여부 확인
    const passKey = `user-by-pass:${sha256(passcode)}`;
    let userToken = await kv.get(passKey);
    
    if (!userToken) {
      // 새 사용자
      userToken = crypto.randomBytes(16).toString('hex');
      await kv.set(passKey, userToken);
    }
    
    // 비번 해시 (verify.js와 동일 스키마)
    const salt = crypto.randomBytes(8).toString('hex');
    const passcodeHash = sha256(salt + passcode);
    
    const userData = {
      userToken,
      passcodeHash,        // sha256(salt + passcode)
      salt,                // 솔트 (verify에서 같이 사용)
      format: format || 'joined-after',
      createdAt: Date.now(),
    };
    
    await kv.set(`user:${userToken}`, JSON.stringify(userData));
    
    return res.json({
      status: 'success',
      token: userToken,
      format: format || 'joined-after',
      message: '정답입니다. 통과 다음 단계로',
    });
    
  } catch (err) {
    console.error('[MUFE register] 에러:', err);
    return res.status(500).json({ 
      status: 'error', 
      message: '서버 오류' 
    });
  }
}
