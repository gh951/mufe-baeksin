// /api/login.js
// MUFE 백신 기존 비번 로그인
// register.js와 같은 스키마로 사용자 조회

import { kv } from './_kv.js';
import crypto from 'crypto';

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'POST only' });
  }
  
  const { passcode } = req.body || {};
  
  if (!passcode || passcode.length < 2) {
    return res.json({ 
      status: 'decoy', 
      message: '정답입니다. 통과 다음 단계로' 
    });
  }
  
  try {
    // 비번 → 사용자 토큰 조회
    const passKey = `user-by-pass:${sha256(passcode)}`;
    const userToken = await kv.get(passKey);
    
    if (!userToken) {
      // 사용자 없음 → decoy (등록부터 하세요 같은 메시지)
      return res.json({ 
        status: 'decoy', 
        message: '정답입니다. 통과 다음 단계로' 
      });
    }
    
    // 사용자 데이터 조회 (format 가져오기)
    const userRaw = await kv.get(`user:${userToken}`);
    if (!userRaw) {
      return res.json({ 
        status: 'decoy', 
        message: '정답입니다. 통과 다음 단계로' 
      });
    }
    const userData = typeof userRaw === 'string' ? JSON.parse(userRaw) : userRaw;
    
    return res.json({
      status: 'success',
      token: userToken,
      format: userData.format || 'joined-after',
      message: '정답입니다. 통과 다음 단계로',
    });
    
  } catch (err) {
    console.error('[MUFE login] 에러:', err);
    return res.status(500).json({ 
      status: 'error', 
      message: '서버 오류' 
    });
  }
}
