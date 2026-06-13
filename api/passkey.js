/**
 * ════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 패스키(WebAuthn) 서버 검증  [C-55 · #2]
 *
 *  목적: 출입문(패스키) 검증을 *서버로 격상*.
 *   1) register : 등록 때 공개키(spki)만 서버에 저장 (개인키는 폰 보안칩에만)
 *   2) challenge: 서버가 1회용 숫자 발급 (재전송·재생공격 차단)
 *   3) verify   : 폰이 그 숫자에 찍은 ECDSA(P-256) 서명을 *서버가* 공개키로 검증
 *                 → 통과 시 패스키 세션 토큰 발급 + 우회 시도 서버 기록
 *
 *  · 추가형: 클라의 기존 검증을 대체하지 않는다(클라는 폴백으로 유지) → 오류 0.
 *  · 정직: 최종 진입 판정은 클라에 남아 '껍데기 우회'까지 닫진 못함.
 *          진짜 금고는 verify.js·proof.js 토큰이 따로 지킨다.
 *  · MUFE_SECRET 없으면 거부(조용한 약화 방지). 거부 벽 없음 — 실패는 'locked'.
 * ════════════════════════════════════════════════════════════════
 */
const crypto = require('crypto');
const { kvGet, kvSet, kvDel, kvIncr, isKVAvailable } = require('./_kv');

const SECRET = process.env.MUFE_SECRET;   // 기본키 fallback 없음
const NONCE_TTL = 120;                    // 1회용 챌린지 120초
// [#2 피싱] 허용 origin 화이트리스트 — 환경변수(MUFE_ORIGIN, 콤마 구분) 우선, 없으면 기본 도메인.
//   피싱 사이트(다른 origin)에서 온 패스키 응답은 여기서 차단. 패스키는 보조 출입문이라, 막혀도 본 인증(비번+생체)은 별개로 작동.
const DEFAULT_ORIGINS = ['https://mufe-baeksin.com', 'https://www.mufe-baeksin.com', 'https://e-baeksin.com', 'https://www.e-baeksin.com'];
const ENV_ORIGINS = (process.env.MUFE_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
const ALLOWED_ORIGINS = ENV_ORIGINS.length ? ENV_ORIGINS : DEFAULT_ORIGINS;

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex').slice(0, 16);
}
// 패스키 통과 세션 토큰 (출입문용 — 금고 토큰과는 별개 prefix)
function issueToken(credHash) {
  const payload = { type: 'passkey', issuedAt: Date.now(), sessionId: crypto.randomBytes(8).toString('hex'), via: 'passkey', ck: credHash };
  const b = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `mufe-pk.${b}.${sign(b)}`;
}
function b64ToBuf(s) { return Buffer.from(String(s || ''), 'base64'); }

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ status: 'error', error: 'Method not allowed' });
  if (!SECRET) return res.status(500).json({ status: 'error', error: 'server-misconfigured' });
  if (!isKVAvailable()) return res.status(200).json({ status: 'no-storage', message: '서버 저장소(KV) 미연결 — 패스키 서버검증 사용 불가' });

  try {
    const { action, credId, spki, authData, clientDataJSON, signature } = req.body || {};
    if (typeof credId !== 'string' || credId.length < 4) {
      return res.status(200).json({ status: 'error', message: 'credId 필요' });
    }
    const credHash = crypto.createHash('sha256').update(credId).digest('hex').slice(0, 24);

    // ── 1) 공개키 등록 (등록 때 1회) ──
    if (action === 'register') {
      if (typeof spki !== 'string' || spki.length < 40) {
        return res.status(200).json({ status: 'error', message: '공개키 형식 오류' });
      }
      const existing = await kvGet('pkpub:' + credHash);
      if (existing) {
        // 첫 등록만 신뢰 — 같은 키면 OK, 다른 키면 덮어쓰기 금지
        return res.status(200).json({ status: existing === spki ? 'registered' : 'exists', message: '이미 등록된 패스키 공개키가 있습니다' });
      }
      await kvSet('pkpub:' + credHash, spki);
      await kvIncr('stats:pk:register');
      return res.status(200).json({ status: 'registered' });
    }

    // ── 2) 1회용 챌린지 발급 (b64url) ──
    if (action === 'challenge') {
      const n = crypto.randomBytes(32).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');   // b64url (WebAuthn 비교용)
      await kvSet('pkch:' + credHash, n, NONCE_TTL);
      return res.status(200).json({ status: 'challenge', challenge: n });
    }

    // ── 3) 서명 검증 → 패스키 세션 토큰 ──
    if (action === 'verify') {
      const spkiStored = await kvGet('pkpub:' + credHash);
      if (!spkiStored) return res.status(200).json({ status: 'locked', message: '등록된 공개키 없음 — 먼저 등록하세요' });

      const storedCh = await kvGet('pkch:' + credHash);
      await kvDel('pkch:' + credHash);                       // 1회용: 즉시 폐기
      if (!storedCh) return res.status(200).json({ status: 'locked', message: '챌린지 만료 — 다시 시도' });

      // clientDataJSON 파싱·검증
      let cd;
      try { cd = JSON.parse(b64ToBuf(clientDataJSON).toString()); } catch { return res.status(200).json({ status: 'locked', message: 'clientData 형식 오류' }); }
      if (cd.type !== 'webauthn.get') { await kvIncr('stats:pk:bad-type'); return res.status(200).json({ status: 'locked', message: 'type 불일치' }); }
      if (cd.challenge !== storedCh) { await kvIncr('stats:pk:bad-challenge'); return res.status(200).json({ status: 'locked', message: '챌린지 불일치' }); }
      if (!ALLOWED_ORIGINS.includes(cd.origin)) { await kvIncr('stats:pk:bad-origin'); return res.status(200).json({ status: 'locked', message: 'origin 불일치 (피싱 차단)' }); }

      // authenticatorData 플래그 (UP=presence, UV=user verified)
      const authBuf = b64ToBuf(authData);
      if (authBuf.length < 37) return res.status(200).json({ status: 'locked', message: 'authData 형식 오류' });
      const flags = authBuf[32];
      if (!(flags & 0x01)) return res.status(200).json({ status: 'locked', message: 'user presence 없음' });
      if (!(flags & 0x04)) { await kvIncr('stats:pk:no-uv'); return res.status(200).json({ status: 'locked', message: '생체 확인(UV) 안 됨' }); }

      // ECDSA(P-256) 서명 검증 — 서명 대상 = authData || SHA256(clientDataJSON)
      const cdHash = crypto.createHash('sha256').update(b64ToBuf(clientDataJSON)).digest();
      const signed = Buffer.concat([authBuf, cdHash]);
      let ok = false;
      try {
        const pub = crypto.createPublicKey({ key: b64ToBuf(spkiStored), format: 'der', type: 'spki' });
        ok = crypto.verify('sha256', signed, { key: pub, dsaEncoding: 'der' }, b64ToBuf(signature));
      } catch (e) { ok = false; }

      if (!ok) { await kvIncr('stats:pk:bad-sig'); return res.status(200).json({ status: 'locked', message: '서명 검증 실패' }); }

      // [강화] 서명 카운터 검증 — 복제된 인증기 탐지. authData[33..36]가 단조증가해야 함.
      //   단, 동기 패스키(iCloud/구글 등)는 counter=0 고정이라 그 경우만 건너뜀(정상 사용자 안 깨지게).
      const counter = authBuf.length >= 37 ? authBuf.readUInt32BE(33) : 0;
      if (counter > 0) {
        const prev = (await kvGet('pkcnt:' + credHash)) || 0;
        if (counter <= prev) {
          await kvIncr('stats:pk:clone-suspect');
          return res.status(200).json({ status: 'locked', message: '카운터 역행 — 복제 의심' });
        }
        await kvSet('pkcnt:' + credHash, counter);
      }

      await kvIncr('stats:pk:verified');
      return res.status(200).json({ status: 'ok', token: issueToken(credHash) });
    }

    // ── 4) 네이티브 보안칩(TEE) 서명 검증  [#5 · TEE 바인딩 2단계] ──
    //   안드로이드 보안칩(StrongBox/TEE)이 만든 P-256 키로, challenge에 *직접* 서명한 것을 검증.
    //   WebAuthn 래핑(clientDataJSON/authData) 없음 — 네이티브가 challenge 바이트에 SHA256withECDSA 서명.
    //   생체 강제는 칩(setUserAuthenticationRequired=true)이 보장 → 서명이 존재한다는 것 자체가 생체 통과 증거.
    //   공개키 등록·챌린지 발급은 위의 register·challenge 액션을 그대로 재사용한다(additive).
    if (action === 'tee-verify') {
      const spkiStored = await kvGet('pkpub:' + credHash);
      if (!spkiStored) return res.status(200).json({ status: 'locked', message: '등록된 보안칩 공개키 없음 — 먼저 register' });

      const storedCh = await kvGet('pkch:' + credHash);
      await kvDel('pkch:' + credHash);                       // 1회용: 즉시 폐기 (재전송 차단)
      if (!storedCh) return res.status(200).json({ status: 'locked', message: '챌린지 만료 — 다시 시도' });

      if (typeof signature !== 'string' || signature.length < 40) {
        return res.status(200).json({ status: 'locked', message: '서명 형식 오류' });
      }

      // 서명 대상 = challenge 문자열의 UTF-8 바이트 (네이티브 challenge.getBytes("UTF-8")와 동일)
      const signed = Buffer.from(storedCh, 'utf8');
      let ok = false;
      try {
        const pub = crypto.createPublicKey({ key: b64ToBuf(spkiStored), format: 'der', type: 'spki' });
        ok = crypto.verify('sha256', signed, { key: pub, dsaEncoding: 'der' }, b64ToBuf(signature));
      } catch (e) { ok = false; }

      if (!ok) { await kvIncr('stats:tee:bad-sig'); return res.status(200).json({ status: 'locked', message: '보안칩 서명 검증 실패' }); }

      await kvIncr('stats:tee:verified');
      // 출입문 통과 토큰 발급 (금고 토큰과는 별개 — 본 인증/금고는 verify.js·proof.js가 따로 지킴)
      return res.status(200).json({ status: 'ok', via: 'tee', token: issueToken(credHash) });
    }

    return res.status(200).json({ status: 'error', message: '알 수 없는 action' });
  } catch (err) {
    console.error('[passkey] error:', err && err.message);
    return res.status(500).json({ status: 'error' });
  }
};
