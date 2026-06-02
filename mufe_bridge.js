/* ════════════════════════════════════════════════════════════════════
 *  MUFE 백신 — Wasm 연결 브리지 (mufe_bridge.js)
 *
 *  index.html 이 이 파일을 불러서 window.MUFE_WASM 으로 진짜 무기를 씁니다.
 *
 *  ▶ 동작:
 *    - mufe_core.wasm 이 있으면  → 진짜 C 코어(물리 휘발) 사용
 *    - 없으면(아직 빌드 전)       → JS 폴백(시연 모드)으로 자동 전환
 *      → 그래서 .wasm 굽기 전에도 화면은 멀쩡히 돌아감.
 *      → 나중에 mufe_core.wasm 만 서버에 올리면 자동으로 진짜 무기로 승격.
 *
 *  ▶ index.html 에서 쓰는 법:
 *      await MUFE_WASM.ready();
 *      const { helper, commit } = MUFE_WASM.enroll(sliderCoord, pupilArray, answerStr);
 *      const ok = MUFE_WASM.authenticate(sliderCoord, pupilArray, answerStr, helper, commit);
 * ════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const KEY_LEN = 32, COMMIT_LEN = 32;
  let mod = null;          // 로드된 wasm 모듈
  let usingWasm = false;   // true=진짜 C코어, false=JS폴백
  let readyPromise = null;

  /* ── 문자열(답)을 UTF-8 바이트로 ── */
  function strBytes(s) { return new TextEncoder().encode(s || ''); }

  /* ── wasm 로드 시도 (없으면 폴백) ── */
  function ready() {
    if (readyPromise) return readyPromise;
    readyPromise = (async () => {
      if (typeof createMufeCore === 'function') {
        try {
          mod = await createMufeCore();
          usingWasm = true;
          console.log('%c[MUFE-WASM] 진짜 C 코어 로드됨 — 물리적 휘발 가동', 'color:#16a34a;font-weight:bold');
        } catch (e) {
          console.warn('[MUFE-WASM] wasm 로드 실패 → JS 폴백', e);
          usingWasm = false;
        }
      } else {
        console.log('%c[MUFE-WASM] wasm 없음 → JS 폴백(시연) — .wasm 올리면 자동 승격', 'color:#d4a843');
        usingWasm = false;
      }
      return usingWasm;
    })();
    return readyPromise;
  }

  /* ════════════════════════════════════════════════════════════
   *  Wasm 메모리에 배열을 올리고 포인터 얻기 (진짜 모드용)
   * ════════════════════════════════════════════════════════════ */
  function pushFloats(arr) {
    const n = arr.length;
    const ptr = mod._malloc(n * 4);
    mod.HEAPF32.set(arr, ptr >> 2);
    return { ptr, n, free: () => mod._free(ptr) };
  }
  function pushBytes(bytes) {
    const ptr = mod._malloc(bytes.length || 1);
    mod.HEAPU8.set(bytes, ptr);
    return { ptr, n: bytes.length, free: () => mod._free(ptr) };
  }
  function pullBytes(ptr, len) {
    return mod.HEAPU8.slice(ptr, ptr + len);
  }

  /* ════════════════════════════════════════════════════════════
   *  [등록]  슬라이더+동공+답 → 헬퍼데이터 + 커밋먼트
   * ════════════════════════════════════════════════════════════ */
  function enroll(sliderCoord, pupilArray, answerStr) {
    const ans = strBytes(answerStr);
    if (usingWasm) {
      const P = pushFloats(Float32Array.from(pupilArray));
      const A = pushBytes(ans);
      const helperPtr = mod._malloc(KEY_LEN);
      const commitPtr = mod._malloc(COMMIT_LEN);
      mod.ccall('mufe_enroll', 'number',
        ['number','number','number','number','number','number','number'],
        [sliderCoord, P.ptr, P.n, A.ptr, A.n, helperPtr, commitPtr]);
      const helper = pullBytes(helperPtr, KEY_LEN);
      const commit = pullBytes(commitPtr, COMMIT_LEN);
      P.free(); A.free(); mod._free(helperPtr); mod._free(commitPtr);
      return { helper: Array.from(helper), commit: Array.from(commit), wasm: true };
    }
    /* ── JS 폴백 (시연) ── */
    return _jsEnroll(sliderCoord, pupilArray, ans);
  }

  /* ════════════════════════════════════════════════════════════
   *  [인증]  오늘 입력 + 헬퍼 → 키 복원 → 통과/실패(1/0)
   * ════════════════════════════════════════════════════════════ */
  function authenticate(sliderCoord, pupilArray, answerStr, helperArr, commitArr) {
    const ans = strBytes(answerStr);
    if (usingWasm) {
      const P = pushFloats(Float32Array.from(pupilArray));
      const A = pushBytes(ans);
      const H = pushBytes(Uint8Array.from(helperArr));
      const C = pushBytes(Uint8Array.from(commitArr));
      const proofPtr = mod._malloc(COMMIT_LEN);
      const r = mod.ccall('mufe_authenticate', 'number',
        ['number','number','number','number','number','number','number','number'],
        [sliderCoord, P.ptr, P.n, A.ptr, A.n, H.ptr, C.ptr, proofPtr]);
      P.free(); A.free(); H.free(); C.free(); mod._free(proofPtr);
      /* 진짜 휘발 검증 (박사 시연용): 0이면 메모리에서 키 완전 증발 */
      const leak = mod.ccall('mufe_master_key_nonzero', 'number', [], []);
      return { pass: r === 1, wiped: leak === 0, wasm: true };
    }
    /* ── JS 폴백 (시연) ── */
    return _jsAuth(sliderCoord, pupilArray, ans, helperArr, commitArr);
  }

  /* ════════════════════════════════════════════════════════════
   *  JS 폴백 (wasm 없을 때 시연용 — 진짜 물리휘발은 아님)
   *  ※ 로직은 C와 동일 구조라, 화면 흐름·복원은 똑같이 보임.
   *    단 "메모리 물리 증발"은 wasm에서만 진짜.
   * ════════════════════════════════════════════════════════════ */
  /* 동기 SHA-256 (C 코어와 동일 알고리즘 — wasm 없을 때 폴백) */
  function _sha256(bytes) {
    function rotr(x,n){return (x>>>n)|(x<<(32-n));}
    const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const l=bytes.length; const bitLen=l*8;
    const withPad=[...bytes,0x80];
    while(withPad.length%64!==56) withPad.push(0);
    for(let i=7;i>=0;i--) withPad.push((bitLen/Math.pow(2,8*i))&0xff);
    for(let off=0;off<withPad.length;off+=64){
      const w=new Array(64);
      for(let i=0;i<16;i++) w[i]=(withPad[off+i*4]<<24)|(withPad[off+i*4+1]<<16)|(withPad[off+i*4+2]<<8)|(withPad[off+i*4+3]);
      for(let i=16;i<64;i++){
        const s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
        const s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
        w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
      }
      let [a,b,c,d,e,f,g,hh]=h;
      for(let i=0;i<64;i++){
        const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        const ch=(e&f)^(~e&g);
        const t1=(hh+S1+ch+K[i]+w[i])|0;
        const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        const maj=(a&b)^(a&c)^(b&c);
        const t2=(S0+maj)|0;
        hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
      }
      h=[(h[0]+a)|0,(h[1]+b)|0,(h[2]+c)|0,(h[3]+d)|0,(h[4]+e)|0,(h[5]+f)|0,(h[6]+g)|0,(h[7]+hh)|0];
    }
    const out=new Uint8Array(32);
    for(let i=0;i<8;i++){out[i*4]=(h[i]>>>24)&0xff;out[i*4+1]=(h[i]>>>16)&0xff;out[i*4+2]=(h[i]>>>8)&0xff;out[i*4+3]=h[i]&0xff;}
    return out;
  }
  /* 도메인 태그 + 카운터로 outLen 확장 (C의 sha_hash와 동일) */
  function _shaHash(bytes, tag, outLen) {
    const out = new Uint8Array(outLen);
    let counter = 0, done = 0;
    while (done < outLen) {
      const input = new Uint8Array(2 + bytes.length);
      input[0] = tag; input[1] = counter; input.set(bytes, 2);
      const block = _sha256(input);
      const take = Math.min(32, outLen - done);
      out.set(block.subarray(0, take), done);
      done += take; counter++;
    }
    return out;
  }
  function _material(sliderCoord, pupilArray, ans) {
    let sum = 0;
    for (let i=0;i<pupilArray.length;i++){ sum += Math.round(pupilArray[i]*10)/10; }
    const anchor = Math.round((sum/pupilArray.length)*10);
    const slider = Math.round((Math.round(sliderCoord*1000)+5)/10)*10;
    const m = new Uint8Array(64);
    new DataView(m.buffer).setFloat64(0, anchor, true);
    new DataView(m.buffer).setFloat64(8, slider, true);
    m.set(ans.slice(0,40), 16);
    return m;
  }
  let _jsKey = null;
  function _jsEnroll(sliderCoord, pupilArray, ans) {
    const m = _material(sliderCoord, pupilArray, ans);
    const key = _shaHash(m, 0x4B, KEY_LEN);      /* 'K' 키 도메인 */
    const digest = _shaHash(m, 0x44, KEY_LEN);   /* 'D' 다이제스트 도메인 (분리!) */
    const helper = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) helper[i] = key[i]^digest[i];
    const commit = _shaHash(key, 0x4B, COMMIT_LEN);
    _jsKey = null;
    return { helper: Array.from(helper), commit: Array.from(commit), wasm: false };
  }
  function _jsAuth(sliderCoord, pupilArray, ans, helperArr, commitArr) {
    const m = _material(sliderCoord, pupilArray, ans);
    const digest = _shaHash(m, 0x44, KEY_LEN);   /* 'D' — 등록과 동일 */
    const key = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) key[i] = helperArr[i]^digest[i];
    const proof = _shaHash(key, 0x4B, COMMIT_LEN);
    let pass = true;
    for (let i=0;i<COMMIT_LEN;i++) if (proof[i]!==commitArr[i]) pass=false;
    return { pass, wiped: false, wasm: false };
  }

  /* ── 외부 공개 ── */
  window.MUFE_WASM = {
    ready,
    enroll,
    authenticate,
    isWasm: () => usingWasm,
  };
})();
