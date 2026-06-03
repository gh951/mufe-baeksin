/* ════════════════════════════════════════════════════════════════════
 *  MUFE 백신 — Wasm 연결 브리지 (mufe_bridge.js)   [v4 코어 호환 수정본]
 *
 *  index.html 이 이 파일을 불러서 window.MUFE_WASM 으로 진짜 무기를 씁니다.
 *
 *  ▶ 동작:
 *    - mufe_core.wasm 이 있으면  → 진짜 C 코어(물리 휘발) 사용
 *    - 없으면(아직 빌드 전)       → JS 폴백(시연 모드)으로 자동 전환
 *
 *  ▶ index.html 에서 쓰는 법(인터페이스 그대로 유지):
 *      await MUFE_WASM.ready();
 *      const { helper, commit } = MUFE_WASM.enroll(sliderCoord, pupilArray, answerStr);
 *      const r = MUFE_WASM.authenticate(sliderCoord, pupilArray, answerStr, helper, commit);
 *
 *  ▶ [중요 수정] v4 C 코어의 실제 함수 모양에 맞춤:
 *      int mufe_enroll(int big,int small,int micro, const int* pupil,int pupil_n,
 *                      const char* pass, unsigned char* helper, unsigned char* commit)
 *      int mufe_authenticate(int big,int small,int micro, const int* pupil,int pupil_n,
 *                      const char* pass, const unsigned char* helper,
 *                      const unsigned char* commit, unsigned char* out_master)
 *    · 슬라이더 1개 → big/small/micro 정수 3개로 분해(등록·인증 동일 변환)
 *    · 동공은 정수 배열로 변환(코어가 int 로 읽음, 실수 아님), 최대 16개
 *    · 비번은 널(0) 종료 C 문자열로 전달(코어가 strlen 사용)
 *    · helper 는 32바이트 고정이 아니라 가변 길이(=등록이 돌려준 길이)로 저장/사용
 * ════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const COMMIT_LEN = 32;     // 커밋(다이제스트) 길이 — C 코어 고정
  const KEY_LEN = 32;        // 마스터키 길이 — C 코어 고정
  const HELPER_CAP = 256;    // helper 임시 버퍼(넉넉히). 실제 길이는 enroll 반환값.
  const MAX_PUPIL = 16;      // C 코어가 받는 동공 점 최대 개수
  const PUPIL_SCALE = 1000;  // 동공 실수(~0.3~0.7) → 정수 변환 배율

  let mod = null;          // 로드된 wasm 모듈
  let usingWasm = false;   // true=진짜 C코어, false=JS폴백
  let readyPromise = null;

  // 코어 격자(칸) 폭 — 로드 후 코어에서 읽어옴(없으면 기본값). 눈금→칸 매핑에 사용.
  let GBIG = 16, GSMALL = 16, GMICRO = 800;

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
          try {
            const g = (fn, d) => { try { return mod.ccall(fn, 'number', [], []) || d; } catch (e) { return d; } };
            GBIG = g('mufe_grid_big', 16); GSMALL = g('mufe_grid_small', 16); GMICRO = g('mufe_grid_micro', 800);
          } catch (e) {}
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
   *  입력 변환 (등록·인증 양쪽에서 똑같이 — 그래야 같은 키가 복원됨)
   * ════════════════════════════════════════════════════════════ */
  // 슬라이더 좌표 → big/small/micro 정수 3개.
  //  index.html 의 바가 '눈금'으로 스냅되면 좌표는 다음 꼴이 됩니다(B,S,M = 각 바의 눈금 0~10):
  //    coord = (100·B)*10000 + (100·S)*10 + (1000·M)/1000 = 1,000,000·B + 1,000·S + M
  //  → 여기서 B,S,M 을 정확히 되찾아, 각 눈금이 코어 격자 '한 칸'이 되도록 격자폭만큼 곱함.
  //    그러면 q(=칸번호)=눈금, r(=오차)=0 → 같은 눈금이면 100% 같은 키, 세 바가 각각 독립.
  //  ※ 등록·인증 양쪽에서 똑같이 도는 함수라, 같은 눈금이면 언제나 같은 결과.
  function splitCoord(sliderCoord) {
    let c = Math.round(Number(sliderCoord) || 0);
    if (c < 0) c = 0;
    const B = Math.floor(c / 1000000);
    const rem = c - B * 1000000;
    const S = Math.floor(rem / 1000);
    const M = rem - S * 1000;
    return [B * GBIG, S * GSMALL, M * GMICRO];
  }
  // 동공 실수배열 → 정수배열(최대 16개). 코어가 int 로 읽으므로 실수 그대로 보내면 안 됨.
  function pupilInts(pupilArray) {
    const n = Math.min((pupilArray && pupilArray.length) || 0, MAX_PUPIL);
    const out = new Int32Array(n);
    for (let i = 0; i < n; i++) out[i] = Math.round((pupilArray[i] || 0) * PUPIL_SCALE);
    return out;
  }

  /* ════════════════════════════════════════════════════════════
   *  Wasm 메모리에 올리고 포인터 얻기 (진짜 모드용)
   * ════════════════════════════════════════════════════════════ */
  function pushInts(int32arr) {
    const n = int32arr.length;
    const ptr = mod._malloc(Math.max(n, 1) * 4);
    if (n) mod.HEAP32.set(int32arr, ptr >> 2);
    return { ptr, n, free: () => mod._free(ptr) };
  }
  // 널 종료 C 문자열로 올림 (코어가 strlen 으로 길이를 잼)
  function pushCString(s) {
    const b = strBytes(s);
    const ptr = mod._malloc(b.length + 1);
    mod.HEAPU8.set(b, ptr);
    mod.HEAPU8[ptr + b.length] = 0;   // 널 종료
    return { ptr, free: () => mod._free(ptr) };
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
    if (usingWasm) {
      const [big, small, micro] = splitCoord(sliderCoord);
      const P = pushInts(pupilInts(pupilArray));
      const A = pushCString(answerStr);
      const helperPtr = mod._malloc(HELPER_CAP);
      const commitPtr = mod._malloc(COMMIT_LEN);
      // C: mufe_enroll(big, small, micro, pupilPtr, pupilN, passPtr, helperPtr, commitPtr) → helper 길이
      const len = mod.ccall('mufe_enroll', 'number',
        ['number','number','number','number','number','number','number','number'],
        [big, small, micro, P.ptr, P.n, A.ptr, helperPtr, commitPtr]);
      const helperLen = (len && len > 0) ? len : KEY_LEN;
      const helper = pullBytes(helperPtr, helperLen);
      const commit = pullBytes(commitPtr, COMMIT_LEN);
      P.free(); A.free(); mod._free(helperPtr); mod._free(commitPtr);
      return { helper: Array.from(helper), commit: Array.from(commit), wasm: true };
    }
    /* ── JS 폴백 (시연) ── */
    return _jsEnroll(sliderCoord, pupilArray, strBytes(answerStr));
  }

  /* ════════════════════════════════════════════════════════════
   *  [인증]  오늘 입력 + 헬퍼 → 키 복원 → 통과/실패
   * ════════════════════════════════════════════════════════════ */
  function authenticate(sliderCoord, pupilArray, answerStr, helperArr, commitArr) {
    if (usingWasm) {
      const [big, small, micro] = splitCoord(sliderCoord);
      const P = pushInts(pupilInts(pupilArray));
      const A = pushCString(answerStr);
      const H = pushBytes(Uint8Array.from(helperArr));
      const C = pushBytes(Uint8Array.from(commitArr));
      const outPtr = mod._malloc(KEY_LEN);   // out_master (9번째 인자) — 반드시 필요
      // C: mufe_authenticate(big, small, micro, pupilPtr, pupilN, passPtr, helperPtr, commitPtr, outMasterPtr) → 1/0
      const r = mod.ccall('mufe_authenticate', 'number',
        ['number','number','number','number','number','number','number','number','number'],
        [big, small, micro, P.ptr, P.n, A.ptr, H.ptr, C.ptr, outPtr]);
      // out_master 는 성공 시 복원된 키(비밀). 읽지 않고 즉시 0으로 덮고 해제.
      //   (코어 내부의 master/mat/q 는 C 가 volatile 0쓰기로 이미 물리 소거함 → wiped 항상 true)
      try { mod.HEAPU8.fill(0, outPtr, outPtr + KEY_LEN); } catch (e) {}
      P.free(); A.free(); H.free(); C.free(); mod._free(outPtr);
      return { pass: r === 1, wiped: true, wasm: true };
    }
    /* ── JS 폴백 (시연) ── */
    return _jsAuth(sliderCoord, pupilArray, strBytes(answerStr), helperArr, commitArr);
  }

  /* ════════════════════════════════════════════════════════════
   *  JS 폴백 (wasm 없을 때 시연용 — 진짜 물리휘발은 아님)
   *  ※ wasm 이 로드되면 이 경로는 안 쓰임. 데모/오프라인 표시용.
   * ════════════════════════════════════════════════════════════ */
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
  // 폴백도 진짜 코어와 같은 입력 변환 사용 (모드 일관성)
  function _material(sliderCoord, pupilArray, ans) {
    const [big, small, micro] = splitCoord(sliderCoord);
    const q = pupilInts(pupilArray);
    const m = new Uint8Array(64);
    const dv = new DataView(m.buffer);
    dv.setInt32(0, big, true);
    dv.setInt32(4, small, true);
    dv.setInt32(8, micro, true);
    for (let i = 0; i < q.length && 12 + i * 2 < 56; i++) dv.setInt16(12 + i * 2, q[i] & 0xffff, true);
    m.set(ans.slice(0, 8), 56);
    return m;
  }
  function _jsEnroll(sliderCoord, pupilArray, ans) {
    const m = _material(sliderCoord, pupilArray, ans);
    const key = _shaHash(m, 0x4B, KEY_LEN);
    const digest = _shaHash(m, 0x44, KEY_LEN);
    const helper = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) helper[i] = key[i]^digest[i];
    const commit = _shaHash(key, 0x4B, COMMIT_LEN);
    return { helper: Array.from(helper), commit: Array.from(commit), wasm: false };
  }
  function _jsAuth(sliderCoord, pupilArray, ans, helperArr, commitArr) {
    const m = _material(sliderCoord, pupilArray, ans);
    const digest = _shaHash(m, 0x44, KEY_LEN);
    const key = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) key[i] = helperArr[i]^digest[i];
    const proof = _shaHash(key, 0x4B, COMMIT_LEN);
    let pass = true;
    for (let i=0;i<COMMIT_LEN;i++) if (proof[i]!==commitArr[i]) pass=false;
    return { pass, wiped: false, wasm: false };
  }

  /* ── 외부 공개 (인터페이스 동일) ── */
  window.MUFE_WASM = {
    ready,
    enroll,
    authenticate,
    isWasm: () => usingWasm,
  };
})();
