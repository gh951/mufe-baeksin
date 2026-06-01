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
  function _fnv(bytes, outLen) {
    const out = new Uint8Array(outLen);
    let h = 0xcbf29ce484222325n;
    for (let i = 0; i < outLen; i++) {
      for (let j = 0; j < bytes.length; j++) {
        h ^= BigInt(bytes[j]); h *= 0x100000001b3n; h ^= BigInt(i*131+j);
        h &= 0xffffffffffffffffn;
      }
      out[i] = Number((h >> BigInt((i % 8) * 8)) & 0xffn);
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
    const key = _fnv(m, KEY_LEN);
    const digest = _fnv(m, KEY_LEN);
    const helper = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) helper[i] = key[i]^digest[i];
    const commit = _fnv(key, COMMIT_LEN);
    _jsKey = null; // (폴백) 키 참조 해제 — 진짜 증발은 wasm
    return { helper: Array.from(helper), commit: Array.from(commit), wasm: false };
  }
  function _jsAuth(sliderCoord, pupilArray, ans, helperArr, commitArr) {
    const m = _material(sliderCoord, pupilArray, ans);
    const digest = _fnv(m, KEY_LEN);
    const key = new Uint8Array(KEY_LEN);
    for (let i=0;i<KEY_LEN;i++) key[i] = helperArr[i]^digest[i];
    const proof = _fnv(key, COMMIT_LEN);
    let pass = true;
    for (let i=0;i<COMMIT_LEN;i++) if (proof[i]!==commitArr[i]) pass=false;
    return { pass, wiped: false, wasm: false }; // wiped:false → 폴백은 물리증발 아님
  }

  /* ── 외부 공개 ── */
  window.MUFE_WASM = {
    ready,
    enroll,
    authenticate,
    isWasm: () => usingWasm,
  };
})();
