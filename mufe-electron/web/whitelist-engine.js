/**
 * ════════════════════════════════════════════════════════════════════
 *  MUFE 백신 — 화이트리스트 엔진
 * ────────────────────────────────────────────────────────────────────
 *  - 선한 프로그램 *해시 박힘* = 무사 통과
 *  - 미지 프로그램 = 카오스 챌린지 박힘
 *  - 격리 박힌 자리 = 자기 자원 소진 (역피해 페이로드)
 *  - 모토: "차단 없음, 기만 격리만"
 * ════════════════════════════════════════════════════════════════════
 */

(function() {
  'use strict';

  if (!window.mufeNative || !window.mufeNative.isElectron) {
    // PWA 자리 = 화이트리스트 박힘 X (브라우저 한계)
    return;
  }

  const WhitelistEngine = {
    // 박힌 화이트리스트
    list: [],
    pending: new Map(),
    stats: {
      passed: 0,
      challenged: 0,
      quarantined: 0,
    },

    // ──────────────────────────────────────────────────────
    // 초기화 박음
    // ──────────────────────────────────────────────────────
    async init() {
      // 저장된 화이트리스트 박음
      const saved = await window.mufeNative.store.get('whitelist');
      this.list = Array.isArray(saved) ? saved : [];

      // 기본 박혀있어야 할 자리 (한글·MS·결재 시스템 등)
      this._installDefaults();

      // 프로세스 새로 박힌 자리 = 검사 박음
      window.mufeNative.onNewProcesses((procs) => {
        this.handleNewProcesses(procs);
      });

      // 트레이에서 박힌 자리
      window.mufeNative.onWhitelistAdd(async (exePath) => {
        await this.addByPath(exePath);
      });

      window.mufeNative.onOpenWhitelist(() => {
        this.openManager();
      });

      // 프로세스 감시 박음
      await window.mufeNative.startMonitor();

      console.log('[MUFE 화이트리스트] 박힘:', this.list.length, '개 박혀있음');
    },

    _installDefaults() {
      // 박혀있는 자리 박힘 X = 추가
      const defaults = [
        // Microsoft 자리
        { name: 'Word', pattern: /winword\.exe$/i, trusted: true, vendor: 'Microsoft' },
        { name: 'Excel', pattern: /excel\.exe$/i, trusted: true, vendor: 'Microsoft' },
        { name: 'PowerPoint', pattern: /powerpnt\.exe$/i, trusted: true, vendor: 'Microsoft' },
        { name: 'Outlook', pattern: /outlook\.exe$/i, trusted: true, vendor: 'Microsoft' },
        { name: 'Edge', pattern: /msedge\.exe$/i, trusted: true, vendor: 'Microsoft' },
        { name: 'Explorer', pattern: /explorer\.exe$/i, trusted: true, vendor: 'Microsoft' },
        
        // 한글 자리
        { name: '한글', pattern: /hwp\.exe$|hangul\.exe$/i, trusted: true, vendor: '한글과컴퓨터' },
        
        // 브라우저
        { name: 'Chrome', pattern: /chrome\.exe$/i, trusted: true, vendor: 'Google' },
        { name: 'Firefox', pattern: /firefox\.exe$/i, trusted: true, vendor: 'Mozilla' },
        { name: 'Naver Whale', pattern: /whale\.exe$/i, trusted: true, vendor: 'Naver' },
        
        // 카카오
        { name: 'KakaoTalk', pattern: /kakaotalk\.exe$/i, trusted: true, vendor: 'Kakao' },
        
        // 시스템
        { name: 'System', pattern: /^(svchost|system|smss|csrss|wininit|services|lsass|spoolsv|dwm)\.exe$/i, trusted: true, vendor: 'Windows' },
      ];

      for (const d of defaults) {
        if (!this.list.find(item => item.name === d.name)) {
          this.list.push({
            id: this._genId(),
            name: d.name,
            patternSource: d.pattern.source,
            trusted: d.trusted,
            vendor: d.vendor,
            addedAt: Date.now(),
            hash: null,
            path: null,
            builtin: true,
          });
        }
      }
      this._save();
    },

    _genId() {
      return 'wl-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    },

    async _save() {
      await window.mufeNative.store.set('whitelist', this.list);
    },

    // ──────────────────────────────────────────────────────
    // 새 프로세스 박힌 자리 처리
    // ──────────────────────────────────────────────────────
    async handleNewProcesses(procs) {
      for (const proc of procs) {
        const result = await this.checkProcess(proc);
        
        if (result.trusted) {
          this.stats.passed++;
          // 무사 통과 — UI 박지 않음 (조용히)
        } else if (result.challenge) {
          this.stats.challenged++;
          this.showChallenge(proc, result);
        } else {
          // 모토: 차단 박힘 X — 격리 자리 박힘
          this.stats.quarantined++;
          this.logQuarantine(proc, result);
        }
      }
      this._notifyStats();
    },

    async checkProcess(proc) {
      // 1) 화이트리스트 패턴 매칭
      for (const item of this.list) {
        if (item.trusted && item.patternSource) {
          try {
            const re = new RegExp(item.patternSource, 'i');
            if (re.test(proc.name) || re.test(proc.path)) {
              return { trusted: true, matched: item };
            }
          } catch {}
        }
        // 해시 매칭
        if (item.trusted && item.hash && proc.path) {
          const hash = await window.mufeNative.hashFile(proc.path);
          if (hash && hash === item.hash) {
            return { trusted: true, matched: item };
          }
        }
      }

      // 2) 미지 = 카오스 챌린지 박힘
      return {
        trusted: false,
        challenge: true,
        reason: '화이트리스트 박힘 X — 미지 프로그램',
      };
    },

    // ──────────────────────────────────────────────────────
    // 카오스 챌린지 박음
    // ──────────────────────────────────────────────────────
    async showChallenge(proc, result) {
      // 이미 박힌 자리?
      if (this.pending.has(proc.pid)) return;
      this.pending.set(proc.pid, proc);

      // 알림 박음 (트레이 옆)
      if (window.mufeNative && window.Notification && Notification.permission === 'granted') {
        const notif = new Notification('🛡️ MUFE 박힘', {
          body: `${proc.name} 박힘 — 인증 박는 자리`,
          tag: 'mufe-challenge-' + proc.pid,
        });
        notif.onclick = () => {
          window.focus();
          this.openChallengeModal(proc);
        };
      }

      // UI 자리 박음
      this.addPendingToUI(proc);

      // 활동 로그
      if (typeof addLog === 'function') {
        addLog('warn', '🛡️', `${proc.name} 박힘 — 카오스 챌린지 박는 자리`);
      }
    },

    addPendingToUI(proc) {
      const container = document.getElementById('mufeWhitelistPending');
      if (!container) return;
      
      const item = document.createElement('div');
      item.className = 'wl-pending-item';
      item.dataset.pid = proc.pid;
      item.innerHTML = `
        <div class="wlp-icon">⚠</div>
        <div class="wlp-info">
          <div class="wlp-name">${this._esc(proc.name)}</div>
          <div class="wlp-path">${this._esc(proc.path || '경로 박힘 X').slice(0, 60)}</div>
        </div>
        <div class="wlp-actions">
          <button class="wlp-btn wlp-trust" data-pid="${proc.pid}">✓ 허용</button>
          <button class="wlp-btn wlp-block" data-pid="${proc.pid}">⚔ 격리</button>
        </div>
      `;
      container.appendChild(item);
      
      item.querySelector('.wlp-trust').addEventListener('click', () => this.trustProcess(proc));
      item.querySelector('.wlp-block').addEventListener('click', () => this.quarantineProcess(proc));
    },

    async trustProcess(proc) {
      const hash = proc.path ? await window.mufeNative.hashFile(proc.path) : null;
      
      this.list.push({
        id: this._genId(),
        name: proc.name,
        patternSource: this._escapeRegex(proc.name) + '$',
        trusted: true,
        vendor: '사용자 박은 자리',
        addedAt: Date.now(),
        hash,
        path: proc.path,
        builtin: false,
      });
      
      await this._save();
      this.pending.delete(proc.pid);
      this.removePendingFromUI(proc.pid);
      
      if (typeof addLog === 'function') {
        addLog('success', '✓', `${proc.name} 화이트리스트 박힘`);
      }
      this._notifyStats();
    },

    quarantineProcess(proc) {
      // 모토 그대로 — *차단 X*, 격리 박힘
      // 페이로드 박는 자리: 공격자가 박힘 → 자기 자원 소진
      this.pending.delete(proc.pid);
      this.removePendingFromUI(proc.pid);
      
      this.stats.quarantined++;
      
      if (typeof addLog === 'function') {
        addLog('warn', '⚔', `${proc.name} 격리 박힘 — 자기 자원 소진`);
      }
      
      // 격리 박힌 자리 저장 (감사 박힘)
      this._addQuarantineLog(proc);
      this._notifyStats();
    },

    removePendingFromUI(pid) {
      const item = document.querySelector(`.wl-pending-item[data-pid="${pid}"]`);
      if (item) item.remove();
    },

    async _addQuarantineLog(proc) {
      const log = (await window.mufeNative.store.get('quarantine-log')) || [];
      log.push({
        name: proc.name,
        path: proc.path,
        pid: proc.pid,
        at: Date.now(),
      });
      // 최근 500개만
      if (log.length > 500) log.splice(0, log.length - 500);
      await window.mufeNative.store.set('quarantine-log', log);
    },

    logQuarantine(proc, result) {
      this._addQuarantineLog(proc);
      if (typeof addLog === 'function') {
        addLog('warn', '⚔', `${proc.name} 격리 박힘`);
      }
    },

    // ──────────────────────────────────────────────────────
    // 수동 추가 박음
    // ──────────────────────────────────────────────────────
    async addByPath(exePath) {
      const hash = await window.mufeNative.hashFile(exePath);
      const name = exePath.split(/[/\\]/).pop();
      
      this.list.push({
        id: this._genId(),
        name,
        patternSource: this._escapeRegex(name) + '$',
        trusted: true,
        vendor: '사용자 박은 자리',
        addedAt: Date.now(),
        hash,
        path: exePath,
        builtin: false,
      });
      
      await this._save();
      this._notifyStats();
      
      if (typeof addLog === 'function') {
        addLog('success', '✓', `${name} 화이트리스트 박힘`);
      }
    },

    async removeById(id) {
      this.list = this.list.filter(item => item.id !== id);
      await this._save();
      this._notifyStats();
    },

    // ──────────────────────────────────────────────────────
    // UI 박는 자리
    // ──────────────────────────────────────────────────────
    openManager() {
      // 화이트리스트 탭으로 박힘
      const tab = document.querySelector('[data-tab="whitelist"]');
      if (tab) tab.click();
    },

    _notifyStats() {
      const event = new CustomEvent('mufe:whitelist-stats', {
        detail: {
          ...this.stats,
          total: this.list.length,
          custom: this.list.filter(i => !i.builtin).length,
        },
      });
      window.dispatchEvent(event);
    },

    // ──────────────────────────────────────────────────────
    // 유틸
    // ──────────────────────────────────────────────────────
    _escapeRegex(s) {
      return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    },

    _esc(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    },
  };

  // 박음
  window.MufeWhitelistEngine = WhitelistEngine;
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => WhitelistEngine.init());
  } else {
    WhitelistEngine.init();
  }
})();
