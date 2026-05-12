/**
 * ════════════════════════════════════════════════════════════════════
 *  MUFE 백신 — Preload (보안 브릿지)
 * ────────────────────────────────────────────────────────────────────
 *  contextIsolation 박혀있어서 window.mufeNative만 박음
 * ════════════════════════════════════════════════════════════════════
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('mufeNative', {
  // 기본 정보
  getVersion: () => ipcRenderer.invoke('mufe:get-version'),
  getPlatform: () => ipcRenderer.invoke('mufe:get-platform'),
  
  // 프로세스 박음
  listProcesses: () => ipcRenderer.invoke('mufe:list-processes'),
  hashFile: (filePath) => ipcRenderer.invoke('mufe:hash-file', filePath),
  pickFile: () => ipcRenderer.invoke('mufe:pick-file'),
  startMonitor: () => ipcRenderer.invoke('mufe:start-monitor'),
  stopMonitor: () => ipcRenderer.invoke('mufe:stop-monitor'),
  
  // 자동 시작
  autostartGet: () => ipcRenderer.invoke('mufe:autostart-get'),
  autostartSet: (enabled) => ipcRenderer.invoke('mufe:autostart-set', enabled),
  
  // 저장소 (Electron Store)
  store: {
    get: (key) => ipcRenderer.invoke('mufe:store-get', key),
    set: (key, value) => ipcRenderer.invoke('mufe:store-set', key, value),
    delete: (key) => ipcRenderer.invoke('mufe:store-delete', key),
  },
  
  // 외부 링크
  openExternal: (url) => ipcRenderer.invoke('mufe:open-external', url),
  
  // 이벤트 박음 (메인 → renderer)
  onNewProcesses: (callback) => {
    ipcRenderer.on('processes-new', (event, procs) => callback(procs));
  },
  onNavigateTab: (callback) => {
    ipcRenderer.on('navigate-tab', (event, tabName) => callback(tabName));
  },
  onWhitelistAdd: (callback) => {
    ipcRenderer.on('whitelist-add', (event, exePath) => callback(exePath));
  },
  onOpenWhitelist: (callback) => {
    ipcRenderer.on('open-whitelist', () => callback());
  },
  
  // 플랫폼 자리
  isElectron: true,
  isWindows: process.platform === 'win32',
  isMac: process.platform === 'darwin',
  isLinux: process.platform === 'linux',
});

// MUFE 환경 박음
window.addEventListener('DOMContentLoaded', () => {
  document.body.classList.add('mufe-electron');
  document.body.dataset.platform = process.platform;
});
