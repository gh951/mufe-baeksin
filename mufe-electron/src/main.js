/**
 * ════════════════════════════════════════════════════════════════════
 *  🛡️  M U F E   백 신   —   Electron 메인 프로세스
 * ────────────────────────────────────────────────────────────────────
 *  - 양자·AI 시대 보안 자리
 *  - 화이트리스트 + 카오스 챌린지 + 역피해 페이로드
 *  - 모토: "차단 없음, 기만 격리만"
 * ════════════════════════════════════════════════════════════════════
 */

const { app, BrowserWindow, ipcMain, Tray, Menu, shell, nativeImage, dialog, screen } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { exec, spawn } = require('child_process');

let Store;
try { Store = require('electron-store'); } catch { Store = null; }

// ──────────────────────────────────────────────────────────────
// 상태 박음
// ──────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let appStore = null;
const isDev = process.argv.includes('--dev') || !app.isPackaged;
const SINGLE_INSTANCE_LOCK = app.requestSingleInstanceLock();

if (!SINGLE_INSTANCE_LOCK) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

// ──────────────────────────────────────────────────────────────
// 보안 자리 — 박혀야 할 자리
// ──────────────────────────────────────────────────────────────
app.commandLine.appendSwitch('disable-features', 'OutOfBlinkCors');
app.commandLine.appendSwitch('disable-http-cache');
app.enableSandbox();

// Production 자리 - DevTools 박힘 X
if (!isDev) {
  app.commandLine.appendSwitch('disable-features', 'DialerEmergencyCallButton');
}

// ──────────────────────────────────────────────────────────────
// 메인 윈도우 박음
// ──────────────────────────────────────────────────────────────
function createMainWindow() {
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;

  mainWindow = new BrowserWindow({
    width: Math.min(1280, width - 40),
    height: Math.min(900, height - 40),
    minWidth: 800,
    minHeight: 600,
    title: 'MUFE 백신',
    icon: path.join(__dirname, '..', 'build', process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
    backgroundColor: '#020a18',
    show: false,
    autoHideMenuBar: true,
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      spellcheck: false,
    },
  });

  // 웹 컨텐츠 박음 (로컬 PWA 자리)
  const indexPath = path.join(__dirname, '..', 'web', 'index.html');
  if (fs.existsSync(indexPath)) {
    mainWindow.loadFile(indexPath);
  } else {
    // 폴백 - mufe-baeksin.com 박음
    mainWindow.loadURL('https://mufe-baeksin.com');
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // 외부 링크 = 브라우저 박음
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  // 네비게이션 보안 박음
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const allowed = [
      'file://',
      'https://mufe-baeksin.com',
      'https://mufe-baeksin.vercel.app',
    ];
    if (!allowed.some(prefix => url.startsWith(prefix))) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  // 새 창 박힘 X
  mainWindow.webContents.on('new-window', (event) => event.preventDefault());

  // 우클릭 박힘 X (Production)
  if (!isDev) {
    mainWindow.webContents.on('context-menu', (e) => e.preventDefault());
  }

  // 닫힘 = 트레이로 박음 (옵션)
  mainWindow.on('close', (event) => {
    if (appStore && appStore.get('minimizeToTray', true) && !app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ──────────────────────────────────────────────────────────────
// 시스템 트레이 박음
// ──────────────────────────────────────────────────────────────
function createTray() {
  const iconPath = path.join(__dirname, '..', 'build', process.platform === 'win32' ? 'icon.ico' : 'icon.png');
  
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    if (trayIcon.isEmpty()) {
      trayIcon = nativeImage.createEmpty();
    }
  } catch {
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip('MUFE 백신 — 보호 박힘');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: '🛡️ MUFE 백신',
      enabled: false,
    },
    { type: 'separator' },
    {
      label: '열기',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createMainWindow();
        }
      },
    },
    {
      label: '인증 챌린지',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
          mainWindow.webContents.executeJavaScript('openAuthModal && openAuthModal()').catch(() => {});
        }
      },
    },
    {
      label: '생체 인증 (rPPG)',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
          mainWindow.webContents.executeJavaScript('openBioAuthModal && openBioAuthModal()').catch(() => {});
        }
      },
    },
    { type: 'separator' },
    {
      label: '화이트리스트 박는 자리',
      submenu: [
        {
          label: '현재 박힌 자리 보기',
          click: () => {
            if (mainWindow) mainWindow.webContents.send('open-whitelist');
          },
        },
        {
          label: '프로세스 추가 박음',
          click: async () => {
            const result = await dialog.showOpenDialog(mainWindow, {
              title: '화이트리스트에 박을 프로그램 선택',
              filters: [
                { name: '실행 파일', extensions: ['exe', 'app', 'AppImage'] },
                { name: '모든 파일', extensions: ['*'] },
              ],
              properties: ['openFile'],
            });
            if (!result.canceled && result.filePaths[0]) {
              const exePath = result.filePaths[0];
              if (mainWindow) mainWindow.webContents.send('whitelist-add', exePath);
            }
          },
        },
      ],
    },
    { type: 'separator' },
    {
      label: '대시보드',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.webContents.send('navigate-tab', 'patrol');
        }
      },
    },
    {
      label: '설정',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.webContents.send('navigate-tab', 'settings');
        }
      },
    },
    { type: 'separator' },
    {
      label: '버전 정보',
      click: () => {
        dialog.showMessageBox({
          type: 'info',
          title: 'MUFE 백신',
          message: 'MUFE 백신 — 양자·AI 시대 보안',
          detail: `버전: ${app.getVersion()}\nElectron: ${process.versions.electron}\nNode: ${process.versions.node}\nChromium: ${process.versions.chrome}\n\n웹: https://mufe-baeksin.com`,
        });
      },
    },
    {
      label: '종료',
      click: () => {
        app.isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) mainWindow.hide();
      else mainWindow.show();
    }
  });
}

// ──────────────────────────────────────────────────────────────
// 프로세스 감시 박음 (화이트리스트 핵심 자리)
// ──────────────────────────────────────────────────────────────
const processMonitor = {
  watching: false,
  interval: null,
  lastSnapshot: new Map(),
  
  start() {
    if (this.watching) return;
    this.watching = true;
    
    // 5초마다 박음
    this.interval = setInterval(() => {
      this.scan().catch(err => console.error('[프로세스 감시 박힘 X]', err));
    }, 5000);
    
    // 즉시 1회 박음
    this.scan().catch(() => {});
  },
  
  stop() {
    this.watching = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  },
  
  async scan() {
    if (!mainWindow) return;
    
    try {
      const processes = await this.listProcesses();
      const newProcesses = [];
      
      for (const proc of processes) {
        if (!this.lastSnapshot.has(proc.pid)) {
          newProcesses.push(proc);
        }
      }
      
      // 스냅샷 갱신
      this.lastSnapshot.clear();
      processes.forEach(p => this.lastSnapshot.set(p.pid, p));
      
      // 새 프로세스 박힌 자리 → renderer에 박음
      if (newProcesses.length > 0) {
        mainWindow.webContents.send('processes-new', newProcesses);
      }
    } catch (err) {
      // 박지 못함 — 권한 자리
    }
  },
  
  listProcesses() {
    return new Promise((resolve) => {
      const platform = process.platform;
      let cmd;
      
      if (platform === 'win32') {
        // PowerShell — 빠름 + 신뢰
        cmd = 'powershell -NoProfile -Command "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"';
      } else if (platform === 'darwin') {
        cmd = "ps -axo pid,comm";
      } else {
        cmd = "ps -axo pid,comm,args";
      }
      
      exec(cmd, { maxBuffer: 5 * 1024 * 1024, timeout: 4000 }, (err, stdout) => {
        if (err) return resolve([]);
        
        const procs = [];
        try {
          if (platform === 'win32') {
            const data = JSON.parse(stdout);
            const list = Array.isArray(data) ? data : [data];
            for (const item of list) {
              if (!item || !item.Id) continue;
              procs.push({
                pid: item.Id,
                name: item.ProcessName,
                path: item.Path || '',
              });
            }
          } else {
            const lines = stdout.split('\n').slice(1);
            for (const line of lines) {
              const parts = line.trim().split(/\s+/);
              if (parts.length < 2) continue;
              const pid = parseInt(parts[0], 10);
              if (!pid) continue;
              procs.push({
                pid,
                name: parts[1],
                path: parts.slice(2).join(' ') || parts[1],
              });
            }
          }
        } catch {}
        
        resolve(procs);
      });
    });
  },
  
  hashFile(filePath) {
    return new Promise((resolve) => {
      try {
        if (!filePath || !fs.existsSync(filePath)) return resolve(null);
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', d => hash.update(d));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', () => resolve(null));
      } catch {
        resolve(null);
      }
    });
  },
};

// ──────────────────────────────────────────────────────────────
// IPC 박음 — renderer ↔ main
// ──────────────────────────────────────────────────────────────
ipcMain.handle('mufe:get-version', () => app.getVersion());
ipcMain.handle('mufe:get-platform', () => ({
  os: process.platform,
  arch: process.arch,
  version: os.release(),
  hostname: os.hostname(),
}));

ipcMain.handle('mufe:list-processes', async () => {
  return await processMonitor.listProcesses();
});

ipcMain.handle('mufe:hash-file', async (event, filePath) => {
  return await processMonitor.hashFile(filePath);
});

ipcMain.handle('mufe:pick-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '화이트리스트에 박을 프로그램',
    filters: [
      { name: '실행 파일', extensions: ['exe', 'app', 'AppImage', 'msi'] },
      { name: '모든 파일', extensions: ['*'] },
    ],
    properties: ['openFile'],
  });
  if (result.canceled || !result.filePaths[0]) return null;
  
  const filePath = result.filePaths[0];
  const hash = await processMonitor.hashFile(filePath);
  return {
    path: filePath,
    name: path.basename(filePath),
    hash,
  };
});

ipcMain.handle('mufe:store-get', (event, key) => {
  if (!appStore) return null;
  return appStore.get(key);
});

ipcMain.handle('mufe:store-set', (event, key, value) => {
  if (!appStore) return false;
  appStore.set(key, value);
  return true;
});

ipcMain.handle('mufe:store-delete', (event, key) => {
  if (!appStore) return false;
  appStore.delete(key);
  return true;
});

ipcMain.handle('mufe:open-external', (event, url) => {
  if (typeof url === 'string' && (url.startsWith('https://') || url.startsWith('http://'))) {
    shell.openExternal(url);
    return true;
  }
  return false;
});

ipcMain.handle('mufe:start-monitor', () => {
  processMonitor.start();
  return true;
});

ipcMain.handle('mufe:stop-monitor', () => {
  processMonitor.stop();
  return true;
});

ipcMain.handle('mufe:autostart-get', () => {
  if (process.platform === 'darwin' || process.platform === 'win32') {
    return app.getLoginItemSettings().openAtLogin;
  }
  return false;
});

ipcMain.handle('mufe:autostart-set', (event, enabled) => {
  if (process.platform === 'darwin' || process.platform === 'win32') {
    app.setLoginItemSettings({
      openAtLogin: enabled,
      openAsHidden: true,
      args: ['--hidden'],
    });
    return true;
  }
  return false;
});

// ──────────────────────────────────────────────────────────────
// 앱 라이프사이클
// ──────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  // electron-store 박음
  if (Store) {
    try {
      appStore = new Store({
        name: 'mufe-config',
        defaults: {
          minimizeToTray: true,
          autoStart: false,
          showNotifications: true,
          whitelist: [],
        },
      });
    } catch (err) {
      console.error('[Store 박힘 X]', err);
    }
  }

  createMainWindow();
  createTray();

  // 프로세스 감시 박음 (자동)
  setTimeout(() => processMonitor.start(), 3000);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});

app.on('window-all-closed', () => {
  // 트레이로 박힘 — 종료 X
  if (process.platform !== 'darwin' && (!tray || app.isQuitting)) {
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  processMonitor.stop();
});

// ──────────────────────────────────────────────────────────────
// 보안 - webContents 통째로 박음
// ──────────────────────────────────────────────────────────────
app.on('web-contents-created', (event, contents) => {
  contents.on('will-attach-webview', (e) => e.preventDefault());
  
  contents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });
});
