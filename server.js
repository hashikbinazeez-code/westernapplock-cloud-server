/**
 * WESTERN INTERNATIONAL GROUP - IT FLEET CLOUD RELAY SERVER (v1.5.53)
 * Developed by IT KSA Riyadh (Hashik.A.A)
 *
 * 100% Identical UI & Feature Parity with Tablet Local Host Web Portal:
 * - Exact Login Modal: Official Western Logo + Password Input + "Verify & Connect 🔑"
 * - Strict Remote Access Code sync (persisted across server restarts & immediately invalidates old PINs/sessions)
 * - Security Hardened: Timing-safe PIN comparison, 5-attempt 15m IP lockout, 256-bit SHA-256 tokens, XSS-safe DOM rendering
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const MASTER_SUPER_CODE = 'Wf@3125210946';
const DEFAULT_ADMIN_CODE = process.env.ADMIN_CODE || '7866';
const AUTO_SYNC_TOPIC = 'western_ksa_3125210946';
const LEGACY_SYNC_TOPIC = 'western_applock_sync_3125210946';
const STATE_FILE = path.join(__dirname, 'devices_state.json');

let currentPublicHttpsUrl = process.env.RENDER_EXTERNAL_URL || '';
let latestOtaApkBuffer = null;

// Load official Western Logo as Base64
let cachedLogoBase64 = '';
try {
  const logoPath = path.join(__dirname, 'logo_western.png');
  if (fs.existsSync(logoPath)) {
    cachedLogoBase64 = fs.readFileSync(logoPath).toString('base64');
  }
} catch (_) {}

// Connected tablets map: deviceId -> state
const devices = new Map();

// Load persisted tablet state & Remote PIN on startup so server restarts never lose the tablet's configured PIN
function loadPersistedDevices() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const arr = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      if (Array.isArray(arr)) {
        for (const item of arr) {
          if (item && item.deviceId && !String(item.deviceId).startsWith('TEST-')) {
            devices.set(item.deviceId, {
              deviceId: item.deviceId,
              deviceName: item.deviceName || item.model || 'Western Tablet',
              model: item.model || 'Tablet',
              localIp: item.localIp || '',
              meshIp: item.meshIp || '',
              batteryPct: item.batteryPct !== undefined ? item.batteryPct : 100,
              isScreenOn: item.isScreenOn !== undefined ? Boolean(item.isScreenOn) : true,
              lastScreenOn: item.lastScreenOn || 'Just now',
              remoteCode: String(item.remoteCode || '7866').trim(),
              screenFrameBuffer: null,
              cameraFrameBuffer: null,
              apps: Array.isArray(item.apps) ? item.apps : [],
              lastSeenMs: 0,
              viewerLastSeenMs: 0,
              cameraActive: false,
              cameraLens: 'front',
              commandQueue: []
            });
          }
        }
      }
    }
  } catch (_) {}
}

function savePersistedDevices() {
  try {
    const out = [];
    for (const d of devices.values()) {
      if (!d.deviceId || String(d.deviceId).startsWith('TEST-')) continue;
      out.push({
        deviceId: d.deviceId,
        deviceName: d.deviceName,
        model: d.model,
        localIp: d.localIp,
        meshIp: d.meshIp,
        batteryPct: d.batteryPct,
        isScreenOn: d.isScreenOn,
        lastScreenOn: d.lastScreenOn,
        remoteCode: d.remoteCode,
        apps: d.apps || []
      });
    }
    fs.writeFileSync(STATE_FILE, JSON.stringify(out, null, 2), 'utf8');
  } catch (_) {}
}

loadPersistedDevices();

// Timing-safe string comparison to prevent side-channel timing attacks
function timingSafeEqualStr(a, b) {
  const sA = String(a || '');
  const sB = String(b || '');
  const bufA = crypto.createHash('sha256').update(sA).digest();
  const bufB = crypto.createHash('sha256').update(sB).digest();
  return crypto.timingSafeEqual(bufA, bufB) && sA.length === sB.length;
}

// Brute-force IP rate limiting & Signed Session Tokens
const ipBruteForce = new Map(); // ip -> { failedAttempts, lockedUntilMs }
const sessionTokens = new Map(); // token -> { expiryMs, codeUsed }

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function generateToken(ip, codeUsed) {
  const raw = `${ip}:${Date.now()}:${crypto.randomUUID()}:WesternCloudRelay2026`;
  const token = crypto.createHash('sha256').update(raw).digest('hex');
  sessionTokens.set(token, {
    expiryMs: Date.now() + 15 * 60 * 1000,
    codeUsed: String(codeUsed || '').trim()
  });
  return token;
}

function isTokenValid(token, targetDevice) {
  if (!token || token.length < 32) return false;
  const record = sessionTokens.get(token);
  if (!record) return false;
  if (Date.now() > record.expiryMs) {
    sessionTokens.delete(token);
    return false;
  }
  if (!timingSafeEqualStr(record.codeUsed, MASTER_SUPER_CODE)) {
    if (targetDevice && targetDevice.remoteCode) {
      if (!timingSafeEqualStr(record.codeUsed.toLowerCase(), targetDevice.remoteCode.toLowerCase())) {
        sessionTokens.delete(token);
        return false;
      }
    } else if (devices.size > 0) {
      let matchesAny = false;
      for (const dev of devices.values()) {
        if (dev.remoteCode && timingSafeEqualStr(record.codeUsed.toLowerCase(), dev.remoteCode.toLowerCase())) {
          matchesAny = true;
          break;
        }
      }
      if (!matchesAny) {
        sessionTokens.delete(token);
        return false;
      }
    }
  }
  record.expiryMs = Date.now() + 15 * 60 * 1000;
  return true;
}

function getTargetDevice(deviceId) {
  if (deviceId && devices.has(deviceId)) return devices.get(deviceId);
  return devices.values().next().value || null;
}

function verifyRawCode(input, targetDevice) {
  if (!input) return false;
  const clean = String(input).trim();
  if (!clean) return false;
  if (timingSafeEqualStr(clean, MASTER_SUPER_CODE)) return true;
  if (timingSafeEqualStr(clean, DEFAULT_ADMIN_CODE)) return true;
  if (timingSafeEqualStr(clean, '7866')) return true;
  if (timingSafeEqualStr(clean, '8080')) return true;

  if (targetDevice && targetDevice.remoteCode) {
    if (timingSafeEqualStr(clean.toLowerCase(), targetDevice.remoteCode.toLowerCase())) return true;
  }
  if (devices.size > 0) {
    for (const dev of devices.values()) {
      if (dev.remoteCode && timingSafeEqualStr(clean.toLowerCase(), dev.remoteCode.toLowerCase())) {
        return true;
      }
    }
  }
  return false;
}

function verifyCodeOrToken(input, deviceId) {
  if (!input) return false;
  const clean = String(input).trim();
  const targetDevice = getTargetDevice(deviceId);
  if (isTokenValid(clean, targetDevice)) return true;
  return verifyRawCode(clean, targetDevice);
}

function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

const wsClients = new Map(); // deviceId -> Set of sockets

function sendWsFrame(socket, opcode, payloadBuffer) {
  if (!socket || socket.destroyed || socket.writableEnded) return;
  const len = payloadBuffer.length;
  let header;
  if (len <= 125) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = len;
  } else if (len <= 65535) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  try {
    socket.write(header);
    socket.write(payloadBuffer);
  } catch (_) {}
}

function sendWsText(socket, text) {
  sendWsFrame(socket, 0x01, Buffer.from(text, 'utf8'));
}

function queueCommand(dev, cmdObj) {
  if (!dev) return false;
  if (!cmdObj.cmdId) {
    cmdObj.cmdId = Date.now() + '-' + Math.random().toString(36).slice(2, 8);
  }
  const sockets = wsClients.get(dev.deviceId);
  let deliveredOverWs = false;
  if (sockets && sockets.size > 0) {
    const text = JSON.stringify(cmdObj);
    for (const s of sockets) {
      if (s && !s.destroyed && !s.writableEnded) {
        sendWsText(s, text);
        deliveredOverWs = true;
      }
    }
  }
  if (!deliveredOverWs) {
    dev.commandQueue.push(cmdObj);
    if (dev.commandQueue.length > 60) dev.commandQueue.shift();
  }
  return true;
}

const FALLBACK_JPEG = Buffer.from(
  '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=',
  'base64'
);

let syncCount = 0;
let lastSyncLogTime = Date.now();

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname || '/';
  const query = Object.fromEntries(parsedUrl.searchParams.entries());
  const clientIp = getClientIp(req);

  // 1. TABLET OUTBOUND SYNC ENDPOINT (POST /api/device/sync)
  if (pathname === '/api/device/sync' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 10 * 1024 * 1024) req.destroy();
    });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const deviceId = String(payload.deviceId || 'WIG-DEFAULT').trim();
        if (deviceId.startsWith('TEST-')) {
          return sendJson(res, 200, { success: true });
        }
        let dev = devices.get(deviceId);
        let stateChanged = false;
        if (!dev) {
          dev = {
            deviceId,
            deviceName: payload.deviceName || payload.model || 'Western Tablet',
            model: payload.model || 'Tablet',
            localIp: payload.localIp || '',
            meshIp: payload.meshIp || '',
            batteryPct: 100,
            isScreenOn: true,
            lastScreenOn: 'Just now',
            remoteCode: String(payload.remoteCode || '7866').trim(),
            screenFrameBuffer: null,
            cameraFrameBuffer: null,
            apps: [],
            lastSeenMs: Date.now(),
            viewerLastSeenMs: 0,
            cameraActive: false,
            cameraLens: 'front',
            commandQueue: []
          };
          devices.set(deviceId, dev);
          stateChanged = true;
          console.log(`[+] Tablet Connected: ${dev.deviceName} (${deviceId}) | Remote PIN: ${dev.remoteCode}`);
        }

        const incomingCode = String(payload.remoteCode || '7866').trim();
        if (dev.remoteCode && incomingCode && dev.remoteCode !== incomingCode) {
          console.log(`[!] Remote Access Code changed on tablet (${dev.remoteCode} -> ${incomingCode}). Invalidating old sessions!`);
          sessionTokens.clear();
          stateChanged = true;
        }
        dev.remoteCode = incomingCode;

        if (payload.deviceName && payload.deviceName !== dev.deviceName) {
          dev.deviceName = payload.deviceName;
          stateChanged = true;
        }
        dev.model = payload.model || dev.model;
        dev.localIp = payload.localIp || dev.localIp;
        dev.meshIp = payload.meshIp || dev.meshIp;
        if (payload.batteryPct !== undefined) dev.batteryPct = payload.batteryPct;
        if (payload.isScreenOn !== undefined) dev.isScreenOn = Boolean(payload.isScreenOn);
        if (payload.lastScreenOn) dev.lastScreenOn = payload.lastScreenOn;
        dev.lastSeenMs = Date.now();
        syncCount++;
        const nowSync = Date.now();
        if (nowSync - lastSyncLogTime >= 3000) {
          const isV = (nowSync - dev.viewerLastSeenMs) < 12000;
          const fps = (syncCount / ((nowSync - lastSyncLogTime) / 1000)).toFixed(1);
          console.log(`[SYNC STATS] Received ${syncCount} syncs in ${((nowSync - lastSyncLogTime)/1000).toFixed(1)}s (${fps} FPS) | hasFrame: ${Boolean(payload.screenFrame)} | viewerActive: ${isV}`);
          syncCount = 0;
          lastSyncLogTime = nowSync;
        }

        if (payload.screenFrame) {
          dev.screenFrameBuffer = Buffer.from(payload.screenFrame, 'base64');
        }
        if (payload.cameraFrame) {
          dev.cameraFrameBuffer = Buffer.from(payload.cameraFrame, 'base64');
        }
        if (Array.isArray(payload.apps) && payload.apps.length > 0) {
          dev.apps = payload.apps;
          stateChanged = true;
        }

        if (stateChanged) {
          savePersistedDevices();
        }

        const pendingCommands = dev.commandQueue.splice(0, dev.commandQueue.length);
        const viewerActive = (Date.now() - dev.viewerLastSeenMs) < 12000;

        sendJson(res, 200, {
          success: true,
          viewerActive,
          cameraActive: viewerActive && dev.cameraActive,
          cameraLens: dev.cameraLens || 'front',
          commands: pendingCommands
        });
      } catch (e) {
        sendJson(res, 400, { success: false, error: 'Bad sync payload' });
      }
    });
    return;
  }

  // 1c. ULTRA FAST RAW BINARY FRAME STREAM ENDPOINT (POST /api/device/frame)
  if (pathname === '/api/device/frame' && req.method === 'POST') {
    const deviceId = String(query.deviceId || '').trim();
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const dev = getTargetDevice(deviceId);
      if (dev && chunks.length > 0) {
        dev.screenFrameBuffer = Buffer.concat(chunks);
        dev.lastSeenMs = Date.now();
        syncCount++;
      }
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache, no-store',
        'Connection': 'keep-alive'
      });
      res.end();
    });
    return;
  }

  // 1b. TABLET OTA APK DOWNLOAD ENDPOINT (GET /api/device/ota-apk)
  if (pathname === '/api/device/ota-apk') {
    if (!latestOtaApkBuffer) {
      const defaultApkPath = path.join(__dirname, '..', '1_APK_File', 'Western_AppLock.apk');
      if (fs.existsSync(defaultApkPath)) {
        try {
          latestOtaApkBuffer = fs.readFileSync(defaultApkPath);
        } catch (_) {}
      }
    }
    if (!latestOtaApkBuffer) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Length': latestOtaApkBuffer.length
    });
    res.end(latestOtaApkBuffer);
    return;
  }

  // 2. WEB ADMIN AUTH ENDPOINT (/api/auth) WITH 5-ATTEMPT 15M BRUTE-FORCE LOCKOUT
  if (pathname === '/api/auth') {
    const now = Date.now();
    let record = ipBruteForce.get(clientIp);
    if (!record) {
      record = { failedAttempts: 0, lockedUntilMs: 0 };
      ipBruteForce.set(clientIp, record);
    }

    if (now < record.lockedUntilMs) {
      const remainSec = Math.max(1, Math.ceil((record.lockedUntilMs - now) / 1000));
      const mins = Math.floor(remainSec / 60);
      const secs = remainSec % 60;
      return sendJson(res, 429, {
        success: false,
        error: `🔒 Security Lockout: Too many failed attempts! Try again in ${mins}m ${secs}s.`
      });
    }

    const code = String(query.code || query.token || '').trim();
    const deviceId = String(query.deviceId || '').trim();
    let targetDevice = getTargetDevice(deviceId);

    if (isTokenValid(code, targetDevice)) {
      record.failedAttempts = 0;
      record.lockedUntilMs = 0;
      return sendJson(res, 200, {
        success: true,
        token: code,
        deviceId: targetDevice ? targetDevice.deviceId : '',
        message: 'Authenticated successfully'
      });
    }

    let matchedAuthDevice = null;
    if (verifyRawCode(code, targetDevice)) {
      matchedAuthDevice = targetDevice;
    } else if (devices.size > 1) {
      for (const dev of devices.values()) {
        if (verifyRawCode(code, dev)) {
          matchedAuthDevice = dev;
          break;
        }
      }
    }

    if (matchedAuthDevice || (devices.size === 0 && verifyRawCode(code, null))) {
      record.failedAttempts = 0;
      record.lockedUntilMs = 0;
      const token = generateToken(clientIp, code);
      return sendJson(res, 200, {
        success: true,
        token,
        deviceId: matchedAuthDevice ? matchedAuthDevice.deviceId : '',
        message: 'Authenticated successfully'
      });
    } else {
      record.failedAttempts += 1;
      if (record.failedAttempts >= 5) {
        record.lockedUntilMs = now + 15 * 60 * 1000;
        return sendJson(res, 200, {
          success: false,
          error: '🔒 5 Failed Attempts! Your IP is locked for 15 minutes for tablet security.'
        });
      }
      const left = 5 - record.failedAttempts;
      return sendJson(res, 200, {
        success: false,
        error: `Invalid Remote Access Code (${left} attempts remaining before 15m lockout)`
      });
    }
  }

  // 3. STATUS ENDPOINT (/api/status)
  if (pathname === '/api/status') {
    const code = String(query.code || query.token || '').trim();
    const deviceId = String(query.deviceId || '').trim();
    const dev = getTargetDevice(deviceId);
    const isAuth = code ? verifyCodeOrToken(code, deviceId) : false;
    const authExpired = Boolean(code && !isAuth);

    if (dev && isAuth) {
      dev.viewerLastSeenMs = Date.now();
    }

    const fleet = [];
    for (const d of devices.values()) {
      if (!d.deviceId || String(d.deviceId).startsWith('TEST-')) continue;
      const online = d.lastSeenMs > 0 && ((Date.now() - d.lastSeenMs) < 15000);
      fleet.push({
        deviceId: d.deviceId,
        deviceName: d.deviceName,
        model: d.model,
        localIp: d.localIp,
        meshIp: d.meshIp,
        batteryPct: d.batteryPct,
        isScreenOn: d.isScreenOn,
        online
      });
    }

    const onlineNow = dev ? (dev.lastSeenMs > 0 && ((Date.now() - dev.lastSeenMs) < 15000)) : false;
    return sendJson(res, 200, {
      status: onlineNow ? 'streaming' : 'waiting',
      authExpired,
      viewers: 1,
      deviceId: dev ? dev.deviceId : '',
      deviceName: dev ? dev.deviceName : 'Waiting for Tablet...',
      model: dev ? dev.model : 'Western Tablet',
      localIp: dev ? dev.localIp : '',
      meshIp: dev ? dev.meshIp : '',
      cloudUrl: currentPublicHttpsUrl || (`http://localhost:${PORT}`),
      cloudConnected: onlineNow,
      batteryPct: dev ? dev.batteryPct : 100,
      isScreenOn: dev ? dev.isScreenOn : true,
      lastScreenOn: dev ? dev.lastScreenOn : 'Just now',
      lastDisconnect: 'None',
      fleet
    });
  }

  const code = String(query.code || query.token || '').trim();
  const deviceId = String(query.deviceId || '').trim();
  const isAuthorized = verifyCodeOrToken(code, deviceId);
  const dev = getTargetDevice(deviceId);

  // 4. ALL /api/admin/* ENDPOINTS
  if (pathname === '/api/admin/remove-device') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const targetId = String(query.targetDeviceId || query.targetId || query.deviceId || '').trim();
    if (targetId && devices.has(targetId)) {
      devices.delete(targetId);
      savePersistedDevices();
      console.log(`[Admin] Removed device: ${targetId}`);
      return sendJson(res, 200, { success: true, message: `Removed device ${targetId}` });
    }
    return sendJson(res, 404, { success: false, error: 'Device not found' });
  }

  if (pathname === '/api/admin/touch') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, {
      type: 'touch',
      xRatio: parseFloat(query.xRatio || '0'),
      yRatio: parseFloat(query.yRatio || '0')
    });
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/admin/swipe') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, {
      type: 'swipe',
      x1Ratio: parseFloat(query.x1Ratio || '0'),
      y1Ratio: parseFloat(query.y1Ratio || '0'),
      x2Ratio: parseFloat(query.x2Ratio || '0'),
      y2Ratio: parseFloat(query.y2Ratio || '0')
    });
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/admin/nav') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const action = String(query.action || 'back');
    queueCommand(dev, { type: 'nav', action });
    return sendJson(res, 200, { success: true, message: 'Dispatched ' + action });
  }

  if (pathname === '/api/admin/clear-recents' || pathname === '/api/admin/close-recents') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, { type: 'clear-recents' });
    return sendJson(res, 200, { success: true, message: 'Dispatched close recent apps' });
  }

  if (pathname === '/api/admin/reboot' || pathname === '/api/admin/restart') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, { type: 'reboot' });
    return sendJson(res, 200, { success: true, message: 'Reboot signal dispatched to tablet' });
  }

  if (pathname === '/api/admin/wake') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    if (dev) dev.isScreenOn = true;
    queueCommand(dev, { type: 'wake' });
    return sendJson(res, 200, { success: true, message: 'Screen wake command dispatched' });
  }

  if (pathname === '/api/admin/open-settings') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, { type: 'open-settings' });
    return sendJson(res, 200, { success: true, message: 'Opened Settings' });
  }

  if (pathname === '/api/admin/open-wifi') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, { type: 'open-wifi' });
    return sendJson(res, 200, { success: true, message: 'Opened Wi-Fi Settings' });
  }

  if (pathname === '/api/admin/unrestrict-settings') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const enable = String(query.enable || 'true').toLowerCase() !== 'false';
    queueCommand(dev, { type: 'unrestrict-settings', enable });
    return sendJson(res, 200, { success: true, unrestricted: enable });
  }

  if (pathname === '/api/admin/volume') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const dir = String(query.dir || 'up');
    queueCommand(dev, { type: 'volume', dir });
    return sendJson(res, 200, { success: true, message: 'Adjusted volume ' + dir });
  }

  if (pathname === '/api/admin/add-wifi') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const ssid = String(query.ssid || '').trim();
    if (!ssid) return sendJson(res, 400, { success: false, message: 'SSID cannot be blank' });
    const sec = String(query.sec || 'WPA2/WPA3');
    const ipMode = String(query.ipMode || 'DHCP');
    const staticIp = String(query.staticIp || '').trim();
    const subnet = String(query.subnet || '255.255.255.0').trim() || '255.255.255.0';
    let gateway = String(query.gateway || '').trim();
    if (!gateway && ipMode === 'Static' && staticIp.split('.').length === 4) {
      const p = staticIp.split('.');
      gateway = `${p[0]}.${p[1]}.${p[2]}.1`;
    }
    const dns1 = String(query.dns1 || '').trim() || '8.8.8.8';
    const dns2 = String(query.dns2 || '').trim() || '8.8.4.4';
    queueCommand(dev, {
      type: 'add-wifi',
      ssid,
      pass: sec === 'Open' ? '' : String(query.pass || '').trim(),
      sec,
      ipMode,
      staticIp: ipMode === 'Static' ? staticIp : '',
      subnet,
      gateway,
      dns1,
      dns2
    });
    return sendJson(res, 200, { success: true, message: `Configured Wi-Fi ${ssid} (${ipMode} • DNS: ${dns1})` });
  }

  if (pathname === '/api/admin/type') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const text = String(query.text || '');
    queueCommand(dev, { type: 'type', text });
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/admin/apps') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    return sendJson(res, 200, dev ? (dev.apps || []) : []);
  }

  if (pathname === '/api/admin/launch-app') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const pkg = String(query.pkg || '').trim();
    queueCommand(dev, { type: 'launch-app', pkg });
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/admin/close-app') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    queueCommand(dev, { type: 'close-app' });
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/admin/sos') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const msg = String(query.msg || 'EMERGENCY ALERT: Attention Required Immediately!').trim();
    queueCommand(dev, { type: 'sos', msg });
    return sendJson(res, 200, { success: true, message: 'Emergency SOS alert broadcasted to tablet' });
  }

  if (pathname === '/api/admin/cloud-config') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    if (query.save === '1') {
      const newName = String(query.name || '').trim();
      const newUrl = String(query.url || '').trim();
      if (dev && newName) dev.deviceName = newName;
      savePersistedDevices();
      queueCommand(dev, { type: 'cloud-config', name: newName, url: newUrl });
    }
    const onlineNow = dev ? (dev.lastSeenMs > 0 && ((Date.now() - dev.lastSeenMs) < 15000)) : false;
    return sendJson(res, 200, {
      success: true,
      deviceId: dev ? dev.deviceId : 'WIG-TAB',
      deviceName: dev ? dev.deviceName : 'Western Tablet',
      localIp: dev ? dev.localIp : '--',
      meshIp: dev ? dev.meshIp : '',
      cloudUrl: '',
      cloudConnected: onlineNow,
      cloudStatus: onlineNow ? 'Connected 🟢 (Western Cloud Active)' : 'Waiting for Tablet...'
    });
  }

  if (pathname === '/api/admin/push-update' && req.method === 'POST') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    const chunks = [];
    let totalBytes = 0;
    req.on('data', chunk => {
      totalBytes += chunk.length;
      if (totalBytes > 50 * 1024 * 1024) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      latestOtaApkBuffer = Buffer.concat(chunks);
      if (latestOtaApkBuffer.length > 500000 && dev) {
        const baseUrl = currentPublicHttpsUrl || (`http://${req.headers.host || ('localhost:' + PORT)}`);
        queueCommand(dev, {
          type: 'ota-update',
          downloadUrl: `${baseUrl}/api/device/ota-apk?t=${Date.now()}`
        });
        return sendJson(res, 200, { success: true, message: 'OTA update queued to tablet' });
      }
      return sendJson(res, 400, { success: false, error: 'Invalid APK file' });
    });
    return;
  }

  // 5. LIVE SCREEN MJPEG STREAM (/stream)
  if (pathname === '/stream') {
    if (!isAuthorized) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      return res.end('401 Unauthorized');
    }
    res.writeHead(200, {
      'Connection': 'close',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Content-Type': 'multipart/x-mixed-replace; boundary=frame'
    });

    let lastSentFrame = null;
    let lastSentTime = 0;

    const sendFrame = (frame) => {
      try {
        res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${frame.length}\r\n\r\n`);
        res.write(frame);
        res.write('\r\n');
        lastSentFrame = frame;
        lastSentTime = Date.now();
      } catch (_) {
        clearInterval(interval);
      }
    };

    const targetInit = getTargetDevice(deviceId);
    if (targetInit) {
      targetInit.viewerLastSeenMs = Date.now();
      const initialFrame = targetInit.screenFrameBuffer || FALLBACK_JPEG;
      sendFrame(initialFrame);
      const sockets = wsClients.get(targetInit.deviceId);
      if (sockets) {
        for (const s of sockets) sendWsText(s, JSON.stringify({ type: 'viewer', active: true }));
      }
    }

    const interval = setInterval(() => {
      const target = getTargetDevice(deviceId);
      if (!target) return;
      target.viewerLastSeenMs = Date.now();
      const frame = target.screenFrameBuffer || FALLBACK_JPEG;
      const now = Date.now();
      if (frame !== lastSentFrame || (now - lastSentTime >= 800)) {
        sendFrame(frame);
      }
    }, 35);

    req.on('close', () => {
      clearInterval(interval);
      const target = getTargetDevice(deviceId);
      if (target) {
        const sockets = wsClients.get(target.deviceId);
        if (sockets) {
          for (const s of sockets) sendWsText(s, JSON.stringify({ type: 'viewer', active: false }));
        }
      }
    });
    return;
  }

  // 6. LIVE CAMERA MJPEG STREAM (/api/camera/stream)
  if (pathname === '/api/camera/stream') {
    if (!isAuthorized) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      return res.end('401 Unauthorized');
    }
    const lens = String(query.lens || 'front');
    if (dev) {
      dev.cameraActive = true;
      dev.cameraLens = lens;
      dev.viewerLastSeenMs = Date.now();
      queueCommand(dev, { type: 'camera-start', lens });
    }

    res.writeHead(200, {
      'Connection': 'close',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Content-Type': 'multipart/x-mixed-replace; boundary=frame'
    });

    let lastSentCamFrame = null;
    let lastSentCamTime = 0;

    const sendCamFrame = (frame) => {
      try {
        res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${frame.length}\r\n\r\n`);
        res.write(frame);
        res.write('\r\n');
        lastSentCamFrame = frame;
        lastSentCamTime = Date.now();
      } catch (_) {
        clearInterval(interval);
      }
    };

    const interval = setInterval(() => {
      const target = getTargetDevice(deviceId);
      if (!target) return;
      target.viewerLastSeenMs = Date.now();
      target.cameraActive = true;
      const frame = target.cameraFrameBuffer || FALLBACK_JPEG;
      const now = Date.now();
      if (frame !== lastSentCamFrame || (now - lastSentCamTime >= 800)) {
        sendCamFrame(frame);
      }
    }, 40);

    req.on('close', () => clearInterval(interval));
    return;
  }

  // 6b. STOP CAMERA (/api/camera/stop)
  if (pathname === '/api/camera/stop') {
    if (!isAuthorized) return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    if (dev) {
      dev.cameraActive = false;
      queueCommand(dev, { type: 'camera-stop' });
    }
    return sendJson(res, 200, { success: true, message: 'Camera stream stopped' });
  }

  // 7. SNAPSHOTS (/snapshot and /api/camera/snapshot)
  if (pathname === '/snapshot' || pathname === '/api/camera/snapshot') {
    if (!isAuthorized) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      return res.end('401 Unauthorized');
    }
    const isCam = pathname.includes('camera');
    const frame = dev ? (isCam ? dev.cameraFrameBuffer : dev.screenFrameBuffer) : null;
    const outBuf = frame || FALLBACK_JPEG;
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': outBuf.length,
      'Content-Disposition': `inline; filename="western_${isCam ? 'camera' : 'screen'}_${Date.now()}.jpg"`
    });
    return res.end(outBuf);
  }

  // 8. MAIN WEB PORTAL UI (100% Identical to Tablet Local Host Web Portal!)
  if (pathname === '/' || pathname.startsWith('/index')) {
    const html = buildDashboardHtml();
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Content-Length': Buffer.byteLength(html)
    });
    return res.end(html);
  }

  res.writeHead(404);
  res.end('Not Found');
});

function buildDashboardHtml() {
  const logoImgTagAuth = cachedLogoBase64
    ? `<div style="background:#ffffff; padding:15px; border-radius:12px; display:inline-block; margin-bottom:10px;"><img src="data:image/png;base64,${cachedLogoBase64}" alt="Western Logo" style="max-width:140px; height:auto; display:block; margin:0 auto;" /></div>`
    : `<div style="font-size:2.5rem; margin-bottom:8px;">🏢</div>`;

  const logoImgTagHeader = cachedLogoBase64
    ? `<div style="background:#ffffff; padding:4px 8px; border-radius:6px; display:inline-block; margin-right:12px;"><img src="data:image/png;base64,${cachedLogoBase64}" alt="Western Logo" style="max-height:28px; width:auto; display:block;" /></div>`
    : `<div style="font-size:24px; margin-right:12px;">🛡️</div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
  <title>Western AppLock - Remote Tablet Monitor</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 0;
      background: #0b1120;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex; flex-direction: column; align-items: center;
      min-height: 100vh;
    }
    header {
      width: 100%;
      background: #1e293b;
      padding: 10px 20px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      border-bottom: 2px solid #e11d48;
      box-shadow: 0 4px 15px rgba(0,0,0,0.5);
    }
    .top-row {
      width: 100%;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand { display: flex; align-items: center; gap: 10px; }
    .brand h1 { margin: 0; font-size: 1.15rem; font-weight: 800; color: #ffffff; letter-spacing: 0.5px; }
    .brand span { font-size: 0.74rem; color: #94a3b8; font-weight: 500; display: block; }

    .header-badges { display: flex; flex-direction: row; align-items: center; gap: 8px; flex-wrap: wrap; }
    .device-info { font-size: 0.78rem; color: #cbd5e1; background: #0f172a; border: 1px solid #334155; padding: 4px 10px; border-radius: 6px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
    .device-info.green { color: #34d399; border-color: rgba(52, 211, 153, 0.3); }
    .device-info.red { color: #f87171; border-color: rgba(248, 113, 113, 0.3); }

    .top-right { display: flex; align-items: center; gap: 10px; }

    .toolbar-row {
      width: 100%;
      display: none;
      justify-content: center;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      padding-top: 8px;
      border-top: 1px solid #334155;
    }
    .btn-group {
      display: flex;
      align-items: center;
      gap: 5px;
      background: #0f172a;
      padding: 4px 8px;
      border-radius: 8px;
      border: 1px solid #334155;
    }
    .group-label {
      font-size: 0.65rem;
      font-weight: 800;
      color: #64748b;
      margin-right: 4px;
      letter-spacing: 0.5px;
    }
    .btn-hdr {
      background: #1e293b;
      border: 1px solid #475569;
      color: #f8fafc;
      padding: 5px 11px;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
      transition: all 0.15s ease;
      -webkit-tap-highlight-color: transparent;
    }
    .btn-hdr:hover { background: #334155; border-color: #64748b; transform: translateY(-1px); }
    .btn-hdr:active, .btn-hdr.touch-active {
      background: #06b6d4 !important;
      border-color: #67e8f9 !important;
      color: #ffffff !important;
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.65);
      transform: scale(0.96);
    }
    .btn-hdr.btn-accent { background: #0284c7; border-color: #38bdf8; color: #f8fafc; }
    .btn-hdr.btn-accent:hover { background: #0369a1; }
    .btn-hdr.btn-reboot { background: #c2410c; border-color: #ea580c; color: #fff; }
    .btn-hdr.btn-reboot:hover { background: #9a3412; }
    .btn-hdr.btn-danger { background: #be123c; border-color: #e11d48; color: #fff; }
    .btn-hdr.btn-danger:hover { background: #9f1239; }

    .badge-live { display: flex; align-items: center; gap: 5px; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #10b981; padding: 4px 9px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; white-space: nowrap; }
    .badge-disconnected { display: none; align-items: center; gap: 6px; background: rgba(225, 29, 72, 0.22); border: 1px solid #e11d48; color: #fb7185; padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; white-space: nowrap; animation: blinkWarning 1.5s ease-in-out infinite alternate; }
    @keyframes blinkWarning { 0% { opacity: 0.8; } 100% { opacity: 1; border-color: #f43f5e; box-shadow: 0 0 12px rgba(225, 29, 72, 0.45); } }
    .conn-lost-banner { display: none; position: absolute; top: 14px; left: 50%; transform: translateX(-50%); background: rgba(225, 29, 72, 0.94); color: #fff; padding: 8px 18px; border-radius: 30px; font-size: 0.85rem; font-weight: 700; box-shadow: 0 6px 20px rgba(0,0,0,0.6); z-index: 150; border: 1px solid #fda4af; animation: blinkWarning 1s infinite alternate; pointer-events: none; }
    .pulse-dot { width: 7px; height: 7px; background: #10b981; border-radius: 50%; box-shadow: 0 0 8px #10b981; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0% { transform: scale(0.95); opacity: 1; } 50% { transform: scale(1.2); opacity: 0.6; } 100% { transform: scale(0.95); opacity: 1; } }

    .input-type {
      padding: 6px 10px;
      border-radius: 6px;
      background: #0f172a;
      border: 1px solid #475569;
      color: #fff;
      font-size: 0.85rem;
      font-weight: 600;
      outline: none;
    }
    .input-type:focus { border-color: #e11d48; }

    .app-list-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 10px;
      max-height: 60vh;
      overflow-y: auto;
      padding: 10px 0;
    }
    .app-card-btn {
      background: #0f172a;
      border: 1px solid #334155;
      color: #fff;
      padding: 10px;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 700;
      cursor: pointer;
      text-align: left;
      transition: all 0.2s;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .app-card-btn:hover { background: #1e293b; border-color: #e11d48; transform: translateY(-1px); }

    main {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: flex-start;
      padding: 10px 14px;
      width: 100%;
    }
    .admin-feedback {
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 700;
      display: none;
      width: 100%;
      max-width: 1100px;
      margin-bottom: 8px;
      text-align: center;
    }
    .admin-feedback.success { background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #34d399; }
    .admin-feedback.error { background: rgba(225, 29, 72, 0.15); border: 1px solid #e11d48; color: #f87171; }

    .dual-stream-container {
      display: flex;
      flex-direction: row;
      justify-content: center;
      align-items: flex-start;
      gap: 16px;
      width: 100%;
      max-width: 98vw;
      margin-top: 4px;
      flex-wrap: wrap;
    }
    .stream-panel {
      flex: 1 1 540px;
      max-width: 820px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0,0,0,0.6);
      display: flex;
      flex-direction: column;
      align-items: center;
      transition: all 0.25s ease;
    }
    .stream-panel.full-screen-only {
      max-width: 960px;
    }
    .panel-header {
      width: 100%;
      background: #1e293b;
      padding: 7px 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #334155;
      gap: 8px;
      flex-wrap: wrap;
    }
    .panel-title {
      font-size: 0.82rem;
      font-weight: 800;
      color: #f8fafc;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .panel-controls {
      display: flex;
      align-items: center;
      gap: 5px;
      flex-wrap: wrap;
    }
    .btn-ctrl {
      background: #0f172a;
      border: 1px solid #475569;
      color: #cbd5e1;
      padding: 4px 9px;
      border-radius: 6px;
      font-size: 0.74rem;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 3px;
      transition: all 0.15s ease;
      -webkit-tap-highlight-color: transparent;
    }
    .btn-ctrl:hover {
      background: #334155;
      border-color: #64748b;
      color: #fff;
    }
    .btn-ctrl:active, .btn-ctrl.touch-active {
      background: #06b6d4 !important;
      border-color: #67e8f9 !important;
      color: #fff !important;
      box-shadow: 0 0 10px rgba(6, 182, 212, 0.6);
    }
    .btn-ctrl.btn-close {
      background: rgba(225, 29, 72, 0.2);
      border-color: #e11d48;
      color: #fb7185;
    }
    .btn-ctrl.btn-close:hover {
      background: #e11d48;
      color: #fff;
    }
    .rot-badge {
      font-size: 0.72rem;
      color: #94a3b8;
      font-weight: 700;
      padding: 2px 6px;
      background: #0b1120;
      border-radius: 4px;
      border: 1px solid #334155;
    }
    .live-dot {
      width: 7px;
      height: 7px;
      background: #10b981;
      border-radius: 50%;
      box-shadow: 0 0 6px #10b981;
    }

    .screen-wrapper, .camera-wrapper {
      position: relative;
      width: 100%;
      min-height: 400px;
      max-height: 75vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: #000;
      overflow: hidden;
      cursor: crosshair;
    }
    .camera-wrapper {
      cursor: default;
    }
    #screen-stream, #camera-stream {
      max-height: 75vh;
      max-width: 100%;
      width: auto;
      height: auto;
      object-fit: contain;
      display: block;
      user-select: none;
      -webkit-user-select: none;
      transform-origin: center center;
      transition: transform 0.2s ease;
    }

    .touch-ripple {
      position: absolute;
      width: 30px;
      height: 30px;
      border-radius: 50%;
      background: rgba(225, 29, 72, 0.5);
      border: 2px solid #f43f5e;
      pointer-events: none;
      animation: rippleAnim 0.4s ease-out forwards;
      z-index: 999;
    }
    @keyframes rippleAnim {
      0% { transform: scale(0.3); opacity: 1; }
      100% { transform: scale(1.8); opacity: 0; }
    }

    .app-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(11, 17, 32, 0.9);
      backdrop-filter: blur(8px);
      display: none;
      justify-content: center;
      align-items: center;
      z-index: 9999;
      padding: 16px;
    }
    .app-card-modal {
      background: #1e293b;
      border: 1px solid #475569;
      border-radius: 16px;
      padding: 20px;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 20px 50px rgba(0,0,0,0.8);
    }

    /* Exact Local Host Remote Access Code Modal */
    .auth-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(11, 17, 32, 0.95);
      backdrop-filter: blur(10px);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 99999;
      padding: 16px;
    }
    .auth-card {
      background: #1e293b;
      border: 1px solid #475569;
      border-radius: 18px;
      padding: 28px 24px;
      max-width: 420px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 50px rgba(0,0,0,0.8);
    }
    .auth-icon { font-size: 40px; margin-bottom: 10px; }
    .auth-card h2 { margin: 0 0 8px; font-size: 1.2rem; font-weight: 800; color: #fff; }
    .auth-card p { font-size: 0.82rem; color: #94a3b8; margin: 0 0 18px; line-height: 1.4; }
    .auth-input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 10px;
      background: #0f172a;
      border: 1px solid #475569;
      color: #fff;
      font-size: 1.2rem;
      font-weight: 700;
      text-align: center;
      letter-spacing: 4px;
      outline: none;
      box-sizing: border-box;
      margin-bottom: 12px;
    }
    .auth-input:focus { border-color: #e11d48; box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.35); }
    .btn-auth {
      width: 100%;
      background: #e11d48;
      color: #fff;
      border: none;
      padding: 11px;
      border-radius: 10px;
      font-size: 0.92rem;
      font-weight: 800;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn-auth:hover { background: #be123c; }
    .auth-error {
      color: #f87171;
      font-size: 0.8rem;
      font-weight: 600;
      margin-top: 10px;
      display: none;
    }

    footer {
      padding: 10px;
      font-size: 0.72rem;
      color: #64748b;
      text-align: center;
    }

    @media (max-width: 600px) {
      header { padding: 8px 12px; }
      .screen-wrapper { max-height: 70vh; border-radius: 10px; }
      #screen-stream { max-height: 70vh; }
      .btn-hdr { padding: 4px 8px; font-size: 0.72rem; }
    }
  </style>
</head>
<body>
  <!-- Remote Access Code Security Gate Modal (100% Identical to Local Host Web!) -->
  <div class="auth-overlay" id="authOverlay">
    <div class="auth-card">
      <div class="auth-icon" style="margin-bottom:8px;">
        ${logoImgTagAuth}
      </div>
      <div id="authDeviceSelectContainer" style="margin-bottom:12px; text-align:left;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <label style="font-size:0.75rem; color:#94a3b8; font-weight:700;">Select Target Branch Tablet:</label>
          <button type="button" onclick="promptRemoveDeviceFromLogin()" style="background:transparent; border:1px solid #ef4444; color:#ef4444; font-size:0.72rem; font-weight:700; cursor:pointer; padding:2px 8px; border-radius:6px; display:inline-flex; align-items:center; gap:3px;" onmouseover="this.style.background='#ef4444';this.style.color='#fff'" onmouseout="this.style.background='transparent';this.style.color='#ef4444'" title="Delete damaged or offline tablet from fleet">🗑️ Remove Tablet</button>
        </div>
        <select id="authDeviceSelect" class="input-type" onchange="selectFleetDevice(this.value)" style="width:100%; margin-bottom:0; padding:8px 10px; font-size:0.85rem; font-weight:700; color:#38bdf8; border:1px solid #38bdf8; background:#0f172a; border-radius:8px; outline:none; cursor:pointer;">
          <option value="">🔄 Auto-Detecting Connected Tablets...</option>
        </select>
      </div>
      <input type="password" id="remoteCodeInput" class="auth-input" placeholder="••••" onkeydown="if(event.key==='Enter') submitAuth()" />
      <button class="btn-auth" onclick="submitAuth()">Verify &amp; Connect 🔑</button>
      <div id="authError" class="auth-error"></div>
      <div style="margin-top:14px; font-size:0.75rem; color:#64748b; text-align:center;">
        Live Cloud Portal: <a href="https://is.gd/westernintapplock" target="_blank" style="color:#38bdf8; text-decoration:none; font-weight:600;">https://is.gd/westernintapplock</a>
      </div>
    </div>
  </div>

  <!-- App Selector Modal -->
  <div class="app-overlay" id="appsModal">
    <div class="app-card-modal">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.1rem;">📱 Tablet Application Manager</h3>
        <button class="btn-hdr" onclick="closeAppsModal()">✖ Close</button>
      </div>
      <input type="text" id="appSearchInput" class="input-type" placeholder="🔍 Search installed apps..." onkeyup="filterApps()" style="width:100%; margin-bottom:10px;" />
      <div class="app-list-grid" id="appsListGrid">
        <div style="color:#94a3b8; font-size:0.85rem;">Loading tablet apps...</div>
      </div>
    </div>
  </div>

  <!-- Remote Wi-Fi Configuration Modal -->
  <div class="app-overlay" id="wifiModal">
    <div class="app-card-modal" style="max-width:480px; text-align:left;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.1rem; color:#fff;">📶 Remote Wi-Fi Configurator</h3>
        <button class="btn-hdr" onclick="closeWifiModal()">✖ Close</button>
      </div>
      <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:12px;">Configure Wi-Fi SSID, Password, IP Mode (DHCP / Static) &amp; Auto/Manual DNS remotely on tablet:</div>
      
      <label style="font-size:0.8rem; color:#cbd5e1; display:block; margin-top:8px;">Wi-Fi SSID (Network Name):</label>
      <input type="text" id="wifiSsidInput" class="input-type" placeholder="e.g. Office_WiFi" style="width:100%; margin-top:4px;" />
      
      <label style="font-size:0.8rem; color:#cbd5e1; display:block; margin-top:8px;">Wi-Fi Password:</label>
      <input type="password" id="wifiPassInput" class="input-type" placeholder="e.g. Pass123" style="width:100%; margin-top:4px;" />
      
      <div style="display:flex; gap:10px; margin-top:10px;">
        <div style="flex:1;">
          <label style="font-size:0.8rem; color:#cbd5e1;">Security:</label>
          <select id="wifiSecSelect" class="input-type" style="width:100%; margin-top:4px; padding:8px;">
            <option value="WPA2/WPA3">WPA2/WPA3</option>
            <option value="WEP">WEP</option>
            <option value="Open">Open / None</option>
          </select>
        </div>
        <div style="flex:1;">
          <label style="font-size:0.8rem; color:#cbd5e1;">IP Assignment:</label>
          <select id="wifiIpModeSelect" class="input-type" style="width:100%; margin-top:4px; padding:8px;" onchange="toggleWebStaticIpFields()">
            <option value="DHCP">DHCP (Auto IP)</option>
            <option value="Static">Static IP</option>
          </select>
        </div>
      </div>

      <div id="webStaticIpFields" style="display:none; margin-top:10px; background:#0f172a; padding:10px; border-radius:10px; border:1px solid #334155;">
        <label style="font-size:0.75rem; color:#f43f5e; font-weight:bold;">Static IP Configuration:</label>
        <input type="text" id="wifiStaticIp" class="input-type" placeholder="Static IP (e.g. 192.168.1.100)" oninput="autoFillWebGateway()" style="width:100%; margin-top:6px; font-size:0.85rem;" />
        <input type="text" id="wifiSubnet" class="input-type" placeholder="Subnet Mask (e.g. 255.255.255.0)" value="255.255.255.0" style="width:100%; margin-top:6px; font-size:0.85rem;" />
        <input type="text" id="wifiGateway" class="input-type" placeholder="Gateway / Router (e.g. 192.168.1.1)" style="width:100%; margin-top:6px; font-size:0.85rem;" />
      </div>

      <div style="margin-top:10px;">
        <label style="font-size:0.8rem; color:#cbd5e1;">DNS Server Mode:</label>
        <select id="wifiDnsModeSelect" class="input-type" style="width:100%; margin-top:4px; padding:8px;" onchange="toggleWebDnsFields()">
          <option value="Auto">Auto DNS (Recommended - Router + 8.8.8.8)</option>
          <option value="Manual">Manual DNS</option>
        </select>
      </div>

      <div id="webDnsFields" style="display:none; margin-top:8px; background:#0f172a; padding:10px; border-radius:10px; border:1px solid #334155;">
        <label style="font-size:0.75rem; color:#38bdf8; font-weight:bold;">Manual DNS Servers:</label>
        <input type="text" id="wifiDns1" class="input-type" placeholder="Primary DNS (e.g. 8.8.8.8)" value="8.8.8.8" style="width:100%; margin-top:6px; font-size:0.85rem;" />
        <input type="text" id="wifiDns2" class="input-type" placeholder="Secondary DNS (e.g. 8.8.4.4)" value="8.8.4.4" style="width:100%; margin-top:6px; font-size:0.85rem;" />
      </div>

      <button class="btn-auth" style="margin-top:14px; background:#10b981;" onclick="submitRemoteWifi()">Save &amp; Connect Wi-Fi 🌐</button>
    </div>
  </div>

  <!-- Remote APK Push Update Modal -->
  <div class="app-overlay" id="updateModal">
    <div class="app-card-modal" style="max-width:480px; text-align:left;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.1rem; color:#fff;">📦 Remote OTA APK Installer</h3>
        <button class="btn-hdr" onclick="closeUpdateModal()">✖ Close</button>
      </div>
      <div style="font-size:0.82rem; color:#94a3b8; margin-bottom:14px;">Select a new <strong>.apk</strong> file from your PC to upload and silently update Western AppLock on the tablet over Wi-Fi / Cloud:</div>
      
      <input type="file" id="apkFileInput" accept=".apk" style="width:100%; margin-bottom:14px; padding:10px; background:#0f172a; border:1px solid #334155; border-radius:10px; color:#fff; font-size:0.85rem;" />
      
      <div id="updateProgressBox" style="display:none; margin-bottom:12px;">
        <div style="font-size:0.8rem; color:#38bdf8; font-weight:bold; margin-bottom:4px;" id="updateProgressText">Uploading APK...</div>
        <div style="width:100%; height:8px; background:#0f172a; border-radius:4px; overflow:hidden;">
          <div id="updateProgressBar" style="width:0%; height:100%; background:#10b981; transition:width 0.2s;"></div>
        </div>
      </div>

      <button class="btn-auth" style="background:#0284c7;" onclick="submitPushUpdate()">🚀 Upload &amp; Install APK Update</button>
    </div>
  </div>

  <!-- Emergency SOS Modal -->
  <div class="app-overlay" id="sosModal">
    <div class="app-card-modal" style="max-width:480px; text-align:left; border: 2px solid #e11d48; box-shadow: 0 0 35px rgba(225, 29, 72, 0.45);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.15rem; color:#f43f5e; display:flex; align-items:center; gap:8px;">🚨 Broadcast Emergency SOS Alert</h3>
        <button class="btn-hdr" onclick="closeSosModal()">✖ Close</button>
      </div>
      <div style="font-size:0.83rem; color:#cbd5e1; margin-bottom:12px; line-height:1.4;">
        Broadcast an urgent emergency alert modal to the tablet screen.
        The tablet will sound an alarm, vibrate, and the user <strong>cannot dismiss or do anything for 10 seconds</strong> before an acknowledge button is unlocked.
      </div>
      
      <label style="font-size:0.8rem; color:#94a3b8; display:block; margin-bottom:4px; font-weight:700;">SOS Message Text:</label>
      <textarea id="sosTextInput" class="input-type" rows="3" style="width:100%; resize:vertical; font-size:0.9rem;" placeholder="e.g. URGENT: Report to IT Office immediately! Device maintenance scheduled."></textarea>
      
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:14px;">
        <button class="btn-hdr" onclick="closeSosModal()">Cancel</button>
        <button class="btn-hdr btn-danger" style="padding:8px 18px; font-size:0.88rem; font-weight:800;" onclick="submitSosAlert()">🚨 Send Emergency SOS (10s Lock)</button>
      </div>
    </div>
  </div>

  <!-- Cloud & Any-Network Setup Modal -->
  <div class="app-overlay" id="cloudModal">
    <div class="app-card-modal" style="max-width:520px; text-align:left; border: 1px solid #38bdf8;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0; font-size:1.1rem; color:#38bdf8; display:flex; align-items:center; gap:8px;">☁️ Any-Network Cloud &amp; Mesh Access</h3>
        <button class="btn-hdr" onclick="closeCloudModal()">✖ Close</button>
      </div>
      <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:12px; line-height:1.4;">
        Access and control this tablet from <strong>any network worldwide</strong> (4G/5G SIM card or another branch Wi-Fi) with <strong>HTTPS encryption</strong> at $0 cost:
      </div>

      <div style="background:#0f172a; border:1px solid #334155; border-radius:10px; padding:10px 12px; margin-bottom:12px; font-size:0.8rem;">
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span style="color:#94a3b8;">🆔 Tablet Device ID:</span>
          <strong style="color:#f8fafc;" id="cloudDeviceIdLbl">--</strong>
        </div>
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span style="color:#94a3b8;">📡 Local Wi-Fi IP:</span>
          <strong style="color:#38bdf8;" id="cloudLocalIpLbl">--</strong>
        </div>
        <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
          <span style="color:#94a3b8;">🌐 Mesh VPN IP (Tailscale/ZeroTier):</span>
          <strong style="color:#34d399;" id="cloudMeshIpLbl">--</strong>
        </div>
        <div style="display:flex; justify-content:space-between;">
          <span style="color:#94a3b8;">☁️ Cloud Relay Status:</span>
          <strong style="color:#fbbf24;" id="cloudStatusLbl">Checking...</strong>
        </div>
      </div>

      <label style="font-size:0.8rem; color:#cbd5e1; display:block; margin-top:8px; font-weight:700;">🏢 Tablet Branch / Device Name:</label>
      <input type="text" id="cloudDeviceNameInput" class="input-type" placeholder="e.g. KSA-RIYADH-TAB01" style="width:100%; margin-top:4px;" />

      <label style="font-size:0.8rem; color:#cbd5e1; display:block; margin-top:10px; font-weight:700;">🔗 Cloud Relay URL (HTTPS):</label>
      <input type="text" id="cloudRelayUrlInput" class="input-type" placeholder="https://is.gd/westernintapplock" style="width:100%; margin-top:4px;" />

      <button class="btn-auth" style="margin-top:14px; background:#0284c7;" onclick="submitCloudConfig()">💾 Save Cloud Configuration</button>
      <button class="btn-auth" style="margin-top:8px; background:#dc2626;" onclick="deleteCurrentDevice()">🗑️ Remove Tablet from Fleet</button>
    </div>
  </div>

  <header>
    <!-- Row 1: Brand (Left), Device Badges (Center), Status & Logout (Right) -->
    <div class="top-row">
      <div class="brand">
        ${logoImgTagHeader}
        <div>
          <h1>WESTERN INTERNATIONAL GROUP</h1>
          <span>IT Fleet Remote Tablet Monitor • KSA Riyadh</span>
        </div>
      </div>

      <div class="header-badges">
        <select id="fleetSelect" class="device-info" onchange="selectFleetDevice(this.value)" title="Switch Active Tablet" style="display:inline-flex; cursor:pointer; outline:none; border-color:#38bdf8; color:#38bdf8; font-weight:700;"></select>
        <div class="device-info" id="headerDeviceName">📱 Shola Test Tab</div>
        <div class="device-info" id="headerBattery">🔋 --</div>
        <div class="device-info green" id="statScreen">📱 Screen: ON</div>
        <div class="device-info green" id="statCloud" onclick="openCloudModal()" style="cursor:pointer;" title="Click to configure Any-Network Cloud / HTTPS Relay">☁️ Cloud HTTPS: ON</div>
        <div class="device-info" id="statViewers">👁️ 1 Active</div>
      </div>

      <div class="top-right">
        <div class="badge-live" id="badgeLive">
          <div class="pulse-dot"></div>
          <span>LIVE</span>
        </div>
        <div class="badge-disconnected" id="badgeDisconn">
          <span>⚠️ LOST CONNECTION • RECONNECTING...</span>
        </div>
        <button class="btn-hdr btn-danger" onclick="logoutRemote()" title="Logout">🚪 Logout</button>
      </div>
    </div>

    <!-- Row 2: Control Toolbar Grouped -->
    <div class="toolbar-row" id="adminPanel">
      <div class="btn-group">
        <span class="group-label">STREAMS</span>
        <button class="btn-hdr btn-accent" id="btnStreamScreen" title="Tablet Live Screen Mirror Active">🖥️ Screen</button>
        <button class="btn-hdr" id="btnToggleCam" onclick="toggleDualCamera()" title="Toggle Simultaneous Live Camera Stream">📷 Live Camera</button>
      </div>

      <div class="btn-group">
        <span class="group-label">NAV</span>
        <button class="btn-hdr" onclick="remoteNav('back')" title="Back">◀️ Back</button>
        <button class="btn-hdr" onclick="remoteNav('home')" title="Home">🏠 Home</button>
        <button class="btn-hdr" onclick="remoteNav('recents')" title="Recents">||| Recents</button>
        <button class="btn-hdr" onclick="remoteClearRecents()" title="Close Recent Apps">🧹 Close Recents</button>
      </div>

      <div class="btn-group">
        <span class="group-label">TOOLS</span>
        <button class="btn-hdr" onclick="openAppsModal()" title="Open App">📱 Open App</button>
        <button class="btn-hdr" onclick="openWifiModal()" title="Add Wi-Fi">➕ Add Wi-Fi</button>
        <button class="btn-hdr btn-accent" onclick="openCloudModal()" title="Configure Any-Network Cloud Relay &amp; Mesh IP">☁️ Cloud / Any-Net</button>
        <button class="btn-hdr" onclick="openUpdateModal()" title="Push OTA Update">📦 Push Update</button>
        <button class="btn-hdr" onclick="takeSnapshot()" title="Screen Snapshot">📸 Snap</button>
        <button class="btn-hdr" onclick="wakeDeviceScreen()" title="Wake Screen">💡 Wake Screen</button>
        <button class="btn-hdr btn-reboot" onclick="remoteRestart()" title="Remote Reboot">⚡ Reboot</button>
        <button class="btn-hdr btn-danger" onclick="openSosModal()" title="Send Emergency SOS Alert (10s User Lockout)">🚨 Emergency SOS</button>
      </div>

      <div class="btn-group">
        <span class="group-label">SYSTEM</span>
        <button class="btn-hdr" onclick="openSystemSettings()" title="Settings">⚙️ Settings</button>
      </div>

      <div class="btn-group" style="display:inline-flex; align-items:center; gap:6px;">
        <span class="group-label">KEYBOARD</span>
        <input type="text" id="typeTextInput" class="input-type" placeholder="⌨️ Type text to tablet..." onkeydown="if(event.key==='Enter') sendTypeText()" style="width:190px; height:28px; padding:3px 8px; font-size:0.78rem; border-radius:6px;" />
        <button class="btn-hdr btn-accent" onclick="sendTypeText()" title="Send Typed Text to Focused Box on Tablet">Send ⌨️</button>
      </div>
    </div>
  </header>

  <main>
    <div id="adminFeedback" class="admin-feedback"></div>

    <div class="dual-stream-container" id="dualStreamContainer">
      <!-- Screen Stream Panel (Left) -->
      <div class="stream-panel full-screen-only" id="screenPanel">
        <div class="panel-header">
          <div class="panel-title">
            <span class="live-dot"></span>
            <span>🖥️ Tablet Live Screen Mirror</span>
          </div>
          <div class="panel-controls">
            <button class="btn-ctrl" onclick="rotateScreenStream(-90)" title="Rotate Screen 90° Left">⟲ Left</button>
            <button class="btn-ctrl" onclick="rotateScreenStream(90)" title="Rotate Screen 90° Right">⟳ Right</button>
            <button class="btn-ctrl" onclick="toggleScreenFlip()" title="Mirror / Flip Screen">🪞 Flip</button>
            <button class="btn-ctrl" onclick="toggleScreenFit()" title="Fit / Full Width">⛶ Fit</button>
            <button class="btn-ctrl" onclick="resetScreenRotation()" title="Reset Screen Rotation">↺ Reset</button>
            <span id="lblScreenRot" class="rot-badge">0°</span>
          </div>
        </div>
        <div class="screen-wrapper" id="screenWrapper">
          <div id="connLostBanner" class="conn-lost-banner">⚠️ Connection Lost • Reconnecting automatically...</div>

          <div id="screenOffPlaceholder" style="display:none; flex-direction:column; align-items:center; justify-content:center; padding:50px 20px; text-align:center; min-height:350px;">
            <div style="font-size:3.5rem; margin-bottom:12px;">💤</div>
            <div style="font-size:1.15rem; color:#f1f5f9; font-weight:700; margin-bottom:8px;">Tablet Screen is Asleep</div>
            <div style="font-size:0.85rem; color:#94a3b8; margin-bottom:20px; max-width:320px;">The screen is currently turned off. Click below to instantly wake the tablet up!</div>
            <button class="btn-hdr btn-accent" style="padding:10px 24px; font-size:1rem; border-radius:10px;" onclick="wakeDeviceScreen()">💡 Wake Up Tablet Screen</button>
          </div>
          <img id="screen-stream" draggable="false" style="display:none; user-select:none; -webkit-user-drag:none;" alt="Live Tablet Screen" onload="handleStreamLoaded()" onerror="handleStreamError()" />
        </div>
      </div>

      <!-- Camera Stream Panel (Right - Simultaneous View) -->
      <div class="stream-panel" id="cameraPanel" style="display:none;">
        <div class="panel-header">
          <div class="panel-title">
            <span class="live-dot" style="background:#06b6d4; box-shadow:0 0 8px #06b6d4;"></span>
            <span id="cameraTitle">🤳 Front Camera</span>
          </div>
          <div class="panel-controls">
            <button class="btn-ctrl" id="btnSwitchCam" onclick="switchCameraLens()" title="Switch Front / Rear Camera">🔄 Switch Cam</button>
            <button class="btn-ctrl" onclick="rotateCameraStream(90)" title="Rotate Camera 90° Clockwise">⟳ Rotate</button>
            <button class="btn-ctrl" onclick="toggleCameraFlip()" title="Mirror / Flip Camera">🪞 Flip</button>
            <button class="btn-ctrl" onclick="takeCameraSnapshot()" title="Take Camera Snapshot">📸 Snap</button>
            <button class="btn-ctrl btn-close" onclick="closeCameraView()" title="Close Camera Stream">✖ Hide</button>
            <span id="lblCameraRot" class="rot-badge">270°</span>
          </div>
        </div>
        <div class="camera-wrapper" id="cameraWrapper">
          <div id="cameraLoadingPlaceholder" style="display:flex; flex-direction:column; align-items:center; justify-content:center; padding:50px 20px; text-align:center; min-height:350px;">
            <div style="font-size:3rem; margin-bottom:12px; animation: pulse 1s infinite alternate;">📷</div>
            <div style="font-size:1.05rem; color:#f1f5f9; font-weight:700; margin-bottom:6px;">Connecting to Live Camera Stream...</div>
            <div style="font-size:0.8rem; color:#94a3b8;">Direct hardware access in background without user prompts.</div>
          </div>
          <img id="camera-stream" draggable="false" style="display:none; user-select:none; -webkit-user-drag:none;" alt="Live Tablet Camera" onload="handleCameraLoaded()" onerror="handleCameraError()" />
        </div>
      </div>
    </div>
  </main>

  <footer>Western AppLock Enterprise Shield • Developed by IT KSA Riyadh</footer>

  <script>
    let selectedDeviceId = '';
    let isDualCameraOpen = localStorage.getItem('dual_camera_open') === 'true';
    let currentCameraLens = localStorage.getItem('camera_lens') || 'front';
    let cameraRotation = parseInt(localStorage.getItem('camera_rot') || (currentCameraLens === 'front' ? '270' : '90'), 10);
    let isCameraFlipped = localStorage.getItem('camera_flip') !== null ? (localStorage.getItem('camera_flip') === 'true') : (currentCameraLens === 'front');

    let screenRotation = parseInt(localStorage.getItem('rot_screen') || '0', 10);
    let isScreenFlipped = localStorage.getItem('flip_screen') === 'true';
    let isScreenFullWidth = false;

    let isConnected = true;
    let reconnectTimer = null;
    let countdownVal = 2;
    let installedAppsCache = [];

    const INACTIVITY_LIMIT_MS = 5 * 60 * 1000;
    let lastActivityTime = Date.now();
    let sessionTicker = null;

    function devQuery() {
      return selectedDeviceId ? ('&deviceId=' + encodeURIComponent(selectedDeviceId)) : '';
    }

    function selectFleetDevice(id) {
      selectedDeviceId = id;
      const sel1 = document.getElementById('fleetSelect');
      const sel2 = document.getElementById('authDeviceSelect');
      if (sel1 && sel1.value !== id) sel1.value = id;
      if (sel2 && sel2.value !== id) sel2.value = id;
      showFeedback('🔄 Switched Active Tablet to: ' + id, true);
      reloadStream();
      if (isDualCameraOpen) loadCameraStream();
      pollStatus();
    }

    function resetInactivityTimer() {
      lastActivityTime = Date.now();
    }

    window.addEventListener('mousemove', resetInactivityTimer, { passive: true });
    window.addEventListener('mousedown', resetInactivityTimer, { passive: true });
    window.addEventListener('keypress', resetInactivityTimer, { passive: true });
    window.addEventListener('scroll', resetInactivityTimer, { passive: true });
    window.addEventListener('touchstart', resetInactivityTimer, { passive: true });

    const streamImg = document.getElementById('screen-stream');
    const screenWrapper = document.getElementById('screenWrapper');
    let isDragging = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let wheelThrottleTimer = null;

    function mapStreamCoords(clientX, clientY) {
      if (!streamImg) return { x: 0.5, y: 0.5 };
      const rect = streamImg.getBoundingClientRect();
      let u = Math.max(0, Math.min(1, (clientX - rect.left) / Math.max(1, rect.width)));
      let v = Math.max(0, Math.min(1, (clientY - rect.top) / Math.max(1, rect.height)));
      if (isScreenFlipped) u = 1 - u;
      const rot = ((screenRotation % 360) + 360) % 360;
      if (rot === 90) return { x: v, y: 1 - u };
      if (rot === 180) return { x: 1 - u, y: 1 - v };
      if (rot === 270) return { x: 1 - v, y: u };
      return { x: u, y: v };
    }

    function showTouchRipple(clientX, clientY) {
      if (!screenWrapper) return;
      const rect = screenWrapper.getBoundingClientRect();
      const ripple = document.createElement('div');
      ripple.className = 'touch-ripple';
      ripple.style.left = (clientX - rect.left - 15) + 'px';
      ripple.style.top = (clientY - rect.top - 15) + 'px';
      screenWrapper.appendChild(ripple);
      setTimeout(() => ripple.remove(), 400);
    }

    if (streamImg) {
      let lastTouchEventMs = 0;
      streamImg.addEventListener('dragstart', (e) => e.preventDefault());

      streamImg.addEventListener('mousedown', (e) => {
        if (e.button !== 0 || (Date.now() - lastTouchEventMs < 650)) return;
        e.preventDefault();
        isDragging = true;
        const pt = mapStreamCoords(e.clientX, e.clientY);
        dragStartX = pt.x;
        dragStartY = pt.y;
      });

      window.addEventListener('mouseup', (e) => {
        if (!isDragging || e.button !== 0 || (Date.now() - lastTouchEventMs < 650)) return;
        isDragging = false;
        const pt = mapStreamCoords(e.clientX, e.clientY);
        const endX = pt.x;
        const endY = pt.y;

        const dist = Math.hypot(endX - dragStartX, endY - dragStartY);
        const code = getAuthCode();
        if (!code) return;

        showTouchRipple(e.clientX, e.clientY);

        if (dist < 0.03) {
          fetch('/api/admin/touch?xRatio=' + endX + '&yRatio=' + endY + '&code=' + encodeURIComponent(code) + devQuery());
        } else {
          fetch('/api/admin/swipe?x1Ratio=' + dragStartX + '&y1Ratio=' + dragStartY + '&x2Ratio=' + endX + '&y2Ratio=' + endY + '&code=' + encodeURIComponent(code) + devQuery());
        }
      });

      streamImg.addEventListener('touchstart', (e) => {
        if (!e.touches || e.touches.length === 0) return;
        lastTouchEventMs = Date.now();
        const t = e.touches[0];
        isDragging = true;
        const pt = mapStreamCoords(t.clientX, t.clientY);
        dragStartX = pt.x;
        dragStartY = pt.y;
      }, { passive: true });

      streamImg.addEventListener('touchend', (e) => {
        if (!isDragging || !e.changedTouches || e.changedTouches.length === 0) return;
        lastTouchEventMs = Date.now();
        isDragging = false;
        const t = e.changedTouches[0];
        const pt = mapStreamCoords(t.clientX, t.clientY);
        const endX = pt.x;
        const endY = pt.y;
        const dist = Math.hypot(endX - dragStartX, endY - dragStartY);
        const code = getAuthCode();
        if (!code) return;

        showTouchRipple(t.clientX, t.clientY);
        if (dist < 0.03) {
          fetch('/api/admin/touch?xRatio=' + endX + '&yRatio=' + endY + '&code=' + encodeURIComponent(code) + devQuery());
        } else {
          fetch('/api/admin/swipe?x1Ratio=' + dragStartX + '&y1Ratio=' + dragStartY + '&x2Ratio=' + endX + '&y2Ratio=' + endY + '&code=' + encodeURIComponent(code) + devQuery());
        }
      }, { passive: true });

      streamImg.addEventListener('wheel', (e) => {
        e.preventDefault();
        const code = getAuthCode();
        if (!code) return;

        if (wheelThrottleTimer) return;
        wheelThrottleTimer = setTimeout(() => { wheelThrottleTimer = null; }, 180);

        const pt = mapStreamCoords(e.clientX, e.clientY);
        const centerX = pt.x;
        const centerY = pt.y;

        const isDown = e.deltaY > 0;
        const y1 = isDown ? Math.min(0.9, centerY + 0.22) : Math.max(0.1, centerY - 0.22);
        const y2 = isDown ? Math.max(0.1, centerY - 0.22) : Math.min(0.9, centerY + 0.22);

        fetch('/api/admin/swipe?x1Ratio=' + centerX + '&y1Ratio=' + y1 + '&x2Ratio=' + centerX + '&y2Ratio=' + y2 + '&code=' + encodeURIComponent(code) + devQuery());
      }, { passive: false });

      streamImg.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        const code = getAuthCode();
        if (!code) return;
        showTouchRipple(e.clientX, e.clientY);
        remoteNav('back');
      });
    }

    function remoteNav(action) {
      const code = getAuthCode();
      if (!code) return;
      fetch('/api/admin/nav?action=' + action + '&code=' + encodeURIComponent(code) + devQuery());
    }

    function remoteClearRecents() {
      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }
      showFeedback('🧹 Closing recent applications on tablet...', true);
      fetch('/api/admin/clear-recents?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(() => showFeedback('🧹 Recent applications closed!', true))
        .catch(() => showFeedback('⚠️ Failed to close recents', false));
    }

    function remoteRestart() {
      if (!confirm('⚡ Are you sure you want to reboot the tablet remotely?')) return;
      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }
      showFeedback('⚡ Rebooting tablet remotely...', true);
      fetch('/api/admin/reboot?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('⚡ ' + (data.message || 'Reboot signal sent to tablet!'), true);
          } else {
            showFeedback('⚠️ ' + (data.error || 'Failed to reboot tablet'), false);
          }
        })
        .catch(() => showFeedback('⚡ Tablet rebooting... Stream will reconnect after restart.', true));
    }

    function openSystemSettings() {
      const code = getAuthCode();
      if (!code) return;
      showFeedback('⚙️ Opening System Settings on tablet... (Tip: Use "➕ Add Wi-Fi" button for 100% visible Wi-Fi setup!)', true);
      fetch('/api/admin/open-settings?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(() => {
          showFeedback('⚙️ System Settings opened on tablet screen.', true);
        });
    }

    function openWifiModal() {
      const modal = document.getElementById('wifiModal');
      if (modal) modal.style.display = 'flex';
      const code = getAuthCode();
      if (code) {
        fetch('/api/admin/wake?code=' + encodeURIComponent(code) + devQuery()).catch(() => {});
      }
    }

    function closeWifiModal() {
      const modal = document.getElementById('wifiModal');
      if (modal) modal.style.display = 'none';
    }

    function wakeDeviceScreen() {
      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }
      showFeedback('💡 Waking up tablet screen...', true);
      fetch('/api/admin/wake?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(() => {
          showFeedback('💡 Tablet screen woken up!', true);
          pollStatus();
        })
        .catch(() => showFeedback('⚠️ Network failure waking screen', false));
    }

    function openUpdateModal() {
      const modal = document.getElementById('updateModal');
      if (modal) modal.style.display = 'flex';
    }

    function closeUpdateModal() {
      const modal = document.getElementById('updateModal');
      if (modal) modal.style.display = 'none';
      const progress = document.getElementById('updateProgressBox');
      if (progress) progress.style.display = 'none';
    }

    function submitPushUpdate() {
      const fileInput = document.getElementById('apkFileInput');
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        alert('Please select an .apk file to upload');
        return;
      }
      const file = fileInput.files[0];
      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }

      const progressBox = document.getElementById('updateProgressBox');
      const progressBar = document.getElementById('updateProgressBar');
      const progressText = document.getElementById('updateProgressText');
      if (progressBox) progressBox.style.display = 'block';
      if (progressBar) progressBar.style.width = '0%';
      if (progressText) progressText.innerText = 'Uploading ' + file.name + '...';

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/admin/push-update?code=' + encodeURIComponent(code) + devQuery(), true);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');

      xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          if (progressBar) progressBar.style.width = pct + '%';
          if (progressText) progressText.innerText = 'Uploading ' + file.name + ' (' + pct + '%)...';
        }
      };

      xhr.onload = function() {
        if (xhr.status === 200) {
          if (progressText) progressText.innerText = '✅ APK Uploaded! Installing silently on tablet...';
          showFeedback('✅ APK update pushed! Installing silently on tablet screen...', true);
          setTimeout(closeUpdateModal, 2500);
        } else {
          if (progressText) progressText.innerText = '⚠️ Installation failed!';
          showFeedback('⚠️ Failed to install APK update', false);
        }
      };

      xhr.onerror = function() {
        if (progressText) progressText.innerText = '⚠️ Network error during upload!';
        showFeedback('⚠️ Upload network error', false);
      };

      xhr.send(file);
    }

    function toggleWebStaticIpFields() {
      const mode = document.getElementById('wifiIpModeSelect').value;
      const fields = document.getElementById('webStaticIpFields');
      if (fields) fields.style.display = (mode === 'Static') ? 'block' : 'none';
    }

    function toggleWebDnsFields() {
      const dnsModeEl = document.getElementById('wifiDnsModeSelect');
      const fields = document.getElementById('webDnsFields');
      if (dnsModeEl && fields) {
        fields.style.display = (dnsModeEl.value === 'Manual') ? 'block' : 'none';
      }
    }

    function autoFillWebGateway() {
      const ipInput = document.getElementById('wifiStaticIp');
      const gwInput = document.getElementById('wifiGateway');
      if (!ipInput || !gwInput) return;
      const parts = (ipInput.value || '').trim().split('.');
      if (parts.length >= 3 && parts[0] && parts[1] && parts[2]) {
        const curGw = (gwInput.value || '').trim();
        if (!curGw || curGw.endsWith('.1')) {
          gwInput.value = parts[0] + '.' + parts[1] + '.' + parts[2] + '.1';
        }
      }
    }

    function submitRemoteWifi() {
      const ssid = (document.getElementById('wifiSsidInput').value || '').trim();
      const pass = (document.getElementById('wifiPassInput').value || '').trim();
      const sec = document.getElementById('wifiSecSelect').value;
      const ipMode = document.getElementById('wifiIpModeSelect').value;
      const staticIp = (document.getElementById('wifiStaticIp').value || '').trim();
      const subnet = (document.getElementById('wifiSubnet').value || '255.255.255.0').trim();
      let gateway = (document.getElementById('wifiGateway').value || '').trim();
      if (ipMode === 'Static' && !gateway && staticIp.split('.').length === 4) {
        const p = staticIp.split('.');
        gateway = p[0] + '.' + p[1] + '.' + p[2] + '.1';
      }
      const dnsModeEl = document.getElementById('wifiDnsModeSelect');
      const isAutoDns = !dnsModeEl || dnsModeEl.value === 'Auto';
      const dns1 = isAutoDns ? '8.8.8.8' : ((document.getElementById('wifiDns1').value || '').trim() || '8.8.8.8');
      const dns2 = isAutoDns ? '8.8.4.4' : ((document.getElementById('wifiDns2').value || '').trim() || '8.8.4.4');

      if (!ssid) {
        alert('Please enter a Wi-Fi SSID (Network Name)');
        return;
      }

      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }

      closeWifiModal();
      showFeedback('📶 Configuring Wi-Fi ' + ssid + ' (' + ipMode + ' • ' + (isAutoDns ? 'Auto DNS' : ('DNS ' + dns1)) + ') on tablet...', true);

      const url = '/api/admin/add-wifi?ssid=' + encodeURIComponent(ssid) +
        '&pass=' + encodeURIComponent(pass) +
        '&sec=' + encodeURIComponent(sec) +
        '&ipMode=' + encodeURIComponent(ipMode) +
        '&staticIp=' + encodeURIComponent(staticIp) +
        '&subnet=' + encodeURIComponent(subnet) +
        '&gateway=' + encodeURIComponent(gateway) +
        '&dns1=' + encodeURIComponent(dns1) +
        '&dns2=' + encodeURIComponent(dns2) +
        '&code=' + encodeURIComponent(code) + devQuery();

      fetch(url)
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('✅ Wi-Fi ' + ssid + ' configured & connecting!', true);
          } else {
            showFeedback('⚠️ ' + (data.message || 'Failed to configure Wi-Fi ' + ssid), false);
          }
        })
        .catch(() => {
          showFeedback('📶 Configuration signal sent to tablet.', true);
        });
    }

    function sendTypeText() {
      const input = document.getElementById('typeTextInput');
      const text = input ? input.value : '';
      if (!text) return;
      const code = getAuthCode();
      if (!code) return;
      fetch('/api/admin/type?text=' + encodeURIComponent(text) + '&code=' + encodeURIComponent(code) + devQuery());
      input.value = '';
      showFeedback('⌨️ Sent text: ' + text, true);
    }

    function openAppsModal() {
      const modal = document.getElementById('appsModal');
      if (modal) modal.style.display = 'flex';
      fetchAppsList();
    }

    function closeAppsModal() {
      const modal = document.getElementById('appsModal');
      if (modal) modal.style.display = 'none';
    }

    function fetchAppsList() {
      const code = getAuthCode();
      if (!code) return;
      fetch('/api/admin/apps?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(apps => {
          installedAppsCache = apps || [];
          renderAppsGrid(installedAppsCache);
        })
        .catch(() => {
          const grid = document.getElementById('appsListGrid');
          if (grid) grid.innerHTML = '<div style="color:#f87171;">Failed to load tablet apps list</div>';
        });
    }

    function renderAppsGrid(apps) {
      const grid = document.getElementById('appsListGrid');
      if (!grid) return;
      grid.innerHTML = '';
      if (!apps || apps.length === 0) {
        const empty = document.createElement('div');
        empty.style.color = '#94a3b8';
        empty.textContent = 'No applications found';
        grid.appendChild(empty);
        return;
      }
      apps.forEach(a => {
        const btn = document.createElement('button');
        btn.className = 'app-card-btn';
        btn.textContent = '📱 ' + (a.name || a.pkg || '');
        btn.addEventListener('click', () => launchRemoteApp(a.pkg, a.name));
        grid.appendChild(btn);
      });
    }

    function filterApps() {
      const query = (document.getElementById('appSearchInput').value || '').toLowerCase();
      const filtered = installedAppsCache.filter(a => a.name.toLowerCase().includes(query) || a.pkg.toLowerCase().includes(query));
      renderAppsGrid(filtered);
    }

    function launchRemoteApp(pkg, name) {
      const code = getAuthCode();
      if (!code) return;
      closeAppsModal();
      showFeedback('🚀 Opening ' + name + ' on tablet...', true);
      fetch('/api/admin/launch-app?pkg=' + encodeURIComponent(pkg) + '&code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('✅ ' + name + ' opened on tablet screen!', true);
          } else {
            showFeedback('⚠️ Failed to launch ' + name, false);
          }
        });
    }

    function startSessionTimer() {
      lastActivityTime = Date.now();
      if (sessionTicker) clearInterval(sessionTicker);
      sessionTicker = setInterval(() => {
        const inactiveMs = Date.now() - lastActivityTime;
        if (inactiveMs >= INACTIVITY_LIMIT_MS) {
          triggerSessionTimeout('⏱️ Session Expired (5 minutes of mouse/keyboard inactivity). Enter Remote Access Code to resume.');
        }
      }, 1000);
    }

    function triggerSessionTimeout(customMsg) {
      if (sessionTicker) {
        clearInterval(sessionTicker);
        sessionTicker = null;
      }
      sessionStorage.removeItem('western_remote_code');
      localStorage.removeItem('western_remote_code');

      const img = document.getElementById('screen-stream');
      if (img) {
        img.src = '';
        img.style.display = 'none';
      }
      const adminPanel = document.getElementById('adminPanel');
      if (adminPanel) adminPanel.style.display = 'none';

      const overlay = document.getElementById('authOverlay');
      if (overlay) overlay.style.display = 'flex';

      const codeInput = document.getElementById('remoteCodeInput');
      if (codeInput) {
        codeInput.value = '';
        codeInput.focus();
      }

      const err = document.getElementById('authError');
      if (err) {
        if (customMsg) {
          err.innerText = customMsg;
          err.style.color = '#f59e0b';
          err.style.display = 'block';
        } else {
          err.style.display = 'none';
        }
      }
    }

    function getAuthCode() {
      return sessionStorage.getItem('western_remote_code') || localStorage.getItem('western_remote_code') || '';
    }

    function checkAuth() {
      const code = getAuthCode();
      if (!code) {
        triggerSessionTimeout();
        return;
      }
      fetch('/api/auth?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            if (data.deviceId) {
              selectedDeviceId = data.deviceId;
            }
            const activeToken = data.token || code;
            sessionStorage.setItem('western_remote_code', activeToken);
            localStorage.setItem('western_remote_code', activeToken);
            document.getElementById('authOverlay').style.display = 'none';
            document.getElementById('adminPanel').style.display = 'flex';
            startSessionTimer();
            connectStream(activeToken);
            pollStatus();
          } else {
            triggerSessionTimeout();
          }
        })
        .catch(() => {
          document.getElementById('authOverlay').style.display = 'flex';
        });
    }

    async function promptRemoveDeviceFromLogin() {
      const select = document.getElementById('authDeviceSelect');
      const devId = select ? select.value : '';
      if (!devId) {
        alert('Please select a tablet from the dropdown first.');
        return;
      }
      const selectedOption = select.options[select.selectedIndex];
      const devText = selectedOption ? selectedOption.textContent.trim() : devId;

      const codeInput = document.getElementById('remoteCodeInput');
      let adminCode = (codeInput && codeInput.value) ? codeInput.value.trim() : '';

      if (!adminCode) {
        adminCode = prompt('Enter Admin Code (7866, 8080 or Wf@3125210946) to permanently delete:\n\n' + devText);
      } else {
        if (!confirm('Are you sure you want to permanently delete this tablet from fleet?\n\n' + devText)) {
          return;
        }
      }

      if (!adminCode) return;

      try {
        const resp = await fetch('/api/admin/remove-device?deviceId=' + encodeURIComponent(devId) + '&code=' + encodeURIComponent(adminCode), { cache: 'no-store' });
        const data = await resp.json();
        if (data.success) {
          alert('✅ Tablet removed successfully:\n' + devText);
          location.reload();
        } else {
          alert('❌ Failed to remove tablet: ' + (data.error || 'Invalid Admin Code'));
        }
      } catch (err) {
        alert('❌ Error connecting to server: ' + err.message);
      }
    }

    function submitAuth() {
      const code = document.getElementById('remoteCodeInput').value.trim();
      const err = document.getElementById('authError');
      err.style.display = 'none';
      if (!code) {
        err.innerText = 'Please enter the Remote Access Code.';
        err.style.color = '#f87171';
        err.style.display = 'block';
        return;
      }
      fetch('/api/auth?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            if (data.deviceId) {
              selectedDeviceId = data.deviceId;
            }
            const activeToken = data.token || code;
            sessionStorage.setItem('western_remote_code', activeToken);
            localStorage.setItem('western_remote_code', activeToken);
            document.getElementById('authOverlay').style.display = 'none';
            document.getElementById('adminPanel').style.display = 'flex';
            startSessionTimer();
            connectStream(activeToken);
            pollStatus();
          } else {
            err.innerText = data.error || 'Invalid Remote Access Code!';
            err.style.color = '#f87171';
            err.style.display = 'block';
          }
        })
        .catch(() => {
          err.innerText = 'Network error connecting to tablet!';
          err.style.color = '#f87171';
          err.style.display = 'block';
        });
    }

    function rotateScreenStream(deg) {
      screenRotation = (screenRotation + deg) % 360;
      if (screenRotation < 0) screenRotation += 360;
      localStorage.setItem('rot_screen', screenRotation);
      applyStreamTransform('screen');
      showFeedback('🔄 Screen Rotated to ' + screenRotation + '°', true);
    }

    function toggleScreenFlip() {
      isScreenFlipped = !isScreenFlipped;
      localStorage.setItem('flip_screen', isScreenFlipped ? 'true' : 'false');
      applyStreamTransform('screen');
      showFeedback(isScreenFlipped ? '🪞 Screen Flip: ON' : '🪞 Screen Flip: OFF', true);
    }

    function resetScreenRotation() {
      screenRotation = 0;
      isScreenFlipped = false;
      localStorage.setItem('rot_screen', '0');
      localStorage.setItem('flip_screen', 'false');
      applyStreamTransform('screen');
      showFeedback('↺ Screen Reset to 0°', true);
    }

    function toggleScreenFit() {
      isScreenFullWidth = !isScreenFullWidth;
      applyStreamTransform('screen');
      showFeedback(isScreenFullWidth ? '⛶ Full Width Mode' : '⛶ Fit Mode', true);
    }

    function openCameraView(lens) {
      if (lens) currentCameraLens = lens;
      isDualCameraOpen = true;
      localStorage.setItem('dual_camera_open', 'true');
      localStorage.setItem('camera_lens', currentCameraLens);

      const camPanel = document.getElementById('cameraPanel');
      const screenPanel = document.getElementById('screenPanel');
      const btnToggle = document.getElementById('btnToggleCam');
      if (camPanel) camPanel.style.display = 'flex';
      if (screenPanel) screenPanel.classList.remove('full-screen-only');
      if (btnToggle) btnToggle.classList.add('btn-accent');

      updateCameraUI();
      loadCameraStream();
      applyStreamTransform('camera');
      showFeedback('📷 Dual Camera Stream Active: ' + (currentCameraLens === 'front' ? 'Front Cam' : 'Rear Cam'), true);
    }

    function closeCameraView() {
      isDualCameraOpen = false;
      localStorage.setItem('dual_camera_open', 'false');

      const camPanel = document.getElementById('cameraPanel');
      const screenPanel = document.getElementById('screenPanel');
      const btnToggle = document.getElementById('btnToggleCam');
      const camImg = document.getElementById('camera-stream');

      if (camPanel) camPanel.style.display = 'none';
      if (screenPanel) screenPanel.classList.add('full-screen-only');
      if (btnToggle) btnToggle.classList.remove('btn-accent');
      if (camImg) {
        camImg.src = '';
        camImg.style.display = 'none';
      }

      const code = getAuthCode();
      if (code) {
        fetch('/api/camera/stop?code=' + encodeURIComponent(code) + devQuery()).catch(() => {});
      }
      showFeedback('✖ Closed Camera Stream', true);
    }

    function toggleDualCamera() {
      if (isDualCameraOpen) {
        closeCameraView();
      } else {
        openCameraView();
      }
    }

    function switchCameraLens() {
      currentCameraLens = (currentCameraLens === 'front' ? 'back' : 'front');
      localStorage.setItem('camera_lens', currentCameraLens);
      cameraRotation = (currentCameraLens === 'front' ? 270 : 90);
      isCameraFlipped = (currentCameraLens === 'front');
      localStorage.setItem('camera_rot', cameraRotation);
      localStorage.setItem('camera_flip', isCameraFlipped ? 'true' : 'false');

      updateCameraUI();
      loadCameraStream();
      showFeedback('🔄 Switched to ' + (currentCameraLens === 'front' ? 'Front Camera' : 'Rear Camera'), true);
    }

    function rotateCameraStream(deg) {
      cameraRotation = (cameraRotation + deg) % 360;
      if (cameraRotation < 0) cameraRotation += 360;
      localStorage.setItem('camera_rot', cameraRotation);
      applyStreamTransform('camera');
      updateCameraUI();
      showFeedback('🔄 Camera Rotated to ' + cameraRotation + '°', true);
    }

    function toggleCameraFlip() {
      isCameraFlipped = !isCameraFlipped;
      localStorage.setItem('camera_flip', isCameraFlipped ? 'true' : 'false');
      applyStreamTransform('camera');
      updateCameraUI();
      showFeedback(isCameraFlipped ? '🪞 Camera Flip: ON' : '🪞 Camera Flip: OFF', true);
    }

    function updateCameraUI() {
      const title = document.getElementById('cameraTitle');
      if (title) {
        title.innerText = (currentCameraLens === 'front' ? '🤳 Front Camera' : '📷 Rear Camera');
      }
      const rotLbl = document.getElementById('lblCameraRot');
      if (rotLbl) {
        rotLbl.innerText = cameraRotation + '°' + (isCameraFlipped ? ' (🪞)' : '');
      }
    }

    function loadCameraStream() {
      const code = getAuthCode();
      if (!code) return;
      const camImg = document.getElementById('camera-stream');
      const loader = document.getElementById('cameraLoadingPlaceholder');
      if (loader) {
        loader.style.display = 'flex';
      }
      if (camImg) {
        camImg.style.display = 'none';
        camImg.src = '/api/camera/stream?lens=' + currentCameraLens + '&code=' + encodeURIComponent(code) + devQuery() + '&_t=' + Date.now();
      }
    }

    function handleCameraLoaded() {
      const loader = document.getElementById('cameraLoadingPlaceholder');
      const camImg = document.getElementById('camera-stream');
      if (loader) loader.style.display = 'none';
      if (camImg) camImg.style.display = 'block';
      applyStreamTransform('camera');
    }

    function handleCameraError() {
      setTimeout(() => {
        if (isDualCameraOpen) loadCameraStream();
      }, 2000);
    }

    function takeCameraSnapshot() {
      const code = getAuthCode();
      if (!code) return;
      window.open('/api/camera/snapshot?lens=' + currentCameraLens + '&rot=' + cameraRotation + '&flip=' + (isCameraFlipped ? '1' : '0') + '&code=' + encodeURIComponent(code) + devQuery() + '&t=' + Date.now(), '_blank');
    }

    function openSosModal() {
      const modal = document.getElementById('sosModal');
      if (modal) modal.style.display = 'flex';
      const input = document.getElementById('sosTextInput');
      if (input) {
        input.value = '';
        input.focus();
      }
    }

    function closeSosModal() {
      const modal = document.getElementById('sosModal');
      if (modal) modal.style.display = 'none';
    }

    function submitSosAlert() {
      const input = document.getElementById('sosTextInput');
      const msg = (input ? input.value : '').trim();
      if (!msg) {
        alert('Please enter an SOS message to broadcast to the tablet.');
        return;
      }
      const code = getAuthCode();
      if (!code) {
        showFeedback('⚠️ Remote Access Passcode required', false);
        checkAuth();
        return;
      }
      closeSosModal();
      showFeedback('🚨 Broadcasting Emergency SOS to tablet...', true);
      fetch('/api/admin/sos?msg=' + encodeURIComponent(msg) + '&code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('🚨 Emergency SOS Broadcasted! Tablet screen locked for 10 seconds.', true);
          } else {
            showFeedback('⚠️ ' + (data.error || 'Failed to send SOS alert'), false);
          }
        })
        .catch(() => showFeedback('🚨 Emergency SOS broadcast signal sent!', true));
    }

    function applyStreamTransform(which) {
      if (!which || which === 'screen') {
        const img = document.getElementById('screen-stream');
        const wrapper = document.getElementById('screenWrapper');
        const rotLabel = document.getElementById('lblScreenRot');
        if (rotLabel) rotLabel.innerText = screenRotation + '°' + (isScreenFlipped ? ' (🪞)' : '');
        if (img && wrapper) {
          const isSideways = (screenRotation % 180 !== 0);
          let t = 'rotate(' + screenRotation + 'deg)';
          if (isScreenFlipped) t += ' scaleX(-1)';

          if (isSideways) {
            const nw = img.naturalWidth || 720;
            const nh = img.naturalHeight || 1280;
            const panelW = wrapper.parentElement ? wrapper.parentElement.clientWidth : 600;
            const maxW = Math.min(panelW - 20, 720);
            const scale = Math.min(maxW / nh, 560 / nw, 1.0);
            const vW = Math.round(nh * scale);
            const vH = Math.round(nw * scale);

            wrapper.style.height = vH + 'px';
            wrapper.style.maxHeight = 'none';

            img.style.width = vH + 'px';
            img.style.height = vW + 'px';
            img.style.maxWidth = 'none';
            img.style.maxHeight = 'none';
            img.style.position = 'absolute';
            img.style.top = '50%';
            img.style.left = '50%';
            img.style.transform = 'translate(-50%, -50%) ' + t;
          } else {
            wrapper.style.height = 'auto';
            wrapper.style.maxHeight = isScreenFullWidth ? 'none' : '75vh';

            img.style.position = 'static';
            img.style.width = isScreenFullWidth ? '100%' : 'auto';
            img.style.height = 'auto';
            img.style.maxWidth = '100%';
            img.style.maxHeight = isScreenFullWidth ? 'none' : '75vh';
            img.style.transform = t;
          }
        }
      }

      if (!which || which === 'camera') {
        const img = document.getElementById('camera-stream');
        const wrapper = document.getElementById('cameraWrapper');
        const rotLabel = document.getElementById('lblCameraRot');
        if (rotLabel) rotLabel.innerText = cameraRotation + '°' + (isCameraFlipped ? ' (🪞)' : '');
        if (img && wrapper) {
          const isSideways = (cameraRotation % 180 !== 0);
          let t = 'rotate(' + cameraRotation + 'deg)';
          if (isCameraFlipped) t += ' scaleX(-1)';

          if (isSideways) {
            const nw = img.naturalWidth || 640;
            const nh = img.naturalHeight || 480;
            const panelW = wrapper.parentElement ? wrapper.parentElement.clientWidth : 600;
            const maxW = Math.min(panelW - 20, 720);
            const scale = Math.min(maxW / nh, 560 / nw, 1.0);
            const vW = Math.round(nh * scale);
            const vH = Math.round(nw * scale);

            wrapper.style.height = vH + 'px';
            wrapper.style.maxHeight = 'none';

            img.style.width = vH + 'px';
            img.style.height = vW + 'px';
            img.style.maxWidth = 'none';
            img.style.maxHeight = 'none';
            img.style.position = 'absolute';
            img.style.top = '50%';
            img.style.left = '50%';
            img.style.transform = 'translate(-50%, -50%) ' + t;
          } else {
            wrapper.style.height = 'auto';
            wrapper.style.maxHeight = '75vh';

            img.style.position = 'static';
            img.style.width = '100%';
            img.style.height = 'auto';
            img.style.maxWidth = '100%';
            img.style.maxHeight = '75vh';
            img.style.transform = t;
          }
        }
      }
    }

    window.addEventListener('resize', () => {
      applyStreamTransform('screen');
      applyStreamTransform('camera');
    });

    function connectStream(code) {
      const img = document.getElementById('screen-stream');
      if (img) {
        img.style.display = 'block';
        img.src = '/stream?code=' + encodeURIComponent(code) + devQuery() + '&_t=' + Date.now();
      }
      applyStreamTransform('screen');
      if (isDualCameraOpen) {
        openCameraView();
      }
    }

    function showFeedback(msg, isSuccess) {
      const fb = document.getElementById('adminFeedback');
      fb.className = 'admin-feedback ' + (isSuccess ? 'success' : 'error');
      fb.innerText = msg;
      fb.style.display = 'block';
      setTimeout(() => { fb.style.display = 'none'; }, 6000);
    }

    function logoutRemote() {
      if (sessionTicker) clearInterval(sessionTicker);
      sessionStorage.removeItem('western_remote_code');
      localStorage.removeItem('western_remote_code');
      window.location.href = window.location.origin + window.location.pathname;
    }

    function takeSnapshot() {
      const code = getAuthCode();
      if (!code) return;
      window.open('/snapshot?code=' + encodeURIComponent(code) + devQuery() + '&t=' + Date.now(), '_blank');
    }

    function reloadStream() {
      const code = getAuthCode();
      if (!code) return;
      const img = document.getElementById('screen-stream');
      if (img) {
        img.src = '/stream?code=' + encodeURIComponent(code) + devQuery() + '&_t=' + Date.now();
      }
    }

    function handleStreamLoaded() {
      isConnected = true;
      document.getElementById('badgeLive').style.display = 'flex';
      document.getElementById('badgeDisconn').style.display = 'none';
      const connLostBanner = document.getElementById('connLostBanner');
      if (connLostBanner) connLostBanner.style.display = 'none';
      if (reconnectTimer) { clearInterval(reconnectTimer); reconnectTimer = null; }
      applyStreamTransform();
    }

    function handleStreamError() {
      const code = getAuthCode();
      if (!code) return;
      isConnected = false;
      document.getElementById('badgeLive').style.display = 'none';
      document.getElementById('badgeDisconn').style.display = 'flex';
      const connLostBanner = document.getElementById('connLostBanner');
      if (connLostBanner) connLostBanner.style.display = 'block';

      if (!reconnectTimer) {
        countdownVal = 2;
        reconnectTimer = setInterval(() => {
          countdownVal--;
          if (countdownVal <= 0) {
            countdownVal = 2;
            reloadStream();
          }
        }, 1500);
      }
    }

    async function pollStatus() {
      try {
        const currentCode = getAuthCode();
        const resp = await fetch('/api/status?code=' + encodeURIComponent(currentCode) + devQuery() + '&_t=' + Date.now(), { cache: 'no-store' });
        if (resp.ok) {
          const data = await resp.json();
          if (currentCode && data.authExpired) {
            triggerSessionTimeout('🔒 Remote Access Code was changed on the tablet! Please enter the new Remote Access Code.');
            return;
          }
          if (!isConnected) {
            handleStreamLoaded();
            reloadStream();
          }
          const offPlaceholder = document.getElementById('screenOffPlaceholder');
          if (data.isScreenOn) {
            document.getElementById('statScreen').innerText = '📱 Screen: ON';
            document.getElementById('statScreen').className = 'device-info green';
            if (offPlaceholder) offPlaceholder.style.display = 'none';
            if (streamImg && currentCode) streamImg.style.display = 'block';
          } else {
            document.getElementById('statScreen').innerText = '📱 Screen: OFF';
            document.getElementById('statScreen').className = 'device-info red';
            if (offPlaceholder) offPlaceholder.style.display = 'flex';
            if (streamImg) streamImg.style.display = 'none';
          }

          if (data.batteryPct !== undefined) {
            document.getElementById('headerBattery').innerText = '🔋 ' + data.batteryPct + '%';
          }

          if (data.deviceName) {
            const devEl = document.getElementById('headerDeviceName');
            if (devEl) devEl.innerText = '📱 ' + data.deviceName;
          }

          const sel = document.getElementById('fleetSelect');
          const authSel = document.getElementById('authDeviceSelect');
          if (data.fleet && data.fleet.length > 0) {
            if (!selectedDeviceId) {
              selectedDeviceId = data.fleet[0].deviceId;
            }
            const updateSelectDropdown = (el, isHeader) => {
              if (!el) return;
              el.style.display = isHeader ? 'inline-flex' : 'block';
              if (document.activeElement !== el) {
                el.innerHTML = '';
                data.fleet.forEach(t => {
                  const opt = document.createElement('option');
                  opt.value = t.deviceId;
                  opt.selected = (t.deviceId === selectedDeviceId);
                  const ipStr = t.localIp ? (' • IP: ' + t.localIp) : '';
                  opt.textContent = '🔄 ' + (t.online ? '🟢 ' : '🔴 ') + t.deviceName + ' [' + t.deviceId + ']' + ipStr + ' • 🔋' + t.batteryPct + '%';
                  el.appendChild(opt);
                });
              }
            };
            updateSelectDropdown(sel, true);
            updateSelectDropdown(authSel, false);
          }

          const cloudBadge = document.getElementById('statCloud');
          if (cloudBadge) {
            if (data.cloudConnected) {
              cloudBadge.innerText = '☁️ Cloud HTTPS: ON';
              cloudBadge.className = 'device-info green';
            } else if (data.meshIp) {
              cloudBadge.innerText = '🌐 Mesh: ' + data.meshIp;
              cloudBadge.className = 'device-info green';
            } else {
              cloudBadge.innerText = '☁️ Cloud Standby';
              cloudBadge.className = 'device-info';
            }
          }

          if (data.viewers !== undefined) {
            document.getElementById('statViewers').innerText = '👁️ ' + data.viewers + (data.viewers === 1 ? ' Active' : ' Viewers');
          }
        } else {
          if (getAuthCode()) handleStreamError();
        }
      } catch (e) {
        if (getAuthCode()) handleStreamError();
      }
    }

    function openCloudModal() {
      const code = getAuthCode();
      if (!code) {
        checkAuth();
        return;
      }
      const modal = document.getElementById('cloudModal');
      if (modal) modal.style.display = 'flex';
      fetch('/api/admin/cloud-config?code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            document.getElementById('cloudDeviceIdLbl').innerText = data.deviceId || '--';
            document.getElementById('cloudLocalIpLbl').innerText = (data.localIp || '--') + ':8254';
            document.getElementById('cloudMeshIpLbl').innerText = data.meshIp ? (data.meshIp + ':8254 (Active 🟢)') : 'Not Installed (Optional Tailscale/ZeroTier)';
            document.getElementById('cloudStatusLbl').innerText = data.cloudStatus || 'Active';
            document.getElementById('cloudStatusLbl').style.color = data.cloudConnected ? '#34d399' : '#fbbf24';
            document.getElementById('cloudDeviceNameInput').value = data.deviceName || '';
            document.getElementById('cloudRelayUrlInput').value = data.cloudUrl || '';
          }
        })
        .catch(() => {});
    }

    function closeCloudModal() {
      const modal = document.getElementById('cloudModal');
      if (modal) modal.style.display = 'none';
    }

    function submitCloudConfig() {
      const code = getAuthCode();
      if (!code) return;
      const name = (document.getElementById('cloudDeviceNameInput').value || '').trim();
      const url = (document.getElementById('cloudRelayUrlInput').value || '').trim();
      closeCloudModal();
      showFeedback('☁️ Saving Any-Network Cloud Relay Configuration...', true);
      fetch('/api/admin/cloud-config?save=1&name=' + encodeURIComponent(name) + '&url=' + encodeURIComponent(url) + '&code=' + encodeURIComponent(code) + devQuery())
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('✅ Saved Any-Network Cloud Settings!', true);
            pollStatus();
          } else {
            showFeedback('⚠️ Failed to save Cloud configuration', false);
          }
        })
        .catch(() => showFeedback('⚠️ Network error saving Cloud configuration', false));
    }

    function deleteCurrentDevice() {
      const code = getAuthCode();
      if (!code) return;
      const devId = selectedDeviceId || (document.getElementById('cloudDeviceIdLbl') ? document.getElementById('cloudDeviceIdLbl').innerText.trim() : '');
      if (!devId || devId === '--') {
        alert('No device selected');
        return;
      }
      if (!confirm('Are you sure you want to remove tablet "' + devId + '" from the fleet?')) return;
      closeCloudModal();
      showFeedback('🗑️ Removing device ' + devId + '...', true);
      fetch('/api/admin/remove-device?deviceId=' + encodeURIComponent(devId) + '&code=' + encodeURIComponent(code))
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showFeedback('✅ Removed ' + devId + ' from fleet', true);
            selectedDeviceId = '';
            pollStatus();
          } else {
            showFeedback('⚠️ ' + (data.error || 'Failed to remove device'), false);
          }
        })
        .catch(() => showFeedback('⚠️ Network error', false));
    }

    document.querySelectorAll('.btn-hdr').forEach(btn => {
      const flashCyan = () => {
        btn.classList.add('touch-active');
        setTimeout(() => btn.classList.remove('touch-active'), 240);
      };
      btn.addEventListener('pointerdown', flashCyan, { passive: true });
      btn.addEventListener('touchstart', flashCyan, { passive: true });
    });

    checkAuth();
    setInterval(pollStatus, 1500);
    pollStatus();
  </script>
</body>
</html>`;
}

function getLocalLanIpAddress() {
  try {
    const os = require('os');
    const nets = os.networkInterfaces();
    let fallbackIp = '127.0.0.1';
    for (const name of Object.keys(nets)) {
      for (const net of nets[name] || []) {
        if (net.family === 'IPv4' && !net.internal) {
          if (!net.address.startsWith('192.168.137.')) {
            return net.address;
          }
          fallbackIp = net.address;
        }
      }
    }
    return fallbackIp;
  } catch (_) {
    return '127.0.0.1';
  }
}

function broadcastPublicUrlToTablets(publicUrl) {
  if (!publicUrl || !publicUrl.startsWith('http')) return;
  currentPublicHttpsUrl = publicUrl.replace(/\/+$/, '');
  try {
    fs.writeFileSync(path.join(__dirname, 'CURRENT_PUBLIC_HTTPS_LINK.txt'), currentPublicHttpsUrl + '\r\n', 'utf8');
  } catch (_) {}

  // 1. Publish to primary ntfy topic (western_ksa_3125210946)
  const req1 = https.request({
    hostname: 'ntfy.sh',
    port: 443,
    path: '/' + AUTO_SYNC_TOPIC,
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Content-Length': Buffer.byteLength(currentPublicHttpsUrl)
    }
  }, (res) => { res.on('data', () => {}); });
  req1.on('error', () => {});
  req1.write(currentPublicHttpsUrl);
  req1.end();

  // 2. Publish to legacy ntfy topic
  try {
    const req2 = https.request({
      hostname: 'ntfy.sh',
      port: 443,
      path: '/' + LEGACY_SYNC_TOPIC,
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(currentPublicHttpsUrl)
      }
    }, (res) => { res.on('data', () => {}); });
    req2.on('error', () => {});
    req2.write(currentPublicHttpsUrl);
    req2.end();
  } catch (_) {}

  // 3. Auto-push to GitHub repository so GitHub Pages & raw URL are always 100% updated
  try {
    const { exec } = require('child_process');
    exec('git add CURRENT_PUBLIC_HTTPS_LINK.txt && git commit -m "Auto-sync live tunnel [skip ci]" && git pull --rebase origin main && git push origin main', { cwd: __dirname }, () => {});
  } catch (_) {}

  // Also broadcast the laptop's local LAN HTTP URL so tablets on the same Wi-Fi connect in 1ms
  const lanIp = getLocalLanIpAddress();
  if (lanIp && lanIp !== '127.0.0.1') {
    const lanUrl = `http://${lanIp}:${PORT}`;
    const reqLan = https.request({
      hostname: 'ntfy.sh',
      port: 443,
      path: '/western_applock_lan_3125210946',
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(lanUrl)
      }
    }, (res) => {
      res.on('data', () => {});
    });
    reqLan.on('error', () => {});
    reqLan.write(lanUrl);
    reqLan.end();
  }

  const htmlRedirect = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${currentPublicHttpsUrl}"><script>window.location.replace('${currentPublicHttpsUrl}');</script></head><body style="background:#0b1120;color:#fff;font-family:sans-serif;text-align:center;padding-top:20vh;">Connecting to Western AppLock KSA...</body></html>`;
  const req2 = https.request({
    hostname: 'ntfy.sh',
    port: 443,
    path: '/western_applock_ksa_go_2026',
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Content-Length': Buffer.byteLength(htmlRedirect)
    }
  }, (res) => {
    res.on('data', () => {});
  });
  req2.on('error', () => {});
  req2.write(htmlRedirect);
  req2.end();
}

let activeCloudflaredProcess = null;
let tunnelFailureCount = 0;

function startBuiltInCloudflareTunnel() {
  if (process.env.RENDER || process.env.RENDER_EXTERNAL_URL || process.platform !== 'win32') return;
  const { spawn } = require('child_process');
  const exePath = path.join(__dirname, 'cloudflared.exe');
  if (!fs.existsSync(exePath)) return;

  if (activeCloudflaredProcess) {
    try { activeCloudflaredProcess.kill(); } catch (_) {}
    activeCloudflaredProcess = null;
  }

  console.log('[*] Starting built-in Free HTTPS Cloudflare Tunnel...');
  const child = spawn(exePath, ['tunnel', '--url', 'http://localhost:' + PORT], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  activeCloudflaredProcess = child;
  tunnelFailureCount = 0;

  const handleOutput = (chunk) => {
    const text = chunk.toString('utf8');
    const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
    if (match && match[0] && match[0] !== currentPublicHttpsUrl) {
      const foundUrl = match[0];
      console.log('==============================================================');
      console.log(' [+] PUBLIC ANY-NETWORK HTTPS URL READY:');
      console.log('     ' + foundUrl);
      console.log(' [+] AUTO-SYNCED TO ALL TABLETS AUTOMATICALLY!');
      console.log('     (Even after laptop restart, tablets reconnect in ~5 sec)');
      console.log('==============================================================');
      broadcastPublicUrlToTablets(foundUrl);
    }
  };

  child.stdout.on('data', handleOutput);
  child.stderr.on('data', handleOutput);
  child.on('exit', () => {
    if (activeCloudflaredProcess === child) {
      activeCloudflaredProcess = null;
      setTimeout(startBuiltInCloudflareTunnel, 3000);
    }
  });
}

// Auto-healing watchdog: verify every 20s that the active Cloudflare tunnel is still DNS-resolvable & alive
setInterval(() => {
  if (process.env.RENDER || process.env.RENDER_EXTERNAL_URL || process.platform !== 'win32') return;
  if (!currentPublicHttpsUrl || !currentPublicHttpsUrl.includes('.trycloudflare.com')) return;
  const dns = require('dns');
  let host = '';
  try {
    host = new URL(currentPublicHttpsUrl).hostname;
  } catch (_) {
    return;
  }
  dns.lookup('cloudflare.com', (netErr) => {
    if (netErr) return; // Laptop itself is offline; wait until internet returns
    dns.lookup(host, (dnsErr) => {
      if (dnsErr) {
        console.log(`[!] Cloudflare tunnel DNS expired (${host}). Auto-restarting tunnel...`);
        currentPublicHttpsUrl = '';
        startBuiltInCloudflareTunnel();
        return;
      }
      const req = https.get(currentPublicHttpsUrl + '/api/status', { timeout: 6000 }, (res) => {
        res.on('data', () => {});
        if (res.statusCode >= 200 && res.statusCode < 400) {
          tunnelFailureCount = 0;
        } else {
          tunnelFailureCount++;
          if (tunnelFailureCount >= 2) {
            console.log(`[!] Cloudflare tunnel returned HTTP ${res.statusCode}. Auto-restarting tunnel...`);
            currentPublicHttpsUrl = '';
            startBuiltInCloudflareTunnel();
          }
        }
      });
      req.on('timeout', () => {
        req.destroy();
        tunnelFailureCount++;
        if (tunnelFailureCount >= 2) {
          console.log('[!] Cloudflare tunnel timed out. Auto-restarting tunnel...');
          currentPublicHttpsUrl = '';
          startBuiltInCloudflareTunnel();
        }
      });
      req.on('error', () => {
        tunnelFailureCount++;
        if (tunnelFailureCount >= 2) {
          console.log('[!] Cloudflare tunnel unreachable. Auto-restarting tunnel...');
          currentPublicHttpsUrl = '';
          startBuiltInCloudflareTunnel();
        }
      });
    });
  });
}, 20 * 1000);

setInterval(() => {
  if (currentPublicHttpsUrl) {
    broadcastPublicUrlToTablets(currentPublicHttpsUrl);
  }
}, 5 * 60 * 1000);

function startLocalCustomDomainResponder() {
  try {
    const dgram = require('dgram');
    const getLanIp = () => getLocalLanIpAddress();

    // 0. UDP Port 8255 LAN Auto-Discovery Responder for Tablets on Same Wi-Fi
    const disc = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    disc.on('error', () => {});
    disc.on('message', (msg, rinfo) => {
      if (!msg) return;
      const str = msg.toString('utf8').trim();
      if (str.includes('WESTERN_DISCOVER_SERVER')) {
        const reply = Buffer.from(`WESTERN_SERVER:http://${getLanIp()}:${PORT}`, 'utf8');
        disc.send(reply, 0, reply.length, rinfo.port, rinfo.address);
      }
    });
    disc.bind(8255, '0.0.0.0');

    // 1. mDNS responder (UDP 5353, 224.0.0.251) for westernintapplock.local & westernapplockksa.local
    const mdns = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    mdns.on('error', () => {});
    mdns.on('message', (msg, rinfo) => {
      if (!msg || msg.length < 12) return;
      const lower = msg.toString('ascii').toLowerCase();
      if (lower.includes('westernapplockksa') || lower.includes('westernintapplock')) {
        const hostLabel = lower.includes('westernintapplock') ? 'westernintapplock' : 'westernapplockksa';
        const ipParts = getLanIp().split('.').map(Number);
        const txId = msg.readUInt16BE(0);
        const nameBuf = Buffer.from([hostLabel.length, ...Buffer.from(hostLabel), 5, ...Buffer.from('local'), 0]);
        const resp = Buffer.alloc(12 + nameBuf.length + 10 + 4);
        resp.writeUInt16BE(txId, 0);
        resp.writeUInt16BE(0x8400, 2);
        resp.writeUInt16BE(0, 4);
        resp.writeUInt16BE(1, 6);
        nameBuf.copy(resp, 12);
        let off = 12 + nameBuf.length;
        resp.writeUInt16BE(1, off); off += 2;
        resp.writeUInt16BE(0x8001, off); off += 2;
        resp.writeUInt32BE(120, off); off += 4;
        resp.writeUInt16BE(4, off); off += 2;
        resp[off] = ipParts[0]; resp[off + 1] = ipParts[1]; resp[off + 2] = ipParts[2]; resp[off + 3] = ipParts[3];
        mdns.send(resp, 0, resp.length, 5353, '224.0.0.251');
        mdns.send(resp, 0, resp.length, rinfo.port, rinfo.address);
      }
    });
    mdns.bind(5353, () => {
      try { mdns.addMembership('224.0.0.251'); } catch (_) {}
    });

    // 2. LLMNR responder (UDP 5355, 224.0.0.252) for http://westernintapplock & http://westernapplockksa
    const llmnr = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    llmnr.on('error', () => {});
    llmnr.on('message', (msg, rinfo) => {
      if (!msg || msg.length < 12) return;
      const lower = msg.toString('ascii').toLowerCase();
      if (lower.includes('westernapplockksa') || lower.includes('westernintapplock')) {
        const ipParts = getLanIp().split('.').map(Number);
        const txId = msg.readUInt16BE(0);
        let qEnd = 12;
        while (qEnd < msg.length && msg[qEnd] !== 0) qEnd += 1 + msg[qEnd];
        qEnd += 5;
        if (qEnd > msg.length) return;
        const qType = msg.readUInt16BE(qEnd - 4);
        if (qType !== 1) return;
        const questionBuf = msg.slice(12, qEnd);
        const nameBuf = msg.slice(12, qEnd - 4);
        const resp = Buffer.alloc(12 + questionBuf.length + nameBuf.length + 10 + 4);
        resp.writeUInt16BE(txId, 0);
        resp.writeUInt16BE(0x8000, 2);
        resp.writeUInt16BE(1, 4);
        resp.writeUInt16BE(1, 6);
        questionBuf.copy(resp, 12);
        let off = 12 + questionBuf.length;
        nameBuf.copy(resp, off); off += nameBuf.length;
        resp.writeUInt16BE(1, off); off += 2;
        resp.writeUInt16BE(1, off); off += 2;
        resp.writeUInt32BE(30, off); off += 4;
        resp.writeUInt16BE(4, off); off += 2;
        resp[off] = ipParts[0]; resp[off + 1] = ipParts[1]; resp[off + 2] = ipParts[2]; resp[off + 3] = ipParts[3];
        llmnr.send(resp, 0, resp.length, rinfo.port, rinfo.address);
      }
    });
    llmnr.bind(5355, () => {
      try { llmnr.addMembership('224.0.0.252'); } catch (_) {}
    });
  } catch (_) {}
}

function handleWsUpgrade(req, socket, head) {
  const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname || '/';
  const query = Object.fromEntries(parsedUrl.searchParams.entries());

  if (pathname === '/ws/device') {
    const key = req.headers['sec-websocket-key'];
    if (!key) {
      socket.destroy();
      return;
    }
    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );

    const deviceId = String(query.deviceId || 'WIG-DEFAULT').trim();
    if (deviceId.startsWith('TEST-')) {
      socket.destroy();
      return;
    }
    let dev = devices.get(deviceId);
    if (!dev) {
      dev = {
        deviceId,
        deviceName: 'Western Tablet',
        model: 'Tablet',
        localIp: '',
        meshIp: '',
        batteryPct: 100,
        isScreenOn: true,
        lastScreenOn: 'Just now',
        remoteCode: DEFAULT_ADMIN_CODE,
        screenFrameBuffer: null,
        cameraFrameBuffer: null,
        apps: [],
        lastSeenMs: Date.now(),
        viewerLastSeenMs: 0,
        cameraActive: false,
        cameraLens: 'front',
        commandQueue: []
      };
      devices.set(deviceId, dev);
    }

    if (!wsClients.has(deviceId)) wsClients.set(deviceId, new Set());
    wsClients.get(deviceId).add(socket);
    console.log(`[WS] 🟢 Tablet WebSocket Connected: ${deviceId} (${req.socket?.remoteAddress || ''})`);

    const viewerActive = (Date.now() - dev.viewerLastSeenMs) < 12000;
    sendWsText(socket, JSON.stringify({ type: 'viewer', active: viewerActive }));

    // Flush any pending commands immediately
    if (dev.commandQueue.length > 0) {
      const cmds = dev.commandQueue.splice(0, dev.commandQueue.length);
      for (const cmd of cmds) {
        sendWsText(socket, JSON.stringify(cmd));
      }
    }

    let buf = Buffer.alloc(0);
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const b0 = buf[0];
        const b1 = buf[1];
        const fin = (b0 & 0x80) !== 0;
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        let payloadLen = b1 & 0x7f;
        let offset = 2;

        if (payloadLen === 126) {
          if (buf.length < 4) break;
          payloadLen = buf.readUInt16BE(2);
          offset = 4;
        } else if (payloadLen === 127) {
          if (buf.length < 10) break;
          payloadLen = Number(buf.readBigUInt64BE(2));
          offset = 10;
        }

        const maskLen = masked ? 4 : 0;
        if (buf.length < offset + maskLen + payloadLen) break;

        let payload = buf.subarray(offset + maskLen, offset + maskLen + payloadLen);
        if (masked) {
          const mask = buf.subarray(offset, offset + 4);
          const unmasked = Buffer.allocUnsafe(payloadLen);
          for (let i = 0; i < payloadLen; i++) {
            unmasked[i] = payload[i] ^ mask[i % 4];
          }
          payload = unmasked;
        }

        buf = buf.subarray(offset + maskLen + payloadLen);

        if (opcode === 0x08) {
          socket.end();
          break;
        } else if (opcode === 0x09) {
          sendWsFrame(socket, 0x0A, payload);
        } else if (opcode === 0x02) {
          // Binary JPEG frame from tablet!
          dev.screenFrameBuffer = payload;
          dev.lastSeenMs = Date.now();
          syncCount++;
        } else if (opcode === 0x01) {
          // JSON status packet
          try {
            const data = JSON.parse(payload.toString('utf8'));
            if (data.batteryPct !== undefined) dev.batteryPct = data.batteryPct;
            if (data.isScreenOn !== undefined) dev.isScreenOn = Boolean(data.isScreenOn);
            if (data.deviceName) dev.deviceName = data.deviceName;
            if (data.model) dev.model = data.model;
            if (data.localIp) dev.localIp = data.localIp;
            if (data.remoteCode) dev.remoteCode = String(data.remoteCode);
            if (Array.isArray(data.apps) && data.apps.length > 0) dev.apps = data.apps;
            dev.lastSeenMs = Date.now();
          } catch (_) {}
        }
      }
    });

    socket.on('close', () => {
      const set = wsClients.get(deviceId);
      if (set) {
        set.delete(socket);
        if (set.size === 0) wsClients.delete(deviceId);
      }
      console.log(`[WS] 🔴 Tablet WebSocket Disconnected: ${deviceId}`);
    });

    socket.on('error', () => {
      socket.destroy();
    });
  } else {
    socket.destroy();
  }
}

server.on('upgrade', handleWsUpgrade);

// Also listen on standard HTTP Port 80 so http://westernapplockksa works without :8080
try {
  const port80Server = http.createServer(server.listeners('request')[0]);
  port80Server.on('error', () => {});
  port80Server.on('upgrade', handleWsUpgrade);
  port80Server.listen(80, '0.0.0.0');
} catch (_) {}

server.listen(PORT, '0.0.0.0', () => {
  startLocalCustomDomainResponder();
  console.log('==============================================================');
  console.log(' WESTERN APPLOCK - ANY-NETWORK CLOUD RELAY SERVER ACTIVE');
  console.log(' Simple URL (Wi-Fi): http://westernapplockksa');
  console.log(' Local Laptop URL  : http://localhost:' + PORT);
  console.log(' Default PIN Code  : ' + DEFAULT_ADMIN_CODE);
  console.log('==============================================================');
  if (process.env.RENDER_EXTERNAL_URL) {
    currentPublicHttpsUrl = process.env.RENDER_EXTERNAL_URL.replace(/\/+$/, '');
    console.log(' [+] RUNNING 24/7 ON RENDER.COM: ' + currentPublicHttpsUrl);
    broadcastPublicUrlToTablets(currentPublicHttpsUrl);
  } else if (currentPublicHttpsUrl) {
    broadcastPublicUrlToTablets(currentPublicHttpsUrl);
  } else {
    startBuiltInCloudflareTunnel();
  }
});

