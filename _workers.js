/**
 * Personal Drive v5.1.2 - R2 + KV + Durable Object
 * UI: Apple / macOS Sonoma style, refined toolbar layout
 * Security patch v5.1.2: 代码审查全量修复（H1-H4 / M1-M7 / L1-L5 / R1-R8，共约 24 项）
 *   H1 WebDAV PUT 配额与流式写入 / H2 URL 抓取回滚 / H3 分享目录锁 / H4 分享密码限频
 *   M1 登录用户级限频 / M2 Turnstile 配置完整性 / M3 WebDAV GET 净化 / M4 删除锁定子树
 *   M5 chunks 孤儿豁免 / M6 上传计数原子化 / M7 分享 TTL 过期即清
 *   L1 密码无盐迁移 / L2 token 改 Authorization 头 / L3 前端属性转义 / L4 webhook host 校验 / L5 错误脱敏
 * Bindings: R2="DRIVE", KV="STORE", DO="DIR"(可选), Env: DRIVE_PASSWORD
 */

const SESSION_TTL = 86400 * 7;
const APP_VERSION = 'v5.1.2';
const THUMB_PREFIX = '.thumb/';
const VERSIONS_PREFIX = '.versions/';
const BACKUP_PREFIX = '.backup/';
const TRASH_PREFIX = '.trash/';
const TRASH_ROOT = '/' + TRASH_PREFIX;     // 回收站元数据目录
const MAX_VERSIONS = 5;
const MAX_UPLOAD_SIZE = 500 * 1024 * 1024;
const UNZIP_MAX_BYTES = 50 * 1024 * 1024;
const CHUNK_SIZE = 5 * 1024 * 1024;
const CHUNKS_PREFIX = '.chunks/';          // 以点开头，避免与用户目录名冲突（sanitizeName 会去掉前导点）
const UNZIP_MAX_ENTRIES = 1000;            // 解压条目数上限
const UNZIP_MAX_OUT_BYTES = 200 * 1024 * 1024; // 解压后总量上限
const USAGE_DO_NAME = '__usage__';
const DO_ITEMS_MAX = 96 * 1024;            // DO 单值上限 128KiB 的安全余量

// ===== Helpers =====
function json(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' } });
}
function html(body, status) {
  return new Response(body, { status: status || 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
}
function randToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, '0')).join('');
}
function normPath(p) {
  if (!p || p === '/') return '/';
  const parts = p.split('/').filter(Boolean);
  const resolved = [];
  for (const seg of parts) {
    if (seg === '.') continue;
    if (seg === '..') { resolved.pop(); continue; }
    resolved.push(seg);
  }
  return '/' + resolved.join('/') + (resolved.length ? '/' : '');
}
function sanitizeName(name) {
  if (!name) return 'untitled';
  return name.replace(/[\\/:*?"<>|\x00-\x1f]/g, '').replace(/^\.+/, '').substring(0, 200) || 'untitled';
}
function parentOf(p) {
  const parts = p.split('/').filter(Boolean); parts.pop();
  return parts.length === 0 ? '/' : '/' + parts.join('/') + '/';
}
// WebDAV 路径规范化：解析 . / .. ，但保留"目录带尾斜杠、文件不带"的语义（normPath 会强制加尾斜杠，不能用）
function davPathNorm(p) {
  const raw = String(p == null ? '/' : p);
  const isDir = raw.endsWith('/');
  const resolved = [];
  for (const seg of raw.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { resolved.pop(); continue; }
    resolved.push(seg);
  }
  if (!resolved.length) return '/';
  return '/' + resolved.join('/') + (isDir ? '/' : '');
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
}
function xmlEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;', '`': '&#96;' }[c]));
}

// ===== Hardening helpers =====
function safeEqual(a, b) {
  const A = String(a == null ? '' : a), B = String(b == null ? '' : b);
  if (A.length !== B.length) return false;
  let r = 0;
  for (let i = 0; i < A.length; i++) r |= A.charCodeAt(i) ^ B.charCodeAt(i);
  return r === 0;
}
function clampDays(d) {
  const n = parseInt(d, 10);
  if (!isFinite(n) || n <= 0) return 7;
  return Math.min(Math.max(n, 1), 3650);
}
function clampCount(n) {
  const v = parseInt(n, 10);
  if (!isFinite(v) || v <= 0) return 0;
  return Math.min(v, 1000000);
}
function quotaTotal(env) {
  const cfg = Number(CFG.quotaGB);
  if (Number.isFinite(cfg) && cfg > 0) return cfg * 1024 * 1024 * 1024;
  const n = env ? Number(env.DRIVE_QUOTA) : NaN;
  return (Number.isFinite(n) && n > 0) ? n : 10 * 1024 * 1024 * 1024;
}
// 口令加盐（兼容历史无盐记录）
async function hashPassword(pw, salt) { return sha256(salt + ':' + (pw || '')); }
async function verifyPassword(pw, rec) {
  if (!rec) return false;
  if (rec.salt) return safeEqual(await hashPassword(pw, rec.salt), rec.hash);
  return safeEqual(await sha256(pw || ''), rec.hash || '');
}
// R2 对象搬运（复制 + 删除源），用于回收站
async function copyObject(env, fromKey, toKey) {
  try {
    const o = await env.DRIVE.get(fromKey);
    if (!o) return false;
    await env.DRIVE.put(toKey, o.body, { httpMetadata: o.httpMetadata });
    await env.DRIVE.delete(fromKey);
    return true;
  } catch (e) { return false; }
}
// 保留源对象的复制（站内复制/粘贴用）
async function copyObjectKeep(env, fromKey, toKey) {
  try {
    const o = await env.DRIVE.get(fromKey);
    if (!o) return false;
    await env.DRIVE.put(toKey, o.body, { httpMetadata: o.httpMetadata });
    return true;
  } catch (e) { return false; }
}
async function copyThumb(env, fromKey, toKey) {
  try {
    const t = await env.DRIVE.get(THUMB_PREFIX + fromKey);
    if (t) await env.DRIVE.put(THUMB_PREFIX + toKey, t.body, { httpMetadata: t.httpMetadata });
  } catch (e) {}
}
// 备注随文件移动/改名迁移
async function moveNote(env, oldKey, newKey) {
  try {
    const from = 'note:/' + String(oldKey).replace(/^\/+/, '');
    const n = await env.STORE.get(from, 'json');
    if (n != null) {
      await env.STORE.put('note:/' + String(newKey).replace(/^\/+/, ''), JSON.stringify(n));
      await env.STORE.delete(from);
    }
  } catch (e) {}
}

// ===== KV / R2 防爆（配额与放大保护）=====
// 思路：
//  1) 读：热数据加隔离级短 TTL 缓存（令牌 / 目录锁 / webhook / 相册 / 收藏…），
//     isPathLocked 改为基于"目录锁前缀列表"判断，无锁场景几乎零 KV 读；
//  2) 写：日志 / 下载明细 / 每日统计 / 最近访问改为内存缓冲 + 定时合并写，
//     并受"非关键 KV 写预算"限制，避免单请求多次读改写同一热键；
//  3) 增长：秒传索引与版本索引加 TTL，单目录条目数 / KV 值大小 / 备注标签大小设硬上限；
//  4) R2：大文件不留历史版本、分片与回收站定期回收、备份按体积裁剪、cron 做孤儿清理与用量校准。
function numEnv(env, name, def, allowZero) {
  const n = (env && env[name] != null) ? Number(env[name]) : NaN;
  if (!Number.isFinite(n)) return def;
  if (n > 0) return n;
  return allowZero && n === 0 ? 0 : def;
}
// ===== 站点配置（KV 覆盖 > 环境变量 > 默认值）=====
// 通过网页改配置，无需重新部署；隔离级 30 秒缓存，每个 isolate 每 30 秒最多 1 次 KV 读。
let CFG = {}, CFG_AT = 0, CFG_OK = false;
const CONFIG_SPEC = {
  title: { t: 'string', max: 60 }, logo: { t: 'string', max: 8 },
  quotaGB: { t: 'number', min: 1, max: 1000000 },
  maxDirItems: { t: 'number', min: 10, max: 500000 },
  kvValueMB: { t: 'number', min: 1, max: 24 },
  versionMaxMB: { t: 'number', min: 0, max: 102400 },
  versionsMax: { t: 'number', min: 0, max: 50 },
  versionsTtlDays: { t: 'number', min: 1, max: 3650 },
  hashTtlDays: { t: 'number', min: 1, max: 3650 },
  trashDays: { t: 'number', min: 0, max: 3650 },
  chunkGcHours: { t: 'number', min: 0, max: 720 },
  backupKeep: { t: 'number', min: 1, max: 500 },
  backupMaxMB: { t: 'number', min: 1, max: 100 },
  backupTotalMB: { t: 'number', min: 10, max: 1000000 },
  backupIncremental: { t: 'bool' },
  telemetryMaxPerDay: { t: 'number', min: 0, max: 1000000 },
  telemetryFlushMs: { t: 'number', min: 0, max: 600000 },
  sessionCacheSec: { t: 'number', min: 0, max: 3600 },
  kvBudgetPerMin: { t: 'number', min: 0, max: 1000000 },
  rlReadPerMin: { t: 'number', min: 0, max: 1000000 },
  rlWritePerMin: { t: 'number', min: 0, max: 1000000 },
  maxUploadMB: { t: 'number', min: 1, max: 10240 },
  doorMaxMB: { t: 'number', min: 1, max: 10240 },
  publicUploadMaxMB: { t: 'number', min: 1, max: 10240 },
  publicUploadDir: { t: 'string', max: 300 },
  ipAllow: { t: 'string', max: 500 }, ipDeny: { t: 'string', max: 500 },
  countryAllow: { t: 'string', max: 200 }, countryDeny: { t: 'string', max: 200 },
  uaAllow: { t: 'string', max: 500 }, uaDeny: { t: 'string', max: 500 },
  disableUrlFetch: { t: 'bool' },
  signTtlMin: { t: 'number', min: 1, max: 43200 },
  shareZipMaxMB: { t: 'number', min: 1, max: 10240 },
  notice: { t: 'string', max: 300 }
};
async function loadConfig(env, force) {
  if (!force && CFG_OK && Date.now() - CFG_AT < 30000) return CFG;
  try { const c = await env.STORE.get('meta:config', 'json'); CFG = (c && typeof c === 'object') ? c : {}; }
  catch (e) { CFG = {}; }
  CFG_AT = Date.now(); CFG_OK = true;
  return CFG;
}
function cfgNum(env, envName, cfgName, def, allowZero) {
  const c = CFG[cfgName];
  if (typeof c === 'number' && Number.isFinite(c)) { if (c > 0) return c; if (allowZero && c === 0) return 0; }
  return numEnv(env, envName, def, allowZero);
}
function cfgStr(env, envName, cfgName, def) {
  const c = CFG[cfgName];
  if (typeof c === 'string' && c.trim()) return c.trim();
  const e = env && env[envName];
  if (typeof e === 'string' && e.trim()) return e.trim();
  return def;
}
function cfgBool(env, envName, cfgName, def) {
  const c = CFG[cfgName];
  if (typeof c === 'boolean') return c;
  if (env && env[envName] != null && env[envName] !== '') return String(env[envName]) === '1' || env[envName] === true;
  return def;
}
function siteTitle(env) { return cfgStr(env, 'DRIVE_TITLE', 'title', '云端网盘').slice(0, 60); }
function siteLogo(env) { return cfgStr(env, 'DRIVE_LOGO', 'logo', '☁️').slice(0, 8); }
function validateConfig(patch) {
  const out = {}, errs = [];
  for (const k of Object.keys(patch || {})) {
    if (!Object.prototype.hasOwnProperty.call(CONFIG_SPEC, k)) { errs.push('unknown key: ' + k); continue; }
    const spec = CONFIG_SPEC[k];
    const v = patch[k];
    if (v === null || v === '') { out[k] = null; continue; }     // null/空 = 清除该项覆盖
    if (spec.t === 'bool') { out[k] = !!v; continue; }
    if (spec.t === 'number') {
      const n = Number(v);
      if (!Number.isFinite(n)) { errs.push(k + ' must be a number'); continue; }
      if (n < spec.min || n > spec.max) { errs.push(k + ' out of range [' + spec.min + ',' + spec.max + ']'); continue; }
      out[k] = n; continue;
    }
    const s = String(v);
    if (s.length > spec.max) { errs.push(k + ' too long (max ' + spec.max + ')'); continue; }
    out[k] = s;
  }
  return { out, errs };
}
// —— 可调上限（配置面板 > 环境变量 > 默认值）——
function maxDirItems(env) { return Math.floor(cfgNum(env, 'MAX_DIR_ITEMS', 'maxDirItems', 20000)); }
// 说明：配置面板里的 MB 类键优先；同名旧环境变量按其历史单位（字节）解释，保持向后兼容
function mbOrBytes(env, cfgKey, envName, defBytes) {
  const c = CFG[cfgKey];
  if (typeof c === 'number' && Number.isFinite(c) && c >= 0) return c * 1048576;
  const n = (env && env[envName] != null) ? Number(env[envName]) : NaN;
  if (Number.isFinite(n) && n >= 0) return n;
  return defBytes;
}
function kvValueMax(env) { return mbOrBytes(env, 'kvValueMB', 'KV_VALUE_MAX', 8 * 1024 * 1024); }
function versionMaxBytes(env) { return mbOrBytes(env, 'versionMaxMB', 'VERSION_MAX_BYTES', 64 * 1024 * 1024); }
function backupMaxBytes(env) { return mbOrBytes(env, 'backupMaxMB', 'BACKUP_MAX_BYTES', 8 * 1024 * 1024); }
function hashTtl(env) { return Math.floor(cfgNum(env, 'HASH_TTL_DAYS', 'hashTtlDays', 30) * 86400); }
function versionsTtl(env) { return Math.floor(cfgNum(env, 'VERSIONS_TTL_DAYS', 'versionsTtlDays', 90) * 86400); }
function trashDays(env) { return Math.max(0, Math.floor(cfgNum(env, 'TRASH_DAYS', 'trashDays', 30, true))); }
function chunkGcHours(env) { return cfgNum(env, 'CHUNK_GC_HOURS', 'chunkGcHours', 24, true); }
function backupKeep(env) { return Math.floor(cfgNum(env, 'BACKUP_KEEP', 'backupKeep', 14)); }
function backupTotalBytes(env) { return cfgNum(env, 'BACKUP_TOTAL_MB', 'backupTotalMB', 200) * 1024 * 1024; }
function maxNoteBytes(env) { return numEnv(env, 'MAX_NOTE_BYTES', 64 * 1024); }
function maxTagsBytes(env) { return numEnv(env, 'MAX_TAGS_BYTES', 8 * 1024); }
function telemetryFlushMs(env) { return cfgNum(env, 'TELEMETRY_FLUSH_MS', 'telemetryFlushMs', 15000, true); }
function kvBudgetPerMin(env) { return Math.floor(cfgNum(env, 'KV_BUDGET_PER_MIN', 'kvBudgetPerMin', 600)); }
// 每日遥测写预算：防止"日志/最近/下载明细"把免费额度（1000 写/天）吃光
function telemetryMaxPerDay(env) { return Math.floor(cfgNum(env, 'TELEMETRY_MAX_PER_DAY', 'telemetryMaxPerDay', 800)); }
function maxVersions(env) { return Math.floor(cfgNum(env, 'VERSIONS_MAX', 'versionsMax', MAX_VERSIONS, true)); }
function kvMirrorDir(env) { return cfgBool(env, 'KV_MIRROR_DIR', 'kvMirrorDir', true); }
function maxUploadBytes(env) { return cfgNum(env, 'MAX_UPLOAD_MB', 'maxUploadMB', 500) * 1024 * 1024; }
function sessionCacheSec(env) { return numEnv(env, 'SESSION_CACHE_SEC', 10, true); }
const KV_KEY_MAX = 480;          // KV key 硬限 512B
const PATH_MAX = 400;            // 路径长度上限（防止 KV key 超限导致静默丢元数据）
function pathTooLong(p) { return String(p == null ? '' : p).length > PATH_MAX; }

// —— 隔离级读缓存（多 isolate 之间最多各自陈旧 TTL 秒）——
const KV_CACHE = new Map();
async function kvCached(key, ttlSec, loader) {
  if (!(ttlSec > 0)) return loader();
  const hit = KV_CACHE.get(key);
  if (hit && Date.now() < hit.exp) return hit.v;
  const v = await loader();
  if (KV_CACHE.size > 400) KV_CACHE.clear();
  KV_CACHE.set(key, { v, exp: Date.now() + ttlSec * 1000 });
  return v;
}
function kvInvalidate(prefix) {
  for (const k of Array.from(KV_CACHE.keys())) if (k === prefix || k.indexOf(prefix) === 0) KV_CACHE.delete(k);
}

// —— 非关键 KV 写预算（滑动窗口，每分钟）——
const KV_WRITE_LOG = [];
function kvWritesLastMin() { const t = Date.now(); return KV_WRITE_LOG.filter(x => t - x < 60000).length; }
function kvBudgetOk(env) {
  const t = Date.now();
  while (KV_WRITE_LOG.length && t - KV_WRITE_LOG[0] > 60000) KV_WRITE_LOG.shift();
  if (KV_WRITE_LOG.length >= kvBudgetPerMin(env)) return false;
  KV_WRITE_LOG.push(t);
  return true;
}

// —— 遥测缓冲：日志 / 下载明细 / 下载汇总 / 每日统计 / 最近访问 ——
// 这些数据是"只增不减"的热键，原先每次请求都要读改写一遍，是 KV 写爆的主因。
const TEL = { log: [], dllog: [], dl: { total: 0, bytes: 0 }, daily: {}, recent: [], lastFlush: 0, lastChunkGc: 0, day: '', dayCount: 0 };
// 每日遥测预算：有 DO 时用 DO 计数（不消耗 KV 写），否则退化为进程内计数
async function telemetryBudgetOk(env) {
  const day = new Date().toISOString().substring(0, 10);
  const max = telemetryMaxPerDay(env);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(counterStub(env, 'tel:' + day).fetch('https://dir/counterAdd', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ delta: 1 })
      }), 2000);
      if (r && r.ok) {
        const v = (await r.json()).value;
        if (typeof v === 'number') return v <= max;
      }
    } catch (e) {}
  }
  if (TEL.day !== day) { TEL.day = day; TEL.dayCount = 0; }
  TEL.dayCount++;
  return TEL.dayCount <= max;
}
function telPending() {
  return TEL.log.length + TEL.dllog.length + TEL.recent.length + (TEL.dl.total || TEL.dl.bytes ? 1 : 0) + Object.keys(TEL.daily).length;
}
function telBufLog(entry) { TEL.log.unshift(entry); if (TEL.log.length > 200) TEL.log.length = 200; }
function telBufDlLog(entry) { TEL.dllog.unshift(entry); if (TEL.dllog.length > 300) TEL.dllog.length = 300; }
function telBufDaily(kind, bytes) {
  const day = new Date().toISOString().substring(0, 10);
  const d = TEL.daily[day] || (TEL.daily[day] = { up: 0, upBytes: 0, dl: 0, dlBytes: 0 });
  if (kind === 'up') { d.up++; d.upBytes += (bytes || 0); }
  else if (kind !== 'del') { d.dl++; d.dlBytes += (bytes || 0); }
}
function telBufRecent(path) {
  TEL.recent = TEL.recent.filter(x => x.path !== path);
  TEL.recent.unshift({ path, time: Date.now() });
  if (TEL.recent.length > 50) TEL.recent.length = 50;
}
async function flushTelemetry(env) {
  if (!telPending()) return false;
  if (Date.now() - TEL.lastFlush < telemetryFlushMs(env)) return false;
  if (!kvBudgetOk(env) || !await telemetryBudgetOk(env)) {
    // 预算用尽：继续缓冲但强制裁剪，宁可丢日志也不能把 KV 写爆
    if (TEL.log.length > 200) TEL.log.length = 200;
    if (TEL.dllog.length > 300) TEL.dllog.length = 300;
    if (TEL.recent.length > 50) TEL.recent.length = 50;
    return false;
  }
  TEL.lastFlush = Date.now();
  try {
    if (TEL.log.length) {
      const cur = (await env.STORE.get('meta:log', 'json')) || [];
      const merged = TEL.log.concat(Array.isArray(cur) ? cur : []);
      if (merged.length > 200) merged.length = 200;
      await env.STORE.put('meta:log', JSON.stringify(merged));
      TEL.log = [];
    }
    if (TEL.dllog.length) {
      const cur = (await env.STORE.get('meta:dllog', 'json')) || [];
      const merged = TEL.dllog.concat(Array.isArray(cur) ? cur : []);
      if (merged.length > 300) merged.length = 300;
      await env.STORE.put('meta:dllog', JSON.stringify(merged));
      TEL.dllog = [];
    }
    if (TEL.dl.total || TEL.dl.bytes) {
      const agg = (await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 };
      agg.total = (agg.total || 0) + TEL.dl.total;
      agg.bytes = (agg.bytes || 0) + TEL.dl.bytes;
      await env.STORE.put('meta:dlstat', JSON.stringify(agg));
      TEL.dl = { total: 0, bytes: 0 };
    }
    const days = Object.keys(TEL.daily);
    if (days.length) {
      const all = (await env.STORE.get('meta:daily', 'json')) || {};
      for (const day of days) {
        const b = TEL.daily[day], d = all[day] || (all[day] = { up: 0, upBytes: 0, dl: 0, dlBytes: 0 });
        d.up = (d.up || 0) + (b.up || 0); d.upBytes = (d.upBytes || 0) + (b.upBytes || 0);
        d.dl = (d.dl || 0) + (b.dl || 0); d.dlBytes = (d.dlBytes || 0) + (b.dlBytes || 0);
      }
      const keys = Object.keys(all).sort();
      while (keys.length > 90) delete all[keys.shift()];
      await env.STORE.put('meta:daily', JSON.stringify(all));
      TEL.daily = {};
    }
    if (TEL.recent.length) {
      const cur = (await env.STORE.get('meta:recent', 'json')) || [];
      const merged = TEL.recent.concat(Array.isArray(cur) ? cur : []);
      const out = [];
      const seen = {};
      for (const it of merged) {
        if (!it || !it.path || seen[it.path]) continue;
        seen[it.path] = 1; out.push(it);
        if (out.length >= 50) break;
      }
      await env.STORE.put('meta:recent', JSON.stringify(out), { expirationTtl: 180 * 86400 });
      TEL.recent = [];
    }
  } catch (e) { /* 尽力而为，绝不因遥测写失败影响主流程 */ }
  return true;
}
// 读侧合并缓冲，保证面板立刻能看到最新数据
function telMergeLogs(cur) { return TEL.log.concat(Array.isArray(cur) ? cur : []).slice(0, 200); }
function telMergeDlLogs(cur) { return TEL.dllog.concat(Array.isArray(cur) ? cur : []).slice(0, 300); }
function telMergeDlStat(cur) {
  const c = cur && typeof cur === 'object' ? cur : { total: 0, bytes: 0 };
  return { total: (c.total || 0) + TEL.dl.total, bytes: (c.bytes || 0) + TEL.dl.bytes };
}
function telMergeDaily(all) {
  const out = Object.assign({}, all || {});
  for (const day of Object.keys(TEL.daily)) {
    const b = TEL.daily[day], d = out[day] || { up: 0, upBytes: 0, dl: 0, dlBytes: 0 };
    out[day] = {
      up: (d.up || 0) + (b.up || 0), upBytes: (d.upBytes || 0) + (b.upBytes || 0),
      dl: (d.dl || 0) + (b.dl || 0), dlBytes: (d.dlBytes || 0) + (b.dlBytes || 0)
    };
  }
  return out;
}
function telMergeRecent(cur) {
  const merged = TEL.recent.concat(Array.isArray(cur) ? cur : []);
  const out = [], seen = {};
  for (const it of merged) {
    if (!it || !it.path || seen[it.path]) continue;
    seen[it.path] = 1; out.push(it);
    if (out.length >= 50) break;
  }
  return out;
}

// ===== Range / 流式响应 =====
function dangerType(mime) {
  const m = String(mime || '').toLowerCase();
  if (!m) return false;
  if (/^(text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/xml|application\/xml|application\/xhtml)$/.test(m)) return true;
  if (m.indexOf('+xml') >= 0) return true;
  if (/^application\/(javascript|ecmascript|x-javascript)$/.test(m)) return true;
  if (/^text\/(javascript|ecmascript|x-javascript)$/.test(m)) return true;
  return false;
}
// 解析 Range 头：返回 {offset,length,start,end}，或 {invalid:true}
function parseRange(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(header || '').trim());
  if (!m) return { invalid: true };
  if (m[1] === '' && m[2] === '') return { invalid: true };
  if (!Number.isFinite(size) || size <= 0) return { invalid: true };
  let start, end;
  if (m[1] === '') {
    const n = parseInt(m[2], 10);
    if (!Number.isFinite(n) || n <= 0) return { invalid: true };
    start = Math.max(0, size - n); end = size - 1;
  } else {
    start = parseInt(m[1], 10);
    end = m[2] === '' ? size - 1 : Math.min(parseInt(m[2], 10), size - 1);
  }
  if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= size) return { invalid: true };
  return { offset: start, length: end - start + 1, start, end };
}
// 统一的对象流式响应：支持 Range(206/416)，供下载/预览/缩略图/分享/WebDAV 复用
// opts: { disposition, cacheControl, sanitize }
async function serveObject(env, req, key, opts) {
  opts = opts || {};
  const rangeHeader = (req && req.headers) ? req.headers.get('Range') : null;
  const base = { 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
  let obj, status = 200, contentRange = null, contentLength = null;
  if (rangeHeader) {
    let head = null;
    try { head = await env.DRIVE.head(key); } catch (e) {}
    if (!head) return json({ error: 'Not found' }, 404);
    const r = parseRange(rangeHeader, head.size);
    if (!r || r.invalid) return new Response(null, { status: 416, headers: Object.assign({}, base, { 'Content-Range': 'bytes */' + head.size }) });
    try { obj = await env.DRIVE.get(key, { range: { offset: r.offset, length: r.length } }); } catch (e) { obj = null; }
    if (!obj) return json({ error: 'Not found' }, 404);
    status = 206;
    contentRange = 'bytes ' + r.start + '-' + r.end + '/' + head.size;
    contentLength = r.length;
  } else {
    try { obj = await env.DRIVE.get(key); } catch (e) { obj = null; }
    if (!obj) return json({ error: 'Not found' }, 404);
  }
  let type = (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream';
  const headers = Object.assign({}, base);
  if (opts.sanitize && dangerType(type)) {
    type = 'text/plain; charset=utf-8';
    headers['Content-Security-Policy'] = "default-src 'none'; sandbox";
  }
  headers['Content-Type'] = type;
  if (opts.disposition) headers['Content-Disposition'] = opts.disposition;
  if (opts.cacheControl && status === 200) headers['Cache-Control'] = opts.cacheControl;
  if (contentRange) { headers['Content-Range'] = contentRange; headers['Content-Length'] = String(contentLength); }
  return new Response(obj.body, { status, headers });
}
// 原子计数（DO 可用时；否则 KV 退化为尽力而为），绝不抛错
function counterStub(env, id) { return env.DIR.get(env.DIR.idFromName('__counter__:' + id)); }
async function counterAdd(env, id, delta) {
  if (hasDO(env)) {
    try {
      const r = await withTimeout(counterStub(env, id).fetch('https://dir/counterAdd', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ delta })
      }), 3000);
      if (r && r.ok) return (await r.json()).value;
    } catch (e) { console.warn('DO counterAdd → KV:', e && e.message); }
  }
  try {
    const cur = await env.STORE.get('counter:' + id, 'json');
    const base = (typeof cur === 'number' && Number.isFinite(cur)) ? cur : 0;
    const v = base + (Number(delta) || 0);
    await env.STORE.put('counter:' + id, JSON.stringify(v));
    return v;
  } catch (e) { return null; }
}
async function counterDel(env, id) {
  if (hasDO(env)) {
    try { await withTimeout(counterStub(env, id).fetch('https://dir/counterDel', { method: 'POST' }), 3000); } catch (e) {}
  }
  try { await env.STORE.delete('counter:' + id); } catch (e) {}
}

// ===== Turnstile（可选：未配置 Secret 时自动跳过） =====
function turnstileSecret(env) { return (env && env.TURNSTILE_SECRET) || ''; }
function turnstileSiteKey(env) { return (env && env.TURNSTILE_SITE_KEY) || ''; }
async function verifyTurnstile(env, token, ip) {
  const secret = turnstileSecret(env);
  if (!secret) {
    // M2: 配置了 site key（意图启用验证）但缺 secret 时视为配置不完整，拒绝放行
    if (turnstileSiteKey(env)) return false;
    return true;                                  // 完全未配置 → 保持跳过（向后兼容）
  }
  if (!token) return false;
  try {
    const form = new FormData();
    form.append('secret', secret);
    form.append('response', String(token));
    if (ip) form.append('remoteip', String(ip));
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    const d = await r.json();
    return !!(d && d.success);
  } catch (e) { return false; }
}

// ===== 公开上传（需显式配置 PUBLIC_UPLOAD_DIR 才开启） =====
function publicUploadDir(env) {
  const d = cfgStr(env, 'PUBLIC_UPLOAD_DIR', 'publicUploadDir', '');
  if (!d) return null;
  return normPath(d);
}
function publicUploadMax(env) {
  return cfgNum(env, 'PUBLIC_UPLOAD_MAX', 'publicUploadMaxMB', 100) * 1024 * 1024;
}

// ===== 客户端信息 / 下载明细 =====
function parseUA(ua) {
  const s = String(ua || '');
  let browser = 'Other', os = 'Other', device = 'Desktop';
  if (/Edg\//i.test(s)) browser = 'Edge';
  else if (/OPR\/|Opera/i.test(s)) browser = 'Opera';
  else if (/Firefox\//i.test(s)) browser = 'Firefox';
  else if (/Chrome\//i.test(s)) browser = 'Chrome';
  else if (/Safari\//i.test(s)) browser = 'Safari';
  else if (/curl|Wget|aria2|python|node|PowerShell|Go-http/i.test(s)) browser = 'CLI';
  if (/Windows/i.test(s)) os = 'Windows';
  else if (/iPhone|iPad|iPod/i.test(s)) os = 'iOS';
  else if (/Android/i.test(s)) os = 'Android';
  else if (/Mac OS X|Macintosh/i.test(s)) os = 'macOS';
  else if (/Linux/i.test(s)) os = 'Linux';
  if (/iPad|Tablet/i.test(s)) device = 'Tablet';
  else if (/Mobi|iPhone|Android/i.test(s)) device = 'Mobile';
  return { browser, os, device };
}
function clientInfo(req) {
  const ua = (req && req.headers.get('User-Agent')) || '';
  const ip = (req && req.headers.get('CF-Connecting-IP')) || '';
  const country = (req && req.cf && req.cf.country) || '';
  const p = parseUA(ua);
  return { ip, country, browser: p.browser, os: p.os, device: p.device };
}
async function addDownloadLog(env, e) {
  // 下载明细改为内存缓冲 + 定时合并写（原先每次下载都要读改写两个热键）
  try {
    telBufDlLog(e);
    TEL.dl.total += 1;
    TEL.dl.bytes += (e.size || 0);
    telBufDaily('dl', e.size || 0);
  } catch (err) {}
}

// 按前缀列出 KV key（用于分享/上传链接管理）
async function listKV(env, prefix, max) {
  const out = [];
  const cap = max || 500;
  try {
    let cursor;
    do {
      const res = await env.STORE.list({ prefix, cursor, limit: 1000 });
      for (const k of res.keys) { out.push(k.name); if (out.length >= cap) break; }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor && out.length < cap);
  } catch (e) {}
  return out;
}
// 分享 / 上传链接面板：限制单次列出的条数，避免一次面板打开产生上百次 KV 读
const LIST_PANEL_MAX = 200;

// ===== S3 兼容多后端（纯 JS AWS SigV4，未配置 DRIVE_BACKENDS 时全部空转） =====
function getBackends(env) {
  if (!env || !env.DRIVE_BACKENDS) return [];
  try {
    let raw = env.DRIVE_BACKENDS;
    let arr = (typeof raw === 'string') ? JSON.parse(raw) : raw;
    if (!Array.isArray(arr)) {
      if (arr && typeof arr === 'object') arr = Object.keys(arr).map(k => Object.assign({ id: k }, arr[k]));
      else arr = [];
    }
    return arr.filter(b => b && b.endpoint && b.bucket && b.accessKey && b.secretKey).map(b => ({
      id: String(b.id || b.bucket),
      endpoint: String(b.endpoint).replace(/\/+$/, ''),
      region: String(b.region || 'auto'),
      bucket: String(b.bucket),
      accessKey: String(b.accessKey),
      secretKey: String(b.secretKey),
      sessionToken: b.sessionToken ? String(b.sessionToken) : '',
      pathStyle: b.pathStyle !== false,
      prefix: b.prefix ? String(b.prefix).replace(/^\/+/, '').replace(/\/+$/, '') : '',
      mirrorMaxBytes: Number(b.mirrorMaxBytes) > 0 ? Number(b.mirrorMaxBytes) : 25 * 1024 * 1024
    }));
  } catch (e) { return []; }
}
function UriEnc(s) { return encodeURIComponent(String(s)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase()); }
async function sha256HexBytes(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hmacSha256(keyBytes, dataBytes) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, dataBytes));
}
// AWS SigV4 签名核心（headers 的 key 必须小写；amzDate 形如 20130524T000000Z）
export async function signV4(o) {
  const dateStamp = o.amzDate.substring(0, 8);
  const names = Object.keys(o.headers).map(k => k.toLowerCase()).sort();
  const lower = {};
  for (const k of Object.keys(o.headers)) lower[k.toLowerCase()] = String(o.headers[k]).trim();
  const canonicalHeaders = names.map(n => n + ':' + lower[n] + '\n').join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = o.method + '\n' + o.canonicalUri + '\n' + (o.canonicalQuery || '') + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + o.payloadHash;
  const scope = dateStamp + '/' + o.region + '/' + o.service + '/aws4_request';
  const stringToSign = 'AWS4-HMAC-SHA256\n' + o.amzDate + '\n' + scope + '\n' + await sha256HexBytes(new TextEncoder().encode(canonicalRequest));
  const enc = new TextEncoder();
  let k = await hmacSha256(enc.encode('AWS4' + o.secretKey), enc.encode(dateStamp));
  k = await hmacSha256(k, enc.encode(o.region));
  k = await hmacSha256(k, enc.encode(o.service));
  k = await hmacSha256(k, enc.encode('aws4_request'));
  const signature = Array.from(await hmacSha256(k, enc.encode(stringToSign))).map(b => b.toString(16).padStart(2, '0')).join('');
  return {
    authorization: 'AWS4-HMAC-SHA256 Credential=' + o.accessKey + '/' + scope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature,
    signedHeaders
  };
}
async function s3Request(env, cfg, method, key, query, body, contentType) {
  const u = new URL(cfg.endpoint);
  const host = u.host;
  const segs = String(key || '').split('/').filter(s => s !== '').map(UriEnc);
  const prefixSegs = cfg.prefix ? cfg.prefix.split('/').filter(Boolean).map(UriEnc) : [];
  const bucketSeg = cfg.pathStyle ? [UriEnc(cfg.bucket)] : [];
  const allSegs = bucketSeg.concat(prefixSegs, segs);
  const canonicalUri = '/' + allSegs.join('/');
  const hostHeader = cfg.pathStyle ? host : (cfg.bucket + '.' + host);
  const bodyBytes = body == null ? new Uint8Array(0) : body;
  const payloadHash = await sha256HexBytes(bodyBytes);
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const headers = { host: hostHeader, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  if (cfg.sessionToken) headers['x-amz-security-token'] = cfg.sessionToken;
  if (method === 'PUT' || method === 'POST') headers['content-type'] = contentType || 'application/octet-stream';
  const qp = Object.keys(query || {}).map(k => [UriEnc(k), UriEnc(query[k])]).sort((a, b) => a[0] < b[0] ? -1 : (a[0] > b[0] ? 1 : 0));
  const canonicalQuery = qp.map(p => p[0] + '=' + p[1]).join('&');
  const signed = await signV4({
    accessKey: cfg.accessKey, secretKey: cfg.secretKey, region: cfg.region, service: 's3',
    method, canonicalUri, canonicalQuery, headers, payloadHash, amzDate
  });
  const sendHeaders = { 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate, 'Authorization': signed.authorization };
  if (cfg.sessionToken) sendHeaders['x-amz-security-token'] = cfg.sessionToken;
  if (method === 'PUT' || method === 'POST') sendHeaders['Content-Type'] = contentType || 'application/octet-stream';
  // 虚拟主机风格必须把 bucket 放进 Host，否则签名用的 host 与实际请求不符（403）
  const origin = cfg.pathStyle ? cfg.endpoint : (u.protocol + '//' + cfg.bucket + '.' + u.host);
  const url = origin + canonicalUri + (canonicalQuery ? '?' + canonicalQuery : '');
  return fetch(url, { method, headers: sendHeaders, body: (method === 'PUT' || method === 'POST') ? bodyBytes : undefined });
}
async function recordMirror(env, id, ok, error) {
  try { await env.STORE.put('meta:mirror:' + id, JSON.stringify({ t: Date.now(), ok: !!ok, error: error || '' }), { expirationTtl: 7 * 86400 }); } catch (e) {}
}
// 把主存储（R2）中的对象镜像到各后端；尽力而为，绝不抛错
async function mirrorPut(env, key) {
  const list = getBackends(env);
  if (!list.length) return;
  let obj = null;
  try { obj = await env.DRIVE.get(key); } catch (e) {}
  if (!obj) return;
  const size = obj.size || 0;
  let buf = null;
  for (const cfg of list) {
    if (size > cfg.mirrorMaxBytes) { await recordMirror(env, cfg.id, false, 'skipped (size ' + size + ' > limit)'); continue; }
    try {
      if (!buf) buf = new Uint8Array(await obj.arrayBuffer());
      const ct = (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream';
      const r = await s3Request(env, cfg, 'PUT', key, null, buf, ct);
      await recordMirror(env, cfg.id, r.ok, r.ok ? '' : ('HTTP ' + r.status));
    } catch (e) { await recordMirror(env, cfg.id, false, (e && e.message) || 'error'); }
  }
}
async function mirrorDelete(env, key) {
  const list = getBackends(env);
  if (!list.length) return;
  for (const cfg of list) {
    try {
      const r = await s3Request(env, cfg, 'DELETE', key, null, null, null);
      const ok = r.ok || r.status === 404;
      await recordMirror(env, cfg.id, ok, ok ? '' : ('HTTP ' + r.status));
    } catch (e) { await recordMirror(env, cfg.id, false, (e && e.message) || 'error'); }
  }
}
async function s3Probe(env, cfg) {
  const t0 = Date.now();
  try {
    const r = await s3Request(env, cfg, 'GET', '', { 'list-type': '2', 'max-keys': '1' }, null, null);
    const ms = Date.now() - t0;
    const text = await r.text();
    let count = 0;
    if (r.ok) { const m = /<KeyCount>(\d+)<\/KeyCount>/.exec(text); count = m ? parseInt(m[1], 10) : 0; }
    await recordMirror(env, cfg.id, r.ok, r.ok ? '' : ('HTTP ' + r.status + ' ' + text.slice(0, 160)));
    return { id: cfg.id, ok: r.ok, ms, count, status: r.status, error: r.ok ? '' : ('HTTP ' + r.status + ' ' + text.slice(0, 200)) };
  } catch (e) {
    await recordMirror(env, cfg.id, false, (e && e.message) || 'error');
    return { id: cfg.id, ok: false, ms: Date.now() - t0, count: 0, error: (e && e.message) || 'error' };
  }
}
// 写入 / 删除主存储后同步镜像
async function putAndMirror(env, key, body, opts) {
  const res = await env.DRIVE.put(key, body, opts);
  try { await mirrorPut(env, key); } catch (e) {}
  return res;
}
async function deleteAndMirror(env, key) {
  try { await env.DRIVE.delete(key); } catch (e) {}
  try { await mirrorDelete(env, key); } catch (e) {}
}
async function handleListBackends(env) {
  const list = getBackends(env);
  const out = [];
  for (const c of list) {
    let last = null;
    try { last = await env.STORE.get('meta:mirror:' + c.id, 'json'); } catch (e) {}
    out.push({ id: c.id, endpoint: c.endpoint, bucket: c.bucket, region: c.region, pathStyle: c.pathStyle, prefix: c.prefix, mirrorMaxBytes: c.mirrorMaxBytes, last });
  }
  return json({ backends: out, enabled: out.length > 0 });
}
async function handleCheckBackends(env) {
  const list = getBackends(env);
  const results = [];
  for (const c of list) results.push(await s3Probe(env, c));
  return json({ results });
}

// ===== Durable Object: 目录元数据 + 用量统计 =====
export class DirStore {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.name = (state.id && state.id.name) ? state.id.name : '';
  }

  async fetch(req) {
    try {
    const url = new URL(req.url);
    const op = url.pathname.replace(/^\/+/, '');

    // 关键修复：所有读改写操作都必须先从 KV 播种，否则新起的 DO 实例会把空列表镜像回 KV，
    // 导致该目录其它条目全部从列表消失。
    const loadItems = async () => {
      let items = await this.state.storage.get('items');
      if (items === undefined) {
        try { items = (await this.env.STORE.get('dir:' + this.name, 'json')) || []; }
        catch (e) { items = []; }
        try { await this.state.storage.put('items', items); } catch (e) {}
      }
      return Array.isArray(items) ? items : [];
    };
    // DO 单值上限 128KiB：过大时清空本地副本，让后续读走 KV，避免读到陈旧列表
    const saveItems = async (items) => {
      if (JSON.stringify(items).length > DO_ITEMS_MAX) {
        try { await this.state.storage.delete('items'); } catch (e) {}
        return false;
      }
      await this.state.storage.put('items', items);
      return true;
    };

    if (op === 'get') {
      return json(await loadItems());
    }
    if (op === 'set' && req.method === 'PUT') {
      const items = await req.json();
      const ok = await saveItems(Array.isArray(items) ? items : []);
      return json({ ok: true, cached: ok });
    }
    if (op === 'upsert' && req.method === 'POST') {
      const { item } = await req.json();
      const items = await loadItems();
      const idx = items.findIndex(i => i.name === item.name);
      if (idx < 0 && items.length >= maxDirItems(this.env)) return json({ error: 'dir-full', limit: maxDirItems(this.env) }, 507);
      if (idx >= 0) items[idx] = item; else items.push(item);
      const ok = await saveItems(items);
      return json({ ok: true, existed: idx >= 0, cached: ok });
    }
    if (op === 'remove' && req.method === 'POST') {
      const { name } = await req.json();
      const items = await loadItems();
      const filtered = items.filter(i => i.name !== name);
      const ok = await saveItems(filtered);
      return json({ ok: true, removed: items.length - filtered.length, cached: ok });
    }
    if (op === 'rename' && req.method === 'POST') {
      const { oldName, newName } = await req.json();
      const items = await loadItems();
      const idx = items.findIndex(i => i.name === oldName);
      if (idx < 0) return json({ error: 'not found' }, 404);
      if (items.find(i => i.name === newName)) return json({ error: 'exists' }, 409);
      items[idx] = { ...items[idx], name: newName, time: new Date().toISOString() };
      const ok = await saveItems(items);
      return json({ ok: true, item: items[idx], cached: ok });
    }
    if (op === 'find' && req.method === 'GET') {
      const name = url.searchParams.get('name');
      const items = await loadItems();
      return json({ item: items.find(i => i.name === name) || null });
    }
    if (op === 'delete' && req.method === 'POST') {
      await this.state.storage.deleteAll();
      return json({ ok: true });
    }

    if (op === 'getUsage') {
      let u = await this.state.storage.get('usage');
      if (!u) {
        try { u = await this.env.STORE.get('meta:usage', 'json') || { used: 0, files: 0 }; }
        catch (e) { u = { used: 0, files: 0 }; }
        await this.state.storage.put('usage', u);
      }
      return json(u);
    }
    if (op === 'addUsage' && req.method === 'POST') {
      const { size, count } = await req.json();
      let u = await this.state.storage.get('usage');
      if (!u) {
        try { u = await this.env.STORE.get('meta:usage', 'json') || { used: 0, files: 0 }; }
        catch (e) { u = { used: 0, files: 0 }; }
      }
      u.used = Math.max(0, (u.used || 0) + (size || 0));
      u.files = Math.max(0, (u.files || 0) + (count || 0));
      await this.state.storage.put('usage', u);
      return json({ ok: true, usage: u });
    }
    if (op === 'setUsage' && req.method === 'PUT') {
      const u = await req.json();
      await this.state.storage.put('usage', { used: u.used || 0, files: u.files || 0 });
      return json({ ok: true });
    }

    if (op === 'counterAdd' && req.method === 'POST') {
      const { delta } = await req.json();
      const v = ((await this.state.storage.get('v')) || 0) + (Number(delta) || 0);
      await this.state.storage.put('v', v);
      return json({ value: v });
    }
    if (op === 'counterGet') {
      const v = (await this.state.storage.get('v')) || 0;
      return json({ value: v });
    }
    if (op === 'counterDel' && req.method === 'POST') {
      // 只清计数器自身，避免误删同 DO 实例里的其它键
      await this.state.storage.delete('v');
      return json({ ok: true });
    }

    // 按令牌限流：读/写各一个令牌桶，按时间回填；桶初始为满（rpm），首次请求即放行
    if (op === 'rl' && req.method === 'POST') {
      let body = {};
      try { body = await req.json(); } catch (e) {}
      const isWrite = !!body.isWrite;
      const rpm = (Number(body.rpm) > 0) ? Number(body.rpm) : (isWrite ? 30 : 150);
      const rate = rpm / 60; // 每秒回填数量
      const now = Date.now();
      let b = await this.state.storage.get('rl');
      if (!b || typeof b !== 'object') b = { r: null, w: null };
      const bucket = isWrite ? (b.w || (b.w = { tokens: rpm, ts: now })) : (b.r || (b.r = { tokens: rpm, ts: now }));
      const elapsed = Math.max(0, (now - (bucket.ts || now)) / 1000);
      bucket.tokens = Math.min(rpm, (bucket.tokens || 0) + elapsed * rate);
      if (bucket.tokens < 1) {
        const retryAfter = Math.max(1, Math.ceil((1 - bucket.tokens) / rate));
        try { await this.state.storage.put('rl', b); } catch (e) {}
        return json({ ok: false, retryAfter });
      }
      bucket.tokens -= 1; bucket.ts = now;
      try { await this.state.storage.put('rl', b); } catch (e) {}
      return json({ ok: true, remaining: Math.floor(bucket.tokens) });
    }

    return json({ error: 'Unknown op' }, 404);
    } catch (e) {
      return json({ error: 'DO error' }, 500);
    }
  }
}

// ===== Dir 访问层（DO 优先，3秒超时后降级 KV） =====
function hasDO(env) {
  return !!(env && env.DIR && typeof env.DIR.idFromName === 'function');
}
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error('DO timeout')), ms || 3000))
  ]);
}
function dirStub(env, path) {
  const np = normPath(path);
  return env.DIR.get(env.DIR.idFromName(np));
}
function usageStub(env) {
  return env.DIR.get(env.DIR.idFromName(USAGE_DO_NAME));
}

async function getDir(env, path) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/get'), 3000);
      if (r && r.ok) return await r.json();
    } catch (e) { console.warn('DO getDir → KV:', e && e.message); }
  }
  try { return await env.STORE.get('dir:' + np, 'json') || []; } catch (e) { return []; }
}

async function putDir(env, path, items) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/set', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(items)
      }), 3000);
    } catch (e) { console.warn('DO putDir → KV:', e && e.message); }
  }
  const body = JSON.stringify(items || []);
  if (body.length > kvValueMax(env)) { console.warn('dir metadata too large, KV write skipped:', np); return; }
  if (!kvKeyOk('dir:' + np)) return;
  try { await env.STORE.put('dir:' + np, body); } catch (e) {}
}

// DO 成功变更后，把最新目录镜像回 KV，避免 DO 故障时读到陈旧数据
// （KV_MIRROR_DIR=0 可关闭镜像以省 KV 写配额，代价是 DO 故障时可能读到较旧列表）
async function mirrorDirToKV(env, np) {
  if (!hasDO(env) || !kvMirrorDir(env)) return;
  try {
    const r = await withTimeout(dirStub(env, np).fetch('https://dir/get'), 3000);
    if (r && r.ok) {
      const body = JSON.stringify(await r.json());
      if (body.length > kvValueMax(env) || !kvKeyOk('dir:' + np)) return;
      await env.STORE.put('dir:' + np, body);
    }
  } catch (e) {}
}

async function upsertDirItem(env, path, item) {
  const np = normPath(path);
  const cap = maxDirItems(env);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/upsert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item })
      }), 3000);
      if (r && r.status === 507) return { ok: false, error: 'Directory is full', limit: cap };
      if (r && r.ok) {
        const out = await r.json();
        // cached=false 表示 DO 放不下（超大目录），此时必须走 KV 合并路径
        if (!out || out.cached !== false) { await mirrorDirToKV(env, np); return out; }
      }
    } catch (e) { console.warn('DO upsert → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const idx = items.findIndex(i => i.name === item.name);
  if (idx < 0 && items.length >= cap) return { ok: false, error: 'Directory is full', limit: cap };
  if (idx >= 0) items[idx] = item; else items.push(item);
  const body = JSON.stringify(items);
  if (body.length > kvValueMax(env)) return { ok: false, error: 'Directory metadata too large', limit: kvValueMax(env) };
  if (kvKeyOk('dir:' + np)) { try { await env.STORE.put('dir:' + np, body); } catch (e) {} }
  return { ok: true, existed: idx >= 0 };
}
// KV key 长度保护：超限时跳过写入（DO 仍持有），避免 put 抛错导致元数据静默丢失
function kvKeyOk(key) {
  if (String(key).length <= KV_KEY_MAX) return true;
  console.warn('KV key too long, skipped:', String(key).slice(0, 60), '...');
  return false;
}
// 目录是否还能放下新条目（写入前预检查，给用户明确报错）
async function dirRoom(env, dirPath, adding) {
  try {
    const items = await getDir(env, dirPath);
    const cap = maxDirItems(env);
    if (items.length + (adding || 1) > cap) return { error: 'Directory is full (max ' + cap + ' items)', limit: cap };
    return null;
  } catch (e) { return null; }
}

async function removeDirItem(env, path, name) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      }), 3000);
      if (r && r.ok) {
        const out = await r.json();
        if (!out || out.cached !== false) { await mirrorDirToKV(env, np); return out; }
      }
    } catch (e) { console.warn('DO remove → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const filtered = items.filter(i => i.name !== name);
  if (kvKeyOk('dir:' + np)) { try { await env.STORE.put('dir:' + np, JSON.stringify(filtered)); } catch (e) {} }
  return { ok: true, removed: items.length - filtered.length };
}

async function renameDirItem(env, path, oldName, newName) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/rename', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ oldName, newName })
      }), 3000);
      if (r && r.ok) {
        const out = await r.json();
        if (!out || out.cached !== false) { await mirrorDirToKV(env, np); return out; }
      }
      if (r && r.status === 404) return { error: 'not found' };
      if (r && r.status === 409) return { error: 'exists' };
    } catch (e) { console.warn('DO rename → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const idx = items.findIndex(i => i.name === oldName);
  if (idx < 0) return { error: 'not found' };
  if (items.find(i => i.name === newName)) return { error: 'exists' };
  items[idx] = { ...items[idx], name: newName, time: new Date().toISOString() };
  if (kvKeyOk('dir:' + np)) { try { await env.STORE.put('dir:' + np, JSON.stringify(items)); } catch (e) {} }
  return { ok: true, item: items[idx] };
}

async function findDirItem(env, path, name) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/find?name=' + encodeURIComponent(name)), 3000);
      if (r && r.ok) return await r.json();
    } catch (e) { console.warn('DO find → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  return { item: items.find(i => i.name === name) || null };
}
async function destroyDir(env, path) {
  const np = normPath(path);
  if (hasDO(env)) {
    try { await withTimeout(dirStub(env, np).fetch('https://dir/delete', { method: 'POST' }), 3000); }
    catch (e) { console.warn('DO destroy → KV:', e && e.message); }
  }
  try { await env.STORE.delete('dir:' + np); } catch (e) {}
}

async function getUsage(env) {
  if (hasDO(env)) {
    try {
      const r = await withTimeout(usageStub(env).fetch('https://dir/getUsage'), 3000);
      if (r && r.ok) return await r.json();
    } catch (e) { console.warn('DO getUsage → KV:', e && e.message); }
  }
  try { return await env.STORE.get('meta:usage', 'json') || { used: 0, files: 0 }; }
  catch (e) { return { used: 0, files: 0 }; }
}

async function addUsage(env, size, count) {
  if (hasDO(env)) {
    try {
      const r = await withTimeout(usageStub(env).fetch('https://dir/addUsage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size, count })
      }), 3000);
      if (r && r.ok) return;
    } catch (e) { console.warn('DO addUsage → KV:', e && e.message); }
  }
  try {
    const u = await env.STORE.get('meta:usage', 'json') || { used: 0, files: 0 };
    u.used = Math.max(0, (u.used || 0) + (size || 0));
    u.files = Math.max(0, (u.files || 0) + (count || 0));
    await env.STORE.put('meta:usage', JSON.stringify(u));
  } catch (e) {}
}

async function setUsage(env, used, files) {
  if (hasDO(env)) {
    try {
      const r = await withTimeout(usageStub(env).fetch('https://dir/setUsage', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ used, files })
      }), 3000);
      if (r && r.ok) return;
    } catch (e) { console.warn('DO setUsage → KV:', e && e.message); }
  }
  try { await env.STORE.put('meta:usage', JSON.stringify({ used: used || 0, files: files || 0 })); } catch (e) {}
}

async function recalcUsage(env) {
  let used = 0, files = 0;
  async function scan(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file' && !dirPath.startsWith(TRASH_ROOT)) { used += it.size || 0; files++; }
      else if (it.type === 'dir') await scan(dirPath + it.name + '/');
    }
  }
  await scan('/');
  await setUsage(env, used, files);
  return { used, files };
}

async function calcDirSize(env, dirPath) {
  const items = await getDir(env, dirPath); let total = 0;
  for (const it of items) { if (it.type === 'file') total += it.size || 0; else if (it.type === 'dir') total += await calcDirSize(env, dirPath + it.name + '/'); }
  return total;
}
async function searchDir(env, dirPath, query, locked) {
  const results = []; const items = await getDir(env, dirPath); const q = query.toLowerCase();
  for (const it of items) {
    if (q && it.name.toLowerCase().includes(q)) results.push({ ...it, path: dirPath });
    if (!q && it.type === 'dir') results.push({ ...it, path: dirPath });
    if (it.type === 'dir') {
      const sub = dirPath + it.name + '/';
      if (locked && isLockedPrefix(sub, locked)) continue;
      const nested = await searchDir(env, sub, query, locked);
      results.push(...nested);
    }
  }
  return results;
}

// ===== Recent & Favorites =====
async function addRecent(env, path) {
  // 预览/打开文件都会触发，改为内存缓冲 + 定时合并写
  try { telBufRecent(path); } catch (e) {}
}
async function getRecent(env) {
  try { return telMergeRecent(await env.STORE.get('meta:recent', 'json')); } catch (e) { return telMergeRecent([]); }
}
// 把 "{path,time}" 之类的路径列表补全为真正的目录项（带 name/type/size/mime/path），
// 否则前端会拿到没有 name 的条目，操作按钮会误作用到当前目录。
async function enrichPathItems(env, paths) {
  const out = [];
  for (const p of (Array.isArray(paths) ? paths : [])) {
    const fp = '/' + String(p || '').replace(/^\/+/, '');
    const dir = parentOf(fp);
    const name = fp.split('/').filter(Boolean).pop();
    if (!name) continue;
    let item = null;
    try { const f = await findDirItem(env, dir, name); item = f.item; } catch (e) {}
    if (item) out.push(Object.assign({}, item, { path: dir, name }));
  }
  return out;
}
async function handleGetRecent(env) {
  const list = await getRecent(env);
  const items = await enrichPathItems(env, list.map(r => (r && r.path) || ''));
  return json({ items });
}
async function toggleFav(env, path) {
  let favs = await env.STORE.get('meta:favs', 'json') || [];
  const idx = favs.indexOf(path);
  if (idx >= 0) {
    favs.splice(idx, 1);
    // 取消收藏时同步从分组里移除，避免分组残留失效路径
    try {
      const groups = (await env.STORE.get('meta:favgroups', 'json')) || [];
      let changed = false;
      for (const g of groups) {
        if (!Array.isArray(g.paths)) continue;
        const n = g.paths.filter(p => p !== path);
        if (n.length !== g.paths.length) { g.paths = n; changed = true; }
      }
      if (changed) { await env.STORE.put('meta:favgroups', JSON.stringify(groups)); kvInvalidate('meta:favgroups'); }
    } catch (e) {}
  } else favs.push(path);
  await env.STORE.put('meta:favs', JSON.stringify(favs));
  kvInvalidate('meta:favs');
  return favs;
}
async function getFavs(env) {
  return await kvCached('meta:favs', 15, async () => {
    try { return await env.STORE.get('meta:favs', 'json') || []; } catch (e) { return []; }
  });
}
// ===== 收藏分组 =====
async function getFavGroups(env) {
  return await kvCached('meta:favgroups', 15, async () => {
    try { const g = await env.STORE.get('meta:favgroups', 'json'); return Array.isArray(g) ? g : []; } catch (e) { return []; }
  });
}
// 旧的 meta:favs 是路径数组；分组是 [{name, paths:[]}]
// 注意：分组操作只会把路径补进收藏，绝不会删除收藏（取消收藏由 toggleFav 负责），
// 否则「删除分组/移出分组」会把收藏本身一并清空。
async function saveFavGroups(env, groups) {
  const flat = (await env.STORE.get('meta:favs', 'json') || []).slice();
  for (const g of groups) for (const p of (g.paths || [])) if (flat.indexOf(p) < 0) flat.push(p);
  await env.STORE.put('meta:favgroups', JSON.stringify(groups));
  await env.STORE.put('meta:favs', JSON.stringify(flat));
  kvInvalidate('meta:favgroups');
  kvInvalidate('meta:favs');
  return { groups, flat };
}
async function handleFavGroups(env, req) {
  if (req.method === 'GET') {
    const groups = await getFavGroups(env);
    const flat = await getFavs(env);
    const inGroup = {};
    for (const g of groups) for (const p of (g.paths || [])) inGroup[p] = g.name;
    return json({ groups, total: flat.length, inGroup, ungrouped: flat.filter(p => !inGroup[p]) });
  }
  const b = await req.json();
  let groups = (await getFavGroups(env)).slice();
  if (b && b.delete) {
    groups = groups.filter(g => g.name !== b.delete);
    await saveFavGroups(env, groups);
    return json({ ok: true, groups });
  }
  if (b && b.renameFrom) {
    const g = groups.find(x => x.name === b.renameFrom);
    if (!g) return json({ error: 'Not found' }, 404);
    if (groups.some(x => x.name === b.renameTo)) return json({ error: 'Name exists' }, 400);
    g.name = sanitizeName(String(b.renameTo || '').slice(0, 60)) || g.name;
    await saveFavGroups(env, groups);
    return json({ ok: true, groups });
  }
  if (b && b.setPath && b.group !== undefined) {
    // 把某个路径加入/移出分组（group 为空表示移出全部分组）
    const p = '/' + String(b.setPath).replace(/^\/+/, '');
    for (const g of groups) g.paths = (g.paths || []).filter(x => x !== p);
    if (b.group) {
      let g = groups.find(x => x.name === b.group);
      if (!g) { g = { name: sanitizeName(String(b.group).slice(0, 60)), paths: [], created: new Date().toISOString() }; groups.push(g); }
      g.paths.push(p);
    }
    const r = await saveFavGroups(env, groups);
    return json({ ok: true, groups: r.groups });
  }
  const name = sanitizeName(String((b && b.name) || '').slice(0, 60));
  if (!name) return json({ error: 'No name' }, 400);
  if (groups.length >= 100) return json({ error: 'Too many groups' }, 413);
  if (!groups.some(g => g.name === name)) groups.push({ name, paths: [], created: new Date().toISOString() });
  await saveFavGroups(env, groups);
  return json({ ok: true, groups });
}
// ===== 元数据导出 / 导入 =====
async function collectMetaForExport(env, dir, out, depth) {
  if (depth > 8 || out.files >= 20000) return;
  let items = [];
  try { items = await getDir(env, dir); } catch (e) { return; }
  for (const it of items) {
    if (!it || !it.name) continue;
    if (it.type === 'dir') { out.dirs.push(dir + it.name + '/'); await collectMetaForExport(env, dir + it.name + '/', out, depth + 1); continue; }
    const full = dir + it.name;
    let tags = [], note = '';
    try { tags = await env.STORE.get('tags:' + full, 'json') || []; } catch (e) {}
    try {
      const rawNote = await env.STORE.get('note:' + full);
      if (rawNote != null) {
        try { note = JSON.parse(rawNote) || ''; } catch (e) { note = String(rawNote); }   // 备注以 JSON 字符串存储
        if (typeof note !== 'string') note = String(note);
      }
    } catch (e) {}
    out.files.push({ path: full, name: it.name, size: it.size || 0, mime: it.mime || '', time: it.time || '', ph: it.ph || '', tags: tags.map(t => (t && t.name) || ''), note: note.slice(0, 500) });
    if (out.files.length >= 20000) return;
  }
}
async function handleExportMeta(env, q) {
  const dir = normPath(q.path || '/');
  const out = { dirs: [], files: [] };
  await collectMetaForExport(env, dir, out, 0);
  const favs = await getFavs(env);
  const payload = {
    app: 'personal-drive', version: APP_VERSION, created: new Date().toISOString(), scope: dir,
    dirs: out.dirs, files: out.files,
    favorites: favs.filter(p => p.indexOf(dir) === 0)
  };
  const body = JSON.stringify(payload);
  if (q.format === 'download') {
    return new Response(body, {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="drive-meta-' + new Date().toISOString().substring(0, 10) + '.json"',
        'Cache-Control': 'no-store'
      }
    });
  }
  if (q.format === 'csv') {
    const rows = ['path,size,mime,time,tags,note'];
    for (const f of out.files) {
      rows.push([f.path, f.size, f.mime, f.time, f.tags.join('|'), String(f.note || '').replace(/[\r\n]+/g, ' ')]
        .map(x => '"' + String(x == null ? '' : x).replace(/"/g, '""') + '"').join(','));
    }
    return new Response('\ufeff' + rows.join('\n'), {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="drive-meta-' + new Date().toISOString().substring(0, 10) + '.csv"',
        'Cache-Control': 'no-store'
      }
    });
  }
  return json({ ok: true, files: out.files.length, dirs: out.dirs.length, bytes: body.length, payload });
}
async function handleImportMeta(env, b) {
  const data = (b && b.payload) ? b.payload : b;
  if (!data || !Array.isArray(data.files)) return json({ error: 'Bad payload' }, 400);
  const mode = (b && b.mode) === 'replace' ? 'replace' : 'merge';
  const applyFav = !(b && b.favorites === false);
  let matched = 0, missing = 0, tagsWritten = 0, notesWritten = 0, favAdded = 0;
  const limit = Math.min(data.files.length, 5000);
  for (let i = 0; i < limit; i++) {
    const f = data.files[i];
    if (!f || !f.path) continue;
    const p = '/' + String(f.path).replace(/^\/+/, '');
    const dir = parentOf(p), name = p.split('/').filter(Boolean).pop();
    const found = await findDirItem(env, dir, name);
    if (!found.item) { missing++; continue; }
    matched++;
    const incoming = Array.isArray(f.tags) ? f.tags.filter(Boolean).map(n => ({ name: String(n).slice(0, 60), color: '' })) : [];
    if (incoming.length) {
      let cur = [];
      try { cur = await env.STORE.get('tags:' + p, 'json') || []; } catch (e) { cur = []; }
      let next;
      if (mode === 'replace') next = incoming;
      else {
        const map = {};
        for (const t of cur) if (t && t.name) map[t.name] = t.color || '';
        for (const t of incoming) if (!(t.name in map)) map[t.name] = '';
        next = Object.keys(map).map(n => ({ name: n, color: map[n] }));
      }
      if (JSON.stringify(next).length <= maxTagsBytes(env)) {
        await env.STORE.put('tags:' + p, JSON.stringify(next));
        tagsWritten++;
        await addGlobalTags(env, incoming);
      }
    }
    if (f.note) {
      const note = String(f.note).slice(0, 4000);
      const enc = JSON.stringify(note);
      if (enc.length <= maxNoteBytes(env)) { await env.STORE.put('note:' + p, enc); notesWritten++; }
    }
  }
  if (applyFav && Array.isArray(data.favorites) && data.favorites.length) {
    let favs = (await getFavs(env)).slice();
    const before = favs.length;
    for (const p of data.favorites.slice(0, 5000)) {
      const k = '/' + String(p).replace(/^\/+/, '');
      if (favs.indexOf(k) < 0 && favs.length < 5000) favs.push(k);
    }
    favAdded = favs.length - before;
    if (favAdded) {
      await env.STORE.put('meta:favs', JSON.stringify(favs));
      kvInvalidate('meta:favs');
    }
  }
  kvInvalidate('tagcounts');
  return json({ ok: true, matched, missing, tagsWritten, notesWritten, favAdded, mode, considered: limit });
}

// ===== Auth =====
// 统一鉴权：会话令牌（rw）或访问令牌（ro/rw）；也支持 Authorization: Bearer
// 注意：query 里的 token 可能另有用途（例如 /api/share-stats?token=<分享令牌>），
// 因此两个来源都要尝试，不能只认 query。
async function authInfo(env, req) {
  const cands = [];
  try { const q = new URL(req.url).searchParams.get('token'); if (q) cands.push(q); } catch (e) {}
  try {
    const a = req.headers.get('Authorization') || '';
    if (a.startsWith('Bearer ')) { const b = a.substring(7).trim(); if (b && cands.indexOf(b) < 0) cands.push(b); }
  } catch (e) {}
  if (!cands.length) return { ok: false, perm: '' };
  for (const t of cands) {
    try {
      // 会话读取是每个请求的固定开销，默认缓存 10 秒（SESSION_CACHE_SEC=0 可关闭）
      const s = await kvCached('session@' + t, sessionCacheSec(env), async () => {
        try { return await env.STORE.get('session:' + t, 'json'); } catch (e) { return null; }
      });
      if (s && Date.now() < s.exp) return { ok: true, perm: 'rw', kind: 'session' };
    } catch (e) {}
  }
  try {
    const tokens = await getAccessTokens(env);
    for (const t of cands) {
      const found = tokens.find(x => safeEqual(x.token, t));
      if (found) {
        if (found.exp && Date.now() > new Date(found.exp).getTime()) continue;
        return { ok: true, perm: found.perm === 'ro' ? 'ro' : 'rw', kind: 'token' };
      }
    }
  } catch (e) {}
  return { ok: false, perm: '' };
}
async function checkAuth(env, req) {
  const a = await authInfo(env, req);
  return a.ok;
}
// ===== 防外链：签名直链（HMAC-SHA256，可绑定请求 IP）=====
async function signSecretValue(env) {
  const s = (env && (env.URL_SIGN_SECRET || env.DRIVE_PASSWORD)) || '';
  if (s) return String(s);
  try { const rec = await adminPasswordRec(env); if (rec && rec.hash) return String(rec.hash); } catch (e) {}
  return 'personal-drive-default-sign-key';
}
async function signPath(env, key, expSec, ip) {
  const secret = await signSecretValue(env);
  const enc = new TextEncoder();
  const mac = await hmacSha256(enc.encode(secret), enc.encode(key + '|' + expSec + '|' + (ip || '')));
  return Array.from(mac).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 40);
}
async function verifySignedUrl(env, req, key) {
  try {
    const u = new URL(req.url);
    const exp = parseInt(u.searchParams.get('exp') || '0', 10);
    const sig = String(u.searchParams.get('sig') || '');
    if (!exp || !sig) return { ok: false };
    if (Math.floor(Date.now() / 1000) > exp) return { ok: false, reason: 'expired' };
    const bind = String(u.searchParams.get('ip') || '');
    if (bind) {
      const reqIp = req.headers.get('CF-Connecting-IP') || '';
      if (bind !== reqIp) return { ok: false, reason: 'ip' };
    }
    return (safeEqual(await signPath(env, key, exp, bind), sig)) ? { ok: true } : { ok: false, reason: 'sig' };
  } catch (e) { return { ok: false }; }
}
async function handleSign(env, req, path, ttl, bindIp) {
  const key = String(path || '').replace(/^\/+/, '');
  if (!key) return json({ error: 'Bad path' }, 400);
  const ttlSec = Math.min(Math.max(parseInt(ttl, 10) || 3600, 60), 30 * 86400);
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  const ip = bindIp ? (req.headers.get('CF-Connecting-IP') || '') : '';
  const sig = await signPath(env, key, exp, ip);
  const q = 'exp=' + exp + '&sig=' + sig + (ip ? '&ip=' + encodeURIComponent(ip) : '');
  return json({
    ok: true, exp, ttl: ttlSec, bound: ip || null,
    url: '/api/download?path=' + encodeURIComponent('/' + key) + '&' + q,
    preview: '/api/preview?path=' + encodeURIComponent('/' + key) + '&' + q
  });
}

// ===== 审计日志：筛选与 CSV 导出 =====
async function handleLogs(env, q) {
  const logs = await getLogs(env);
  const action = String((q && q.action) || '');
  const kw = String((q && q.q) || '').toLowerCase();
  const from = (q && q.from) ? Date.parse(q.from) : 0;
  const to = (q && q.to) ? Date.parse(q.to) + 86399999 : 0;
  const limit = Math.min(Math.max(parseInt((q && q.limit) || 200, 10) || 200, 1), 1000);
  const out = logs.filter(l => {
    if (action && l.action !== action) return false;
    if (kw && (String(l.path || '') + ' ' + String(l.detail || '')).toLowerCase().indexOf(kw) < 0) return false;
    const ts = Date.parse(l.time || '') || 0;
    if (from && ts < from) return false;
    if (to && ts > to) return false;
    return true;
  }).slice(0, limit);
  const actions = {};
  for (const l of logs) actions[l.action || '?'] = (actions[l.action || '?'] || 0) + 1;
  return json({ logs: out, total: logs.length, shown: out.length, actions });
}
function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
async function handleLogsCsv(env) {
  const logs = await getLogs(env);
  const rows = [['time', 'action', 'path', 'detail']].concat(logs.map(l => [l.time, l.action, l.path, l.detail]));
  const csv = '\ufeff' + rows.map(r => r.map(csvCell).join(',')).join('\r\n');
  return new Response(csv, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="drive-log.csv"', 'Cache-Control': 'private, no-store' } });
}

// 从请求中提取用于限流的令牌（解析方式与 authInfo 保持一致：优先 ?token，其次 Authorization: Bearer）
function extractToken(req) {
  let t = '';
  try { t = new URL(req.url).searchParams.get('token') || ''; } catch (e) {}
  if (!t) { const a = (req.headers && req.headers.get && req.headers.get('Authorization')) || ''; if (a.startsWith('Bearer ')) t = a.substring(7).trim(); }
  return t;
}
// 按令牌限流配置（每分钟读写次数，可用环境变量覆盖；DO 未配置时跳过）
function rlReadPerMin(env) { return Math.floor(cfgNum(env, 'RL_READ_PER_MIN', 'rlReadPerMin', 150)); }
function rlWritePerMin(env) { return Math.floor(cfgNum(env, 'RL_WRITE_PER_MIN', 'rlWritePerMin', 30)); }
function rlStub(env, token) { return env.DIR.get(env.DIR.idFromName('__rl__:' + (token || 'anon'))); }
// 令牌桶限流：读/写各一个桶，按时间回填；DO 故障或超时时放行（fail-open），避免误伤正常请求
async function rateLimitCheck(env, token, isWrite) {
  if (!hasDO(env)) return { limited: false };
  const rpm = isWrite ? rlWritePerMin(env) : rlReadPerMin(env);
  try {
    const r = await withTimeout(rlStub(env, token).fetch('https://dir/rl', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isWrite, rpm })
    }), 3000);
    if (r && r.ok) { const d = await r.json(); return { limited: !d.ok, retryAfter: d.retryAfter || 1 }; }
  } catch (e) { console.warn('DO rl → allow:', e && e.message); }
  return { limited: false };
}
async function makeSession(env, req) {
  const t = randToken();
  const ci = req ? clientInfo(req) : {};
  await env.STORE.put('session:' + t, JSON.stringify({
    exp: Date.now() + SESSION_TTL * 1000, created: Date.now(),
    ip: ci.ip || '', browser: ci.browser || '', os: ci.os || '', device: ci.device || ''
  }), { expirationTtl: SESSION_TTL + 60 });
  return t;
}
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}
// 管理员密码：优先用 KV 里的自定义密码，未设置时回退到环境变量 DRIVE_PASSWORD
async function adminPasswordRec(env) {
  try { return await env.STORE.get('meta:adminpass', 'json'); } catch (e) { return null; }
}
async function adminPasswordSet(env) {
  const rec = await adminPasswordRec(env);
  return !!(rec && rec.hash);
}
async function checkAdminPassword(env, pw) {
  const rec = await adminPasswordRec(env);
  if (rec && rec.hash) {
    const ok = await verifyPassword(pw || '', rec);
    // L1: 兼容历史无盐记录，验证通过后自动迁移为带盐哈希
    if (ok && !rec.salt) {
      const salt = randToken().substring(0, 16);
      const hash = await hashPassword(String(pw || ''), salt);
      try { await env.STORE.put('meta:adminpass', JSON.stringify({ hash, salt })); } catch (e) {}
    }
    return ok;
  }
  const expected = env.DRIVE_PASSWORD;
  if (!expected) return false;
  return safeEqual(pw || '', expected);
}
async function handleAdminPassGet(env) {
  return json({ usingKv: await adminPasswordSet(env), envSet: !!env.DRIVE_PASSWORD });
}

// ===== TOTP 双因素（RFC 6238）=====
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const s = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totpAt(secretB32, offsetSteps) {
  const key = base32Decode(secretB32);
  if (!key.length) return '';
  const counter = Math.floor(Date.now() / 1000 / 30) + (offsetSteps || 0);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 4294967296));
  dv.setUint32(4, counter >>> 0);
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, buf));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | ((mac[off + 1] & 0xff) << 16) | ((mac[off + 2] & 0xff) << 8) | (mac[off + 3] & 0xff);
  return String(bin % 1000000).padStart(6, '0');
}
async function totpVerify(secretB32, code) {
  const c = String(code || '').replace(/\D/g, '');
  if (c.length !== 6 || !secretB32) return false;
  for (const off of [-1, 0, 1]) {
    if (safeEqual(await totpAt(secretB32, off), c)) return true;
  }
  return false;
}
function makeBackupCodes(n) {
  const out = [];
  for (let i = 0; i < (n || 8); i++) {
    const raw = randToken().substring(0, 8).toUpperCase();
    out.push(raw.substring(0, 4) + '-' + raw.substring(4, 8));
  }
  return out;
}
async function totpRecord(env) {
  try { return await env.STORE.get('meta:totp', 'json'); } catch (e) { return null; }
}
async function totpEnabled(env) {
  const r = await totpRecord(env);
  return !!(r && r.enabled && r.secret);
}
// 校验动态码或一次性备用码（备用码用过即失效）
async function totpCheck(env, code) {
  const rec = await totpRecord(env);
  if (!rec || !rec.enabled || !rec.secret) return { ok: true, kind: 'off' };
  const c = String(code || '').trim();
  if (!c) return { ok: false, error: 'Missing code' };
  if (await totpVerify(rec.secret, c)) return { ok: true, kind: 'totp' };
  const h = await sha256(c.toUpperCase().replace(/[^A-Z0-9]/g, ''));
  const list = Array.isArray(rec.backup) ? rec.backup : [];
  const idx = list.findIndex(x => safeEqual(x, h));
  if (idx >= 0) {
    list.splice(idx, 1);
    rec.backup = list;
    try { await env.STORE.put('meta:totp', JSON.stringify(rec)); } catch (e) {}
    return { ok: true, kind: 'backup', left: list.length };
  }
  return { ok: false, error: 'Wrong code' };
}
async function handleTotpGet(env) {
  const rec = await totpRecord(env);
  return json({
    enabled: !!(rec && rec.enabled),
    pending: !!(rec && rec.secret && !rec.enabled),
    backupLeft: (rec && Array.isArray(rec.backup)) ? rec.backup.length : 0,
    created: (rec && rec.created) || ''
  });
}
async function handleTotpSetup(env, label) {
  const rec = (await totpRecord(env)) || {};
  if (rec.enabled) return json({ error: 'Already enabled' }, 400);
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const secret = base32Encode(bytes);
  const next = Object.assign({}, rec, { secret, enabled: false, created: new Date().toISOString() });
  await env.STORE.put('meta:totp', JSON.stringify(next));
  const name = String(label || 'PersonalDrive').replace(/[^A-Za-z0-9._-]/g, '') || 'PersonalDrive';
  const otpauth = 'otpauth://totp/' + encodeURIComponent(name) + '?secret=' + secret + '&issuer=' + encodeURIComponent(name) + '&algorithm=SHA1&digits=6&period=30';
  return json({ ok: true, secret, otpauth });
}
async function handleTotpEnable(env, code) {
  const rec = await totpRecord(env);
  if (!rec || !rec.secret) return json({ error: 'No pending secret' }, 400);
  if (rec.enabled) return json({ error: 'Already enabled' }, 400);
  if (!await totpVerify(rec.secret, code)) return json({ error: 'Wrong code' }, 403);
  const codes = makeBackupCodes(8);
  const hashes = [];
  for (const c of codes) hashes.push(await sha256(c.replace(/[^A-Z0-9]/g, '')));
  rec.enabled = true;
  rec.backup = hashes;
  rec.enabledAt = new Date().toISOString();
  await env.STORE.put('meta:totp', JSON.stringify(rec));
  try { await addLog(env, 'sec', '(二次验证)', 'TOTP enabled'); } catch (e) {}
  return json({ ok: true, backupCodes: codes });
}
async function handleTotpDisable(env, password, code) {
  if (!await checkAdminPassword(env, password || '')) return json({ error: 'Wrong password' }, 403);
  const v = await totpCheck(env, code);
  if (!v.ok) return json({ error: v.error || 'Wrong code' }, 403);
  try { await env.STORE.delete('meta:totp'); } catch (e) {}
  try { await addLog(env, 'sec', '(二次验证)', 'TOTP disabled'); } catch (e) {}
  return json({ ok: true });
}
async function handleTotpBackup(env, password, code) {
  if (!await checkAdminPassword(env, password || '')) return json({ error: 'Wrong password' }, 403);
  const rec = await totpRecord(env);
  if (!rec || !rec.enabled) return json({ error: 'TOTP not enabled' }, 400);
  if (!await totpVerify(rec.secret, code)) return json({ error: 'Wrong code' }, 403);
  const codes = makeBackupCodes(8);
  const hashes = [];
  for (const c of codes) hashes.push(await sha256(c.replace(/[^A-Z0-9]/g, '')));
  rec.backup = hashes;
  await env.STORE.put('meta:totp', JSON.stringify(rec));
  return json({ ok: true, backupCodes: codes });
}
async function handleAdminPassSet(env, current, next) {
  if (!next) return json({ error: 'Empty password' }, 400);
  if (!(await adminPasswordSet(env)) && !env.DRIVE_PASSWORD) return json({ error: 'Server not configured' }, 500);
  if (!await checkAdminPassword(env, current || '')) return json({ error: 'Wrong current password' }, 403);
  const salt = randToken().substring(0, 16);
  const hash = await hashPassword(String(next), salt);
  await env.STORE.put('meta:adminpass', JSON.stringify({ hash, salt }));
  // 修改密码后让所有旧会话失效
  try {
    const keys = await listKV(env, 'session:', 1000);
    for (const k of keys) { try { await env.STORE.delete(k); } catch (e) {} }
    kvInvalidate('session@');
  } catch (e) {}
  return json({ ok: true });
}

// ===== IP 黑/白名单（可选环境变量 IP_ALLOW / IP_DENY） =====
function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || ''));
  if (!m) return null;
  const a = +m[1], b = +m[2], c = +m[3], d = +m[4];
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  return (((a << 24) >>> 0) + (b << 16) + (c << 8) + d) >>> 0;
}
function ipMatch(ip, rule) {
  const r = String(rule || '').trim();
  if (!ip || !r) return false;
  if (r.indexOf('/') >= 0) {
    const parts = r.split('/');
    const bits = parseInt(parts[1], 10);
    const a = ipToInt(ip), n = ipToInt(parts[0]);
    if (a == null || n == null || !Number.isFinite(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
    return ((a & mask) >>> 0) === ((n & mask) >>> 0);
  }
  return ip === r || String(ip).indexOf(r) === 0;
}
function ipAllowed(env, ip) {
  const allow = csvList(cfgStr(env, 'IP_ALLOW', 'ipAllow', ''));
  const deny = csvList(cfgStr(env, 'IP_DENY', 'ipDeny', ''));
  for (let i = 0; i < deny.length; i++) { if (ipMatch(ip, deny[i])) return false; }
  if (allow.length) { for (let i = 0; i < allow.length; i++) { if (ipMatch(ip, allow[i])) return true; } return false; }
  return true;
}
// ===== 地区 / User-Agent 风控（可选环境变量）=====
// COUNTRY_ALLOW / COUNTRY_DENY：ISO 国家码（逗号分隔，如 "CN,HK,TW"）
// UA_DENY / UA_ALLOW：User-Agent 关键字（逗号分隔，大小写不敏感）
function csvList(v) { return String(v == null ? '' : v).split(',').map(s => s.trim()).filter(Boolean); }
function countryAllowed(env, country) {
  const allow = csvList(cfgStr(env, 'COUNTRY_ALLOW', 'countryAllow', '')).map(s => s.toUpperCase());
  const deny = csvList(cfgStr(env, 'COUNTRY_DENY', 'countryDeny', '')).map(s => s.toUpperCase());
  const c = String(country || '').toUpperCase();
  if (c && deny.indexOf(c) >= 0) return false;
  if (allow.length) return !!c && allow.indexOf(c) >= 0;
  return true;
}
function uaAllowed(env, ua) {
  const allow = csvList(cfgStr(env, 'UA_ALLOW', 'uaAllow', '')).map(s => s.toLowerCase());
  const deny = csvList(cfgStr(env, 'UA_DENY', 'uaDeny', '')).map(s => s.toLowerCase());
  const u = String(ua || '').toLowerCase();
  for (const d of deny) { if (d && u.indexOf(d) >= 0) return false; }
  if (allow.length) { for (const a of allow) { if (a && u.indexOf(a) >= 0) return true; } return false; }
  return true;
}
function requestAllowed(env, req) {
  const ip = (req && req.headers.get('CF-Connecting-IP')) || '';
  if (!ipAllowed(env, ip)) return { ok: false, reason: 'ip' };
  const country = (req && req.cf && req.cf.country) || '';
  if (!countryAllowed(env, country)) return { ok: false, reason: 'country' };
  const ua = (req && req.headers.get('User-Agent')) || '';
  if (!uaAllowed(env, ua)) return { ok: false, reason: 'ua' };
  return { ok: true };
}
// 新设备/新地区登录提醒（只保留最近 50 条 ip|country，1 读 1 写，登录才触发）
async function loginSeenCheck(env, req) {
  try {
    const ci = clientInfo(req);
    const key = (ci.ip || '') + '|' + (ci.country || '');
    if (!ci.ip) return true;
    const rec = (await kvCached('meta:loginseen', 5, async () => {
      try { return await env.STORE.get('meta:loginseen', 'json') || []; } catch (e) { return []; }
    })) || [];
    const known = rec.some(x => x === key);
    if (!known) {
      const next = [key].concat(rec).slice(0, 50);
      try { await env.STORE.put('meta:loginseen', JSON.stringify(next), { expirationTtl: 180 * 86400 }); } catch (e) {}
      kvInvalidate('meta:loginseen');
      try { await notifyWebhook(env, { event: 'login', path: '/', detail: '新设备登录 ' + key + ' ' + (ci.browser || '') + '/' + (ci.os || '') }); } catch (e) {}
    }
    return !known;
  } catch (e) { return true; }
}

// ===== 会话 / 设备管理 =====
async function handleListSessions(env, currentToken) {
  const keys = await listKV(env, 'session:', 200);
  const out = [];
  for (const k of keys) {
    try {
      const s = await env.STORE.get(k, 'json');
      if (!s) continue;
      const tok = k.substring(8);
      out.push({
        id: tok.substring(0, 12),
        ip: s.ip || '', browser: s.browser || '', os: s.os || '', device: s.device || '',
        created: s.created || 0, exp: s.exp || 0,
        current: !!(currentToken && tok === currentToken)
      });
    } catch (e) {}
  }
  out.sort((a, b) => b.created - a.created);
  return json({ sessions: out, ipAllow: String((env && env.IP_ALLOW) || ''), ipDeny: String((env && env.IP_DENY) || '') });
}
async function handleRevokeSession(env, id, all) {
  const keys = await listKV(env, 'session:', 300);
  let n = 0;
  for (const k of keys) {
    const tok = k.substring(8);
    if (all || (id && tok.indexOf(String(id)) === 0)) {
      try { await env.STORE.delete(k); n++; } catch (e) {}
    }
  }
  kvInvalidate('session@');
  return json({ ok: true, revoked: n });
}

// ===== Folder lock =====
async function isPathLocked(env, dirPath, sessionToken) {
  dirPath = normPath(dirPath);
  // 先看"目录锁前缀列表"（带缓存）：没有锁时零 KV 读，避免每层路径一次 get
  let all;
  try { all = await getLockedPrefixes(env); } catch (e) { all = new Set(); }
  if (!all.size) return false;
  const locked = [];
  for (const lp of all) {
    if (lp === '/' || dirPath === lp || dirPath.startsWith(lp)) locked.push(lp);
  }
  if (!locked.length) return false;
  if (!sessionToken) return true;
  for (const lp of locked) {
    try {
      const u = await kvCached('unlock@' + sessionToken + ':' + lp, 10, async () => {
        try { return await env.STORE.get('unlock:' + sessionToken + ':' + lp, 'json'); } catch (e) { return null; }
      });
      if (!u || Date.now() >= u.exp) return true;
    } catch (e) { return true; }
  }
  return false;
}
async function guard(env, req, ...paths) {
  // 会话令牌同时支持 ?token= 与 Authorization: Bearer（否则用头鉴权时锁目录永远解不开）
  const st = extractToken(req);
  for (const p of paths) {
    if (!p) continue;
    const np = normPath(p);
    if (await isPathLocked(env, np, st)) return json({ locked: true, path: np }, 423);
  }
  return null;
}

// 收集被密码保护的目录，用于全局扫描接口过滤，避免泄露锁定目录内容
// （LIST 属于较贵的操作，带 20 秒隔离级缓存；设置/移除目录密码时失效）
async function getLockedPrefixes(env) {
  const arr = await kvCached('dirpass-list', 20, async () => {
    const set = new Set();
    try {
      let cursor;
      do {
        const res = await env.STORE.list({ prefix: 'dirpass:', cursor, limit: 1000 });
        for (const k of res.keys) set.add(k.name.substring('dirpass:'.length));
        cursor = res.list_complete ? undefined : res.cursor;
      } while (cursor);
    } catch (e) {}
    return Array.from(set);
  });
  return new Set(arr);
}
async function unlockedPrefixes(env, sessionToken) {
  const locked = await getLockedPrefixes(env);
  if (!sessionToken) return locked;
  const out = new Set();
  for (const lp of locked) {
    try {
      const u = await env.STORE.get('unlock:' + sessionToken + ':' + lp, 'json');
      if (u && Date.now() < u.exp) continue;
    } catch (e) {}
    out.add(lp);
  }
  return out;
}
function insideLocked(p, locked) {
  for (const lp of locked) {
    if (lp === '/') return true;                 // 根目录锁：所有路径都在其内
    if (p !== lp && p.startsWith(lp)) return true;
  }
  return false;
}
// p 自身是否就是被锁目录（用于"是否继续向下遍历"的判断）
function isLockedPrefix(p, locked) {
  for (const lp of locked) { if (lp === '/' || p === lp) return true; }
  return false;
}

// ===== Thumb =====
async function deleteThumb(env, key) { try { await env.DRIVE.delete(THUMB_PREFIX + key); } catch (e) {} }
async function moveThumb(env, oldKey, newKey) {
  try {
    const to = await env.DRIVE.get(THUMB_PREFIX + oldKey);
    if (to) {
      await env.DRIVE.put(THUMB_PREFIX + newKey, to.body, { httpMetadata: to.httpMetadata });
      await env.DRIVE.delete(THUMB_PREFIX + oldKey);
    }
  } catch (e) {}
}

// ===== Version history =====
async function listVersions(env, key) { try { return await env.STORE.get('versions:' + key, 'json') || []; } catch (e) { return []; } }
async function pushVersion(env, key, entry) {
  try {
    const oldObj = await env.DRIVE.get(key);
    if (!oldObj) return null;
    // R2 防爆：大文件不保留历史版本（否则每次覆盖都会让占用成倍增长）
    if ((oldObj.size || 0) > versionMaxBytes(env)) return null;
    const ts = Date.now();
    const vKey = VERSIONS_PREFIX + key + '/' + ts;
    await env.DRIVE.put(vKey, oldObj.body, { httpMetadata: oldObj.httpMetadata });
    let list = await listVersions(env, key);
    list.unshift({ ts, size: (entry && entry.size) || 0, mime: (entry && entry.mime) || '' });
    const maxV = maxVersions(env);
    while (list.length > maxV) {
      const old = list.pop();
      try { await env.DRIVE.delete(VERSIONS_PREFIX + key + '/' + old.ts); } catch (e) {}
    }
    // 版本索引加 TTL，避免长期不动的文件永久占用 KV
    await env.STORE.put('versions:' + key, JSON.stringify(list), { expirationTtl: versionsTtl(env) });
    return ts;
  } catch (e) { return null; }
}
async function deleteVersions(env, key) {
  try {
    const list = await listVersions(env, key);
    for (const v of list) { try { await env.DRIVE.delete(VERSIONS_PREFIX + key + '/' + v.ts); } catch (e) {} }
    await env.STORE.delete('versions:' + key);
  } catch (e) {}
}
async function moveVersions(env, oldKey, newKey) {
  try {
    const list = await listVersions(env, oldKey);
    if (!list.length) return;
    for (const v of list) {
      try {
        const o = await env.DRIVE.get(VERSIONS_PREFIX + oldKey + '/' + v.ts);
        if (o) {
          await env.DRIVE.put(VERSIONS_PREFIX + newKey + '/' + v.ts, o.body, { httpMetadata: o.httpMetadata });
          await env.DRIVE.delete(VERSIONS_PREFIX + oldKey + '/' + v.ts);
        }
      } catch (e) {}
    }
    await env.STORE.put('versions:' + newKey, JSON.stringify(list), { expirationTtl: versionsTtl(env) });
    await env.STORE.delete('versions:' + oldKey);
  } catch (e) {}
}

// ===== API =====
async function handleLogin(req, env) {
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
  const bumpFail = async (loginUser) => {
    try {
      const attempts = JSON.parse(await env.STORE.get('login:' + ip) || '{"n":0,"t":0}');
      attempts.n = Date.now() - attempts.t > 300000 ? 1 : attempts.n + 1;
      attempts.t = Date.now();
      await env.STORE.put('login:' + ip, JSON.stringify(attempts), { expirationTtl: 600 });
      if (loginUser) {
        const ua = JSON.parse(await env.STORE.get('login:u:' + loginUser) || '{"n":0,"t":0}');
        ua.n = Date.now() - ua.t > 300000 ? 1 : ua.n + 1;
        ua.t = Date.now();
        await env.STORE.put('login:u:' + loginUser, JSON.stringify(ua), { expirationTtl: 600 });
      }
    } catch (e) {}
  };
  try {
    const attempts = JSON.parse(await env.STORE.get('login:' + ip) || '{"n":0,"t":0}');
    if (attempts.n >= 5 && Date.now() - attempts.t < 300000) return json({ error: 'Too many attempts, wait 5min' }, 429);
  } catch (e) {}
  const form = await req.formData();
  // M1: 增加用户名级限频，防定向爆破
  const loginUser = String(form.get('username') || '');
  if (loginUser) {
    try {
      const ua = JSON.parse(await env.STORE.get('login:u:' + loginUser) || '{"n":0,"t":0}');
      if (ua.n >= 5 && Date.now() - ua.t < 300000) return json({ error: 'Too many attempts, wait 5min' }, 429);
    } catch (e) {}
  }
  const configured = (await adminPasswordSet(env)) || !!env.DRIVE_PASSWORD;
  if (!configured) return json({ error: 'Server not configured' }, 500);
  if (!await checkAdminPassword(env, form.get('password') || '')) {
    await bumpFail(loginUser);
    return json({ error: 'Wrong password' }, 401);
  }
  // 二次验证：启用后必须提供动态码或一次性备用码（失败同样计入爆破限频）
  if (await totpEnabled(env)) {
    const v = await totpCheck(env, form.get('code') || '');
    if (!v.ok) {
      await bumpFail(loginUser);
      return json({ error: v.error || 'Wrong code', totp: true }, 401);
    }
  }
  await env.STORE.delete('login:' + ip); if (loginUser) { try { await env.STORE.delete('login:u:' + loginUser); } catch (e) {} }
  // 新设备/新地区登录提醒（webhook）
  try { await loginSeenCheck(env, req); } catch (e) {}
  return json({ token: await makeSession(env, req) });
}

async function handleList(env, path, withSize, sessionToken) {
  path = normPath(path);
  const locked = await isPathLocked(env, path, sessionToken);
  if (locked) return json({ locked: true, path });
  const items = await getDir(env, path);
  if (withSize) {
    for (const it of items) {
      if (it.type !== 'dir') continue;
      const sub = path + it.name + '/';
      if (await isPathLocked(env, sub, sessionToken)) continue;
      it.dirSize = await calcDirSize(env, sub);
    }
  }
  return json({ path, items });
}

async function handleUnlockDir(env, sessionToken, dirPath, password) {
  dirPath = normPath(dirPath);
  const pass = await env.STORE.get('dirpass:' + dirPath, 'json');
  if (!pass) return json({ ok: true });
  if (!await verifyPassword(password || '', pass)) return json({ error: 'Wrong password' }, 403);
  // L1: 目录密码同样支持无盐记录自动迁移
  if (!pass.salt) {
    const salt = randToken().substring(0, 16);
    const hash = await hashPassword(String(password || ''), salt);
    try { await env.STORE.put('dirpass:' + dirPath, JSON.stringify({ hash, salt })); } catch (e) {}
  }
  await env.STORE.put('unlock:' + sessionToken + ':' + dirPath, JSON.stringify({ path: dirPath, exp: Date.now() + 3600000 }), { expirationTtl: 3700 });
  kvInvalidate('unlock@' + sessionToken + ':' + dirPath);
  return json({ ok: true });
}

async function ensureDir(env, parentPath, name) {
  const res = await findDirItem(env, parentPath, name);
  if (!res.item || res.item.type !== 'dir') {
    await upsertDirItem(env, parentPath, { name, type: 'dir', time: new Date().toISOString() });
  }
}

async function handleUpload(req, env, path) {
  path = normPath(path);
  const form = await req.formData();
  const file = form.get('file');
  const thumb = form.get('thumb');
  const relPath = (form.get('relPath') || '').toString().replace(/^\/+/, '');
  if (!file || typeof file === 'string') return json({ error: 'No file' }, 400);
  if (file.size > maxUploadBytes(env)) return json({ error: 'File too large', max: maxUploadBytes(env) }, 413);

  let uploadDir = path;
  if (relPath) {
    const parts = relPath.split('/').filter(Boolean);
    parts.pop();
    let cur = path;
    for (const raw of parts) {
      const safe = sanitizeName(raw);
      if (!safe) continue;
      await ensureDir(env, cur, safe);
      cur = cur + safe + '/';
    }
    uploadDir = cur;
  }

  const safeName = sanitizeName(file.name);
  const clientHash = String(form.get('hash') || '');
  uploadDir = await applyAutoArchive(env, uploadDir, safeName, file.type || '');
  const key = uploadDir.replace(/^\//, '') + safeName;
  if (pathTooLong('/' + key)) return json({ error: 'Path too long', max: PATH_MAX }, 400);

  const oldRes = await findDirItem(env, uploadDir, safeName);
  const oldItem = oldRes.item;
  if (!oldItem) {
    const ruleChk = await checkDirRule(env, uploadDir, safeName, file.size);
    if (ruleChk) return json({ error: ruleChk.error }, 403);
    const room = await dirRoom(env, uploadDir, 1);
    if (room) return json({ error: room.error, limit: room.limit }, 507);
  }
  const upDelta = file.size - (oldItem ? (oldItem.size || 0) : 0);
  if (upDelta > 0) {
    const u = await getUsage(env);
    if ((u.used || 0) + upDelta > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  }
  let versionTs = null;
  if (oldItem) versionTs = await pushVersion(env, key, oldItem);

  const putRes = await putAndMirror(env, key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
  const etag = (putRes && putRes.etag) ? String(putRes.etag).replace(/"/g, '') : '';

  let hasThumb = false;
  if (thumb && typeof thumb !== 'string') {
    try {
      await env.DRIVE.put(THUMB_PREFIX + key, thumb.stream(), { httpMetadata: { contentType: 'image/jpeg' } });
      hasThumb = true;
    } catch (e) {}
  }

  try {
    const entry = { name: safeName, type: 'file', size: file.size, mime: file.type || '', time: new Date().toISOString(), hash: etag, hasThumb };
    const up = await upsertDirItem(env, uploadDir, entry);
    if (up && up.ok === false) { const err = new Error(up.error || 'Metadata rejected'); err.dirFull = true; err.limit = up.limit; throw err; }
    if (isHex64(clientHash)) { try { await env.STORE.put('hash:' + clientHash, JSON.stringify({ key, time: Date.now() }), { expirationTtl: hashTtl(env) }); } catch (e) {} }
    if (oldItem) {
      if (oldItem.hasThumb && !hasThumb) await deleteThumb(env, key);
      await addUsage(env, file.size - (oldItem.size || 0), 0);
    } else {
      await addUsage(env, file.size, 1);
      await addLog(env, 'up', uploadDir + safeName, file.size + ' bytes');
    }
  } catch (e) {
    // 元数据写入失败：回滚对象。若覆盖的是旧文件，先把旧内容从历史版本恢复回去，
    // 否则目录条目会指向一个已被删除的 key（文件"消失"）。
    let restored = false;
    if (oldItem && versionTs) {
      try {
        const v = await env.DRIVE.get(VERSIONS_PREFIX + key + '/' + versionTs);
        if (v) { await putAndMirror(env, key, v.body, { httpMetadata: v.httpMetadata }); restored = true; }
      } catch (e2) {}
    }
    if (!restored) { try { await deleteAndMirror(env, key); } catch (e2) {} }
    if (!hasThumb) await deleteThumb(env, key);
    if (e && e.dirFull) return json({ error: e.message, limit: e.limit }, 507);
    return json({ error: 'Metadata update failed' }, 500);
  }
  return json({ ok: true, hasThumb, dir: uploadDir });
}

async function handleDownload(env, req, path) {
  const key = path.replace(/^\/+/, '');
  const name = key.split('/').pop();
  let size = 0;
  try { const h = await env.DRIVE.head(key); if (!h) return json({ error: 'Not found' }, 404); size = h.size; } catch (e) {}
  const res = await serveObject(env, req, key, { disposition: 'attachment; filename="' + encodeURIComponent(name) + '"' });
  if (res.status === 200) {
    await addDownloadLog(env, Object.assign({ time: new Date().toISOString(), path: '/' + key, name, size, source: 'web' }, clientInfo(req)));
  }
  return res;
}

async function handlePreview(env, req, path) {
  const key = path.replace(/^\/+/, '');
  return serveObject(env, req, key, { disposition: 'inline', sanitize: true, cacheControl: 'private, max-age=3600' });
}

async function handleThumb(env, req, path) {
  const key = path.replace(/^\/+/, '');
  return serveObject(env, req, THUMB_PREFIX + key, { cacheControl: 'private, max-age=86400' });
}

async function handleSaveText(env, path, content) {
  if (typeof content !== 'string') return json({ error: 'Bad content' }, 400);
  if (content.length > 2 * 1024 * 1024) return json({ error: 'Text too large' }, 413);
  const norm = normPath('/' + String(path || '').replace(/^\/+/, ''));
  const dir = parentOf(norm);
  const name = sanitizeName(norm.split('/').filter(Boolean).pop() || 'untitled');
  const key = dir.replace(/^\//, '') + name;
  if (pathTooLong(dir + name)) return json({ error: 'Path too long', max: PATH_MAX }, 400);
  const size = new TextEncoder().encode(content).byteLength;

  const oldRes = await findDirItem(env, dir, name);
  const oldItem = oldRes.item;
  if (!oldItem) {
    const room = await dirRoom(env, dir, 1);
    if (room) return json({ error: room.error, limit: room.limit }, 507);
  }
  const delta = size - (oldItem ? (oldItem.size || 0) : 0);
  if (delta > 0) {
    const u = await getUsage(env);
    if ((u.used || 0) + delta > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  }
  if (oldItem) await pushVersion(env, key, oldItem);

  const putRes = await putAndMirror(env, key, content, { httpMetadata: { contentType: 'text/plain' } });
  const etag = (putRes && putRes.etag) ? String(putRes.etag).replace(/"/g, '') : '';

  const old = oldItem || {};
  const entry = {
    name, type: 'file', size, mime: 'text/plain',
    time: new Date().toISOString(),
    hash: etag || old.hash || '',
    hasThumb: !!old.hasThumb
  };
  await upsertDirItem(env, dir, entry);
  if (oldItem) {
    await addUsage(env, size - (oldItem.size || 0), 0);
  } else {
    await addUsage(env, size, 1);
    try { await addLog(env, 'up', dir + name, size + ' bytes (text)'); } catch (e) {}
  }
  return json({ ok: true });
}

async function handleDelete(env, path) {
  path = '/' + path.replace(/^\/+/, '');
  const dir = parentOf(path); const name = path.split('/').filter(Boolean).pop();
  const res = await findDirItem(env, dir, name);
  const entry = res.item;
  if (!entry) return json({ error: 'Not found' }, 404);

  // M4: 锁定子树检查必须在移除目录条目之前，否则会返回 423 而条目已经被删掉
  const dirPath = path.replace(/\/+$/, '') + '/';   // 统一成单个尾斜杠，避免记录出 "/box//"
  if (entry.type === 'dir') {
    const lockedSub = await hasLockedSubtree(env, dirPath);
    if (lockedSub) return json({ error: 'Locked', path: lockedSub }, 423);
  }

  await removeDirItem(env, dir, name);
  const deletedAt = new Date().toISOString();

  if (entry.type === 'dir') {
    // 目录删除进入回收站（可恢复）：整体搬入 /.trash/<id>/
    const tid = 'd' + randToken().substring(0, 8);
    await recursiveMoveDir(env, dirPath, TRASH_ROOT + tid + '/');
    const trash = await getDir(env, TRASH_ROOT);
    trash.push({ name, type: 'dir', size: entry.dirSize || 0, mime: '', originalPath: dirPath, deletedAt, id: tid });
    await putDir(env, TRASH_ROOT, trash);
    try { await addLog(env, 'del', dirPath, '目录 → 回收站'); } catch (e) {}
    return json({ ok: true });
  }

  // 文件删除同样把对象搬到 /.trash/<id>/<name>：避免原 key 被重新上传后被"清空回收站"误删
  const tid = 'f' + randToken().substring(0, 8);
  const srcKey = path.replace(/^\//, '');
  const trashKey = TRASH_PREFIX + tid + '/' + name;
  const moved = await copyObject(env, srcKey, trashKey);
  if (moved) { try { await mirrorDelete(env, srcKey); } catch (e) {} }
  await moveThumb(env, srcKey, trashKey);
  await deleteVersions(env, srcKey);
  const trash = await getDir(env, TRASH_ROOT);
  trash.push({ name, type: 'file', size: entry.size || 0, mime: entry.mime || '', originalPath: path, deletedAt, id: tid, trashKey: moved ? trashKey : '' });
  await putDir(env, TRASH_ROOT, trash);
  try { await addLog(env, 'del', path, (entry.size || 0) + ' bytes → 回收站'); } catch (e) {}
  try { await addDailyStat(env, 'del', entry.size || 0); } catch (e) {}
  return json({ ok: true });
}

// M4: 递归检查目录内是否存在已锁定子目录，返回首个锁定路径（无则 null）
async function hasLockedSubtree(env, dirPath) {
  const items = await getDir(env, dirPath);
  for (const it of items) {
    if (it.type !== 'dir') continue;
    const sub = dirPath + it.name + '/';
    if (await isPathLocked(env, sub, '')) return sub;
    const deeper = await hasLockedSubtree(env, sub);
    if (deeper) return deeper;
  }
  return null;
}
async function recursiveDeleteDir(env, dirPath) {
  const items = await getDir(env, dirPath);
  const BATCH = 10;
  const fileOps = items.filter(it => it.type === 'file');
  for (let i = 0; i < fileOps.length; i += BATCH) {
    const batch = fileOps.slice(i, i + BATCH);
    await Promise.all(batch.map(async it => {
      const k = dirPath.replace(/^\//, '') + it.name;
      await deleteAndMirror(env, k);
      await deleteThumb(env, k);
      await deleteVersions(env, k);
      try { await env.STORE.delete('note:/' + k); } catch (e) {}
    }));
  }
  if (fileOps.length) {
    await addUsage(env, -fileOps.reduce((s, it) => s + (it.size || 0), 0), -fileOps.length);
    await addLog(env, 'del', dirPath, fileOps.length + ' files');
  }
  const dirOps = items.filter(it => it.type === 'dir');
  for (let i = 0; i < dirOps.length; i += BATCH) {
    const batch = dirOps.slice(i, i + BATCH);
    await Promise.all(batch.map(async it => {
      const sub = dirPath + it.name + '/';
      // R4: 锁定子树跳过删除；目录删除幂等重试（最多 3 次，避免 KV 最终一致残留）
      if (await hasLockedSubtree(env, sub)) return;
      for (let attempt = 0; attempt < 3; attempt++) {
        await recursiveDeleteDir(env, sub);
        const remain = await getDir(env, sub);
        if (!remain.length) break;
        await new Promise(res => setTimeout(res, 300 * (attempt + 1)));
      }
    }));
  }
  await destroyDir(env, dirPath);
}

async function handleTrash(env) {
  // 顺手做一次有界的过期回收（即使用户没配 Cron 触发器，回收站也不会无限膨胀）
  try { await gcTrash(env, 20); } catch (e) {}
  const items = await getDir(env, TRASH_ROOT);
  const now = Date.now();
  const days = trashDays(env);
  const enriched = items.map(it => {
    const dt = it.deletedAt ? new Date(it.deletedAt).getTime() : now;
    const daysLeft = Math.max(0, days - Math.floor((now - (Number.isFinite(dt) ? dt : now)) / 86400000));
    return { ...it, daysLeft };
  });
  return json({ items: enriched });
}
// 过期回收站清理（cron 与访问时共用），返回清理条数
async function gcTrash(env, limit) {
  const trash = await getDir(env, TRASH_ROOT);
  const now = Date.now();
  const maxAge = trashDays(env) * 86400 * 1000;
  const keep = [];
  let purged = 0, totalSize = 0, removedAny = false, handled = 0;
  for (const item of trash) {
    const dt = item.deletedAt ? new Date(item.deletedAt).getTime() : 0;
    if (!Number.isFinite(dt) || dt <= 0) { keep.push(item); continue; }
    if (maxAge >= 0 && now - dt >= maxAge && handled < limit) {
      handled++;
      removedAny = true;
      if (item.type === 'dir' && item.id) {
        await recursiveDeleteDir(env, TRASH_ROOT + item.id + '/');   // 内部已扣减用量
      } else {
        const k = item.trashKey ? item.trashKey : String(item.originalPath || '').replace(/^\//, '');
        if (k) {
          await deleteAndMirror(env, k);
          await deleteThumb(env, k);
          if (!item.trashKey) await deleteVersions(env, k);
        }
        totalSize += item.size || 0; purged++;
      }
    } else { keep.push(item); }
  }
  if (removedAny) {
    await putDir(env, TRASH_ROOT, keep);
    if (purged > 0) await addUsage(env, -totalSize, -purged);
  }
  return handled;
}

async function handleRestore(env, id) {
  const trash = await getDir(env, TRASH_ROOT);
  let idx = trash.findIndex(i => i.id === id);
  if (idx < 0) idx = trash.findIndex(i => i.name === id);
  if (idx < 0) return { error: 'Not in trash', status: 404 };
  const entry = trash[idx];
  if (entry.type === 'dir') {
    // 恢复目录：把 /.trash/<id>/ 整体搬回 originalPath，并重建父目录引用
    const pdir = parentOf(entry.originalPath);
    const existing = await findDirItem(env, pdir, entry.name);
    if (existing.item) return { error: 'Name exists', status: 409 };
    if (entry.id) await recursiveMoveDir(env, TRASH_ROOT + entry.id + '/', entry.originalPath);
    await upsertDirItem(env, pdir, { name: entry.name, type: 'dir', time: entry.deletedAt, size: entry.size });
    trash.splice(idx, 1); await putDir(env, TRASH_ROOT, trash);
    try { await addLog(env, 'res', entry.originalPath, '从回收站恢复目录'); } catch (e) {}
    return { ok: true };
  }
  const dir = parentOf(entry.originalPath);
  const existing = await findDirItem(env, dir, entry.name);
  if (existing.item) return { error: 'Name exists', status: 409 };
  const srcKey = entry.originalPath.replace(/^\//, '');
  if (entry.trashKey) {
    const ok = await copyObject(env, entry.trashKey, srcKey);
    if (!ok) return { error: 'File content missing', status: 410 };
    await moveThumb(env, entry.trashKey, srcKey);
    try { await mirrorPut(env, srcKey); } catch (e) {}
  }
  await upsertDirItem(env, dir, { name: entry.name, type: entry.type, size: entry.size, mime: entry.mime, time: entry.deletedAt });
  trash.splice(idx, 1); await putDir(env, TRASH_ROOT, trash);
  try { await addLog(env, 'res', entry.originalPath, '从回收站恢复'); } catch (e) {}
  return { ok: true };
}

async function handleBatchRestore(env, ids) {
  let ok = 0, failed = 0;
  for (const id of (Array.isArray(ids) ? ids : [])) {
    try { const r = await handleRestore(env, id); if (r && r.ok) ok++; else failed++; } catch (e) { failed++; }
  }
  return json({ ok: true, restored: ok, failed });
}

async function handlePurge(env, id) {
  const trash = await getDir(env, TRASH_ROOT);
  // 回收站对象可能在 /.trash/<id>/<name>（新版），也可能是历史记录里的原始路径
  const purgeFile = async (item) => {
    const delKey = item.trashKey ? item.trashKey : String(item.originalPath || '').replace(/^\//, '');
    if (!delKey) return;
    await deleteAndMirror(env, delKey);
    await deleteThumb(env, delKey);
    if (!item.trashKey) await deleteVersions(env, delKey);
  };
  if (id === 'ALL') {
    let sz = 0, ct = 0;
    for (const item of trash) {
      if (item.type === 'dir' && item.id) {
        await recursiveDeleteDir(env, TRASH_ROOT + item.id + '/');  // 内部已扣减用量
      } else {
        await purgeFile(item);
        sz += item.size || 0; ct++;
      }
    }
    await putDir(env, TRASH_ROOT, []); await addUsage(env, -sz, -ct); return json({ ok: true });
  }
  let idx = trash.findIndex(i => i.id === id);
  if (idx < 0) idx = trash.findIndex(i => i.name === id);
  if (idx < 0) return json({ error: 'Not in trash' }, 404);
  const entry = trash[idx];
  if (entry.type === 'dir' && entry.id) {
    await recursiveDeleteDir(env, TRASH_ROOT + entry.id + '/');  // 内部已扣减用量
    trash.splice(idx, 1); await putDir(env, TRASH_ROOT, trash); return json({ ok: true });
  }
  await purgeFile(entry);
  trash.splice(idx, 1); await putDir(env, TRASH_ROOT, trash); await addUsage(env, -(entry.size || 0), -1); return json({ ok: true });
}

async function handleBatchPurge(env, ids) {
  for (const id of (Array.isArray(ids) ? ids : [])) { try { await handlePurge(env, id); } catch (e) {} }
  return json({ ok: true });
}

async function handleMkdir(env, path, name) {
  path = normPath(path);
  const safeName = sanitizeName(name);
  if (!safeName) return json({ error: 'Bad name' }, 400);
  if (pathTooLong(path + safeName + '/')) return json({ error: 'Path too long', max: PATH_MAX }, 400);
  const existing = await findDirItem(env, path, safeName);
  if (!existing.item) {
    const room = await dirRoom(env, path, 1);
    if (room) return json({ error: room.error, limit: room.limit }, 507);
  }
  const up = await upsertDirItem(env, path, { name: safeName, type: 'dir', time: new Date().toISOString() });
  if (up && up.ok === false) return json({ error: up.error, limit: up.limit }, 507);
  return json({ ok: true });
}

async function handleRename(env, oldPath, newName) {
  oldPath = '/' + oldPath.replace(/^\/+/, ''); newName = sanitizeName(newName);
  const dir = parentOf(oldPath); const oldName = oldPath.split('/').filter(Boolean).pop();

  const r = await renameDirItem(env, dir, oldName, newName);
  if (r.error) {
    return json({ error: r.error === 'exists' ? 'Name exists' : 'Not found' }, r.error === 'exists' ? 409 : 404);
  }
  const entry = r.item;

  if (entry.type === 'file') {
    const oldKey = oldPath.replace(/^\//, ''); const newKey = dir.replace(/^\//, '') + newName;
    const obj = await env.DRIVE.get(oldKey);
    if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); try { await mirrorPut(env, newKey); await mirrorDelete(env, oldKey); } catch (e) {} }
    await moveThumb(env, oldKey, newKey);
    await moveVersions(env, oldKey, newKey);
    await moveNote(env, oldKey, newKey);
    try {
      const tags = await env.STORE.get('tags:/' + oldKey, 'json');
      if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
    } catch (e) {}
  } else {
    await recursiveMoveDir(env, oldPath + '/', dir.replace(/^\//, '') + newName + '/');
  }
  try { await addLog(env, 'mov', oldPath, '重命名为 ' + newName); } catch (e) {}
  return json({ ok: true });
}

async function recursiveMoveDir(env, oldPrefix, newPrefix) {
  const items = await getDir(env, oldPrefix);
  for (const it of items) {
    if (it.type === 'file') {
      const oldKey = oldPrefix.replace(/^\//, '') + it.name;
      const newKey = newPrefix.replace(/^\//, '') + it.name;
      const obj = await env.DRIVE.get(oldKey);
      if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); try { await mirrorPut(env, newKey); await mirrorDelete(env, oldKey); } catch (e) {} }
      await moveThumb(env, oldKey, newKey);
      await moveVersions(env, oldKey, newKey);
      await moveNote(env, oldKey, newKey);
      try {
        const tags = await env.STORE.get('tags:/' + oldKey, 'json');
        if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
      } catch (e) {}
    } else if (it.type === 'dir') {
      await recursiveMoveDir(env, oldPrefix + it.name + '/', newPrefix + it.name + '/');
    }
  }
  await putDir(env, newPrefix, items || []);
  await destroyDir(env, oldPrefix);
  try {
    const dp = await env.STORE.get('dirpass:' + oldPrefix, 'json');
    if (dp) { await env.STORE.put('dirpass:' + newPrefix, JSON.stringify(dp)); await env.STORE.delete('dirpass:' + oldPrefix); kvInvalidate('dirpass-list'); }
  } catch (e) {}
}

async function handleMove(env, srcPath, targetDir) {
  srcPath = '/' + srcPath.replace(/^\/+/, ''); targetDir = normPath(targetDir);
  const srcDir = parentOf(srcPath); const name = srcPath.split('/').filter(Boolean).pop();
  if (srcDir === targetDir) return json({ error: 'Same directory' }, 400);
  if (targetDir.startsWith(srcPath + '/')) return json({ error: 'Cannot move into itself' }, 400);

  const srcRes = await findDirItem(env, srcDir, name);
  if (!srcRes.item) return json({ error: 'Not found' }, 404);
  const tgtRes = await findDirItem(env, targetDir, name);
  if (tgtRes.item) return json({ error: 'Name exists in target' }, 409);

  const entry = srcRes.item;

  if (entry.type === 'file') {
    const oldKey = srcPath.replace(/^\//, ''); const newKey = targetDir.replace(/^\//, '') + name;
    const obj = await env.DRIVE.get(oldKey);
    if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); try { await mirrorPut(env, newKey); await mirrorDelete(env, oldKey); } catch (e) {} }
    await moveThumb(env, oldKey, newKey);
    await moveVersions(env, oldKey, newKey);
    await moveNote(env, oldKey, newKey);
    try {
      const tags = await env.STORE.get('tags:/' + oldKey, 'json');
      if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
    } catch (e) {}
  } else {
    await recursiveMoveDir(env, srcPath + '/', targetDir.replace(/^\//, '') + name + '/');
  }

  await removeDirItem(env, srcDir, name);
  await upsertDirItem(env, targetDir, entry);
  try { await addLog(env, 'mov', srcPath, '移动到 ' + targetDir); } catch (e) {}
  return json({ ok: true });
}

// 站内复制：把文件/目录复制到目标目录（同名自动加后缀，不覆盖）
async function copyDirRecursive(env, srcPrefix, dstPrefix, depth, budget) {
  if (depth > 12 || budget.n <= 0) return;
  const items = await getDir(env, srcPrefix);
  for (const it of items) {
    if (budget.n <= 0) return;
    if (it.type === 'dir') {
      await ensureDir(env, dstPrefix, it.name);
      await copyDirRecursive(env, srcPrefix + it.name + '/', dstPrefix + it.name + '/', depth + 1, budget);
    } else {
      const sk = srcPrefix.replace(/^\//, '') + it.name;
      const dk = dstPrefix.replace(/^\//, '') + it.name;
      if (await copyObjectKeep(env, sk, dk)) {
        await copyThumb(env, sk, dk);
        const up = await upsertDirItem(env, dstPrefix, Object.assign({}, it, { time: new Date().toISOString() }));
        if (up && up.ok === false) { try { await deleteAndMirror(env, dk); } catch (e) {} return; }
        await addUsage(env, it.size || 0, 1);
        budget.n--; budget.bytes += it.size || 0;
      }
    }
  }
}
async function handleCopy(env, paths, target, sessionToken) {
  const t = normPath(target || '/');
  const list = Array.isArray(paths) ? paths.filter(Boolean) : [];
  if (!list.length) return json({ error: 'No paths' }, 400);
  const items = [];
  let copied = 0, failed = 0;
  const budget = { n: 500, bytes: 0 };          // 单次复制上限，避免一次请求做太多工作
  const u0 = await getUsage(env);
  let usedNow = u0.used || 0;
  for (const p of list) {
    try {
      const src = '/' + String(p || '').replace(/^\/+/, '');
      const srcDir = src.endsWith('/') ? src : src + '/';
      if (src === '/' || src === t || t === srcDir) { failed++; continue; }
      if (t.startsWith(srcDir)) { items.push({ path: src, error: 'cannot copy into itself' }); failed++; continue; }
      const sdir = parentOf(src), name = src.split('/').filter(Boolean).pop();
      const res = await findDirItem(env, sdir, name);
      if (!res.item) { items.push({ path: src, error: 'not found' }); failed++; continue; }
      if (await isPathLocked(env, src, sessionToken) || await isPathLocked(env, sdir, sessionToken)) { items.push({ path: src, error: 'locked' }); failed++; continue; }
      const entry = res.item;
      // 目录先算体积，做配额与体量预检查
      let needBytes = entry.size || 0;
      if (entry.type === 'dir') {
        needBytes = await calcDirSize(env, src + '/');
        if (needBytes > 2 * 1024 * 1024 * 1024) { items.push({ path: src, error: 'folder too large to copy' }); failed++; continue; }
      }
      if (usedNow + needBytes > quotaTotal(env)) { items.push({ path: src, error: 'Quota exceeded' }); failed++; continue; }
      const existing = await findDirItem(env, t, name);
      const finalName = existing.item ? await uniqueFileName(env, t, name) : name;
      const dst = t + finalName;
      if (pathTooLong(dst + (entry.type === 'dir' ? '/' : ''))) { items.push({ path: src, error: 'path too long' }); failed++; continue; }
      const room = await dirRoom(env, t, 1);
      if (room) { items.push({ path: src, error: room.error }); failed++; continue; }

      if (entry.type === 'dir') {
        await ensureDir(env, t, finalName);
        const dPre = dst.endsWith('/') ? dst : dst + '/';
        await copyDirRecursive(env, srcDir, dPre, 0, budget);
        await upsertDirItem(env, t, Object.assign({}, entry, { name: finalName, time: new Date().toISOString() }));
      } else {
        const sk = src.replace(/^\//, ''), dk = dst.replace(/^\//, '');
        if (!await copyObjectKeep(env, sk, dk)) { items.push({ path: src, error: 'copy failed' }); failed++; continue; }
        await copyThumb(env, sk, dk);
        const up = await upsertDirItem(env, t, Object.assign({}, entry, { name: finalName, time: new Date().toISOString() }));
        if (up && up.ok === false) { try { await deleteAndMirror(env, dk); } catch (e) {} items.push({ path: src, error: up.error }); failed++; continue; }
        await addUsage(env, needBytes, 1);   // 副本是 R2 里真实多出来的一份，必须计入用量
      }
      usedNow += needBytes;
      budget.bytes += needBytes;
      copied++;
      items.push({ path: src, name: finalName, target: dst });
    } catch (e) { items.push({ path: String(p), error: 'failed' }); failed++; }
  }
  try { await addLog(env, 'cpy', t, copied + ' items copied'); } catch (e) {}
  return json({ ok: true, copied, failed, target: t, items, truncated: budget.n <= 0 });
}
async function handleBatchDelete(env, paths) {  let ok = 0, fail = 0;
  for (const fp of (Array.isArray(paths) ? paths : [])) {
    try {
      const res = await handleDelete(env, fp);
      let good = false;
      try { const d = await res.clone().json(); good = !!(d && d.ok); } catch (e) {}
      if (good) ok++; else fail++;
    } catch (e) { fail++; }
  }
  return json({ ok: true, deleted: ok, failed: fail });
}

async function handleBatchRename(env, paths, pattern) {
  if (!Array.isArray(paths) || !paths.length) return json({ error: 'No files' }, 400);
  let build;
  if (pattern && typeof pattern === 'object') {
    const type = String(pattern.type || '');
    const value = String(pattern.value == null ? '' : pattern.value);
    const repl = String(pattern.replace == null ? '' : pattern.replace);
    build = (base, ext, i) => {
      if (type === 'prefix') return value + base + ext;
      if (type === 'suffix') return base + value + ext;
      if (type === 'counter') { const n = (parseInt(pattern.start, 10) || 1) + i; const pad = String(n).padStart(parseInt(pattern.pad, 10) || 2, '0'); return (value || '') + pad + ext; }
      if (type === 'replace') return value ? (base.split(value).join(repl) + ext) : (base + ext);
      return base + ext;
    };
  } else {
    const tpl = String(pattern == null ? '' : pattern);
    build = (base, ext, i) => {
      if (!tpl) return base + ext;
      const d = new Date().toISOString().substring(0, 10);
      return tpl.replace(/\{n\}/g, String(i + 1)).replace(/\{d\}/g, d).replace(/\{name\}/g, base) + ext;
    };
  }

  let renamed = 0, failed = 0;
  for (let i = 0; i < paths.length; i++) {
    const fp = '/' + String(paths[i] == null ? '' : paths[i]).replace(/^\/+/, '');
    if (fp === '/') continue;
    const dir = parentOf(fp);
    const name = fp.split('/').filter(Boolean).pop();
    if (!name) continue;
    const dotIdx = name.lastIndexOf('.');
    const base = dotIdx > 0 ? name.substring(0, dotIdx) : name;
    const ext = dotIdx > 0 ? name.substring(dotIdx) : '';
    const newName = sanitizeName(build(base, ext, i));
    if (!newName || newName === name) continue;

    const r = await renameDirItem(env, dir, name, newName);
    if (!r || r.error) { failed++; continue; }
    const entry = r.item;
    try {
      if (entry && entry.type === 'dir') {
        await recursiveMoveDir(env, fp + '/', dir.replace(/^\//, '') + newName + '/');
      } else {
        const oldKey = fp.replace(/^\//, ''); const newKey = dir.replace(/^\//, '') + newName;
        const obj = await env.DRIVE.get(oldKey);
        if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); try { await mirrorPut(env, newKey); await mirrorDelete(env, oldKey); } catch (e) {} }
        await moveThumb(env, oldKey, newKey);
        await moveVersions(env, oldKey, newKey);
        await moveNote(env, oldKey, newKey);
      }
      renamed++;
    } catch (e) { failed++; }
  }
  return json({ ok: true, renamed, failed });
}

async function handleDuplicates(env) {
  const locked = await getLockedPrefixes(env);
  const hashMap = {};
  async function scanDir(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file' && it.hash) {
        if (!hashMap[it.hash]) hashMap[it.hash] = [];
        hashMap[it.hash].push({ name: it.name, path: dirPath, size: it.size });
      } else if (it.type === 'dir') {
        const sub = dirPath + it.name + '/';
        if (isLockedPrefix(sub, locked)) continue;
        await scanDir(sub);
      }
      if (Object.keys(hashMap).length >= 2000) return;
    }
  }
  await scanDir('/');
  const dupes = Object.entries(hashMap).filter(([h, files]) => files.length > 1);
  return json({ groups: dupes.map(([hash, files]) => ({ hash, count: files.length, size: files[0].size, files })) });
}

// ===== 活动日志 =====
async function addDailyStat(env, kind, bytes) {
  try { if (kind !== 'del') telBufDaily(kind, bytes); } catch (e) {}
}
async function handleStatsTrend(env, days) {
  const n = Math.min(Math.max(parseInt(days, 10) || 30, 7), 90);
  const all = telMergeDaily((await env.STORE.get('meta:daily', 'json')) || {});
  const out = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().substring(0, 10);
    const v = all[d] || {};
    out.push({ date: d, up: v.up || 0, dl: v.dl || 0, upBytes: v.upBytes || 0, dlBytes: v.dlBytes || 0 });
  }
  return json({ days: out });
}
async function addLog(env, action, path, detail) {
  // 活动日志改为内存缓冲 + 定时合并写：原先每次上传/删除/移动都要读改写 meta:log
  try {
    telBufLog({ action, path, detail: detail || '', time: new Date().toISOString() });
    if (action === 'up') {
      const m = /^(\d+)/.exec(String(detail || ''));
      telBufDaily('up', m ? Number(m[1]) : 0);
    }
  } catch (e) {}
  await notifyWebhook(env, { event: action, path: path || '', detail: detail || '' });
}
async function getLogs(env) {
  try { return telMergeLogs(await env.STORE.get('meta:log', 'json')); } catch (e) { return telMergeLogs([]); }
}

// ===== Access Tokens =====
async function getAccessTokens(env) {
  // 每个请求的鉴权都会读它，加 30 秒隔离级缓存（创建/删除令牌时失效）
  return await kvCached('meta:tokens', 30, async () => {
    try { return (await env.STORE.get('meta:tokens', 'json')) || []; } catch (e) { return []; }
  });
}
async function saveAccessTokens(env, tokens) {
  await env.STORE.put('meta:tokens', JSON.stringify(tokens));
  kvInvalidate('meta:tokens');
}
// ===== Note =====
async function handleGetNote(env, filePath) {
  try { return json({ note: (await env.STORE.get('note:' + filePath, 'json')) || '' }); }
  catch (e) { return json({ note: '' }); }
}
async function handleSetNote(env, filePath, note) {
  const s = JSON.stringify(note || '');
  if (s.length > maxNoteBytes(env)) return json({ error: 'Note too large', max: maxNoteBytes(env) }, 413);
  await env.STORE.put('note:' + filePath, s);
  return json({ ok: true });
}

// ===== Tag =====
async function getFileTags(env, filePath) { try { return await env.STORE.get('tags:' + filePath, 'json') || []; } catch (e) { return []; } }
async function setFileTags(env, filePath, tags) { await env.STORE.put('tags:' + filePath, JSON.stringify(tags)); }
async function getAllTags(env) {
  return await kvCached('meta:tags', 15, async () => {
    try { return await env.STORE.get('meta:tags', 'json') || []; } catch (e) { return []; }
  });
}
// 批量登记全局标签：一次读改写（原先每个标签都要读写一遍 meta:tags）
async function addGlobalTags(env, list) {
  if (!Array.isArray(list) || !list.length) return;
  const tags = (await getAllTags(env)).slice();
  let changed = false;
  for (const t of list) {
    if (t && t.name && !tags.find(x => x.name === t.name)) {
      if (tags.length >= 2000) break;                 // 全局标签数量上限
      tags.push({ name: t.name, color: t.color });
      changed = true;
    }
  }
  if (!changed) return;
  const s = JSON.stringify(tags);
  if (s.length > 512 * 1024) return;                  // 标签总表体积上限
  await env.STORE.put('meta:tags', s);
  kvInvalidate('meta:tags');
}
async function addGlobalTag(env, tag) { return addGlobalTags(env, [tag]); }
async function handleTagFile(env, filePath, tags) {
  filePath = '/' + filePath.replace(/^\/+/, '');
  const list = Array.isArray(tags) ? tags : [];
  if (JSON.stringify(list).length > maxTagsBytes(env)) return json({ error: 'Too many tags', max: maxTagsBytes(env) }, 413);
  await setFileTags(env, filePath, list);
  await addGlobalTags(env, list);
  return json({ ok: true });
}
async function handleGetTags(env) {
  // 同时返回每个标签的引用计数（按需统计，带隔离级缓存，不产生额外热写）
  const tags = await getAllTags(env);
  const counts = await tagCounts(env);
  return json({ tags: tags.map(t => ({ name: t.name, color: t.color || '', count: counts[t.name] || 0 })) });
}
// 标签引用计数：扫描所有 tags:* 键（KV list 有界），带 60 秒缓存
async function tagCounts(env) {
  return await kvCached('tagcounts', 60, async () => {
    const counts = {};
    let cursor = undefined, pages = 0;
    try {
      do {
        const r = await env.STORE.list({ prefix: 'tags:', limit: 300, cursor });
        for (const k of (r.keys || [])) {
          let list = [];
          try { list = await env.STORE.get(k.name, 'json') || []; } catch (e) { list = []; }
          for (const t of list) { if (t && t.name) counts[t.name] = (counts[t.name] || 0) + 1; }
        }
        cursor = r.list_complete ? null : r.cursor;
        pages++;
      } while (cursor && pages < 20);
    } catch (e) {}
    return counts;
  });
}
async function handleTagFilter(env, tagName, mode, extraTags) {
  const locked = await getLockedPrefixes(env);
  const want = [tagName].concat(extraTags || []).filter(Boolean);
  const all = mode === 'all';
  const results = [];
  const seen = new Set();
  async function scanDir(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file') {
        const k = dirPath + it.name;
        const ft = await getFileTags(env, k);
        const names = ft.map(t => t && t.name);
        const hit = all ? want.every(w => names.indexOf(w) >= 0) : want.some(w => names.indexOf(w) >= 0);
        if (hit && !seen.has(k)) { seen.add(k); results.push(Object.assign({}, it, { path: dirPath, tags: ft })); }
      } else if (it.type === 'dir') {
        const sub = dirPath + it.name + '/';
        if (isLockedPrefix(sub, locked)) continue;
        await scanDir(sub);
      }
      if (results.length >= 500) return;
    }
  }
  await scanDir('/');
  return json({ items: results, tags: want, mode: all ? 'all' : 'any' });
}
// 标签重命名 / 合并（批量改写受影响文件的 tags: 键，有界）
async function handleTagRename(env, from, to, color) {
  from = String(from || '').trim();
  to = String(to || '').trim();
  if (!from || !to) return json({ error: 'Need from/to' }, 400);
  if (to.length > 60) return json({ error: 'Tag too long' }, 413);
  const tags = (await getAllTags(env)).slice();
  const src = tags.find(t => t.name === from);
  if (!to.length) return json({ error: 'Bad target' }, 400);
  if (!tags.find(t => t.name === to)) tags.push({ name: to, color: color || (src && src.color) || '' });
  else if (color) tags.find(t => t.name === to).color = color;
  const next = tags.filter(t => t.name !== from);
  if (next.length > 2000) return json({ error: 'Too many tags' }, 413);
  await env.STORE.put('meta:tags', JSON.stringify(next));
  kvInvalidate('meta:tags');
  kvInvalidate('tagcounts');
  // 改写文件标签
  let files = 0, cursor = undefined, pages = 0;
  try {
    do {
      const r = await env.STORE.list({ prefix: 'tags:', limit: 200, cursor });
      for (const k of (r.keys || [])) {
        if (files >= 2000) break;
        let list = [];
        try { list = await env.STORE.get(k.name, 'json') || []; } catch (e) { continue; }
        if (!list.some(t => t && t.name === from)) continue;
        const mapped = [];
        const seen = {};
        for (const t of list) {
          const nm = (t && t.name === from) ? to : (t && t.name);
          if (!nm || seen[nm]) continue;
          seen[nm] = 1;
          mapped.push({ name: nm, color: (t && t.color) || (nm === to ? (color || (src && src.color) || '') : '') });
        }
        await env.STORE.put(k.name, JSON.stringify(mapped));
        files++;
      }
      cursor = r.list_complete ? null : r.cursor;
      pages++;
    } while (cursor && pages < 20 && files < 2000);
  } catch (e) {}
  return json({ ok: true, files, tags: next });
}
async function handleTagColor(env, name, color) {
  const tags = (await getAllTags(env)).slice();
  const t = tags.find(x => x.name === name);
  if (!t) return json({ error: 'Not found' }, 404);
  t.color = String(color || '').slice(0, 20);
  await env.STORE.put('meta:tags', JSON.stringify(tags));
  kvInvalidate('meta:tags');
  return json({ ok: true, tags });
}
async function handleTagBatch(env, paths, add, remove, mode) {
  const list = (Array.isArray(paths) ? paths : []).slice(0, 500);
  const addL = (Array.isArray(add) ? add : []).filter(Boolean).slice(0, 20).map(n => ({ name: sanitizeName(String(n)).slice(0, 60), color: '' }));
  const rm = (Array.isArray(remove) ? remove : []).filter(Boolean);
  let changed = 0;
  for (const p of list) {
    const key = '/' + String(p || '').replace(/^\/+/, '');
    if (!key || key === '/') continue;
    let cur = [];
    try { cur = await env.STORE.get('tags:' + key, 'json') || []; } catch (e) { cur = []; }
    const map = {};
    for (const t of cur) { if (t && t.name && rm.indexOf(t.name) < 0) map[t.name] = t.color || ''; }
    for (const t of addL) { if (mode === 'replace') { } if (!(t.name in map)) map[t.name] = t.color || ''; }
    if (mode === 'replace') { for (const k of Object.keys(map)) if (!addL.some(t => t.name === k)) delete map[k]; }
    const out = Object.keys(map).map(n => ({ name: n, color: map[n] }));
    if (JSON.stringify(out).length > maxTagsBytes(env)) continue;
    await env.STORE.put('tags:' + key, JSON.stringify(out));
    changed++;
  }
  if (addL.length) await addGlobalTags(env, addL);
  kvInvalidate('tagcounts');
  return json({ ok: true, changed, tags: addL.map(t => t.name) });
}
// 自动打标签：按扩展名/类型或拍摄/修改年月（预览或直接应用，有界）
async function handleTagAuto(env, b) {
  const dir = normPath((b && b.path) || '/');
  const mode = (b && b.mode) === 'date' ? 'date' : 'type';
  const apply = !!(b && b.apply);
  const deep = !!(b && b.deep);
  const items = [];
  async function walk(p, depth) {
    if (items.length >= 800) return;
    const list = await getDir(env, p);
    for (const it of list) {
      if (!it || !it.name) continue;
      if (it.type === 'dir') { if (deep && depth < 5) await walk(p + it.name + '/', depth + 1); continue; }
      items.push(Object.assign({}, it, { path: p }));
      if (items.length >= 800) return;
    }
  }
  try { await walk(dir, 0); } catch (e) {}
  const plan = {};
  for (const it of items) {
    let tag = '';
    if (mode === 'type') {
      const m = String(it.mime || ''), n = String(it.name).toLowerCase();
      const ext = n.indexOf('.') >= 0 ? n.substring(n.lastIndexOf('.') + 1) : '';
      if (m.indexOf('image/') === 0) tag = '图片';
      else if (m.indexOf('video/') === 0) tag = '视频';
      else if (m.indexOf('audio/') === 0) tag = '音频';
      else if (m.indexOf('pdf') >= 0) tag = 'PDF';
      else if (['doc', 'docx', 'md', 'txt', 'rtf'].indexOf(ext) >= 0) tag = '文档';
      else if (['xls', 'xlsx', 'csv', 'ods'].indexOf(ext) >= 0) tag = '表格';
      else if (['zip', 'rar', '7z', 'tar', 'gz'].indexOf(ext) >= 0) tag = '压缩包';
      else if (m.indexOf('text/') === 0) tag = '文本';
      else tag = '其他';
    } else {
      const t = it.time ? new Date(it.time) : null;
      tag = (t && !isNaN(t.getTime())) ? (t.getFullYear() + '-' + String(t.getMonth() + 1).padStart(2, '0')) : '未知时间';
    }
    if (!plan[tag]) plan[tag] = [];
    plan[tag].push((it.path + it.name).replace(/^\//, ''));
  }
  const groups = Object.keys(plan).map(k => ({ tag: k, count: plan[k].length, sample: plan[k].slice(0, 5) }));
  if (!apply) return json({ ok: true, dryRun: true, total: items.length, groups });
  let changed = 0;
  for (const tag of Object.keys(plan)) {
    for (const p of plan[tag]) {
      if (changed >= 800) break;
      let cur = [];
      try { cur = await env.STORE.get('tags:/' + p, 'json') || []; } catch (e) { cur = []; }
      if (cur.some(t => t && t.name === tag)) continue;
      cur.push({ name: tag, color: '' });
      await env.STORE.put('tags:/' + p, JSON.stringify(cur));
      changed++;
    }
    await addGlobalTag(env, { name: tag, color: '' });
  }
  kvInvalidate('tagcounts');
  return json({ ok: true, total: items.length, changed, groups });
}
// ===== 高级查询（统一筛选器）=====
function mimeGroupOf(mime, name) {
  const m = String(mime || ''), n = String(name || '').toLowerCase();
  if (m.indexOf('image/') === 0) return 'image';
  if (m.indexOf('video/') === 0) return 'video';
  if (m.indexOf('audio/') === 0) return 'audio';
  if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'].indexOf(n.indexOf('.') >= 0 ? n.substring(n.lastIndexOf('.') + 1) : '') >= 0) return 'zip';
  if (m.indexOf('pdf') >= 0 || m.indexOf('text/') === 0 || ['doc', 'docx', 'md', 'txt', 'rtf', 'xls', 'xlsx', 'csv', 'ods', 'ppt', 'pptx'].indexOf(n.indexOf('.') >= 0 ? n.substring(n.lastIndexOf('.') + 1) : '') >= 0) return 'doc';
  return 'other';
}
async function handleQuery(env, q, sessionToken) {
  const scope = normPath(q.path || '/');
  const locked = await unlockedPrefixes(env, sessionToken);
  const deep = q.deep !== '0';
  const wantType = String(q.type || '');
  const exts = csvList(q.ext).map(s => s.toLowerCase().replace(/^\*/, ''));
  const minSize = q.minSize ? Number(q.minSize) : 0;
  const maxSize = q.maxSize ? Number(q.maxSize) : 0;
  const after = q.after ? Date.parse(q.after) : 0;
  const before = q.before ? Date.parse(q.before) : 0;
  const wantTags = csvList(q.tags);
  const tagMode = q.tagMode === 'all' ? 'all' : 'any';
  const nameQ = String(q.q || '').trim().toLowerCase();
  const favOnly = q.fav === '1';
  const limit = Math.min(Math.max(parseInt(q.limit, 10) || 200, 1), 1000);
  const offset = Math.max(0, parseInt(q.offset, 10) || 0);
  let favs = null;
  if (favOnly) { favs = new Set(await getFavs(env)); }
  const out = [];
  let scanned = 0, capped = false;
  async function walk(dirPath, depth) {
    if (out.length >= 3000) { capped = true; return; }
    let items = [];
    try { items = await getDir(env, dirPath); } catch (e) { return; }
    for (const it of items) {
      if (!it || !it.name) continue;
      if (it.type === 'dir') {
        if (!deep || depth >= 8) continue;
        const sub = dirPath + it.name + '/';
        if (isLockedPrefix(sub, locked)) continue;
        await walk(sub, depth + 1);
        continue;
      }
      scanned++;
      const full = dirPath + it.name;
      if (insideLocked(dirPath, locked)) continue;
      if (nameQ && it.name.toLowerCase().indexOf(nameQ) < 0) continue;
      if (wantType && mimeGroupOf(it.mime, it.name) !== wantType) continue;
      if (exts.length) {
        const n = it.name.toLowerCase();
        if (!exts.some(e => n.endsWith(e))) continue;
      }
      if (minSize && (it.size || 0) < minSize) continue;
      if (maxSize && (it.size || 0) > maxSize) continue;
      const ts = it.time ? Date.parse(it.time) : 0;
      if (after && (!ts || ts < after)) continue;
      if (before && (!ts || ts > before)) continue;
      if (favOnly && !favs.has(full)) continue;
      if (wantTags.length) {
        const ft = await getFileTags(env, full);
        const names = ft.map(t => t && t.name);
        const hit = tagMode === 'all' ? wantTags.every(w => names.indexOf(w) >= 0) : wantTags.some(w => names.indexOf(w) >= 0);
        if (!hit) continue;
      }
      out.push(Object.assign({}, it, { path: dirPath }));
      if (out.length >= 3000) { capped = true; return; }
    }
  }
  await walk(scope, 0);
  out.sort(function (x, y) {
    const k = q.sort === 'size' ? 'size' : (q.sort === 'time' ? 'time' : 'name');
    let r;
    if (k === 'size') r = (x.size || 0) - (y.size || 0);
    else if (k === 'time') r = String(x.time || '').localeCompare(String(y.time || ''));
    else r = String(x.name).localeCompare(String(y.name));
    return q.order === 'desc' ? -r : r;
  });
  return json({
    items: out.slice(offset, offset + limit), total: out.length, scanned, capped,
    offset, limit, hasMore: offset + limit < out.length, scope, deep
  });
}

// ===== Version API =====
async function handleListVersions(env, filePath) {
  const key = filePath.replace(/^\/+/, '');
  const list = await listVersions(env, key);
  return json({ versions: list });
}
async function handleRestoreVersion(env, filePath, ts) {
  const key = filePath.replace(/^\/+/, '');
  const vKey = VERSIONS_PREFIX + key + '/' + ts;
  const obj = await env.DRIVE.get(vKey);
  if (!obj) return json({ error: 'Version not found' }, 404);
  const dir = parentOf('/' + key);
  const name = key.split('/').pop();
  const oldRes = await findDirItem(env, dir, name);
  if (oldRes.item) await pushVersion(env, key, oldRes.item);
  const buf = await obj.arrayBuffer();
  await putAndMirror(env, key, buf, { httpMetadata: obj.httpMetadata });
  return json({ ok: true });
}

// ===== Chunked Upload =====
async function handleChunkInit(env, fileName, totalSize, hash, dirPath, mime) {
  const uploadId = randToken().substring(0, 16);
  dirPath = normPath(dirPath);
  const size = parseInt(totalSize, 10) || 0;
  if (size > maxUploadBytes(env)) return json({ error: 'File too large', max: maxUploadBytes(env) }, 413);
  if (size > 0) {
    const u = await getUsage(env);
    if ((u.used || 0) + size > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  }
  await env.STORE.put('chunk:' + uploadId, JSON.stringify({ fileName: sanitizeName(fileName), totalSize: size, hash: hash || '', dirPath, mime: String(mime || ''), chunks: 0, created: Date.now() }), { expirationTtl: 86400 });
  // 顺手回收一次过期分片（每 isolate 每小时最多一次，避免中途放弃的上传长期占用 R2）
  if (Date.now() - TEL.lastChunkGc > 3600 * 1000) {
    TEL.lastChunkGc = Date.now();
    try { await gcChunks(env, 100); } catch (e) {}
  }
  if (isHex64(hash)) {
    try {
      const r = await instantStore(env, hash, fileName, dirPath, size);
      if (r.hit) { try { await env.STORE.delete('chunk:' + uploadId); } catch (e) {} return json({ instant: true, name: r.name }); }
    } catch (e) {}
  }
  return json({ uploadId, chunkSize: CHUNK_SIZE });
}
// 分片上传：每个分片用独立 KV 键记录已上传状态，避免并发覆盖
async function handleChunkUpload(req, env, uploadId, chunkIndex) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Upload not found' }, 404);
  const st = extractToken(req);
  if (await isPathLocked(env, meta.dirPath, st)) return json({ locked: true, path: meta.dirPath }, 423);
  const idx = parseInt(chunkIndex, 10);
  // R2 分片号上限 10000，且不得超过本次声明的总分片数
  const declaredTotal = (Number(meta.totalSize) > 0) ? Math.ceil(Number(meta.totalSize) / CHUNK_SIZE) : 0;
  if (!Number.isFinite(idx) || idx < 0 || idx > 10000) return json({ error: 'Bad chunk index' }, 400);
  if (declaredTotal && idx >= declaredTotal) return json({ error: 'Chunk index out of range', total: declaredTotal }, 400);
  const body = await req.arrayBuffer();
  if (body.byteLength > CHUNK_SIZE) return json({ error: 'Chunk too large' }, 413);
  await env.DRIVE.put(CHUNKS_PREFIX + uploadId + '/' + idx, body);
  // 每个分片独立 key，避免并发写入互相覆盖
  try { await env.STORE.put('chunkgot:' + uploadId + ':' + idx, '1', { expirationTtl: 86400 }); } catch (e) {}
  // 并发上传时 KV 读改写会丢更新，只作为提示值；完整性以 chunkgot: 键 + totalSize 为准
  if ((meta.chunks || 0) < idx + 1) {
    meta.chunks = idx + 1;
    try { await env.STORE.put('chunk:' + uploadId, JSON.stringify(meta), { expirationTtl: 86400 }); } catch (e) {}
  }
  return json({ ok: true, received: meta.chunks });
}
async function listGotChunks(env, uploadId) {
  const got = [];
  const prefix = 'chunkgot:' + uploadId + ':';
  try {
    let cursor;
    do {
      const res = await env.STORE.list({ prefix, cursor, limit: 1000 });
      for (const k of (res.keys || [])) {
        const idx = parseInt(k.name.substring(prefix.length), 10);
        if (Number.isFinite(idx)) got.push(idx);
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch (e) {}
  return got;
}
async function handleChunkComplete(req, env, uploadId) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Upload not found' }, 404);
  const st = extractToken(req);
  if (await isPathLocked(env, meta.dirPath, st)) return json({ locked: true, path: meta.dirPath }, 423);

  const name = sanitizeName(meta.fileName);
  const outDir = await applyAutoArchive(env, normPath(meta.dirPath), name, '');
  const key = outDir.replace(/^\//, '') + name;
  // 总分片数由声明的 totalSize 推导（meta.chunks 在并发下可能丢更新），并做上限保护
  const declared = Math.max(0, parseInt(meta.totalSize, 10) || 0);
  const total = declared > 0 ? Math.ceil(declared / CHUNK_SIZE) : Math.max(0, parseInt(meta.chunks, 10) || 0);
  if (!total) return json({ error: 'No chunks uploaded' }, 400);
  if (total > 10000) return json({ error: 'Too many chunks', max: 10000 }, 413);

  // 容错：以"已收到分片清单"为准校验完整性（不再单一依赖 meta.chunks），缺失则返回缺失下标便于前端续传
  const got = await listGotChunks(env, uploadId);
  const gotSet = new Set(got);
  const missing = [];
  for (let i = 0; i < total; i++) if (!gotSet.has(i)) missing.push(i);
  if (missing.length) return json({ error: 'Chunks incomplete', missing, total, canResume: true }, 400);

  const oldRes = await findDirItem(env, outDir, name);
  const oldItem = oldRes.item;
  if (!oldItem) {
    const ruleChk = await checkDirRule(env, outDir, name, declared);
    if (ruleChk) return json({ error: ruleChk.error }, 403);
  }
  if (oldItem) await pushVersion(env, key, oldItem);

  let done = false;
  if (total > 1) {
    try {
      const multipart = await env.DRIVE.createMultipartUpload(key, { httpMetadata: { contentType: meta.mime || 'application/octet-stream' } });
      try {
        const uploaded = [];
        for (let i = 0; i < total; i += 10) {
          const batch = [];
          for (let j = i; j < Math.min(i + 10, total); j++) {
            batch.push((async () => {
              const chunk = await env.DRIVE.get(CHUNKS_PREFIX + uploadId + '/' + j);
              if (!chunk) throw new Error('Missing chunk ' + j);
              const buf = await chunk.arrayBuffer();
              return multipart.uploadPart(j + 1, buf);
            })());
          }
          const parts = await Promise.all(batch);
          for (const p of parts) uploaded.push(p);
        }
        await multipart.complete(uploaded);
        done = true;
      } catch (e) {
        try { await multipart.abort(); } catch (e2) {}
        console.warn('multipart upload failed, fallback to memory assembly:', e && e.message);
      }
    } catch (e) { console.warn('createMultipartUpload failed:', e && e.message); }
  }

  if (!done) {
    // 退化为内存拼装（上限 50MB，避免 Worker OOM）
    const parts = []; let totalLen = 0;
    for (let i = 0; i < total; i++) {
      const chunk = await env.DRIVE.get(CHUNKS_PREFIX + uploadId + '/' + i);
      if (!chunk) return json({ error: 'Missing chunk ' + i }, 400);
      const ab = await chunk.arrayBuffer();
      totalLen += ab.byteLength;
      if (totalLen > 50 * 1024 * 1024) return json({ error: 'File too large for assembly (max 50MB without multipart)' }, 413);
      parts.push(new Uint8Array(ab));
    }
    const buf = new Uint8Array(totalLen); let offset = 0;
    for (const p of parts) { buf.set(p, offset); offset += p.byteLength; }
    try { await env.DRIVE.put(key, buf, { httpMetadata: { contentType: meta.mime || 'application/octet-stream' } }); }
    catch (e) { return json({ error: 'Assembly failed' }, 500); }
  }
  try { await mirrorPut(env, key); } catch (e) {}

  // 组装结果必须与声明大小一致，否则保留分片供续传，避免写入"截断但 size 正确"的坏文件
  let actualSize = 0;
  try { const h = await env.DRIVE.head(key); actualSize = h ? (h.size || 0) : 0; } catch (e) {}
  if (!actualSize) return json({ error: 'Assembly failed', canResume: true }, 500);
  if (declared > 0 && actualSize !== declared) {
    try { await deleteAndMirror(env, key); } catch (e) {}
    return json({ error: 'Size mismatch', expected: declared, actual: actualSize, canResume: true }, 400);
  }

  const delPromises = [];
  for (let i = 0; i < total; i++) { delPromises.push(env.DRIVE.delete(CHUNKS_PREFIX + uploadId + '/' + i).catch(() => {})); }
  await Promise.all(delPromises);
  // 清理分片标记键
  try {
    let gcursor;
    do {
      const res = await env.STORE.list({ prefix: 'chunkgot:' + uploadId + ':', cursor: gcursor, limit: 1000 });
      for (const k of (res.keys || [])) { try { await env.STORE.delete(k.name); } catch (e) {} }
      gcursor = res.list_complete ? undefined : res.cursor;
    } while (gcursor);
  } catch (e) {}
  await env.STORE.delete('chunk:' + uploadId);
  if (meta.hash) { try { await env.STORE.put('hash:' + meta.hash, JSON.stringify({ key, time: Date.now() }), { expirationTtl: hashTtl(env) }); } catch (e) {} }

  const finalSize = actualSize;
  const entry = { name, type: 'file', size: finalSize, mime: meta.mime || '', time: new Date().toISOString(), hash: meta.hash || '' };
  await upsertDirItem(env, outDir, entry);
  if (oldItem) await addUsage(env, finalSize - (oldItem.size || 0), 0);
  else await addUsage(env, finalSize, 1);
  await addLog(env, 'up', key, finalSize + ' bytes (chunked)');
  return json({ ok: true, key, size: finalSize });
}
async function handleChunkStatus(env, uploadId) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Not found' }, 404);
  const got = await listGotChunks(env, uploadId);
  return json({
    chunks: meta.chunks, total: Math.ceil(meta.totalSize / CHUNK_SIZE),
    got: got,
    fileName: meta.fileName, totalSize: meta.totalSize, dirPath: meta.dirPath
  });
}

async function handleSearch(env, query, path, sessionToken) {
  path = normPath(path);
  const locked = await unlockedPrefixes(env, sessionToken);
  if (insideLocked(path, locked)) return json({ results: [] });
  return json({ results: await searchDir(env, path, query, locked) });
}

async function handleTree(env, sessionToken) {
  const locked = await unlockedPrefixes(env, sessionToken);
  async function buildNode(dirPath, depth) {
    if (depth > 6) return null;
    const items = await getDir(env, dirPath);
    const node = { name: dirPath === '/' ? 'root' : dirPath.split('/').filter(Boolean).pop(), path: dirPath, children: [] };
    const dirs = items.filter(i => i.type === 'dir');
    if (!dirs.length) return node;
    for (const d of dirs) {
      const childPath = dirPath + d.name + '/';
      if (isLockedPrefix(childPath, locked)) { node.children.push({ name: d.name, path: childPath, children: [] }); continue; }
      const child = await buildNode(childPath, depth + 1);
      if (child) node.children.push(child);
    }
    return node;
  }
  const tree = await buildNode('/', 0);
  return json({ tree });
}

// ===== Share（修复：访问计数在 /data 处 +1，/pv 和 /dl 仅检查配额） =====
function normalizeShareView(v) {
  const out = {};
  if (v && typeof v === 'object') {
    if (v.title !== undefined) out.title = String(v.title || '').slice(0, 80);
    if (v.desc !== undefined) out.desc = String(v.desc || '').slice(0, 300);
    if (v.color !== undefined) { const c = String(v.color || '').trim(); if (!c || /^#[0-9a-fA-F]{3,8}$/.test(c)) out.color = c; }
    if (v.cover !== undefined) out.cover = String(v.cover || '').slice(0, 300);
  }
  return out;
}
const SHARE_SLUG_RE = /^[A-Za-z0-9_-]{2,32}$/;
const SHARE_STAT_LAST = new Map();   // 分享统计落盘节流（防爆：避免每次访问都写 KV）
function shareTtlFor(data) { return Math.max(60, Math.ceil(((data.exp || 0) - Date.now()) / 1000) + 60); }
async function bumpShareStats(env, shareToken, data, kind, req) {
  try {
    data.stats = data.stats || { views: 0, downloads: 0 };
    if (kind === 'download') data.stats.downloads = (data.stats.downloads || 0) + 1;
    else data.stats.views = (data.stats.views || 0) + 1;
    data.stats.lastAt = Date.now();
    const ci = req ? clientInfo(req) : {};
    const visits = Array.isArray(data.visits) ? data.visits : [];
    visits.unshift({ t: Date.now(), k: kind, ip: ci.ip || '', c: ci.country || '', b: ci.browser || '', d: ci.device || '' });
    if (visits.length > 20) visits.length = 20;
    data.visits = visits;
    const last = SHARE_STAT_LAST.get(shareToken) || 0;
    if (Date.now() - last > 3000) {
      SHARE_STAT_LAST.set(shareToken, Date.now());
      await env.STORE.put('share:' + shareToken, JSON.stringify(data), { expirationTtl: shareTtlFor(data) });
    }
  } catch (e) {}
}
async function createShare(env, filePath, days, maxAccesses, password, isDir, opts) {
  opts = opts || {};
  filePath = '/' + String(filePath || '').replace(/^\/+/, '');
  const t = randToken();
  const ttl = clampDays(days) * 86400;
  const pwSalt = password ? randToken().substring(0, 16) : '';
  const pwHash = password ? await hashPassword(password, pwSalt) : '';
  const clean = filePath.replace(/\/+$/, '') || '/';
  // H3: 创建分享前校验目录锁（目录分享查目录本身，文件分享查父目录）
  const lockPath = isDir ? clean + '/' : parentOf(clean);
  if (await isPathLocked(env, lockPath, '')) return { ok: false, locked: true, path: lockPath };
  const name = clean.split('/').filter(Boolean).pop() || (isDir ? 'root' : 'file');
  let size = 0, mime = '';
  if (!isDir) {
    // 只取元数据，避免为了 size 把整个对象 body 拉下来
    try {
      const head = await env.DRIVE.head(filePath.replace(/^\//, ''));
      size = head ? (head.size || 0) : 0;
      mime = (head && head.httpMetadata && head.httpMetadata.contentType) || '';
    } catch (e) {}
  }
  const rec = {
    path: filePath, type: isDir ? 'dir' : 'file', exp: Date.now() + ttl * 1000,
    max: clampCount(maxAccesses), hits: 0, pwHash, pwSalt, name, size, mime,
    // 细粒度权限
    allowDownload: opts.allowDownload !== false,
    allowComment: opts.allowComment !== false,
    once: !!opts.once,
    downloaded: false,
    ipAllow: String(opts.ipAllow || '').slice(0, 300),
    ipDeny: String(opts.ipDeny || '').slice(0, 300),
    countryAllow: String(opts.countryAllow || '').slice(0, 120),
    countryDeny: String(opts.countryDeny || '').slice(0, 120),
    uaDeny: String(opts.uaDeny || '').slice(0, 200),
    note: String(opts.note || '').slice(0, 500),
    slug: '',
    view: normalizeShareView(opts.view),
    stats: { views: 0, downloads: 0, lastAt: 0 },
    visits: []
  };
  await env.STORE.put('share:' + t, JSON.stringify(rec), { expirationTtl: ttl + 60 });
  if (opts.slug && SHARE_SLUG_RE.test(String(opts.slug))) {
    const sr = await setShareSlug(env, t, opts.slug);
    if (sr.ok) rec.slug = sr.slug;
  }
  try { await addLog(env, 'shr', filePath, isDir ? '文件夹分享' : '文件分享'); } catch (e) {}
  return { ok: true, url: '/s/' + (rec.slug || t), token: t, slug: rec.slug || '', hasPassword: !!pwHash, path: filePath, name };
}
// 短链别名：slug:<name> → { token }
async function setShareSlug(env, token, slug) {
  const s = String(slug || '').trim();
  const data = await env.STORE.get('share:' + token, 'json');
  if (!data) return { ok: false, error: 'Not found' };
  if (!s) {
    if (data.slug) { try { await env.STORE.delete('slug:' + data.slug); } catch (e) {} }
    data.slug = '';
    await env.STORE.put('share:' + token, JSON.stringify(data), { expirationTtl: shareTtlFor(data) });
    return { ok: true, slug: '' };
  }
  if (!SHARE_SLUG_RE.test(s)) return { ok: false, error: 'Bad slug (2-32 位字母数字_-)' };
  const existing = await env.STORE.get('slug:' + s, 'json');
  if (existing && existing.token && existing.token !== token) return { ok: false, error: 'Slug already used' };
  if (s.indexOf('data') === 0 && s.length < 6) return { ok: false, error: 'Reserved slug' };
  if (data.slug && data.slug !== s) { try { await env.STORE.delete('slug:' + data.slug); } catch (e) {} }
  await env.STORE.put('slug:' + s, JSON.stringify({ token, path: data.path, at: Date.now() }), { expirationTtl: Math.max(60, Math.ceil((data.exp - Date.now()) / 1000) + 60) });
  data.slug = s;
  await env.STORE.put('share:' + token, JSON.stringify(data), { expirationTtl: shareTtlFor(data) });
  kvInvalidate('share-slugs');
  return { ok: true, slug: s };
}
// 把 /s/<name> 解析成真实 token（支持自定义短链）
async function resolveShareToken(env, name) {
  if (!name) return null;
  const direct = await env.STORE.get('share:' + name, 'json');
  if (direct) return { token: name, data: direct };
  const mapped = await env.STORE.get('slug:' + name, 'json');
  if (mapped && mapped.token) {
    const d = await env.STORE.get('share:' + mapped.token, 'json');
    if (d) return { token: mapped.token, data: d };
  }
  return null;
}
async function handleShare(env, filePath, days, maxAccesses, password, isDir, opts) {
  const r = await createShare(env, filePath, days, maxAccesses, password, !!isDir, opts);
  if (r && r.ok === false && r.locked) return json({ error: 'Locked', path: r.path }, 423);
  return json(r);
}
// 分享设置：权限 / 外观 / 短链
async function handleShareUpdate(env, token, b) {
  const key = 'share:' + String(token || '');
  const data = await env.STORE.get(key, 'json');
  if (!data) return json({ error: 'Not found' }, 404);
  if (b) {
    if (b.allowDownload !== undefined) data.allowDownload = !!b.allowDownload;
    if (b.allowComment !== undefined) data.allowComment = !!b.allowComment;
    if (b.once !== undefined) { data.once = !!b.once; if (data.once) data.downloaded = false; }
    if (b.note !== undefined) data.note = String(b.note || '').slice(0, 500);
    if (b.ipAllow !== undefined) data.ipAllow = String(b.ipAllow || '').slice(0, 300);
    if (b.ipDeny !== undefined) data.ipDeny = String(b.ipDeny || '').slice(0, 300);
    if (b.countryAllow !== undefined) data.countryAllow = String(b.countryAllow || '').slice(0, 120);
    if (b.countryDeny !== undefined) data.countryDeny = String(b.countryDeny || '').slice(0, 120);
    if (b.uaDeny !== undefined) data.uaDeny = String(b.uaDeny || '').slice(0, 200);
    if (b.view !== undefined && b.view && typeof b.view === 'object') data.view = normalizeShareView(b.view);
  }
  let slugResult = null;
  if (b && b.slug !== undefined) {
    slugResult = await setShareSlug(env, String(token), b.slug);
    if (!slugResult.ok) return json({ error: slugResult.error }, 400);
    data.slug = slugResult.slug;
  }
  await env.STORE.put(key, JSON.stringify(data), { expirationTtl: shareTtlFor(data) });
  return json({ ok: true, slug: data.slug || '', token: String(token), url: '/s/' + (data.slug || token) });
}
async function handleShareStats(env, token) {
  const data = await env.STORE.get('share:' + String(token || ''), 'json');
  if (!data) return json({ error: 'Not found' }, 404);
  return json({
    token: String(token), name: data.name || '', path: data.path || '', type: data.type || 'file',
    url: '/s/' + (data.slug || token), slug: data.slug || '',
    hits: data.hits || 0, max: data.max || 0, exp: data.exp || 0,
    allowDownload: data.allowDownload !== false, allowComment: data.allowComment !== false,
    once: !!data.once, downloaded: !!data.downloaded,
    note: data.note || '', view: data.view || {},
    ipAllow: data.ipAllow || '', ipDeny: data.ipDeny || '',
    countryAllow: data.countryAllow || '', countryDeny: data.countryDeny || '', uaDeny: data.uaDeny || '',
    stats: data.stats || { views: 0, downloads: 0, lastAt: 0 },
    visits: (data.visits || []).slice(0, 20),
    hasPassword: !!data.pwHash
  });
}
// 目录分享：相对路径解析为绝对 key，且必须落在被分享目录内（防 ../ 逃逸）
function shareRelKey(data, rel) {
  if (!data || data.type !== 'dir') return data ? data.path.replace(/^\/+/, '') : null;
  const base = normPath(data.path);
  const full = normPath(base + String(rel == null ? '' : rel));
  if (!full.startsWith(base)) return null;
  const k = full.replace(/^\/+/, '').replace(/\/+$/, '');
  return k || null;
}
// 分享访问校验：过期 / 次数 / 密码 / 地区 / IP / UA（可选），返回 {data} 或 {resp}
async function shareGuard(env, shareToken, req, countHit, needPw) {
  const data = await env.STORE.get('share:' + shareToken, 'json');
  if (!data) return { resp: json({ error: 'Not found' }, 404) };
  if (Date.now() > data.exp) {
    // M7: 过期即清理，消除与 KV expirationTtl 的时间偏差
    try { await env.STORE.delete('share:' + shareToken); } catch (e) {}
    return { resp: json({ error: 'Expired' }, 410) };
  }
  // H3: 分享访问同样校验目录锁（目录分享看目录本身，文件分享看父目录）
  const shareLockPath = (data.type === 'dir') ? (normPath(data.path) + '/') : parentOf(normPath(data.path));
  if (await isPathLocked(env, shareLockPath, '')) return { resp: json({ error: 'Locked' }, 423) };
  // 分享级访问控制：IP / 地区 / UA
  if (req) {
    const ip = req.headers.get('CF-Connecting-IP') || '';
    if (data.ipDeny && csvList(data.ipDeny).some(r => ipMatch(ip, r))) return { resp: json({ error: 'Forbidden', reason: 'ip' }, 403) };
    if (data.ipAllow && !csvList(data.ipAllow).some(r => ipMatch(ip, r))) return { resp: json({ error: 'Forbidden', reason: 'ip' }, 403) };
    const country = (req.cf && req.cf.country) || '';
    if (!countryAllowed({ COUNTRY_ALLOW: data.countryAllow, COUNTRY_DENY: data.countryDeny }, country)) return { resp: json({ error: 'Forbidden', reason: 'country' }, 403) };
    const ua = req.headers.get('User-Agent') || '';
    if (!uaAllowed({ UA_DENY: data.uaDeny }, ua)) return { resp: json({ error: 'Forbidden', reason: 'ua' }, 403) };
  }
  if (countHit) {
    const before = data.hits || 0;
    if (data.max > 0 && before >= data.max) return { resp: json({ error: 'Access limit reached', hits: data.max, max: data.max, name: data.name }, 403) };
    const atom = await counterAdd(env, 'share:' + shareToken, 1);
    const hits = (atom == null) ? (before + 1) : atom;
    data.hits = hits;
    try { await env.STORE.put('share:' + shareToken, JSON.stringify(data), { expirationTtl: shareTtlFor(data) }); } catch (e) {}
    if (data.max > 0 && hits > data.max) return { resp: json({ error: 'Access limit reached', hits: data.max, max: data.max, name: data.name }, 403) };
  } else if (data.max > 0 && (data.hits || 0) >= data.max) {
    return { resp: json({ error: 'Access limit reached' }, 403) };
  }
  if (needPw && data.pwHash) {
    const pw = (req ? (new URL(req.url).searchParams.get('pw') || '') : '');
    if (!await verifyPassword(pw, { hash: data.pwHash, salt: data.pwSalt })) return { resp: json({ error: 'Wrong password' }, 403) };
  }
  return { data };
}
// 分享 /data：密码未通过前不返回真实元数据（仅返回 needPassword + hits/max）
// 计入一次分享访问（仅当密码（如有）已通过时调用），同时校验访问上限
async function shareCount(env, shareToken, data, req) {
  if (data.max > 0) {
    const before = data.hits || 0;
    if (before >= data.max) return { resp: json({ error: 'Access limit reached', hits: data.max, max: data.max, name: data.name }, 403) };
    const atom = await counterAdd(env, 'share:' + shareToken, 1);
    const hits = (atom == null) ? (before + 1) : atom;
    data.hits = hits;
    try { await env.STORE.put('share:' + shareToken, JSON.stringify(data), { expirationTtl: shareTtlFor(data) }); } catch (e) {}
    if (data.max > 0 && hits > data.max) return { resp: json({ error: 'Access limit reached', hits: data.max, max: data.max, name: data.name }, 403) };
  }
  await bumpShareStats(env, shareToken, data, 'view', req);
  return { ok: true };
}
async function handleShareData(env, shareToken, req) {
  try {
    const pw = new URL(req.url).searchParams.get('pw') || '';
    // 先取分享数据（不计数、不要求密码）。仅在密码（若设置）验证通过后才计入访问次数，
    // 否则密码保护链接会在尚未认证时就被匿名消耗掉访问配额（修复：未授权即扣减访问次数）
    const g = await shareGuard(env, shareToken, req, false, false);
    if (g.resp) return g.resp;
    const d = g.data;
    const stats = { hits: d.max > 0 ? Math.min(d.hits || 0, d.max) : (d.hits || 0), max: d.max || 0 };
    const view = d.view || {};
    if (d.pwHash && !await verifyPassword(pw, { hash: d.pwHash, salt: d.pwSalt })) {
      return json(Object.assign({ needPassword: true, hasPassword: true, view, note: d.note || '' }, stats));
    }
    const c = await shareCount(env, shareToken, d, req);
    if (c.resp) return c.resp;
    return json(Object.assign({
      type: d.type || 'file', name: d.name, size: d.size || 0, mime: d.mime || '',
      allowDownload: d.allowDownload !== false, allowComment: d.allowComment !== false,
      once: !!d.once, note: d.note || '', view, slug: d.slug || '', token: shareToken
    }, stats));
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
// ===== 文件评论（站内 + 分享访客）=====
const COMMENT_MAX = 200;
const COMMENT_TEXT_MAX = 2000;
async function getComments(env, path) {
  try { return await env.STORE.get('comments:' + path, 'json') || []; } catch (e) { return []; }
}
async function addComment(env, path, text, who, req) {
  const t = String(text == null ? '' : text).trim();
  if (!t) return { error: 'Empty comment' };
  if (t.length > COMMENT_TEXT_MAX) return { error: 'Comment too long', max: COMMENT_TEXT_MAX };
  const key = 'comments:' + path;
  if (!kvKeyOk(key)) return { error: 'Path too long' };
  const list = await getComments(env, path);
  const ci = req ? clientInfo(req) : {};
  const item = {
    id: randToken().substring(0, 10), t: Date.now(),
    by: String(who || 'owner').slice(0, 40),
    ip: ci.ip || '', country: ci.country || '', text: t
  };
  list.unshift(item);
  while (list.length > COMMENT_MAX) list.pop();
  try { await env.STORE.put(key, JSON.stringify(list), { expirationTtl: 400 * 86400 }); } catch (e) { return { error: 'Save failed' }; }
  try { await notifyWebhook(env, { event: 'comment', path, detail: item.by + ': ' + t.slice(0, 120) }); } catch (e) {}
  return { ok: true, item, count: list.length };
}
async function handleComments(env, req, url) {
  let body = null;
  if (req.method === 'POST' || req.method === 'DELETE') { try { body = await req.json(); } catch (e) { body = null; } }
  const path = String(url.searchParams.get('path') || (body && body.path) || '');
  if (!path) return json({ error: 'No path' }, 400);
  if (req.method === 'GET') return json({ comments: await getComments(env, path) });
  if (req.method === 'POST') {
    const b = body || {};
    const r = await addComment(env, path, b.text, b.by || 'owner', req);
    if (r.error) return json({ error: r.error }, r.error === 'Comment too long' ? 413 : 400);
    try { await addLog(env, 'cmt', path, String(b.text || '').slice(0, 60)); } catch (e) {}
    return json(r);
  }
  if (req.method === 'DELETE') {
    const id = String(url.searchParams.get('id') || (body && body.id) || '');
    const list = await getComments(env, path);
    const next = list.filter(c => c.id !== id);
    try { await env.STORE.put('comments:' + path, JSON.stringify(next), { expirationTtl: 400 * 86400 }); } catch (e) {}
    return json({ ok: true, removed: list.length - next.length });
  }
  return json({ error: 'Method not allowed' }, 405);
}
// 分享访客评论（受限：必须在分享范围内，且分享允许评论）
async function handleShareComment(env, shareToken, req) {
  try {
    const g = await shareGuard(env, shareToken, req, false, true);
    if (g.resp) return g.resp;
    const d = g.data;
    if (d.allowComment === false) return json({ error: 'Comment disabled' }, 403);
    const b = await req.json();
    let target;
    if (d.type === 'dir') {
      const base = normPath(d.path);
      const rel = String(b.p || '');
      const full = normPath(base + rel);
      if (!full.startsWith(base)) return json({ error: 'Forbidden' }, 403);
      target = full.replace(/\/+$/, '') || '/';
    } else {
      target = '/' + String(d.path || '').replace(/^\/+/, '');
    }
    const r = await addComment(env, target, b.text, (b.name ? String(b.name).slice(0, 40) : 'guest'), req);
    if (r.error) return json({ error: r.error }, r.error === 'Comment too long' ? 413 : 400);
    return json({ ok: true, count: r.count });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
async function handleShareList(env, shareToken, req) {
  try {
    const g = await shareGuard(env, shareToken, req, false, true);
    if (g.resp) return g.resp;
    const d = g.data;
    if (d.type !== 'dir') return json({ error: 'Not a folder share' }, 400);
    const rel = new URL(req.url).searchParams.get('p') || '';
    const base = normPath(d.path);
    const dir = normPath(base + rel);
    if (!dir.startsWith(base)) return json({ error: 'Forbidden' }, 403);
    // H3: 分享根目录之下的加密子目录同样不能通过分享访问
    if (await isPathLocked(env, dir, '')) return json({ error: 'Locked' }, 423);
    const items = await getDir(env, dir);
    const out = items
      .filter(it => it && it.name && it.name !== '.trash')
      .map(it => ({ name: it.name, type: it.type, size: it.size || 0, mime: it.mime || '', time: it.time || '', hasThumb: !!it.hasThumb }));
    out.sort((a, b) => (a.type === b.type ? String(a.name).localeCompare(String(b.name)) : (a.type === 'dir' ? -1 : 1)));
    return json({ rel: String(rel).replace(/^\/+|\/+$/g, ''), items: out });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
async function handleSharePreview(env, shareToken, req) {
  try {
    const g = await shareGuard(env, shareToken, req, false, true);
    if (g.resp) return g.resp;
    const key = shareRelKey(g.data, new URL(req.url).searchParams.get('p') || '');
    if (!key) return json({ error: 'Not found' }, 404);
    if (await isPathLocked(env, parentOf('/' + key), '')) return json({ error: 'Locked' }, 423);
    return await serveObject(env, req, key, { disposition: 'inline', sanitize: true, cacheControl: 'private, max-age=3600' });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
async function handleShareDownload(env, shareToken, req) {
  try {
    const g = await shareGuard(env, shareToken, req, false, true);
    if (g.resp) return g.resp;
    const d = g.data;
    if (d.allowDownload === false) return json({ error: 'Download disabled' }, 403);
    if (d.once && d.downloaded) return json({ error: 'Download already used', once: true }, 410);
    const key = shareRelKey(d, new URL(req.url).searchParams.get('p') || '');
    if (!key) return json({ error: 'Not found' }, 404);
    if (await isPathLocked(env, parentOf('/' + key), '')) return json({ error: 'Locked' }, 423);
    const name = key.split('/').pop();
    const resp = await serveObject(env, req, key, { disposition: 'attachment; filename="' + encodeURIComponent(name) + '"' });
    if (resp.status === 200) {
      await addDownloadLog(env, Object.assign({ time: new Date().toISOString(), path: '/' + key, name, size: d.size || 0, source: 'share' }, clientInfo(req)));
      if (d.once && !d.downloaded) {
        d.downloaded = true;
        try { await env.STORE.put('share:' + shareToken, JSON.stringify(d), { expirationTtl: shareTtlFor(d) }); } catch (e) {}
      }
      await bumpShareStats(env, shareToken, d, 'download', req);
    }
    return resp;
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
async function handleBatchShare(env, paths, days, maxAccesses, password, sessionToken) {
  const items = [];
  let created = 0, failed = 0;
  for (const p of (Array.isArray(paths) ? paths : [])) {
    try {
      const fp = '/' + String(p || '').replace(/^\/+/, '');
      if (fp === '/') { failed++; continue; }
      if (await isPathLocked(env, fp, sessionToken || '') || await isPathLocked(env, parentOf(fp), sessionToken || '')) { items.push({ path: fp, error: 'locked' }); failed++; continue; }
      const base = parentOf(fp);
      const nm = fp.split('/').filter(Boolean).pop();
      const found = await findDirItem(env, base, nm);
      const isDir = !!(found.item && found.item.type === 'dir');
      const r = await createShare(env, fp, days, maxAccesses, password, isDir);
      if (r && r.ok) { items.push({ path: fp, name: r.name, url: r.url, type: isDir ? 'dir' : 'file' }); created++; }
      else { items.push({ path: fp, error: (r && r.locked) ? 'locked' : 'failed' }); failed++; }
    } catch (e) { failed++; }
  }
  return json({ ok: true, created, failed, items });
}
async function handleBatchMove(env, paths, target) {
  const t = normPath(target);
  let ok = 0, failed = 0;
  for (const p of (Array.isArray(paths) ? paths : [])) {
    try {
      const res = await handleMove(env, p, t);
      let good = false;
      try { const d = await res.clone().json(); good = !!(d && d.ok); } catch (e) {}
      if (good) ok++; else failed++;
    } catch (e) { failed++; }
  }
  return json({ ok: true, moved: ok, failed });
}

// ===== 公共页面设计 token（分享页 / 相册页 / 上传页共用，与主应用同一套变量）=====
function publicPageCss() {
  return `
/* 兼容旧变量名：页面原有 CSS 继续可用 */
:root{--sys-blue:#0a84ff;--sys-blue-hover:#0066ff;--sys-blue-soft:rgba(10,132,255,.14);
  --sys-card:rgba(255,255,255,.72);--sys-card-solid:#fff;--sys-fill:#f6f8fa;--sys-fill-2:#eef1f4;
  --sys-separator:rgba(0,0,0,.08);--sys-separator-opaque:#d8dee4;--sys-text:#1f2328;--sys-text-2:#57606a;--sys-text-3:#8c959f;
  --sys-green:#1a7f37;--sys-red:#cf222e;--sys-orange:#9a6700;--sys-shadow-sm:0 2px 8px rgba(31,35,40,.06);
  --sys-shadow-md:0 10px 30px rgba(31,35,40,.12);--sys-blur:saturate(180%) blur(20px);
  --bg:var(--sys-fill);--card:var(--sys-card-solid);--border:var(--sys-separator-opaque);--text:var(--sys-text);
  --text2:var(--sys-text-2);--text3:var(--sys-text-3);--accent:var(--sys-blue);--accent-h:var(--sys-blue-hover);
  --fill:var(--sys-fill);--red:var(--sys-red);--warn:var(--sys-orange)}
:root.dark{--sys-card:rgba(22,27,34,.72);--sys-card-solid:#161b22;--sys-fill:#0d1117;--sys-fill-2:#21262d;
  --sys-separator:rgba(255,255,255,.12);--sys-separator-opaque:#30363d;--sys-text:#e6edf3;--sys-text-2:#8b949e;--sys-text-3:#6e7681;
  --sys-blue-soft:rgba(47,129,247,.18);--sys-green:#3fb950;--sys-red:#f85149;--sys-orange:#d29922;
  --sys-shadow-sm:0 2px 10px rgba(0,0,0,.35);--sys-shadow-md:0 18px 44px rgba(0,0,0,.5);--bg:#0d1117;--card:#161b22}
body{background:var(--sys-fill);color:var(--sys-text);-webkit-font-smoothing:antialiased}
a{color:var(--sys-blue)}
/* 顶栏 + 卡片 + 按钮：与主应用一致的分级 */
.pg-bar{display:flex;align-items:center;gap:10px;margin-bottom:14px;padding:10px 14px;border-radius:16px;
  background:var(--sys-card);border:.5px solid var(--sys-separator);backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  box-shadow:var(--sys-shadow-sm)}
.pg-bar .pg-logo{font-size:20px;line-height:1}
.pg-bar .pg-title{font-weight:600;font-size:15px;letter-spacing:-.01em}
.pg-bar .pg-sub{font-size:11.5px;color:var(--sys-text-3);font-family:ui-monospace,Menlo,monospace}
.pg-bar .pg-actions{margin-left:auto;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.pg-card{background:var(--sys-card-solid);border:.5px solid var(--sys-separator);border-radius:18px;padding:18px;box-shadow:var(--sys-shadow-md)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:12px;border:1px solid var(--sys-separator);
  background:var(--sys-card-solid);color:var(--sys-text);font-size:14px;font-weight:500;cursor:pointer;text-decoration:none;transition:filter .12s,background .12s}
.btn:hover{background:var(--sys-fill-2)}
.btn.primary{background:linear-gradient(180deg,var(--sys-blue),var(--sys-blue-hover));color:#fff;border-color:transparent}
.btn.gray{background:var(--sys-fill);border-color:transparent;color:var(--sys-text)}
.btn.tiny{padding:5px 11px;font-size:12.5px;border-radius:10px}
.btn.danger{background:var(--sys-red);color:#fff;border-color:transparent}
.chip{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;border:1px solid var(--sys-separator);
  background:var(--sys-fill);color:var(--sys-text);font-size:12.5px;cursor:pointer}
.dup-path{font-size:11.5px;color:var(--sys-text-3);font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.theme-btn{position:fixed;top:16px;right:16px;z-index:999;width:42px;height:42px;border-radius:50%;border:1px solid var(--sys-separator);
  background:var(--sys-card-solid);color:var(--sys-text);font-size:18px;cursor:pointer;box-shadow:var(--sys-shadow-md);
  display:flex;align-items:center;justify-content:center;backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);transition:transform .12s}
.theme-btn:active{transform:scale(.92)}
:root[data-density="compact"] .pg-card{padding:13px}
:root[data-density="compact"] .row{padding:7px 6px}
:root[data-density="compact"] .list li{padding:5px 0}
`;
}
function publicPageThemeJs() {
  return "(function(){"
    + "var dth=localStorage.getItem('dth')||'auto';"
    + "function applyTheme(){var h=document.documentElement;var d=dth==='dark'||(dth==='auto'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches);h.classList.toggle('dark',!!d);var b=document.getElementById('themeBtn');if(b)b.textContent=dth==='auto'?'\\uD83C\\uDF17':(dth==='light'?'\\u2600\\uFE0F':'\\uD83C\\uDF19')}"
    + "function hexA(x,a){var s=String(x||'').replace('#','');if(s.length===3)s=s[0]+s[0]+s[1]+s[1]+s[2]+s[2];var n=parseInt(s,16);if(!isFinite(n))return 'rgba(10,132,255,'+a+')';return 'rgba('+((n>>16)&255)+','+((n>>8)&255)+','+(n&255)+','+a+')'}"
    + "function applyAccent(){try{var c=localStorage.getItem('dAccent');if(!/^#[0-9a-fA-F]{6}$/.test(String(c||'')))return;var r=document.documentElement;r.style.setProperty('--sys-blue',c);r.style.setProperty('--sys-blue-hover',c);r.style.setProperty('--sys-blue-soft',hexA(c,0.14))}catch(e){}}"
    + "function applyDensity(){try{var v=localStorage.getItem('dDensity')==='compact'?'compact':'cozy';document.documentElement.setAttribute('data-density',v)}catch(e){}}"
    + "applyTheme();applyAccent();applyDensity();"
    + "var b=document.createElement('button');b.id='themeBtn';b.className='theme-btn';b.title='\\u5207\\u6362\\u4e3b\\u9898';b.textContent='\\uD83C\\uDF17';"
    + "b.onclick=function(){dth=dth==='auto'?'light':(dth==='light'?'dark':'auto');localStorage.setItem('dth',dth);applyTheme()};"
    + "document.body.appendChild(b);"
    + "if(window.matchMedia){try{window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(){if(dth==='auto')applyTheme()})}catch(e){}}"
    + "})();";
}

function sharePage(token, rec) {
  const view = (rec && rec.view) || {};
  const title = escHtml(view.title || '文件分享');
  const note = escHtml((rec && rec.note) || '');
  const accent = (view.color && /^#[0-9a-fA-F]{3,8}$/.test(view.color)) ? view.color : '';
  const allowDl = !(rec && rec.allowDownload === false);
  const allowCmt = !(rec && rec.allowComment === false);
  const desc = escHtml(view.desc || '');
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
${publicPageCss()}
${accent ? ':root{--sys-blue:' + accent + ';--sys-blue-hover:' + accent + ';--accent:' + accent + '}' : ''}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:28px;max-width:560px;width:100%;text-align:center}
h2{font-size:13px;color:var(--text2);margin-bottom:8px;font-weight:600;letter-spacing:.4px}
.meta{font-size:12px;color:var(--text3);margin-bottom:16px;font-family:ui-monospace,Menlo,monospace}
.name{font-size:16px;word-break:break-all;margin-bottom:6px;font-weight:600}
.ficon{font-size:38px;line-height:1;margin:4px 0 8px}
.pv{margin:16px 0;max-height:60vh;overflow:auto;background:var(--fill);border:1px solid var(--border);border-radius:8px;padding:12px}
.pv img,.pv video{max-width:100%;max-height:55vh;border-radius:6px}
.pv audio{width:100%}
.pv pre{text-align:left;font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-all;margin:0;font-family:ui-monospace,Menlo,monospace}
input,button{padding:9px 14px;border-radius:6px;border:1px solid var(--border);background:var(--fill);color:inherit;font-size:14px;outline:none;font-family:inherit}
input{flex:1;min-width:0;background:var(--card)}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(9,105,218,.15)}
button{cursor:pointer;background:var(--accent);border-color:var(--accent);color:#fff;font-weight:500;padding:9px 20px}
button:hover{background:var(--accent-h);border-color:var(--accent-h)}
.row{display:flex;gap:8px;margin-top:16px}
.msg{font-size:13px;margin-top:12px;min-height:18px}
.err{color:var(--red)}
.hidden{display:none!important}

.theme-btn{position:fixed;top:16px;right:16px;z-index:999;width:42px;height:42px;border-radius:50%;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:18px;cursor:pointer;box-shadow:0 8px 22px rgba(0,0,0,.18);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);transition:transform .12s}
.theme-btn:active{transform:scale(.92)}
.card{box-shadow:0 14px 34px rgba(31,35,40,.12);border-radius:20px}
:root.dark .card{box-shadow:0 18px 44px rgba(0,0,0,.5)}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="card">
<h2>📎 ${title}</h2>
${desc ? '<div class="meta" style="font-family:inherit;font-size:13px">' + desc + '</div>' : ''}
<div class="meta" id="meta">加载中...</div>
<div class="ficon" id="ficon">📄</div>
<div class="name" id="fname">—</div>
${note ? '<div style="font-size:12px;color:var(--warn);margin:6px 0 4px;white-space:pre-wrap;word-break:break-word">' + note + '</div>' : ''}
<div class="pv hidden" id="pvBox"></div>
<div class="row hidden" id="pwRow"><input type="password" id="pwInput" placeholder="请输入访问密码" autocomplete="off"><button id="btnPw">确定</button></div>
<div class="row hidden" id="dlRow"><button id="btnDl">下载文件</button></div>
${allowCmt ? '<div id="cmtWrap" style="margin-top:18px;text-align:left"><div style="font-size:12px;color:var(--text3);margin-bottom:6px">💬 留言</div><div id="cmtList" style="max-height:220px;overflow:auto;font-size:13px"></div><div class="row" style="margin-top:8px"><input id="cmtName" placeholder="昵称（可选）" style="flex:0 0 110px;padding:8px 10px;border-radius:8px;border:1px solid var(--border);background:var(--fill);color:inherit"><input id="cmtText" placeholder="说点什么..." style="flex:1;padding:8px 10px;border-radius:8px;border:1px solid var(--border);background:var(--fill);color:inherit"><button id="cmtSend">发送</button></div></div>' : ''}
<div class="msg" id="msg"></div>
</div>
<script>
var tk=${JSON.stringify(token)};
var pw='';
var ALLOW_DL=${allowDl ? 'true' : 'false'};
var ALLOW_CMT=${allowCmt ? 'true' : 'false'};
var fname='',fmime='',fsize=0;
function esc(s){return String(s==null?'':s).replace(/[&<>"'\`]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\`':'&#96;'}[c]})}
function fmt(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i]}
function setMsg(s,isErr){var m=document.getElementById('msg');m.textContent=s||'';m.className='msg'+(isErr?' err':'')}
function iconFor(m){m=String(m||'').toLowerCase();if(m.indexOf('image/')===0)return'🖼️';if(m.indexOf('video/')===0)return'🎬';if(m.indexOf('audio/')===0)return'🎵';if(m.indexOf('pdf')>=0)return'📄';if(m.indexOf('zip')>=0||m.indexOf('compress')>=0)return'📦';if(m.indexOf('text/')===0||m.indexOf('json')>=0)return'📝';if(m.indexOf('word')>=0||m.indexOf('document')>=0)return'📃';if(m.indexOf('sheet')>=0||m.indexOf('excel')>=0)return'📊';return'📄'}

function loadData(){
  fetch('/s/'+tk+'/data',{cache:'no-store'}).then(function(r){return r.json().then(function(d){return{r:r,d:d}})}).then(function(res){
    var d=res.d;
    if(res.r.status===403 || d.error==='Access limit reached'){
      document.getElementById('meta').textContent='—';
      document.getElementById('fname').textContent=d.name||'';
      document.getElementById('pvBox').classList.add('hidden');
      document.getElementById('dlRow').classList.add('hidden');
      document.getElementById('pwRow').classList.add('hidden');
      setMsg('访问次数已达上限，链接已失效',true);
      return;
    }
    if(d.error){setMsg(d.error,true);document.getElementById('meta').textContent='—';return}
    if(d.needPassword){
      document.getElementById('meta').textContent=(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
      document.getElementById('pwRow').classList.remove('hidden');
      return;
    }
    fname=d.name||'';fmime=d.mime||'';fsize=d.size||0;
    document.getElementById('fname').textContent=fname;
    document.getElementById('ficon').textContent=iconFor(fmime);
    document.getElementById('meta').textContent=fmt(fsize)+' · '+(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
    document.getElementById('pwRow').classList.add('hidden');
    if(ALLOW_DL)document.getElementById('dlRow').classList.remove('hidden');
    else setMsg((d.once?'此链接为一次性下载，已被使用':'该分享仅允许在线预览，未开放下载'),false);
    tryPreview();
    loadComments();
  }).catch(function(){setMsg('加载失败',true)});
}
function loadComments(){
  if(!ALLOW_CMT)return;
  fetch('/s/'+tk+'/comments',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
    var box=document.getElementById('cmtList');if(!box)return;
    var list=d.comments||[];
    if(!list.length){box.innerHTML='<div style="color:var(--text3);font-size:12px">还没有留言</div>';return}
    box.innerHTML=list.map(function(c){
      return '<div style="padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text2);font-size:12px">'+esc(c.by||'guest')+' · '+esc(new Date(c.t).toLocaleString())+'</span><div style="white-space:pre-wrap;word-break:break-word">'+esc(c.text||'')+'</div></div>';
    }).join('');
  }).catch(function(){});
}
function sendComment(){
  if(!ALLOW_CMT)return;
  var t=document.getElementById('cmtText'),n=document.getElementById('cmtName');
  var text=(t&&t.value||'').trim();if(!text)return;
  fetch('/s/'+tk+'/comment',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,name:(n&&n.value||'').trim()})}).then(function(r){return r.json()}).then(function(d){
    if(d&&d.ok){if(t)t.value='';loadComments()}
    else setMsg((d&&d.error)||'留言失败',true);
  }).catch(function(){setMsg('留言失败',true)});
}
function tryPreview(){
  if(!fmime)return;
  if(fmime.indexOf('image/')===0){
    document.getElementById('pvBox').innerHTML='<img src="/s/'+tk+'/pv?pw='+encodeURIComponent(pw)+'">';
    document.getElementById('pvBox').classList.remove('hidden');
  }else if(fmime.indexOf('video/')===0){
    document.getElementById('pvBox').innerHTML='<video controls src="/s/'+tk+'/pv?pw='+encodeURIComponent(pw)+'"></video>';
    document.getElementById('pvBox').classList.remove('hidden');
  }else if(fmime.indexOf('audio/')===0){
    document.getElementById('pvBox').innerHTML='<audio controls src="/s/'+tk+'/pv?pw='+encodeURIComponent(pw)+'"></audio>';
    document.getElementById('pvBox').classList.remove('hidden');
  }else if(fmime.indexOf('text/')===0||fmime==='application/json'){
    fetch('/s/'+tk+'/pv?pw='+encodeURIComponent(pw)).then(function(r){return r.text()}).then(function(txt){
      document.getElementById('pvBox').innerHTML='<pre>'+esc(txt.substring(0,50000))+'</pre>';
      document.getElementById('pvBox').classList.remove('hidden');
    });
  }
}
document.getElementById('btnPw').onclick=function(){
  pw=document.getElementById('pwInput').value;
  setMsg('');
  fetch('/s/'+tk+'/data?pw='+encodeURIComponent(pw),{cache:'no-store'}).then(function(r){
    return r.json().then(function(d){return{r:r,d:d}});
  }).then(function(res){
    var d=res.d;
    if(res.r.status===403 || d.error==='Access limit reached'){setMsg('访问次数已达上限，链接已失效',true);return}
    if(res.r.status===410){setMsg('链接已过期',true);return}
    if(d.needPassword){setMsg('密码错误',true);return}
    fname=d.name||'';fmime=d.mime||'';fsize=d.size||0;
    document.getElementById('fname').textContent=fname;
    document.getElementById('ficon').textContent=iconFor(fmime);
    document.getElementById('meta').textContent=fmt(fsize)+' · '+(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
    document.getElementById('pwRow').classList.add('hidden');
    if(ALLOW_DL)document.getElementById('dlRow').classList.remove('hidden');
    tryPreview();
    loadComments();
  }).catch(function(){setMsg('密码错误或加载失败',true)});
};
document.getElementById('pwInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnPw').click()};
(function(){var b=document.getElementById('cmtSend');if(b)b.onclick=sendComment})();
(function(){var b=document.getElementById('btnZipAll');if(b)b.onclick=function(){window.location='/s/'+tk+'/zip?p='+encodeURIComponent(rel||'')+'&pw='+encodeURIComponent(pw)}})();
document.getElementById('btnDl').onclick=function(){
  window.location='/s/'+tk+'/dl?pw='+encodeURIComponent(pw);
};
loadData();
</script><script>${publicPageThemeJs()}</script></body></html>`;
}

function shareDirPage(token, rec) {
  const tk = JSON.stringify(token);
  const dview = (rec && rec.view) || {};
  const title = escHtml(dview.title || '文件夹分享');
  const descD = escHtml(dview.desc || '');
  const noteD = escHtml((rec && rec.note) || '');
  const allowDlD = !(rec && rec.allowDownload === false);
  const allowCmtD = !(rec && rec.allowComment === false);
  const daccent = (dview.color && /^#[0-9a-fA-F]{3,8}$/.test(dview.color)) ? dview.color : '';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
${publicPageCss()}
${daccent ? ':root{--sys-blue:' + daccent + ';--sys-blue-hover:' + daccent + ';--accent:' + daccent + '}' : ''}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:22px;max-width:720px;width:100%;align-self:flex-start}
h2{font-size:13px;color:var(--text2);margin-bottom:6px;font-weight:600;letter-spacing:.4px}
.meta{font-size:12px;color:var(--text3);margin-bottom:12px;font-family:ui-monospace,Menlo,monospace}
.name{font-size:16px;font-weight:600;margin-bottom:12px;word-break:break-all}
.bc{font-size:13px;color:var(--text2);padding:8px 2px;border-bottom:1px solid var(--border);margin-bottom:2px;overflow-x:auto;white-space:nowrap}
.bc a{color:var(--accent);cursor:pointer;text-decoration:none}
.bc a:hover{text-decoration:underline}
.row{display:flex;align-items:center;gap:10px;padding:9px 6px;border-bottom:1px solid var(--border);font-size:14px}
.row:hover{background:var(--fill)}
.row .ic{width:22px;text-align:center;flex-shrink:0}
.row .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .nm.dir{cursor:pointer;color:var(--accent);font-weight:500}
.row .nm.dir:hover{text-decoration:underline}
.row .sz{font-size:12px;color:var(--text3);font-family:ui-monospace,Menlo,monospace;min-width:78px;text-align:right}
.row .dt{font-size:12px;color:var(--text3);font-family:ui-monospace,Menlo,monospace;min-width:76px;text-align:right;display:none}
@media(min-width:560px){.row .dt{display:block}}
.row button{padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--fill);color:var(--text);font-size:12px;cursor:pointer;font-family:inherit}
.row button:hover{border-color:var(--accent);color:var(--accent)}
input,button.btn{padding:9px 14px;border-radius:6px;border:1px solid var(--border);background:var(--fill);color:inherit;font-size:14px;outline:none;font-family:inherit}
input{flex:1;min-width:0;background:var(--card)}
button.btn{cursor:pointer;background:var(--accent);border-color:var(--accent);color:#fff;font-weight:500}
button.btn:hover{background:var(--accent-h);border-color:var(--accent-h)}
.pwrow{display:flex;gap:8px;margin:10px 0}
.msg{font-size:13px;margin-top:10px;min-height:18px}
.err{color:var(--red)}
.hidden{display:none!important}
.empty{padding:26px;text-align:center;color:var(--text3);font-size:14px}

.theme-btn{position:fixed;top:16px;right:16px;z-index:999;width:42px;height:42px;border-radius:50%;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:18px;cursor:pointer;box-shadow:0 8px 22px rgba(0,0,0,.18);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);transition:transform .12s}
.theme-btn:active{transform:scale(.92)}
.card{box-shadow:0 14px 34px rgba(31,35,40,.12);border-radius:20px}
:root.dark .card{box-shadow:0 18px 44px rgba(0,0,0,.5)}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="card">
  <h2>📁 ${title}</h2>
  ${descD ? '<div class="meta" style="font-family:inherit;font-size:13px">' + descD + '</div>' : ''}
  <div class="meta" id="meta">加载中...</div>
  <div class="name" id="fname">—</div>
  ${noteD ? '<div style="font-size:12px;color:var(--warn);margin:0 0 8px;white-space:pre-wrap;word-break:break-word">' + noteD + '</div>' : ''}
  <div class="pwrow hidden" id="pwRow"><input type="password" id="pwInput" placeholder="请输入访问密码" autocomplete="off"><button class="btn" id="btnPw">确定</button></div>
  <div class="hidden" id="box"><div class="bc" id="bc"></div><div id="list"></div>${allowDlD ? '<div style="margin-top:12px;text-align:right"><button class="btn" id="btnZipAll">📦 打包下载整个文件夹</button></div>' : ''}</div>
  ${allowCmtD ? '<div id="cmtWrap" style="margin-top:18px"><div style="font-size:12px;color:var(--text3);margin-bottom:6px">💬 留言</div><div id="cmtList" style="max-height:200px;overflow:auto;font-size:13px"></div><div style="display:flex;gap:8px;margin-top:8px"><input id="cmtName" placeholder="昵称（可选）" style="flex:0 0 110px"><input id="cmtText" placeholder="说点什么..."><button class="btn" id="cmtSend">发送</button></div></div>' : ''}
  <div class="msg" id="msg"></div>
</div>
<script>
var tk=${tk},pw='',rel='';
var ALLOW_DL=${allowDlD ? 'true' : 'false'};
var ALLOW_CMT=${allowCmtD ? 'true' : 'false'};
function esc(s){return String(s==null?'':s).replace(/[&<>"'\`]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\`':'&#96;'}[c]})}
function fmt(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i]}
function setMsg(s,isErr){var m=document.getElementById('msg');m.textContent=s||'';m.className='msg'+(isErr?' err':'')}
function loadComments(){
  if(!ALLOW_CMT)return;
  fetch('/s/'+tk+'/comments?p='+encodeURIComponent(rel||''),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
    var box=document.getElementById('cmtList');if(!box)return;
    var list=d.comments||[];
    if(!list.length){box.innerHTML='<div style="color:var(--text3);font-size:12px">还没有留言</div>';return}
    box.innerHTML=list.map(function(c){
      return '<div style="padding:6px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text2);font-size:12px">'+esc(c.by||'guest')+' · '+esc(new Date(c.t).toLocaleString())+'</span><div style="white-space:pre-wrap;word-break:break-word">'+esc(c.text||'')+'</div></div>';
    }).join('');
  }).catch(function(){});
}
function sendComment(){
  var t=document.getElementById('cmtText'),n=document.getElementById('cmtName');
  var text=(t&&t.value||'').trim();if(!text)return;
  fetch('/s/'+tk+'/comment',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,name:(n&&n.value||'').trim(),p:rel||''})}).then(function(r){return r.json()}).then(function(d){
    if(d&&d.ok){if(t)t.value='';loadComments()}else setMsg((d&&d.error)||'留言失败',true);
  }).catch(function(){setMsg('留言失败',true)});
}
function iconFor(n,m){m=String(m||'').toLowerCase();n=String(n||'').toLowerCase();if(m.indexOf('image/')===0)return'🖼️';if(m.indexOf('video/')===0)return'🎬';if(m.indexOf('audio/')===0)return'🎵';if(n.endsWith('.zip'))return'📦';if(m.indexOf('pdf')>=0)return'📄';if(m.indexOf('sheet')>=0||n.endsWith('.xlsx')||n.endsWith('.xls'))return'📊';if(n.endsWith('.docx')||n.endsWith('.doc'))return'📃';if(m.indexOf('text/')===0||m.indexOf('json')>=0||n.endsWith('.md'))return'📝';return'📄'}
function load(){
  fetch('/s/'+tk+'/data',{cache:'no-store'}).then(function(r){return r.json().then(function(d){return{r:r,d:d}})}).then(function(res){
    var d=res.d;
    if(res.r.status===403){setMsg(d.error==='Access limit reached'?'访问次数已达上限，链接已失效':(d.error||''),true);document.getElementById('fname').textContent=d.name||'';document.getElementById('meta').textContent='—';return}
    if(d.error){setMsg(d.error,true);document.getElementById('meta').textContent='—';return}
    if(d.needPassword){
      document.getElementById('meta').textContent=(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
      document.getElementById('pwRow').classList.remove('hidden');
      return;
    }
    document.getElementById('fname').textContent=d.name||'—';
    document.getElementById('meta').textContent=(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
    document.getElementById('pwRow').classList.add('hidden');
    document.getElementById('box').classList.remove('hidden');
    render();
    loadComments();
  }).catch(function(){setMsg('加载失败',true)});
}
function go(r){rel=r;render()}
function render(){
  fetch('/s/'+tk+'/list?p='+encodeURIComponent(rel)+'&pw='+encodeURIComponent(pw),{cache:'no-store'}).then(function(r){
    return r.json().then(function(d){
      if(d.error){setMsg(d.error==='Wrong password'?'密码错误':(d.error||''),true);return}
      setMsg('');
      var parts=String(rel||'').split('/').filter(Boolean);
      var h='<a data-go="">根目录</a>';var acc='';
      parts.forEach(function(p){acc+=(acc?'/':'')+p;h+=' <span style="opacity:.4">/</span> <a data-go="'+esc(acc)+'">'+esc(p)+'</a>'});
      document.getElementById('bc').innerHTML=h;
      document.getElementById('bc').querySelectorAll('[data-go]').forEach(function(a){a.onclick=function(){go(a.getAttribute('data-go'))}});
      var it=d.items||[];
      if(!it.length){document.getElementById('list').innerHTML='<div class="empty">此文件夹为空</div>';return}
      var html='';
      it.forEach(function(x){
        var sub=(rel?(rel.replace(/\\/+$/,'')+'/'):'')+x.name;
        if(x.type==='dir'){
          html+='<div class="row"><span class="ic">📁</span><span class="nm dir" data-d="'+esc(sub)+'">'+esc(x.name)+'</span><span class="dt"></span><span class="sz"></span><span></span></div>';
        }else{
          var href='/s/'+tk+'/dl?p='+encodeURIComponent(sub)+'&amp;pw='+encodeURIComponent(pw);
          html+='<div class="row"><span class="ic">'+iconFor(x.name,x.mime)+'</span><span class="nm">'+esc(x.name)+'</span><span class="dt">'+esc(String(x.time||'').slice(0,10))+'</span><span class="sz">'+fmt(x.size)+'</span><a href="'+href+'"><button>下载</button></a></div>';
        }
      });
      document.getElementById('list').innerHTML=html;
      document.getElementById('list').querySelectorAll('[data-d]').forEach(function(el){el.onclick=function(){go(el.getAttribute('data-d'))}});
    });
  }).catch(function(){setMsg('加载失败',true)});
}
document.getElementById('btnPw').onclick=function(){
  pw=document.getElementById('pwInput').value;setMsg('');
  fetch('/s/'+tk+'/data?pw='+encodeURIComponent(pw),{cache:'no-store'}).then(function(r){
    return r.json().then(function(d){return{r:r,d:d}});
  }).then(function(res){
    var d=res.d;
    if(res.r.status===403){setMsg('访问次数已达上限，链接已失效',true);return}
    if(d.needPassword){setMsg('密码错误',true);return}
    document.getElementById('fname').textContent=d.name||'—';
    document.getElementById('meta').textContent=(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
    document.getElementById('pwRow').classList.add('hidden');
    document.getElementById('box').classList.remove('hidden');
    render();
  }).catch(function(){setMsg('密码错误或加载失败',true)});
};
document.getElementById('pwInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnPw').click()};
load();
</script><script>${publicPageThemeJs()}</script></body></html>`;
}

// ===== Upload Links =====
async function handleCreateUploadLink(env, dirPath, days, maxFiles) {
  dirPath = normPath(dirPath); const t = randToken(); const ttl = clampDays(days) * 86400;
  await env.STORE.put('ulink:' + t, JSON.stringify({ path: dirPath, exp: Date.now() + ttl * 1000, max: clampCount(maxFiles), count: 0 }), { expirationTtl: ttl + 60 });
  return json({ ok: true, url: '/u/' + t });
}

function uploadPage(token) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件上传</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
${publicPageCss()}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:32px;max-width:440px;width:100%;text-align:center}
h2{font-size:18px;color:var(--text);margin-bottom:8px;font-weight:600}
p{font-size:14px;color:var(--text2);margin-bottom:24px}
.zone{border:1px dashed var(--border);border-radius:8px;padding:36px 20px;cursor:pointer;transition:all .15s;background:var(--fill)}
.zone:hover,.zone.over{border-color:var(--accent);background:var(--sys-blue-soft)}
.zone p{margin:0;font-size:15px;color:var(--text2)}
.list{margin-top:16px;text-align:left;font-size:14px}.list div{padding:8px 0;border-bottom:1px solid var(--border)}
.ok{color:var(--accent)}.err{color:var(--red)}
.card{box-shadow:var(--sys-shadow-md);border-radius:20px}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="card">
<div class="pg-bar" style="margin-bottom:18px;background:var(--sys-fill);box-shadow:none">
  <span class="pg-logo">📤</span>
  <div style="text-align:left"><div class="pg-title">文件上传</div><div class="pg-sub">有人给你分享了一个上传链接</div></div>
</div>
<div class="zone" id="zone"><p>点击或拖拽文件到此处</p></div>
<input type="file" id="fi" multiple style="display:none">
<div class="list" id="list"></div></div>
<script>
var tk=` + JSON.stringify(token) + `;
var zone=document.getElementById('zone'),fi=document.getElementById('fi'),list=document.getElementById('list');
zone.onclick=function(){fi.click()};
zone.ondragover=function(e){e.preventDefault();zone.classList.add('over')};
zone.ondragleave=function(){zone.classList.remove('over')};
zone.ondrop=function(e){e.preventDefault();zone.classList.remove('over');up(e.dataTransfer.files)};
fi.onchange=function(){up(fi.files);fi.value=''};
function up(files){for(var i=0;i<files.length;i++){(function(f){
var d=document.createElement('div');d.textContent=f.name+' - 上传中...';list.appendChild(d);
var fd=new FormData();fd.append('file',f);
fetch('/api/upload-link/'+tk,{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(r){
d.className=r.ok?'ok':'err';d.textContent=f.name+' - '+(r.ok?'完成':r.error||'失败');
}).catch(function(){d.className='err';d.textContent=f.name+' - 失败'});
})(files[i])}}
</`+`script><script>${publicPageThemeJs()}</script></body></html>`;
}

function errorPage(msg) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问受限</title>
<style>${publicPageCss()}*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.c{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:36px;max-width:400px;width:100%;text-align:center}h1{font-size:20px;margin-bottom:8px;color:var(--red)}p{font-size:14px;color:var(--text2)}
.theme-btn{position:fixed;top:16px;right:16px;z-index:999;width:42px;height:42px;border-radius:50%;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:18px;cursor:pointer;box-shadow:0 8px 22px rgba(0,0,0,.18);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);transition:transform .12s}
.theme-btn:active{transform:scale(.92)}
.card{box-shadow:0 14px 34px rgba(31,35,40,.12);border-radius:20px}
:root.dark .card{box-shadow:0 18px 44px rgba(0,0,0,.5)}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="c"><h1>⚠️ 链接不可用</h1><p>${escHtml(msg)}</p></div><script>${publicPageThemeJs()}</script></body></html>`;
}

function publicUploadPage(env) {
  const siteKey = String(turnstileSiteKey(env) || '');
  const dir = publicUploadDir(env) || '/';
  const tsHead = siteKey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></scr' + 'ipt>' : '';
  const tsWidget = siteKey ? '<div class="cf-turnstile" data-sitekey="' + escHtml(siteKey) + '" data-theme="auto" style="margin:14px 0"></div>' : '';
  const tsNote = siteKey ? '' : '<p style="font-size:12px;color:#ff9500">未启用 Turnstile 人机验证</p>';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件上传</title>
${tsHead}
<style>*{margin:0;padding:0;box-sizing:border-box}
${publicPageCss()}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:32px;max-width:460px;width:100%;text-align:center}
h2{font-size:18px;color:var(--text);margin-bottom:8px;font-weight:600}
p{font-size:14px;color:var(--text2);margin-bottom:20px}
code{background:var(--fill);border:1px solid var(--border);padding:2px 6px;border-radius:4px;font-size:13px;font-family:ui-monospace,Menlo,monospace}
.zone{border:1px dashed var(--border);border-radius:8px;padding:36px 20px;cursor:pointer;transition:all .15s;background:var(--fill)}
.zone:hover,.zone.over{border-color:var(--accent);background:var(--sys-blue-soft)}
.zone p{margin:0;font-size:15px;color:var(--text2)}
.list{margin-top:16px;text-align:left;font-size:14px}.list div{padding:8px 0;border-bottom:1px solid var(--border)}
.ok{color:var(--accent)}.err{color:var(--red)}
.card{box-shadow:var(--sys-shadow-md);border-radius:20px}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="card">
<div class="pg-bar" style="margin-bottom:18px;background:var(--sys-fill);box-shadow:none">
  <span class="pg-logo">📤</span>
  <div style="text-align:left;min-width:0"><div class="pg-title">公开上传</div><div class="pg-sub">${escHtml(dir)}</div></div>
</div>
<div class="zone" id="zone"><p>点击或拖拽文件到此处</p></div>
<input type="file" id="fi" multiple style="display:none">
${tsWidget}${tsNote}
<div class="list" id="list"></div></div>
<script>
var zone=document.getElementById('zone'),fi=document.getElementById('fi'),list=document.getElementById('list');
zone.onclick=function(){fi.click()};
zone.ondragover=function(e){e.preventDefault();zone.classList.add('over')};
zone.ondragleave=function(){zone.classList.remove('over')};
zone.ondrop=function(e){e.preventDefault();zone.classList.remove('over');up(e.dataTransfer.files)};
fi.onchange=function(){up(fi.files);fi.value=''};
function up(files){for(var i=0;i<files.length;i++){(function(f){
var d=document.createElement('div');d.textContent=f.name+' - 上传中...';list.appendChild(d);
var fd=new FormData();fd.append('file',f);
var ti=document.querySelector('input[name="cf-turnstile-response"]');
if(ti&&ti.value)fd.append('cf-turnstile-response',ti.value);
fetch('/api/public-upload',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(r){
d.className=r.ok?'ok':'err';d.textContent=f.name+' - '+(r.ok?'完成':(r.error||'失败'));
if(window.turnstile&&turnstile.reset){try{turnstile.reset()}catch(e){}}
}).catch(function(){d.className='err';d.textContent=f.name+' - 失败'});
})(files[i])}}
</scr` + `ipt><script>${publicPageThemeJs()}</script></body></html>`;
}

// ===== 元数据快照备份（KV + 目录树 → R2 的 .backup/，不显示在文件列表） =====
async function collectDirs(env) {
  const out = {};
  const seen = {};
  async function walk(dirPath, depth) {
    if (depth > 12 || seen[dirPath]) return;
    seen[dirPath] = 1;
    let items = [];
    try { items = await getDir(env, dirPath); } catch (e) { items = []; }
    out[dirPath] = items;
    for (const it of items) {
      if (it && it.type === 'dir' && it.name) await walk(dirPath + it.name + '/', depth + 1);
    }
  }
  await walk('/', 0);
  return out;
}
async function collectMeta(env) {
  // 注意：不纳入 meta:totp（二次验证密钥不应随快照/下载外泄，恢复时保留当前设置）
  const singles = ['meta:tags', 'meta:favs', 'meta:recent', 'meta:tokens', 'meta:autorule', 'meta:usage', 'meta:dlstat',
    'meta:favgroups', 'meta:albums', 'meta:config', 'meta:dirrules', 'meta:cron', 'meta:bookmarks'];
  // 每个前缀限制读取条数；整体还有字节预算，防止备份本身把 KV 读配额/R2 体积吃满
  const prefixes = [['note:', 400], ['tags:', 400], ['share:', 200], ['ulink:', 200], ['dirpass:', 100], ['versions:', 200]];
  const budget = backupMaxBytes(env);
  const kv = {};
  let bytes = 0, truncated = false;
  for (const key of singles) {
    try {
      const v = await env.STORE.get(key);
      if (v !== null && v !== undefined) { kv[key] = v; bytes += String(v).length; }
    } catch (e) {}
  }
  for (const [p, cap] of prefixes) {
    if (bytes >= budget) { truncated = true; break; }
    const keys = await listKV(env, p, cap);
    for (const k of keys) {
      if (bytes >= budget) { truncated = true; break; }
      try {
        const v = await env.STORE.get(k);
        if (v !== null && v !== undefined) { kv[k] = v; bytes += String(v).length; }
      } catch (e) {}
    }
  }
  return { kv, bytes, truncated: truncated || bytes >= budget };
}
async function dirChecksum(items) {
  const s = (items || []).map(i => (i && i.name) ? (i.name + ':' + (i.size || 0) + ':' + (i.type || '')) : '').sort().join('|');
  return (await sha256(s)).slice(0, 16);
}
async function backupIndex(env) {
  try { return await env.STORE.get('meta:backupidx', 'json'); } catch (e) { return null; }
}
// 解析快照链（增量 → 基线），返回合并后的目录与 KV
async function resolveSnapshot(env, key, withKv) {
  const out = { dirs: {}, kv: {}, chain: 0, truncated: false, created: '' };
  const seen = {};
  const stack = [];
  let cur = key;
  while (cur && !seen[cur] && stack.length < 25) {
    seen[cur] = 1;
    let snap = null;
    try {
      const o = await env.DRIVE.get(cur);
      if (o) snap = JSON.parse(new TextDecoder().decode(await o.arrayBuffer()));
    } catch (e) { snap = null; }
    if (!snap || typeof snap !== 'object') break;
    stack.push(snap);
    out.truncated = out.truncated || !!snap.truncated;
    cur = snap.base || null;
  }
  for (let i = stack.length - 1; i >= 0; i--) {
    const s = stack[i];
    if (s.dirs && typeof s.dirs === 'object') for (const p of Object.keys(s.dirs)) out.dirs[p] = s.dirs[p];
    if (Array.isArray(s.removed)) for (const p of s.removed) delete out.dirs[p];
    if (withKv && s.kv && typeof s.kv === 'object') Object.assign(out.kv, s.kv);
    if (!out.created) out.created = s.created || '';
    out.chain++;
  }
  return out;
}
async function createBackup(env, reason) {
  const dirs = await collectDirs(env);
  const checksums = {};
  for (const p of Object.keys(dirs)) checksums[p] = await dirChecksum(dirs[p]);
  // 增量：只存变化的目录 + 已删除目录清单，base 指向上一份快照
  const idx = await backupIndex(env);
  const useIncremental = cfgBool(env, 'BACKUP_INCREMENTAL', 'backupIncremental', true) && !!(idx && idx.key) && (idx.chain || 0) < 19;
  let base = null, storeDirs = dirs, removed = [], chain = 0;
  if (useIncremental) {
    const prev = idx.checksums || {};
    const changed = {};
    for (const p of Object.keys(dirs)) { if (prev[p] !== checksums[p]) changed[p] = dirs[p]; }
    for (const p of Object.keys(prev)) { if (!dirs[p]) removed.push(p); }
    base = idx.key; storeDirs = changed; chain = (idx.chain || 0) + 1;
  }
  const meta = await collectMeta(env);
  const kv = meta.kv;
  let dirCount = 0, fileCount = 0;
  for (const p of Object.keys(dirs)) {
    dirCount++;
    for (const it of dirs[p]) { if (it && it.type === 'file') fileCount++; }
  }
  const snap = {
    version: APP_VERSION, created: new Date().toISOString(), reason: reason || 'manual',
    incremental: !!base, base, chain, removed, truncated: meta.truncated,
    dirs: storeDirs, checksums, kv
  };
  const body = JSON.stringify(snap);
  const key = BACKUP_PREFIX + new Date().toISOString().substring(0, 10) + '-' + Date.now().toString(36) + '-' + randToken().substring(0, 6) + '.json';
  await env.DRIVE.put(key, body, { httpMetadata: { contentType: 'application/json' } });
  try {
    await env.STORE.put('meta:backupidx', JSON.stringify({ key, created: snap.created, base, chain, checksums, dirs: dirCount }), { expirationTtl: 400 * 86400 });
  } catch (e) {}
  // 备份保留策略：既限制份数，也限制总占用（防止快照把 R2 撑爆）
  try {
    const listed = await env.DRIVE.list({ prefix: BACKUP_PREFIX, limit: 1000 });
    const objs = (listed.objects || []).slice().sort(function (a, b) {
      const ta = a.uploaded ? new Date(a.uploaded).getTime() : 0;
      const tb = b.uploaded ? new Date(b.uploaded).getTime() : 0;
      if (ta !== tb) return tb - ta;
      return String(b.key).localeCompare(String(a.key));
    });
    const keep = backupKeep(env);
    const totalMax = backupTotalBytes(env);
    let acc = 0;
    for (let i = 0; i < objs.length; i++) {
      const o = objs[i];
      acc += o.size || 0;
      if (i >= keep || acc > totalMax) { try { await env.DRIVE.delete(o.key); } catch (e) {} }
    }
  } catch (e) {}
  return {
    ok: true, key, size: body.length, dirs: dirCount, files: fileCount, kvKeys: Object.keys(kv).length,
    truncated: meta.truncated, created: snap.created, version: APP_VERSION,
    incremental: !!base, base, chain, storedDirs: Object.keys(storeDirs).length, removedDirs: removed.length
  };
}
// 恢复前预览：对比快照与当前目录树
async function handleBackupDiff(env, key) {
  if (!key || String(key).indexOf(BACKUP_PREFIX) !== 0) return json({ error: 'Bad key' }, 400);
  const snap = await resolveSnapshot(env, key, false);
  if (!snap.chain) return json({ error: 'Not found' }, 404);
  const cur = await collectDirs(env);
  const added = [], removed = [], changed = [];
  for (const p of Object.keys(snap.dirs)) {
    if (!cur[p]) removed.push(p);
    else if (JSON.stringify(cur[p] || []) !== JSON.stringify(snap.dirs[p] || [])) changed.push(p);
  }
  for (const p of Object.keys(cur)) { if (!snap.dirs[p]) added.push(p); }
  return json({
    key, chain: snap.chain, truncated: snap.truncated, created: snap.created,
    snapshotDirs: Object.keys(snap.dirs).length, currentDirs: Object.keys(cur).length,
    added: added.slice(0, 200), removed: removed.slice(0, 200), changed: changed.slice(0, 200),
    addedTotal: added.length, removedTotal: removed.length, changedTotal: changed.length
  });
}
async function handleBackupList(env) {
  let items = [];
  try {
    const listed = await env.DRIVE.list({ prefix: BACKUP_PREFIX, limit: 1000 });
    items = (listed.objects || []).map(function (o) {
      return { key: o.key, size: o.size || 0, uploaded: (o.uploaded && o.uploaded.toISOString) ? o.uploaded.toISOString() : '' };
    });
    items.sort(function (a, b) {
      const ta = a.uploaded ? Date.parse(a.uploaded) : 0;
      const tb = b.uploaded ? Date.parse(b.uploaded) : 0;
      if (ta !== tb) return tb - ta;
      return String(b.key).localeCompare(String(a.key));
    });
  } catch (e) {}
  const idx = await backupIndex(env);
  return json({ backups: items, version: APP_VERSION, last: idx ? { key: idx.key, created: idx.created, base: idx.base || null, chain: idx.chain || 0, dirs: idx.dirs || 0 } : null });
}
async function handleBackupRestore(env, key, password) {
  if (!await checkAdminPassword(env, password || '')) return json({ error: 'Wrong password' }, 403);
  if (!key || String(key).indexOf(BACKUP_PREFIX) !== 0) return json({ error: 'Bad key' }, 400);
  const resolved = await resolveSnapshot(env, String(key), true);
  if (!resolved.chain) return json({ error: 'Not found' }, 404);
  const snap = { dirs: resolved.dirs, kv: resolved.kv, created: resolved.created, truncated: resolved.truncated };
  let dirs = 0, kvN = 0;
  if (snap.dirs && typeof snap.dirs === 'object') {
    for (const p of Object.keys(snap.dirs)) {
      const np = normPath(p);
      const items = Array.isArray(snap.dirs[p]) ? snap.dirs[p] : [];
      await putDir(env, np, items);
      dirs++;
    }
  }
  if (snap.kv && typeof snap.kv === 'object') {
    for (const k of Object.keys(snap.kv)) {
      // 敏感密钥：不随快照回滚
      if (k.indexOf('meta:adminpass') === 0 || k.indexOf('meta:totp') === 0 || k.indexOf('session:') === 0 || k.indexOf('meta:tokens') === 0) continue;
      try { await env.STORE.put(k, snap.kv[k]); kvN++; } catch (e) {}
    }
  }
  try { await addLog(env, 'res', '(备份恢复)', String(key)); } catch (e) {}
  return json({ ok: true, dirs, kvKeys: kvN, snapshot: snap.created || '', truncated: !!snap.truncated, chain: resolved.chain });
}

// ===== 站点配置面板 =====
async function handleConfigGet(env) {
  await loadConfig(env, true);
  const eff = {
    title: siteTitle(env), logo: siteLogo(env),
    quotaGB: Math.round(quotaTotal(env) / 1073741824 * 100) / 100,
    maxDirItems: maxDirItems(env), kvValueMB: Math.round(kvValueMax(env) / 1048576),
    versionMaxMB: Math.round(versionMaxBytes(env) / 1048576), versionsMax: maxVersions(env),
    versionsTtlDays: Math.round(versionsTtl(env) / 86400), hashTtlDays: Math.round(hashTtl(env) / 86400),
    trashDays: trashDays(env), chunkGcHours: chunkGcHours(env),
    backupKeep: backupKeep(env), backupMaxMB: Math.round(backupMaxBytes(env) / 1048576),
    backupTotalMB: Math.round(backupTotalBytes(env) / 1048576), backupIncremental: cfgBool(env, 'BACKUP_INCREMENTAL', 'backupIncremental', true),
    telemetryMaxPerDay: telemetryMaxPerDay(env), telemetryFlushMs: telemetryFlushMs(env),
    sessionCacheSec: sessionCacheSec(env), kvBudgetPerMin: kvBudgetPerMin(env),
    rlReadPerMin: rlReadPerMin(env), rlWritePerMin: rlWritePerMin(env),
    maxUploadMB: Math.round(maxUploadBytes(env) / 1048576),
    publicUploadDir: publicUploadDir(env) || '', publicUploadMaxMB: Math.round(publicUploadMax(env) / 1048576),
    ipAllow: cfgStr(env, 'IP_ALLOW', 'ipAllow', ''), ipDeny: cfgStr(env, 'IP_DENY', 'ipDeny', ''),
    countryAllow: cfgStr(env, 'COUNTRY_ALLOW', 'countryAllow', ''), countryDeny: cfgStr(env, 'COUNTRY_DENY', 'countryDeny', ''),
    uaAllow: cfgStr(env, 'UA_ALLOW', 'uaAllow', ''), uaDeny: cfgStr(env, 'UA_DENY', 'uaDeny', ''),
    disableUrlFetch: cfgBool(env, 'DISABLE_URL_FETCH', 'disableUrlFetch', false),
    signTtlMin: cfgNum(env, 'SIGN_TTL_MIN', 'signTtlMin', 60),
    shareZipMaxMB: cfgNum(env, 'SHARE_ZIP_MAX_MB', 'shareZipMaxMB', 512),
    notice: cfgStr(env, 'DRIVE_NOTICE', 'notice', '')
  };
  const envKeys = {
    title: 'DRIVE_TITLE', logo: 'DRIVE_LOGO', quotaGB: 'DRIVE_QUOTA', maxDirItems: 'MAX_DIR_ITEMS',
    maxUploadMB: 'MAX_UPLOAD_MB', trashDays: 'TRASH_DAYS', chunkGcHours: 'CHUNK_GC_HOURS',
    ipAllow: 'IP_ALLOW', ipDeny: 'IP_DENY', countryAllow: 'COUNTRY_ALLOW', countryDeny: 'COUNTRY_DENY',
    uaAllow: 'UA_ALLOW', uaDeny: 'UA_DENY', publicUploadDir: 'PUBLIC_UPLOAD_DIR', publicUploadMaxMB: 'PUBLIC_UPLOAD_MAX',
    disableUrlFetch: 'DISABLE_URL_FETCH', rlReadPerMin: 'RL_READ_PER_MIN', rlWritePerMin: 'RL_WRITE_PER_MIN'
  };
  const sources = {};
  for (const k of Object.keys(CONFIG_SPEC)) {
    const envSet = envKeys[k] && env && env[envKeys[k]] != null && env[envKeys[k]] !== '';
    sources[k] = (CFG[k] !== undefined && CFG[k] !== null) ? 'kv' : (envSet ? 'env' : 'default');
  }
  return json({ config: CFG, effective: eff, sources, spec: CONFIG_SPEC, envKeys });
}
async function handleConfigSet(env, b) {
  const patch = (b && b.patch) ? b.patch : (b || {});
  const { out, errs } = validateConfig(patch);
  if (errs.length) return json({ error: errs.join('; '), errors: errs }, 400);
  const cur = (await env.STORE.get('meta:config', 'json')) || {};
  for (const k of Object.keys(out)) {
    if (out[k] === null) delete cur[k];
    else cur[k] = out[k];
  }
  const s = JSON.stringify(cur);
  if (s.length > 8 * 1024) return json({ error: 'Config too large' }, 413);
  await env.STORE.put('meta:config', s);
  kvInvalidate('meta:config');
  await loadConfig(env, true);
  try { await addLog(env, 'sec', '(站点配置)', Object.keys(out).join(',')); } catch (e) {}
  return json({ ok: true, config: cur });
}
async function handleConfigReset(env) {
  try { await env.STORE.delete('meta:config'); } catch (e) {}
  CFG = {}; CFG_AT = Date.now(); CFG_OK = true;
  return json({ ok: true });
}

// ===== 目录级规则 =====
async function getDirRules(env) {
  return await kvCached('dirrules', 15, async () => {
    try { const r = await env.STORE.get('meta:dirrules', 'json'); return Array.isArray(r) ? r : []; } catch (e) { return []; }
  });
}
function ruleFor(rules, dirPath) {
  const np = normPath(dirPath);
  let best = null;
  for (const r of (rules || [])) {
    if (!r || !r.path) continue;
    const rp = normPath(r.path);
    if (np === rp || np.startsWith(rp)) { if (!best || rp.length > normPath(best.path).length) best = r; }
  }
  return best ? Object.assign({}, best, { path: normPath(best.path) }) : null;
}
async function checkDirRule(env, dirPath, name, size) {
  try {
    const rules = await getDirRules(env);
    if (!rules.length) return null;
    const r = ruleFor(rules, dirPath);
    if (!r) return null;
    const nm = String(name || '').toLowerCase();
    const ext = nm.indexOf('.') >= 0 ? nm.substring(nm.lastIndexOf('.')) : '';
    if (r.extDeny) {
      const list = csvList(r.extDeny).map(x => x.toLowerCase().replace(/^\*/, ''));
      if (list.some(x => x && (x === ext || nm.endsWith(x)))) return { error: '该目录不允许此类文件（' + ext + '）' };
    }
    if (r.extAllow) {
      const list = csvList(r.extAllow).map(x => x.toLowerCase().replace(/^\*/, ''));
      if (list.length && !list.some(x => x && (x === ext || nm.endsWith(x)))) return { error: '该目录只允许：' + r.extAllow };
    }
    if (r.maxFileMB && size > r.maxFileMB * 1048576) return { error: '该目录单文件上限 ' + r.maxFileMB + 'MB' };
    if (r.maxItems || r.maxBytes) {
      const items = await getDir(env, dirPath);
      const files = items.filter(i => i && i.type === 'file');
      const exists = files.some(i => i.name === name);
      if (!exists && r.maxItems && files.length >= r.maxItems) return { error: '该目录文件数已达上限 ' + r.maxItems };
      if (r.maxBytes && !exists) {
        let used = 0;
        for (const i of files) used += i.size || 0;
        if (used + (size || 0) > r.maxBytes * 1048576) return { error: '该目录容量上限 ' + r.maxBytes + 'MB' };
      }
    }
    return null;
  } catch (e) { return null; }
}
async function handleDirRules(env, req) {
  if (req.method === 'GET') return json({ rules: await getDirRules(env) });
  const b = await req.json();
  if (b && b.delete) {
    const list = (await getDirRules(env)).filter(r => normPath(r.path) !== normPath(b.delete));
    await env.STORE.put('meta:dirrules', JSON.stringify(list));
    kvInvalidate('dirrules');
    return json({ ok: true, rules: list });
  }
  const path = normPath((b && b.path) || '/');
  const rule = { path };
  if (b.maxItems !== undefined) rule.maxItems = Math.max(0, parseInt(b.maxItems, 10) || 0);
  if (b.maxBytes !== undefined) rule.maxBytes = Math.max(0, parseInt(b.maxBytes, 10) || 0);
  if (b.maxFileMB !== undefined) rule.maxFileMB = Math.max(0, parseInt(b.maxFileMB, 10) || 0);
  if (b.extAllow !== undefined) rule.extAllow = String(b.extAllow || '').slice(0, 300);
  if (b.extDeny !== undefined) rule.extDeny = String(b.extDeny || '').slice(0, 300);
  const list = (await getDirRules(env)).filter(r => normPath(r.path) !== path);
  if (rule.maxItems || rule.maxBytes || rule.maxFileMB || rule.extAllow || rule.extDeny) list.push(rule);
  if (list.length > 200) return json({ error: 'Too many rules (max 200)' }, 413);
  await env.STORE.put('meta:dirrules', JSON.stringify(list));
  kvInvalidate('dirrules');
  return json({ ok: true, rules: list });
}

// ===== 定时任务（TTL 目录 / 清空目录 / 自动归档）=====
async function getCronJobs(env) {
  try { const r = await env.STORE.get('meta:cron', 'json'); return Array.isArray(r) ? r : []; } catch (e) { return []; }
}
async function handleCron(env, req, url) {
  if (req.method === 'GET') return json({ jobs: await getCronJobs(env) });
  const b = await req.json();
  if (b && b.delete) {
    const list = (await getCronJobs(env)).filter(j => j.id !== b.delete);
    await env.STORE.put('meta:cron', JSON.stringify(list));
    return json({ ok: true, jobs: list });
  }
  if (b && b.run) {
    const jobs = await getCronJobs(env);
    const job = jobs.find(j => j.id === b.run);
    if (!job) return json({ error: 'Not found' }, 404);
    const r = await runCronJob(env, job);
    await env.STORE.put('meta:cron', JSON.stringify(jobs));
    return json({ ok: true, result: r, jobs });
  }
  const kind = String((b && b.kind) || 'ttl-dir');
  if (['ttl-dir', 'clean-dir', 'archive'].indexOf(kind) < 0) return json({ error: 'Bad kind' }, 400);
  const path = normPath((b && b.path) || '/');
  if (path === '/') return json({ error: 'Refusing to run on root' }, 400);
  const daysRaw = parseInt((b && b.days), 10);
  const job = {
    id: randToken().substring(0, 10), kind, path,
    days: Number.isFinite(daysRaw) ? Math.max(0, daysRaw) : 30,
    toTrash: !(b && b.toTrash === false),
    enabled: !(b && b.enabled === false),
    created: new Date().toISOString(), lastRun: '', lastResult: ''
  };
  const list = await getCronJobs(env);
  if (list.length >= 50) return json({ error: 'Too many jobs (max 50)' }, 413);
  list.push(job);
  await env.STORE.put('meta:cron', JSON.stringify(list));
  return json({ ok: true, job, jobs: list });
}
async function runCronJob(env, job) {
  const out = { id: job.id, kind: job.kind, path: job.path, moved: 0, deleted: 0, bytes: 0, errors: 0 };
  try {
    const items = await getDir(env, job.path);
    const cutoff = Date.now() - (job.days || 0) * 86400000;
    for (const it of items) {
      if (!it || !it.name) continue;
      if (out.moved + out.deleted >= 500) break;
      const srcRel = job.path.replace(/^\//, '') + it.name;
      if (job.kind === 'clean-dir') {
        const r = await handleDelete(env, srcRel);
        if (r && r.status === 200) out.deleted++; else out.errors++;
        continue;
      }
      if (it.type === 'dir') continue;
      const ts = it.time ? Date.parse(it.time) : 0;
      if (!ts || ts > cutoff) continue;   // 早于阈值（days=0 表示立即生效）
      if (job.kind === 'ttl-dir') {
        if (job.toTrash) {
          const r = await handleDelete(env, srcRel);
          if (r && r.status === 200) out.deleted++; else out.errors++;
        } else {
          await deleteAndMirror(env, srcRel); await deleteThumb(env, srcRel); await deleteVersions(env, srcRel);
          await removeDirItem(env, job.path, it.name);
          await addUsage(env, -(it.size || 0), -1);
          out.deleted++; out.bytes += it.size || 0;
        }
      } else if (job.kind === 'archive') {
        const sub = new Date(ts).toISOString().substring(0, 7).replace('-', '/');
        await ensureDir(env, job.path, 'archive');
        await ensureDir(env, job.path + 'archive/', sub.replace(/\/$/, ''));
        const r = await handleMove(env, srcRel, job.path + 'archive/' + sub + '/');
        if (r && r.status === 200) out.moved++; else out.errors++;
      }
    }
    job.lastRun = new Date().toISOString();
    job.lastResult = 'moved=' + out.moved + ' deleted=' + out.deleted + ' errors=' + out.errors;
    try { await addLog(env, 'mov', job.path, '定时任务 ' + job.kind + ' → ' + job.lastResult); } catch (e) {}
  } catch (e) { out.errors++; job.lastResult = 'failed: ' + ((e && e.message) || ''); }
  return out;
}
async function runAllCronJobs(env, limit) {
  const jobs = await getCronJobs(env);
  let n = 0;
  for (const j of jobs) {
    if (!j.enabled) continue;
    if (n >= (limit || 10)) break;
    n++;
    await runCronJob(env, j);
  }
  if (n) { try { await env.STORE.put('meta:cron', JSON.stringify(jobs)); } catch (e) {} }
  return n;
}

// ===== 从 WebDAV 导入（有界：深度 ≤3 / ≤200 文件 / ≤500MB）=====
async function handleImportWebdav(env, b) {
  const base = String((b && b.url) || '').trim();
  if (!base) return json({ error: 'No url' }, 400);
  let u;
  try { u = new URL(base); } catch (e) { return json({ error: 'Bad url' }, 400); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return json({ error: 'Only http(s)' }, 400);
  if (await resolveAndCheckHost(u.hostname)) return json({ error: 'Blocked host' }, 403);
  const target = normPath((b && b.path) || '/');
  if (await isPathLocked(env, target, '')) return json({ locked: true, path: target }, 423);
  const auth = (b && b.user) ? 'Basic ' + btoa(String(b.user) + ':' + String(b.pass || '')) : '';
  const maxFiles = Math.min(Math.max(parseInt((b && b.maxFiles), 10) || 100, 1), 200);
  const maxBytes = 500 * 1024 * 1024;

  async function listDav(dirUrl) {
    const out = [];
    const r = await fetch(dirUrl, {
      method: 'PROPFIND',
      headers: Object.assign({ Depth: '1', 'Content-Type': 'application/xml' }, auth ? { Authorization: auth } : {}),
      body: '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/></D:prop></D:propfind>'
    });
    if (!r.ok) throw new Error('PROPFIND HTTP ' + r.status);
    const xml = await r.text();
    const blocks = xml.match(/<(?:D:)?response[\s\S]*?<\/(?:D:)?response>/gi) || [];
    for (const blk of blocks) {
      const hrefM = /<(?:D:)?href>([\s\S]*?)<\/(?:D:)?href>/i.exec(blk);
      if (!hrefM) continue;
      let href = hrefM[1].trim();
      try { href = decodeURIComponent(href); } catch (e) {}
      const isDir = /<(?:D:)?collection\s*\/?>/i.test(blk);
      const sizeM = /<(?:D:)?getcontentlength>(\d+)</i.exec(blk);
      const full = new URL(href, dirUrl).toString();
      if (full.replace(/\/+$/, '') === dirUrl.replace(/\/+$/, '')) continue;
      out.push({ url: full, name: href.replace(/\/+$/, '').split('/').pop(), dir: isDir, size: sizeM ? parseInt(sizeM[1], 10) : 0 });
    }
    return out;
  }
  let files = 0, bytes = 0, skipped = 0, failed = 0;
  const queue = [{ url: u.toString(), depth: 0, dir: target }];
  while (queue.length) {
    const cur = queue.shift();
    if (cur.depth > 3) continue;
    let entries = [];
    try { entries = await listDav(cur.url); } catch (e) { failed++; continue; }
    for (const e of entries) {
      if (files >= maxFiles || bytes >= maxBytes) break;
      if (e.dir) { queue.push({ url: e.url, depth: cur.depth + 1, dir: normPath(cur.dir + e.name + '/') }); continue; }
      const name = sanitizeName(e.name || 'file');
      const existing = await findDirItem(env, cur.dir, name);
      if (existing.item && (existing.item.size || 0) === (e.size || 0)) { skipped++; continue; }
      const chk = await checkDirRule(env, cur.dir, name, e.size || 0);
      if (chk) { skipped++; continue; }
      try {
        const rr = await fetch(e.url, { headers: auth ? { Authorization: auth } : {} });
        if (!rr.ok) { failed++; continue; }
        const ab = await rr.arrayBuffer();
        if (bytes + ab.byteLength > maxBytes) { failed++; continue; }
        const key = cur.dir.replace(/^\//, '') + name;
        if (pathTooLong('/' + key)) { failed++; continue; }
        await putAndMirror(env, key, ab, { httpMetadata: { contentType: rr.headers.get('Content-Type') || 'application/octet-stream' } });
        const up = await upsertDirItem(env, cur.dir, { name, type: 'file', size: ab.byteLength, mime: rr.headers.get('Content-Type') || '', time: new Date().toISOString(), hasThumb: false });
        if (up && up.ok === false) { failed++; continue; }
        await addUsage(env, ab.byteLength, 1);
        files++; bytes += ab.byteLength;
      } catch (e) { failed++; }
    }
  }
  try { await addLog(env, 'up', target, 'WebDAV 导入 ' + files + ' 个文件 / ' + bytes + ' 字节（跳过 ' + skipped + '，失败 ' + failed + '）'); } catch (e) {}
  return json({ ok: true, imported: files, bytes, skipped, failed, path: target });
}

// ===== 仪表盘聚合（首页一次性取数；隔离级 30 秒缓存，避免多次 KV 读）=====
async function topDirsBySize(env, limit) {
  const direct = {};
  let dirs = 0;
  async function walk(p, depth) {
    if (depth > 6 || dirs > 400) return;
    let list = [];
    try { list = await getDir(env, p); } catch (e) { return; }
    dirs++;
    let sum = 0;
    const subs = [];
    for (const it of list) {
      if (!it || !it.name) continue;
      if (it.type === 'file') sum += it.size || 0;
      else subs.push(p + it.name + '/');
    }
    direct[p] = sum;
    for (const s of subs) await walk(s, depth + 1);
  }
  try { await walk('/', 0); } catch (e) {}
  const total = {};
  for (const p of Object.keys(direct)) {
    let cur = p;
    for (let guard = 0; guard < 12; guard++) {
      total[cur] = (total[cur] || 0) + direct[p];
      if (cur === '/') break;
      const parts = cur.split('/').filter(Boolean);
      parts.pop();
      cur = parts.length ? '/' + parts.join('/') + '/' : '/';
    }
  }
  return {
    dirs,
    top: Object.keys(total).filter(p => p !== '/').map(p => ({ path: p, bytes: total[p] }))
      .sort((a, b) => b.bytes - a.bytes).slice(0, limit || 6)
  };
}
async function handleDashboard(env, sessionToken) {
  const data = await kvCached('dashboard', 30, async () => {
    const usage = await getUsage(env);
    const daily = telMergeDaily((await env.STORE.get('meta:daily', 'json')) || {});
    const today = new Date().toISOString().substring(0, 10);
    const t = daily[today] || {};
    let shares = 0, ulinks = 0, trash = 0;
    try { shares = (await listKV(env, 'share:', 500)).length; } catch (e) {}
    try { ulinks = (await listKV(env, 'ulink:', 500)).length; } catch (e) {}
    try { trash = (await listKV(env, 'trash:', 500)).length; } catch (e) {}
    const topInfo = await topDirsBySize(env, 6);
    let recent = [], favs = [], tags = [];
    try { recent = (await getRecent(env)).slice(0, 12).map(r => (r && r.path) || '').filter(Boolean); } catch (e) {}
    try { favs = (await getFavs(env)).slice(0, 12); } catch (e) {}
    try { tags = (await getAllTags(env)).slice(0, 24); } catch (e) {}
    return {
      usage: { used: usage.used || 0, count: usage.files || usage.count || 0, total: quotaTotal(env) },
      dirs: topInfo.dirs,
      shares, ulinks, trash,
      today: { up: t.up || 0, dl: t.dl || 0, upBytes: t.upBytes || 0, dlBytes: t.dlBytes || 0 },
      trend: (function () {
        const out = [];
        for (let i = 6; i >= 0; i--) {
          const d = new Date(Date.now() - i * 86400000).toISOString().substring(0, 10);
          const v = daily[d] || {};
          out.push({ date: d, up: v.up || 0, dl: v.dl || 0 });
        }
        return out;
      })(),
      topDirs: topInfo.top,
      recentPaths: recent, favPaths: favs, tags
    };
  });
  // 路径类数据实时富化（不缓存，保证点开就是最新）
  let recentItems = [], favItems = [];
  try { recentItems = await enrichPathItems(env, data.recentPaths || []); } catch (e) {}
  try { favItems = await enrichPathItems(env, data.favPaths || []); } catch (e) {}
  return json(Object.assign({}, data, { recentItems, favItems, generated: new Date().toISOString() }));
}

// ===== 健康自检 =====
// 有界采样 R2 占用，用于和"用量计数"对照，及时发现漂移（防止配额形同虚设）
async function guardStats(env, u) {
  const out = {
    kv: {
      cacheEntries: KV_CACHE.size,
      writesLastMin: kvWritesLastMin(),
      budgetPerMin: kvBudgetPerMin(env),
      telemetryBuffered: telPending(),
      sessionCacheSec: sessionCacheSec(env),
      flushMs: telemetryFlushMs(env),
      telemetryMaxPerDay: telemetryMaxPerDay(env),
      dayCount: TEL.dayCount,
      mirrorDir: kvMirrorDir(env)
    },
    limits: {
      maxDirItems: maxDirItems(env),
      kvValueMaxMB: Math.round(kvValueMax(env) / 1048576),
      pathMax: PATH_MAX,
      versionMaxMB: Math.round(versionMaxBytes(env) / 1048576),
      versionsTtlDays: Math.round(versionsTtl(env) / 86400),
      versionsMax: maxVersions(env),
      hashTtlDays: Math.round(hashTtl(env) / 86400),
      trashDays: trashDays(env),
      chunkGcHours: chunkGcHours(env),
      backupMaxMB: Math.round(backupMaxBytes(env) / 1048576),
      backupKeep: backupKeep(env)
    },
    usage: { tracked: (u && u.used) || 0, files: (u && u.files) || 0 },
    r2: { objects: 0, bytes: 0, capped: false, internal: { chunks: 0, thumbs: 0, versions: 0, trash: 0, backup: 0 } }
  };
  try {
    let cursor, n = 0;
    do {
      const l = await env.DRIVE.list({ prefix: '', limit: 1000, cursor });
      for (const o of (l.objects || [])) {
        n++; out.r2.objects++; out.r2.bytes += o.size || 0;
        const k = o.key, sz = o.size || 0;
        if (k.indexOf(CHUNKS_PREFIX) === 0) out.r2.internal.chunks += sz;
        else if (k.indexOf(THUMB_PREFIX) === 0) out.r2.internal.thumbs += sz;
        else if (k.indexOf(VERSIONS_PREFIX) === 0) out.r2.internal.versions += sz;
        else if (k.indexOf(TRASH_PREFIX) === 0) out.r2.internal.trash += sz;
        else if (k.indexOf(BACKUP_PREFIX) === 0) out.r2.internal.backup += sz;
        if (n >= 5000) { out.r2.capped = true; return out; }
      }
      cursor = l.truncated ? l.cursor : undefined;
    } while (cursor);
  } catch (e) {}
  return out;
}
async function handleHealth(env) {
  const checks = [];
  async function run(name, fn) {
    const t0 = Date.now();
    try { const info = await fn(); checks.push({ name, ok: true, ms: Date.now() - t0, info: info || '' }); }
    catch (e) { checks.push({ name, ok: false, ms: Date.now() - t0, error: 'check failed' }); }
  }
  await run('R2 主存储', async () => { const l = await env.DRIVE.list({ prefix: '', limit: 1 }); return 'objects=' + ((l.objects || []).length); });
  await run('KV 命名空间', async () => { await env.STORE.get('meta:usage'); return 'ok'; });
  if (hasDO(env)) await run('Durable Object', async () => { const r = await withTimeout(usageStub(env).fetch('https://dir/getUsage'), 3000); if (!r || !r.ok) throw new Error('HTTP ' + (r && r.status)); return 'ok'; });
  else checks.push({ name: 'Durable Object', ok: true, ms: 0, info: '未配置（已回退 KV）' });
  const backs = getBackends(env);
  if (backs.length) { for (const b of backs) await run('S3 后端 ' + b.id, async () => { const r = await s3Probe(env, b); if (!r.ok) throw new Error(r.error || 'fail'); return r.ms + 'ms'; }); }
  else checks.push({ name: 'S3 后端', ok: true, ms: 0, info: '未配置' });
  await run('回收站', async () => { const t = await getDir(env, '/.trash/'); return (t.length || 0) + ' items'; });
  const u = await getUsage(env);
  let guard = null;
  try { guard = await guardStats(env, u); } catch (e) {}
  return json({ version: APP_VERSION, checks, usage: { used: u.used || 0, files: u.files || 0, total: quotaTotal(env) }, guard });
}

// ===== 孤儿文件扫描 =====
async function listAllKeys(env, cap) {
  const keys = []; const sizes = {}; const ages = {};
  let cursor;
  do {
    const r = await env.DRIVE.list({ prefix: '', limit: 1000, cursor });
    for (const o of (r.objects || [])) {
      keys.push(o.key); sizes[o.key] = o.size || 0;
      if (o.uploaded) ages[o.key] = o.uploaded;
      if (keys.length >= cap) return { keys, sizes, ages, capped: true };
    }
    cursor = r.truncated ? r.cursor : undefined;
  } while (cursor);
  return { keys, sizes, ages, capped: false };
}
async function scanOrphans(env) {
  const dirs = await collectDirs(env);
  const referenced = new Set(); const entries = [];
  for (const p of Object.keys(dirs)) {
    for (const it of dirs[p]) {
      if (!it || it.type !== 'file' || !it.name) continue;
      const k = p.replace(/^\/+/, '') + it.name;
      referenced.add(k);
      entries.push({ key: k, path: p, name: it.name, size: it.size || 0 });
    }
  }
  const listed = await listAllKeys(env, 20000);
  const present = new Set(listed.keys);
  const orphanFiles = [], orphanInternal = [], missing = [];
  for (const k of listed.keys) {
    if (referenced.has(k) || k.indexOf(BACKUP_PREFIX) === 0 || k.indexOf(TRASH_PREFIX) === 0) continue;
    if (k.indexOf(THUMB_PREFIX) === 0) {
      const base = k.substring(THUMB_PREFIX.length);
      if (base.indexOf(TRASH_PREFIX) === 0) continue;   // 回收站内文件的缩略图，随恢复/清理一起处理
      if (!referenced.has(base)) orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base });
    } else if (k.indexOf(VERSIONS_PREFIX) === 0) {
      const rest = k.substring(VERSIONS_PREFIX.length);
      const base = rest.substring(0, rest.lastIndexOf('/'));
      if (base.indexOf(TRASH_PREFIX) === 0) continue;
      if (!base || !referenced.has(base)) orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base });
    } else if (k.indexOf(CHUNKS_PREFIX) === 0) {
      // M5: 分片由上传会话管理，24 小时内视为活跃，不归孤儿
      const upAt = listed.ages[k] ? new Date(listed.ages[k]).getTime() : 0;
      if (upAt && Date.now() - upAt < 24 * 3600 * 1000) continue;
      orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base: '' });
    } else if (/^chunks\/[0-9a-f]{16}\/\d+$/.test(k)) {
      // 兼容旧版分片路径（严格的 <id>/<idx> 形态，不会误伤用户目录）
      const upAt = listed.ages[k] ? new Date(listed.ages[k]).getTime() : 0;
      if (upAt && Date.now() - upAt < 24 * 3600 * 1000) continue;
      orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base: '' });
    } else {
      orphanFiles.push({ key: k, size: listed.sizes[k] || 0 });
    }
  }
  for (const e of entries) { if (!present.has(e.key)) missing.push(e); }
  return {
    capped: listed.capped, scannedObjects: listed.keys.length, scannedFiles: entries.length,
    orphans: orphanFiles.slice(0, 500), orphansTotal: orphanFiles.length, orphansBytes: orphanFiles.reduce(function (s, x) { return s + (x.size || 0); }, 0),
    internal: orphanInternal.slice(0, 500), internalTotal: orphanInternal.length,
    missing: missing.slice(0, 500), missingTotal: missing.length
  };
}
async function handleScanOrphans(env) { return json(await scanOrphans(env)); }

// ===== 自动内务回收（R2 防爆）=====
// 只回收"肯定没人引用"的内部对象，不需要遍历整棵树：
//   1) .chunks/  超过 CHUNK_GC_HOURS 未更新的上传分片（会话键早已 TTL 过期）
//   2) .versions/<key>/<ts>  版本索引里已经不存在的条目
//   3) .thumb/<key>  目录里已不存在的文件缩略图
async function gcChunks(env, limit) {
  const cutoff = Date.now() - chunkGcHours(env) * 3600 * 1000;
  let checked = 0, deleted = 0, cursor;
  try {
    do {
      const listed = await env.DRIVE.list({ prefix: CHUNKS_PREFIX, limit: 500, cursor });
      for (const o of (listed.objects || [])) {
        if (checked++ >= limit) return deleted;
        const up = o.uploaded ? new Date(o.uploaded).getTime() : 0;
        if (up && up <= cutoff) { try { await env.DRIVE.delete(o.key); deleted++; } catch (e) {} }
      }
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor && checked < limit);
  } catch (e) {}
  return deleted;
}
async function gcInternalObjects(env, limit) {
  let removed = 0, checked = 0;
  // 版本对象：索引不存在则删除
  try {
    let cursor;
    do {
      const listed = await env.DRIVE.list({ prefix: VERSIONS_PREFIX, limit: 300, cursor });
      for (const o of (listed.objects || [])) {
        if (checked++ >= limit) return removed;
        const rest = o.key.substring(VERSIONS_PREFIX.length);
        const base = rest.substring(0, rest.lastIndexOf('/'));
        const ts = parseInt(rest.substring(rest.lastIndexOf('/') + 1), 10);
        if (!base || !Number.isFinite(ts)) { try { await env.DRIVE.delete(o.key); removed++; } catch (e) {} continue; }
        const idx = await listVersions(env, base);
        if (!idx.some(v => Number(v.ts) === ts)) { try { await env.DRIVE.delete(o.key); removed++; } catch (e) {} }
      }
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor && checked < limit);
  } catch (e) {}
  // 缩略图：对应文件已不存在则删除
  try {
    let cursor;
    do {
      const listed = await env.DRIVE.list({ prefix: THUMB_PREFIX, limit: 300, cursor });
      for (const o of (listed.objects || [])) {
        if (checked++ >= limit) return removed;
        const key = o.key.substring(THUMB_PREFIX.length);
        if (key.indexOf(TRASH_PREFIX) === 0 || key.indexOf(CHUNKS_PREFIX) === 0) continue;   // 回收站/分片由各自流程处理
        const dir = parentOf('/' + key);
        const name = key.split('/').pop();
        let found = false;
        try { const f = await findDirItem(env, dir, name); found = !!(f && f.item); } catch (e) { found = true; }
        if (!found) { try { await env.DRIVE.delete(o.key); removed++; } catch (e) {} }
      }
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor && checked < limit);
  } catch (e) {}
  return removed;
}async function handlePurgeOrphans(env, mode) {
  const data = await scanOrphans(env);
  // R3: 扫描被截断（对象数超过 2 万上限）时拒绝清理，防止误删
  if (data.capped) return json({ error: 'Scan incomplete, purge refused', capped: true }, 409);
  let deleted = 0, removed = 0;
  if (mode === 'objects' || mode === 'all') {
    for (const o of (data.orphans || [])) { try { await deleteAndMirror(env, o.key); deleted++; } catch (e) {} }
    for (const o of (data.internal || [])) { try { await env.DRIVE.delete(o.key); deleted++; } catch (e) {} }
  }
  if (mode === 'missing' || mode === 'all') {
    for (const m of (data.missing || [])) { try { await removeDirItem(env, m.path, m.name); removed++; } catch (e) {} }
  }
  try { await addLog(env, 'del', '(孤儿清理)', 'objects=' + deleted + ' entries=' + removed); } catch (e) {}
  return json({ ok: true, deleted, removed, truncatedObjects: data.orphansTotal > (data.orphans || []).length, truncatedMissing: data.missingTotal > (data.missing || []).length });
}

// ===== Webhook 通知 =====
async function getWebhook(env) {
  return await kvCached('meta:webhook', 30, async () => {
    try {
      const r = await env.STORE.get('meta:webhook', 'json');
      if (r && typeof r === 'object') return { enabled: !!r.enabled, url: String(r.url || ''), secret: String(r.secret || ''), events: Array.isArray(r.events) ? r.events : ['up', 'del', 'shr', 'mov'] };
    } catch (e) {}
    return { enabled: false, url: '', secret: '', events: ['up', 'del', 'shr', 'mov'] };
  });
}
async function handleGetWebhook(env) { const w = await getWebhook(env); return json({ enabled: w.enabled, url: w.url, hasSecret: !!w.secret, events: w.events }); }
async function handleSetWebhook(env, b) {
  const url = String((b && b.url) || '').trim();
  if (url) {
    try {
      const u = new URL(url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return json({ error: 'Only http(s)' }, 400);
      if (await resolveAndCheckHost(u.hostname)) return json({ error: 'Blocked host' }, 403);
    } catch (e) { return json({ error: 'Bad url' }, 400); }
  }
  const prev = await getWebhook(env);
  // 密钥留空表示"不修改"（GET 不会回传明文）；需要清除时显式传 null
  let secret = prev.secret || '';
  if (b && Object.prototype.hasOwnProperty.call(b, 'secret')) {
    if (b.secret === null) secret = '';
    else if (String(b.secret || '') !== '') secret = String(b.secret);
  }
  const w = {
    enabled: !!(b && b.enabled), url,
    secret,
    events: Array.isArray(b && b.events) ? b.events.filter(function (x) { return typeof x === 'string' && x.length < 12; }).slice(0, 10) : []
  };
  await env.STORE.put('meta:webhook', JSON.stringify(w));
  kvInvalidate('meta:webhook');
  return json({ ok: true });
}
async function notifyWebhook(env, payload) {
  const w = await getWebhook(env);
  if (!w.enabled || !w.url) return;
  if (w.events.length && w.events.indexOf(payload.event) < 0) return;
  try {
    const body = JSON.stringify(Object.assign({ version: APP_VERSION, at: new Date().toISOString() }, payload));
    const headers = { 'Content-Type': 'application/json', 'User-Agent': 'BlueDrift/' + APP_VERSION };
    if (w.secret) headers['X-Signature'] = 'sha256=' + await sha256HexBytes(new TextEncoder().encode(w.secret + ':' + body));
    // L4: 发送前二次校验目标 host，防 SSRF
    try { const tu = new URL(w.url); if (await resolveAndCheckHost(tu.hostname)) return; } catch (e) { return; }
    await fetch(w.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(3000) });
  } catch (e) {}
}
async function handleWebhookTest(env) {
  const w = await getWebhook(env);
  if (!w.url) return json({ error: 'No url' }, 400);
  try {
    const body = JSON.stringify({ version: APP_VERSION, event: 'test', path: '/', detail: '测试通知', at: new Date().toISOString() });
    const headers = { 'Content-Type': 'application/json', 'User-Agent': 'BlueDrift/' + APP_VERSION };
    if (w.secret) headers['X-Signature'] = 'sha256=' + await sha256HexBytes(new TextEncoder().encode(w.secret + ':' + body));
    const r = await fetch(w.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(5000) });
    return json({ ok: r.ok, status: r.status });
  } catch (e) { return json({ error: (e && e.message) || 'failed' }, 502); }
}

// ===== 公开只读相册 =====
async function getAlbums(env) {
  return await kvCached('meta:albums', 30, async () => {
    try { const a = await env.STORE.get('meta:albums', 'json'); return Array.isArray(a) ? a : []; } catch (e) { return []; }
  });
}
async function handleListAlbums(env) {
  const albums = (await getAlbums(env)).map(a => ({
    id: a.id, path: a.path, name: a.name, created: a.created,
    hasPassword: !!a.pwHash, count: a.count || 0
  }));
  return json({ albums });
}
async function handleCreateAlbum(env, path, name, password) {
  const dir = normPath(path || '/');
  if (await isPathLocked(env, dir, '')) return json({ locked: true, path: dir }, 423);
  const albums = (await getAlbums(env)).slice();
  const id = randToken().substring(0, 16);
  const nm = sanitizeName(name || dir.split('/').filter(Boolean).pop() || '相册');
  const rec = { id, path: dir, name: nm, created: new Date().toISOString() };
  if (password) {
    rec.pwSalt = randToken().substring(0, 16);
    rec.pwHash = await hashPassword(String(password), rec.pwSalt);
  }
  albums.push(rec);
  await env.STORE.put('meta:albums', JSON.stringify(albums));
  kvInvalidate('meta:albums');
  return json({ ok: true, id, url: '/a/' + id, name: nm, hasPassword: !!rec.pwHash });
}
async function handleAlbumUpdate(env, id, b) {
  const albums = (await getAlbums(env)).slice();
  const a = albums.find(x => x.id === id);
  if (!a) return json({ error: 'Not found' }, 404);
  if (b && b.name !== undefined) a.name = sanitizeName(String(b.name || a.name));
  if (b && b.password !== undefined) {
    if (!b.password) { delete a.pwHash; delete a.pwSalt; }
    else {
      a.pwSalt = randToken().substring(0, 16);
      a.pwHash = await hashPassword(String(b.password), a.pwSalt);
    }
  }
  await env.STORE.put('meta:albums', JSON.stringify(albums));
  kvInvalidate('meta:albums');
  return json({ ok: true, hasPassword: !!a.pwHash });
}
async function handleDeleteAlbum(env, id) {
  await env.STORE.put('meta:albums', JSON.stringify((await getAlbums(env)).filter(a => a.id !== id)));
  kvInvalidate('meta:albums');
  return json({ ok: true });
}
// 相册密码校验（?pw=）
async function albumGuard(env, req, a) {
  if (await isPathLocked(env, a.path, '')) return { resp: json({ error: 'Locked' }, 423) };
  if (a.pwHash) {
    const pw = (req ? (new URL(req.url).searchParams.get('pw') || '') : '');
    if (!await verifyPassword(pw, { hash: a.pwHash, salt: a.pwSalt })) return { resp: json({ error: 'Wrong password', needPassword: true, hasPassword: true, name: a.name }, 403) };
  }
  return { ok: true };
}
async function collectMedia(env, dirPath, out, depth, kind, cap) {
  const limit = cap || 300;
  if (depth > 8 || out.length >= limit) return;
  let items = [];
  try { items = await getDir(env, dirPath); } catch (e) {}
  for (const it of items) {
    if (out.length >= limit) return;
    if (!it || !it.name) continue;
    if (it.type === 'dir') { await collectMedia(env, dirPath + it.name + '/', out, depth + 1, kind, limit); continue; }
    const m = String(it.mime || '');
    const isImg = m.indexOf('image/') === 0;
    const isVid = m.indexOf('video/') === 0;
    const isAud = m.indexOf('audio/') === 0;
    const match = (kind === 'image') ? isImg : ((kind === 'audio') ? isAud : (isImg || isVid || isAud));
    if (!match) continue;
    out.push({
      k: (dirPath + it.name).replace(/^\//, ''), name: it.name, mime: m, size: it.size || 0,
      time: it.time || '', hasThumb: !!it.hasThumb, ph: it.ph || '', path: dirPath
    });
  }
}
// 媒体清单（相似图片/相册等复用；带 ph 感知哈希）
async function handleMediaList(env, q) {
  const dir = normPath(q.path || '/');
  const kind = String(q.kind || 'media');
  const limit = Math.min(Math.max(parseInt(q.limit, 10) || 500, 1), 2000);
  const out = [];
  await collectMedia(env, dir, out, 0, kind, limit);
  out.sort(function (x, y) { return String(y.time).localeCompare(String(x.time)); });
  return json({ path: dir, kind, count: out.length, items: out, capped: out.length >= limit });
}
// 记录图片感知哈希（客户端计算 dHash，64bit hex）
async function handleSetPhash(env, b) {
  const p = '/' + String((b && b.path) || '').replace(/^\/+/, '');
  const h = String((b && b.hash) || '').toLowerCase();
  if (!/^[0-9a-f]{16}$/.test(h)) return json({ error: 'Bad hash' }, 400);
  const dir = parentOf(p), name = p.split('/').filter(Boolean).pop();
  if (!name) return json({ error: 'Bad path' }, 400);
  const cur = await findDirItem(env, dir, name);
  if (!cur.item) return json({ error: 'Not found' }, 404);
  if (cur.item.ph === h) return json({ ok: true, unchanged: true });
  await upsertDirItem(env, dir, Object.assign({}, cur.item, { ph: h }));
  return json({ ok: true });
}
async function handleAlbumList(env, req, id) {
  const a = (await getAlbums(env)).find(x => x.id === id);
  if (!a) return json({ error: 'Not found' }, 404);
  const g = await albumGuard(env, req, a);
  if (g.resp) return g.resp;
  const url = new URL(req.url);
  const offset = Math.max(0, parseInt(url.searchParams.get('offset'), 10) || 0);
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit'), 10) || 60, 1), 300);
  const out = [];
  await collectMedia(env, a.path, out, 0, 'media', 600);
  out.sort(function (x, y) { return String(y.time).localeCompare(String(x.time)); });
  const page = out.slice(offset, offset + limit);
  return json({
    name: a.name, count: out.length, total: out.length, offset, limit,
    items: page, hasMore: offset + limit < out.length,
    hasPassword: !!a.pwHash, path: a.path
  });
}
async function handleAlbumRaw(env, req, id) {
  const a = (await getAlbums(env)).find(x => x.id === id);
  if (!a) return json({ error: 'Not found' }, 404);
  const g = await albumGuard(env, req, a);
  if (g.resp) return g.resp;
  const q = new URL(req.url);
  const k = String(q.searchParams.get('k') || '');
  const base = a.path.replace(/^\/+/, '');
  if (!k || k.indexOf(base) !== 0 || k.indexOf('..') >= 0) return json({ error: 'Forbidden' }, 403);
  // 内部对象（.backup/.versions/.thumb/.trash/.chunks）不得通过公开相册读取
  if (k.split('/').some(seg => seg.charAt(0) === '.')) return json({ error: 'Forbidden' }, 403);
  const dl = q.searchParams.get('dl') === '1';
  const filename = k.split('/').pop() || 'file';
  return await serveObject(env, req, k, dl
    ? { disposition: 'attachment; filename="' + encodeURIComponent(filename) + '"', sanitize: true, cacheControl: 'private, max-age=3600' }
    : { disposition: 'inline', sanitize: true, cacheControl: 'public, max-age=3600' });
}

// ===== 公开相册页 =====
function albumPage(id) {
  const aid = JSON.stringify(id);
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>相册</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
${publicPageCss()}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;-webkit-font-smoothing:antialiased}
.hd{max-width:1200px;margin:0 auto 16px}
h1{font-size:20px;font-weight:700;letter-spacing:-.02em}
.sub{font-size:12px;color:var(--text3);margin-top:4px;font-family:ui-monospace,Menlo,monospace}
.grid{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.it{position:relative;background:var(--fill);border:1px solid var(--border);border-radius:8px;overflow:hidden;cursor:pointer;aspect-ratio:4/3}
.it img,.it video{width:100%;height:100%;object-fit:cover;display:block;transition:transform .2s}
.it:hover img,.it:hover video{transform:scale(1.04)}
.it .nm{position:absolute;left:0;right:0;bottom:0;padding:16px 8px 6px;font-size:11px;color:#fff;background:linear-gradient(transparent,rgba(0,0,0,.68));overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lb{position:fixed;inset:0;background:rgba(1,4,9,.93);display:none;align-items:center;justify-content:center;z-index:50;padding:24px}
.lb.show{display:flex}
.lb img,.lb video{max-width:100%;max-height:100%;border-radius:6px}
.lb .x{position:absolute;top:16px;right:20px;color:#fff;font-size:26px;cursor:pointer;opacity:.8;line-height:1}
.lb .x:hover{opacity:1}
.msg{max-width:1200px;margin:0 auto;color:var(--text3);font-size:14px;padding:24px 0}
.pw{max-width:1200px;margin:20px auto;display:flex;gap:8px;align-items:center}
.pw input{flex:1;padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:var(--fill);color:inherit;font-size:14px}
.pw button{padding:10px 18px;border-radius:10px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer;font-size:14px}
.day{max-width:1200px;margin:16px auto 6px;font-size:13px;font-weight:600;color:var(--text2)}
.more{max-width:1200px;margin:18px auto;text-align:center}
.more button{padding:9px 20px;border-radius:10px;border:1px solid var(--border);background:var(--fill);color:inherit;cursor:pointer}
.it .dl{position:absolute;top:6px;right:6px;background:rgba(0,0,0,.5);color:#fff;border:none;border-radius:8px;padding:3px 7px;font-size:12px;cursor:pointer;opacity:0;transition:opacity .15s}
.it:hover .dl{opacity:1}
.it .geo{position:absolute;top:6px;left:6px;background:rgba(0,0,0,.5);color:#fff;border-radius:8px;padding:3px 7px;font-size:12px;text-decoration:none}

.theme-btn{position:fixed;top:16px;right:16px;z-index:999;width:42px;height:42px;border-radius:50%;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:18px;cursor:pointer;box-shadow:0 8px 22px rgba(0,0,0,.18);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);transition:transform .12s}
.theme-btn:active{transform:scale(.92)}
.card{box-shadow:0 14px 34px rgba(31,35,40,.12);border-radius:20px}
:root.dark .card{box-shadow:0 18px 44px rgba(0,0,0,.5)}
input,button,.zone{border-radius:11px}
</style></head><body>
<div class="pg-bar" style="max-width:1200px;margin:0 auto 16px">
  <span class="pg-logo">🖼</span>
  <div style="min-width:0"><div class="pg-title" id="ttl">相册</div><div class="pg-sub" id="sub"></div></div>
  <div class="pg-actions"><button class="btn gray tiny" id="albTheme" title="切换主题">🌗</button></div>
</div>
<div class="pw" id="pwRow" style="display:none"><input id="pwInput" type="password" placeholder="请输入相册密码" autocomplete="off"><button id="btnPw">进入</button></div>
<div id="grid"></div>
<div class="more" id="moreWrap" style="display:none"><button id="btnMore">加载更多</button></div>
<div class="msg" id="msg" style="display:none"></div>
<div class="lb" id="lb"><span class="x" id="lbx">✕</span><div id="lbbody" style="max-width:100%;max-height:100%;display:flex;align-items:center;justify-content:center"></div></div>
<script>
var ID=${aid};
var PW='',OFFSET=0,LIMIT=60,TOTAL=0,LOADED=0;
function esc(s){return String(s==null?'':s).replace(/[&<>"'\`]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\`':'&#96;'}[c]})}
function closeLb(){document.getElementById('lb').classList.remove('show');document.getElementById('lbbody').innerHTML=''}
function rawUrl(k,dl){return '/album/'+ID+'/raw?k='+encodeURIComponent(k)+(PW?('&pw='+encodeURIComponent(PW)):'')+(dl?'&dl=1':'')}
function loadMore(reset){
  if(reset){OFFSET=0;LOADED=0;document.getElementById('grid').innerHTML=''}
  fetch('/album/'+ID+'/list?offset='+OFFSET+'&limit='+LIMIT+(PW?('&pw='+encodeURIComponent(PW)):''),{cache:'no-store'}).then(function(r){return r.json().then(function(d){return{r:r,d:d}})}).then(function(res){
    var d=res.d;
    if(res.r.status===403&&d.needPassword){
      document.getElementById('pwRow').style.display='flex';
      document.getElementById('msg').style.display='none';
      if(d.name)document.getElementById('ttl').textContent=d.name;
      return;
    }
    if(d.error){document.getElementById('msg').style.display='block';document.getElementById('msg').textContent=d.error;return}
    document.getElementById('pwRow').style.display='none';
    document.getElementById('ttl').textContent=d.name||'相册';
    document.getElementById('msg').style.display='none';
    TOTAL=d.total||d.count||0;LOADED+= (d.items||[]).length;OFFSET=LOADED;
    document.getElementById('sub').textContent=TOTAL+' 项'+(PW?' · 🔒':'');
    var g=document.getElementById('grid');
    var h='';
    var lastDay='';
    (d.items||[]).forEach(function(it){
      var isV=String(it.mime||'').indexOf('video/')===0;
      var src=rawUrl(it.k,false);
      h+='<div class="it" data-k="'+esc(it.k)+'" data-v="'+(isV?1:0)+'" data-n="'+esc(it.name)+'" data-t="'+esc(it.time||'')+'">';
      h+=isV?('<video src="'+src+'" muted preload="metadata"></video>'):('<img loading="lazy" src="'+src+'" alt="">');
      h+='<button class="dl" data-dl="'+esc(it.k)+'">⬇</button>';
      h+='<div class="nm">'+esc(it.name)+'</div></div>';
    });
    g.insertAdjacentHTML('beforeend',h);
    var mw=document.getElementById('moreWrap');
    mw.style.display=d.hasMore?'block':'none';
    document.getElementById('btnMore').textContent='加载更多（'+LOADED+'/'+TOTAL+'）';
    bindItems();
    if(reset)groupByDay();
  }).catch(function(){document.getElementById('msg').style.display='block';document.getElementById('msg').textContent='加载失败'});
}
function bindItems(){
  var g=document.getElementById('grid');
  g.querySelectorAll('.it').forEach(function(el){
    if(el.__b)return;el.__b=1;
    el.onclick=function(ev){
      if(ev.target&&ev.target.getAttribute&&ev.target.getAttribute('data-dl'))return;
      var k=el.getAttribute('data-k');
      var isV=el.getAttribute('data-v')==='1';
      document.getElementById('lbbody').innerHTML=isV?('<video src="'+rawUrl(k,false)+'" controls autoplay></video>'):('<img src="'+rawUrl(k,false)+'" alt="">');
      document.getElementById('lb').classList.add('show');
    };
  });
  g.querySelectorAll('[data-dl]').forEach(function(b){
    if(b.__b)return;b.__b=1;
    b.onclick=function(ev){ev.stopPropagation();location.href=rawUrl(b.getAttribute('data-dl'),true)};
  });
}
// EXIF：读取前 128KB 解析拍摄时间与 GPS，按天分组并给出地图链接
function groupByDay(){
  if(typeof ExifReader==='undefined'||!window.ExifReader)return;
  var g=document.getElementById('grid');
  var els=[].slice.call(g.querySelectorAll('.it')).filter(function(el){return el.getAttribute('data-v')!=='1'}).slice(0,40);
  els.forEach(function(el){
    fetch(rawUrl(el.getAttribute('data-k'),false),{headers:{Range:'bytes=0-131071'}}).then(function(r){return r.arrayBuffer()}).then(function(buf){
      var tags=ExifReader.load(buf,{expanded:true});
      var dt=(tags.exif&&tags.exif.DateTimeOriginal&&tags.exif.DateTimeOriginal.description)||'';
      var lat=(tags.gps&&tags.gps.Latitude)||null,lng=(tags.gps&&tags.gps.Longitude)||null;
      if(dt){el.setAttribute('data-day',String(dt).substring(0,10))}
      if(lat&&lng){
        var a=document.createElement('a');
        a.className='geo';a.target='_blank';a.rel='noopener';
        a.href='https://www.openstreetmap.org/?mlat='+lat+'&mlon='+lng+'#map=15/'+lat+'/'+lng;
        a.textContent='📍';
        el.appendChild(a);
      }
      applyDays();
    }).catch(function(){});
  });
}
function applyDays(){
  var g=document.getElementById('grid');
  var kids=[].slice.call(g.children);
  kids.forEach(function(el){if(el.classList&&el.classList.contains('day-h'))el.remove()});
  var items=[].slice.call(g.querySelectorAll('.it'));
  var seen={},lastEl=null;
  items.forEach(function(el){
    var day=el.getAttribute('data-day');
    if(!day)return;
    if(seen[day])return;
    seen[day]=1;
    var h=document.createElement('div');h.className='day-h';h.className+=' day';h.textContent=day;
    g.insertBefore(h,el);
  });
}
(function(){var b=document.getElementById('albTheme');if(b)b.onclick=function(){var t=document.getElementById('themeBtn');if(t)t.click()}})();
loadMore(true);
document.getElementById('btnMore').onclick=function(){loadMore(false)};
document.getElementById('btnPw').onclick=function(){PW=document.getElementById('pwInput').value;loadMore(true)};
document.getElementById('pwInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnPw').click()};
document.getElementById('lbx').onclick=closeLb;
document.getElementById('lb').onclick=function(e){if(e.target===this)closeLb()};
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeLb()});
(function(){var s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/exifreader@4.23.3/dist/exif-reader.js';s.async=true;s.onload=function(){groupByDay()};document.head.appendChild(s)})();
</script><script>${publicPageThemeJs()}</script></body></html>`;
}

// ===== PWA：manifest / 图标 / Service Worker =====
function manifestJSON(env) {
  const title = siteTitle(env);
  return {
    name: title, short_name: title.slice(0, 12),
    start_url: '/', scope: '/', display: 'standalone',
    background_color: '#0d1117', theme_color: '#0d1117',
    icons: [{ src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }],
    // 手机系统分享面板 → 分享即上传
    share_target: {
      action: '/share-target',
      method: 'POST',
      enctype: 'multipart/form-data',
      params: {
        files: [{ name: 'files', accept: ['*/*'] }],
        title: 'title', text: 'text', url: 'url'
      }
    },
    shortcuts: [
      { name: '收藏', url: '/?fav=1' },
      { name: '最近', url: '/?recent=1' }
    ]
  };
}
function iconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="42" fill="#2f81f7"/><path d="M58 130h76a25 25 0 0 0 3-49.8A35 35 0 0 0 66 74a28 28 0 0 0-8 56z" fill="#ffffff"/></svg>';
}
function swJS() {
  return [
    "const SHELL='bluedrift-shell-v2', DATA='bluedrift-data-v1', SHARE='bluedrift-share-v1';",
    "self.addEventListener('install',()=>self.skipWaiting());",
    "self.addEventListener('activate',e=>e.waitUntil((async()=>{",
    "  const ks=await caches.keys();",
    "  await Promise.all(ks.filter(k=>k!==SHELL&&k!==DATA&&k!==SHARE).map(k=>caches.delete(k)));",
    "  await self.clients.claim();",
    "})()));",
    // 分享目标：把文件暂存到缓存，通知页面并跳转回去
    "async function handleShare(req){",
    "  try{",
    "    const fd=await req.formData();",
    "    const files=(fd.getAll('files')||[]).filter(f=>f&&typeof f!=='string'&&f.size>0).slice(0,20);",
    "    const text=String(fd.get('text')||fd.get('title')||fd.get('url')||'');",
    "    const cache=await caches.open(SHARE);",
    "    const old=await cache.keys();",
    "    for(const k of old){await cache.delete(k)}",
    "    let i=0;",
    "    for(const f of files){",
    "      const name=f.name||('shared-'+i);",
    "      await cache.put('/shared/'+i,new Response(f,{headers:{'Content-Type':f.type||'application/octet-stream','X-File-Name':encodeURIComponent(name)}}));",
    "      i++;",
    "    }",
    "    if(!files.length&&text){await cache.put('/shared/0',new Response(text,{headers:{'Content-Type':'text/plain','X-File-Name':encodeURIComponent('shared-note.txt')}}));i=1}",
    "    const cs=await self.clients.matchAll({includeUncontrolled:true,type:'window'});",
    "    cs.forEach(c=>{try{c.postMessage({type:'shared-files',count:i})}catch(_){}});",
    "    return Response.redirect('/?shared='+i,303);",
    "  }catch(err){return Response.redirect('/?shared=0',303)}",
    "}",
    "async function putCapped(cacheName,key,resp,max){",
    "  try{const c=await caches.open(cacheName);await c.put(key,resp);const ks=await c.keys();if(ks.length>max){for(let i=0;i<ks.length-max;i++)await c.delete(ks[i])}}catch(_){}",
    "}",
    "self.addEventListener('fetch',e=>{",
    "  const r=e.request;",
    "  let u;try{u=new URL(r.url)}catch(_){return}",
    "  if(u.origin!==location.origin)return;",
    "  if(r.method==='POST'&&u.pathname==='/share-target'){e.respondWith(handleShare(r));return}",
    "  if(r.method!=='GET')return;",
    // 分享暂存文件回传给页面
    "  if(u.pathname.indexOf('/shared/')===0){",
    "    e.respondWith(caches.open(SHARE).then(c=>c.match(u.pathname)).then(x=>x||new Response('',{status:404})));",
    "    return;",
    "  }",
    "  if(u.pathname==='/'){",
    "    e.respondWith(fetch(r).then(x=>{try{if(x&&x.ok){const c=x.clone();caches.open(SHELL).then(k=>k.put('/',c))}}catch(_){}return x}).catch(()=>caches.match('/')));",
    "    return;",
    "  }",
    // 目录列表/用量：网络优先，离线回退到上次结果（离线只读）
    "  if(u.pathname==='/api/list'||u.pathname==='/api/usage'||u.pathname==='/api/tree'){",
    "    e.respondWith(fetch(r).then(x=>{if(x&&x.ok){const c=x.clone();putCapped(DATA,r.url,c,60)}return x}).catch(()=>caches.open(DATA).then(c=>c.match(r.url)).then(x=>x||new Response('{\"offline\":true,\"items\":[]}',{status:200,headers:{'Content-Type':'application/json'}}))));",
    "    return;",
    "  }",
    // 缩略图/预览：缓存优先（有上限，避免离线缓存无限膨胀）
    "  if(u.pathname==='/api/thumb'){",
    "    e.respondWith(caches.open(DATA).then(c=>c.match(r.url)).then(x=>x||fetch(r).then(y=>{if(y&&y.ok){const z=y.clone();putCapped(DATA,r.url,z,200)}return y})));",
    "    return;",
    "  }",
    "  if(u.pathname==='/api/preview'){",
    "    e.respondWith(fetch(r).then(x=>{if(x&&x.ok){const c=x.clone();putCapped(DATA,r.url,c,40)}return x}).catch(()=>caches.open(DATA).then(c=>c.match(r.url)).then(x=>x||new Response('',{status:504}))));",
    "    return;",
    "  }",
    "});"
  ].join('\n');
}

async function handleUploadViaLink(req, env, linkToken) {
  try {
    const data = await env.STORE.get('ulink:' + linkToken, 'json');
    if (!data) return json({ error: 'Link not found' }, 404);
    if (Date.now() > data.exp) { await env.STORE.delete('ulink:' + linkToken); return json({ error: 'Link expired' }, 410); }
    if (data.max > 0 && data.count >= data.max) return json({ error: 'Upload limit reached' }, 403);

    const form = await req.formData(); const file = form.get('file');
    if (!file || typeof file === 'string') return json({ error: 'No file' }, 400);
    if (file.size > maxUploadBytes(env)) return json({ error: 'File too large', max: maxUploadBytes(env) }, 413);

    const dirPath = normPath(data.path);
    if (await isPathLocked(env, dirPath, '')) return json({ locked: true, path: dirPath }, 423);

    const safeName = sanitizeName(file.name);
    const key = dirPath.replace(/^\//, '') + safeName;
    if (pathTooLong('/' + key)) return json({ error: 'Path too long', max: PATH_MAX }, 400);

    const oldRes = await findDirItem(env, dirPath, safeName);
    const oldItem = oldRes.item;
    if (!oldItem) {
      const ruleChk = await checkDirRule(env, dirPath, safeName, file.size);
      if (ruleChk) return json({ error: ruleChk.error }, 403);
      const room = await dirRoom(env, dirPath, 1);
      if (room) return json({ error: room.error, limit: room.limit }, 507);
    }
    const delta = file.size - (oldItem ? (oldItem.size || 0) : 0);
    if (delta > 0) {
      const u = await getUsage(env);
      if ((u.used || 0) + delta > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
    }
    if (oldItem) await pushVersion(env, key, oldItem);
    if (oldItem && oldItem.hasThumb) await deleteThumb(env, key);

    const putRes = await putAndMirror(env, key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    const etag = (putRes && putRes.etag) ? String(putRes.etag).replace(/"/g, '') : '';

    const entry = { name: safeName, type: 'file', size: file.size, mime: file.type || '', time: new Date().toISOString(), hash: etag, hasThumb: false };
    const up = await upsertDirItem(env, dirPath, entry);
    if (up && up.ok === false) { try { await deleteAndMirror(env, key); } catch (e2) {} return json({ error: up.error, limit: up.limit }, 507); }
    if (oldItem) { await addUsage(env, delta, 0); }
    else { await addUsage(env, file.size, 1); }
    await addLog(env, 'up', dirPath + safeName, file.size + ' bytes (link)');

    // M6: 上传计数改为原子累加，避免并发上传覆盖计数
    const cnt = await counterAdd(env, 'ulink:' + linkToken, 1);
    data.count = (cnt != null && Number.isFinite(cnt)) ? cnt : (data.count || 0) + 1;
    await env.STORE.put('ulink:' + linkToken, JSON.stringify(data), { expirationTtl: Math.max(60, Math.ceil((data.exp - Date.now()) / 1000) + 60) });
    return json({ ok: true });
  } catch (e) { return json({ error: 'Failed' }, 500); }
}

// ===== 公开上传（需 PUBLIC_UPLOAD_DIR；配了 TURNSTILE_SECRET 才强制验证） =====
async function handlePublicUpload(req, env) {
  const dir = publicUploadDir(env);
  if (!dir) return json({ error: 'Public upload disabled' }, 403);
  if (await isPathLocked(env, dir, '')) return json({ locked: true, path: dir }, 423);
  let form;
  try { form = await req.formData(); } catch (e) { return json({ error: 'Bad form' }, 400); }
  const file = form.get('file');
  if (!file || typeof file === 'string') return json({ error: 'No file' }, 400);
  const ip = req.headers.get('CF-Connecting-IP') || '';
  const tsToken = form.get('cf-turnstile-response') || form.get('turnstile') || '';
  if (!await verifyTurnstile(env, tsToken, ip)) return json({ error: 'Captcha failed' }, 403);
  if (file.size > publicUploadMax(env)) return json({ error: 'File too large' }, 413);
  const u = await getUsage(env);
  if ((u.used || 0) + file.size > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  const pubRule = await checkDirRule(env, dir, sanitizeName(file.name), file.size);
  if (pubRule) return json({ error: pubRule.error }, 403);
  try {
    const base = sanitizeName(file.name);
    const existing = await findDirItem(env, dir, base);
    let finalName = base;
    if (existing.item) {
      const dotIdx = base.lastIndexOf('.');
      const stem = dotIdx > 0 ? base.substring(0, dotIdx) : base;
      const ext = dotIdx > 0 ? base.substring(dotIdx) : '';
      finalName = sanitizeName(stem + '-' + Date.now().toString(36) + ext);
    }
    const key = dir.replace(/^\//, '') + finalName;
    const putRes = await putAndMirror(env, key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    const etag = (putRes && putRes.etag) ? String(putRes.etag).replace(/"/g, '') : '';
    await upsertDirItem(env, dir, { name: finalName, type: 'file', size: file.size, mime: file.type || '', time: new Date().toISOString(), hash: etag, hasThumb: false });
    await addUsage(env, file.size, 1);
    await addLog(env, 'up', dir + finalName, file.size + ' bytes (public)');
    return json({ ok: true, name: finalName });
  } catch (e) { return json({ error: 'Failed' }, 500); }
}

// ===== 分享 / 上传链接 管理面板 =====
async function handleListShares(env) {
  const keys = await listKV(env, 'share:', LIST_PANEL_MAX);
  const shares = [];
  for (const k of keys) {
    try {
      const d = await env.STORE.get(k, 'json');
      if (!d) continue;
      if (d.exp && Date.now() > d.exp) { try { await env.STORE.delete(k); } catch (e) {} continue; }
      shares.push({ token: k.substring(6), name: d.name || '', path: d.path || '', size: d.size || 0, hits: d.hits || 0, max: d.max || 0, exp: d.exp || 0, hasPassword: !!d.pwHash, mime: d.mime || '' });
    } catch (e) {}
  }
  shares.sort((a, b) => b.exp - a.exp);
  return json({ shares });
}
async function handleDeleteShare(env, token) {
  if (!token) return json({ error: 'No token' }, 400);
  await env.STORE.delete('share:' + token);
  await counterDel(env, 'share:' + token);
  return json({ ok: true });
}
async function handleListUploadLinks(env) {
  const keys = await listKV(env, 'ulink:', LIST_PANEL_MAX);
  const links = [];
  for (const k of keys) {
    try {
      const d = await env.STORE.get(k, 'json');
      if (!d) continue;
      if (d.exp && Date.now() > d.exp) { try { await env.STORE.delete(k); } catch (e) {} continue; }
      links.push({ token: k.substring(6), path: d.path || '', exp: d.exp || 0, max: d.max || 0, count: d.count || 0 });
    } catch (e) {}
  }
  links.sort((a, b) => b.exp - a.exp);
  return json({ links });
}
async function handleDeleteUploadLink(env, token) {
  if (!token) return json({ error: 'No token' }, 400);
  await env.STORE.delete('ulink:' + token);
  return json({ ok: true });
}
async function handleDlStats(env) {
  const logs = telMergeDlLogs((await env.STORE.get('meta:dllog', 'json')) || []);
  const agg = telMergeDlStat((await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 });
  const byDay = {};
  for (const l of logs) {
    const d = String(l.time || '').substring(0, 10);
    if (!d) continue;
    byDay[d] = (byDay[d] || 0) + 1;
  }
  const daily = Object.keys(byDay).sort().reverse().slice(0, 7).map(k => ({ date: k, count: byDay[k] }));
  return json({ stats: { total: agg.total || 0, bytes: agg.bytes || 0 }, logs, daily });
}
async function handleStatsFull(env) {
  const u = await getUsage(env);
  const logs = await getLogs(env);
  const dl = telMergeDlStat((await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 });
  let shares = 0, ulinks = 0, trash = 0, tokens = 0;
  try { shares = (await listKV(env, 'share:', 500)).length; } catch (e) {}
  try { ulinks = (await listKV(env, 'ulink:', 500)).length; } catch (e) {}
  try { trash = (await getDir(env, '/.trash/')).length; } catch (e) {}
  try { tokens = (await getAccessTokens(env)).length; } catch (e) {}
  return json({
    usage: { used: u.used || 0, files: u.files || 0, total: quotaTotal(env) },
    logCount: logs.length,
    dlCount: dl.total || 0, dlBytes: dl.bytes || 0,
    shares, ulinks, trash, tokens
  });
}
async function handleClearDlStats(env) {
  TEL.dllog = []; TEL.dl = { total: 0, bytes: 0 };
  try { await env.STORE.delete('meta:dllog'); } catch (e) {}
  try { await env.STORE.put('meta:dlstat', JSON.stringify({ total: 0, bytes: 0 })); } catch (e) {}
  return json({ ok: true });
}

// ===== Folder Password =====
async function handleSetFolderPass(env, dirPath, password) {
  dirPath = normPath(dirPath);
  if (!password) {
    await env.STORE.delete('dirpass:' + dirPath);
    kvInvalidate('dirpass-list'); kvInvalidate('dirpass:' + dirPath);
    return json({ ok: true, removed: true });
  }
  const salt = randToken().substring(0, 16);
  const hash = await hashPassword(password, salt);
  await env.STORE.put('dirpass:' + dirPath, JSON.stringify({ hash, salt }));
  kvInvalidate('dirpass-list'); kvInvalidate('dirpass:' + dirPath);
  return json({ ok: true });
}

// ===== ZIP =====
function crc32Table() {
  let table = crc32Table.t;
  if (!table) {
    table = crc32Table.t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; table[n] = c; }
  }
  return table;
}
function crc32(buf) {
  const table = crc32Table();
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}
function crc32Update(crc, buf) {
  const table = crc32Table();
  let c = crc;
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return c;
}
// ===== 流式打包（边读边写，不再受 Worker 内存限制）=====
// files: [{ key, name, size }]；上限由调用方保证
function streamZip(env, files, filename) {
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let offset = 0;
      const central = [];
      const put = (u8) => { controller.enqueue(u8); offset += u8.length; };
      try {
        for (const f of files) {
          const nameBytes = enc.encode(f.name);
          const localOffset = offset;
          const lh = new Uint8Array(30);
          const lv = new DataView(lh.buffer);
          lv.setUint32(0, 0x04034B50, true); lv.setUint16(4, 20, true);
          lv.setUint16(6, 0x0008, true);                     // 使用数据描述符（CRC/大小后置）
          lv.setUint16(8, 0, true); lv.setUint16(10, 0, true); lv.setUint16(12, 0, true);
          lv.setUint32(14, 0, true); lv.setUint32(18, 0, true); lv.setUint32(22, 0, true);
          lv.setUint16(26, nameBytes.length, true); lv.setUint16(28, 0, true);
          put(lh); put(nameBytes);
          let crc = 0xFFFFFFFF, size = 0;
          let obj = null;
          try { obj = await env.DRIVE.get(f.key); } catch (e) { obj = null; }
          if (obj && obj.body) {
            const reader = obj.body.getReader();
            for (;;) {
              const r = await reader.read();
              if (r.done) break;
              const chunk = r.value instanceof Uint8Array ? r.value : new Uint8Array(r.value);
              crc = crc32Update(crc, chunk);
              size += chunk.length;
              put(chunk);
            }
          }
          const crcFinal = (crc ^ 0xFFFFFFFF) >>> 0;
          const dd = new Uint8Array(16);
          const dv = new DataView(dd.buffer);
          dv.setUint32(0, 0x08074B50, true);
          dv.setUint32(4, crcFinal, true);
          dv.setUint32(8, size, true);
          dv.setUint32(12, size, true);
          put(dd);
          const ch = new Uint8Array(46 + nameBytes.length);
          const cv = new DataView(ch.buffer);
          cv.setUint32(0, 0x02014B50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true);
          cv.setUint16(8, 0x0008, true); cv.setUint16(10, 0, true); cv.setUint16(12, 0, true); cv.setUint16(14, 0, true);
          cv.setUint32(16, crcFinal, true); cv.setUint32(20, size, true); cv.setUint32(24, size, true);
          cv.setUint16(28, nameBytes.length, true); cv.setUint32(42, localOffset, true);
          ch.set(nameBytes, 46);
          central.push(ch);
        }
        let cdSize = 0;
        for (const c of central) { put(c); cdSize += c.length; }
        const eocd = new Uint8Array(22);
        const ev = new DataView(eocd.buffer);
        ev.setUint32(0, 0x06054B50, true);
        ev.setUint16(8, central.length, true); ev.setUint16(10, central.length, true);
        ev.setUint32(12, cdSize, true); ev.setUint32(16, offset, true);
        put(eocd);
        controller.close();
      } catch (e) {
        try { controller.error(e); } catch (e2) {}
      }
    }
  });
  return new Response(stream, {
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename="' + encodeURIComponent(filename || 'files.zip') + '"',
      'Cache-Control': 'private, no-store'
    }
  });
}
// 打包下载时的对象读取（单独抽出便于测试替换）
async function buildZip(files) {
  const enc = new TextEncoder(); let offset = 0; const locals = []; const centrals = [];
  for (const f of files) {
    const nameBytes = enc.encode(f.name); const data = new Uint8Array(f.data); const crc = crc32(data);
    const lh = new Uint8Array(30 + nameBytes.length + data.length); const lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034B50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0, true); lv.setUint16(8, 0, true);
    lv.setUint16(10, 0, true); lv.setUint16(12, 0, true); lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true); lv.setUint32(22, data.length, true); lv.setUint16(26, nameBytes.length, true); lv.setUint16(28, 0, true);
    lh.set(nameBytes, 30); lh.set(data, 30 + nameBytes.length);
    locals.push(lh);
    const ch = new Uint8Array(46 + nameBytes.length); const cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014B50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0, true); cv.setUint16(10, 0, true);
    cv.setUint16(12, 0, true); cv.setUint16(14, 0, true); cv.setUint32(16, crc, true); cv.setUint32(20, data.length, true); cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true); cv.setUint32(42, offset, true); ch.set(nameBytes, 46);
    centrals.push(ch); offset += lh.length;
  }
  const cdSize = centrals.reduce((s, c) => s + c.length, 0);
  const end = new Uint8Array(22); const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054B50, true); ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true);
  ev.setUint32(12, cdSize, true); ev.setUint32(16, offset, true);
  const total = offset + cdSize + 22; const result = new Uint8Array(total); let pos = 0;
  for (const l of locals) { result.set(l, pos); pos += l.length; }
  for (const c of centrals) { result.set(c, pos); pos += c.length; }
  result.set(end, pos);
  return result.buffer;
}
// 目录打包：流式输出（边读边写），上限只受"文件数/总量/时间"约束，不再受 Worker 内存限制
async function collectZipFiles(env, dirPath, sessionToken, opts) {
  opts = opts || {};
  const maxFiles = opts.maxFiles || 2000;
  const maxBytes = opts.maxBytes || 2 * 1024 * 1024 * 1024;
  const dir = normPath(dirPath);
  const prefix = dir.replace(/^\//, '');
  const locked = await unlockedPrefixes(env, sessionToken || '');
  const files = [];
  let totalBytes = 0, cursor, hitLimit = false;
  do {
    const listed = await env.DRIVE.list({ prefix, limit: 1000, cursor });
    for (const obj of (listed.objects || [])) {
      const rel = obj.key.slice(prefix.length);
      if (!rel) continue;
      if (obj.key.indexOf(CHUNKS_PREFIX) === 0 || obj.key.indexOf(BACKUP_PREFIX) === 0 || obj.key.indexOf(TRASH_PREFIX) === 0 || obj.key.indexOf(THUMB_PREFIX) === 0 || obj.key.indexOf(VERSIONS_PREFIX) === 0) continue;
      if (insideLocked('/' + obj.key, locked)) continue;
      if (files.length >= maxFiles || totalBytes + (obj.size || 0) > maxBytes) { hitLimit = true; break; }
      totalBytes += obj.size || 0;
      files.push({ key: obj.key, name: rel, size: obj.size || 0 });
    }
    if (hitLimit) break;
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return { files, totalBytes, hitLimit, dir };
}
async function handleZip(env, dirPath, sessionToken) {
  const r = await collectZipFiles(env, dirPath, sessionToken, {});
  if (!r.files.length) return json({ error: 'Empty folder' }, 404);
  if (r.hitLimit) return json({ error: 'Too large to zip (max 2000 files / 2GB)' }, 413);
  const folderName = r.dir.replace(/\/+$/, '').split('/').pop() || 'files';
  return streamZip(env, r.files, folderName + '.zip');
}
// 多选打包下载：把选中的若干个文件打成一个 zip（同样流式）
async function handleZipPaths(env, paths) {
  const list = Array.isArray(paths) ? paths.filter(Boolean) : [];
  if (!list.length) return json({ error: 'No files' }, 400);
  const MAX_FILES = 2000, MAX_BYTES = 2 * 1024 * 1024 * 1024;
  const files = []; let totalBytes = 0, hitLimit = false;
  const used = {};
  for (const p of list) {
    if (files.length >= MAX_FILES || totalBytes >= MAX_BYTES) { hitLimit = true; break; }
    const key = String(p).replace(/^\/+/, '').replace(/\/+$/, '');
    if (!key) continue;
    let head = null;
    try { head = await env.DRIVE.head(key); } catch (e) {}
    if (!head) continue;
    const size = head.size || 0;
    if (totalBytes + size > MAX_BYTES) { hitLimit = true; break; }
    totalBytes += size;
    let name = key.split('/').pop() || 'file';
    if (used[name]) { used[name]++; name = used[name] + '_' + name; } else used[name] = 1;
    files.push({ key, name, size });
  }
  if (!files.length) return json({ error: 'Empty' }, 404);
  if (hitLimit) return json({ error: 'Too large to zip (max 2000 files / 2GB)' }, 413);
  return streamZip(env, files, 'files.zip');
}
// 分享目录打包下载（公开路由，走分享的权限校验）
async function handleShareZip(env, req, shareToken, g) {
  const d = g.data;
  if (d.type !== 'dir') return json({ error: 'Not a folder share' }, 400);
  if (d.allowDownload === false) return json({ error: 'Download disabled' }, 403);
  const base = normPath(d.path);
  const rel = new URL(req.url).searchParams.get('p') || '';
  const dir = normPath(base + rel);
  if (!dir.startsWith(base)) return json({ error: 'Forbidden' }, 403);
  if (await isPathLocked(env, dir, '')) return json({ error: 'Locked' }, 423);
  const r = await collectZipFiles(env, dir, '', { maxFiles: 500, maxBytes: 512 * 1024 * 1024 });
  if (!r.files.length) return json({ error: 'Empty folder' }, 404);
  if (r.hitLimit) return json({ error: 'Too large to zip (max 500 files / 512MB)' }, 413);
  await shareCount(env, shareToken, d);   // 打包下载计入一次访问
  const folderName = r.dir.replace(/\/+$/, '').split('/').pop() || 'files';
  return streamZip(env, r.files, folderName + '.zip');
}

// ===== 远程 URL 抓取（离线下载）：带 SSRF 防护 =====
const DNS_CACHE = new Map();   // host -> {t, blocked}，避免每条通知都做一次 DoH 查询
function isBlockedHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  if (/^(fc|fd|fe[89a-f])/.test(h)) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
  }
  return false;
}
async function resolveAndCheckHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').split(':')[0];
  if (!h) return true;
  if (isBlockedHost(h)) return true;
  if (/^[\d.]+$/.test(h) || h.indexOf(':') >= 0) return isBlockedHost(h);
  // 结果缓存 5 分钟：notifyWebhook 每次通知都要校验，避免重复 DoH 查询与延迟
  const now = Date.now();
  const hit = DNS_CACHE.get(h);
  if (hit && now - hit.t < 300000) return hit.blocked;
  let blocked = false;
  try {
    const dns = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(h) + '&type=A', { headers: { accept: 'application/dns-json' } });
    if (dns.ok) {
      const dj = await dns.json();
      const answers = (dj && dj.Answer) || [];
      for (const a of answers) {
        if (a && a.type === 1 && isBlockedHost(String(a.data))) { blocked = true; break; }
      }
    }
  } catch (e) { return false; }   // 查询失败时不缓存，保持原有放行语义
  if (DNS_CACHE.size > 500) DNS_CACHE.clear();
  DNS_CACHE.set(h, { t: now, blocked });
  return blocked;
}
// 手动跟随重定向，逐跳校验主机（防 SSRF）
async function handleFetchUrl(req, env, b) {
  if (cfgBool(env, 'DISABLE_URL_FETCH', 'disableUrlFetch', false)) return json({ error: 'URL fetch disabled' }, 403);
  const raw = String((b && b.url) || '').trim();
  if (!raw) return json({ error: 'No url' }, 400);
  let u;
  try { u = new URL(raw); } catch (e) { return json({ error: 'Bad url' }, 400); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return json({ error: 'Only http(s)' }, 400);
  if (await resolveAndCheckHost(u.hostname)) return json({ error: 'Blocked host' }, 403);
  const dir = normPath((b && b.dir) || '/');
  if (await isPathLocked(env, dir, '')) return json({ locked: true, path: dir }, 423);
  const maxBytes = (Number(env && env.FETCH_MAX_BYTES) > 0) ? Number(env.FETCH_MAX_BYTES) : 200 * 1024 * 1024;
  const MAX_REDIRECTS = 5;
  let current = u.toString();
  let resp = null;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      resp = await fetch(current, { redirect: 'manual', headers: { 'User-Agent': 'BlueDrift/1.0' }, signal: AbortSignal.timeout(10000) });
      if (resp.status >= 300 && resp.status < 400) {
        const loc = resp.headers.get('location');
        if (!loc) break;
        let next;
        try { next = new URL(loc, current); } catch (e) { return json({ error: 'Bad redirect' }, 502); }
        if (next.protocol !== 'http:' && next.protocol !== 'https:') return json({ error: 'Blocked redirect' }, 403);
        if (await resolveAndCheckHost(next.hostname)) return json({ error: 'Blocked host' }, 403);
        current = next.toString();
        continue;
      }
      break;
    }
  } catch (e) { return json({ error: 'Fetch failed' }, 502); }
  if (!resp) return json({ error: 'Fetch failed' }, 502);
  if (resp.status >= 300 && resp.status < 400) return json({ error: 'Too many redirects' }, 502);
  if (!resp.ok) return json({ error: 'Remote HTTP ' + resp.status }, 502);
  const len = Number(resp.headers.get('content-length') || 0);
  if (len && len > maxBytes) return json({ error: 'Remote file too large' }, 413);
  if (len) { const uu = await getUsage(env); if ((uu.used || 0) + len > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413); }
  let baseName;
  try { baseName = sanitizeName(decodeURIComponent((new URL(current).pathname.split('/').pop() || 'download'))); } catch (e) { baseName = sanitizeName('download'); }
  const wantName = (b && b.name) ? sanitizeName(b.name) : baseName;
  const name = await uniqueFileName(env, dir, wantName || 'download');
  const ctype = resp.headers.get('content-type') || 'application/octet-stream';
  const outDir = await applyAutoArchive(env, dir, name, ctype);
  const key = outDir.replace(/^\//, '') + name;
  if (!len) {
    // H2: 无 Content-Length（chunked）时先用 HEAD 探测体积，仍未知则写后回滚
    try {
      const probe = await fetch(current, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(8000) });
      const hlen = Number((probe && probe.headers.get('content-length')) || 0);
      if (hlen > maxBytes) return json({ error: 'Remote file too large' }, 413);
      if (hlen) { const uu = await getUsage(env); if ((uu.used || 0) + hlen > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413); }
    } catch (e) {}
  }
  try { await putAndMirror(env, key, resp.body, { httpMetadata: { contentType: ctype } }); }
  catch (e) { return json({ error: 'Save failed' }, 500); }
  let size = len;
  if (!size) { try { const h = await env.DRIVE.head(key); size = h ? h.size : 0; } catch (e) {} }
  if (size > maxBytes) {
    try { await deleteAndMirror(env, key); } catch (e) {}
    return json({ error: 'Remote file too large' }, 413);
  }
  const uu2 = await getUsage(env);
  if ((uu2.used || 0) + size > quotaTotal(env)) {
    try { await deleteAndMirror(env, key); } catch (e) {}
    return json({ error: 'Quota exceeded' }, 413);
  }
  await upsertDirItem(env, outDir, { name, type: 'file', size, mime: ctype, time: new Date().toISOString(), hash: '', hasThumb: false });
  await addUsage(env, size, 1);
  await addLog(env, 'up', outDir + name, size + ' bytes (url)');
  return json({ ok: true, name, size });
}

// ===== 秒传 / 断点续传 / 上传后自动归档 =====
function isHex64(s) { return /^[0-9a-f]{64}$/i.test(String(s || '')); }
async function uniqueFileName(env, dir, name) {
  const base = sanitizeName(name) || 'file';
  let ex = null;
  try { ex = await findDirItem(env, dir, base); } catch (e) {}
  if (!ex || !ex.item) return base;
  const i = base.lastIndexOf('.');
  const stem = i > 0 ? base.substring(0, i) : base;
  const ext = i > 0 ? base.substring(i) : '';
  return sanitizeName(stem + '-' + Date.now().toString(36) + ext);
}
// 命中已有内容则直接在目标目录"落一份"，不再上传
async function instantStore(env, hash, name, dir, size) {
  let idx = null;
  try { idx = await env.STORE.get('hash:' + hash, 'json'); } catch (e) {}
  if (!idx || !idx.key) return { hit: false };
  let obj = null;
  try { obj = await env.DRIVE.get(idx.key); } catch (e) {}
  if (!obj) { try { await env.STORE.delete('hash:' + hash); } catch (e) {} return { hit: false }; }
  const finalName = await uniqueFileName(env, dir, name || idx.key.split('/').pop() || 'file');
  const key = dir.replace(/^\//, '') + finalName;
  const mime = (obj.httpMetadata && obj.httpMetadata.contentType) || '';
  const sz = obj.size || size || 0;
  if (pathTooLong('/' + key)) return { hit: false };
  const room = await dirRoom(env, dir, 1);
  if (room) return { hit: false };
  try {
    if (key !== idx.key) await putAndMirror(env, key, obj.body, { httpMetadata: obj.httpMetadata });
  } catch (e) { return { hit: false }; }
  const up = await upsertDirItem(env, dir, { name: finalName, type: 'file', size: sz, mime, time: new Date().toISOString(), hash, hasThumb: false });
  if (up && up.ok === false) { try { if (key !== idx.key) await deleteAndMirror(env, key); } catch (e) {} return { hit: false }; }
  await addUsage(env, sz, 1);
  await addLog(env, 'up', dir + finalName, sz + ' bytes (instant)');
  return { hit: true, name: finalName, size: sz };
}
async function handleInstantCheck(env, b) {
  if (!isHex64(b && b.hash)) return json({ hit: false });
  const dir = normPath((b && b.dir) || '/');
  if (await isPathLocked(env, dir, '')) return json({ locked: true, path: dir }, 423);
  try { return json(await instantStore(env, b.hash, b.name, dir, Number(b.size) || 0)); }
  catch (e) { return json({ hit: false }); }
}
async function getAutoRule(env) {
  return await kvCached('meta:autorule', 30, async () => {
    try {
      const r = await env.STORE.get('meta:autorule', 'json');
      if (r && typeof r === 'object') return { enabled: !!r.enabled, mode: r.mode === 'type' ? 'type' : 'date', base: normPath(r.base || '/') };
    } catch (e) {}
    return { enabled: false, mode: 'date', base: '/' };
  });
}
async function handleGetAutoRule(env) { return json(await getAutoRule(env)); }
async function handleSetAutoRule(env, b) {
  const rule = { enabled: !!(b && b.enabled), mode: (b && b.mode) === 'type' ? 'type' : 'date', base: normPath((b && b.base) || '/') };
  await env.STORE.put('meta:autorule', JSON.stringify(rule));
  kvInvalidate('meta:autorule');
  return json({ ok: true, rule });
}
function archiveSubdir(mode, name, mime) {
  if (mode === 'type') {
    const m = String(mime || '').toLowerCase(), n = String(name || '').toLowerCase();
    if (m.indexOf('image/') === 0) return '图片/';
    if (m.indexOf('video/') === 0) return '视频/';
    if (m.indexOf('audio/') === 0) return '音频/';
    if (/\.(zip|rar|7z|tar|gz)$/.test(n) || m.indexOf('zip') >= 0) return '压缩包/';
    if (m.indexOf('text/') === 0 || m.indexOf('json') >= 0 || /\.(md|txt|log|csv|docx?|xlsx?|pptx?|pdf)$/.test(n)) return '文档/';
    return '其他/';
  }
  const d = new Date();
  return d.getUTCFullYear() + '/' + String(d.getUTCMonth() + 1).padStart(2, '0') + '/';
}
async function applyAutoArchive(env, dirPath, name, mime) {
  try {
    const rule = await getAutoRule(env);
    if (!rule.enabled) return dirPath;
    const base = normPath(rule.base || '/');
    if (!dirPath.startsWith(base)) return dirPath;
    let cur = dirPath;
    for (const seg of archiveSubdir(rule.mode, name, mime).split('/').filter(Boolean)) {
      const s = sanitizeName(seg);
      if (!s) continue;
      await ensureDir(env, cur, s);
      cur = cur + s + '/';
    }
    return cur;
  } catch (e) { return dirPath; }
}

// ===== ZIP 解压（仅 STORE） =====
function findEOCD(buf) {
  const min = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4B && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) return i;
  }
  return -1;
}
function parseZip(buf) {
  if (!buf || buf.length < 22) return { error: 'Not a zip' };
  const eocd = findEOCD(buf);
  if (eocd < 0) return { error: 'Bad zip (no EOCD)' };
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const total = dv.getUint16(eocd + 10, true);
  const cdSize = dv.getUint32(eocd + 12, true);
  const cdOffset = dv.getUint32(eocd + 16, true);
  if (cdOffset + cdSize > buf.length) return { error: 'Bad zip (CD out of range)' };

  const entries = [];
  let pos = cdOffset;
  const td = new TextDecoder('utf-8');
  for (let i = 0; i < total && pos + 46 <= buf.length; i++) {
    if (dv.getUint32(pos, true) !== 0x02014B50) break;
    const method = dv.getUint16(pos + 10, true);
    const compSize = dv.getUint32(pos + 20, true);
    const uncompSize = dv.getUint32(pos + 24, true);
    const nameLen = dv.getUint16(pos + 28, true);
    const extraLen = dv.getUint16(pos + 30, true);
    const commentLen = dv.getUint16(pos + 32, true);
    const localOffset = dv.getUint32(pos + 42, true);
    const name = td.decode(buf.subarray(pos + 46, pos + 46 + nameLen));
    pos += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith('/')) continue;
    if (localOffset + 30 > buf.length) return { error: 'Bad zip (local header out of range)' };
    if (dv.getUint32(localOffset, true) !== 0x04034B50) return { error: 'Bad zip (local sig)' };
    const lNameLen = dv.getUint16(localOffset + 26, true);
    const lExtraLen = dv.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    if (dataStart + compSize > buf.length) return { error: 'Bad zip (data out of range)' };
    if (method !== 0) return { error: '仅支持 STORE（无压缩）的 ZIP，请先用本网盘打包' };
    const data = buf.subarray(dataStart, dataStart + compSize);
    entries.push({ name, data, size: uncompSize });
  }
  return { entries };
}
async function handleUnzip(env, zipPath) {
  zipPath = '/' + zipPath.replace(/^\/+/, '');
  const key = zipPath.replace(/^\//, '');
  const obj = await env.DRIVE.get(key);
  if (!obj) return json({ error: 'Not found' }, 404);
  if (obj.size > UNZIP_MAX_BYTES) return json({ error: 'ZIP 太大（最大 50MB）' }, 413);
  const buf = new Uint8Array(await obj.arrayBuffer());
  const parsed = parseZip(buf);
  if (parsed.error) return json({ error: parsed.error }, 400);
  if (!parsed.entries || !parsed.entries.length) return json({ error: '空 ZIP' }, 400);
  // 反解压炸弹：限制条目数（此前同一段数据可被数万条目重复引用）
  if (parsed.entries.length > UNZIP_MAX_ENTRIES) return json({ error: 'ZIP 条目过多（最多 ' + UNZIP_MAX_ENTRIES + ' 个）' }, 413);

  const parentDir = parentOf(zipPath);
  const zipName = key.split('/').pop();
  const folderName = sanitizeName(zipName.replace(/\.zip$/i, '')) || 'unzipped';
  await ensureDir(env, parentDir, folderName);
  const targetDir = parentDir + folderName + '/';

  const usage0 = await getUsage(env);
  let usedNow = usage0.used || 0;
  let created = 0, totalSize = 0;
  for (const e of parsed.entries) {
    // 总量与配额双重上限
    if (e.size > UNZIP_MAX_OUT_BYTES || totalSize + e.size > UNZIP_MAX_OUT_BYTES) return json({ error: '解压总量过大（上限 ' + Math.round(UNZIP_MAX_OUT_BYTES / 1048576) + 'MB，已解出 ' + Math.round(totalSize / 1048576) + 'MB）' }, 413);
    if (usedNow + e.size > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
    const cleanRel = normPath('/' + e.name).replace(/^\//, '');
    if (!cleanRel) continue;
    const relParts = cleanRel.split('/').filter(Boolean);
    const fname = sanitizeName(relParts.pop());
    let curDir = targetDir;
    for (const seg of relParts) {
      const safe = sanitizeName(seg);
      if (!safe) continue;
      await ensureDir(env, curDir, safe);
      curDir = curDir + safe + '/';
    }
    const targetKey = curDir.replace(/^\//, '') + fname;
    await putAndMirror(env, targetKey, e.data, { httpMetadata: { contentType: 'application/octet-stream' } });
    const existing = await findDirItem(env, curDir, fname);
    if (!existing.item) {
      const up = await upsertDirItem(env, curDir, { name: fname, type: 'file', size: e.size, mime: '', time: new Date().toISOString() });
      if (up && up.ok === false) return json({ error: up.error, limit: up.limit }, 507);
      await addUsage(env, e.size, 1);
      usedNow += e.size;
    } else if ((existing.item.size || 0) !== e.size) {
      // 覆盖已有文件时同步修正记录大小，避免出现"大小与实际不符"的条目
      await addUsage(env, e.size - (existing.item.size || 0), 0);
      usedNow += e.size - (existing.item.size || 0);
      await upsertDirItem(env, curDir, Object.assign({}, existing.item, { size: e.size, time: new Date().toISOString() }));
    }
    created++; totalSize += e.size;
  }
  return json({ ok: true, created, totalSize, dir: targetDir });
}

// ===== Frontend (Apple Style, refined toolbar) =====
function page(env) {
  const brand = {
    title: siteTitle(env),
    logo: siteLogo(env)
  };
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0d1117">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">
<title>${escHtml(brand.title)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.7/dist/purify.min.js" defer></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js" defer></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdn.jsdelivr.net/npm/exifreader@4.23.3/dist/exif-reader.js" defer></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js" defer></script>
<script>
(function(){try{
  var pref=localStorage.getItem('dth')||'auto';
  var isDark = pref==='dark' || (pref==='auto' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.classList.add(isDark?'dark':'light');
}catch(e){document.documentElement.classList.add('light')}})();
try{if('serviceWorker' in navigator&&location.protocol.indexOf('http')===0){window.addEventListener('load',function(){navigator.serviceWorker.register('/sw.js').catch(function(){})})}}catch(e){}
</script>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root, :root.light{
  --sys-bg:#f6f8fa;
  --sys-card:#ffffff;
  --sys-card-solid:#ffffff;
  --sys-fill:#f6f8fa;
  --sys-fill-2:#eaeef2;
  --sys-fill-3:#d0d7de;
  --sys-text:#1f2328;
  --sys-text-2:#57606a;
  --sys-text-3:#8c959f;
  --sys-blue:#0969da;
  --sys-blue-hover:#0860c4;
  --sys-blue-soft:rgba(9,105,218,0.10);
  --sys-red:#cf222e;
  --sys-red-soft:rgba(207,34,46,0.10);
  --sys-green:#1a7f37;
  --sys-orange:#9a6700;
  --sys-separator:#d8dee4;
  --sys-separator-opaque:#afb8c1;
  --sys-shadow-sm:0 1px 0 rgba(31,35,40,0.04);
  --sys-shadow-md:0 1px 3px rgba(31,35,40,0.08);
  --sys-shadow-lg:0 8px 24px rgba(140,149,159,0.20);
  --sys-blur:none;
  --bg-grad-1:none;
  --bg-grad-2:none;
}
:root.dark{
  --sys-bg:#0d1117;
  --sys-card:#161b22;
  --sys-card-solid:#161b22;
  --sys-fill:#21262d;
  --sys-fill-2:#30363d;
  --sys-fill-3:#484f58;
  --sys-text:#e6edf3;
  --sys-text-2:#8b949e;
  --sys-text-3:#6e7681;
  --sys-blue:#2f81f7;
  --sys-blue-hover:#58a6ff;
  --sys-blue-soft:rgba(47,129,247,0.15);
  --sys-red:#f85149;
  --sys-red-soft:rgba(248,81,73,0.15);
  --sys-green:#3fb950;
  --sys-orange:#d29922;
  --sys-separator:#30363d;
  --sys-separator-opaque:#484f58;
  --sys-shadow-sm:0 0 0 transparent;
  --sys-shadow-md:0 1px 3px rgba(1,4,9,0.55);
  --sys-shadow-lg:0 8px 24px rgba(1,4,9,0.75);
  --sys-blur:none;
  --bg-grad-1:none;
  --bg-grad-2:none;
}
html,body{height:100%}
body{
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;
  background:var(--sys-bg);
  color:var(--sys-text);
  font-size:15px;line-height:1.47;letter-spacing:-0.01em;
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
  min-height:100vh;
  transition:background-color .3s,color .3s;
  overscroll-behavior:none;
}
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;
  background-image:var(--bg-grad-1),var(--bg-grad-2);
}
button,input,select,textarea{font-family:inherit;font-size:inherit}
a{color:var(--sys-blue);text-decoration:none}

.wrap{max-width:1120px;margin:0 auto;padding:24px 24px 80px;padding-top:max(24px,env(safe-area-inset-top));padding-bottom:max(80px,env(safe-area-inset-bottom))}

.page-header{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.brand-logo{width:42px;height:42px;border-radius:12px;flex-shrink:0;
  background:linear-gradient(160deg,#0a84ff,#5e5ce6);color:#fff;font-size:22px;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 6px 18px rgba(10,132,255,0.35),inset 0 1px 0 rgba(255,255,255,0.3)}
.brand-title{font-size:20px;font-weight:700;letter-spacing:-0.02em;color:var(--sys-text)}
.hdr-right{display:flex;gap:8px;flex-wrap:wrap;align-items:center}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:9px 16px;border-radius:980px;border:none;
  font-size:14px;font-weight:600;cursor:pointer;letter-spacing:-0.01em;
  background:var(--sys-blue);color:#fff;
  transition:transform .12s cubic-bezier(.4,0,.2,1),background-color .15s,opacity .15s;
  box-shadow:var(--sys-shadow-sm);white-space:nowrap;
  -webkit-user-select:none;user-select:none}
.btn:hover{background:var(--sys-blue-hover)}
.btn:active{transform:scale(0.96)}
.btn.gray{background:var(--sys-fill);color:var(--sys-text);box-shadow:none;
  backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur)}
.btn.gray:hover{background:var(--sys-fill-2)}
.btn.danger{background:var(--sys-red);color:#fff}
.btn.danger:hover{background:#ff5c52}
.btn.small{padding:6px 12px;font-size:13px}
.btn.tiny{padding:4px 10px;font-size:12px;font-weight:500}

.input,input[type=text],input[type=password],input[type=search],select,textarea{
  padding:10px 14px;border-radius:11px;border:none;
  background:var(--sys-fill);color:var(--sys-text);
  font-size:15px;outline:none;transition:all .15s;
  -webkit-appearance:none;appearance:none}
.input:focus,input:focus,select:focus,textarea:focus{
  background:var(--sys-card-solid);
  box-shadow:0 0 0 3px var(--sys-blue-soft),0 0 0 1px var(--sys-blue)}
::placeholder{color:var(--sys-text-3)}
textarea{width:100%;min-height:340px;resize:vertical;
  font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  font-size:13px;line-height:1.6;letter-spacing:0}

.card{background:var(--sys-card);border-radius:18px;padding:20px;margin-bottom:16px;
  box-shadow:var(--sys-shadow-md);
  backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  border:.5px solid var(--sys-separator)}
.card.flat{padding:0;overflow:hidden;background:var(--sys-card-solid)}

.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.row+.row{margin-top:10px}

.layout{display:flex;gap:18px;align-items:flex-start}
.sidebar{width:220px;flex-shrink:0;position:sticky;top:24px;
  max-height:calc(100vh - 48px);overflow-y:auto;padding:14px}
.sidebar .s-title{font-size:11px;color:var(--sys-text-3);text-transform:uppercase;
  letter-spacing:.8px;margin:4px 0 10px 10px;font-weight:600}
.tree-item{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:10px;
  cursor:pointer;font-size:14px;font-weight:500;color:var(--sys-text);
  transition:background .12s;white-space:nowrap;overflow:hidden}
.tree-item:hover{background:var(--sys-fill)}
.tree-item.active{background:var(--sys-blue);color:#fff}
.tree-item.active .tw{color:rgba(255,255,255,0.9)}
.tree-item .tw{font-size:9px;width:12px;flex-shrink:0;text-align:center;
  transition:transform .15s;opacity:.7;color:var(--sys-text-2)}
.tree-children{margin-left:14px;border-left:.5px solid var(--sys-separator);padding-left:4px}
.tree-children.hidden{display:none}
.main{flex:1;min-width:0}
.sidebar-toggle{display:none}

.toolbar-card{padding:16px 18px}
.toolbar-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.toolbar-row.main{margin-bottom:14px}

.btn.primary{padding:11px 22px;font-size:15px;flex-shrink:0}

.input-group{
  display:flex;align-items:center;flex-shrink:0;
  background:var(--sys-fill);border-radius:11px;overflow:hidden;
  transition:all .15s;
}
.input-group:focus-within{
  background:var(--sys-card-solid);
  box-shadow:0 0 0 3px var(--sys-blue-soft),0 0 0 1px var(--sys-blue);
}
.input-group input{
  border:none;background:transparent;padding:10px 14px;
  box-shadow:none;width:130px;font-size:14px;
}
.input-group input:focus{box-shadow:none;background:transparent}
.input-addon{
  border:none;background:transparent;color:var(--sys-blue);
  padding:10px 16px;font-size:16px;font-weight:600;
  cursor:pointer;transition:background .15s;
  border-left:.5px solid var(--sys-separator);
  line-height:1;
}
.input-addon:hover{background:var(--sys-fill-2)}

.search-box{
  flex:1;min-width:220px;display:flex;align-items:center;
  background:var(--sys-fill);border-radius:11px;overflow:hidden;
  transition:all .15s;
}
.search-box:focus-within{
  background:var(--sys-card-solid);
  box-shadow:0 0 0 3px var(--sys-blue-soft),0 0 0 1px var(--sys-blue);
}
.search-box input{
  flex:1;border:none;background:transparent;padding:10px 14px;box-shadow:none;
}
.search-box input:focus{box-shadow:none;background:transparent}
.search-box button{
  border:none;background:transparent;color:var(--sys-blue);
  padding:10px 18px;font-size:14px;font-weight:600;
  cursor:pointer;transition:background .15s;
  border-left:.5px solid var(--sys-separator);
}
.search-box button:hover{background:var(--sys-fill-2)}

.toolbar-row.tools{gap:8px}
.chips{display:flex;gap:6px;flex-wrap:wrap;flex:1;align-items:center}
.chip{
  display:inline-flex;align-items:center;gap:6px;
  padding:7px 14px;border-radius:99px;
  background:var(--sys-fill);color:var(--sys-text);
  border:none;font-size:13px;font-weight:500;cursor:pointer;
  transition:all .15s;white-space:nowrap;
}
.chip:hover{background:var(--sys-fill-2)}
.chip:active{transform:scale(0.96)}

.sort-wrap{display:flex;align-items:center;gap:8px;flex-shrink:0}
.sort-label{font-size:12px;color:var(--sys-text-3);font-weight:500}
.sort-group{display:inline-flex;background:var(--sys-fill);border-radius:9px;padding:2px;gap:2px}
.sort-btn{
  font-size:13px;padding:5px 14px;background:none;border:none;border-radius:7px;
  color:var(--sys-text-2);cursor:pointer;transition:all .15s;font-weight:500;
}
.sort-btn:hover{color:var(--sys-text)}
.sort-btn.active{
  color:var(--sys-text);background:var(--sys-card-solid);
  box-shadow:var(--sys-shadow-sm);font-weight:600;
}

#dropZone{
  margin-top:14px;padding:22px;
  border:1.5px dashed var(--sys-separator-opaque);
  border-radius:14px;text-align:center;font-size:14px;
  color:var(--sys-text-3);cursor:pointer;
  transition:all .2s;
  display:flex;align-items:center;justify-content:center;gap:12px;
}
#dropZone .drop-icon{
  width:32px;height:32px;border-radius:50%;
  background:var(--sys-fill);display:flex;align-items:center;justify-content:center;
  font-size:15px;color:var(--sys-text-2);flex-shrink:0;
  transition:all .2s;
}
#dropZone:hover,#dropZone.over{
  border-color:var(--sys-blue);color:var(--sys-blue);
  background:var(--sys-blue-soft);
}
#dropZone:hover .drop-icon,#dropZone.over .drop-icon{
  background:var(--sys-blue);color:#fff;
}

.card.flat .bc{font-size:13px;color:var(--sys-text-2);padding:14px 20px;
  border-bottom:.5px solid var(--sys-separator);overflow-x:auto;white-space:nowrap;background:transparent}
.card.flat .bc a{color:var(--sys-blue);cursor:pointer;font-weight:500}
.card.flat .bc a:hover{opacity:.7}

.file-list{list-style:none}
.file-list li{display:flex;align-items:center;gap:10px;padding:11px 20px;
  border-bottom:.5px solid var(--sys-separator);transition:background .12s;min-height:52px}
.file-list li:last-child{border:none}
.file-list li:hover{background:var(--sys-fill)}
.file-list li.selected{background:var(--sys-blue-soft)}
.file-list .fname{flex:1;cursor:pointer;color:var(--sys-text);font-size:15px;font-weight:400;
  min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-list .fname:hover{color:var(--sys-blue)}
.file-list .fsize{font-size:13px;color:var(--sys-text-3);min-width:72px;text-align:right;font-variant-numeric:tabular-nums}
.file-list .fdate{font-size:12px;color:var(--sys-text-3);min-width:80px;text-align:right;display:none;font-variant-numeric:tabular-nums}
.file-list li:hover .fdate{display:block}
.file-list input[type=checkbox]{width:20px;height:20px;cursor:pointer;accent-color:var(--sys-blue);flex-shrink:0}
.file-icon{width:26px;height:26px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:20px;line-height:1}
.fav-star{cursor:pointer;font-size:16px;color:var(--sys-text-3);background:none;border:none;padding:4px;
  flex-shrink:0;transition:all .15s;line-height:1;border-radius:6px}
.fav-star:hover{color:var(--sys-orange);transform:scale(1.1)}
.fav-star.on{color:var(--sys-orange)}
.fpath{font-size:12px;color:var(--sys-text-3);margin-left:6px}

.file-list .btn.tiny{opacity:0;transition:opacity .15s;background:var(--sys-fill);color:var(--sys-text-2);box-shadow:none}
.file-list .btn.tiny:hover{background:var(--sys-fill-2);color:var(--sys-blue)}
.file-list .btn.tiny.danger{color:var(--sys-red)}
.file-list .btn.tiny.danger:hover{background:var(--sys-red-soft)}
.file-list li:hover .btn.tiny{opacity:1}
@media(max-width:900px){.file-list .btn.tiny{opacity:1}}

.empty{text-align:center;color:var(--sys-text-3);padding:60px 20px;font-size:15px}
.empty::before{content:'📂';display:block;font-size:44px;margin-bottom:14px;opacity:.4}

.file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:14px;padding:20px}
.gitem{background:var(--sys-fill);border-radius:14px;padding:12px 8px;text-align:center;cursor:pointer;
  transition:all .18s cubic-bezier(.4,0,.2,1);position:relative;border:.5px solid transparent}
.gitem:hover{background:var(--sys-card);border-color:var(--sys-separator);transform:translateY(-2px);box-shadow:var(--sys-shadow-md)}
.gitem.selected{background:var(--sys-blue-soft);border-color:var(--sys-blue)}
.gthumb{width:100%;height:88px;object-fit:cover;border-radius:10px;margin-bottom:10px;background:var(--sys-fill-2)}
.gicon{font-size:40px;margin-bottom:10px;line-height:88px;height:88px}
.gname{font-size:13px;font-weight:500;overflow-wrap:anywhere;word-break:normal;line-height:1.35;max-height:2.7em;overflow:hidden;color:var(--sys-text);padding:0 4px}
.gitem input[type=checkbox]{position:absolute;top:8px;left:8px;accent-color:var(--sys-blue);width:18px;height:18px}

.usage{margin-top:16px;padding:16px 20px;background:var(--sys-card);border-radius:16px;
  box-shadow:var(--sys-shadow-sm);backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  border:.5px solid var(--sys-separator)}
.usage .ulabel{display:flex;justify-content:space-between;align-items:center;font-size:13px;color:var(--sys-text-2);margin-bottom:10px;font-weight:500}
.ubar{height:6px;background:var(--sys-fill-2);border-radius:99px;overflow:hidden}
.ufill{height:100%;background:linear-gradient(90deg,var(--sys-blue),#5e5ce6);border-radius:99px;transition:width .4s cubic-bezier(.4,0,.2,1)}

#loginPage{display:none;flex-direction:column;align-items:center;justify-content:center;min-height:calc(100vh - 80px);padding:20px}
.login-logo{width:88px;height:88px;border-radius:22px;
  background:linear-gradient(160deg,#0a84ff,#5e5ce6);color:#fff;font-size:48px;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 16px 40px rgba(10,132,255,0.4),inset 0 1px 0 rgba(255,255,255,0.35);
  margin-bottom:22px}
.login-title{font-size:30px;font-weight:700;letter-spacing:-0.03em;margin-bottom:6px;color:var(--sys-text)}
.login-sub{font-size:15px;color:var(--sys-text-3);margin-bottom:34px}
.login-card{width:100%;max-width:400px;padding:28px;background:var(--sys-card);border-radius:20px;
  box-shadow:var(--sys-shadow-lg);backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  border:.5px solid var(--sys-separator)}
.login-card .row{gap:10px;flex-wrap:nowrap}
.login-card input{flex:1;background:var(--sys-fill)}
.login-err{color:var(--sys-red);font-size:14px;margin-top:14px;padding:10px 14px;background:var(--sys-red-soft);border-radius:10px;display:none;font-weight:500}

.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.4);
  backdrop-filter:saturate(180%) blur(20px);-webkit-backdrop-filter:saturate(180%) blur(20px);
  z-index:900;display:none;align-items:center;justify-content:center;padding:20px;
  animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes sheetUp{from{opacity:0;transform:translateY(16px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
.modal-bg.show{display:flex}
.modal{background:var(--sys-card-solid);border-radius:20px;padding:24px;max-width:90vw;max-height:88vh;overflow:auto;
  position:relative;color:var(--sys-text);box-shadow:var(--sys-shadow-lg);
  animation:sheetUp .22s cubic-bezier(.4,0,.2,1);border:.5px solid var(--sys-separator)}
.modal img,.modal video{max-width:100%;max-height:68vh;border-radius:12px;display:block;margin:0 auto}
.modal audio{width:100%;min-width:280px}
.modal pre{background:var(--sys-fill);padding:16px;border-radius:12px;font-size:13px;line-height:1.6;
  overflow:auto;max-height:60vh;white-space:pre-wrap;word-break:break-all;
  font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,monospace;color:var(--sys-text)}
.modal .mtitle{font-size:14px;color:var(--sys-text-2);margin-top:16px;
  display:flex;justify-content:space-between;align-items:center;gap:10px;padding-top:14px;
  border-top:.5px solid var(--sys-separator)}
.modal .mtitle>span:first-child{font-weight:600;color:var(--sys-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.modal .mclose{position:absolute;top:14px;right:14px;font-size:17px;cursor:pointer;
  color:var(--sys-text-2);background:var(--sys-fill);border:none;width:30px;height:30px;border-radius:50%;
  padding:0;display:flex;align-items:center;justify-content:center;transition:all .15s;line-height:1;font-weight:500}
.modal .mclose:hover{background:var(--sys-fill-2);color:var(--sys-text)}
.modal .mdl{font-size:13px;padding:7px 14px;background:var(--sys-fill);border:none;color:var(--sys-blue);
  border-radius:9px;cursor:pointer;font-weight:600;transition:all .15s}
.modal .mdl:hover{background:var(--sys-fill-2)}

.pv-nav{position:absolute;top:50%;transform:translateY(-50%);font-size:22px;color:var(--sys-text);
  background:var(--sys-card-solid);border:none;border-radius:50%;width:44px;height:44px;
  cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:10;padding:0;line-height:1;
  box-shadow:var(--sys-shadow-md);transition:all .15s;opacity:.85}
.pv-nav:hover{opacity:1;transform:translateY(-50%) scale(1.06)}
.pv-nav.prev{left:-58px}.pv-nav.next{right:-58px}
.pv-nav.hidden{display:none}
@media(max-width:900px){.pv-nav.prev{left:8px}.pv-nav.next{right:8px}}
.pv-counter{position:absolute;top:14px;left:18px;font-size:12px;color:var(--sys-text-2);
  background:var(--sys-fill);padding:5px 12px;border-radius:99px;font-weight:600;font-variant-numeric:tabular-nums}

.uplist{margin-bottom:14px}
.uplist:empty{display:none}
.upqbar{display:none;align-items:center;gap:8px;margin-bottom:8px;padding:8px 12px;background:var(--sys-card);border:.5px solid var(--sys-separator);border-radius:12px;font-size:12px;color:var(--sys-text-2);flex-wrap:wrap}
.upqbar .upq-t{font-weight:600;color:var(--sys-text)}
.upqbar .upq-l{display:flex;align-items:center;gap:4px}
.upqbar select{padding:3px 6px;border-radius:7px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:12px}
.upacts{display:flex;gap:2px;margin-left:6px}
.upacts button{border:none;background:var(--sys-fill);color:var(--sys-text-2);border-radius:7px;width:24px;height:24px;font-size:12px;cursor:pointer;padding:0;line-height:1}
.upacts button:hover{background:var(--sys-fill-2);color:var(--sys-blue)}
.clipbar{display:none;align-items:center;gap:8px;margin-bottom:8px;padding:8px 12px;background:var(--sys-blue-soft);border:.5px solid var(--sys-blue);border-radius:12px;font-size:12px;color:var(--sys-text)}
.upitem.paused{opacity:.75}

/* 命令面板 */
.palette{position:fixed;inset:0;z-index:1200;display:none;align-items:flex-start;justify-content:center;padding:12vh 16px 16px;background:rgba(0,0,0,.28);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
.palette.show{display:flex}
.palette-box{width:100%;max-width:620px;background:var(--sys-card-solid);border:.5px solid var(--sys-separator);border-radius:16px;box-shadow:0 24px 60px rgba(0,0,0,.32);overflow:hidden}
.palette-box input{width:100%;padding:15px 18px;border:none;border-radius:0;background:transparent;font-size:16px;color:var(--sys-text);outline:none}
.palette-list{max-height:52vh;overflow:auto;border-top:.5px solid var(--sys-separator)}
.palette-item{display:flex;align-items:center;gap:10px;padding:10px 16px;font-size:14px;cursor:pointer;color:var(--sys-text)}
.palette-item .pi-ic{width:22px;text-align:center}
.palette-item .pi-sub{font-size:11.5px;color:var(--sys-text-3);margin-left:auto;font-family:ui-monospace,Menlo,monospace}
.palette-item.active{background:var(--sys-blue-soft);color:var(--sys-blue)}
.palette-foot{padding:8px 16px;font-size:11.5px;color:var(--sys-text-3);border-top:.5px solid var(--sys-separator)}

/* 虚拟滚动容器 + 列视图 */
.vscroll{max-height:calc(100vh - 340px);overflow:auto;contain:strict}
.vscroll .file-list{margin:0}
.col-table{width:100%;border-collapse:collapse;font-size:13.5px}
.col-table th{position:sticky;top:0;background:var(--sys-card-solid);text-align:left;padding:8px 10px;font-size:12px;color:var(--sys-text-3);border-bottom:.5px solid var(--sys-separator);cursor:pointer;white-space:nowrap;z-index:2}
.col-table th:hover{color:var(--sys-blue)}
.col-table td{padding:7px 10px;border-bottom:.5px solid var(--sys-separator);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px}
.col-table tr:hover td{background:var(--sys-fill)}
.col-table tr.selected td{background:var(--sys-blue-soft)}

/* 离线提示 */
.offline-bar{padding:7px 16px;background:var(--sys-orange);color:#fff;font-size:12.5px;text-align:center}

/* ===== 新布局：应用栏 / 侧栏导航 / 视图 / 仪表盘 ===== */
.app-bar{position:sticky;top:0;z-index:700;display:flex;align-items:center;gap:10px;padding:10px 16px;
  background:var(--sys-card);backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  border-bottom:.5px solid var(--sys-separator)}
.app-bar .brand{display:flex;align-items:center;gap:8px;flex:0 0 auto}
.appbar-main{display:flex;align-items:center;gap:8px;flex:1;min-width:0;position:relative}
.appbar-main .search-box{flex:1;max-width:420px;transition:max-width .18s ease,opacity .18s ease}
.appbar-main .search-box.collapsed{max-width:0;opacity:0;pointer-events:none;overflow:hidden;border:none;padding:0}
.app-bar .hdr-right{display:flex;align-items:center;gap:8px;flex:0 0 auto;position:relative}
.icon-btn{width:38px;height:38px;border-radius:12px;border:1px solid var(--sys-separator);background:var(--sys-fill);
  color:var(--sys-text);font-size:17px;line-height:1;cursor:pointer;display:flex;align-items:center;justify-content:center;flex:0 0 auto}
.icon-btn:hover{background:var(--sys-fill-2)}
.btn.icon-only{min-width:40px;padding:9px 10px;font-size:16px}
.menu-wrap{position:relative}
.pop-menu{position:absolute;top:calc(100% + 8px);left:0;z-index:800;display:none;flex-direction:column;min-width:186px;padding:6px;
  background:var(--sys-card-solid);border:.5px solid var(--sys-separator);border-radius:14px;box-shadow:0 18px 44px rgba(31,35,40,.22)}
:root.dark .pop-menu{box-shadow:0 22px 54px rgba(0,0,0,.6)}
.pop-menu.show{display:flex;animation:sheetUp .16s cubic-bezier(.4,0,.2,1)}
.pop-menu .chip{justify-content:flex-start;width:100%}
.side-nav{display:flex;flex-direction:column;gap:2px;margin-bottom:14px}
.side-item{display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:none;border-radius:10px;
  background:transparent;color:var(--sys-text);font-size:13.5px;font-weight:500;cursor:pointer;text-align:left}
.side-item:hover{background:var(--sys-fill)}
.side-item.active{background:var(--sys-blue-soft);color:var(--sys-blue);font-weight:600}
.side-item .si-ic{width:18px;text-align:center}
.side-foot{margin-top:auto;padding-top:12px;border-top:.5px solid var(--sys-separator);display:flex;flex-wrap:wrap;gap:6px}
.side-mini{display:flex;align-items:center;gap:5px;padding:6px 9px;border:1px solid var(--sys-separator);border-radius:10px;
  background:var(--sys-fill);color:var(--sys-text-2);font-size:12px;cursor:pointer}
.side-mini:hover{color:var(--sys-text);background:var(--sys-fill-2)}
.side-mini input[type=color]{width:18px;height:18px;padding:0;border:none;background:none;cursor:pointer}
.sidebar{display:flex;flex-direction:column}
.view{display:none}
.view.active{display:block}
/* 密度：紧凑 */
:root[data-density="compact"] .side-item{padding:5px 9px;font-size:13px}
:root[data-density="compact"] .file-list li{padding-top:5px;padding-bottom:5px}
:root[data-density="compact"] .btn{padding:6px 12px;font-size:13px}
:root[data-density="compact"] .gitem{font-size:11.5px}
:root[data-density="compact"] .app-bar{padding:7px 14px}
:root[data-density="cozy"] .side-item{padding:10px 11px;font-size:14px}
/* 仪表盘 */
.dash-loading{padding:40px;text-align:center;color:var(--sys-text-3)}
.dash{display:grid;gap:14px;grid-template-columns:repeat(12,1fr)}
.dash-card{grid-column:span 12;background:var(--sys-card);border:.5px solid var(--sys-separator);border-radius:18px;padding:16px;
  backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);box-shadow:var(--sys-shadow-sm)}
.dash-card h4{margin:0 0 12px;font-size:13px;color:var(--sys-text-2);font-weight:600;display:flex;align-items:center;gap:8px}
.dash-card h4 .dash-more{margin-left:auto;font-size:12px;color:var(--sys-blue);cursor:pointer;background:none;border:none}
.quick-zone{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.quick-zone .drop-mini{flex:1;min-width:220px;border:1.5px dashed var(--sys-separator-opaque);border-radius:14px;padding:14px;
  text-align:center;color:var(--sys-text-3);font-size:13px;cursor:pointer}
.quick-zone .drop-mini.over{border-color:var(--sys-blue);background:var(--sys-blue-soft);color:var(--sys-blue)}
.ring-wrap{display:flex;align-items:center;gap:16px}
.ring{width:104px;height:104px;border-radius:50%;flex:0 0 auto;display:flex;align-items:center;justify-content:center;
  background:conic-gradient(var(--sys-blue) calc(var(--p,0)*1%), var(--sys-fill-2) 0)}
.ring>div{width:80px;height:80px;border-radius:50%;background:var(--sys-card-solid);display:flex;flex-direction:column;
  align-items:center;justify-content:center;font-size:15px;font-weight:700}
.ring>div small{font-size:10.5px;font-weight:500;color:var(--sys-text-3)}
.stat-row{display:flex;gap:10px;flex-wrap:wrap}
.stat{flex:1;min-width:104px;background:var(--sys-fill);border-radius:14px;padding:12px}
.stat b{display:block;font-size:20px;font-weight:700;letter-spacing:-.02em}
.stat span{font-size:11.5px;color:var(--sys-text-3)}
.spark{display:flex;align-items:flex-end;gap:3px;height:38px;margin-top:10px}
.spark i{flex:1;background:var(--sys-blue);border-radius:3px 3px 0 0;min-height:3px;opacity:.85}
.recent-list{display:flex;flex-direction:column;gap:2px}
.recent-item{display:flex;align-items:center;gap:10px;padding:7px 8px;border-radius:10px;cursor:pointer;font-size:13.5px}
.recent-item:hover{background:var(--sys-fill)}
.recent-item img{width:34px;height:34px;border-radius:8px;object-fit:cover;background:var(--sys-fill-2);flex:0 0 auto}
.recent-item .ri-ic{width:34px;height:34px;border-radius:8px;background:var(--sys-fill-2);display:flex;align-items:center;justify-content:center;font-size:16px;flex:0 0 auto}
.recent-item .ri-tx{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recent-item .ri-sub{font-size:11px;color:var(--sys-text-3);font-family:ui-monospace,Menlo,monospace}
.tag-cloud{display:flex;flex-wrap:wrap;gap:6px}
.tag-cloud button{border:1px solid var(--sys-separator);background:var(--sys-fill);color:var(--sys-text);border-radius:999px;
  padding:4px 11px;font-size:12.5px;cursor:pointer;display:flex;align-items:center;gap:6px}
.tag-cloud button:hover{background:var(--sys-fill-2)}
.tag-cloud .tc-dot{width:8px;height:8px;border-radius:50%}
.topdir{display:flex;align-items:center;gap:10px;padding:6px 4px;font-size:13px;cursor:pointer;border-radius:10px}
.topdir:hover{background:var(--sys-fill)}
.topdir .td-bar{height:8px;border-radius:5px;background:var(--sys-blue);opacity:.75;min-width:4px}
.topdir .td-path{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (min-width:900px){
  .dash .span-4{grid-column:span 4}
  .dash .span-6{grid-column:span 6}
  .dash .span-8{grid-column:span 8}
  .dash .span-12{grid-column:span 12}
}
/* 行内操作：常显，长尾进 ⋯ */
.row-actions .row-more-wrap{position:relative;display:inline-flex}
.row-menu{position:absolute;top:calc(100% + 6px);right:0;z-index:600;display:none;flex-direction:column;min-width:150px;padding:5px;
  background:var(--sys-card-solid);border:.5px solid var(--sys-separator);border-radius:12px;box-shadow:0 16px 38px rgba(31,35,40,.22)}
.row-menu.show{display:flex}
.row-menu .btn{justify-content:flex-start;width:100%;white-space:nowrap}
/* 移动端选择模式操作栏 */
.selbar{display:none;position:fixed;left:0;right:0;bottom:calc(58px + env(safe-area-inset-bottom));z-index:880;gap:6px;padding:8px 10px;
  background:var(--sys-card-solid);border-top:.5px solid var(--sys-separator)}
.selbar.show{display:flex;overflow-x:auto}
@media (max-width:760px){
  .app-bar{flex-wrap:wrap;gap:8px;padding:8px 10px}
  .appbar-main{order:3;flex-basis:100%}
  .appbar-main .search-box{max-width:none}
  .sidebar{position:fixed;top:0;bottom:0;left:0;width:270px;z-index:950;transform:translateX(-102%);transition:transform .22s ease;
    border-radius:0;overflow-y:auto}
  .sidebar.show{transform:none}
  .dash-card{padding:13px}
}

.tabbar{display:none;position:fixed;left:0;right:0;bottom:0;z-index:900;background:var(--sys-card-solid);border-top:.5px solid var(--sys-separator);padding:6px 4px calc(6px + env(safe-area-inset-bottom));backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur)}
.tabbar button{flex:1;background:transparent;border:none;color:var(--sys-text-2);font-size:11px;display:flex;flex-direction:column;align-items:center;gap:2px;padding:4px 0;cursor:pointer}
.tabbar button .tb-ic{font-size:19px;line-height:1}
.tabbar button.on{color:var(--sys-blue)}
@media (max-width:760px){
  .tabbar{display:flex}
  .main{padding-bottom:74px}
  .vscroll{max-height:calc(100vh - 420px)}
  .toolbar-row.main{flex-wrap:wrap}
}
.upitem{display:flex;align-items:center;gap:12px;padding:11px 16px;background:var(--sys-card);
  border-radius:12px;margin-bottom:6px;font-size:13px;box-shadow:var(--sys-shadow-sm);
  backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);border:.5px solid var(--sys-separator)}
.upitem .upname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.upitem .upbar{width:100px;height:4px;background:var(--sys-fill-2);border-radius:99px;overflow:hidden}
.upitem .upfill{height:100%;background:linear-gradient(90deg,var(--sys-blue),#5e5ce6);border-radius:99px;transition:width .2s}
.upitem .upst{color:var(--sys-text-3);min-width:48px;text-align:right;font-weight:600;font-variant-numeric:tabular-nums}

.ctxmenu{position:fixed;background:var(--sys-card-solid);border-radius:12px;padding:5px;min-width:180px;z-index:1000;display:none;
  box-shadow:var(--sys-shadow-lg);border:.5px solid var(--sys-separator);
  animation:sheetUp .12s cubic-bezier(.4,0,.2,1)}
.ctxmenu.show{display:block}
.ctxmenu .mi{padding:9px 14px;border-radius:8px;font-size:14px;cursor:pointer;color:var(--sys-text);
  transition:all .1s;display:flex;align-items:center;gap:8px;font-weight:500}
.ctxmenu .mi:hover{background:var(--sys-blue);color:#fff}
.ctxmenu .mi.danger{color:var(--sys-red)}
.ctxmenu .mi.danger:hover{background:var(--sys-red);color:#fff}

.batch-bar{display:none;align-items:center;gap:10px;padding:12px 18px;margin-bottom:14px;
  background:var(--sys-blue-soft);border-radius:12px;font-size:14px;font-weight:500;
  backdrop-filter:var(--sys-blur);-webkit-backdrop-filter:var(--sys-blur);
  border:.5px solid rgba(0,122,255,0.3)}
.batch-bar.show{display:flex;animation:sheetUp .2s ease}
.batch-bar #batchCount{flex:1;color:var(--sys-blue);font-weight:600}

.tr-row{display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:.5px solid var(--sys-separator)}
.tr-row:last-child{border:none}
.tr-row input[type=checkbox]{width:18px;height:18px;accent-color:var(--sys-blue)}
.tr-name{flex:1;font-size:14px;word-break:break-all;font-weight:500}
.tr-meta{font-size:12px;color:var(--sys-text-3);white-space:nowrap;font-variant-numeric:tabular-nums}

.ver-row{display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:.5px solid var(--sys-separator);font-size:14px}
.ver-row:last-child{border:none}
.ver-row .vtime{flex:1;color:var(--sys-text-2);font-variant-numeric:tabular-nums}
.ver-row .vsize{color:var(--sys-text-3);font-size:13px;min-width:72px;text-align:right;font-variant-numeric:tabular-nums}

.modal h3{font-size:17px;font-weight:700;margin-bottom:18px;letter-spacing:-0.02em}


/* Tag chips */
.tag-chip{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:99px;background:var(--sys-blue-soft);color:var(--sys-blue);font-size:12px;font-weight:500;cursor:pointer;transition:all .15s;margin:2px}
.tag-chip:hover{background:var(--sys-blue);color:#fff}
.tag-chip .tag-x{font-size:14px;line-height:1;margin-left:2px;cursor:pointer;opacity:.7}
.tag-chip .tag-x:hover{opacity:1}
.tag-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.sidebar .tag-section{margin-top:14px;padding-top:14px;border-top:.5px solid var(--sys-separator)}
.sidebar .tag-section .s-title{margin-bottom:8px}
.tag-filter-item{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--sys-text);transition:background .12s}
.tag-filter-item:hover{background:var(--sys-fill)}
.tag-filter-item.active{background:var(--sys-blue);color:#fff}

/* Markdown preview */
.md-body{padding:20px;max-height:60vh;overflow:auto;font-size:15px;line-height:1.7;color:var(--sys-text)}
.md-body h1,.md-body h2,.md-body h3{margin:1.2em 0 .6em;font-weight:700;letter-spacing:-.02em}
.md-body h1{font-size:1.8em;border-bottom:.5px solid var(--sys-separator);padding-bottom:.3em}
.md-body h2{font-size:1.4em}
.md-body h3{font-size:1.15em}
.md-body p{margin:.8em 0}
.md-body code{background:var(--sys-fill);padding:2px 6px;border-radius:5px;font-size:.9em;font-family:ui-monospace,"SF Mono",monospace}
.md-body pre{background:var(--sys-fill);padding:16px;border-radius:12px;overflow:auto;margin:1em 0}
.md-body pre code{background:none;padding:0}
.md-body blockquote{border-left:3px solid var(--sys-blue);padding-left:16px;margin:1em 0;color:var(--sys-text-2)}
.md-body ul,.md-body ol{padding-left:1.6em;margin:.8em 0}
.md-body li{margin:.3em 0}
.md-body table{border-collapse:collapse;width:100%;margin:1em 0}
.md-body th,.md-body td{border:.5px solid var(--sys-separator);padding:8px 12px;text-align:left}
.md-body th{background:var(--sys-fill);font-weight:600}
.md-body img{max-width:100%;border-radius:8px}
.md-body a{color:var(--sys-blue)}

/* Syntax highlight in preview */
.hl-pre{background:var(--sys-fill);padding:16px;border-radius:12px;font-size:13px;line-height:1.6;overflow:auto;max-height:60vh;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,"SF Mono",SFMono-Regular,Menlo,monospace;color:var(--sys-text)}

/* Note tooltip */
.note-badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:6px;background:var(--sys-fill);color:var(--sys-text-2);font-size:11px;cursor:pointer;margin-left:4px;transition:all .15s}
.note-badge:hover{background:var(--sys-blue-soft);color:var(--sys-blue)}
.note-textarea{width:100%;min-height:120px;resize:vertical;padding:12px;border-radius:10px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px;line-height:1.6;font-family:inherit;outline:none;transition:all .15s}
.note-textarea:focus{background:var(--sys-card-solid);box-shadow:0 0 0 3px var(--sys-blue-soft),0 0 0 1px var(--sys-blue)}

/* Encrypt button style */
.chip.enc-active{background:var(--sys-green);color:#fff}

/* Duplicate panel */
.dup-group{padding:12px 16px;border-bottom:.5px solid var(--sys-separator)}
.dup-group:last-child{border:none}
.dup-hash{font-size:11px;color:var(--sys-text-3);font-family:ui-monospace,monospace}
.dup-file{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:14px}
.dup-path{color:var(--sys-text-2);font-size:12px}

/* Keyboard hint */
.kbd{display:inline-block;padding:1px 6px;border-radius:4px;background:var(--sys-fill);color:var(--sys-text-3);font-size:11px;font-family:ui-monospace,monospace;margin-left:6px;vertical-align:middle}


/* PDF preview */
.pdf-canvas{max-width:100%;border-radius:8px;margin:0 auto;display:block;box-shadow:var(--sys-shadow-sm)}
.pdf-pages{display:flex;flex-direction:column;gap:12px;max-height:60vh;overflow:auto;padding:4px}
.pdf-status{text-align:center;color:var(--sys-text-3);font-size:13px;padding:20px}

/* Music playlist */
.playlist{margin-top:8px;max-height:180px;overflow:auto;border-top:.5px solid var(--sys-separator);padding-top:8px}
.pl-item{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--sys-text);transition:background .12s}
.pl-item:hover{background:var(--sys-fill)}
.pl-item.active{background:var(--sys-blue-soft);color:var(--sys-blue);font-weight:600}
.pl-item .pl-dur{margin-left:auto;color:var(--sys-text-3);font-size:12px;font-variant-numeric:tabular-nums}

/* Image slideshow extra */
.exif-bar{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;font-size:12px;color:var(--sys-text-3)}
.exif-bar span{background:var(--sys-fill);padding:3px 8px;border-radius:6px}
.screenshot-btn{position:absolute;bottom:16px;right:16px;z-index:20}

/* Stats panel */
.stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
.stats-card{background:var(--sys-fill);border-radius:12px;padding:16px;text-align:center}
.stats-card .sv{font-size:24px;font-weight:700;color:var(--sys-blue)}
.stats-card .sl{font-size:12px;color:var(--sys-text-3);margin-top:4px}

/* Batch rename */
.br-preview{max-height:200px;overflow:auto;margin-top:10px;font-size:13px}
.br-row{display:flex;gap:8px;padding:5px 0;border-bottom:.5px solid var(--sys-separator)}
.br-old{color:var(--sys-text-2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.br-new{color:var(--sys-blue);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}

/* Activity log */
.log-entry{display:flex;gap:10px;padding:8px 0;border-bottom:.5px solid var(--sys-separator);font-size:13px}
.log-entry:last-child{border:none}
.log-time{color:var(--sys-text-3);min-width:70px;font-variant-numeric:tabular-nums}
.log-action{font-weight:500;min-width:50px}
.log-action.up{color:var(--sys-green)}
.log-action.del{color:var(--sys-red)}
.log-action.shr{color:var(--sys-orange)}

/* Token mgmt */
.token-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:.5px solid var(--sys-separator)}
.token-row:last-child{border:none}
.token-name{flex:1;font-weight:500;font-size:14px}
.token-perm{font-size:12px;padding:3px 8px;border-radius:6px;background:var(--sys-fill);color:var(--sys-text-2)}
.token-perm.ro{background:var(--sys-blue-soft);color:var(--sys-blue)}

/* QR container */
.qr-box{display:flex;justify-content:center;padding:16px;background:#fff;border-radius:12px;margin-top:12px}

/* WebDAV info */
.webdav-box{padding:16px;background:var(--sys-fill);border-radius:12px;margin-top:12px;font-size:13px;line-height:1.8}
.webdav-box code{background:var(--sys-card-solid);padding:2px 8px;border-radius:5px;font-size:12px}

.chip-group{display:flex;align-items:center;gap:6px}
.chip-label{font-size:10px;color:var(--sys-text-3);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-right:2px;white-space:nowrap}
.chip-sep{width:1px;height:24px;background:var(--sys-separator);margin:0 6px;flex-shrink:0}
.admin-row{display:flex;gap:6px;flex-wrap:wrap;padding:8px 0 2px;border-top:.5px solid var(--sys-separator);margin-top:8px;animation:sheetUp .15s ease}
.small-chip{padding:5px 10px;font-size:12px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--sys-fill-3);border-radius:99px;border:3px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:var(--sys-text-3);background-clip:padding-box}

@media(max-width:820px){
  .wrap{padding:14px 14px 40px}
  .layout{flex-direction:column}
  .sidebar{width:100%;position:static;max-height:none;display:none}
  .sidebar.show{display:block}
  .sidebar-toggle{display:inline-flex}
  .file-grid{grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;padding:14px}
  .file-list .fdate{display:none!important}
  .btn.primary{width:100%}
  .input-group{width:100%}
  .input-group input{width:auto;flex:1}
  .search-box{min-width:100%}
  .toolbar-row.main{flex-direction:column;align-items:stretch;gap:8px}
  .toolbar-row.tools{flex-direction:column;align-items:stretch;gap:10px}
  .chips{flex-wrap:wrap;gap:6px}
  .chip-sep{display:none}
  .chip-group{width:100%}
  .chip-label{display:none}
  .sort-wrap{justify-content:space-between}
  .page-header{gap:8px}
  .hdr-right .btn{padding:8px 12px;font-size:13px}
  .modal{padding:20px;border-radius:16px}
  .card{padding:16px;border-radius:16px}
  .brand-title{font-size:17px}
  .brand-logo{width:36px;height:36px;font-size:19px}
}

/* ===== 精致 Apple 风（升级）：毛玻璃 / 大圆角 / 柔和阴影 / 渐变强调 ===== */
:root.light{
  --bg-grad-1:radial-gradient(1200px 760px at 12% -8%, rgba(10,132,255,0.10), transparent 60%);
  --bg-grad-2:radial-gradient(1100px 720px at 100% 0%, rgba(94,92,230,0.12), transparent 55%);
}
:root.dark{
  --bg-grad-1:radial-gradient(1200px 760px at 12% -8%, rgba(10,132,255,0.18), transparent 60%);
  --bg-grad-2:radial-gradient(1100px 720px at 100% 0%, rgba(94,92,230,0.18), transparent 55%);
}
body{background:var(--sys-bg)}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;background-image:var(--bg-grad-1),var(--bg-grad-2)}

/* 玻璃卡片 */
.card,.card.flat,.modal,.login-card,.sidebar,.upitem,.batch-bar,.ctxmenu,.stats-card,.hdr-menu{
  backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
.card,.card.flat{background:rgba(255,255,255,0.72);border:1px solid rgba(0,0,0,0.08);
  box-shadow:0 1px 2px rgba(31,35,40,0.04),0 12px 32px rgba(31,35,40,0.08);border-radius:20px}
:root.dark .card,:root.dark .card.flat{background:rgba(22,27,34,0.66);border-color:rgba(255,255,255,0.10);
  box-shadow:0 1px 2px rgba(0,0,0,0.4),0 16px 40px rgba(0,0,0,0.5)}
.card.flat{background:rgba(255,255,255,0.60);overflow:hidden}
:root.dark .card.flat{background:rgba(22,27,34,0.55)}
.usage{background:rgba(255,255,255,0.60);border:1px solid rgba(0,0,0,0.08);
  box-shadow:0 1px 2px rgba(31,35,40,0.04),0 8px 24px rgba(31,35,40,0.06);
  backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
:root.dark .usage{background:rgba(22,27,34,0.55);border-color:rgba(255,255,255,0.10)}

/* 按钮：Apple 风 */
.btn{background:var(--sys-blue);color:#fff;border:none;border-radius:980px;padding:9px 16px;font-weight:600;
  box-shadow:0 1px 2px rgba(0,0,0,0.12),inset 0 1px 0 rgba(255,255,255,0.22);
  transition:transform .12s cubic-bezier(.4,0,.2,1),background-color .15s,filter .15s}
.btn:hover{background:var(--sys-blue-hover);filter:brightness(1.02)}
.btn:active{transform:scale(0.96)}
.btn.gray{background:var(--sys-fill-2);color:var(--sys-text);box-shadow:none}
.btn.gray:hover{background:var(--sys-fill-3)}
.btn.primary{background:linear-gradient(180deg,#0a84ff,#0066ff);font-size:15px;padding:11px 22px}
.btn.primary:hover{filter:brightness(1.05)}
.btn.danger{background:var(--sys-red);color:#fff}
.btn.danger:hover{filter:brightness(1.05)}
.btn.small{padding:6px 12px;font-size:13px}
.btn.tiny{padding:4px 10px;font-size:12px;font-weight:500}

/* 输入 */
.input,input[type=text],input[type=password],input[type=search],select,textarea{
  background:var(--sys-fill);border:1px solid var(--sys-separator);border-radius:12px;color:var(--sys-text)}
.input:focus,input:focus,select:focus,textarea:focus{background:var(--sys-card-solid);
  box-shadow:0 0 0 3px var(--sys-blue-soft),0 0 0 1px var(--sys-blue);border-color:transparent}
.input-group,.search-box{background:var(--sys-fill);border:1px solid var(--sys-separator);border-radius:12px}
.input-group:focus-within,.search-box:focus-within{border-color:var(--sys-blue);
  box-shadow:0 0 0 3px var(--sys-blue-soft);background:var(--sys-card-solid)}
.input-group input,.search-box input{background:transparent;border:none;box-shadow:none}
.input-addon,.search-box button{border-left:1px solid var(--sys-separator);background:transparent;color:var(--sys-blue)}
.input-addon:hover,.search-box button:hover{background:var(--sys-fill-2);color:var(--sys-blue-hover)}

/* 工具栏（z-index 提升，避免毛玻璃建立的层叠上下文被内容卡片盖住导致下拉穿模） */
.toolbar-card{padding:16px 18px;position:relative;z-index:5}
.toolbar-row.main{margin-bottom:14px;position:relative;gap:10px}
.toolbar-row.main .btn.primary{padding:10px 20px}
.toolbar-row.main #btnMore{margin-left:auto;min-width:42px;font-size:18px;line-height:1;padding:7px 12px;border-radius:980px}

/* ⋯ 下拉 */
.hdr-menu{position:absolute;top:calc(100% + 8px);right:0;z-index:600;width:280px;max-height:74vh;overflow:auto;display:none;
  background:rgba(255,255,255,0.82);border:1px solid rgba(0,0,0,0.08);
  box-shadow:0 20px 50px rgba(31,35,40,0.22);padding:6px;border-radius:16px}
:root.dark .hdr-menu{background:rgba(22,27,34,0.80);border-color:rgba(255,255,255,0.12);box-shadow:0 24px 60px rgba(0,0,0,0.6)}
.hdr-menu.show{display:block;animation:sheetUp .18s cubic-bezier(.4,0,.2,1)}
.hdr-menu .mgroup{padding:2px 0}
.hdr-menu .mgroup+.mgroup{border-top:1px solid var(--sys-separator);margin-top:4px;padding-top:6px}
.hdr-menu .mlabel{font-size:11px;color:var(--sys-text-3);font-weight:600;padding:5px 10px 4px}
.hdr-menu .chip{display:flex;width:100%;justify-content:flex-start;align-items:center;gap:9px;
  background:transparent;border:none;color:var(--sys-text);font-size:13.5px;font-weight:500;padding:7px 10px;text-align:left;border-radius:10px}
.hdr-menu .chip:hover{background:var(--sys-fill);color:var(--sys-text)}
.hdr-menu .chip.enc-active{background:var(--sys-green);color:#fff}
.btn.active{background:var(--sys-fill-3)}

/* 拖拽区 */
#dropZone{margin-top:14px;padding:22px;gap:12px;border:1.5px dashed var(--sys-separator-opaque);border-radius:16px;background:transparent;color:var(--sys-text-3);transition:all .2s}
#dropZone .drop-icon{width:34px;height:34px;font-size:16px;background:var(--sys-fill);color:var(--sys-text-2)}
#dropZone:hover,#dropZone.over{border-color:var(--sys-blue);background:var(--sys-blue-soft);color:var(--sys-blue)}
#dropZone:hover .drop-icon,#dropZone.over .drop-icon{background:var(--sys-blue);color:#fff}

/* 面包屑 + 排序 */
.card.flat .bc{display:flex;align-items:center;gap:14px;justify-content:space-between;flex-wrap:wrap;
  padding:12px 20px;white-space:normal;overflow:visible;font-size:13px;background:transparent;border-bottom:.5px solid var(--sys-separator)}
.card.flat .bc .bc-path{flex:1;min-width:0;overflow-x:auto;white-space:nowrap;scrollbar-width:none;font-weight:500}
.card.flat .bc .bc-path::-webkit-scrollbar{display:none}
.card.flat .bc .bc-path a{color:var(--sys-blue)}
.card.flat .bc .sort-wrap{flex-shrink:0}
.sort-wrap{gap:8px}
.sort-label{font-size:12px;color:var(--sys-text-3)}
.sort-group{display:inline-flex;background:var(--sys-fill);border:1px solid var(--sys-separator);border-radius:11px;padding:2px;gap:2px}
.sort-btn{font-size:13px;padding:6px 14px;background:none;border:none;border-radius:9px;color:var(--sys-text-2);cursor:pointer;font-weight:500;transition:all .15s}
.sort-btn:hover{color:var(--sys-text)}
.sort-btn.active{color:var(--sys-text);background:var(--sys-card-solid);box-shadow:var(--sys-shadow-sm);font-weight:600}

/* 筛选条 */
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 18px;border-bottom:1px solid var(--sys-separator);font-size:12px;background:transparent}
.filter-bar .chip-label{font-size:11px;color:var(--sys-text-3);font-weight:600;letter-spacing:.2px}
.filter-bar .chip-sep{height:18px;background:var(--sys-separator)}
.fchip{padding:5px 12px;border-radius:980px;border:1px solid var(--sys-separator);background:var(--sys-fill);color:var(--sys-text-2);font-size:12px;cursor:pointer;font-family:inherit;transition:all .15s}
.fchip:hover{background:var(--sys-fill-2);color:var(--sys-text)}
.fchip.active{background:var(--sys-blue);border-color:var(--sys-blue);color:#fff;font-weight:600}

/* 列表：桌面表格列 */
.list-head{display:none}
.row-actions{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.file-list li{padding:11px 20px;gap:12px;border-bottom:.5px solid var(--sys-separator);min-height:54px}
.file-list li:hover{background:var(--sys-fill)}
.file-list li.selected{background:var(--sys-blue-soft)}
.file-list .fname{font-size:15px;font-weight:400}
.file-list .fdate{display:block;color:var(--sys-text-3);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.file-list .fsize{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--sys-text-3)}
@media(min-width:821px){
  .list-head{display:grid;grid-template-columns:22px 24px minmax(120px,1fr) 26px 92px 76px 212px;align-items:center;gap:12px;padding:9px 20px;font-size:12px;color:var(--sys-text-3);border-bottom:1px solid var(--sys-separator);background:transparent}
  .list-head .lh-r{text-align:right}
  .file-list li{display:grid;grid-template-columns:22px 24px minmax(120px,1fr) 26px 92px 76px 212px;align-items:center;gap:12px}
  .file-list .fsize,.file-list .fdate{text-align:right}
.row-actions .btn.extra{display:none}
.row-actions .btn.alw{display:inline-flex}
.row-menu .btn{display:inline-flex;justify-content:flex-start}
}

/* 网格 + 图库 */
.file-grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px;padding:20px}
.gitem{background:var(--sys-fill);border:1px solid transparent;border-radius:16px;padding:14px 10px 12px;transition:all .18s cubic-bezier(.4,0,.2,1)}
.gitem:hover{background:var(--sys-card-solid);border-color:var(--sys-separator);transform:translateY(-3px);box-shadow:var(--sys-shadow-lg)}
.gitem.selected{background:var(--sys-blue-soft);border-color:var(--sys-blue)}
.gthumb{height:108px;margin-bottom:10px;border-radius:12px;border:1px solid var(--sys-separator);background:var(--sys-fill-2)}
.gicon{height:108px;line-height:108px;font-size:42px;margin-bottom:10px;border-radius:12px;background:var(--sys-card-solid);border:1px solid var(--sys-separator)}
.gname{font-size:13px;line-height:1.4;max-height:2.8em;font-weight:500}
.gmeta{display:flex;justify-content:space-between;gap:6px;font-size:11px;color:var(--sys-text-3);margin-top:5px;padding:0 4px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.gitem input[type=checkbox]{opacity:0;transition:opacity .15s}
.gitem:hover input[type=checkbox],.gitem.selected input[type=checkbox]{opacity:1}

/* 侧栏：桌面常驻（可折叠并记忆），移动端抽屉 */
.sidebar{display:none;position:sticky;top:24px;width:248px;max-height:calc(100vh - 48px);overflow-y:auto;padding:14px;
  background:rgba(255,255,255,0.72);border:1px solid rgba(0,0,0,0.08);border-radius:16px;box-shadow:var(--sys-shadow-md)}
:root.dark .sidebar{background:rgba(22,27,34,0.66);border-color:rgba(255,255,255,0.10)}
.sidebar.show{display:block}
@media (min-width:761px){
  .sidebar{display:flex;flex-direction:column}
  .layout.sidebar-hidden .sidebar{display:none}
  .only-mobile{display:none!important}
}
/* 移动端：选择模式 + 底部操作栏 */
@media (max-width:760px){
  .file-list li [data-chk],.gitem input[type=checkbox]{display:none}
  body.selmode .file-list li [data-chk],body.selmode .gitem input[type=checkbox]{display:inline-block;opacity:1}
  .batch-bar.show{display:flex;position:fixed;left:0;right:0;bottom:calc(58px + env(safe-area-inset-bottom));z-index:870;
    flex-wrap:nowrap;overflow-x:auto;gap:6px;margin:0;border-radius:0;padding:8px 10px}
  .batch-bar .btn{white-space:nowrap}
  .row-actions .row-more-wrap .row-menu{right:auto;left:0}
}
.sidebar-toggle{display:inline-flex}
.tree-item{padding:8px 10px;font-size:14px;border-radius:10px}
.tree-item:hover{background:var(--sys-fill)}
.tree-item.active{background:var(--sys-blue);color:#fff}
.tree-item.active .tw{color:rgba(255,255,255,0.9)}
.tag-section{border-top:1px solid var(--sys-separator);margin-top:12px;padding-top:12px}
.tag-filter-item{padding:7px 10px;border-radius:9px;font-size:13px}

/* 面板 / 登录 / 模态 */
.modal{background:rgba(255,255,255,0.86);border:1px solid rgba(0,0,0,0.08);border-radius:22px;box-shadow:0 30px 70px rgba(31,35,40,0.28);padding:24px}
:root.dark .modal{background:rgba(22,27,34,0.82);border-color:rgba(255,255,255,0.12);box-shadow:0 36px 80px rgba(0,0,0,0.65)}
.modal-bg{background:rgba(0,0,0,0.28);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
.modal h3{font-size:18px;font-weight:700;letter-spacing:-0.02em;margin-bottom:18px}
.mclose{background:var(--sys-fill);border:1px solid var(--sys-separator)}
.mclose:hover{background:var(--sys-fill-2)}
.batch-bar{background:var(--sys-blue-soft);border:1px solid rgba(10,122,255,0.35);padding:11px 16px;border-radius:14px}
.stats-card{background:var(--sys-fill);border:1px solid var(--sys-separator);border-radius:14px;padding:16px;text-align:center}
.hl-pre,.md-body pre,pre{border:1px solid var(--sys-separator);border-radius:12px}
.login-card{max-width:400px;padding:32px;border-radius:24px;background:rgba(255,255,255,0.82);border:1px solid rgba(0,0,0,0.08);box-shadow:0 30px 70px rgba(31,35,40,0.28)}
:root.dark .login-card{background:rgba(22,27,34,0.82);border-color:rgba(255,255,255,0.12);box-shadow:0 36px 80px rgba(0,0,0,0.65)}
.login-logo,.brand-logo{box-shadow:0 12px 30px rgba(10,132,255,0.35),inset 0 1px 0 rgba(255,255,255,0.35)}
.brand-logo{border-radius:13px}
.login-logo{border-radius:24px}

/* 进度条渐变 */
.ufill,.upfill{background:linear-gradient(90deg,#0a84ff,#5e5ce6)}
.ubar{background:var(--sys-fill-2)}

/* 图库视图 */
.file-grid.gallery{grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:16px;padding:20px}
.file-grid.gallery .gitem{padding:8px 8px 10px}
.file-grid.gallery .gthumb{height:160px;object-fit:cover;margin-bottom:8px;border:none;background:var(--sys-fill-2)}
.file-grid.gallery .gname{font-size:13px}

/* 骨架屏 + 轻动效 */
@keyframes skShim{0%{opacity:.5}50%{opacity:1}100%{opacity:.5}}
@keyframes fadeUp{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.file-list.sk li{display:flex;align-items:center;gap:12px;padding:12px 20px}
.sk{background:var(--sys-fill-2);border-radius:8px;animation:skShim 1.2s ease-in-out infinite}
.sk-ic{width:22px;height:22px;flex:none}
.sk-bar{height:12px}
.file-list li,.gitem{animation:fadeUp .18s ease both}
@media (prefers-reduced-motion: reduce){.sk{animation:none}.file-list li,.gitem{animation:none}}

/* 日志 / 下载明细 */
.log-day{font-size:11px;color:var(--sys-text-3);font-weight:600;margin:12px 0 4px;letter-spacing:.3px}
.log-action{font-weight:500;min-width:66px;font-size:12.5px;flex-shrink:0}
.src-badge{padding:1px 6px;border-radius:6px;background:var(--sys-fill);color:var(--sys-text-3);font-size:11px;flex-shrink:0}
.dl-days{max-height:160px;overflow:auto;margin-bottom:6px;border:1px solid var(--sys-separator);border-radius:12px;padding:4px 10px}

/* 滚动条 */
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--sys-fill-3);border-radius:99px;border:3px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:var(--sys-text-3);background-clip:padding-box}

@media(max-width:820px){
  .wrap{padding:14px 14px 40px}
  .layout{flex-direction:column}
  .sidebar{width:100%;position:static;max-height:none;display:none}
  .sidebar.show{display:block}
  .file-grid{grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:10px;padding:14px}
  .file-list .fdate{display:none!important}
  .btn.primary{width:100%}
  .input-group{width:100%}
  .input-group input{width:auto;flex:1}
  .search-box{min-width:100%}
  .toolbar-row.main{flex-direction:column;align-items:stretch;gap:8px}
  .toolbar-row.tools{flex-direction:column;align-items:stretch;gap:10px}
  .chips{flex-wrap:wrap;gap:6px}
  .chip-sep{display:none}
  .chip-group{width:100%}
  .chip-label{display:none}
  .sort-wrap{justify-content:space-between}
  .page-header{gap:8px}
  .hdr-right .btn{padding:8px 12px;font-size:13px}
  .modal{padding:20px;border-radius:18px}
  .card{padding:16px;border-radius:16px}
  .brand-title{font-size:17px}
  .brand-logo{width:36px;height:36px;font-size:19px}
}
</style></head><body>
<div class="wrap">
<div id="loginPage">
<div class="login-logo">${escHtml(brand.logo)}</div>
<div class="login-title">${escHtml(brand.title)}</div>
<div class="login-sub">安全 · 私密 · 快速</div>
<div class="login-card">
<div class="row"><input id="pw" type="password" placeholder="输入访问密码" style="flex:1" autocomplete="current-password"><button id="btnLogin" class="btn">登录</button></div>
<div class="row hidden" id="totpRow" style="margin-top:8px"><input id="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="动态码 / 备用码" style="flex:1"></div>
<div class="login-err" id="loginErr">密码错误，请重试</div>
</div>
<div class="ver login-ver">${APP_VERSION}</div>
</div>
<div id="mainPage">
<div id="offlineBar" class="offline-bar" style="display:none"></div>
<header class="app-bar">
  <button id="btnSidebar" class="icon-btn sidebar-toggle" title="侧栏">☰</button>
  <div class="brand"><span class="brand-logo">${escHtml(brand.logo)}</span><span class="brand-title">${escHtml(brand.title)}</span></div>
  <div class="appbar-main">
    <button id="btnUp" class="btn primary">上传文件</button>
    <div class="menu-wrap">
      <button id="btnNew" class="btn gray" title="新建">＋</button>
      <div class="pop-menu" id="newMenu">
        <button class="chip" data-new="file">⬆ 上传文件</button>
        <button class="chip" data-new="files">🗂 上传文件夹</button>
        <button class="chip" data-new="dir">📁 新建文件夹</button>
        <button class="chip" data-new="text">📝 新建文本</button>
        <button class="chip" data-new="folder-pw">🔒 目录密码</button>
      </div>
    </div>
    <div class="input-group" id="folderInputWrap" style="display:none">
      <input id="folderInput" placeholder="文件夹名">
      <button id="btnMk" class="input-addon" title="新建文件夹">＋</button>
    </div>
    <button id="btnSearchToggle" class="icon-btn" title="搜索 (⌘F)">🔍</button>
    <button id="btnSelect" class="icon-btn only-mobile" title="选择">☑</button>
    <div class="search-box collapsed" id="searchWrap">
      <input id="searchInput" placeholder="搜索文件...">
      <button id="btnSearch">搜索</button>
    </div>
  </div>
  <div class="hdr-right">
    <button id="btnPalette" class="btn gray" title="命令面板 (⌘K / Ctrl+K)">⌘K</button>
    <button id="btnView" class="btn gray icon-only" title="切换视图">▦</button>
    <button id="btnMore" class="btn" title="更多功能" aria-haspopup="true" aria-expanded="false">⋯</button>
    <div class="hdr-menu" id="hdrMenu">
      <div class="mgroup"><div class="mlabel" data-l="views">页面</div>
        <button id="btnFav" class="chip">★ 收藏</button>
        <button id="btnRecent" class="chip">🕐 最近</button>
        <button id="btnTag" class="chip">🏷 标签</button>
        <button id="btnTrash" class="chip">🗑 回收站</button>
        <button id="btnAlbums" class="chip">🖼 公开相册</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="organize">整理</div>
        <button id="btnQuery" class="chip">🔎 高级筛选</button>
        <button id="btnSimilar" class="chip">🖼 相似图片</button>
        <button id="btnImgTools" class="chip">🖌 图片处理</button>
        <button id="btnDup" class="chip">📋 重复文件</button>
        <button id="btnFavGroups" class="chip">★ 收藏分组</button>
        <button id="btnMeta" class="chip">🏷 元数据导出/导入</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="actions">操作</div>
        <button id="btnZip" class="chip">📦 打包当前目录</button>
        <button id="btnShareDir" class="chip">📁 分享当前目录</button>
        <button id="btnFetchUrl" class="chip">⬇ 抓取链接</button>
        <button id="btnImport" class="chip">📥 从 WebDAV 导入</button>
        <button id="btnAutoRule" class="chip">🗂 自动归档</button>
        <button id="btnComp" class="chip" onclick="window.toggleCompress&&window.toggleCompress(this)">🗜 压缩</button>
        <button id="btnLock" class="chip">🔒 目录密码</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="links">链接</div>
        <button id="btnShareMgmt" class="chip">🔗 分享管理</button>
        <button id="btnULinkMgmt" class="chip">📤 上传链接管理</button>
        <button id="btnULink" class="chip">🔗 传链</button>
        <button id="btnEnc" class="chip">🔐 加密</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="data">数据</div>
        <button id="btnStats" class="chip">📊 统计</button>
        <button id="btnLog" class="chip">📋 日志</button>
        <button id="btnDlStats" class="chip">📥 下载明细</button>
        <button id="btnBackup" class="chip">💾 备份与恢复</button>
        <button id="btnHealth" class="chip">🩺 健康检查</button>
        <button id="btnOrphans" class="chip">🧹 孤儿扫描</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="system">系统</div>
        <button id="btnOps" class="chip">🛠 运维与配置</button>
        <button id="btnTotp" class="chip">🛡 二次验证</button>
        <button id="btnTokens" class="chip">🔑 访问令牌</button>
        <button id="btnSessions" class="chip">🖥 登录设备</button>
        <button id="btnAdminPass" class="chip">🔐 改密码</button>
        <button id="btnBackends" class="chip">☁️ 存储后端</button>
        <button id="btnWebDAV" class="chip">🌐 WebDAV</button>
        <button id="btnWebhook" class="chip">🔔 通知</button>
        <button id="btnApi" class="chip">⚡ 上传接口</button>
        <button id="btnClearPend" class="chip">🧹 清除断点记录</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="appearance">外观</div>
        <button id="btnTheme" class="chip">🌗 切换主题</button>
        <button id="btnLang" class="chip">🌐 English</button>
        <button id="btnLogout" class="chip">🚪 退出登录</button>
      </div>
    </div>
  </div>
</header>
<div class="upqbar" id="upQueueBar" style="display:none"></div>
<div class="clipbar" id="clipBar" style="display:none"></div>
<div class="uplist" id="upList"></div>
<div class="layout">
<aside class="card sidebar" id="sidebar">
  <nav class="side-nav" id="sideNav">
    <button class="side-item" data-nav="home"><span class="si-ic">🏠</span><span class="si-tx" data-l="home">首页</span></button>
    <button class="side-item" data-nav="files"><span class="si-ic">📁</span><span class="si-tx" data-l="allFiles">全部文件</span></button>
    <button class="side-item" data-nav="fav"><span class="si-ic">★</span><span class="si-tx" data-l="favs">收藏</span></button>
    <button class="side-item" data-nav="recent"><span class="si-ic">🕐</span><span class="si-tx" data-l="recents">最近</span></button>
    <button class="side-item" data-nav="albums"><span class="si-ic">🖼</span><span class="si-tx" data-l="albums">相册</span></button>
    <button class="side-item" data-nav="trash"><span class="si-ic">🗑</span><span class="si-tx" data-l="trash">回收站</span></button>
    <button class="side-item" data-nav="upload"><span class="si-ic">📤</span><span class="si-tx" data-l="uploadLinks">上传链接</span></button>
  </nav>
  <div class="s-title" data-l="tree">目录</div><div id="treeBox"></div>
  <div class="tag-section" id="tagSection"><div class="s-title" data-l="tags">标签</div><div id="tagBox"></div></div>
  <div class="side-foot">
    <button id="footTheme" class="side-mini">🌗 <span data-l="theme">主题</span></button>
    <button id="footDensity" class="side-mini">📐 <span data-l="density">密度</span></button>
    <label class="side-mini" title="主题色"><input type="color" id="footAccent" value="#0a84ff"><span data-l="accent">主题色</span></label>
    <button id="footLang" class="side-mini">🌐 <span data-l="language">语言</span></button>
    <button id="footLogout" class="side-mini">🚪 <span data-l="logout">退出</span></button>
  </div>
</aside>
<div class="main">

<section class="view" id="viewHome">
  <div id="dashWrap"><div class="dash-loading">加载概览…</div></div>
</section>

<section class="view" id="viewFiles">
<div class="card toolbar-card">
  <div id="dropZone">
    <span class="drop-icon">⬇</span>
    <span>拖拽文件 / 文件夹到此处，或点击上传</span>
  </div>
</div>

<div class="batch-bar" id="batchBar"><span id="batchCount"></span><button id="batchCopy" class="btn gray small">复制</button><button id="batchCut" class="btn gray small">剪切</button><button id="batchDel" class="btn danger small">批量删除</button><button id="batchDl" class="btn gray small">批量下载</button><button id="batchZip" class="btn gray small">打包下载</button><button id="batchShare" class="btn gray small">批量分享</button><button id="batchMv" class="btn gray small">移动</button><button id="batchRen" class="btn gray small">重命名</button><button id="batchClr" class="btn gray small">取消</button></div>
<div class="card flat"><div class="bc"><span class="bc-path" id="bcPath"></span><div class="sort-wrap"><span class="sort-label" data-l="sort">排序</span><div class="sort-group"><button class="sort-btn" data-s="name">名称</button><button class="sort-btn" data-s="size">大小</button><button class="sort-btn" data-s="time">日期</button></div></div></div><div class="filter-bar" id="filterBar"><div class="chip-group"><span class="chip-label" data-l="type">类型</span><button class="fchip active" data-ft="">全部</button><button class="fchip" data-ft="image">图片</button><button class="fchip" data-ft="video">视频</button><button class="fchip" data-ft="audio">音频</button><button class="fchip" data-ft="doc">文档</button><button class="fchip" data-ft="zip">压缩包</button><button class="fchip" data-ft="other">其他</button></div><span class="chip-sep"></span><div class="chip-group"><span class="chip-label" data-l="time">时间</span><button class="fchip active" data-fa="">全部</button><button class="fchip" data-fa="today">今天</button><button class="fchip" data-fa="7">7 天</button><button class="fchip" data-fa="30">30 天</button></div></div><div id="fileList"></div></div><div class="usage"><div class="ulabel"><span id="uUsed">...</span><span class="ver">${APP_VERSION}</span><span style="display:flex;gap:8px;align-items:center"><span id="uFiles"></span><button id="btnRecalc" class="btn gray tiny" title="重新统计">↻</button></span></div><div class="ubar"><div class="ufill" id="uFill" style="width:0%"></div></div></div>
</section>

</div>
</div>
</div>
</div>
<input type="file" id="fileInput" multiple style="display:none">
<div class="modal-bg" id="pvModal"><div class="modal" id="pvBox"><button class="mclose" id="pvClose">✕</button><button class="pv-nav prev hidden" id="pvPrev">‹</button><button class="pv-nav next hidden" id="pvNext">›</button><span class="pv-counter" id="pvCounter"></span><div id="pvContent"></div></div></div>
<div class="modal-bg" id="trModal"><div class="modal" style="min-width:380px;max-width:580px"><button class="mclose" id="trClose">✕</button><h3 id="trTitle">回收站</h3><div id="trContent"></div></div></div>
<div class="modal-bg" id="mvModal"><div class="modal" style="min-width:300px;max-width:420px"><button class="mclose" id="mvClose">✕</button><h3 id="mvTitle">移动到...</h3><div id="mvContent"></div></div></div>
<div class="modal-bg" id="statsModal"><div class="modal" style="min-width:420px;max-width:640px"><button class="mclose" id="statsClose">✕</button><h3>统计</h3><div id="statsContent"></div></div></div>
<div class="modal-bg" id="logModal"><div class="modal" style="min-width:400px;max-width:600px"><button class="mclose" id="logClose">✕</button><h3>活动日志</h3><div id="logContent" style="max-height:400px;overflow:auto"></div></div></div>
<div class="modal-bg" id="tokensModal"><div class="modal" style="min-width:400px;max-width:560px"><button class="mclose" id="tokensClose">✕</button><h3>访问令牌</h3><div id="tokensContent"></div></div></div>
<div class="modal-bg" id="webdavModal"><div class="modal" style="min-width:400px;max-width:520px"><button class="mclose" id="webdavClose">✕</button><h3>WebDAV</h3><div id="webdavContent"></div></div></div>
<div class="modal-bg" id="brModal"><div class="modal" style="min-width:400px;max-width:560px"><button class="mclose" id="brClose">✕</button><h3>批量重命名</h3><div id="brContent"></div></div></div>
<div class="modal-bg" id="tagModal"><div class="modal" style="min-width:360px;max-width:500px"><button class="mclose" id="tagClose">✕</button><h3 id="tagTitle">管理标签</h3><div id="tagContent"></div></div></div>
<div class="palette" id="palette"><div class="palette-box">
  <input id="paletteInput" placeholder="输入命令或文件名…（↑↓ 选择，Enter 执行，Esc 关闭）" autocomplete="off">
  <div class="palette-list" id="paletteList"></div>
  <div class="palette-foot" id="paletteFoot">⌘K / Ctrl+K 打开 · 支持命令与文件搜索</div>
</div></div>
<div class="tabbar" id="tabBar">
  <button data-tb="home"><span class="tb-ic">🏠</span>首页</button>
  <button data-tb="files"><span class="tb-ic">📁</span>文件</button>
  <button data-tb="fav"><span class="tb-ic">★</span>收藏</button>
  <button data-tb="recent"><span class="tb-ic">🕐</span>最近</button>
  <button data-tb="more"><span class="tb-ic">☰</span>我的</button>
</div>
<div class="modal-bg" id="noteModal"><div class="modal" style="min-width:360px;max-width:500px"><button class="mclose" id="noteClose">✕</button><h3 id="noteTitle">文件备注</h3><div id="noteContent"></div></div></div>
<div class="modal-bg" id="dupModal"><div class="modal" style="min-width:400px;max-width:640px"><button class="mclose" id="dupClose">✕</button><h3 id="dupTitle">重复文件</h3><div id="dupContent"></div></div></div>
<div class="modal-bg" id="encModal"><div class="modal" style="min-width:360px;max-width:480px"><button class="mclose" id="encClose">✕</button><h3 id="encTitle">AES 加密</h3><div id="encContent"></div></div></div>
<div class="modal-bg" id="verModal"><div class="modal" style="min-width:380px;max-width:520px"><button class="mclose" id="verClose">✕</button><h3 id="verTitle">历史版本</h3><div id="verContent"></div></div></div>
<div class="modal-bg" id="shareMgmtModal"><div class="modal" style="min-width:420px;max-width:680px"><button class="mclose" id="shareMgmtClose">✕</button><h3>分享链接管理</h3><div id="shareMgmtContent"></div></div></div>
<div class="modal-bg" id="ulinkMgmtModal"><div class="modal" style="min-width:420px;max-width:680px"><button class="mclose" id="ulinkMgmtClose">✕</button><h3>上传链接管理</h3><div id="ulinkMgmtContent"></div></div></div>
<div class="modal-bg" id="dlModal"><div class="modal" style="min-width:440px;max-width:720px"><button class="mclose" id="dlModalClose">✕</button><h3>下载明细</h3><div id="dlContent"></div></div></div>
<div class="modal-bg" id="backendsModal"><div class="modal" style="min-width:440px;max-width:700px"><button class="mclose" id="backendsClose">✕</button><h3>存储后端</h3><div id="backendsContent"></div></div></div>
<div class="modal-bg" id="apModal"><div class="modal" style="min-width:360px;max-width:460px"><button class="mclose" id="apClose">✕</button><h3>修改管理员密码</h3><div id="apContent"></div></div></div>
<div class="modal-bg" id="autoModal"><div class="modal" style="min-width:360px;max-width:460px"><button class="mclose" id="autoClose">✕</button><h3>上传后自动归档</h3><div id="autoContent"></div></div></div>
<div class="modal-bg" id="sessModal"><div class="modal" style="min-width:380px;max-width:560px"><button class="mclose" id="sessClose">✕</button><h3>登录设备</h3><div id="sessContent"></div></div></div>
<div class="modal-bg" id="bkModal"><div class="modal" style="min-width:400px;max-width:600px"><button class="mclose" id="bkClose">✕</button><h3>备份与恢复</h3><div id="bkContent"></div></div></div>
<div class="modal-bg" id="hlModal"><div class="modal" style="min-width:380px;max-width:560px"><button class="mclose" id="hlClose">✕</button><h3>健康检查</h3><div id="hlContent"></div></div></div>
<div class="modal-bg" id="orModal"><div class="modal" style="min-width:420px;max-width:640px"><button class="mclose" id="orClose">✕</button><h3>孤儿文件扫描</h3><div id="orContent"></div></div></div>
<div class="modal-bg" id="whModal"><div class="modal" style="min-width:400px;max-width:560px"><button class="mclose" id="whClose">✕</button><h3>通知 (Webhook)</h3><div id="whContent"></div></div></div>
<div class="modal-bg" id="apiModal"><div class="modal" style="min-width:440px;max-width:680px"><button class="mclose" id="apiClose">✕</button><h3>上传接口 / 脚本</h3><div id="apiContent"></div></div></div>
<div class="modal-bg" id="albModal"><div class="modal" style="min-width:420px;max-width:600px"><button class="mclose" id="albClose">✕</button><h3>公开相册</h3><div id="albContent"></div></div></div>
<div class="ctxmenu" id="ctxMenu"></div>
<script>
var tk=sessionStorage.getItem('dt')||'',cur='/',viewMode=localStorage.getItem('dv')||'grid',sortKey=localStorage.getItem('ds')||'name',sortAsc=true,selected={},searchMode=false,searchResults=[],favMode=false,recentMode=false,filterType='',filterAge='';
var lang=localStorage.getItem('dl')||'zh';
var currentItems=[];
var previewIdx=-1;
var uploadQueue=0;
var CHUNK_SIZE=5*1024*1024;
var T={zh:{upload:'上传',folder:'文件夹名',search:'搜索文件...',go:'搜索',fav:'收藏',recent:'最近',zip:'打包',ulink:'传链',lock:'密码',trash:'回收站',view:'网格',viewList:'列表',logout:'退出',home:'首页',empty:'此文件夹为空',noResult:'无结果',del:'删除',ren:'改名',move:'移动',share:'分享',download:'下载',edit:'编辑',rename:'重命名为:',delete:'确定删除？',batchDel:'批量删除',batchDl:'批量下载',clear:'取消',sort:'排序',drop:'拖拽文件 / 文件夹到此处，或点击上传',trashEmpty:'回收站为空',restore:'恢复',purge:'彻底删除',emptyTrash:'清空回收站',moveTo:'移动到...',save:'保存',saved:'已保存',days:'有效天数:',link:'分享链接（复制）：',used:'已用',files:'个文件',maxAcc:'最大访问次数(0=不限):',maxUp:'最大上传数(0=不限):',setPw:'设置密码(留空取消):',pwSet:'密码已设置',pwRm:'密码已移除',title:'云端网盘',sidebar:'目录',locked:'该文件夹已加密',enterPw:'请输入文件夹密码:',wrongPw:'密码错误',upDone:'完成',upFail:'失败',upLocked:'已锁',sharePw:'分享密码(留空则不设):',unzip:'解压',unzipping:'解压中...',unzipDone:'解压完成',history:'历史版本',restoreV:'恢复此版本',noVers:'无历史版本',confirmRestore:'确定用此版本覆盖当前文件？',daysLeft:'天后过期',batchRestore:'批量恢复',batchPurge:'批量彻底删除',tag:'标签',tags:'标签管理',addTag:'添加标签',tagColor:'颜色',noTags:'暂无标签',dup:'重复',duplicates:'重复文件',noDup:'无重复文件',enc:'加密',encrypt:'加密文件',decrypt:'解密文件',encPw:'加密密码:',encDone:'加密完成',encFail:'加密失败',decDone:'解密完成',note:'备注',noteSaved:'备注已保存',paste:'粘贴上传',shortcuts:'快捷键',renderMd:'渲染',raw:'原文',stats:'统计',log:'日志',tokens:'令牌',webdav:'WebDAV',brRen:'批量重命名',brPattern:'替换规则 (支持 {n} 序号, {d} 日期):',brPreview:'预览',slideshow:'幻灯片',screenshot:'截图',qrCode:'二维码',upQueue:'上传队列',pause:'暂停',resume:'继续',retry:'重试',cancel:'取消',conc:'并发',clearDone:'清除已完成',pauseAll:'全部暂停',resumeAll:'全部继续',copy:'复制',cut:'剪切',pasteHere:'粘贴到此处',clipEmpty:'剪贴板为空',pasteDone:'已粘贴',resumeTitle:'未完成的分片上传（重新选择同名文件即可续传）',pendHint:'重新选择同名文件',clearPend:'清除记录'},en:{upload:'Upload',folder:'Folder',search:'Search...',go:'Go',fav:'Fav',recent:'Recent',zip:'ZIP',ulink:'ULink',lock:'Lock',trash:'Trash',view:'Grid',viewList:'List',logout:'Out',home:'Home',empty:'Empty folder',noResult:'No results',del:'Del',ren:'Ren',move:'Move',share:'Share',download:'Download',edit:'Edit',rename:'Rename:',delete:'Delete?',batchDel:'Del All',batchDl:'Download',clear:'Clear',sort:'Sort',drop:'Drop files or folder here, or click to upload',trashEmpty:'Empty',restore:'Restore',purge:'Del',emptyTrash:'Empty All',moveTo:'Move to...',save:'Save',saved:'Saved',days:'Days:',link:'Link:',used:'Used',files:'files',maxAcc:'Max accesses (0=unlimited):',maxUp:'Max uploads (0=unlimited):',setPw:'Set password (empty to remove):',pwSet:'Password set',pwRm:'Password removed',title:'Cloud Drive',sidebar:'Folders',locked:'Folder is locked',enterPw:'Enter folder password:',wrongPw:'Wrong password',upDone:'Done',upFail:'Fail',upLocked:'Locked',sharePw:'Share password (empty=none):',unzip:'Unzip',unzipping:'Unzipping...',unzipDone:'Unzipped',history:'History',restoreV:'Restore',noVers:'No versions',confirmRestore:'Overwrite current file with this version?',daysLeft:'days left',batchRestore:'Restore All',batchPurge:'Delete All',tag:'Tag',tags:'Tags',addTag:'Add tag',tagColor:'Color',noTags:'No tags',dup:'Dups',duplicates:'Duplicates',noDup:'No duplicates',enc:'Encrypt',encrypt:'Encrypt',decrypt:'Decrypt',encPw:'Password:',encDone:'Encrypted',encFail:'Encrypt failed',decDone:'Decrypted',note:'Note',noteSaved:'Note saved',paste:'Paste upload',shortcuts:'Shortcuts',renderMd:'Render',raw:'Source',stats:'Stats',log:'Log',tokens:'Tokens',webdav:'WebDAV',brRen:'Rename',brPattern:'Pattern ({n}=index, {d}=date):',brPreview:'Preview',slideshow:'Slideshow',screenshot:'Snap',qrCode:'QR',upQueue:'Queue',pause:'Pause',resume:'Resume',retry:'Retry',cancel:'Cancel',conc:'Concurrency',clearDone:'Clear done',pauseAll:'Pause all',resumeAll:'Resume all',copy:'Copy',cut:'Cut',pasteHere:'Paste here',clipEmpty:'Clipboard empty',pasteDone:'Pasted',resumeTitle:'Unfinished chunked uploads (re-select the same file to resume)',pendHint:'re-select the same file',clearPend:'Clear records'}};
function t(k){return(T[lang]&&T[lang][k])||k}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function safeColor(c){c=String(c==null?'':c).trim();return /^#[0-9a-fA-F]{3,8}$/.test(c)?c:'#0a84ff'}
function show(id){document.getElementById('loginPage').style.display=id==='login'?'flex':'none';document.getElementById('mainPage').style.display=id==='main'?'block':'none'}
// 登录页：若服务端启用了二次验证，直接展示动态码输入框
(function(){
  fetch('/api/version',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
    if(d&&d.totp){var row=document.getElementById('totpRow');if(row)row.classList.remove('hidden')}
  }).catch(function(){});
})();
function fmt(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i]}
function getIcon(it){if(it.type==='dir')return'📁';var e=(it.name||'').split('.').pop().toLowerCase();var m={jpg:'🖼️',jpeg:'🖼️',png:'🖼️',gif:'🖼️',webp:'🖼️',heic:'🖼️',mp4:'🎬',mov:'🎬',mp3:'🎵',wav:'🎵',zip:'📦',pdf:'📄',txt:'📝',md:'📝',doc:'📄',docx:'📄',xls:'📊',xlsx:'📊',ppt:'📽️',pptx:'📽️'};return m[e]||'📄'}
function isImage(it){return(it.mime||'').indexOf('image/')===0}
function isText(it){var m=it.mime||'';return m.indexOf('text/')===0||m==='application/json'||m==='application/javascript'}
function isZip(name){return(name||'').toLowerCase().endsWith('.zip')}
function normP(p){if(!p||p==='/')return'/';p='/'+p.replace(/^\\/+/, '').replace(/\\/+$/,'')+'/';while(p.indexOf('//')>=0)p=p.replace('//','/');return p}
function isPreviewable(it){return it.type==='file'&&((it.mime||'').indexOf('image/')===0||(it.mime||'').indexOf('video/')===0||(it.mime||'').indexOf('audio/')===0||isText(it)||isPDF(it.name))}
function api(p,o){o=o||{};o.headers=o.headers||{};if(tk)o.headers['Authorization']='Bearer '+tk;return fetch(p,o).then(function(r){if(r.status===401){show('login');throw 0}return r.json()})}

var themePref=localStorage.getItem('dth')||'auto';
function applyTheme(){
  var html=document.documentElement;
  html.classList.remove('light','dark');
  var isDark;
  if(themePref==='light')isDark=false;
  else if(themePref==='dark')isDark=true;
  else isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  html.classList.add(isDark?'dark':'light');
  var btn=document.getElementById('btnTheme');
  if(btn)btn.textContent = themePref==='auto'?'🌗':(themePref==='light'?'☀️':'🌙');
}
document.getElementById('btnTheme').onclick=function(){
  themePref = themePref==='auto'?'light':(themePref==='light'?'dark':'auto');
  localStorage.setItem('dth',themePref);
  applyTheme();
};
if(window.matchMedia){
  try{window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(){if(themePref==='auto')applyTheme()})}catch(e){}
}
applyTheme();

function sortItems(items){items.sort(function(a,b){if(a.type==='dir'&&b.type!=='dir')return-1;if(a.type!=='dir'&&b.type==='dir')return 1;var r=0;if(sortKey==='name')r=(a.name||'').localeCompare(b.name||'');else if(sortKey==='size')r=(a.size||a.dirSize||0)-(b.size||b.dirSize||0);else r=new Date(a.time||0)-new Date(b.time||0);return sortAsc?r:-r});return items}
function skeletonRows(n){
  var h='<ul class="file-list sk">';
  for(var i=0;i<(n||6);i++)h+='<li><span class="sk sk-ic"></span><span class="sk sk-bar" style="flex:1;max-width:340px"></span><span class="sk sk-bar" style="width:64px"></span><span class="sk sk-bar" style="width:52px"></span></li>';
  return h+'</ul>';
}
function matchFilter(it){
  if(filterType){
    var m=(it.mime||''),n=(it.name||'').toLowerCase(),ok=false;
    if(filterType==='image')ok=m.indexOf('image/')===0;
    else if(filterType==='video')ok=m.indexOf('video/')===0;
    else if(filterType==='audio')ok=m.indexOf('audio/')===0;
    else if(filterType==='doc')ok=m.indexOf('text/')===0||m.indexOf('json')>=0||/\\.(md|txt|log|csv|docx?|xlsx?|pptx?|pdf)$/.test(n);
    else if(filterType==='zip')ok=m.indexOf('zip')>=0||/\\.(zip|rar|7z|tar|gz)$/.test(n);
    else if(filterType==='other')ok=!(m.indexOf('image/')===0||m.indexOf('video/')===0||m.indexOf('audio/')===0||m.indexOf('text/')===0||m.indexOf('json')>=0||/\\.(md|txt|log|csv|docx?|xlsx?|pptx?|pdf|zip|rar|7z|tar|gz)$/.test(n));
    if(!ok)return false;
  }
  if(filterAge){
    if(it.type==='dir')return true;
    var t2=it.time?Date.parse(it.time):0;
    if(!t2)return false;
    var days=(Date.now()-t2)/86400000;
    if(filterAge==='today'&&days>1)return false;
    if(filterAge==='7'&&days>7)return false;
    if(filterAge==='30'&&days>30)return false;
  }
  return true;
}

function render(){
  selected={};updateBatch();
  var parts=cur.split('/').filter(Boolean);var h='<a data-p="/">'+t('home')+'</a>';var acc='/';
  parts.forEach(function(p){acc+=p+'/';h+=' <span style="opacity:.4">/</span> <a data-p="'+esc(acc)+'">'+esc(p)+'</a>'});
  var bcEl=document.getElementById('bcPath');bcEl.innerHTML=h;
  bcEl.querySelectorAll('a').forEach(function(a){a.onclick=function(){cur=a.getAttribute('data-p');setMode('');load()}});
  document.getElementById('btnView').textContent=viewMode==='list'?(lang==='zh'?'网格':'Grid'):(viewMode==='grid'?(lang==='zh'?'图库':'Gallery'):(lang==='zh'?'列表':'List'));
  document.querySelectorAll('.fchip').forEach(function(b){
    var v=b.hasAttribute('data-ft')?b.getAttribute('data-ft'):b.getAttribute('data-fa');
    var cur2=b.hasAttribute('data-ft')?filterType:filterAge;
    b.classList.toggle('active',v===cur2);
  });
  var compBtn=document.getElementById('btnComp');if(compBtn)compBtn.classList.toggle('enc-active',compressEnabled);
  document.getElementById('btnLang').textContent=lang==='zh'?'EN':'中文';
  var dz=document.getElementById('dropZone');if(dz&&dz.children.length>1)dz.children[1].textContent=t('drop');
  document.getElementById('searchInput').placeholder=t('search');
  document.getElementById('folderInput').placeholder=t('folder');
  document.getElementById('btnUp').textContent=lang==='zh'?'上传文件':'Upload';
  document.getElementById('btnMk').textContent='＋';
  document.getElementById('btnSearch').textContent=t('go');
  document.getElementById('btnFav').textContent='★ '+(lang==='zh'?'收藏':'Fav');
  document.getElementById('btnRecent').textContent='🕐 '+(lang==='zh'?'最近':'Recent');
  document.getElementById('btnZip').textContent='📦 '+(lang==='zh'?'打包':'ZIP');
  document.getElementById('btnULink').textContent='🔗 '+(lang==='zh'?'传链':'ULink');
  document.getElementById('btnLock').textContent='🔒 '+(lang==='zh'?'密码':'Lock');
  document.getElementById('btnTag').textContent='🏷 '+(lang==='zh'?'标签':'Tag');
  document.getElementById('btnStats').textContent='📊 '+(lang==='zh'?'统计':'Stats');
  document.getElementById('btnLog').textContent='📋 '+(lang==='zh'?'日志':'Log');
  document.getElementById('btnTokens').textContent='🔑 '+(lang==='zh'?'令牌':'Tokens');
  document.getElementById('btnWebDAV').textContent='🌐 WebDAV';
  var bmEl=document.getElementById('btnMore');if(bmEl)bmEl.title=lang==='zh'?'更多功能':'More';
  (function(){
    var bUp=document.getElementById('btnUp');if(bUp)bUp.textContent=lang==='zh'?'上传':'Upload';
    var bNew=document.getElementById('btnNew');if(bNew)bNew.title=lang==='zh'?'新建':'New';
    var bSt=document.getElementById('btnSearchToggle');if(bSt)bSt.title=lang==='zh'?'搜索':'Search';
    var bSel=document.getElementById('btnSelect');if(bSel)bSel.title=lang==='zh'?'选择':'Select';
    var sIn=document.getElementById('searchInput');if(sIn)sIn.placeholder=lang==='zh'?'搜索文件...':'Search files...';
    var plIn=document.getElementById('paletteInput');if(plIn)plIn.placeholder=lang==='zh'?'输入命令或文件名…（↑↓ 选择，Enter 执行，Esc 关闭）':'Type a command or file name…';
  })();
  (function(){
    var CL={zh:{browse:'浏览',actions:'操作',data:'数据',links:'链接',system:'系统',sort:'排序',type:'类型',time:'时间',views:'页面',organize:'整理',appearance:'外观',
      home:'首页',allFiles:'全部文件',favs:'收藏',recents:'最近',albums:'相册',trash:'回收站',uploadLinks:'上传链接',tree:'目录',tags:'标签',
      theme:'主题',density:'密度',accent:'主题色',language:'语言',logout:'退出'},
    en:{browse:'Browse',actions:'Actions',data:'Data',links:'Links',system:'System',sort:'Sort',type:'Type',time:'Time',views:'Pages',organize:'Organize',appearance:'Appearance',
      home:'Home',allFiles:'All files',favs:'Favorites',recents:'Recent',albums:'Albums',trash:'Trash',uploadLinks:'Upload links',tree:'Folders',tags:'Tags',
      theme:'Theme',density:'Density',accent:'Accent',language:'Language',logout:'Log out'}};
    document.querySelectorAll('.chip-label[data-l],.mlabel[data-l],.sort-label[data-l],.si-tx[data-l],.side-mini span[data-l],.s-title[data-l]').forEach(function(el){var k=el.getAttribute('data-l');if(CL[lang]&&CL[lang][k])el.textContent=CL[lang][k]});
  })();
  document.getElementById('btnDup').textContent='📋 '+(lang==='zh'?'重复':'Dups');
  document.getElementById('btnEnc').textContent='🔐 '+(lang==='zh'?'加密':'Encrypt');
  document.getElementById('btnTrash').textContent='🗑 '+(lang==='zh'?'回收站':'Trash');
  document.getElementById('btnLogout').textContent=t('logout');
  document.querySelectorAll('.sort-btn').forEach(function(b){var k=b.getAttribute('data-s');b.textContent=lang==='zh'?(k==='name'?'名称':k==='size'?'大小':'日期'):(k==='name'?'Name':k==='size'?'Size':'Date');b.classList.toggle('active',k===sortKey)});
  renderTree();
  renderTagSidebar();
  showFilesView();   // 任何一次列表渲染都意味着要看到文件页（仪表盘 → 文件页）

  var promise;
  if(QUERY.on){promise=Promise.resolve({items:QUERY.items})}
  else if(tagFilterMode){promise=api('/api/tags?filter='+encodeURIComponent(tagFilterName)).then(function(d){return{items:d.items||d.results||[]}})}
  else if(favMode){promise=api('/api/favs').then(function(d){return{items:d.items||[]}})}
  else if(recentMode){promise=api('/api/recent').then(function(d){return{items:d.items||[]}})}
  else if(searchMode){promise=Promise.resolve({items:searchResults})}
  else{promise=api('/api/list?path='+encodeURIComponent(cur)+'&size=1')}

  var skTimer=setTimeout(function(){var el=document.getElementById('fileList');if(el)el.innerHTML=skeletonRows(6)},120);
  promise.then(function(d){
    clearTimeout(skTimer);
    if(d&&d.locked){
      document.getElementById('fileList').innerHTML='<div class="lock-panel"><p class="empty">🔒 '+t('locked')+'</p><form id="lockForm" class="lock-form"><input type="password" id="lockPw" placeholder="'+t('enterPw')+'" autocomplete="off" /><button type="submit" class="btn">'+(lang==='zh'?'解锁':'Unlock')+'</button></form></div>';
      var lf=document.getElementById('lockForm');
      if(lf)lf.onsubmit=function(ev){ev.preventDefault();var pw=document.getElementById('lockPw').value;if(!pw)return;api('/api/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:d.path,password:pw})}).then(function(r){if(r&&r.ok){load()}else{alert(t('wrongPw'))}});};
      var lpw=document.getElementById('lockPw');if(lpw)lpw.focus();
      return;
    }
    var items=sortItems((d.items||[]).filter(matchFilter).slice());
    var truncated=false;
    if(!searchMode&&!favMode&&!recentMode&&!tagFilterMode&&!QUERY.on&&items.length>500){items=items.slice(0,500);truncated=true;}
    currentItems=items;
    var container=document.getElementById('fileList');
    if(!items.length){container.innerHTML='<p class="empty">'+(searchMode||favMode||recentMode||QUERY.on?t('noResult'):((filterType||filterAge)?(lang==='zh'?'没有符合条件的文件':'No matching files'):t('empty')))+'</p>';return}
    var truncTip=truncated?('<p class="list-tip">'+(lang==='zh'?'目录较大，仅显示前 500 项，请使用搜索或筛选定位':'Directory truncated to 500 items, use search/filter to locate')+'</p>'):'';
    var html='';
    if(viewMode==='gallery'){
      var media=items.filter(function(it){return it.type==='file'&&((it.mime||'').indexOf('image/')===0||(it.mime||'').indexOf('video/')===0)});
      if(!media.length){container.innerHTML='<p class="empty">'+(lang==='zh'?'此目录没有图片或视频':'No images or videos here')+'</p>';return}
      html='<div class="file-grid gallery">';
      media.forEach(function(it){
        var p=it.path||cur;
        var gsrc=(it.hasThumb?'/api/thumb?path=':'/api/preview?path=')+encodeURIComponent(p+it.name)+'&token='+tk;
        var isV=(it.mime||'').indexOf('video/')===0;
        html+='<div class="gitem" data-p="'+esc(p)+'" data-n="'+esc(it.name)+'" data-t="file" data-m="'+esc(it.mime||'')+'">';
        // 视频没有缩略图时按 <video> 渲染，避免全部显示成破图
        html+= isV ? ('<video class="gthumb" muted preload="metadata" src="'+gsrc+'"></video>') : ('<img class="gthumb" loading="lazy" src="'+gsrc+'" alt="">');
        html+='<div class="gname">'+esc(it.name)+'</div>';
        html+='<div class="gmeta"><span>'+fmt(it.size)+'</span><span>'+esc(it.time?new Date(it.time).toLocaleDateString():'')+'</span></div></div>';
      });
      html+='</div>'+truncTip;
    }else if(viewMode==='grid'){
      html='<div class="file-grid">';
      items.forEach(function(it){
        var p=it.path||cur;
        html+='<div class="gitem" data-p="'+esc(p)+'" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">';
        html+='<input type="checkbox" data-chk="'+esc(p+it.name)+'" />';
        if(it.type==='file'&&it.hasThumb){
          html+='<img class="gthumb" src="/api/thumb?path='+encodeURIComponent(p+it.name)+'&token='+tk+'" loading="lazy" />';
        }else if(it.type==='file'&&(it.mime||'').indexOf('video/')===0){
          html+='<div class="gicon">'+getIcon(it)+'</div>';
        }else if(it.type==='file'&&isImage(it)){
          html+='<img class="gthumb" src="/api/preview?path='+encodeURIComponent(p+it.name)+'&token='+tk+'" loading="lazy" />';
        }else{
          html+='<div class="gicon">'+getIcon(it)+'</div>';
        }
        html+='<div class="gname">'+esc(it.name)+'</div>';
        var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
        var gdt=it.time?new Date(it.time).toLocaleDateString():'';
        html+='<div class="gmeta"><span>'+sz+'</span><span>'+esc(gdt)+'</span></div></div>';
      });
      html+='</div>'+truncTip;
    }else if(viewMode==='columns'){
      html+='<div style="overflow:auto;max-height:calc(100vh - 340px)"><table class="col-table"><thead><tr>';
      var COLS=[['name',lang==='zh'?'名称':'Name'],['type',lang==='zh'?'类型':'Type'],['size',lang==='zh'?'大小':'Size'],['time',lang==='zh'?'修改时间':'Modified'],['path',lang==='zh'?'路径':'Path']];
      COLS.forEach(function(c){
        html+='<th data-cs="'+c[0]+'">'+c[1]+(sortKey===c[0]?(sortAsc?' ▲':' ▼'):'')+'</th>';
      });
      html+='<th></th></tr></thead><tbody>';
      items.forEach(function(it){
        var p=it.path||cur, full=p+it.name;
        var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
        html+='<tr data-p="'+esc(p)+'" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">';
        html+='<td><span style="cursor:pointer" class="cfname">'+getIcon(it)+' '+esc(it.name)+'</span></td>';
        html+='<td>'+(it.type==='dir'?(lang==='zh'?'文件夹':'Folder'):esc((it.mime||'').split(';')[0]||'-'))+'</td>';
        html+='<td>'+sz+'</td><td>'+(it.time?esc(new Date(it.time).toLocaleString()):'-')+'</td><td class="dup-path">'+esc(p)+'</td>';
        html+='<td><input type="checkbox" data-chk="'+esc(full)+'"'+(selected[full]?' checked':'')+'></td></tr>';
      });
      html+='</tbody></table></div>'+truncTip;
    }else{
      var head='<div class="list-head"><span></span><span></span><span>'+(lang==='zh'?'名称':'Name')+'</span><span></span><span class="lh-r">'+(lang==='zh'?'大小':'Size')+'</span><span class="lh-r">'+(lang==='zh'?'日期':'Date')+'</span><span></span></div>';
      if(items.length>150&&!truncated){
        // 大目录：虚拟滚动（只渲染可视窗口）
        if(VIRT.dir!==cur){VIRT.dir=cur;VIRT.scroll=0}
        container.innerHTML=head+'<div id="vhost"></div>';
        var host=document.getElementById('vhost');
        renderVirtualList(host,items,function(it){return listRowHtml(it)},function(){bindEvents(container)});
        return;
      }
      html=head+'<ul class="file-list">';
      items.forEach(function(it){ html+=listRowHtml(it) });
      if(truncated)html+='<li class="list-tip">'+(lang==='zh'?'目录较大，仅显示前 500 项，请使用搜索或筛选定位':'Directory truncated to 500 items, use search/filter to locate')+'</li>';
      html+='</ul>';
    }
    container.innerHTML=html;bindEvents(container);
    try{bindGestures(container)}catch(e){}
  });
}
// 列表行标记（普通列表与虚拟滚动共用）
function listRowHtml(it){
  var p=it.path||cur;
  var full=p+it.name;
  var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
  var dt=it.time?new Date(it.time).toLocaleDateString():'';
  var h='<li data-p="'+esc(p)+'" data-li="'+esc(it.name)+'" draggable="true" data-drag="'+esc(full)+'"><input type="checkbox" data-chk="'+esc(full)+'"'+(selected[full]?' checked':'')+' /><span class="file-icon">'+getIcon(it)+'</span>';
  h+='<span class="fname" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">'+esc(it.name);
  if((searchMode||favMode||recentMode||tagFilterMode)&&it.path)h+='<span class="fpath">'+esc(it.path)+'</span>';
  h+='</span>';
  h+='<button class="fav-star" data-fav="'+esc(it.name)+'">☆</button>';
  h+='<span class="fsize">'+sz+'</span><span class="fdate">'+dt+'</span>';
  h+='<span class="row-actions">';
  // 常显的三个主操作（不依赖悬停，触屏可用）
  if(it.type==='file')h+='<button class="btn gray tiny alw" data-dlrow="'+esc(it.name)+'" title="'+(lang==='zh'?'下载':'Download')+'">⬇</button>';
  if(it.type==='file')h+='<button class="btn gray tiny alw" data-shr="'+esc(it.name)+'" title="'+t('share')+'">🔗</button>';
  else h+='<button class="btn gray tiny alw" data-shrd="'+esc(it.name)+'" title="'+t('share')+'">🔗</button>';
  h+='<button class="btn tiny danger alw" data-del="'+esc(it.name)+'" title="'+t('del')+'">🗑</button>';
  // 长尾进 ⋯ 菜单
  h+='<span class="row-more-wrap"><button class="btn gray tiny row-more" data-rm="'+esc(it.name)+'" title="'+(lang==='zh'?'更多操作':'More')+'">⋯</button><span class="row-menu">';
  h+='<button data-ren="'+esc(it.name)+'" class="btn gray tiny">✏️ '+t('ren')+'</button>';
  h+='<button data-mv="'+esc(it.name)+'" class="btn gray tiny">📁 '+t('move')+'</button>';
  if(it.type==='file')h+='<button data-cp="'+esc(it.name)+'" class="btn gray tiny">📄 '+(lang==='zh'?'复制到…':'Copy to…')+'</button>';
  if(it.type==='file')h+='<button data-his="'+esc(it.name)+'" class="btn gray tiny">🕐 '+t('history')+'</button>';
  if(it.type==='file'&&isText(it))h+='<button data-ed="'+esc(it.name)+'" class="btn gray tiny">📝 '+t('edit')+'</button>';
  if(it.type==='file'&&isZip(it.name))h+='<button data-unz="'+esc(it.name)+'" class="btn gray tiny">📦 '+t('unzip')+'</button>';
  if(it.type==='file')h+='<button data-tag="'+esc(it.name)+'" class="btn gray tiny">🏷 '+(lang==='zh'?'标签':'Tag')+'</button>';
  if(it.type==='file')h+='<button data-nt="'+esc(it.name)+'" class="btn gray tiny">📝 '+(lang==='zh'?'备注':'Note')+'</button>';
  h+='<button data-lockrow="'+esc(it.name)+'" class="btn gray tiny">🔒 '+(lang==='zh'?'目录密码':'Folder lock')+'</button>';
  if(it.type==='file')h+='<button data-enc="'+esc(it.name)+'" class="btn gray tiny">🔐 '+(lang==='zh'?'加密':'Encrypt')+'</button>';
  h+='</span></span>';
  h+='</span></li>';
  return h;
}


// ===== Tag sidebar =====
var tagFilterMode=false,tagFilterName='';
var currentTags=[];
// ===== 高级筛选器（/api/query）=====
var QUERY={on:false,params:{},items:[],total:0,offset:0,hasMore:false};
var qDefaults=function(){return {q:'',type:'',ext:'',minMB:'',maxMB:'',after:'',before:'',tags:'',tagMode:'any',fav:false,deep:true,sort:'name',order:'asc'}};
function queryModal(){
  var m=document.getElementById('queryModal');
  if(!m){
    m=document.createElement('div');m.id='queryModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:440px;max-width:700px"><button class="mclose" id="queryClose">✕</button><h3>🔎 '+(lang==='zh'?'高级筛选':'Advanced filter')+'</h3><div id="queryContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('queryClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showQuery(){
  var m=queryModal(),box=document.getElementById('queryContent');
  var p=Object.assign(qDefaults(),QUERY.params);
  var tags=currentTags||[];
  var h='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'文件名包含':'Name contains')+'</span><input id="qQ" value="'+esc(p.q)+'" style="flex:1;padding:6px 10px"></div>';
  var TYPES=[['','全部'],['image','图片'],['video','视频'],['audio','音频'],['doc','文档'],['zip','压缩包'],['other','其他']];
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'类型':'Type')+'</span><select id="qType" style="flex:1;padding:6px 10px">'+TYPES.map(function(x){return '<option value="'+x[0]+'"'+(p.type===x[0]?' selected':'')+'>'+x[1]+'</option>'}).join('')+'</select></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'扩展名（逗号分隔）':'Extensions')+'</span><input id="qExt" value="'+esc(p.ext)+'" placeholder=".jpg,.png" style="flex:1;padding:6px 10px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'大小范围 (MB)':'Size (MB)')+'</span><input id="qMin" type="number" value="'+esc(p.minMB)+'" placeholder="min" style="width:90px;padding:6px 10px"><span>–</span><input id="qMax" type="number" value="'+esc(p.maxMB)+'" placeholder="max" style="width:90px;padding:6px 10px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'修改时间':'Modified')+'</span><input id="qAfter" type="date" value="'+esc(p.after)+'" style="flex:1;padding:5px 8px"><span>–</span><input id="qBefore" type="date" value="'+esc(p.before)+'" style="flex:1;padding:5px 8px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'标签（逗号分隔）':'Tags')+'</span><input id="qTags" value="'+esc(p.tags)+'" list="qTagList" style="flex:1;padding:6px 10px"><datalist id="qTagList">'+tags.map(function(x){return '<option value="'+esc(x.name)+'">'}).join('')+'</datalist>'
    +'<select id="qTagMode" style="padding:6px 8px"><option value="any"'+(p.tagMode==='any'?' selected':'')+'>'+(lang==='zh'?'任一':'any')+'</option><option value="all"'+(p.tagMode==='all'?' selected':'')+'>'+(lang==='zh'?'全部':'all')+'</option></select></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 40%">'+(lang==='zh'?'范围 / 排序':'Scope / sort')+'</span>'
    +'<label style="display:flex;gap:4px;align-items:center;font-size:12.5px"><input type="checkbox" id="qDeep" '+(p.deep?'checked':'')+'>'+(lang==='zh'?'含子目录':'recursive')+'</label>'
    +'<label style="display:flex;gap:4px;align-items:center;font-size:12.5px"><input type="checkbox" id="qFav" '+(p.fav?'checked':'')+'>★</label>'
    +'<select id="qSort" style="padding:6px 8px">'+[['name','名称'],['size','大小'],['time','时间']].map(function(x){return '<option value="'+x[0]+'"'+(p.sort===x[0]?' selected':'')+'>'+x[1]+'</option>'}).join('')+'</select>'
    +'<select id="qOrder" style="padding:6px 8px"><option value="asc"'+(p.order==='asc'?' selected':'')+'>↑</option><option value="desc"'+(p.order==='desc'?' selected':'')+'>↓</option></select></div>';
  h+='<div id="qMsg" style="font-size:13px;min-height:18px"></div>';
  h+='<div style="text-align:right;display:flex;gap:8px;justify-content:flex-end"><button id="qClear" class="btn gray small">'+(lang==='zh'?'清空':'Clear')+'</button><button id="qSave" class="btn gray small">'+(lang==='zh'?'保存为预设':'Save preset')+'</button><button id="qRun" class="btn small">'+(lang==='zh'?'筛选':'Filter')+'</button></div>';
  box.innerHTML=h;
  m.classList.add('show');
  document.getElementById('qClear').onclick=function(){QUERY.params=qDefaults();showQuery()};
  document.getElementById('qSave').onclick=function(){
    try{localStorage.setItem('dQuery',JSON.stringify(readQueryForm()))}catch(e){}
    var msg=document.getElementById('qMsg');msg.style.color='var(--sys-green)';msg.textContent=(lang==='zh'?'已保存为默认预设':'Preset saved');
  };
  document.getElementById('qRun').onclick=function(){runQuery(readQueryForm())};
}
function readQueryForm(){
  function v(id){var el=document.getElementById(id);return el?el.value:''}
  function c(id){var el=document.getElementById(id);return !!(el&&el.checked)}
  return {q:v('qQ'),type:v('qType'),ext:v('qExt'),minMB:v('qMin'),maxMB:v('qMax'),after:v('qAfter'),before:v('qBefore'),tags:v('qTags'),tagMode:v('qTagMode'),fav:c('qFav'),deep:c('qDeep'),sort:v('qSort'),order:v('qOrder')};
}
function queryQS(p,offset){
  var qs=[];
  if(p.q)qs.push('q='+encodeURIComponent(p.q));
  if(p.type)qs.push('type='+encodeURIComponent(p.type));
  if(p.ext)qs.push('ext='+encodeURIComponent(p.ext));
  if(p.minMB)qs.push('minSize='+Math.round(parseFloat(p.minMB)*1048576));
  if(p.maxMB)qs.push('maxSize='+Math.round(parseFloat(p.maxMB)*1048576));
  if(p.after)qs.push('after='+encodeURIComponent(p.after));
  if(p.before)qs.push('before='+encodeURIComponent(new Date(new Date(p.before).getTime()+86399999).toISOString()));
  if(p.tags)qs.push('tags='+encodeURIComponent(p.tags)+'&tagMode='+encodeURIComponent(p.tagMode));
  if(p.fav)qs.push('fav=1');
  qs.push('deep='+(p.deep?'1':'0'));
  qs.push('sort='+encodeURIComponent(p.sort)+'&order='+encodeURIComponent(p.order));
  qs.push('path='+encodeURIComponent(queryScope));
  qs.push('limit=200&offset='+(offset||0));
  return '/api/query?'+qs.join('&');
}
var queryScope='/';
function runQuery(p,append){
  QUERY.params=p;QUERY.on=true;QUERY.offset=append?QUERY.items.length:0;
  searchMode=false;favMode=false;recentMode=false;tagFilterMode=false;
  api(queryQS(p,QUERY.offset)).then(function(d){
    var items=d.items||[];
    QUERY.items=append?QUERY.items.concat(items):items;
    QUERY.total=d.total||0;QUERY.hasMore=!!d.hasMore;
    currentItems=QUERY.items;
    var m=queryModal();
    var msg=document.getElementById('qMsg');
    if(msg){msg.style.color='var(--sys-text-3)';msg.textContent=(lang==='zh'?'命中 ':'hits ')+QUERY.total+(d.capped?(' ('+(lang==='zh'?'结果已截断':'capped')+')'):'')}
    m.classList.remove('show');
    render();loadUsage();
  }).catch(function(){});
}

function renderTagSidebar(){
  api('/api/tags').then(function(d){
    var tags=d.tags||[];
    currentTags=tags;
    var box=document.getElementById('tagBox');
    if(!tags.length){box.innerHTML='<div style="color:var(--sys-text-3);font-size:12px;padding:8px 10px">'+t('noTags')+'</div>';return}
    var h='';
    tags.slice(0,60).forEach(function(tg){
      var isActive=tagFilterMode&&tagFilterName===tg.name;
      h+='<div class="tag-filter-item'+(isActive?' active':'')+'" data-tf="'+esc(tg.name)+'" title="'+(lang==='zh'?'点击筛选 · 右键管理':'click to filter · right-click to manage')+'"><span class="tag-dot" style="background:'+safeColor(tg.color)+'"></span>'+esc(tg.name)+(tg.count?(' <span style="color:var(--sys-text-3);font-size:11px">'+tg.count+'</span>'):'')+'</div>';
    });
    h+='<div style="display:flex;gap:6px;margin-top:8px"><button class="btn gray tiny" id="tagManage" style="flex:1">'+(lang==='zh'?'管理标签':'Manage')+'</button><button class="btn tiny" id="tagAuto" style="flex:1">'+(lang==='zh'?'自动标签':'Auto tag')+'</button></div>';
    box.innerHTML=h;
    box.querySelectorAll('[data-tf]').forEach(function(el){
      el.onclick=function(){
        var n=el.getAttribute('data-tf');
        if(tagFilterMode&&tagFilterName===n){tagFilterMode=false;tagFilterName='';favMode=false;recentMode=false;searchMode=false;QUERY.on=false;load()}
        else{tagFilterMode=true;tagFilterName=n;favMode=false;recentMode=false;searchMode=false;QUERY.on=false;load()}
      };
      el.oncontextmenu=function(e){e.preventDefault();showTagManage(el.getAttribute('data-tf'))};
    });
    var mg=document.getElementById('tagManage');
    if(mg)mg.onclick=function(){showTagManage('')};
    var au=document.getElementById('tagAuto');
    if(au)au.onclick=function(){showTagAuto()};
  }).catch(function(){});
}
// 标签管理：改色 / 重命名合并
function showTagManage(focus){
  var m=queryModal(),box=document.getElementById('queryContent');
  m.classList.add('show');
  var h='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'重命名会把所有文件上的该标签一并改写（合并到同名标签）。':'Rename merges into an existing tag of the same name.')+'</div>';
  h+='<div id="tagRows"></div>';
  box.innerHTML=h;
  function paint(){
    api('/api/tags').then(function(d){
      var tags=d.tags||[];
      var rows=document.getElementById('tagRows');
      var html='';
      if(!tags.length)html='<div class="dup-path">'+(lang==='zh'?'暂无标签':'No tags')+'</div>';
      tags.forEach(function(tg){
        html+='<div class="token-row"><span class="tag-dot" style="background:'+safeColor(tg.color)+'"></span>'
          +'<input value="'+esc(tg.name)+'" data-tgnm="'+esc(tg.name)+'" style="width:150px;padding:5px 8px">'
          +'<input type="color" value="'+safeColor(tg.color)+'" data-tgcl="'+esc(tg.name)+'" style="width:38px;height:30px;padding:0;border:none;background:none">'
          +'<span class="dup-path" style="flex:1">'+(tg.count||0)+'</span>'
          +'<button class="btn gray tiny" data-tgsave="'+esc(tg.name)+'">'+(lang==='zh'?'保存':'Save')+'</button></div>';
      });
      rows.innerHTML=html;
      rows.querySelectorAll('[data-tgcl]').forEach(function(el){el.onchange=function(){
        api('/api/tags/color',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:el.getAttribute('data-tgcl'),color:el.value})}).then(function(){renderTagSidebar()});
      }});
      rows.querySelectorAll('[data-tgsave]').forEach(function(el){el.onclick=function(){
        var from=el.getAttribute('data-tgsave');
        var inp=rows.querySelector('[data-tgnm="'+from.replace(/"/g,'\\"')+'"]');
        var to=inp?inp.value.trim():'';
        var cl=rows.querySelector('[data-tgcl="'+from.replace(/"/g,'\\"')+'"]');
        if(!to||to===from)return;
        api('/api/tags/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({from:from,to:to,color:cl?cl.value:''})}).then(function(r){
          if(r&&r.ok){renderTagSidebar();paint();load()}else alert((r&&r.error)||'failed');
        });
      }});
    });
  }
  paint();
}
function showTagAuto(){
  var m=queryModal(),box=document.getElementById('queryContent');
  m.classList.add('show');
  box.innerHTML='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'为当前目录的文件自动打标签（按类型或按年月）':'Auto-tag files in the current folder')+'</div>'
    +'<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px"><select id="taMode" style="padding:6px 8px"><option value="type">'+(lang==='zh'?'按类型':'By type')+'</option><option value="date">'+(lang==='zh'?'按年月':'By date')+'</option></select>'
    +'<label style="display:flex;gap:4px;align-items:center;font-size:12.5px"><input type="checkbox" id="taDeep">'+(lang==='zh'?'含子目录':'recursive')+'</label>'
    +'<button id="taPreview" class="btn gray small">'+(lang==='zh'?'预览':'Preview')+'</button><button id="taApply" class="btn small">'+(lang==='zh'?'应用':'Apply')+'</button></div>'
    +'<div id="taOut" style="max-height:44vh;overflow:auto;font-size:13px"></div>';
  function run(apply){
    var out=document.getElementById('taOut');
    out.innerHTML='…';
    api('/api/tags/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur,mode:document.getElementById('taMode').value,deep:document.getElementById('taDeep').checked,apply:apply})}).then(function(d){
      var g=d.groups||[];
      var h='<div class="dup-path" style="margin-bottom:6px">'+(lang==='zh'?'共 ':'total ')+d.total+' · '+(apply?((lang==='zh'?'已改 ':'changed ')+d.changed):(lang==='zh'?'预览':'preview'))+'</div>';
      g.forEach(function(x){h+='<div class="token-row"><span class="token-name">'+esc(x.tag)+'</span><span class="dup-path" style="flex:1">'+x.count+' · '+x.sample.map(esc).join(', ')+'</span></div>'});
      out.innerHTML=h;
      if(apply)renderTagSidebar();
    });
  }
  document.getElementById('taPreview').onclick=function(){run(false)};
  document.getElementById('taApply').onclick=function(){if(confirm(lang==='zh'?'确认写入标签？':'Apply tags?'))run(true)};
  run(false);
}


// ===== Tree drag-drop =====
function initTreeDnD(){
  var treeItems=document.querySelectorAll('.tree-item');
  treeItems.forEach(function(el){
    el.addEventListener('dragover',function(e){e.preventDefault();el.style.background='var(--sys-blue-soft)'});
    el.addEventListener('dragleave',function(){el.style.background=''});
    el.addEventListener('drop',function(e){
      e.preventDefault();el.style.background='';
      var targetPath=el.getAttribute('data-tp');
      var dragName=e.dataTransfer.getData('text/plain');
      if(!dragName||!targetPath)return;
      api('/api/move',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:dragName,target:targetPath})}).then(function(){load()}).catch(function(){});
    });
  });
}

var treeState={};
function renderTree(){
  treeState['/']=true;
  var parts=cur.split('/').filter(Boolean);var acc='/';
  for(var i=0;i<parts.length;i++){acc+=parts[i]+'/';treeState[acc]=true;}
  var box=document.getElementById('treeBox');
  if(document.getElementById('btnSidebar').offsetParent===null&&window.innerWidth<=820&&!document.getElementById('sidebar').classList.contains('show'))return;
  api('/api/tree').then(function(d){
    if(!d.tree)return;
    var html='';
    function walk(node,isRoot){
      var isOpen=treeState[node.path]!==false;
      var hasKids=node.children&&node.children.length;
      html+='<div class="tree-item'+(isOpen?' open':'')+(cur===node.path?' active':'')+'" data-tp="'+esc(node.path)+'">';
      html+=hasKids?'<span class="tw">'+(isOpen?'▼':'▶')+'</span>':'<span class="tw"></span>';
      html+=isRoot?'<span>🏠</span>':'<span>📁</span>';
      html+='<span style="overflow:hidden;text-overflow:ellipsis">'+esc(isRoot?t('home'):node.name)+'</span></div>';
      if(hasKids){
        html+='<div class="tree-children'+(isOpen?'':' hidden')+'">';
        node.children.forEach(function(c){walk(c,false)});
        html+='</div>';
      }
    }
    walk(d.tree,true);
    box.innerHTML=html;
    initTreeDnD();
    box.querySelectorAll('.tree-item').forEach(function(el){
      el.onclick=function(e){
        var tp=el.getAttribute('data-tp');
        var tw=el.querySelector('.tw');
        if(tw&&e.target===tw&&tw.textContent!==''){
          treeState[tp]=(treeState[tp]===false)?true:false;
          renderTree();
          return;
        }
        cur=tp;setMode('');load();
      };
    });
  }).catch(function(){});
}
document.getElementById('btnSidebar').onclick=function(){document.getElementById('sidebar').classList.toggle('show')};

// 行内操作一律使用该条目自己的目录（搜索/收藏/最近/标签结果可能来自其它目录），
// 否则会把 cur+name 当成目标路径，导致 404 或误删当前目录的同名文件。
function rowDir(el){var r=(el&&el.closest)?el.closest('[data-p]'):null;return (r&&r.getAttribute('data-p'))||cur}
function enterDir(p,name){cur=normP(p)+name+'/';setMode('');load()}
function setMode(m){
  searchMode=(m==='search');favMode=(m==='fav');recentMode=(m==='recent');tagFilterMode=(m==='tag');
  if(m!=='tag')tagFilterName='';
}
function bindEvents(c){
  c.querySelectorAll('[data-cs]').forEach(function(th){th.onclick=function(){
    var k=th.getAttribute('data-cs');
    if(k==='type'||k==='path')k='name';
    if(sortKey===k)sortAsc=!sortAsc;else{sortKey=k;sortAsc=true}
    try{localStorage.setItem('ds',sortKey)}catch(e){}
    render();
  }});
  c.querySelectorAll('.cfname').forEach(function(el){
    var tr=el.closest('tr');if(!tr)return;
    el.onclick=function(){
      var n=tr.getAttribute('data-n'),tp=tr.getAttribute('data-t'),m=tr.getAttribute('data-m')||'',p=tr.getAttribute('data-p')||cur;
      if(tp==='dir')enterDir(p,n);else doPreview(n,m,-1,p);
    };
  });
  c.querySelectorAll('[data-drag]').forEach(function(el){el.addEventListener('dragstart',function(e){e.dataTransfer.setData('text/plain',el.getAttribute('data-drag'))})});
  c.querySelectorAll('[data-chk]').forEach(function(cb){cb.onchange=function(){var n=cb.getAttribute('data-chk');if(cb.checked)selected[n]=true;else delete selected[n];updateBatch();var li=cb.closest('li')||cb.closest('.gitem');if(li)li.classList.toggle('selected',cb.checked)}});
  c.querySelectorAll('.fname').forEach(function(el){el.onclick=function(){
    var n=el.getAttribute('data-n'),tp=el.getAttribute('data-t'),m=el.getAttribute('data-m')||'',p=rowDir(el);
    if(selMode){var cb=el.closest('li');cb=cb?cb.querySelector('[data-chk]'):null;if(cb){cb.checked=!cb.checked;cb.onchange&&cb.onchange()}return}
    if(tp==='dir'){enterDir(p,n)}else{doPreview(n,m,-1,p)}
  }});
  c.querySelectorAll('.file-list li').forEach(function(li){
    li.oncontextmenu=function(e){e.preventDefault();showCtx(e.clientX,e.clientY,li.getAttribute('data-li'),li.querySelector('.fname')?li.querySelector('.fname').getAttribute('data-t'):'file',li.querySelector('.fname')?li.querySelector('.fname').getAttribute('data-m')||'':'',li.getAttribute('data-p')||cur)};
  });
  c.querySelectorAll('.gitem').forEach(function(el){el.onclick=function(e){if(e.target.type==='checkbox')return;var n=el.getAttribute('data-n'),tp=el.getAttribute('data-t'),m=el.getAttribute('data-m')||'',p=rowDir(el);if(tp==='dir'){enterDir(p,n)}else doPreview(n,m,-1,p)};el.oncontextmenu=function(e){e.preventDefault();showCtx(e.clientX,e.clientY,el.getAttribute('data-n'),el.getAttribute('data-t'),el.getAttribute('data-m')||'',rowDir(el))}});
  c.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){if(!confirm(t('delete')))return;api('/api/delete?path='+encodeURIComponent(rowDir(b)+b.getAttribute('data-del')),{method:'DELETE'}).then(load)}});
  c.querySelectorAll('[data-ren]').forEach(function(b){b.onclick=function(){var o=b.getAttribute('data-ren');var n=prompt(t('rename'),o);if(!n||n===o)return;api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:rowDir(b)+o,newName:n})}).then(load)}});
  c.querySelectorAll('[data-shr]').forEach(function(b){b.onclick=function(){doShare(b.getAttribute('data-shr'),rowDir(b))}});
  c.querySelectorAll('[data-shrd]').forEach(function(b){b.onclick=function(){doShareDir(rowDir(b)+b.getAttribute('data-shrd')+'/')}});
  c.querySelectorAll('[data-mv]').forEach(function(b){b.onclick=function(){showMove(b.getAttribute('data-mv'),rowDir(b))}});
  c.querySelectorAll('[data-ed]').forEach(function(b){b.onclick=function(){editText(b.getAttribute('data-ed'),rowDir(b))}});
  c.querySelectorAll('[data-unz]').forEach(function(b){b.onclick=function(){doUnzip(b.getAttribute('data-unz'),rowDir(b))}});
  c.querySelectorAll('[data-his]').forEach(function(b){b.onclick=function(){showVersions(b.getAttribute('data-his'),rowDir(b))}});
  c.querySelectorAll('[data-tag]').forEach(function(b){b.onclick=function(){doTagFile(b.getAttribute('data-tag'),rowDir(b))}});
  c.querySelectorAll('[data-nt]').forEach(function(b){b.onclick=function(){showNote(b.getAttribute('data-nt'),rowDir(b))}});
  c.querySelectorAll('[data-fav]').forEach(function(b){b.onclick=function(){var n=b.getAttribute('data-fav');api('/api/fav',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:rowDir(b)+n})}).then(function(){b.classList.toggle('on')})}});
  // 常显主操作：下载
  c.querySelectorAll('[data-dlrow]').forEach(function(b){b.onclick=function(e){
    if(e&&e.stopPropagation)e.stopPropagation();
    var p=rowDir(b)+b.getAttribute('data-dlrow');
    window.open('/api/download?path='+encodeURIComponent(p)+'&token='+tk,'_blank');
  }});
  // 行内 ⋯ 菜单
  c.querySelectorAll('[data-rm]').forEach(function(b){b.onclick=function(e){
    e.stopPropagation();
    var wrap=b.closest('.row-more-wrap');
    var menu=wrap?wrap.querySelector('.row-menu'):null;
    if(!menu)return;
    var open=menu.classList.contains('show');
    c.querySelectorAll('.row-menu.show').forEach(function(m){m.classList.remove('show')});
    menu.classList.toggle('show',!open);
  }});
  // 行内长尾：复制到 / 目录密码 / 加密
  c.querySelectorAll('[data-cp]').forEach(function(b){b.onclick=function(){showMove(b.getAttribute('data-cp'),rowDir(b))}});
  c.querySelectorAll('[data-lockrow]').forEach(function(b){b.onclick=function(){
    var dir=rowDir(b);
    var pw=prompt(lang==='zh'?'为该目录设置密码（留空清除）：':'Folder password (empty to clear):','');
    if(pw===null)return;
    api('/api/folder-pass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:dir,password:pw})}).then(function(){load()});
  }});
  c.querySelectorAll('[data-enc]').forEach(function(b){b.onclick=function(){
    var n=b.getAttribute('data-enc');
    try{showEncryptPrompt(n,rowDir(b))}catch(e){}
  }});
}

function updateBatch(){var keys=Object.keys(selected);var bar=document.getElementById('batchBar');if(keys.length){bar.classList.add('show');document.getElementById('batchCount').textContent=keys.length+' selected'}else bar.classList.remove('show')}

// ===== 站内复制 / 剪切 / 粘贴 =====
function clipGet(){try{var c=JSON.parse(localStorage.getItem('du_clip')||'null');return (c&&c.paths&&c.paths.length)?c:null}catch(e){return null}}
function clipSet(mode,paths){try{localStorage.setItem('du_clip',JSON.stringify({mode:mode,paths:paths||[]}))}catch(e){}renderClipBar()}
function clipClear(){try{localStorage.removeItem('du_clip')}catch(e){}renderClipBar()}
function clipFromSelection(mode){
  var keys=Object.keys(selected);
  if(!keys.length){alert(lang==='zh'?'请先选择文件':'Select files first');return}
  clipSet(mode,keys);
}
function renderClipBar(){
  var bar=document.getElementById('clipBar');if(!bar)return;
  var c=clipGet();
  if(!c){bar.innerHTML='';bar.style.display='none';return}
  bar.innerHTML='<span>'+(c.mode==='cut'?'✂ '+t('cut'):'📋 '+t('copy'))+' · '+c.paths.length+' '+(lang==='zh'?'项':'items')+'</span>'
    +'<span style="flex:1"></span>'
    +'<button id="clipPaste" class="btn small">'+t('pasteHere')+'</button>'
    +'<button id="clipCancel" class="btn gray small">'+t('cancel')+'</button>';
  bar.style.display='flex';
  document.getElementById('clipPaste').onclick=function(){pasteHere(cur)};
  document.getElementById('clipCancel').onclick=clipClear;
}
async function pasteHere(target){
  var c=clipGet();
  if(!c){alert(t('clipEmpty'));return}
  target=target||cur;
  if(c.mode==='cut'){
    var r=await api('/api/batch-move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:c.paths,target:target})});
    if(r&&r.ok){clipClear();alert(t('pasteDone')+': '+(r.moved||0)+'/'+c.paths.length);load()}
    else alert((r&&r.error)||t('upFail'));
  }else{
    var r2=await api('/api/copy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:c.paths,target:target})});
    if(r2&&r2.ok){
      var msg=t('pasteDone')+': '+(r2.copied||0)+'/'+c.paths.length;
      if(r2.failed)msg+=(lang==='zh'?'（失败 ':' (failed ')+r2.failed+((lang==='zh'?'）':')'));
      alert(msg);load();
    }else alert((r2&&r2.error)||t('upFail'));
  }
}

// ===== Batch Rename =====
document.getElementById('batchRen').onclick=function(){
  var keys=Object.keys(selected);
  if(!keys.length)return;
  var box=document.getElementById('brContent');
  var h='<div style="margin-bottom:12px"><input id="brPattern" value="{n}_{d}" style="width:100%;padding:10px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px" placeholder="'+t('brPattern')+'"></div>';
  h+='<div class="br-preview" id="brPreview">';
  keys.forEach(function(k,i){
    var bn=k.split('/').filter(Boolean).pop()||k;
    var dot=bn.lastIndexOf('.');
    var ext=dot>=0?bn.substring(dot):'';
    var base=dot>=0?bn.substring(0,dot):bn;
    var newName=(i+1)+'_'+new Date().toISOString().substring(0,10)+ext;
    h+='<div class="br-row"><span class="br-old">'+esc(bn)+'</span><span>→</span><span class="br-new">'+esc(newName)+'</span></div>';
  });
  h+='</div><div style="margin-top:12px;text-align:right"><button id="brApply" class="btn small">Apply</button></div>';
  box.innerHTML=h;
  document.getElementById('brModal').classList.add('show');
  document.getElementById('brApply').onclick=function(){
    var pattern=document.getElementById('brPattern').value;
    var paths=keys.slice();
    api('/api/batch-rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:paths,pattern:pattern})}).then(function(r){
      document.getElementById('brModal').classList.remove('show');
      selected={};load();
    });
  };
};
document.getElementById('brClose').onclick=function(){document.getElementById('brModal').classList.remove('show')};
document.getElementById('brModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

document.getElementById('batchClr').onclick=function(){selected={};render()};
document.getElementById('batchCopy').onclick=function(){clipFromSelection('copy')};
document.getElementById('batchCut').onclick=function(){clipFromSelection('cut');render()};
document.getElementById('batchDel').onclick=function(){var keys=Object.keys(selected);if(!keys.length||!confirm('Delete '+keys.length+'?'))return;api('/api/batch-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys})}).then(function(){selected={};load()})};
document.getElementById('batchDl').onclick=function(){Object.keys(selected).forEach(function(n){window.open('/api/download?path='+encodeURIComponent(n)+'&token='+tk,'_blank')})};
document.getElementById('batchZip').onclick=function(){
  var keys=Object.keys(selected);if(!keys.length)return;
  fetch('/api/zip-multi?token='+tk,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys})})
    .then(function(r){if(!r.ok){return r.json().then(function(d){alert((d&&d.error)||'failed')})}return r.blob()})
    .then(function(b){if(!b)return;var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='files.zip';document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},1500)})
    .catch(function(){alert('failed')});
};
// ===== 目录分享 / 远程 URL 抓取 =====
function doShareDir(dirPath){
  dirPath=dirPath||cur;
  var days=prompt(t('days'),'7');if(!days)return;
  var mx=prompt(t('maxAcc'),'0');if(mx===null)return;
  var pw=prompt(t('sharePw'),'');if(pw===null)return;
  api('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:dirPath,dir:true,days:parseInt(days),max:parseInt(mx)||0,password:pw||''})}).then(function(r){
    if(r&&r.url){
      var u=location.origin+r.url;try{navigator.clipboard.writeText(u)}catch(e){}
      prompt(t('link'),u);
      if(r.token)showShareSettings(r.token,true);   // 创建后直接进设置面板（权限/外观/短链）
    }
    else if(r&&r.locked){alert(t('locked'))}
    else if(r&&r.error){alert(r.error)}
  });
}
document.getElementById('btnShareDir').onclick=function(){doShareDir(cur)};
document.getElementById('btnFetchUrl').onclick=function(){
  var url=prompt('远程文件 URL（http / https）','');if(!url)return;
  var nm=prompt('保存文件名（留空则自动识别）','')||'';
  var div=makeUpItem(nm||url.split('/').pop()||'url');
  div.querySelector('.upst').textContent='...';
  api('/api/fetch-url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url,name:nm,dir:cur})}).then(function(r){
    if(r&&r.ok){
      div.querySelector('.upfill').style.width='100%';
      div.querySelector('.upst').textContent=t('upDone');
      div.querySelector('.upst').style.color='var(--sys-green)';
      setTimeout(function(){if(div.parentNode)div.parentNode.removeChild(div)},1500);
      load();
    }else{
      div.querySelector('.upst').textContent=(r&&r.error)||t('upFail');
      div.querySelector('.upst').style.color='var(--sys-red)';
    }
  }).catch(function(){div.querySelector('.upst').textContent=t('upFail');div.querySelector('.upst').style.color='var(--sys-red)'});
};

document.querySelectorAll('.sort-btn').forEach(function(b){b.onclick=function(){var k=b.getAttribute('data-s');if(sortKey===k)sortAsc=!sortAsc;else{sortKey=k;sortAsc=true}localStorage.setItem('ds',sortKey);render()}});
document.getElementById('btnSearch').onclick=doSearch;
document.getElementById('searchInput').onkeydown=function(e){if(e.key==='Enter')doSearch()};
function doSearch(){var q=document.getElementById('searchInput').value.trim();if(!q){setMode('');load();return}api('/api/search?q='+encodeURIComponent(q)+'&path=/').then(function(d){setMode('search');searchResults=d.results||[];render()})}
document.getElementById('btnFav').onclick=function(){var on=!favMode;setMode(on?'fav':'');render()};
document.getElementById('btnRecent').onclick=function(){var on=!recentMode;setMode(on?'recent':'');render()};
document.getElementById('btnZip').onclick=function(){window.open('/api/zip?path='+encodeURIComponent(cur)+'&token='+tk,'_blank')};


// ===== QR Code for Share =====
function showQR(url){
  var box=document.getElementById('pvContent');
  if(!box)return;
  box.innerHTML='<div class="qr-box" id="qrBox"></div><div class="mtitle"><span>'+esc(url)+'</span></div>';
  var div=document.getElementById('qrBox');
  try{
    if(typeof QRCode!=='undefined'){
      new QRCode(div,{text:url,width:180,height:180,correctLevel:QRCode.CorrectLevel.M});
    }else{div.textContent='QR library not loaded'}
  }catch(e){div.textContent='QR generation failed'}
  document.getElementById('pvModal').classList.add('show');
  document.getElementById('pvPrev').classList.add('hidden');
  document.getElementById('pvNext').classList.add('hidden');
  document.getElementById('pvCounter').textContent='';
}

function doShare(name,base){
  base=base||cur;
  var days=prompt(t('days'),'7');if(!days)return;
  var mx=prompt(t('maxAcc'),'0');if(mx===null)return;
  var pw=prompt(t('sharePw'),'');
  if(pw===null)return;
  api('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:base+name,days:parseInt(days),max:parseInt(mx)||0,password:pw||''})}).then(function(r){
    if(r.url){
      var u=location.origin+r.url;
      prompt(t('link'),u);try{navigator.clipboard.writeText(u)}catch(e){};try{showQR(u)}catch(qe){}
      if(r.token)showShareSettings(r.token,true);
    }
    else if(r.locked){alert(t('locked'))}
    else if(r.error){alert(r.error)}
  });
}

function doUnzip(name,base){
  base=base||cur;
  if(!confirm(t('unzip')+' '+name+'?'))return;
  api('/api/unzip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:base+name})}).then(function(r){
    if(r.ok){alert(t('unzipDone')+': '+r.created+' files');load()}
    else{alert(r.error||t('upFail'))}
  });
}

function showVersions(name,base){
  base=base||cur;
  api('/api/versions?path='+encodeURIComponent(base+name)).then(function(d){
    var vers=d.versions||[];
    var box=document.getElementById('verContent');
    if(!vers.length){box.innerHTML='<p style="color:var(--sys-text-3);text-align:center;padding:24px">'+t('noVers')+'</p>';document.getElementById('verModal').classList.add('show');return}
    var h='';
    vers.forEach(function(v){
      var dt=new Date(v.ts).toLocaleString();
      h+='<div class="ver-row"><span class="vtime">'+esc(dt)+'</span><span class="vsize">'+fmt(v.size)+'</span><button data-ver="'+v.ts+'" class="btn gray tiny">'+t('restoreV')+'</button></div>';
    });
    box.innerHTML=h;
    document.getElementById('verTitle').textContent=t('history')+' · '+name;
    document.getElementById('verModal').classList.add('show');
    box.querySelectorAll('[data-ver]').forEach(function(b){
      b.onclick=function(){
        if(!confirm(t('confirmRestore')))return;
        api('/api/versions/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:base+name,ts:parseInt(b.getAttribute('data-ver'))})}).then(function(r){
          document.getElementById('verModal').classList.remove('show');
          if(r.ok){alert(t('saved'));load()}else{alert(r.error||t('upFail'))}
        });
      };
    });
  });
}
document.getElementById('verClose').onclick=function(){document.getElementById('verModal').classList.remove('show')};
document.getElementById('verModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

document.getElementById('btnULink').onclick=function(){
  var days=prompt(t('days'),'7');if(!days)return;
  var max=prompt(t('maxUp'),'0');
  api('/api/upload-link-create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur,days:parseInt(days),max:parseInt(max)||0})}).then(function(r){
    if(r.url){var u=location.origin+r.url;prompt(t('link'),u);try{navigator.clipboard.writeText(u)}catch(e){}}
  });
};
document.getElementById('btnLock').onclick=function(){
  var pw=prompt(t('setPw'),'');
  if(pw===null)return;
  api('/api/folder-pass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur,password:pw})}).then(function(){alert(pw?t('pwSet'):t('pwRm'))});
};
document.getElementById('btnLang').onclick=function(){lang=lang==='zh'?'en':'zh';localStorage.setItem('dl',lang);render()};
document.getElementById('btnView').onclick=function(){cycleView()};
document.querySelectorAll('.fchip').forEach(function(b){
  b.onclick=function(){
    if(b.hasAttribute('data-ft'))filterType=b.getAttribute('data-ft');
    else filterAge=b.getAttribute('data-fa');
    render();
  };
});


// ===== PDF Preview =====
function isPDF(name){return(name||'').toLowerCase().endsWith('.pdf')}
function previewPDF(src,name){
  var box=document.getElementById('pvContent');
  box.innerHTML='<div class="pdf-status" id="pdfStatus">Loading PDF...</div>';
  import('https://cdn.jsdelivr.net/npm/pdfjs-dist@4.4.168/build/pdf.min.mjs').then(function(pdfjsLib){
    pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdn.jsdelivr.net/npm/pdfjs-dist@4.4.168/build/pdf.worker.min.mjs';
    return pdfjsLib.getDocument(src).promise;
  }).then(function(pdf){
    var container=document.createElement('div');container.className='pdf-pages';
    var promises=[];
    for(var i=1;i<=Math.min(pdf.numPages,50);i++){
      (function(pageNum){
        var canvas=document.createElement('canvas');
        canvas.className='pdf-canvas';
        container.appendChild(canvas);
        promises.push(pdf.getPage(pageNum).then(function(page){
          var scale=1.5;var viewport=page.getViewport({scale:scale});
          canvas.width=viewport.width;canvas.height=viewport.height;
          return page.render({canvasContext:canvas.getContext('2d'),viewport:viewport}).promise;
        }));
      })(i);
    }
    Promise.all(promises).then(function(){
      box.innerHTML='';box.appendChild(container);
      // 必须用 insertAdjacentHTML 追加：innerHTML += 会重新序列化 DOM，canvas 位图会全部丢失
      box.insertAdjacentHTML('beforeend','<div class="mtitle"><span>'+esc(name)+'</span><span style="display:flex;gap:6px"><button class="mdl" id="pvDl">'+t('download')+'</button></span></div>');
      document.getElementById('pvDl').onclick=function(){window.open(src.replace('/api/preview','/api/download'),'_blank')};
    });
  }).catch(function(e){
    box.innerHTML='<div class="pdf-status">PDF preview failed: '+esc(e.message)+'</div>';
  });
}


// ===== Office 文档预览（按需从 CDN 加载解析库）=====
function isOffice(name){var e=(String(name||'').split('.').pop()||'').toLowerCase();return ['docx','xlsx','xls','csv','pptx','ods'].indexOf(e)>=0}
function loadScriptOnce(url){
  if(!loadScriptOnce.c)loadScriptOnce.c={};
  if(loadScriptOnce.c[url])return loadScriptOnce.c[url];
  loadScriptOnce.c[url]=new Promise(function(res,rej){
    var s=document.createElement('script');s.src=url;s.async=true;
    s.onload=function(){res(true)};s.onerror=function(){rej(new Error('load failed'))};
    document.head.appendChild(s);
  });
  return loadScriptOnce.c[url];
}
function previewOffice(src,name){
  var box=document.getElementById('pvContent');
  var ext=(String(name||'').split('.').pop()||'').toLowerCase();
  box.innerHTML='<div class="pdf-status" id="offStatus">'+(lang==='zh'?'加载文档组件…':'Loading document…')+'</div>';
  function fail(msg){
    box.innerHTML='<div class="pdf-status">'+esc(msg||'预览失败')+'</div><div class="mtitle"><span>'+esc(name)+'</span><span><button class="mdl" id="pvDl">'+t('download')+'</button></span></div>';
    document.getElementById('pvDl').onclick=function(){window.open(src.replace('/api/preview','/api/download'),'_blank')};
  }
  function show(html,extra){
    box.innerHTML='<div style="max-height:62vh;overflow:auto;background:var(--sys-fill);border-radius:10px;padding:12px;text-align:left" class="off-body">'+html+'</div>'
      +'<div class="mtitle"><span>'+esc(name)+'</span><span style="display:flex;gap:6px">'+(extra||'')+'<button class="mdl" id="pvDl">'+t('download')+'</button></span></div>';
    document.getElementById('pvDl').onclick=function(){window.open(src.replace('/api/preview','/api/download'),'_blank')};
  }
  if(ext==='xlsx'||ext==='xls'||ext==='csv'||ext==='ods'){
    loadScriptOnce('https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js').then(function(){
      return fetch(src).then(function(r){return r.arrayBuffer()});
    }).then(function(buf){
      var XLSX=window.XLSX;
      if(!XLSX)throw new Error('xlsx missing');
      var wb=XLSX.read(new Uint8Array(buf),{type:'array'});
      var sheets=wb.SheetNames||[];
      if(!sheets.length)throw new Error('empty');
      var cur=0;
      function paint(){
        var html=XLSX.utils.sheet_to_html(wb.Sheets[sheets[cur]],{id:'sheet'+cur});
        var tabs='<div style="margin-bottom:8px;display:flex;gap:4px;flex-wrap:wrap">'+sheets.map(function(s,j){
          return '<button class="mdl" data-sheet="'+j+'" style="'+(j===cur?'background:var(--sys-blue);color:#fff;border-color:var(--sys-blue)':'')+'">'+esc(s)+'</button>';
        }).join('')+'</div>';
        var safe=(typeof DOMPurify!=='undefined')?DOMPurify.sanitize(tabs+html):tabs+html;
        show(safe,'<span class="dup-path" style="align-self:center">'+sheets.length+' sheet(s)</span>');
        var body=box.querySelector('.off-body');
        if(body)body.querySelectorAll('[data-sheet]').forEach(function(b){b.onclick=function(){cur=parseInt(b.getAttribute('data-sheet'),10)||0;paint()}});
        var t1=box.querySelector('table');
        if(t1){t1.style.borderCollapse='collapse';t1.querySelectorAll('td,th').forEach(function(c){c.style.border='1px solid var(--sys-separator)';c.style.padding='3px 6px';c.style.fontSize='12.5px'})}
      }
      paint();
    }).catch(function(e){fail((lang==='zh'?'表格预览失败（需联网加载解析库）：':'Table preview failed: ')+(e&&e.message||''))});
  }else if(ext==='docx'){
    loadScriptOnce('https://cdn.jsdelivr.net/npm/mammoth@1.8.0/mammoth.browser.min.js').then(function(){
      return fetch(src).then(function(r){return r.arrayBuffer()});
    }).then(function(buf){
      if(!window.mammoth)throw new Error('mammoth missing');
      return window.mammoth.convertToHtml({arrayBuffer:buf});
    }).then(function(res){
      var safe=(typeof DOMPurify!=='undefined')?DOMPurify.sanitize(res.value||''):esc(res.value||'');
      show(safe,'<span class="dup-path" style="align-self:center">docx</span>');
      var body=box.querySelector('.off-body');
      if(body){body.style.lineHeight='1.7';body.style.fontSize='14px'}
    }).catch(function(e){fail((lang==='zh'?'文档预览失败（需联网加载解析库）：':'Document preview failed: ')+(e&&e.message||''))});
  }else{
    fail(lang==='zh'?'该格式暂不支持在线预览，请下载查看':'Preview not supported, please download');
  }
}

// ===== 音乐播放器（播放列表 / 随机循环 / 音量记忆 / 歌词 / 封面）=====
var PL={idx:-1,mode:'seq',vol:1,lrc:null,tracks:[]};
function plSave(){try{localStorage.setItem('dPL',JSON.stringify({mode:PL.mode,vol:PL.vol,path:cur}))}catch(e){}}
function plLoad(){
  try{var o=JSON.parse(localStorage.getItem('dPL')||'{}');if(o.mode)PL.mode=o.mode;if(typeof o.vol==='number')PL.vol=o.vol}catch(e){}
}
plLoad();
function plModeIcon(){return PL.mode==='shuffle'?'🔀':(PL.mode==='one'?'🔂':'🔁')}
function plNextIdx(dir){
  var n=PL.tracks.length;if(!n)return -1;
  if(PL.mode==='shuffle')return Math.floor(Math.random()*n);
  var i=PL.idx+dir;
  if(i<0)i=n-1;if(i>=n)i=0;
  return i;
}
function plApplyVolume(){
  var a=document.getElementById('plAudio');
  if(a){try{a.volume=PL.vol}catch(e){}}
}
function plCover(fileUrl){
  // 读取 ID3v2 APIC 封面（仅取前 256KB）
  return fetch(fileUrl,{headers:{Range:'bytes=0-262143'}}).then(function(r){return r.arrayBuffer()}).then(function(buf){
    var u=new Uint8Array(buf);
    if(u.length<10||u[0]!==0x49||u[1]!==0x44||u[2]!==0x33)return null;
    var size=((u[6]&0x7f)<<21)|((u[7]&0x7f)<<14)|((u[8]&0x7f)<<7)|(u[9]&0x7f);
    var pos=10, end=Math.min(u.length,10+size);
    while(pos+10<end){
      var id=String.fromCharCode(u[pos],u[pos+1],u[pos+2],u[pos+3]);
      var sz=((u[pos+4]&0x7f)<<21)|((u[pos+5]&0x7f)<<14)|((u[pos+6]&0x7f)<<7)|(u[pos+7]&0x7f);
      if(sz<=0||pos+10+sz>end)break;
      if(id==='APIC'){
        var q=pos+10, mimeEnd=q;
        while(mimeEnd<end&&u[mimeEnd]!==0)mimeEnd++;
        var mime=String.fromCharCode.apply(null,u.subarray(q,mimeEnd))||'image/jpeg';
        var p=mimeEnd+1; if(p<end&&u[p]===3)p+=1;
        var dstart=p; while(dstart<end&&u[dstart]!==0)dstart++;
        dstart++;
        if(dstart<pos+10+sz)return URL.createObjectURL(new Blob([u.subarray(dstart,pos+10+sz)],{type:mime}));
        return null;
      }
      pos+=10+sz;
    }
    return null;
  }).catch(function(){return null});
}
function plLyrics(name){
  var base=String(name||'').replace(/\\.[^.]+$/,'').toLowerCase();
  var hit=null;
  for(var i=0;i<currentItems.length;i++){
    var it=currentItems[i];
    if(it&&it.type==='file'&&/\\.lrc$/i.test(it.name)&&String(it.name).replace(/\\.[^.]+$/,'').toLowerCase()===base){hit=it;break}
  }
  if(!hit)return Promise.resolve(null);
  var p=encodeURIComponent((hit.path||cur)+hit.name);
  return fetch('/api/preview?path='+p+'&token='+tk).then(function(r){return r.text()}).then(function(txt){
    var lines=[],re=/\\[(\\d+):(\\d+(?:\\.\\d+)?)\\](.*)/g,m;
    while((m=re.exec(txt))){lines.push({t:parseInt(m[1],10)*60+parseFloat(m[2]),s:m[3].trim()})}
    lines.sort(function(a,b){return a.t-b.t});
    return lines.length?lines:null;
  }).catch(function(){return null});
}
function getAudioItems(){
  return currentItems.filter(function(it){return it.type==='file'&&(it.mime||'').indexOf('audio/')===0});
}
function playPlaylist(idx){
  var audios=getAudioItems();
  if(!audios.length)return;
  PL.tracks=audios;
  playlistIdx=idx;PL.idx=idx;
  var it=audios[idx];
  var adir=it.path||cur;
  var src='/api/preview?path='+encodeURIComponent(adir+it.name)+'&token='+tk;
  var box=document.getElementById('pvContent');
  var h='<div id="plCover" style="text-align:center"></div>';
  h+='<audio controls autoplay src="'+src+'" id="plAudio" style="width:100%"></audio>';
  h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;gap:6px">'
    +'<button class="mdl" id="plPrev">⏮</button>'
    +'<button class="mdl" id="plMode" title="'+(lang==='zh'?'播放模式':'Mode')+'">'+plModeIcon()+'</button>'
    +'<span style="font-size:13px;color:var(--sys-text-2)">'+(idx+1)+' / '+audios.length+'</span>'
    +'<button class="mdl" id="plNext">⏭</button></div>';
  h+='<div id="plLrc" style="max-height:180px;overflow:auto;margin-top:8px;font-size:13px;line-height:1.8;text-align:center;color:var(--sys-text-2)"></div>';
  h+='<div class="playlist" style="margin-top:8px">';
  audios.forEach(function(a,i){h+='<div class="pl-item'+(i===idx?' active':'')+'" data-pli="'+i+'">'+getIcon(a)+'<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(a.name)+'</span></div>'});
  h+='</div>';
  box.innerHTML=h;
  document.getElementById('pvModal').classList.add('show');
  var audio=document.getElementById('plAudio');
  plApplyVolume();
  if(audio){
    audio.onended=function(){
      if(PL.mode==='one'){audio.currentTime=0;audio.play();return}
      var n=plNextIdx(1);
      var last=PL.idx===PL.tracks.length-1;
      if(PL.mode==='seq'&&last)return;
      if(n>=0)playPlaylist(n);
    };
    audio.ontimeupdate=function(){
      var c=PL.lrc;if(!c||!c.length)return;
      var t=audio.currentTime,act=-1;
      for(var i=0;i<c.length;i++){if(c[i].t<=t+0.25)act=i;else break}
      var box2=document.getElementById('plLrc');
      if(box2&&act>=0&&box2.getAttribute('data-act')!==String(act)){
        box2.setAttribute('data-act',String(act));
        box2.innerHTML=c.map(function(l,i){
          return '<div style="'+(i===act?'color:var(--sys-blue);font-weight:600':'')+'" data-lt="'+l.t+'">'+esc(l.s||'·')+'</div>';
        }).join('');
        var cur2=box2.querySelector('[data-lt="'+c[act].t+'"]');
        if(cur2&&cur2.scrollIntoView)try{cur2.scrollIntoView({block:'center'})}catch(e){}
      }
    };
    audio.onvolumechange=function(){PL.vol=audio.volume;plSave()};
  }
  var prev=document.getElementById('plPrev');if(prev)prev.onclick=function(){var n=plNextIdx(-1);if(n>=0)playPlaylist(n)};
  var next=document.getElementById('plNext');if(next)next.onclick=function(){var n=plNextIdx(1);if(n>=0)playPlaylist(n)};
  var mb=document.getElementById('plMode');
  if(mb)mb.onclick=function(){
    PL.mode=PL.mode==='seq'?'all':(PL.mode==='all'?'one':(PL.mode==='one'?'shuffle':'seq'));
    mb.textContent=plModeIcon();plSave();
  };
  box.querySelectorAll('[data-pli]').forEach(function(el){el.onclick=function(){playPlaylist(parseInt(el.getAttribute('data-pli'),10))}});
  var active=box.querySelector('.pl-item.active');
  if(active&&active.scrollIntoView)try{active.scrollIntoView({block:'nearest'})}catch(e){}
  // 封面与歌词（异步，失败静默）
  plCover(src).then(function(url){
    var c=document.getElementById('plCover');
    if(url&&c)c.innerHTML='<img src="'+url+'" style="max-width:180px;max-height:180px;border-radius:10px;box-shadow:var(--sys-shadow-sm)">';
  });
  plLyrics(it.name).then(function(lines){
    PL.lrc=lines;
    var box2=document.getElementById('plLrc');
    if(box2&&lines)box2.innerHTML=lines.map(function(l){return '<div data-lt="'+l.t+'">'+esc(l.s||'·')+'</div>'}).join('');
  });
}


// ===== Image Slideshow + EXIF =====
var slideshowTimer=null;
function stopSlideshow(){
  if(slideshowTimer){clearInterval(slideshowTimer);slideshowTimer=null;}
  var p=document.getElementById('pvPrev'),n=document.getElementById('pvNext'),c=document.getElementById('pvCounter');
  if(p)p.classList.remove('hidden');
  if(n)n.classList.remove('hidden');
  if(c)c.textContent='';
}
function startSlideshow(){
  var imgs=currentItems.filter(function(it){return it.type==='file'&&(it.mime||'').indexOf('image/')===0});
  if(!imgs.length)return;
  var idx=0;
  function showNext(){
    var it=imgs[idx];
    var sdir=it.path||cur;
    var src='/api/preview?path='+encodeURIComponent(sdir+it.name)+'&token='+tk;
    var box=document.getElementById('pvContent');
    box.innerHTML='<img src="'+src+'" style="max-width:100%;max-height:65vh;border-radius:8px" /><div class="exif-bar" id="exifBar"></div><div style="text-align:center;margin-top:8px;font-size:13px;color:var(--sys-text-2)">'+(idx+1)+' / '+imgs.length+' · '+esc(it.name)+'</div>';
    loadExif(src);
    idx=(idx+1)%imgs.length;
  }
  showNext();
  document.getElementById('pvModal').classList.add('show');
  if(slideshowTimer)clearInterval(slideshowTimer);
  slideshowTimer=setInterval(showNext,4000);
  document.getElementById('pvPrev').classList.add('hidden');
  document.getElementById('pvNext').classList.add('hidden');
  document.getElementById('pvCounter').textContent='Slideshow';
}
function loadExif(src){
  if(typeof ExifReader==='undefined')return;
  fetch(src).then(function(r){return r.arrayBuffer()}).then(function(buf){
    try{
      var tags=ExifReader.load(buf,{expanded:true});
      var bar=document.getElementById('exifBar');
      if(!bar)return;
      var info=[];
      if(tags.exif&&tags.exif.Make)info.push(tags.exif.Make.description+' '+((tags.exif.Model||{}).description||''));
      if(tags.exif&&tags.exif.DateTimeOriginal)info.push(tags.exif.DateTimeOriginal.description);
      if(tags.exif&&tags.exif.FocalLength)info.push(tags.exif.FocalLength.description+'mm');
      if(tags.exif&&tags.exif.FNumber)info.push('f/'+tags.exif.FNumber.description);
      if(tags.exif&&tags.exif.ExposureTime)info.push(tags.exif.ExposureTime.description+'s');
      if(tags.exif&&tags.exif.ISO)info.push('ISO '+tags.exif.ISO.description);
      if(tags.file&&tags.file.ImageWidth)info.push(tags.file.ImageWidth.description+'×'+((tags.file.ImageHeight||{}).description||''));
      if(info.length)bar.innerHTML=info.map(function(s){return'<span>'+esc(s)+'</span>'}).join('');
    }catch(e){}
  }).catch(function(){});
}

// ===== Video Screenshot =====
function takeScreenshot(){
  var video=document.querySelector('#pvContent video');
  if(!video)return;
  var canvas=document.createElement('canvas');
  canvas.width=video.videoWidth;canvas.height=video.videoHeight;
  canvas.getContext('2d').drawImage(video,0,0);
  var link=document.createElement('a');
  link.download='screenshot-'+Date.now()+'.png';
  link.href=canvas.toDataURL('image/png');
  link.click();
}

function doPreview(name,mime,idx,base){
  base=base||cur;
  if(idx===undefined||idx<0){idx=currentItems.findIndex(function(it){return it.type==='file'&&it.name===name&&((it.path||cur)===base)});}
  if(idx<0||idx>=currentItems.length){return}
  previewIdx=idx;
  var it=currentItems[idx];
  if(!it||it.type!=='file'){return}
  name=it.name;mime=it.mime||'';
  var idir=it.path||base||cur;
  stopSlideshow();   // 打开新预览时先停掉上一次的幻灯片，避免定时器持续覆盖内容
  var path=encodeURIComponent(idir+name);var src='/api/preview?path='+path+'&token='+tk;var box=document.getElementById('pvContent');var html='';
  if((mime||'').indexOf('image/')===0){html='<img src="'+src+'" /><button class="mdl screenshot-btn" onclick="startSlideshow()" style="position:absolute;top:14px;left:18px;z-index:20">▶ '+t('slideshow')+'</button>'}
  else if((mime||'').indexOf('video/')===0)html='<video controls autoplay src="'+src+'" id="pvVideo"></video><button class="mdl screenshot-btn" onclick="takeScreenshot()">📷 '+t('screenshot')+'</button>';
  else if((mime||'').indexOf('audio/')===0){
    // 音频走播放列表，但必须自己把弹窗显示出来（此前提前 return，点音频毫无反应）
    playPlaylist(getAudioItems().findIndex(function(a){return a.name===name&&((a.path||cur)===idir)}));
    document.getElementById('pvModal').classList.add('show');
    document.getElementById('pvPrev').classList.add('hidden');
    document.getElementById('pvNext').classList.add('hidden');
    document.getElementById('pvCounter').textContent='';
    api('/api/recent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:idir+name})}).catch(function(){});
    return;
  }
  else if(isPDF(name)){html='<div class="pdf-status">Loading...</div>'}
  else if(isOffice(name)){html='<div class="pdf-status">Loading...</div>'}
  else if(isText({mime:mime})){var isMd=name.toLowerCase().endsWith('.md');html='<div id="pvTextWrap"><div style="margin-bottom:8px;display:flex;gap:8px;justify-content:flex-end">'+(isMd?'<button id="pvMdToggle" class="mdl">'+t('renderMd')+'</button>':'')+'</div><pre id="pvT" class="hl-pre">Loading...</pre></div>'}
  else html='<p style="color:var(--sys-text-3);padding:40px;text-align:center">'+t('noResult')+'</p>';
  html+='<div class="mtitle"><span>'+esc(name)+'</span><span style="display:flex;gap:6px"><button class="mdl" id="pvCmt">💬</button><button class="mdl" id="pvHis">'+t('history')+'</button><button class="mdl" id="pvEdit" style="display:'+(isText({mime:mime})?'inline-block':'none')+'">'+t('edit')+'</button><button class="mdl" id="pvDl">'+t('download')+'</button></span></div>';
  box.innerHTML=html;
  if(isPDF(name)){previewPDF(src,name)}
  else if(isOffice(name)){previewOffice(src,name)}
  if(isText({mime:mime})){fetch(src).then(function(r){return r.text()}).then(function(txt){
    var p=document.getElementById('pvT');
    if(p){
      p.textContent=txt.substring(0,200000);
      try{if(typeof hljs!=='undefined')hljs.highlightElement(p)}catch(e){}
    }
    var toggle=document.getElementById('pvMdToggle');
    if(toggle){
      var rawMode=true;
      toggle.onclick=function(){
        rawMode=!rawMode;
        var wrap=document.getElementById('pvTextWrap');
        if(!rawMode&&typeof marked!=='undefined'){
          var rendered=(typeof DOMPurify!=='undefined')?DOMPurify.sanitize(marked.parse(txt)):esc(txt);
          if(wrap)wrap.innerHTML='<div style="margin-bottom:8px;display:flex;gap:8px;justify-content:flex-end"><button id="pvMdToggle" class="mdl">'+t('raw')+'</button></div><div class="md-body">'+rendered+'</div>';
          document.getElementById('pvMdToggle').onclick=function(){
            rawMode=true;
            if(wrap)wrap.innerHTML='<div style="margin-bottom:8px;display:flex;gap:8px;justify-content:flex-end"><button id="pvMdToggle" class="mdl">'+t('renderMd')+'</button></div><pre id="pvT" class="hl-pre">'+esc(txt.substring(0,200000))+'</pre>';
            try{if(typeof hljs!=='undefined')hljs.highlightElement(document.getElementById('pvT'))}catch(e2){}
            document.getElementById('pvMdToggle').onclick=toggle.onclick;
          };
        }else{
          if(wrap)wrap.innerHTML='<div style="margin-bottom:8px;display:flex;gap:8px;justify-content:flex-end"><button id="pvMdToggle" class="mdl">'+t('renderMd')+'</button></div><pre id="pvT" class="hl-pre">'+esc(txt.substring(0,200000))+'</pre>';
          try{if(typeof hljs!=='undefined')hljs.highlightElement(document.getElementById('pvT'))}catch(e2){}
          document.getElementById('pvMdToggle').onclick=toggle.onclick;
        }
      };
    }
  })}
  document.getElementById('pvModal').classList.add('show');
  document.getElementById('pvDl').onclick=function(){window.open('/api/download?path='+path+'&token='+tk,'_blank')};
  document.getElementById('pvEdit').onclick=function(){closePv();editText(name,idir)};
  document.getElementById('pvHis').onclick=function(){closePv();showVersions(name,idir)};
  var cmtBtn=document.getElementById('pvCmt');
  if(cmtBtn)cmtBtn.onclick=function(){showComments(idir+name,name)};
  updatePreviewNav();
  api('/api/recent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:idir+name})}).catch(function(){});
}
function findPreviewableStep(dir){
  if(previewIdx<0)return -1;
  var i=previewIdx+dir;
  while(i>=0&&i<currentItems.length){if(isPreviewable(currentItems[i]))return i;i+=dir}
  return -1;
}
function previewNav(dir){
  var n=findPreviewableStep(dir);
  if(n<0)return;
  document.querySelectorAll('#pvContent video,#pvContent audio').forEach(function(el){try{el.pause()}catch(e){}});
  doPreview(currentItems[n].name,currentItems[n].mime||'',n);
}
function updatePreviewNav(){
  var prev=document.getElementById('pvPrev'),next=document.getElementById('pvNext'),ctr=document.getElementById('pvCounter');
  var p=findPreviewableStep(-1),n=findPreviewableStep(1);
  prev.classList.toggle('hidden',p<0);
  next.classList.toggle('hidden',n<0);
  var list=[];for(var i=0;i<currentItems.length;i++){if(isPreviewable(currentItems[i]))list.push(i)}
  var pos=list.indexOf(previewIdx);
  if(list.length>1&&pos>=0){ctr.textContent=(pos+1)+' / '+list.length}else{ctr.textContent=''}
}
document.getElementById('pvPrev').onclick=function(e){e.stopPropagation();previewNav(-1)};
document.getElementById('pvNext').onclick=function(e){e.stopPropagation();previewNav(1)};
document.getElementById('pvClose').onclick=closePv;document.getElementById('pvModal').onclick=function(e){if(e.target===this)closePv()};
function closePv(){stopSlideshow();document.getElementById('pvModal').classList.remove('show');previewIdx=-1;document.querySelectorAll('.modal video,.modal audio').forEach(function(el){el.pause();el.removeAttribute('src');el.load()})}
document.addEventListener('keydown',function(e){
  if(!document.getElementById('pvModal').classList.contains('show'))return;
  if(e.key==='ArrowLeft'){previewNav(-1)}
  else if(e.key==='ArrowRight'){previewNav(1)}
  else if(e.key==='Escape'){closePv()}
});

function editText(name,base){
  base=base||cur;
  var path=encodeURIComponent(base+name);var src='/api/preview?path='+path+'&token='+tk;
  var box=document.getElementById('pvContent');
  box.innerHTML='<textarea id="edArea" spellcheck="false">Loading...</textarea><div id="edMsg"></div><div class="mtitle"><span>'+esc(name)+'</span><button class="mdl" id="edSave">'+t('save')+'</button></div>';
  document.getElementById('pvModal').classList.add('show');
  document.getElementById('pvPrev').classList.add('hidden');
  document.getElementById('pvNext').classList.add('hidden');
  document.getElementById('pvCounter').textContent='';
  fetch(src).then(function(r){return r.text()}).then(function(txt){document.getElementById('edArea').value=txt});
  document.getElementById('edSave').onclick=function(){
    var content=document.getElementById('edArea').value;
    var msg=document.getElementById('edMsg');
    if(msg){msg.textContent='';msg.style.color=''}
    fetch('/api/save?path='+path+'&token='+tk,{method:'POST',body:content}).then(function(r){
      if(r.ok){closePv();load();return}
      // 保存失败（413/403/400 等）必须告知用户，不能照常关窗让内容丢失
      return r.json().then(function(d){
        var em=(d&&d.error)||('HTTP '+r.status);
        if(msg){msg.textContent=(lang==='zh'?'保存失败：':'Save failed: ')+em;msg.style.color='var(--sys-red)'}
        else alert((lang==='zh'?'保存失败：':'Save failed: ')+em);
      }).catch(function(){
        if(msg){msg.textContent=(lang==='zh'?'保存失败':'Save failed');msg.style.color='var(--sys-red)'}
        else alert(lang==='zh'?'保存失败':'Save failed');
      });
    }).catch(function(){
      if(msg){msg.textContent=(lang==='zh'?'网络错误，未保存':'Network error, not saved');msg.style.color='var(--sys-red)'}
      else alert(lang==='zh'?'保存失败':'Save failed');
    });
  };
}

function showMove(name,base){
  base=base||cur;
  api('/api/search?q=&path=/').then(function(all){
    var dirs=[{path:'/',label:'/ (Root)'}];var seen={'/':true};
    (all&&all.results?all.results:[]).forEach(function(r){if(r.type==='dir'){var p=r.path+r.name+'/';if(!seen[p]){seen[p]=true;dirs.push({path:p,label:p})}}});
    var box=document.getElementById('mvContent');var h='';
    dirs.forEach(function(d){h+='<div class="mi" data-mp="'+esc(d.path)+'" style="padding:10px 14px;cursor:pointer;border-radius:8px;font-size:14px;color:var(--sys-blue);font-weight:500">'+esc(d.label)+'</div>'});
    box.innerHTML=h;document.getElementById('mvModal').classList.add('show');document.getElementById('mvTitle').textContent=t('moveTo');
    box.querySelectorAll('[data-mp]').forEach(function(el){el.onclick=function(){api('/api/move',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:base+name,target:el.getAttribute('data-mp')})}).then(function(){document.getElementById('mvModal').classList.remove('show');load()})};el.onmouseenter=function(){el.style.background='var(--sys-fill)'};el.onmouseleave=function(){el.style.background=''}});
  });
}
document.getElementById('mvClose').onclick=function(){document.getElementById('mvModal').classList.remove('show')};
document.getElementById('mvModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

function showCtx(x,y,name,type,mime,base){
  base=base||cur;
  var menu=document.getElementById('ctxMenu');var h='';
  if(type==='file'){
    h+='<div class="mi" data-a="dl">'+t('download')+'</div><div class="mi" data-a="shr">'+t('share')+'</div><div class="mi" data-a="tag">🏷 '+t('tag')+'</div><div class="mi" data-a="note">📝 '+t('note')+'</div><div class="mi" data-a="enc">🔐 '+t('enc')+'</div>';
    h+='<div class="mi" data-a="his">'+t('history')+'</div>';
    if(isZip(name))h+='<div class="mi" data-a="unz">'+t('unzip')+'</div>';
    if(isText({mime:mime}))h+='<div class="mi" data-a="ed">'+t('edit')+'</div>';
  }
  h+='<div class="mi" data-a="ren">'+t('ren')+'</div><div class="mi" data-a="mv">'+t('move')+'</div><div class="mi danger" data-a="del">'+t('del')+'</div>';
  h+='<div class="mi" data-a="cpy">📋 '+t('copy')+'</div><div class="mi" data-a="cut">✂ '+t('cut')+'</div>';
  if(type==='file')h+='<div class="mi" data-a="link">🔗 '+(lang==='zh'?'限时直链':'Signed link')+'</div>';
  if(type==='dir')h+='<div class="mi" data-a="pst">📥 '+t('pasteHere')+'</div>';
  if(type==='dir')h+='<div class="mi" data-a="shrd">📁 '+t('share')+'</div>';
  menu.innerHTML=h;menu.style.left=Math.min(x,window.innerWidth-190)+'px';menu.style.top=Math.min(y,window.innerHeight-260)+'px';menu.classList.add('show');
  menu.onclick=function(e){var a=e.target.getAttribute('data-a');if(!a)return;menu.classList.remove('show');
    if(a==='dl')window.open('/api/download?path='+encodeURIComponent(base+name)+'&token='+tk,'_blank');
    else if(a==='shr')doShare(name,base);
    else if(a==='shrd')doShareDir(base+name+'/');
    else if(a==='his')showVersions(name,base);
    else if(a==='tag')doTagFile(name,base);
    else if(a==='note')showNote(name,base);
    else if(a==='enc')showEncrypt(name,base);
    else if(a==='unz')doUnzip(name,base);
    else if(a==='ed')editText(name,base);
    else if(a==='ren'){var n=prompt(t('rename'),name);if(n&&n!==name)api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:base+name,newName:n})}).then(load)}
    else if(a==='mv')showMove(name,base);
    else if(a==='del'){if(confirm(t('delete')))api('/api/delete?path='+encodeURIComponent(base+name),{method:'DELETE'}).then(load)}
    else if(a==='cpy')clipSet('copy',[base+name]);
    else if(a==='cut')clipSet('cut',[base+name]);
    else if(a==='pst')pasteHere(base+name+'/');
    else if(a==='link')signedLink(base+name,base);
  };
}
document.addEventListener('click',function(){var m=document.getElementById('ctxMenu');if(m)m.classList.remove('show')});


// ===== Tag management =====
document.getElementById('btnTag').onclick=function(){showTagModal()};
document.getElementById('tagClose').onclick=function(){document.getElementById('tagModal').classList.remove('show')};
document.getElementById('tagModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showTagModal(fileName,base){
  base=base||cur;
  var path=fileName?base+fileName:'';
  var box=document.getElementById('tagContent');
  var title=document.getElementById('tagTitle');
  api('/api/tags').then(function(d){
    var allTags=d.tags||[];
    var fileTags=[];
    function render(){
      title.textContent=fileName?(t('tags')+' · '+fileName):t('tags');
      var h='';
      h+='<div style="margin-bottom:14px"><div style="font-size:13px;color:var(--sys-text-2);margin-bottom:8px">'+t('addTag')+'</div>';
      h+='<div style="display:flex;gap:8px"><input id="newTagInput" placeholder="Tag name" style="flex:1;padding:8px 12px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px">';
      h+='<input id="newTagColor" type="color" value="#0a84ff" style="width:36px;height:36px;border:none;border-radius:8px;cursor:pointer">';
      h+='<button id="addTagBtn" class="btn small">+</button></div></div>';
      h+='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:8px">All tags:</div>';
      h+='<div style="display:flex;flex-wrap:wrap;gap:6px">';
      allTags.forEach(function(tg){
        var has=fileName&&fileTags.some(function(ft){return ft.name===tg.name});
        h+='<span class="tag-chip" data-tc="'+esc(tg.name)+'"'+(has?' style="outline:2px solid var(--sys-accent)"':'')+'><span class="tag-dot" style="background:'+safeColor(tg.color)+'"></span>'+esc(tg.name);
        if(fileName)h+='<span class="tag-x" data-tx="'+esc(tg.name)+'">✕</span>';
        h+='</span>';
      });
      h+='</div>';
      if(!allTags.length)h+='<div style="color:var(--sys-text-3);text-align:center;padding:20px">'+t('noTags')+'</div>';
      box.innerHTML=h;
      document.getElementById('tagModal').classList.add('show');
      var addBtn=document.getElementById('addTagBtn');
      if(addBtn)addBtn.onclick=function(){
        var name=document.getElementById('newTagInput').value.trim();
        if(!name)return;
        var color=document.getElementById('newTagColor').value;
        if(fileName){
          var merged=fileTags.concat([{name:name,color:color}]);
          merged=merged.filter(function(t,i,a){return !a.slice(0,i).some(function(x){return x.name===t.name})});
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName,base);renderTagSidebar()});
        }else{
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:'/.tag-register/',tags:[{name:name,color:color}]})}).then(function(){showTagModal();renderTagSidebar()});
        }
      };
      box.querySelectorAll('[data-tc]').forEach(function(el){
        el.onclick=function(){
          if(!fileName)return;
          var tn=el.getAttribute('data-tc');
          var has=fileTags.some(function(ft){return ft.name===tn});
          var merged;
          if(has){
            merged=fileTags.filter(function(ft){return ft.name!==tn});
          }else{
            var tg=allTags.find(function(x){return x.name===tn})||{name:tn,color:'#0a84ff'};
            merged=fileTags.concat([tg]);
          }
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName,base);renderTagSidebar()});
        };
      });
      box.querySelectorAll('[data-tx]').forEach(function(el){
        el.onclick=function(e){
          e.stopPropagation();
          var tn=el.getAttribute('data-tx');
          var merged=fileTags.filter(function(ft){return ft.name!==tn});
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName,base);renderTagSidebar()});
        };
      });
    }
    if(fileName){
      api('/api/tags?filter=__get__&path='+encodeURIComponent(path)).then(function(ft){
        fileTags=ft.tags||[];
        render();
      }).catch(function(){render()});
    }else{
      render();
    }
  });
}
function doTagFile(name,base){showTagModal(name,base)}


// ===== Duplicate finder =====
document.getElementById('btnDup').onclick=function(){showDuplicates()};
document.getElementById('dupClose').onclick=function(){document.getElementById('dupModal').classList.remove('show')};
document.getElementById('dupModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showDuplicates(){
  var box=document.getElementById('dupContent');
  box.innerHTML='<p style="color:var(--sys-text-3);text-align:center;padding:24px">Loading...</p>';
  document.getElementById('dupModal').classList.add('show');
  api('/api/duplicates').then(function(d){
    var groups=d.groups||[];
    if(!groups.length){box.innerHTML='<p style="color:var(--sys-text-3);text-align:center;padding:24px">'+t('noDup')+'</p>';return}
    var h='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:12px">'+groups.length+' groups · '+groups.reduce(function(s,g){return s+g.files.length},0)+' files</div>';
    groups.forEach(function(g,i){
      h+='<div class="dup-group"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span style="font-weight:600;font-size:13px">Group '+(i+1)+'</span><span class="dup-hash">'+esc(g.hash||'').substring(0,12)+'</span></div>';
      g.files.forEach(function(f){
        h+='<div class="dup-file"><span>'+getIcon({name:f.name,type:'file'})+'</span><span style="flex:1">'+esc(f.name)+'</span><span class="dup-path">'+esc(f.path)+'</span><span style="color:var(--sys-text-3);font-size:12px">'+fmt(f.size)+'</span></div>';
      });
      h+='</div>';
    });
    box.innerHTML=h;
  });
}


// ===== File notes =====
document.getElementById('noteClose').onclick=function(){document.getElementById('noteModal').classList.remove('show')};
document.getElementById('noteModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showNote(name,base){
  base=base||cur;
  var path=base+name;
  var box=document.getElementById('noteContent');
  document.getElementById('noteTitle').textContent=t('note')+' · '+name;
  box.innerHTML='<textarea id="noteArea" class="note-textarea" placeholder="Add notes...">Loading...</textarea><div style="margin-top:12px;text-align:right"><button id="noteSave" class="btn small">'+t('save')+'</button></div>';
  document.getElementById('noteModal').classList.add('show');
  api('/api/note?path='+encodeURIComponent(path)).then(function(d){
    var area=document.getElementById('noteArea');
    if(area)area.value=d.note||'';
  });
  document.getElementById('noteSave').onclick=function(){
    var note=document.getElementById('noteArea').value;
    api('/api/note',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,note:note})}).then(function(){
      document.getElementById('noteModal').classList.remove('show');
      load();
    });
  };
}

(function(){
  var mbtn=document.getElementById('btnMore'),menu=document.getElementById('hdrMenu');
  if(!mbtn||!menu)return;
  function closeMenu(){menu.classList.remove('show');mbtn.classList.remove('active');mbtn.setAttribute('aria-expanded','false')}
  mbtn.onclick=function(e){e.stopPropagation();var show=!menu.classList.contains('show');menu.classList.toggle('show',show);mbtn.classList.toggle('active',show);mbtn.setAttribute('aria-expanded',show?'true':'false')};
  menu.addEventListener('click',function(e){if(e.target.closest('button'))closeMenu()});
  document.addEventListener('click',function(e){if(!menu.contains(e.target)&&e.target!==mbtn)closeMenu()});
  document.addEventListener('keydown',function(e){if(e.key==='Escape')closeMenu()});
})();
document.getElementById('btnTrash').onclick=showTrash;
document.getElementById('trClose').onclick=function(){document.getElementById('trModal').classList.remove('show')};
document.getElementById('trModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showTrash(){
  api('/api/trash').then(function(d){
    var items=d.items||[];
    var box=document.getElementById('trContent');
    if(!items.length){box.innerHTML='<p style="color:var(--sys-text-3);text-align:center;padding:24px">'+t('trashEmpty')+'</p>';document.getElementById('trModal').classList.add('show');return}
    var h='<div style="margin-bottom:12px;display:flex;gap:10px;align-items:center;font-size:13px"><input type="checkbox" id="trAll" style="width:18px;height:18px;accent-color:var(--sys-blue)"><label for="trAll" style="cursor:pointer;color:var(--sys-text-2);font-weight:500">全选</label><span style="flex:1"></span><button id="trBatchRst" class="btn gray small">'+t('batchRestore')+'</button><button id="trBatchPg" class="btn danger small">'+t('batchPurge')+'</button></div>';
    items.forEach(function(it){
      var id=esc(it.id||it.name);
      h+='<div class="tr-row"><input type="checkbox" data-trc="'+id+'"><span class="tr-name">'+esc(it.name)+'</span><span class="tr-meta">'+fmt(it.size)+' · '+it.daysLeft+' '+t('daysLeft')+'</span>';
      h+='<button data-rst="'+id+'" class="btn gray tiny">'+t('restore')+'</button>';
      h+='<button data-pg="'+id+'" class="btn tiny danger">'+t('purge')+'</button></div>';
    });
    h+='<div style="margin-top:16px;text-align:right"><button id="trPA" class="btn danger small">'+t('emptyTrash')+'</button></div>';
    box.innerHTML=h;document.getElementById('trModal').classList.add('show');

    function getChecked(){var arr=[];box.querySelectorAll('[data-trc]:checked').forEach(function(cb){arr.push(cb.getAttribute('data-trc'))});return arr}
    box.querySelectorAll('[data-rst]').forEach(function(b){b.onclick=function(){api('/api/restore?name='+encodeURIComponent(b.getAttribute('data-rst')),{method:'POST'}).then(function(r){if(r&&r.error)alert((lang==='zh'?'恢复失败：':'Restore failed: ')+r.error);showTrash();load()})}});
    box.querySelectorAll('[data-pg]').forEach(function(b){b.onclick=function(){if(!confirm(t('purge')+'?'))return;api('/api/purge?name='+encodeURIComponent(b.getAttribute('data-pg')),{method:'DELETE'}).then(function(r){if(r&&r.error)alert(r.error);showTrash()})}});
    var trAll=document.getElementById('trAll');
    if(trAll)trAll.onchange=function(){box.querySelectorAll('[data-trc]').forEach(function(cb){cb.checked=trAll.checked})};
    var br=document.getElementById('trBatchRst');if(br)br.onclick=function(){var arr=getChecked();if(!arr.length)return;api('/api/batch-restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:arr})}).then(function(){showTrash();load()})};
    var bp=document.getElementById('trBatchPg');if(bp)bp.onclick=function(){var arr=getChecked();if(!arr.length)return;if(!confirm(t('batchPurge')+'?'))return;api('/api/batch-purge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:arr})}).then(showTrash)};
    var pa=document.getElementById('trPA');if(pa)pa.onclick=function(){if(confirm(t('emptyTrash')+'?'))api('/api/purge?name=ALL',{method:'DELETE'}).then(showTrash)};
  });
}

document.getElementById('btnLogin').onclick=function(){
  var fd=new FormData();
  fd.append('password',document.getElementById('pw').value);
  var codeEl=document.getElementById('totpCode');
  if(codeEl&&codeEl.value.trim())fd.append('code',codeEl.value.trim());
  fetch('/api/login',{method:'POST',body:fd}).then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})}).then(function(res){
    var d=res.d;
    if(d.token){tk=d.token;sessionStorage.setItem('dt',tk);show('main');goHome();loadUsage();return}
    // 需要二次验证时把动态码输入框显示出来
    if(d&&(d.totp||String(d.error||'').toLowerCase().indexOf('code')>=0)){
      var row=document.getElementById('totpRow');if(row)row.classList.remove('hidden');
      var el=document.getElementById('loginErr');
      if(el){el.textContent=(d.error||'')+(lang==='zh'?'（请输入动态码）':' (enter code)');el.style.display='block'}
      if(codeEl)codeEl.focus();
      return;
    }
    document.getElementById('loginErr').style.display='block';
  }).catch(function(){document.getElementById('loginErr').style.display='block'});
};
document.getElementById('pw').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnLogin').click()};
document.getElementById('totpCode').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnLogin').click()};
document.getElementById('btnLogout').onclick=function(){tk='';sessionStorage.removeItem('dt');show('login')};

document.getElementById('btnUp').onclick=function(){document.getElementById('fileInput').click()};
document.getElementById('fileInput').onchange=function(e){uploadFiles(e.target.files);e.target.value=''};
document.getElementById('dropZone').onclick=function(){document.getElementById('fileInput').click()};
document.addEventListener('dragover',function(e){e.preventDefault()});
document.addEventListener('drop',function(e){e.preventDefault()});
(function(){
  var dz=document.getElementById('dropZone');
  dz.ondragover=function(e){e.preventDefault();e.stopPropagation();dz.classList.add('over')};
  dz.ondragleave=function(e){e.preventDefault();dz.classList.remove('over')};
  dz.ondrop=async function(e){
    e.preventDefault();e.stopPropagation();dz.classList.remove('over');
    var dt=e.dataTransfer;var items=dt.items;
    if(items&&items.length&&items[0].webkitGetAsEntry){
      var files=[];var pending=[];
      for(var i=0;i<items.length;i++){var entry=items[i].webkitGetAsEntry();if(entry)pending.push(walkEntry(entry,'',files));}
      try{await Promise.all(pending)}catch(err){}
      if(files.length)uploadFiles(files);
    }else if(dt.files&&dt.files.length){uploadFiles(dt.files);}
  };
})();
function walkEntry(entry,relPath,files){
  return new Promise(function(resolve){
    if(entry.isFile){
      entry.file(function(f){try{f._relPath=relPath+f.name}catch(e){}files.push(f);resolve()},function(){resolve()});
    }else if(entry.isDirectory){
      var reader=entry.createReader();var all=[];
      (function readBatch(){
        reader.readEntries(function(batch){
          if(!batch.length){Promise.all(all.map(function(e2){return walkEntry(e2,relPath+entry.name+'/',files)})).then(function(){resolve()});return}
          all=all.concat(Array.prototype.slice.call(batch));readBatch();
        },function(){resolve()});
      })();
    }else{resolve()}
  });
}
async function makeThumb(file){
  if(!file.type||file.type.indexOf('image/')!==0)return null;
  if(file.size>10*1024*1024)return null;
  try{
    var bmp=await createImageBitmap(file);
    var maxDim=240;var w=bmp.width,h=bmp.height;
    var scale=Math.min(maxDim/w,maxDim/h,1);
    w=Math.round(w*scale);h=Math.round(h*scale);
    if(w<1||h<1)return null;
    var canvas=document.createElement('canvas');canvas.width=w;canvas.height=h;
    canvas.getContext('2d').drawImage(bmp,0,0,w,h);
    return await new Promise(function(r){canvas.toBlob(r,'image/jpeg',0.8)});
  }catch(e){return null}
}

// ===== Client Image Compression =====
var compressEnabled=localStorage.getItem('dCompress')==='1';
window.toggleCompress=function(btn){compressEnabled=!compressEnabled;localStorage.setItem('dCompress',compressEnabled?'1':'0');if(btn)btn.classList.toggle('enc-active')};
function compressImage(file){
  return new Promise(function(resolve){
    if(!compressEnabled||file.type.indexOf('image/')!==0||file.size<500*1024){resolve(file);return}
    var img=new Image();
    var url=URL.createObjectURL(file);
    img.onload=function(){
      URL.revokeObjectURL(url);
      var maxW=2048,maxH=2048;
      var w=img.width,h=img.height;
      if(w<=maxW&&h<=maxH){resolve(file);return}
      var ratio=Math.min(maxW/w,maxH/h);
      w=Math.round(w*ratio);h=Math.round(h*ratio);
      var canvas=document.createElement('canvas');
      canvas.width=w;canvas.height=h;
      canvas.getContext('2d').drawImage(img,0,0,w,h);
      canvas.toBlob(function(blob){
        if(blob&&blob.size<file.size){
          var nf;
          try{nf=new File([blob],file.name,{type:'image/jpeg'});if(file._relPath)nf._relPath=file._relPath}catch(e){nf=file}
          resolve(nf);
        }else{resolve(file)}
      },'image/jpeg',0.85);
    };
    img.onerror=function(){URL.revokeObjectURL(url);resolve(file)};
    img.src=url;
  });
}

// ===== 命令面板（⌘K / Ctrl+K）=====
var PALETTE={open:false,items:[],idx:0,seq:0};
function paletteModal(){return document.getElementById('palette')}
function paletteCommands(){
  function go(fn){return function(){try{fn()}catch(e){console.warn(e)}}}
  var zh=lang==='zh';
  var list=[
    {ic:'⬆',t:zh?'上传文件':'Upload files',s:'upload',run:go(function(){document.getElementById('fileInput').click()})},
    {ic:'📁',t:zh?'新建文件夹':'New folder',s:'mkdir',run:go(function(){document.getElementById('folderInput').focus()})},
    {ic:'🔎',t:zh?'搜索当前盘':'Search all',s:'search',run:go(function(){document.getElementById('searchInput').focus()})},
    {ic:'🔄',t:zh?'刷新列表':'Refresh',s:'reload',run:go(function(){load()})},
    {ic:'★',t:zh?'收藏视图':'Favorites',s:'fav',run:go(function(){setMode('fav');render()})},
    {ic:'🕐',t:zh?'最近访问':'Recent',s:'recent',run:go(function(){setMode('recent');render()})},
    {ic:'🔀',t:zh?'切换视图（网格/列表/列/图库）':'Cycle view',s:'view',run:go(function(){cycleView()})},
    {ic:'🔤',t:zh?'排序：名称':'Sort by name',s:'sort name',run:go(function(){sortKey='name';render()})},
    {ic:'📅',t:zh?'排序：时间':'Sort by date',s:'sort time',run:go(function(){sortKey='time';render()})},
    {ic:'⚖',t:zh?'排序：大小':'Sort by size',s:'sort size',run:go(function(){sortKey='size';render()})},
    {ic:'📦',t:zh?'打包当前目录':'ZIP current folder',s:'zip',run:go(function(){document.getElementById('btnZip').click()})},
    {ic:'📁',t:zh?'分享当前目录':'Share current folder',s:'share',run:go(function(){doShareDir(cur)})},
    {ic:'📥',t:zh?'从 WebDAV 导入':'Import WebDAV',s:'import',run:go(function(){importWebdav()})},
    {ic:'⭐',t:zh?'上传队列与并发':'Upload queue',s:'queue',run:go(function(){document.getElementById('upQueueBar').scrollIntoView({behavior:'smooth'})})},
    {ic:'📋',t:zh?'粘贴到当前目录':'Paste here',s:'paste',run:go(function(){pasteHere(cur)})},
    {ic:'🗑',t:zh?'回收站':'Trash',s:'trash',run:go(function(){showTrash()})},
    {ic:'🏷',t:zh?'标签管理':'Tags',s:'tags',run:go(function(){showTagModal()})},
    {ic:'🔎',t:zh?'重复文件':'Duplicates',s:'dup',run:go(function(){document.getElementById('btnDup').click()})},
    {ic:'📊',t:zh?'统计面板':'Stats',s:'stats',run:go(function(){showStats()})},
    {ic:'📜',t:zh?'活动日志':'Activity log',s:'log',run:go(function(){showLog()})},
    {ic:'🔗',t:zh?'分享管理':'Share manager',s:'shares',run:go(function(){showShareMgmt()})},
    {ic:'📤',t:zh?'上传链接管理':'Upload links',s:'ulinks',run:go(function(){showULinkMgmt()})},
    {ic:'🔑',t:zh?'访问令牌':'Tokens',s:'tokens',run:go(function(){showTokens()})},
    {ic:'🖥',t:zh?'登录设备':'Sessions',s:'sessions',run:go(function(){showSessions()})},
    {ic:'🛡',t:zh?'二次验证 (TOTP)':'Two-factor',s:'totp',run:go(function(){showTotp()})},
    {ic:'🛠',t:zh?'运维与配置':'Ops & config',s:'config',run:go(function(){showOps('config')})},
    {ic:'💾',t:zh?'备份与恢复':'Backup',s:'backup',run:go(function(){showBackup()})},
    {ic:'🩺',t:zh?'健康检查':'Health',s:'health',run:go(function(){showHealth()})},
    {ic:'🧹',t:zh?'孤儿文件扫描':'Orphan scan',s:'orphans',run:go(function(){showOrphans()})},
    {ic:'🖼',t:zh?'公开相册':'Albums',s:'albums',run:go(function(){showAlbums()})},
    {ic:'🌗',t:zh?'切换主题':'Toggle theme',s:'theme',run:go(function(){document.getElementById('btnTheme').click()})},
    {ic:'🌐',t:zh?'切换语言':'Toggle language',s:'lang',run:go(function(){document.getElementById('btnLang').click()})},
    {ic:'⬆',t:zh?'返回上级目录':'Go to parent',s:'parent',run:go(function(){goParent()})},
    {ic:'🚪',t:zh?'退出登录':'Log out',s:'logout',run:go(function(){document.getElementById('btnLogout').click()})}
  ];
  return list;
}
function paletteRender(){
  var box=document.getElementById('paletteList');
  if(!box)return;
  var h='';
  if(!PALETTE.items.length){h='<div class="palette-item" style="color:var(--sys-text-3)">'+(lang==='zh'?'没有匹配结果':'No matches')+'</div>'}
  PALETTE.items.forEach(function(it,i){
    h+='<div class="palette-item'+(i===PALETTE.idx?' active':'')+'" data-pi="'+i+'"><span class="pi-ic">'+(it.ic||'•')+'</span><span>'+esc(it.t)+'</span>'+(it.s?('<span class="pi-sub">'+esc(it.s)+'</span>'):'')+'</div>';
  });
  box.innerHTML=h;
  box.querySelectorAll('[data-pi]').forEach(function(el){
    el.onclick=function(){paletteRun(parseInt(el.getAttribute('data-pi'),10))};
    el.onmouseenter=function(){PALETTE.idx=parseInt(el.getAttribute('data-pi'),10);paletteRender()};
  });
  var act=box.querySelector('.palette-item.active');
  if(act&&act.scrollIntoView)try{act.scrollIntoView({block:'nearest'})}catch(e){}
}
function paletteFilter(q){
  var all=paletteCommands();
  q=String(q||'').trim().toLowerCase();
  if(!q){PALETTE.items=all.slice(0,12);PALETTE.idx=0;paletteRender();return}
  var hit=all.filter(function(c){return (c.t+' '+(c.s||'')).toLowerCase().indexOf(q)>=0});
  PALETTE.items=hit.slice(0,10);
  // 同时搜文件（防抖后走服务端搜索）
  var my=++PALETTE.seq;
  clearTimeout(PALETTE.timer);
  PALETTE.timer=setTimeout(function(){
    api('/api/search?q='+encodeURIComponent(q)+'&path=/&limit=8').then(function(d){
      if(my!==PALETTE.seq)return;
      var res=(d.results||[]).slice(0,8).map(function(r){
        return {ic:r.type==='dir'?'📁':getIcon(r),t:r.name,s:(r.path||''),file:r,
          run:function(){
            if(r.type==='dir'){cur=normP(r.path||'/')+r.name+'/';setMode('');load()}
            else doPreview(r.name,r.mime||'',-1,r.path||'/');
          }};
      });
      PALETTE.items=hit.slice(0,8).concat(res);
      PALETTE.idx=0;paletteRender();
    }).catch(function(){});
  },220);
  paletteRender();
}
function paletteRun(i){
  var it=PALETTE.items[i];
  if(!it)return;
  paletteClose();
  setTimeout(function(){try{it.run()}catch(e){console.warn(e)}},30);
}
function paletteOpen(){
  var m=paletteModal();if(!m)return;
  PALETTE.open=true;m.classList.add('show');
  var inp=document.getElementById('paletteInput');
  if(inp){inp.value='';inp.focus()}
  paletteFilter('');
}
function paletteClose(){
  var m=paletteModal();if(!m)return;
  PALETTE.open=false;m.classList.remove('show');
}
document.getElementById('btnPalette').onclick=function(){paletteOpen()};
document.getElementById('palette').onclick=function(e){if(e.target===this)paletteClose()};
document.getElementById('paletteInput').oninput=function(){paletteFilter(this.value)};
document.getElementById('paletteInput').onkeydown=function(e){
  if(e.key==='ArrowDown'){e.preventDefault();PALETTE.idx=Math.min(PALETTE.idx+1,PALETTE.items.length-1);paletteRender()}
  else if(e.key==='ArrowUp'){e.preventDefault();PALETTE.idx=Math.max(0,PALETTE.idx-1);paletteRender()}
  else if(e.key==='Enter'){e.preventDefault();paletteRun(PALETTE.idx)}
  else if(e.key==='Escape'){e.preventDefault();paletteClose()}
};

// ===== 视图切换 / 虚拟滚动 / 列视图 =====
var VIEWS=['grid','list','columns','gallery'];
function cycleView(){
  var i=VIEWS.indexOf(viewMode);
  viewMode=VIEWS[(i+1)%VIEWS.length];
  try{localStorage.setItem('dv',viewMode)}catch(e){}
  syncViewBtn();render();
}
function syncViewBtn(){
  var b=document.getElementById('btnView');
  if(!b)return;
  var zh=lang==='zh';
  b.textContent=viewMode==='grid'?(zh?'网格':'Grid'):viewMode==='list'?(zh?'列表':'List'):viewMode==='columns'?(zh?'列':'Columns'):(zh?'图库':'Gallery');
}
var VIRT={rowH:46,pad:10,scroll:0,id:'vscroll'};
function renderVirtualList(container,items,paint,bind){
  var total=items.length;
  var vis=Math.ceil(900/VIRT.rowH)+12;
  var start=Math.max(0,Math.floor(VIRT.scroll/VIRT.rowH)-4);
  var end=Math.min(total,start+vis);
  var h='<div class="vscroll" id="'+VIRT.id+'" style="height:100%">';
  h+='<div style="height:'+(start*VIRT.rowH)+'px"></div><ul class="file-list">';
  for(var i=start;i<end;i++)h+=paint(items[i],i);
  h+='</ul><div style="height:'+Math.max(0,(total-end)*VIRT.rowH)+'px"></div></div>';
  container.innerHTML=h;
  var sc=document.getElementById(VIRT.id);
  if(sc){
    sc.onscroll=function(){
      VIRT.scroll=sc.scrollTop;
      if(VIRT.ticking)return;
      VIRT.ticking=true;
      requestAnimationFrame(function(){
        VIRT.ticking=false;
        var s=Math.max(0,Math.floor(sc.scrollTop/VIRT.rowH)-4);
        if(Math.abs(s-Math.floor(VIRT.scroll/VIRT.rowH))<6)return;
        VIRT.scroll=sc.scrollTop;
        var keep=sc.scrollTop;
        renderVirtualList(container,items,paint,bind);
        var ns=document.getElementById(VIRT.id);
        if(ns)ns.scrollTop=keep;
      });
    };
  }
  bind();
}

// ===== 移动端手势（滑动返回 / 左滑多选 / 长按菜单 / 下拉刷新）=====
function bindGestures(container){
  var startX=0,startY=0,startT=0,row=null,moved=false;
  container.addEventListener('touchstart',function(e){
    if(!e.touches||e.touches.length!==1)return;
    var t=e.touches[0];
    startX=t.clientX;startY=t.clientY;startT=Date.now();moved=false;
    row=e.target.closest?e.target.closest('li,.gitem'):null;
    if(row&&row.__lp)clearTimeout(row.__lp);
    if(row){
      row.__lp=setTimeout(function(){
        if(moved||!row)return;
        var p=rowDir(row),n=row.getAttribute('data-n')||row.getAttribute('data-li')||'';
        showCtx(startX,startY,n,(row.getAttribute('data-p')!==null&&row.getAttribute('data-t'))||'file',row.getAttribute('data-m')||'',p);
        try{navigator.vibrate&&navigator.vibrate(10)}catch(e2){}
      },520);
    }
  },{passive:true});
  container.addEventListener('touchmove',function(e){
    if(!e.touches||e.touches.length!==1)return;
    var t=e.touches[0];
    if(Math.abs(t.clientX-startX)>12||Math.abs(t.clientY-startY)>12){moved=true;if(row&&row.__lp)clearTimeout(row.__lp)}
  },{passive:true});
  container.addEventListener('touchend',function(e){
    if(row&&row.__lp)clearTimeout(row.__lp);
    if(!e.changedTouches||!e.changedTouches.length)return;
    var t=e.changedTouches[0];
    var dx=t.clientX-startX,dy=t.clientY-startY,dt=Date.now()-startT;
    if(dt>700)return;
    if(Math.abs(dy)>Math.abs(dx))return;
    if(dx>70&&Math.abs(dy)<45){goParent();return}                  // 右滑 → 返回上级
    if(dx<-60&&Math.abs(dy)<45&&row){                              // 左滑 → 多选
      var cb=row.querySelector('[data-chk]');
      if(cb){cb.checked=!cb.checked;cb.dispatchEvent(new Event('change'))}
    }
  },{passive:true});
  // 下拉刷新
  var pull=0,pulling=false;
  container.addEventListener('touchstart',function(e){
    if(window.scrollY<=2&&e.touches&&e.touches.length===1){pulling=true;pull=e.touches[0].clientY}
  },{passive:true});
  container.addEventListener('touchmove',function(e){
    if(!pulling||!e.touches||!e.touches.length)return;
    var dy=e.touches[0].clientY-pull;
    if(dy>80){pulling=false;setMsgTouch(lang==='zh'?'正在刷新…':'Refreshing…');load()}
  },{passive:true});
  container.addEventListener('touchend',function(){pulling=false},{passive:true});
}
function setMsgTouch(txt){
  var el=document.getElementById('offlineBar');
  if(!el)return;
  el.style.display='block';el.textContent=txt;
  setTimeout(function(){checkOnline()},1200);
}
function goParent(){
  if(cur==='/')return;
  var parts=cur.split('/').filter(Boolean);parts.pop();
  cur=parts.length?'/'+parts.join('/')+'/':'/';
  setMode('');load();
}

// ===== 离线只读 =====
function checkOnline(){
  var bar=document.getElementById('offlineBar');
  if(!bar)return;
  if(navigator.onLine===false){
    bar.style.display='block';
    bar.textContent=(lang==='zh'?'📴 离线模式：仅可浏览（列表来自缓存，写入操作不可用）':'Offline: read-only (cached listing)');
  }else bar.style.display='none';
}
window.addEventListener('online',checkOnline);
window.addEventListener('offline',checkOnline);

// ===== 系统分享 → 上传（Web Share Target）=====
function bindShareTarget(){
  function pullShared(count){
    var n=parseInt(count,10)||0;
    if(!n)return;
    var files=[];var done=0;
    for(var i=0;i<n;i++){
      (function(i){
        fetch('/shared/'+i,{cache:'no-store'}).then(function(r){
          if(!r.ok)throw new Error('miss');
          var nm='shared-'+i;
          try{var raw=r.headers.get('X-File-Name');if(raw)nm=decodeURIComponent(raw)}catch(e){}
          return r.blob().then(function(b){return new File([b],nm,{type:b.type||'application/octet-stream'})});
        }).then(function(f){files.push(f)}).catch(function(){}).then(function(){
          if(++done===n&&files.length)uploadFiles(files,cur);
        });
      })(i);
    }
  }
  if(navigator.serviceWorker&&navigator.serviceWorker.addEventListener){
    navigator.serviceWorker.addEventListener('message',function(e){
      if(e.data&&e.data.type==='shared-files')pullShared(e.data.count);
    });
  }
  try{
    var m=/[?&]shared=(\\d+)/.exec(location.search);
    if(m&&parseInt(m[1],10)>0){pullShared(m[1]);try{history.replaceState(null,'',location.pathname)}catch(e){}}
  }catch(e){}
}
bindShareTarget();
checkOnline();

// ===== 相似图片（感知哈希 dHash + 汉明距离分组）=====
function dHashFromBlob(blob){
  return createImageBitmap(blob).then(function(bmp){
    var w=9,h=8;
    var c=document.createElement('canvas');c.width=w;c.height=h;
    var ctx=c.getContext('2d');
    ctx.drawImage(bmp,0,0,w,h);
    var d=ctx.getImageData(0,0,w,h).data,bits='';
    for(var y=0;y<h;y++){
      for(var x=0;x<w-1;x++){
        var i=(y*w+x)*4,j=(y*w+x+1)*4;
        var a=0.299*d[i]+0.587*d[i+1]+0.114*d[i+2];
        var b=0.299*d[j]+0.587*d[j+1]+0.114*d[j+2];
        bits+=(a>b)?'1':'0';
      }
    }
    var hex='';
    for(var k=0;k<64;k+=4)hex+=parseInt(bits.substr(k,4),2).toString(16);
    try{if(bmp.close)bmp.close()}catch(e){}
    return hex;
  });
}
function phDistance(a,b){
  if(!a||!b||a.length!==b.length)return 99;
  var n=0;
  for(var i=0;i<a.length;i++){
    var x=parseInt(a[i],16)^parseInt(b[i],16);
    while(x){n+=x&1;x>>=1}
  }
  return n;
}
function imgUrl(p){return '/api/thumb?path='+encodeURIComponent(p)+'&token='+tk}
function simModal(){
  var m=document.getElementById('simModal');
  if(!m){
    m=document.createElement('div');m.id='simModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:460px;max-width:820px"><button class="mclose" id="simClose">✕</button><h3>🖼 '+(lang==='zh'?'相似图片':'Similar images')+'</h3><div id="simContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('simClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showSimilar(){
  var m=simModal(),box=document.getElementById('simContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'正在分析当前目录的图片…':'Analyzing images…')+'</p>';
  m.classList.add('show');
  var threshold=parseInt(localStorage.getItem('dSimTh')||'8',10)||8;
  api('/api/media?path='+encodeURIComponent(cur)+'&kind=image&limit=800').then(function(d){
    var items=(d.items||[]).filter(function(it){return it.mime&&it.mime.indexOf('image/')===0});
    if(!items.length){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'当前目录没有图片（可先进入含图片的目录）':'No images in this folder')+'</p>';return}
    function render(autoIndex){
      var indexed=items.filter(function(it){return it.ph});
      var groups=[];
      indexed.forEach(function(it){
        var placed=false;
        for(var g=0;g<groups.length;g++){
          if(phDistance(groups[g][0].ph,it.ph)<=threshold){groups[g].push(it);placed=true;break}
        }
        if(!placed)groups.push([it]);
      });
      var multi=groups.filter(function(g){return g.length>1});
      var h='<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">'
        +'<span class="dup-path">'+(lang==='zh'?'相似阈值（越小越严格）':'Threshold')+'</span>'
        +'<input id="simTh" type="number" min="0" max="20" value="'+threshold+'" style="width:70px;padding:5px 8px">'
        +'<button id="simApply" class="btn gray tiny">'+(lang==='zh'?'重新分组':'Re-group')+'</button>'
        +'<span style="flex:1"></span><span class="dup-path" id="simStat">'+indexed.length+'/'+items.length+' '+(lang==='zh'?'张已建索引':'indexed')+'</span>'
        +'<button id="simIndex" class="btn tiny">'+(lang==='zh'?'为剩余图片建索引':'Index rest')+'</button></div>';
      if(!multi.length)h+='<p style="text-align:center;color:var(--sys-text-3);padding:14px">'+(lang==='zh'?'没有发现相似图片':'No similar images found')+'</p>';
      multi.forEach(function(g){
        h+='<div style="margin-bottom:14px;padding:10px;background:var(--sys-fill);border-radius:12px">';
        h+='<div class="dup-path" style="margin-bottom:6px">'+g.length+' '+(lang==='zh'?'张相似':'similar')+'</div>';
        h+='<div style="display:flex;gap:8px;flex-wrap:wrap">';
        g.forEach(function(it){
          h+='<div style="width:118px"><img src="'+imgUrl(it.k)+'" loading="lazy" style="width:118px;height:92px;object-fit:cover;border-radius:8px;background:var(--sys-fill-2)">'
            +'<div style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(it.name)+'">'+esc(it.name)+'</div>'
            +'<div class="dup-path" style="font-size:10.5px">'+fmt(it.size)+'</div>'
            +'<button class="btn tiny danger" data-simdel="'+esc(it.k)+'" style="margin-top:2px">'+(lang==='zh'?'删除':'Del')+'</button></div>';
        });
        h+='</div></div>';
      });
      box.innerHTML=h;
      var ap=document.getElementById('simApply');
      if(ap)ap.onclick=function(){threshold=Math.max(0,Math.min(20,parseInt(document.getElementById('simTh').value,10)||0));try{localStorage.setItem('dSimTh',String(threshold))}catch(e){}render(false)};
      var ix=document.getElementById('simIndex');
      if(ix)ix.onclick=function(){indexMissing(items,render)};
      box.querySelectorAll('[data-simdel]').forEach(function(b){b.onclick=function(){
        var k=b.getAttribute('data-simdel');
        if(!confirm((lang==='zh'?'删除 ':'Delete ')+k+'?'))return;
        api('/api/delete?path='+encodeURIComponent('/'+k),{method:'DELETE'}).then(function(){load();showSimilar()});
      }});
      if(autoIndex&&indexed.length<items.length)indexMissing(items,render);
    }
    render(true);
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
// 为缺少 ph 的图片补算感知哈希（每次最多 30 张，避免一次跑太久）
function indexMissing(items,render){
  var todo=items.filter(function(it){return !it.ph}).slice(0,30);
  if(!todo.length)return;
  var stat=document.getElementById('simStat');
  var done=0;
  function step(){
    if(done>=todo.length){render(false);return}
    var it=todo[done++];
    fetch('/api/preview?path='+encodeURIComponent('/'+it.k)+'&token='+tk)
      .then(function(r){return r.blob()})
      .then(function(b){return dHashFromBlob(b)})
      .then(function(hh){return api('/api/phash',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:'/'+it.k,hash:hh})})})
      .then(function(){it.ph='1';if(stat)stat.textContent=(lang==='zh'?'建索引 ':'indexing ')+done+'/'+todo.length})
      .catch(function(){it.ph='skip'})
      .then(function(){setTimeout(step,20)});
  }
  step();
}

// ===== 图片批处理（缩放 / 压缩 / 水印 / 旋转）=====
function imgToolsModal(){
  var m=document.getElementById('imgToolsModal');
  if(!m){
    m=document.createElement('div');m.id='imgToolsModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:420px;max-width:640px"><button class="mclose" id="imgToolsClose">✕</button><h3>🖌 '+(lang==='zh'?'图片批处理':'Image tools')+'</h3><div id="imgToolsContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('imgToolsClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showImgTools(){
  var m=imgToolsModal(),box=document.getElementById('imgToolsContent');
  var sel=Object.keys(selected);
  var imgs=sel.filter(function(p){return /\\.(jpe?g|png|webp|gif|bmp|avif)$/i.test(p)});
  var h='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'已选 ':'Selected ')+sel.length+' · '+(lang==='zh'?'其中图片 ':'images ')+imgs.length+'</div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'最大边长 (px，0=不改)':'Max edge (px)')+'</span><input id="itEdge" type="number" value="2048" style="flex:1;padding:6px 10px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'JPEG 质量 (1-100)':'Quality')+'</span><input id="itQ" type="number" value="82" style="flex:1;padding:6px 10px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'旋转角度':'Rotate')+'</span><select id="itRot" style="flex:1;padding:6px 10px"><option value="0">0°</option><option value="90">90°</option><option value="180">180°</option><option value="270">270°</option></select></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'水印文字（可空）':'Watermark text')+'</span><input id="itWm" placeholder="© your name" style="flex:1;padding:6px 10px"></div>';
  h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'水印位置':'Watermark pos')+'</span><select id="itWmPos" style="flex:1;padding:6px 10px"><option value="br">'+(lang==='zh'?'右下':'bottom-right')+'</option><option value="bl">'+(lang==='zh'?'左下':'bottom-left')+'</option><option value="tr">'+(lang==='zh'?'右上':'top-right')+'</option><option value="center">'+(lang==='zh'?'居中':'center')+'</option></select></div>';
  h+='<label style="display:flex;gap:8px;align-items:center;margin:8px 0;font-size:13.5px"><input type="checkbox" id="itCopy" checked>'+(lang==='zh'?'另存为副本（-edit 后缀），不覆盖原图':'Save as copy (-edit)')+'</label>';
  h+='<div id="itMsg" style="font-size:13px;min-height:18px"></div>';
  h+='<div style="text-align:right"><button id="itRun" class="btn small" '+(imgs.length?'':'disabled')+'>'+(lang==='zh'?'开始处理':'Run')+'</button></div>';
  box.innerHTML=h;
  m.classList.add('show');
  document.getElementById('itRun').onclick=function(){runImgTools(imgs)};
}
async function runImgTools(paths){
  if(!paths||!paths.length)return;
  var edge=parseInt(document.getElementById('itEdge').value,10)||0;
  var q=Math.max(1,Math.min(100,parseInt(document.getElementById('itQ').value,10)||82))/100;
  var rot=parseInt(document.getElementById('itRot').value,10)||0;
  var wm=(document.getElementById('itWm').value||'').trim();
  var wpos=document.getElementById('itWmPos').value;
  var asCopy=document.getElementById('itCopy').checked;
  var msg=document.getElementById('itMsg');
  var ok=0,fail=0;
  for(var i=0;i<paths.length;i++){
    var p=paths[i];
    var div=makeUpItem(p.split('/').filter(Boolean).pop());
    div.querySelector('.upst').textContent='…';
    try{
      var r=await fetch('/api/preview?path='+encodeURIComponent(p)+'&token='+tk);
      if(!r.ok)throw new Error('HTTP '+r.status);
      var blob=await r.blob();
      var bmp=await createImageBitmap(blob);
      var w=bmp.width,hgt=bmp.height;
      if(edge>0&&Math.max(w,hgt)>edge){var s=edge/Math.max(w,hgt);w=Math.round(w*s);hgt=Math.round(hgt*s)}
      var canvas=document.createElement('canvas');
      if(rot===90||rot===270){canvas.width=hgt;canvas.height=w}else{canvas.width=w;canvas.height=hgt}
      var ctx=canvas.getContext('2d');
      ctx.save();
      if(rot===90){ctx.translate(canvas.width,0);ctx.rotate(Math.PI/2)}
      else if(rot===180){ctx.translate(canvas.width,canvas.height);ctx.rotate(Math.PI)}
      else if(rot===270){ctx.translate(0,canvas.height);ctx.rotate(-Math.PI/2)}
      ctx.drawImage(bmp,0,0,w,hgt);
      ctx.restore();
      if(wm){
        var fs=Math.max(12,Math.round(Math.min(canvas.width,canvas.height)/22));
        ctx.font='600 '+fs+'px -apple-system,system-ui,sans-serif';
        ctx.fillStyle='rgba(255,255,255,0.82)';
        ctx.shadowColor='rgba(0,0,0,0.5)';ctx.shadowBlur=6;
        var tw=ctx.measureText(wm).width,pad=Math.round(fs*0.6);
        var x=canvas.width-tw-pad,y=canvas.height-pad;
        if(wpos==='bl')x=pad;
        else if(wpos==='tr')y=fs+pad;
        else if(wpos==='center'){x=(canvas.width-tw)/2;y=canvas.height/2}
        ctx.fillText(wm,x,y);
      }
      var out=await new Promise(function(res){canvas.toBlob(res,'image/jpeg',q)});
      if(!out)throw new Error('encode failed');
      var dir=parentOf(p),name=p.split('/').filter(Boolean).pop();
      var finalName=asCopy?name.replace(/(\\.[^.]+)$/,'-edit$1'):name;
      var fd=new FormData();
      fd.append('file',new File([out],finalName,{type:'image/jpeg'}));
      await new Promise(function(res,rej){
        var xhr=new XMLHttpRequest();
        xhr.open('POST','/api/upload?path='+encodeURIComponent(dir)+'&token='+tk);
        xhr.upload.onprogress=function(e){if(e.lengthComputable)div.querySelector('.upfill').style.width=Math.round(e.loaded/e.total*100)+'%'};
        xhr.onload=function(){if(xhr.status>=200&&xhr.status<300)res();else rej(new Error('HTTP '+xhr.status))};
        xhr.onerror=function(){rej(new Error('network'))};
        xhr.send(fd);
      });
      div.querySelector('.upfill').style.width='100%';
      div.querySelector('.upst').textContent=t('upDone');
      div.querySelector('.upst').style.color='var(--sys-green)';
      ok++;
    }catch(e){
      div.querySelector('.upst').textContent=(e&&e.message)||t('upFail');
      div.querySelector('.upst').style.color='var(--sys-red)';
      fail++;
    }
    if(msg)msg.textContent=(ok+fail)+'/'+paths.length;
    setTimeout(function(){if(div.parentNode)div.parentNode.removeChild(div)},2500);
  }
  if(msg){msg.style.color=fail?'var(--sys-red)':'var(--sys-green)';msg.textContent=(lang==='zh'?'完成 ':'done ')+ok+(fail?(' / '+(lang==='zh'?'失败 ':'failed ')+fail):'')}
  load();
}

// ===== 收藏分组 =====
function favGroupsModal(){
  var m=document.getElementById('favgModal');
  if(!m){
    m=document.createElement('div');m.id='favgModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:440px;max-width:680px"><button class="mclose" id="favgClose">✕</button><h3 id="favgTitle">★ '+(lang==='zh'?'收藏分组':'Favorite groups')+'</h3><div id="favgContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('favgClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showFavGroups(){
  var m=favGroupsModal(),box=document.getElementById('favgContent');
  document.getElementById('favgTitle').textContent='★ '+(lang==='zh'?'收藏分组':'Favorite groups');
  m.classList.add('show');
  function paint(){
    api('/api/favgroups').then(function(d){
      var groups=d.groups||[];
      var h='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'共 ':'total ')+(d.total||0)+' ★ · '+(lang==='zh'?'未分组 ':'ungrouped ')+((d.ungrouped||[]).length)+'</div>';
      h+='<div style="display:flex;gap:6px;margin-bottom:10px"><input id="fgName" placeholder="'+(lang==='zh'?'新分组名称':'New group name')+'" style="flex:1;padding:7px 10px"><button id="fgAdd" class="btn small">'+(lang==='zh'?'新建':'Create')+'</button></div>';
      groups.forEach(function(g){
        h+='<div style="margin-bottom:12px;background:var(--sys-fill);border-radius:12px;padding:10px">';
        h+='<div style="display:flex;gap:6px;align-items:center"><input value="'+esc(g.name)+'" data-fgrnm="'+esc(g.name)+'" style="width:150px;padding:5px 8px"><span class="dup-path" style="flex:1">'+(g.paths||[]).length+'</span>'
          +'<button class="btn gray tiny" data-fgrn="'+esc(g.name)+'">'+(lang==='zh'?'重命名':'Rename')+'</button>'
          +'<button class="btn tiny danger" data-fgrd="'+esc(g.name)+'">✕</button></div>';
        (g.paths||[]).slice(0,40).forEach(function(p){
          h+='<div class="token-row" style="padding:4px 0"><span class="dup-path" style="flex:1;overflow:hidden;text-overflow:ellipsis">'+esc(p)+'</span>'
            +'<button class="btn tiny" data-fgo="'+esc(p)+'">'+(lang==='zh'?'打开':'Open')+'</button>'
            +'<button class="btn tiny danger" data-fgr="'+esc(p)+'">✕</button></div>';
        });
        h+='</div>';
      });
      if((d.ungrouped||[]).length){
        h+='<div style="margin-bottom:8px;font-size:13px;font-weight:600">'+(lang==='zh'?'未分组收藏':'Ungrouped')+'</div>';
        (d.ungrouped||[]).slice(0,40).forEach(function(p){
          h+='<div class="token-row" style="padding:4px 0"><span class="dup-path" style="flex:1;overflow:hidden;text-overflow:ellipsis">'+esc(p)+'</span>'
            +'<input data-fgassign="'+esc(p)+'" placeholder="'+(lang==='zh'?'分到…':'group…')+'" style="width:110px;padding:4px 8px"></div>';
        });
      }
      box.innerHTML=h;
      document.getElementById('fgAdd').onclick=function(){
        var n=document.getElementById('fgName').value.trim();if(!n)return;
        api('/api/favgroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(paint);
      };
      box.querySelectorAll('[data-fgrd]').forEach(function(b){b.onclick=function(){api('/api/favgroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({delete:b.getAttribute('data-fgrd')})}).then(paint)}});
      box.querySelectorAll('[data-fgrn]').forEach(function(b){b.onclick=function(){
        var from=b.getAttribute('data-fgrn');
        var inp=box.querySelector('[data-fgrnm="'+from+'"]');
        var to=inp?inp.value.trim():'';
        if(!to||to===from)return;
        api('/api/favgroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({renameFrom:from,renameTo:to})}).then(paint);
      }});
      box.querySelectorAll('[data-fgr]').forEach(function(b){b.onclick=function(){
        api('/api/favgroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({setPath:b.getAttribute('data-fgr'),group:''})}).then(paint);
      }});
      box.querySelectorAll('[data-fgo]').forEach(function(b){b.onclick=function(){
        var p=b.getAttribute('data-fgo');
        var dir=p.substring(0,p.lastIndexOf('/')+1)||'/';
        cur=dir;QUERY.on=false;setMode('');load();m.classList.remove('show');
      }});
      box.querySelectorAll('[data-fgassign]').forEach(function(inp){
        function commit(){
          var g=inp.value.trim();if(!g)return;
          api('/api/favgroups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({setPath:inp.getAttribute('data-fgassign'),group:g})}).then(paint);
        }
        inp.onchange=commit;
        inp.onkeydown=function(e){if(e.key==='Enter')commit()};
      });
    }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
  }
  paint();
}

// ===== 元数据导出 / 导入 =====
function showMetaIO(){
  var m=favGroupsModal(),box=document.getElementById('favgContent');
  document.getElementById('favgTitle').textContent='🏷 '+(lang==='zh'?'元数据导出 / 导入':'Metadata export / import');
  m.classList.add('show');
  var h='<div style="font-size:12.5px;color:var(--sys-text-3);line-height:1.7;margin-bottom:10px">'
    +'<b>'+(lang==='zh'?'导出':'Export')+'</b>：'+(lang==='zh'?'把当前目录（含子目录）的标签、备注、收藏、大小/时间等元数据导出为 JSON 或 CSV（不含文件内容）。':'Exports tags/notes/favorites/size/time as JSON or CSV (no file contents).')+'<br>'
    +'<b>'+(lang==='zh'?'导入':'Import')+'</b>：'+(lang==='zh'?'把 JSON 元数据套用到现有文件（仅匹配已存在的文件，可合并或覆盖标签）。':'Applies JSON metadata to existing files only.')+'</div>';
  h+='<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">'
    +'<button id="miJson" class="btn small">⬇ JSON</button>'
    +'<button id="miCsv" class="btn gray small">⬇ CSV</button>'
    +'<button id="miImp" class="btn gray small">⬆ '+(lang==='zh'?'导入 JSON':'Import JSON')+'</button>'
    +'<select id="miMode" style="padding:6px 8px"><option value="merge">'+(lang==='zh'?'合并标签':'merge tags')+'</option><option value="replace">'+(lang==='zh'?'覆盖标签':'replace tags')+'</option></select>'
    +'<input id="miFile" type="file" accept=".json,application/json" style="display:none">'
    +'</div><div id="miOut" style="font-size:13px;max-height:44vh;overflow:auto"></div>';
  box.innerHTML=h;
  document.getElementById('miJson').onclick=function(){window.open('/api/export-meta?path='+encodeURIComponent(cur)+'&format=download&token='+tk,'_blank')};
  document.getElementById('miCsv').onclick=function(){window.open('/api/export-meta?path='+encodeURIComponent(cur)+'&format=csv&token='+tk,'_blank')};
  var fi=document.getElementById('miFile');
  document.getElementById('miImp').onclick=function(){fi.click()};
  fi.onchange=function(){
    var f=fi.files&&fi.files[0];if(!f)return;
    var out=document.getElementById('miOut');
    out.textContent='…';
    var rd=new FileReader();
    rd.onload=function(){
      var payload=null;
      try{payload=JSON.parse(rd.result)}catch(e){out.textContent=(lang==='zh'?'JSON 解析失败':'Bad JSON');return}
      api('/api/import-meta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:payload,mode:document.getElementById('miMode').value})}).then(function(r){
        if(r&&r.ok){
          out.innerHTML='<div style="color:var(--sys-green)">'+(lang==='zh'?'导入完成':'Imported')+'</div>'
            +'<div class="dup-path">'+(lang==='zh'?'匹配 ':'matched ')+r.matched+' · '+(lang==='zh'?'缺失 ':'missing ')+r.missing+' · '+(lang==='zh'?'标签写入 ':'tags ')+r.tagsWritten+' · '+(lang==='zh'?'备注写入 ':'notes ')+r.notesWritten+' · ★ '+r.favAdded+'</div>';
          load();renderTagSidebar();
        }else out.textContent=(r&&r.error)||'failed';
      });
    };
    rd.readAsText(f);
  };
}

var UQ=[], upSeq=0;
function upConcurrency(){var n=parseInt(localStorage.getItem('dUpConc')||'',10);return (n>=1&&n<=6)?n:2}
function setUpConcurrency(n){try{localStorage.setItem('dUpConc',String(n))}catch(e){}renderQueueBar();pump()}
function taskOf(div){for(var i=0;i<UQ.length;i++)if(UQ[i].div===div)return UQ[i];return null}
function uploadFiles(files,dir){
  if(!files||!files.length)return;
  dir=dir||cur;
  if(currentView==='home'){cur=dir;goFiles('files');setMode('');load()}   // 从仪表盘发起上传：跳到文件页看进度与落点
  for(var i=0;i<files.length;i++){
    var f=files[i];
    var task={id:'u'+(++upSeq),file:f,name:f.name,size:f.size,dir:dir,relPath:f._relPath||'',status:'waiting',progress:0,div:null,thumb:null,uploadId:null,msg:'',prepared:false};
    makeUpItem(task);
    UQ.push(task);
  }
  renderQueueBar();pump();
}
function pump(){
  var active=0,i;
  for(i=0;i<UQ.length;i++)if(UQ[i].status==='uploading')active++;
  var conc=upConcurrency();
  for(i=0;i<UQ.length&&active<conc;i++){
    if(UQ[i].status==='waiting'){runTask(UQ[i]);active++}
  }
  renderQueueBar();
}
async function runTask(task){
  if(task.status!=='waiting')return;
  task.status='uploading';task.msg='';paintTask(task);renderQueueBar();
  try{
    var file=task.file;
    if(!task.prepared){
      if(file.type&&file.type.indexOf('image/')===0){try{file=await compressImage(file)}catch(e){}}
      if(task.status!=='uploading'){finishTask(task,'paused');return}
      var th=null;try{th=await makeThumb(file)}catch(e){}
      task.workFile=file;task.thumb=th;task.prepared=true;
      if(task.status!=='uploading'){finishTask(task,'paused');return}
    }
    file=task.workFile||file;
    if(file.size>CHUNK_SIZE)await uploadChunked(task,file);
    else await uploadSimple(task,file);
  }catch(e){
    if(task.status==='uploading'){task.status='failed';task.msg=(e&&e.taskMsg)||(e&&e.message)||t('upFail')}
  }
  if(task.status==='uploading')task.status='done';
  finishTask(task,task.status);
}
function finishTask(task,status){
  if(status)task.status=status;
  paintTask(task);renderQueueBar();
  if(task.status==='done'){
    setTimeout(function(){removeTask(task)},1800);
    var more=UQ.some(function(x){return (x.status==='uploading'||x.status==='waiting')&&x!==task});
    if(!more)setTimeout(load,400);
  }
}
function removeTask(task){
  for(var i=0;i<UQ.length;i++)if(UQ[i]===task)UQ.splice(i,1);
  if(task.div&&task.div.parentNode)task.div.parentNode.removeChild(task.div);
  renderQueueBar();
}
function pauseTask(task){
  if(task.status==='waiting'||task.status==='uploading'){
    task.status='paused';
    if(task.xhr){try{task.xhr.abort()}catch(e){}}
    paintTask(task);renderQueueBar();
  }
}
function resumeTask(task){
  if(task.status==='paused'||task.status==='failed'){task.status='waiting';task.msg='';paintTask(task);pump()}
}
function cancelTask(task){
  task.canceled=true;task.status='canceled';
  if(task.xhr){try{task.xhr.abort()}catch(e){}}
  removeTask(task);
}
function renderTaskActs(task){
  var box=task.div?task.div.querySelector('.upacts'):null;if(!box)return;
  var st=task.status,h='';
  if(st==='uploading'||st==='waiting')h+='<button data-act="pause" title="'+t('pause')+'">⏸</button>';
  if(st==='paused'||st==='failed')h+='<button data-act="resume" title="'+t('resume')+'">▶</button>';
  if(st==='failed')h+='<button data-act="retry" title="'+t('retry')+'">↻</button>';
  if(st!=='done')h+='<button data-act="cancel" title="'+t('cancel')+'">✕</button>';
  box.innerHTML=h;
  box.querySelectorAll('[data-act]').forEach(function(b){
    b.onclick=function(e){
      e.stopPropagation();
      var a=b.getAttribute('data-act');
      if(a==='pause')pauseTask(task);
      else if(a==='resume')resumeTask(task);
      else if(a==='retry')resumeTask(task);
      else if(a==='cancel')cancelTask(task);
    };
  });
}
function paintTask(task){
  if(!task.div)return;
  var fill=task.div.querySelector('.upfill'),st=task.div.querySelector('.upst');
  if(fill)fill.style.width=(task.progress||0)+'%';
  if(st){
    if(task.status==='waiting')st.textContent=t('upQueue')+'…';
    else if(task.status==='paused')st.textContent=t('pause');
    else if(task.status==='failed')st.textContent=task.msg||t('upFail');
    else if(task.status==='done')st.textContent=t('upDone');
    else st.textContent=(task.progress||0)+'%';
    st.style.color=task.status==='failed'?'var(--sys-red)':(task.status==='done'?'var(--sys-green)':'');
  }
  renderTaskActs(task);
}
function renderQueueBar(){
  var bar=document.getElementById('upQueueBar');if(!bar)return;
  var waiting=0,active=0,paused=0,failed=0;
  UQ.forEach(function(x){
    if(x.status==='waiting')waiting++;else if(x.status==='uploading')active++;
    else if(x.status==='paused')paused++;else if(x.status==='failed')failed++;
  });
  uploadQueue=waiting+active+paused;
  if(!UQ.length){bar.innerHTML='';bar.style.display='none';return}
  var h='<span class="upq-t">'+t('upQueue')+' · '+active+'/'+(waiting+paused)+(failed?(' · <span style="color:var(--sys-red)">'+t('upFail')+' '+failed+'</span>'):'')+'</span>';
  h+='<span style="flex:1"></span>';
  h+='<label class="upq-l">'+t('conc')+' <select id="upConcSel">'+[1,2,3,4,5,6].map(function(n){return '<option value="'+n+'"'+(n===upConcurrency()?' selected':'')+'>'+n+'</option>'}).join('')+'</select></label>';
  h+='<button id="upPauseAll" class="btn gray tiny">'+t('pauseAll')+'</button>';
  h+='<button id="upResumeAll" class="btn gray tiny">'+t('resumeAll')+'</button>';
  h+='<button id="upClearDone" class="btn gray tiny">'+t('clearDone')+'</button>';
  bar.innerHTML=h;bar.style.display='flex';
  var sel=document.getElementById('upConcSel');if(sel)sel.onchange=function(){setUpConcurrency(parseInt(sel.value,10)||2)};
  var pa=document.getElementById('upPauseAll');if(pa)pa.onclick=function(){UQ.forEach(function(x){if(x.status==='waiting'||x.status==='uploading')pauseTask(x)})};
  var ra=document.getElementById('upResumeAll');if(ra)ra.onclick=function(){UQ.forEach(function(x){if(x.status==='paused'||x.status==='failed')resumeTask(x)})};
  var cd=document.getElementById('upClearDone');if(cd)cd.onclick=function(){UQ.filter(function(x){return x.status==='done'||x.status==='failed'}).forEach(removeTask)};
}
function makeUpItem(x){
  var task=(x&&typeof x==='object')?x:null;
  var name=task?task.name:String(x==null?'':x);
  var list=document.getElementById('upList');
  var div=document.createElement('div');div.className='upitem';
  div.innerHTML='<span class="upname">'+esc(name)+'</span><div class="upbar"><div class="upfill" style="width:0%"></div></div><span class="upst">0%</span><span class="upacts"></span>';
  list.appendChild(div);
  if(task){task.div=div;paintTask(task)}
  return div;
}
function setProgress(div,pct){
  var task=taskOf(div);
  if(task){task.progress=pct;paintTask(task);return}
  if(!div)return;
  var f=div.querySelector('.upfill'),s=div.querySelector('.upst');
  if(f)f.style.width=pct+'%';
  if(s)s.textContent=pct+'%';
}
function setDone(div){
  var task=taskOf(div);
  if(task){task.progress=100;finishTask(task,'done');return}
  if(!div)return;
  var f=div.querySelector('.upfill'),s=div.querySelector('.upst');
  if(f)f.style.width='100%';
  if(s){s.textContent=t('upDone');s.style.color='var(--sys-green)'}
  setTimeout(function(){if(div.parentNode)div.parentNode.removeChild(div)},1500);
  load();
}
function setFail(div,msg){
  var task=taskOf(div);
  if(task){task.msg=msg||t('upFail');finishTask(task,'failed');return}
  if(!div)return;
  var s=div.querySelector('.upst');
  if(s){s.textContent=msg||t('upFail');s.style.color='var(--sys-red)'}
}
// ===== 秒传 / 断点续传 =====
async function sha256File(file){
  if(!file||file.size>64*1024*1024)return '';
  try{
    var buf=await file.arrayBuffer();
    var h=await crypto.subtle.digest('SHA-256',buf);
    return Array.from(new Uint8Array(h)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
  }catch(e){return ''}
}
function pendList(){try{return JSON.parse(localStorage.getItem('du_pending')||'[]')}catch(e){return[]}}
function pendSave(l){try{localStorage.setItem('du_pending',JSON.stringify(l.slice(-20)))}catch(e){}}
function pendFind(file,dir){var l=pendList(),t=Date.now();for(var i=0;i<l.length;i++){var p=l[i];if(p.name===file.name&&p.size===file.size&&p.dir===dir&&(t-p.ts<86400000))return p}return null}
function pendAdd(rec){var l=pendList().filter(function(p){return p.uploadId!==rec.uploadId});l.push(rec);pendSave(l)}
function pendRemove(id){pendSave(pendList().filter(function(p){return p.uploadId!==id}))}
function pendPrune(){var t=Date.now();var l=pendList().filter(function(p){return p&&p.uploadId&&(t-(p.ts||0)<86400000)});pendSave(l);return l}
function showPending(){
  var l=pendPrune();
  var box=document.getElementById('pendBox');
  if(!l.length){alert(lang==='zh'?'没有未完成的上传记录':'No pending uploads');return}
  var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:8px">'+t('resumeTitle')+'</div>';
  l.forEach(function(p){
    h+='<div class="token-row"><span class="token-name">'+esc(p.name)+'</span><span class="dup-path">'+fmt(p.size)+' · '+esc(new Date(p.ts).toLocaleString())+'</span></div>';
  });
  h+='<div style="margin-top:12px;text-align:right"><button id="pendClear" class="btn danger small">'+t('clearPend')+'</button></div>';
  if(!box){box=document.createElement('div');box.id='pendBox';box.className='modal-bg';box.innerHTML='<div class="modal" style="min-width:340px;max-width:520px"><button class="mclose" id="pendClose">✕</button><h3>'+t('resumeTitle')+'</h3><div id="pendContent"></div></div>';document.body.appendChild(box);}
  document.getElementById('pendContent').innerHTML=h;
  box.classList.add('show');
  document.getElementById('pendClose').onclick=function(){box.classList.remove('show')};
  document.getElementById('pendClear').onclick=function(){try{localStorage.removeItem('du_pending')}catch(e){}box.classList.remove('show');renderQueueBar()};
}
async function uploadSimple(task,file){
  var hash=await sha256File(file);
  if(hash){
    try{
      var ic=await api('/api/instant-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hash:hash,name:file.name,size:file.size,dir:task.dir})});
      if(ic&&ic.hit){task.progress=100;return}
    }catch(e){}
  }
  if(task.status!=='uploading')return;
  var fd=new FormData();fd.append('file',file);
  if(task.thumb)fd.append('thumb',task.thumb,'thumb.jpg');
  if(task.relPath)fd.append('relPath',task.relPath);
  if(hash)fd.append('hash',hash);
  await new Promise(function(resolve,reject){
    var xhr=new XMLHttpRequest();task.xhr=xhr;
    xhr.open('POST','/api/upload?path='+encodeURIComponent(task.dir)+'&token='+tk);
    xhr.upload.onprogress=function(e){if(e.lengthComputable){task.progress=Math.round(e.loaded/e.total*100);paintTask(task)}};
    xhr.onload=function(){
      task.xhr=null;
      if(task.status!=='uploading'){resolve();return}
      if(xhr.status>=200&&xhr.status<300){task.progress=100;resolve();return}
      var msg=t('upFail');
      if(xhr.status===423)msg=t('upLocked');
      else if(xhr.status===413)msg=(lang==='zh'?'超出配额或文件过大':'Quota or size limit');
      else if(xhr.status===507)msg=(lang==='zh'?'目录已满':'Directory full');
      var err=new Error(msg);err.taskMsg=msg;reject(err);
    };
    xhr.onerror=function(){task.xhr=null;if(task.status==='uploading'){var e=new Error(t('upFail'));e.taskMsg=t('upFail');reject(e)}else resolve()};
    xhr.onabort=function(){task.xhr=null;resolve()};
    xhr.send(fd);
  });
}
async function uploadChunked(task,file){
  var totalChunks=Math.ceil(file.size/CHUNK_SIZE);
  var hash=await sha256File(file);
  var uploadId=null,got=[];
  var pend=pendFind(file,task.dir);
  if(pend){
    try{
      var st=await api('/api/chunk-status?id='+encodeURIComponent(pend.uploadId));
      if(st&&st.chunks){uploadId=pend.uploadId;got=st.got||[]}
      else pendRemove(pend.uploadId);
    }catch(e){}
  }
  if(task.status!=='uploading')return;
  if(!uploadId){
    var init=await api('/api/chunk-init',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fileName:file.name,totalSize:file.size,hash:hash,path:task.dir,mime:file.type})});
    if(init.instant){task.progress=100;return}
    if(!init.uploadId)throw new Error(t('upFail'));
    uploadId=init.uploadId;
    pendAdd({uploadId:uploadId,name:file.name,size:file.size,dir:task.dir,ts:Date.now()});
  }
  task.uploadId=uploadId;
  var gotSet={};got.forEach(function(i){gotSet[i]=1});
  var CONC=Math.min(4,totalChunks);
  var next=0,doneCount=got.length,aborted=false;
  task.progress=Math.round(doneCount/totalChunks*100);paintTask(task);
  async function worker(){
    while(true){
      if(aborted||task.status!=='uploading'){aborted=true;return}
      var i=next++;
      if(i>=totalChunks)return;
      if(gotSet[i])continue;
      var chunk=file.slice(i*CHUNK_SIZE,(i+1)*CHUNK_SIZE);
      var r=await fetch('/api/chunk-upload/'+uploadId+'/'+i+'?token='+tk,{method:'POST',body:chunk});
      if(!r.ok){aborted=true;var e=new Error('chunk '+i+' HTTP '+r.status);e.taskMsg=t('upFail');throw e}
      doneCount++;task.progress=Math.round(doneCount/totalChunks*100);paintTask(task);
    }
  }
  var workers=[];for(var w=0;w<CONC;w++)workers.push(worker());
  try{await Promise.all(workers)}catch(e){if(task.status==='uploading')throw e;return}
  if(task.status!=='uploading')return;   // 暂停：保留断点记录，继续时从已收分片续传
  var done=await api('/api/chunk-complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uploadId:uploadId})});
  if(done&&done.ok){pendRemove(uploadId);task.progress=100}
  else{var e2=new Error((done&&done.error)||t('upFail'));e2.taskMsg=(done&&done.error)||t('upFail');throw e2}
}

document.getElementById('btnMk').onclick=function(){var n=document.getElementById('folderInput').value.trim();if(!n)return;api('/api/mkdir?path='+encodeURIComponent(cur),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(function(){document.getElementById('folderInput').value='';load()})};
document.getElementById('folderInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnMk').click()};

// ===== 视图路由：仪表盘首页 / 文件页 =====
var currentView='home', currentNav='home';
function showFilesView(){
  if(currentView==='files')return;
  currentView='files';
  var h=document.getElementById('viewHome'),f=document.getElementById('viewFiles');
  if(h)h.classList.remove('active');if(f)f.classList.add('active');
  syncNav();
}
function showHomeView(){
  currentView='home';currentNav='home';
  var h=document.getElementById('viewHome'),f=document.getElementById('viewFiles');
  if(h)h.classList.add('active');if(f)f.classList.remove('active');
  syncNav();
}
function syncNav(){
  var items=document.querySelectorAll('#sideNav .side-item');
  for(var i=0;i<items.length;i++){
    var k=items[i].getAttribute('data-nav');
    var on=(k==='home'&&currentView==='home')||(currentView==='files'&&k===currentNav);
    items[i].classList.toggle('active',on);
  }
  var tb=document.querySelectorAll('#tabBar [data-tb]');
  for(var j=0;j<tb.length;j++){
    var tk2=tb[j].getAttribute('data-tb');
    var on2=(tk2==='home'&&currentView==='home')||(currentView==='files'&&((tk2==='files'&&currentNav==='files')||(tk2==='fav'&&currentNav==='fav')||(tk2==='recent'&&currentNav==='recent')));
    tb[j].classList.toggle('on',on2);
  }
  try{history.replaceState(null,'','#/'+(currentView==='home'?'home':(currentNav==='files'?('files'+cur):currentNav)))}catch(e){}
}
function goHome(){showHomeView();loadDashboard()}
function goFiles(mode){
  currentNav=mode||'files';
  showFilesView();
  syncNav();
}
function navTo(k){
  if(k==='home'){setMode('');goHome();return}
  if(k==='albums'){try{showAlbums()}catch(e){};return}
  if(k==='trash'){try{showTrash()}catch(e){};return}
  if(k==='upload'){try{showULinkMgmt()}catch(e){};return}
  if(k==='fav'){goFiles('fav');setMode('fav');render();return}
  if(k==='recent'){goFiles('recent');setMode('recent');render();return}
  goFiles('files');setMode('');cur='/';load();
}
(function bindSideNav(){
  var nav=document.getElementById('sideNav');
  if(!nav)return;
  nav.querySelectorAll('[data-nav]').forEach(function(b){b.onclick=function(){navTo(b.getAttribute('data-nav'))}});
})();
// 仪表盘
function dashSize(b){return fmt(b||0)}
function loadDashboard(){
  var box=document.getElementById('dashWrap');
  if(!box)return;
  box.innerHTML='<div class="dash-loading">'+(lang==='zh'?'加载概览…':'Loading overview…')+'</div>';
  api('/api/dashboard').then(function(d){
    box.innerHTML=dashHtml(d||{});
    bindDash(box,d||{});
  }).catch(function(){
    box.innerHTML='<div class="dash-loading">'+(lang==='zh'?'概览加载失败':'Failed to load overview')+' <button class="btn gray tiny" id="dashRetry">'+(lang==='zh'?'重试':'Retry')+'</button></div>';
    var r=document.getElementById('dashRetry');if(r)r.onclick=loadDashboard;
  });
}
function dashHtml(d){
  var zh=lang==='zh';
  var u=d.usage||{},t=d.today||{},trend=d.trend||[];
  var pct=u.total?Math.min(100,(u.used||0)/u.total*100):0;
  var h='<div class="dash">';
  // 快捷上传区
  h+='<div class="dash-card span-12"><h4>⚡ '+(zh?'快捷操作':'Quick actions')+'</h4><div class="quick-zone">'
    +'<div class="drop-mini" id="dashDrop">⬆ '+(zh?'拖拽文件到此处上传，或点击选择':'Drop files here or click to upload')+'</div>'
    +'<button class="btn" id="dashNewDir">📁 '+(zh?'新建文件夹':'New folder')+'</button>'
    +'<button class="btn gray" id="dashPaste">📋 '+(zh?'粘贴到根目录':'Paste to root')+'</button>'
    +'<button class="btn gray" id="dashPalette">⌘K '+(zh?'命令面板':'Commands')+'</button>'
    +'</div></div>';
  // 容量 + 统计
  h+='<div class="dash-card span-4"><h4>💾 '+(zh?'存储容量':'Storage')+'</h4><div class="ring-wrap">'
    +'<div class="ring" style="--p:'+pct.toFixed(1)+'"><div>'+pct.toFixed(0)+'%<small>'+dashSize(u.used)+'</small></div></div>'
    +'<div style="flex:1;min-width:0"><div style="font-size:13px;color:var(--sys-text-2)">'+dashSize(u.used)+' / '+dashSize(u.total)+'</div>'
    +'<div class="dup-path" style="margin-top:4px">'+dashSize(Math.max(0,(u.total||0)-(u.used||0)))+' '+(zh?'可用':'free')+'</div>'
    +'<button class="btn gray tiny" id="dashFiles" style="margin-top:8px">'+(zh?'查看全部文件':'All files')+' →</button>'
    +'</div></div></div>';
  h+='<div class="dash-card span-8"><h4>📊 '+(zh?'统计':'Stats')+'<button class="dash-more" id="dashStats">'+(zh?'详细统计':'Details')+' →</button></h4>'
    +'<div class="stat-row">'
    +'<div class="stat"><b>'+(u.count||0)+'</b><span>'+(zh?'文件':'Files')+'</span></div>'
    +'<div class="stat"><b>'+(d.dirs||0)+'</b><span>'+(zh?'目录':'Folders')+'</span></div>'
    +'<div class="stat"><b>'+(d.shares||0)+'</b><span>'+(zh?'分享链接':'Shares')+'</span></div>'
    +'<div class="stat"><b>'+(d.ulinks||0)+'</b><span>'+(zh?'上传链接':'Upload links')+'</span></div>'
    +'<div class="stat"><b>'+(t.up||0)+'/'+(t.dl||0)+'</b><span>'+(zh?'今日上传/下载':'Today up/dl')+'</span></div>'
    +'<div class="stat"><b>'+dashSize((t.upBytes||0)+(t.dlBytes||0))+'</b><span>'+(zh?'今日流量':'Today traffic')+'</span></div>'
    +'</div>'
    +'<div class="spark">'+trend.map(function(x){
        var mx=1;
        for(var i=0;i<trend.length;i++)mx=Math.max(mx,(trend[i].up||0)+(trend[i].dl||0));
        var v=(x.up||0)+(x.dl||0);
        return '<i style="height:'+Math.max(3,Math.round(v/mx*100))+'%" title="'+esc(x.date)+' ↑'+x.up+' ↓'+x.dl+'"></i>';
      }).join('')+'</div><div class="dup-path">'+(zh?'近 7 天上传/下载趋势':'7-day up/download trend')+'</div></div>';
  // 最近
  var recent=d.recentItems||[];
  h+='<div class="dash-card span-6"><h4>🕐 '+(zh?'最近访问':'Recent')+'</h4><div class="recent-list">';
  if(!recent.length)h+='<div class="dup-path">'+(zh?'还没有记录':'Nothing yet')+'</div>';
  recent.slice(0,8).forEach(function(it){
    var full=(it.path||'/')+it.name;
    var isImg=it.type==='file'&&(it.mime||'').indexOf('image/')===0;
    h+='<div class="recent-item" data-rp="'+esc(full)+'" data-rn="'+esc(it.name)+'" data-rm="'+esc(it.mime||'')+'" data-rt="'+esc(it.type||'file')+'">'
      +(isImg?'<img loading="lazy" src="/api/thumb?path='+encodeURIComponent(full)+'&token='+tk+'">':'<span class="ri-ic">'+getIcon(it)+'</span>')
      +'<span class="ri-tx">'+esc(it.name)+'</span><span class="ri-sub">'+esc(it.path||'/')+'</span></div>';
  });
  h+='</div></div>';
  // 收藏 + 标签
  var favs=d.favItems||[],tags=d.tags||[];
  h+='<div class="dash-card span-6"><h4>★ '+(zh?'收藏与标签':'Favorites & tags')+'<button class="dash-more" id="dashFavMore">'+(zh?'收藏分组':'Groups')+' →</button></h4>';
  h+='<div class="recent-list" style="margin-bottom:10px">';
  if(!favs.length)h+='<div class="dup-path">'+(zh?'暂无收藏':'No favorites')+'</div>';
  favs.slice(0,5).forEach(function(it){
    var full=(it.path||'/')+it.name;
    h+='<div class="recent-item" data-rp="'+esc(full)+'" data-rn="'+esc(it.name)+'" data-rm="'+esc(it.mime||'')+'" data-rt="'+esc(it.type||'file')+'"><span class="ri-ic">★</span><span class="ri-tx">'+esc(it.name)+'</span><span class="ri-sub">'+esc(it.path||'/')+'</span></div>';
  });
  h+='</div><div class="tag-cloud" id="dashTags">';
  if(!tags.length)h+='<span class="dup-path">'+(zh?'暂无标签':'No tags')+'</span>';
  tags.forEach(function(x){
    h+='<button data-dtag="'+esc(x.name)+'"><span class="tc-dot" style="background:'+safeColor(x.color)+'"></span>'+esc(x.name)+'</button>';
  });
  h+='</div></div>';
  // Top 目录
  var td=d.topDirs||[];
  var mx=1;td.forEach(function(x){mx=Math.max(mx,x.bytes||0)});
  h+='<div class="dash-card span-12"><h4>📁 '+(zh?'占用排行':'Largest folders')+'</h4>';
  if(!td.length)h+='<div class="dup-path">'+(zh?'暂无数据':'No data')+'</div>';
  td.forEach(function(x){
    h+='<div class="topdir" data-dgo="'+esc(x.path)+'"><span class="td-path">'+esc(x.path)+'</span>'
      +'<span class="td-bar" style="width:'+Math.max(4,Math.round((x.bytes||0)/mx*160))+'px"></span>'
      +'<span class="dup-path">'+dashSize(x.bytes)+'</span></div>';
  });
  h+='</div>';
  h+='</div>';
  return h;
}
function bindDash(box,d){
  var dz=document.getElementById('dashDrop');
  if(dz){
    dz.onclick=function(){document.getElementById('fileInput').click()};
    dz.addEventListener('dragover',function(e){e.preventDefault();dz.classList.add('over')});
    dz.addEventListener('dragleave',function(){dz.classList.remove('over')});
    dz.addEventListener('drop',function(e){
      e.preventDefault();dz.classList.remove('over');
      var fs=e.dataTransfer&&e.dataTransfer.files;if(fs&&fs.length)uploadFiles(fs,'/');
    });
  }
  var nd=document.getElementById('dashNewDir');
  if(nd)nd.onclick=function(){
    var n=prompt(lang==='zh'?'新文件夹名称':'Folder name','');if(!n)return;
    api('/api/mkdir?path=/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(function(){loadDashboard();load()});
  };
  var pa=document.getElementById('dashPaste');
  if(pa)pa.onclick=function(){cur='/';pasteHere('/')};
  var pl=document.getElementById('dashPalette');
  if(pl)pl.onclick=function(){paletteOpen()};
  var sp=document.getElementById('dashStats');
  if(sp)sp.onclick=function(){try{showStats()}catch(e){}};
  var fm=document.getElementById('dashFavMore');
  if(fm)fm.onclick=function(){try{showFavGroups()}catch(e){}};
  var af=document.getElementById('dashFiles');
  if(af)af.onclick=function(){navTo('files')};
  box.querySelectorAll('[data-rp]').forEach(function(el){
    el.onclick=function(){
      var p=el.getAttribute('data-rp'),n=el.getAttribute('data-rn'),m=el.getAttribute('data-rm'),t=el.getAttribute('data-rt');
      var dir=p.substring(0,p.lastIndexOf('/')+1)||'/';
      if(t==='dir'){cur=p.endsWith('/')?p:p+'/';goFiles('files');setMode('');load();return}
      doPreview(n,m,-1,dir);
    };
  });
  box.querySelectorAll('[data-dtag]').forEach(function(b){
    b.onclick=function(){goFiles('files');tagFilterMode=true;tagFilterName=b.getAttribute('data-dtag');favMode=false;recentMode=false;searchMode=false;QUERY.on=false;load()};
  });
  box.querySelectorAll('[data-dgo]').forEach(function(el){
    el.onclick=function(){cur=el.getAttribute('data-dgo');goFiles('files');setMode('');load()};
  });
}
// 侧栏底部：主题 / 密度 / 主题色 / 语言 / 退出
function hexToRgba(hex,a){
  var h=String(hex||'').replace('#','');
  if(h.length===3)h=h[0]+h[0]+h[1]+h[1]+h[2]+h[2];
  var n=parseInt(h,16);
  if(!isFinite(n))return 'rgba(10,132,255,'+a+')';
  return 'rgba('+((n>>16)&255)+','+((n>>8)&255)+','+(n&255)+','+a+')';
}
function applyDensity(v){
  v=(v==='compact')?'compact':'cozy';
  document.documentElement.setAttribute('data-density',v);
  try{localStorage.setItem('dDensity',v)}catch(e){}
  var b=document.getElementById('footDensity');
  if(b)b.title=(v==='compact'?'紧凑':'宽松');
}
function applyAccent(c){
  c=/^#[0-9a-fA-F]{6}$/.test(String(c||''))?String(c):'#0a84ff';
  var r=document.documentElement;
  if(r&&r.style&&r.style.setProperty){
    r.style.setProperty('--sys-blue',c);
    r.style.setProperty('--sys-blue-hover',c);
    r.style.setProperty('--sys-blue-soft',hexToRgba(c,0.14));
  }
  try{localStorage.setItem('dAccent',c)}catch(e){}
  var i=document.getElementById('footAccent');if(i)i.value=c;
}
(function initAppearance(){
  try{applyDensity(localStorage.getItem('dDensity')||'cozy')}catch(e){}
  try{var a=localStorage.getItem('dAccent');if(a)applyAccent(a)}catch(e){}
  try{if(localStorage.getItem('dSidebar')==='0'){var lay0=document.querySelector('.layout');if(lay0)lay0.classList.add('sidebar-hidden')}}catch(e){}
  var ft=document.getElementById('footTheme');
  if(ft)ft.onclick=function(){var b=document.getElementById('btnTheme');if(b)b.click()};
  var fd=document.getElementById('footDensity');
  if(fd)fd.onclick=function(){
    var cur2=document.documentElement.getAttribute('data-density')==='compact'?'cozy':'compact';
    applyDensity(cur2);
  };
  var fa=document.getElementById('footAccent');
  if(fa)fa.oninput=function(){applyAccent(fa.value)};
  var fl=document.getElementById('footLang');
  if(fl)fl.onclick=function(){var b=document.getElementById('btnLang');if(b)b.click()};
  var fo=document.getElementById('footLogout');
  if(fo)fo.onclick=function(){var b=document.getElementById('btnLogout');if(b)b.click()};
})();
// 顶部「＋」新建菜单 / 搜索折叠
(function bindAppBar(){
  var btnNew=document.getElementById('btnNew'),menu=document.getElementById('newMenu');
  if(btnNew&&menu){
    btnNew.onclick=function(e){
      e.stopPropagation();
      var open=menu.classList.contains('show');
      document.querySelectorAll('.pop-menu.show').forEach(function(m){if(m!==menu)m.classList.remove('show')});
      menu.classList.toggle('show',!open);
    };
    menu.querySelectorAll('[data-new]').forEach(function(b){
      b.onclick=function(){
        var k=b.getAttribute('data-new');
        menu.classList.remove('show');
        if(k==='file')document.getElementById('fileInput').click();
        else if(k==='files'){var fi=document.getElementById('fileInput');if(fi){fi.setAttribute('webkitdirectory','');fi.click();setTimeout(function(){fi.removeAttribute('webkitdirectory')},500)}}
        else if(k==='dir'){
          var w=document.getElementById('folderInputWrap');
          if(w){w.style.display='flex';var inp=document.getElementById('folderInput');if(inp){inp.focus();inp.select()}}
        }
        else if(k==='text'){
          var nm=prompt(lang==='zh'?'文件名（会自动补 .txt）':'File name','note.txt');
          if(!nm)return;
          if(!/\\.\\w+$/.test(nm))nm+='.txt';
          var dirp=cur.substring(0,cur.lastIndexOf('/')+1)||'/';
          api('/api/save?path='+encodeURIComponent(dirp+nm),{method:'POST',headers:{'Content-Type':'text/plain'},body:''}).then(function(r){
            if(r&&r.ok){goFiles('files');load();setTimeout(function(){try{editText(nm,dirp)}catch(e){}},300)}
          });
        }
        else if(k==='folder-pw'){
          try{
            showOps('rules');
          }catch(e){}
        }
      };
    });
  }
  var st=document.getElementById('btnSearchToggle'),sw=document.getElementById('searchWrap');
  if(st&&sw){
    st.onclick=function(){
      var col=sw.classList.toggle('collapsed');
      if(!col){var i=document.getElementById('searchInput');if(i)i.focus()}
    };
  }
  document.addEventListener('click',function(e){
    if(!e.target.closest||!e.target.closest('.menu-wrap')){if(menu)menu.classList.remove('show')}
    if(!e.target.closest||!e.target.closest('.row-more-wrap')){document.querySelectorAll('.row-menu.show').forEach(function(m){m.classList.remove('show')})}
  });
  window.addEventListener('hashchange',function(){
    var h=String(location.hash||'');
    if(/#\\/?home/.test(h)){setMode('');goHome();return}
    var m=/#\\/files(.*)$/.exec(h);
    if(m){var p=decodeURIComponent(m[1]||'/')||'/';cur=p;goFiles('files');setMode('');load();return}
    if(/#\\/fav/.test(h)){navTo('fav');return}
    if(/#\\/recent/.test(h)){navTo('recent');return}
  });
})();
function load(){goFiles(currentNav==='fav'||currentNav==='recent'?currentNav:'files');render();loadUsage();syncViewBtn();}
// ===== 移动端：底部标签栏 + 选择模式 =====
var selMode=false;
function toggleSelMode(on){
  selMode=(on===undefined)?!selMode:!!on;
  document.body.classList.toggle('selmode',selMode);
  var b=document.getElementById('btnSelect');
  if(b)b.classList.toggle('active',selMode);
  if(!selMode){selected={};updateBatch()}
}
(function bindTabBar(){
  var bar=document.getElementById('tabBar');
  if(!bar)return;
  bar.querySelectorAll('[data-tb]').forEach(function(b){
    b.onclick=function(){
      var k=b.getAttribute('data-tb');
      if(k==='home'){toggleSelMode(false);navTo('home')}
      else if(k==='files'){toggleSelMode(false);navTo('files')}
      else if(k==='fav'){toggleSelMode(false);navTo('fav')}
      else if(k==='recent'){toggleSelMode(false);navTo('recent')}
      else{document.getElementById('btnMore').click()}
      syncNav();
    };
  });
})();
(function bindSelectBtn(){
  var b=document.getElementById('btnSelect');
  if(b)b.onclick=function(){toggleSelMode()};
})();
(function bindSidebarToggle(){
  var b=document.getElementById('btnSidebar');
  if(!b)return;
  b.onclick=function(){
    var sb=document.getElementById('sidebar');
    if(!sb)return;
    if(window.innerWidth<=760){sb.classList.toggle('show');return}
    var lay=document.querySelector('.layout');
    var hidden=lay?lay.classList.toggle('sidebar-hidden'):false;
    try{localStorage.setItem('dSidebar',hidden?'0':'1')}catch(e){}
  };
})();
// 移动端底部标签栏
(function(){
  var bar=document.getElementById('tabBar');
  if(!bar)return;
  bar.querySelectorAll('[data-tb]').forEach(function(b){
    b.onclick=function(){
      var k=b.getAttribute('data-tb');
      if(k==='files'){setMode('');cur='/';load()}
      else if(k==='fav'){setMode('fav');render()}
      else if(k==='recent'){setMode('recent');render()}
      else if(k==='up'){document.getElementById('fileInput').click()}
      else{document.getElementById('btnMore').click()}
      bar.querySelectorAll('[data-tb]').forEach(function(x){x.classList.toggle('on',x===b)});
    };
  });
})();
function loadUsage(){api('/api/usage').then(function(d){var p=Math.min(100,(d.used/d.total)*100).toFixed(1);document.getElementById('uUsed').textContent=t('used')+': '+fmt(d.used)+' / '+fmt(d.total);document.getElementById('uFiles').textContent=d.files+' '+t('files');document.getElementById('uFill').style.width=p+'%'})}
document.getElementById('btnRecalc').onclick=function(){api('/api/recalc-usage',{method:'POST'}).then(function(){loadUsage();alert('OK')})};


// ===== Paste upload =====
document.addEventListener('paste',function(e){
  if(!tk||document.getElementById('loginPage').style.display!=='none'&&document.getElementById('loginPage').style.display!=='')return;
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  var items=e.clipboardData&&e.clipboardData.items;
  if(!items)return;
  var files=[];
  for(var i=0;i<items.length;i++){
    if(items[i].kind==='file'){
      var f=items[i].getAsFile();
      if(f){
        var ext=f.type.split('/')[1]||'png';
        var ts=new Date().toISOString().replace(/[:.]/g,'-').substring(0,19);
        try{f=new File([f],'paste-'+ts+'.'+ext,{type:f.type})}catch(ex){}
        files.push(f);
      }
    }
  }
  if(files.length){e.preventDefault();uploadFiles(files);return}
  // 剪贴板里没有文件：若站内剪贴板有内容，则执行"粘贴到当前目录"
  if(clipGet()){e.preventDefault();pasteHere(cur)}
});


// ===== Keyboard shortcuts =====
document.addEventListener('keydown',function(e){
  // 命令面板：任何焦点下都可用
  if((e.ctrlKey||e.metaKey)&&(e.key==='k'||e.key==='K')){
    e.preventDefault();
    if(PALETTE.open)paletteClose();else paletteOpen();
    return;
  }
  if(PALETTE.open){
    if(e.key==='Escape'){e.preventDefault();paletteClose()}
    return;
  }
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.tagName==='SELECT')return;
  if(document.getElementById('pvModal').classList.contains('show'))return;
  if(document.querySelector('.modal-bg.show'))return;
  if((e.ctrlKey||e.metaKey)&&e.key==='a'){
    e.preventDefault();
    var cbs=document.querySelectorAll('[data-chk]');
    var allChecked=true;
    cbs.forEach(function(cb){if(!cb.checked)allChecked=false});
    cbs.forEach(function(cb){cb.checked=!allChecked;cb.dispatchEvent(new Event('change'))});
    return;
  }
  if(e.key==='Delete'&&Object.keys(selected).length){
    if(!confirm('Delete '+Object.keys(selected).length+'?'))return;
    api('/api/batch-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:Object.keys(selected)})}).then(function(){selected={};load()});
    return;
  }
  if(e.key==='F2'){
    var keys=Object.keys(selected);
    if(keys.length===1){var o=keys[0];var bn=o.split('/').filter(Boolean).pop();var n=prompt(t('rename'),bn);if(n&&n!==bn)api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:o,newName:n})}).then(load)}
    return;
  }
  if(e.key==='Backspace'&&cur!=='/'){
    e.preventDefault();
    var parts=cur.split('/').filter(Boolean);parts.pop();
    cur=parts.length?'/'+parts.join('/')+'/':'/' ;
    setMode('');load();
    return;
  }
  if((e.ctrlKey||e.metaKey)&&e.key==='f'){
    e.preventDefault();
    document.getElementById('searchInput').focus();
    return;
  }
  if(e.key==='v'||e.key==='V'){cycleView();return}
  if(e.key==='/'||e.key==='?'){e.preventDefault();paletteOpen();return}
  if((e.ctrlKey||e.metaKey)&&(e.key==='c'||e.key==='x')){
    if(!Object.keys(selected).length)return;   // 没有选中就不拦截，保留浏览器原生复制
    e.preventDefault();
    clipFromSelection(e.key==='x'?'cut':'copy');
    return;
  }
  if((e.ctrlKey||e.metaKey)&&e.key==='v'){
    if(!clipGet())return;                      // 让原生粘贴（含文件）走 paste 事件
    e.preventDefault();
    pasteHere(cur);
    return;
  }
});


// ===== AES-GCM Client Encryption =====
document.getElementById('btnEnc').onclick=function(){showEncryptPrompt()};
document.getElementById('encClose').onclick=function(){document.getElementById('encModal').classList.remove('show')};
document.getElementById('encModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showEncrypt(name,base){showEncryptPrompt(name,base)}
function showEncryptPrompt(name,base){
  base=base||cur;
  var box=document.getElementById('encContent');
  document.getElementById('encTitle').textContent=t('enc')+(name?' · '+name:'');
  var h='<div style="margin-bottom:14px"><label style="font-size:13px;color:var(--sys-text-2);display:block;margin-bottom:6px">'+t('encPw')+'</label>';
  h+='<input id="encPwInput" type="password" style="width:100%;padding:10px 14px;border-radius:10px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:15px" autocomplete="off"></div>';
  h+='<div style="display:flex;gap:8px;justify-content:flex-end">';
  if(name)h+='<button id="encDecBtn" class="btn gray small">'+t('decrypt')+'</button>';
  h+='<button id="encEncBtn" class="btn small">'+t('encrypt')+'</button></div>';
  h+='<div id="encStatus" style="margin-top:10px;font-size:13px;color:var(--sys-text-3);text-align:center"></div>';
  box.innerHTML=h;
  document.getElementById('encModal').classList.add('show');
  var encBtn=document.getElementById('encEncBtn');
  if(encBtn)encBtn.onclick=function(){doEncrypt(name,true)};
  var decBtn=document.getElementById('encDecBtn');
  if(decBtn)decBtn.onclick=function(){doEncrypt(name,false)};
}
async function deriveKey(password,salt){
  var enc=new TextEncoder();
  var keyMaterial=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:100000,hash:'SHA-256'},keyMaterial,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function doEncrypt(name,encrypt){
  var pw=document.getElementById('encPwInput').value;
  if(!pw){alert('Password required');return}
  var status=document.getElementById('encStatus');
  status.textContent='Processing...';
  try{
    var path=base+name;
    var res=await fetch('/api/preview?path='+encodeURIComponent(path)+'&token='+tk);
    if(!res.ok)throw new Error('Download failed');
    var data=await res.arrayBuffer();
    var salt=crypto.getRandomValues(new Uint8Array(16));
    var iv=crypto.getRandomValues(new Uint8Array(12));
    var key=await deriveKey(pw,salt);
    var result;
    if(encrypt){
      result=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key,data);
    }else{
      if(name.endsWith('.enc')){
        var raw=new Uint8Array(data);
        salt=raw.slice(0,16);iv=raw.slice(16,28);
        key=await deriveKey(pw,salt);
        result=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,raw.slice(28));
      }else{alert('Not an encrypted file');return}
    }
    var blob;
    var newName;
    if(encrypt){
      var combined=new Uint8Array(16+12+result.byteLength);
      combined.set(salt,0);combined.set(iv,16);combined.set(new Uint8Array(result),28);
      blob=new Blob([combined],{type:'application/octet-stream'});
      newName=name+'.enc';
    }else{
      blob=new Blob([result]);
      newName=name.replace(/\\.enc$/,'');
    }
    var fd=new FormData();
    fd.append('file',blob,newName);
    var xhr=new XMLHttpRequest();
    xhr.open('POST','/api/upload?path='+encodeURIComponent(base)+'&token='+tk);
    xhr.onload=function(){
      if(xhr.status>=200&&xhr.status<300){
        status.textContent=encrypt?t('encDone'):t('decDone');
        status.style.color='var(--sys-green)';
        setTimeout(function(){document.getElementById('encModal').classList.remove('show');load()},800);
      }else{status.textContent=t('encFail');status.style.color='var(--sys-red)'}
    };
    xhr.onerror=function(){status.textContent=t('encFail');status.style.color='var(--sys-red)'};
    xhr.send(fd);
  }catch(e){status.textContent=t('encFail')+': '+e.message;status.style.color='var(--sys-red)'}
}


// ===== Stats Panel =====
document.getElementById('btnStats').onclick=function(){showStats()};
document.getElementById('statsClose').onclick=function(){document.getElementById('statsModal').classList.remove('show')};
document.getElementById('statsModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showStats(){
  var box=document.getElementById('statsContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('statsModal').classList.add('show');
  api('/api/stats').then(function(d){
    var u=d.usage||{};
    function sc(v,l){return '<div class="stats-card"><div class="sv">'+v+'</div><div class="sl">'+l+'</div></div>'}
    var h='<div class="stats-grid">';
    h+=sc(fmt(u.used||0),lang==='zh'?'已用':'Used');
    h+=sc(String(u.files||0),lang==='zh'?'文件':'Files');
    h+=sc(fmt(Math.max(0,(u.total||0)-(u.used||0))),lang==='zh'?'剩余':'Free');
    h+=sc(String(d.shares||0),lang==='zh'?'分享链接':'Shares');
    h+=sc(String(d.ulinks||0),lang==='zh'?'上传链接':'Upload links');
    h+=sc(String(d.dlCount||0),lang==='zh'?'下载次数':'Downloads');
    h+=sc(fmt(d.dlBytes||0),lang==='zh'?'下载流量':'DL traffic');
    h+=sc(String(d.trash||0),lang==='zh'?'回收站':'Trash');
    h+=sc(String(d.tokens||0),lang==='zh'?'访问令牌':'Tokens');
    h+=sc(String(d.logCount||0),lang==='zh'?'操作记录':'Actions');
    h+='</div>';
    h+='<canvas id="statsChart" style="max-height:200px;margin-top:8px"></canvas>';
    h+='<div style="font-size:13px;color:var(--sys-text-2);margin:18px 0 6px">'+(lang==='zh'?'近 30 天上传 / 下载':'Uploads / Downloads (30d)')+'</div><canvas id="trendChart" style="max-height:200px"></canvas>';
    box.innerHTML=h;
    api('/api/stats-trend?days=30').then(function(tr){
      var days=(tr&&tr.days)||[];
      var el=document.getElementById('trendChart');
      if(!el||typeof Chart==='undefined')return;
      var col=(getComputedStyle(document.body).getPropertyValue('--sys-text-2')||'#8b949e').trim()||'#8b949e';
      var grid='rgba(128,128,128,.15)';
      try{
        new Chart(el.getContext('2d'),{type:'line',data:{labels:days.map(function(x){return x.date.slice(5)}),datasets:[
          {label:(lang==='zh'?'上传':'Uploads'),data:days.map(function(x){return x.up}),borderColor:'#2f81f7',backgroundColor:'rgba(47,129,247,.15)',fill:true,tension:.3,pointRadius:0,borderWidth:2},
          {label:(lang==='zh'?'下载':'Downloads'),data:days.map(function(x){return x.dl}),borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.12)',fill:true,tension:.3,pointRadius:0,borderWidth:2}
        ]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:col,boxWidth:12}}},scales:{x:{ticks:{color:col,maxTicksLimit:8},grid:{color:grid}},y:{beginAtZero:true,ticks:{color:col,precision:0},grid:{color:grid}}}}});
      }catch(e){}
    }).catch(function(){});
    try{
      if(typeof Chart!=='undefined'){
        var ctx=document.getElementById('statsChart').getContext('2d');
        new Chart(ctx,{type:'doughnut',data:{labels:['Used','Free'],datasets:[{data:[u.used||0,Math.max(0,(u.total||10*1024*1024*1024)-(u.used||0))],backgroundColor:['#0a84ff','#34c759'],borderWidth:0}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:getComputedStyle(document.body).getPropertyValue('--sys-text').trim()||'#fff'}}}}});
      }
    }catch(e){}
  });
}


// ===== Activity Log =====
document.getElementById('btnLog').onclick=function(){showLog()};
document.getElementById('logClose').onclick=function(){document.getElementById('logModal').classList.remove('show')};
document.getElementById('logModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
var logFilter='',logCache=[],logQuery={q:'',from:'',to:''};
function showLog(){
  var box=document.getElementById('logContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('logModal').classList.add('show');
  logFetch();
}
function logFetch(){
  var qs='?limit=1000';
  if(logFilter)qs+='&action='+encodeURIComponent(logFilter);
  if(logQuery.q)qs+='&q='+encodeURIComponent(logQuery.q);
  if(logQuery.from)qs+='&from='+encodeURIComponent(logQuery.from);
  if(logQuery.to)qs+='&to='+encodeURIComponent(logQuery.to);
  api('/api/log'+qs).then(function(d){logCache=d.logs||[];logTotal=d.total||logCache.length;renderLog()}).catch(function(){
    document.getElementById('logContent').innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'加载失败':'Failed')+'</p>';
  });
}
var logTotal=0;
function renderLog(){
  var box=document.getElementById('logContent');
  var ACT={up:{zh:'上传',en:'upload',c:'var(--sys-green)',i:'⬆'},del:{zh:'删除',en:'delete',c:'var(--sys-red)',i:'🗑'},shr:{zh:'分享',en:'share',c:'var(--sys-orange)',i:'🔗'},mov:{zh:'移动',en:'move',c:'var(--sys-blue)',i:'➡'},res:{zh:'恢复',en:'restore',c:'var(--sys-green)',i:'↩'},sec:{zh:'安全',en:'security',c:'var(--sys-red)',i:'🔒'},cpy:{zh:'复制',en:'copy',c:'var(--sys-blue)',i:'📋'},login:{zh:'登录',en:'login',c:'var(--sys-orange)',i:'🔑'}};
  var counts={};
  logCache.forEach(function(l){counts[l.action]=(counts[l.action]||0)+1});
  var tabs=[['','全部','All'],['up','上传','Upload'],['del','删除','Delete'],['shr','分享','Share'],['mov','移动','Move'],['cpy','复制','Copy'],['sec','安全','Security']];
  var h='<div class="filter-bar" style="border:0;padding:0 0 8px;flex-wrap:wrap">';
  tabs.forEach(function(x){
    var n=x[0]?(counts[x[0]]||0):logCache.length;
    h+='<button class="fchip'+(logFilter===x[0]?' active':'')+'" data-lf="'+x[0]+'">'+(lang==='zh'?x[1]:x[2])+' '+n+'</button>';
  });
  h+='</div>';
  h+='<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px">';
  h+='<input id="logQ" placeholder="'+(lang==='zh'?'关键词 / 路径':'keyword')+'" value="'+esc(logQuery.q)+'" style="flex:1;min-width:120px;padding:6px 10px;font-size:13px">';
  h+='<input id="logFrom" type="date" value="'+esc(logQuery.from)+'" style="padding:6px 8px;font-size:13px">';
  h+='<input id="logTo" type="date" value="'+esc(logQuery.to)+'" style="padding:6px 8px;font-size:13px">';
  h+='<button id="logApply" class="btn gray tiny">'+(lang==='zh'?'筛选':'Filter')+'</button>';
  h+='<button id="logReset" class="btn gray tiny">'+(lang==='zh'?'重置':'Reset')+'</button>';
  h+='<button id="logCsv" class="btn gray tiny">⬇ CSV</button>';
  h+='</div>';
  var list=logCache;
  if(!list.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'暂无记录':'No logs')+'</p>'}
  else{
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:4px">'+list.length+(lang==='zh'?' 条记录（共 ':' records (total ')+logTotal+(lang==='zh'?'）':'）')+'</div>';
    h+='<div style="max-height:440px;overflow:auto">';
    var curDay='';
    list.slice(0,500).forEach(function(l){
      var day=String(l.time||'').substring(0,10);
      if(day!==curDay){curDay=day;h+='<div class="log-day">'+esc(day)+'</div>'}
      var a=ACT[l.action]||{zh:l.action||'-',en:l.action||'-',c:'var(--sys-text-2)',i:'•'};
      h+='<div class="log-entry"><span class="log-time">'+esc(String(l.time||'').slice(11,16))+'</span>';
      h+='<span class="log-action" style="color:'+a.c+'">'+a.i+' '+(lang==='zh'?a.zh:a.en)+'</span>';
      h+='<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(l.path||'')+'">'+esc(l.path||'')+'</span>';
      h+='<span class="tr-meta">'+esc(l.detail||'')+'</span></div>';
    });
    h+='</div>';
  }
  box.innerHTML=h;
  box.querySelectorAll('[data-lf]').forEach(function(b){b.onclick=function(){logFilter=b.getAttribute('data-lf');logFetch()}});
  var ap=document.getElementById('logApply');
  if(ap)ap.onclick=function(){
    logQuery.q=document.getElementById('logQ').value.trim();
    logQuery.from=document.getElementById('logFrom').value;
    logQuery.to=document.getElementById('logTo').value;
    logFetch();
  };
  var rs=document.getElementById('logReset');
  if(rs)rs.onclick=function(){logFilter='';logQuery={q:'',from:'',to:''};logFetch()};
  var cs=document.getElementById('logCsv');
  if(cs)cs.onclick=function(){window.open('/api/log.csv?token='+encodeURIComponent(tk),'_blank')};
}


// ===== Token Management =====
document.getElementById('btnTokens').onclick=function(){showTokens()};
document.getElementById('tokensClose').onclick=function(){document.getElementById('tokensModal').classList.remove('show')};
document.getElementById('tokensModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showTokens(){
  var box=document.getElementById('tokensContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('tokensModal').classList.add('show');
  api('/api/tokens').then(function(d){
    var tokens=d.tokens||[];
    var h='<div style="display:flex;gap:8px;margin-bottom:14px"><input id="tkName" placeholder="Name" style="flex:1;padding:8px 12px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px">';
    h+='<select id="tkPerm" style="padding:8px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px"><option value="ro">Read</option><option value="rw">Read+Write</option></select>';
    h+='<button id="tkAdd" class="btn small">+</button></div>';
    if(tokens.length){
      tokens.forEach(function(t){
        h+='<div class="token-row"><span class="token-name">'+esc(t.name)+'</span><span class="token-perm '+t.perm+'">'+t.perm+'</span>';
        if(t.exp)h+='<span style="font-size:11px;color:var(--sys-text-3)">'+esc(String(t.exp))+'</span>';
        h+='<button class="btn tiny danger" data-tkdel="'+esc(t.id||'')+'">✕</button></div>';
      });
    }else{h+='<p style="text-align:center;color:var(--sys-text-3);padding:16px">'+(lang==='zh'?'暂无令牌':'No tokens')+'</p>'}
    box.innerHTML=h;
    var addBtn=document.getElementById('tkAdd');
    if(addBtn)addBtn.onclick=function(){
      var name=document.getElementById('tkName').value.trim()||'Token';
      var perm=document.getElementById('tkPerm').value;
      api('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,perm:perm})}).then(function(r){
        if(r.token){prompt((lang==='zh'?'新令牌（请保存）：':'New token:'),r.token);try{navigator.clipboard.writeText(r.token)}catch(e){}}
        showTokens();
      });
    };
    box.querySelectorAll('[data-tkdel]').forEach(function(b){
      b.onclick=function(){
        if(!confirm('Delete?'))return;
        api('/api/tokens',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:b.getAttribute('data-tkdel')})}).then(showTokens);
      };
    });
  });
}


// ===== WebDAV Info Panel =====
document.getElementById('btnWebDAV').onclick=function(){
  var box=document.getElementById('webdavContent');
  box.innerHTML='<div class="webdav-box">'+
    '<p style="margin-bottom:12px"><strong>WebDAV Endpoint:</strong></p>'+
    '<p><code>'+location.origin+'/dav/</code></p>'+
    '<p style="margin-top:12px;margin-bottom:8px"><strong>Auth:</strong> Bearer Token</p>'+
    '<p style="font-size:12px;color:var(--sys-text-3)">Create an access token in the 🔑 Tokens panel, then use it as a Bearer token in your WebDAV client (Raidrive, Cyberduck, etc.)</p>'+
    '<p style="margin-top:12px;font-size:12px;color:var(--sys-text-3)">Supported: PROPFIND, GET, PUT, DELETE, MKCOL, OPTIONS</p>'+
    '</div>';
  document.getElementById('webdavModal').classList.add('show');
};
document.getElementById('webdavClose').onclick=function(){document.getElementById('webdavModal').classList.remove('show')};
document.getElementById('webdavModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

// ===== 分享管理 =====
document.getElementById('btnShareMgmt').onclick=function(){showShareMgmt()};
document.getElementById('shareMgmtClose').onclick=function(){document.getElementById('shareMgmtModal').classList.remove('show')};
document.getElementById('shareMgmtModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function fmtWhen(ts){if(!ts)return'-';try{return new Date(ts).toLocaleString()}catch(e){return'-'}}
function showShareMgmt(){
  var box=document.getElementById('shareMgmtContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('shareMgmtModal').classList.add('show');
  api('/api/shares').then(function(d){
    var arr=d.shares||[];var h='';
    if(!arr.length){h='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'暂无分享链接':'No share links')+'</p>';}
    else{
      h='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:10px">'+arr.length+(lang==='zh'?' 个链接':' links')+'</div>';
      arr.forEach(function(s){
        h+='<div class="token-row"><div style="flex:1;min-width:0">';
        h+='<div style="font-weight:500;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(s.name||s.path)+'</div>';
        h+='<div class="dup-path">'+esc(s.path)+' · '+(s.max>0?(s.hits+'/'+s.max):(s.hits+' hits'))+' · '+esc(fmtWhen(s.exp))+(s.hasPassword?' · 🔒':'')+'</div></div>';
        h+='<button class="btn gray tiny" data-shcopy="'+esc(s.token)+'">'+(lang==='zh'?'复制':'Copy')+'</button>';
        h+='<button class="btn gray tiny" data-shset="'+esc(s.token)+'">⚙</button>';
        h+='<button class="btn tiny danger" data-shdel="'+esc(s.token)+'">✕</button></div>';
      });
    }
    h+='<div id="shareExtra" style="margin-top:14px;padding-top:12px;border-top:.5px solid var(--sys-separator);font-size:12px;color:var(--sys-text-3)"></div>';
    box.innerHTML=h;
    box.querySelectorAll('[data-shcopy]').forEach(function(b){b.onclick=function(){var u=location.origin+'/s/'+b.getAttribute('data-shcopy');try{navigator.clipboard.writeText(u)}catch(e){}prompt(t('link'),u)}});
    box.querySelectorAll('[data-shset]').forEach(function(b){b.onclick=function(){showShareSettings(b.getAttribute('data-shset'),false)}});
    box.querySelectorAll('[data-shdel]').forEach(function(b){b.onclick=function(){if(!confirm(t('delete')))return;api('/api/share',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:b.getAttribute('data-shdel')})}).then(showShareMgmt)}});
    api('/api/public-upload-info').then(function(pi){
      var el=document.getElementById('shareExtra');if(!el)return;
      el.textContent=pi.enabled?('公开上传：'+location.origin+'/upload → '+pi.dir+'（'+(pi.turnstile?'已开启人机验证':'未开启人机验证')+'）'):'公开上传未开启：设置环境变量 PUBLIC_UPLOAD_DIR 后可用 /upload 页面接收文件。';
    }).catch(function(){});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}

// ===== 分享设置 / 统计面板 =====
function shareSetModal(){
  var m=document.getElementById('shareSetModal');
  if(!m){
    m=document.createElement('div');
    m.id='shareSetModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:420px;max-width:680px"><button class="mclose" id="shareSetClose">✕</button><h3>🔗 分享设置</h3><div id="shareSetContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('shareSetClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showShareSettings(token,isNew){
  var m=shareSetModal(),box=document.getElementById('shareSetContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  m.classList.add('show');
  api('/api/share-stats?token='+encodeURIComponent(token)).then(function(d){
    if(!d||d.error){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+esc((d&&d.error)||'Error')+'</p>';return}
    var url=location.origin+'/s/'+(d.slug||token);
    var st=d.stats||{views:0,downloads:0};
    var v=d.view||{};
    var h='';
    if(isNew)h+='<div style="font-size:13px;color:var(--sys-green);margin-bottom:10px">'+(lang==='zh'?'分享已创建，可继续调整权限与外观':'Share created')+'</div>';
    h+='<div class="dup-path" style="word-break:break-all;margin-bottom:8px">'+esc(url)+'</div>';
    h+='<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">'
      +'<button class="btn gray tiny" id="ssCopy">'+(lang==='zh'?'复制链接':'Copy')+'</button>'
      +'<button class="btn gray tiny" id="ssOpen">'+(lang==='zh'?'打开':'Open')+'</button>'
      +'<button class="btn gray tiny" id="ssQR">'+(lang==='zh'?'二维码':'QR')+'</button>'
      +(d.type==='dir'?'<button class="btn gray tiny" id="ssZip">📦 '+(lang==='zh'?'打包下载':'ZIP')+'</button>':'')
      +'</div>';
    h+='<div class="token-row"><span class="token-name">'+(d.type==='dir'?'📁 ':'📄 ')+esc(d.name||'')+'</span><span class="dup-path">'+esc(d.path||'')+'</span></div>';
    h+='<div class="dup-path" style="line-height:1.9">'
      +(lang==='zh'?'访问 ':'views ')+(st.views||0)+' · '+(lang==='zh'?'下载 ':'downloads ')+(st.downloads||0)
      +(d.max>0?(' · '+(lang==='zh'?'配额 ':'limit ')+d.hits+'/'+d.max):'')
      +' · '+(lang==='zh'?'过期 ':'expires ')+esc(fmtWhen(d.exp))+(d.hasPassword?' · 🔒':'')+'</div>';
    h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'权限':'Permissions')+'</div>';
    h+='<label style="display:flex;gap:8px;align-items:center;font-size:13.5px;margin:6px 0"><input type="checkbox" id="ssDl" '+(d.allowDownload?'checked':'')+'>'+(lang==='zh'?'允许下载（关闭后仅可在线预览）':'Allow download')+'</label>';
    h+='<label style="display:flex;gap:8px;align-items:center;font-size:13.5px;margin:6px 0"><input type="checkbox" id="ssOnce" '+(d.once?'checked':'')+'>'+(lang==='zh'?'一次性下载（下载一次后失效）':'One-time download')+'</label>';
    h+='<label style="display:flex;gap:8px;align-items:center;font-size:13.5px;margin:6px 0"><input type="checkbox" id="ssCmt" '+(d.allowComment?'checked':'')+'>'+(lang==='zh'?'允许访客留言':'Allow comments')+'</label>';
    h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'外观与说明':'Appearance')+'</div>';
    h+='<input id="ssTitle" placeholder="'+(lang==='zh'?'分享标题':'Title')+'" value="'+esc(v.title||'')+'" style="width:100%;padding:8px 12px;margin-bottom:6px">';
    h+='<input id="ssDesc" placeholder="'+(lang==='zh'?'一句话描述':'Description')+'" value="'+esc(v.desc||'')+'" style="width:100%;padding:8px 12px;margin-bottom:6px">';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><input id="ssColor" type="color" value="'+esc(v.color||'#0a84ff')+'" style="width:40px;height:34px;padding:0;border:none;background:none">'
      +'<input id="ssNote" placeholder="'+(lang==='zh'?'给访客的提示（显示在页面上）':'Note for visitors')+'" value="'+esc(d.note||'')+'" style="flex:1;padding:8px 12px"></div>';
    h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'友好短链与访问限制':'Slug &amp; restrictions')+'</div>';
    h+='<div style="display:flex;gap:6px;align-items:center;margin-bottom:6px"><span class="dup-path">/s/</span><input id="ssSlug" placeholder="my-photos" value="'+esc(d.slug||'')+'" style="flex:1;padding:8px 12px"></div>';
    h+='<input id="ssIpAllow" placeholder="'+(lang==='zh'?'仅允许这些 IP/CIDR（逗号分隔，留空不限）':'IP allow')+'" value="'+esc(d.ipAllow||'')+'" style="width:100%;padding:8px 12px;margin-bottom:6px">';
    h+='<input id="ssIpDeny" placeholder="'+(lang==='zh'?'拒绝这些 IP/CIDR':'IP deny')+'" value="'+esc(d.ipDeny||'')+'" style="width:100%;padding:8px 12px;margin-bottom:6px">';
    h+='<input id="ssCountry" placeholder="'+(lang==='zh'?'仅允许这些国家码（如 CN,HK）':'Country allow')+'" value="'+esc(d.countryAllow||'')+'" style="width:100%;padding:8px 12px;margin-bottom:6px">';
    h+='<input id="ssUa" placeholder="'+(lang==='zh'?'拒绝这些 UA 关键字':'UA deny')+'" value="'+esc(d.uaDeny||'')+'" style="width:100%;padding:8px 12px;margin-bottom:8px">';
    h+='<div id="ssMsg" style="font-size:13px;min-height:18px;margin-bottom:8px"></div>';
    h+='<div style="text-align:right"><button class="btn small" id="ssSave">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    if((d.visits||[]).length){
      h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'最近访问':'Recent visits')+'</div>';
      h+='<div style="max-height:180px;overflow:auto;font-size:12px">';
      d.visits.forEach(function(x){
        h+='<div class="log-entry"><span class="log-time">'+esc(new Date(x.t).toLocaleString())+'</span><span style="flex:1">'+esc((x.k==='download'?'⬇ ':'👁 ')+(x.ip||'')+(x.c?(' · '+x.c):'')+(x.b?(' · '+x.b):''))+'</span></div>';
      });
      h+='</div>';
    }
    box.innerHTML=h;
    document.getElementById('ssCopy').onclick=function(){try{navigator.clipboard.writeText(url)}catch(e){};this.textContent=(lang==='zh'?'已复制':'Copied')};
    document.getElementById('ssOpen').onclick=function(){window.open('/s/'+(d.slug||token),'_blank')};
    document.getElementById('ssQR').onclick=function(){try{showQR(url)}catch(e){}};
    var zipBtn=document.getElementById('ssZip');
    if(zipBtn)zipBtn.onclick=function(){window.open('/s/'+(d.slug||token)+'/zip','_blank')};
    document.getElementById('ssSave').onclick=function(){
      var msg=document.getElementById('ssMsg');
      var body={
        token:token,
        allowDownload:document.getElementById('ssDl').checked,
        once:document.getElementById('ssOnce').checked,
        allowComment:document.getElementById('ssCmt').checked,
        note:document.getElementById('ssNote').value,
        view:{title:document.getElementById('ssTitle').value,desc:document.getElementById('ssDesc').value,color:document.getElementById('ssColor').value},
        slug:document.getElementById('ssSlug').value.trim(),
        ipAllow:document.getElementById('ssIpAllow').value,
        ipDeny:document.getElementById('ssIpDeny').value,
        countryAllow:document.getElementById('ssCountry').value,
        uaDeny:document.getElementById('ssUa').value
      };
      api('/api/share/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){
        if(r&&r.ok){msg.style.color='var(--sys-green)';msg.textContent=(lang==='zh'?'已保存':'Saved');showShareSettings(token,false)}
        else{msg.style.color='var(--sys-red)';msg.textContent=(r&&r.error)||'failed'}
      });
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
// ===== 文件评论面板 =====
function cmtModal(){
  var m=document.getElementById('cmtModal');
  if(!m){
    m=document.createElement('div');
    m.id='cmtModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:380px;max-width:600px"><button class="mclose" id="cmtClose">✕</button><h3 id="cmtTitle">💬 留言</h3><div id="cmtContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('cmtClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showComments(filePath,name){
  var m=cmtModal(),box=document.getElementById('cmtContent');
  document.getElementById('cmtTitle').textContent='💬 '+(name||'');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:16px">Loading...</p>';
  m.classList.add('show');
  function render(){
    api('/api/comments?path='+encodeURIComponent(filePath)).then(function(d){
      var list=d.comments||[];
      var h='<div style="max-height:300px;overflow:auto;font-size:13px">';
      if(!list.length)h+='<div style="color:var(--sys-text-3);padding:10px 0">'+(lang==='zh'?'还没有留言':'No comments')+'</div>';
      list.forEach(function(c){
        h+='<div style="padding:8px 0;border-bottom:.5px solid var(--sys-separator)"><div style="display:flex;gap:8px;align-items:center"><span style="font-weight:600">'+esc(c.by||'')+'</span><span class="dup-path">'+esc(fmtWhen(c.t))+(c.country?(' · '+esc(c.country)):'')+'</span><span style="flex:1"></span><button class="btn tiny danger" data-cdel="'+esc(c.id)+'">✕</button></div>'
          +'<div style="white-space:pre-wrap;word-break:break-word;margin-top:4px">'+esc(c.text||'')+'</div></div>';
      });
      h+='</div><div style="display:flex;gap:8px;margin-top:10px"><input id="cmtNew" placeholder="'+(lang==='zh'?'写下留言...':'Write a comment...')+'" style="flex:1"><button class="btn small" id="cmtAdd">'+(lang==='zh'?'发送':'Send')+'</button></div>';
      box.innerHTML=h;
      document.getElementById('cmtAdd').onclick=function(){
        var v=document.getElementById('cmtNew').value.trim();if(!v)return;
        api('/api/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:filePath,text:v,by:'owner'})}).then(function(){render()});
      };
      box.querySelectorAll('[data-cdel]').forEach(function(b){b.onclick=function(){
        api('/api/comments?path='+encodeURIComponent(filePath)+'&id='+encodeURIComponent(b.getAttribute('data-cdel')),{method:'DELETE'}).then(function(){render()});
      }});
    }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
  }
  render();
}

// ===== 上传链接管理 =====
document.getElementById('btnULinkMgmt').onclick=function(){showULinkMgmt()};
document.getElementById('ulinkMgmtClose').onclick=function(){document.getElementById('ulinkMgmtModal').classList.remove('show')};
document.getElementById('ulinkMgmtModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showULinkMgmt(){
  var box=document.getElementById('ulinkMgmtContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('ulinkMgmtModal').classList.add('show');
  api('/api/upload-links').then(function(d){
    var arr=d.links||[];
    if(!arr.length){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'暂无上传链接':'No upload links')+'</p>';return}
    var h='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:10px">'+arr.length+(lang==='zh'?' 个链接':' links')+'</div>';
    arr.forEach(function(s){
      h+='<div class="token-row"><div style="flex:1;min-width:0">';
      h+='<div style="font-weight:500;font-size:14px">'+esc(s.path)+'</div>';
      h+='<div class="dup-path">'+(s.max>0?(s.count+'/'+s.max):(s.count+' uploads'))+' · '+esc(fmtWhen(s.exp))+'</div></div>';
      h+='<button class="btn gray tiny" data-ulcopy="'+esc(s.token)+'">'+(lang==='zh'?'复制':'Copy')+'</button>';
      h+='<button class="btn tiny danger" data-uldel="'+esc(s.token)+'">✕</button></div>';
    });
    box.innerHTML=h;
    box.querySelectorAll('[data-ulcopy]').forEach(function(b){b.onclick=function(){var u=location.origin+'/u/'+b.getAttribute('data-ulcopy');try{navigator.clipboard.writeText(u)}catch(e){}prompt(t('link'),u)}});
    box.querySelectorAll('[data-uldel]').forEach(function(b){b.onclick=function(){if(!confirm(t('delete')))return;api('/api/upload-link',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:b.getAttribute('data-uldel')})}).then(showULinkMgmt)}});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}

// ===== 下载明细 =====
document.getElementById('btnDlStats').onclick=function(){showDlStats()};
document.getElementById('dlModalClose').onclick=function(){document.getElementById('dlModal').classList.remove('show')};
document.getElementById('dlModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showDlStats(){
  var box=document.getElementById('dlContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('dlModal').classList.add('show');
  fetch('/api/dl-stats?token='+encodeURIComponent(tk),{cache:'no-store'}).then(function(r){
    if(r.status===401){show('login');throw new Error('unauthorized')}
    if(!r.ok)throw new Error('HTTP '+r.status);
    return r.json();
  }).then(function(d){
    var st=d.stats||{total:0,bytes:0},logs=d.logs||[],daily=d.daily||[];
    var h='<div class="stats-grid">';
    h+='<div class="stats-card"><div class="sv">'+(st.total||0)+'</div><div class="sl">'+(lang==='zh'?'下载次数':'Downloads')+'</div></div>';
    h+='<div class="stats-card"><div class="sv">'+fmt(st.bytes||0)+'</div><div class="sl">'+(lang==='zh'?'下载流量':'Traffic')+'</div></div>';
    h+='</div>';
    if(daily.length){
      h+='<div style="font-size:12px;color:var(--sys-text-3);margin:4px 0 6px">'+(lang==='zh'?'最近按天统计':'Recent by day')+'</div><div class="dl-days">';
      daily.forEach(function(x){h+='<div class="dl-day"><span>'+esc(String(x.date).slice(5))+'</span><b>'+x.count+' '+(lang==='zh'?'次':'')+'</b></div>'});
      h+='</div>';
    }
    if(!logs.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:18px">'+(lang==='zh'?'暂无下载记录':'No records')+'</p>'}
    else{
      h+='<div style="font-size:12px;color:var(--sys-text-3);margin:14px 0 6px">'+(lang==='zh'?'最近记录':'Recent')+'</div><div style="max-height:300px;overflow:auto">';
      logs.slice(0,150).forEach(function(l){
        var meta=[l.country,l.ip||'',l.browser,l.os,l.device].filter(Boolean).join(' · ');
        var src=l.source==='share'?(lang==='zh'?'分享':'share'):(lang==='zh'?'网页':'web');
        h+='<div class="log-entry"><span class="log-time">'+esc(String(l.time||'').replace('T',' ').substring(5,16))+'</span>';
        h+='<span class="src-badge">'+esc(src)+'</span>';
        h+='<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(l.path||'')+'">'+esc(l.name||l.path||'')+'</span>';
        h+='<span class="dup-path" style="max-width:38%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(meta)+'</span>';
        h+='<span class="tr-meta">'+fmt(l.size||0)+'</span></div>';
      });
      h+='</div>';
    }
    h+='<div style="margin-top:12px;text-align:right"><button id="dlClearBtn" class="btn danger small">'+(lang==='zh'?'清空记录':'Clear')+'</button></div>';
    box.innerHTML=h;
    var cb=document.getElementById('dlClearBtn');
    if(cb)cb.onclick=function(){if(!confirm('OK?'))return;api('/api/clear-dl-stats',{method:'POST'}).then(showDlStats)};
  }).catch(function(e){
    var msg=String((e&&e.message)||e);
    var hint=(msg==='HTTP 404')?'<div style="margin-top:12px;font-size:12px;color:var(--sys-text-3);line-height:1.8">'+(lang==='zh'?'服务端没有这个接口，说明 Cloudflare 上运行的还是旧版代码。<br>请把最新的 worker.js 重新部署一次再试。':'The server is running an older build — redeploy the latest worker.js.')+'</div>':'';
    box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:12px 0">'+(lang==='zh'?'加载失败':'Failed')+'：'+esc(msg)+'</p>'+hint+'<div style="text-align:center;margin-top:12px"><button id="dlRetry" class="btn small">'+(lang==='zh'?'重试':'Retry')+'</button></div>';
    var rb=document.getElementById('dlRetry');if(rb)rb.onclick=showDlStats;
  });
}

// ===== 存储后端（S3 兼容镜像） =====
document.getElementById('btnBackends').onclick=function(){showBackends()};
document.getElementById('backendsClose').onclick=function(){document.getElementById('backendsModal').classList.remove('show')};
document.getElementById('backendsModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showBackends(){
  var box=document.getElementById('backendsContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('backendsModal').classList.add('show');
  api('/api/backends').then(function(d){
    var arr=d.backends||[];var h='';
    if(!arr.length){
      h='<p style="color:var(--sys-text-3);padding:8px 0 12px;font-size:13px">'+(lang==='zh'?'未配置额外的 S3 兼容后端。设置环境变量 DRIVE_BACKENDS（JSON 数组）后，上传的文件会自动镜像到这些后端；未配置时一切照旧。':'No extra backends. Set DRIVE_BACKENDS (JSON array) to mirror uploads.')+'</p>';
      h+='<pre class="hl-pre" style="max-height:220px;font-size:12px">'+esc('[{"id":"b2","endpoint":"https://s3.us-west-004.backblazeb2.com","region":"us-west-004","bucket":"my-bucket","accessKey":"...","secretKey":"...","pathStyle":true}]')+'</pre>';
    }else{
      h='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:10px">'+arr.length+(lang==='zh'?' 个后端':' backends')+'</div>';
      arr.forEach(function(b){
        var st=b.last?(b.last.ok?'<span style="color:var(--sys-green)">OK</span>':'<span style="color:var(--sys-red)">'+esc(b.last.error||'ERR')+'</span>'):'-';
        h+='<div class="token-row"><div style="flex:1;min-width:0">';
        h+='<div style="font-weight:500;font-size:14px">'+esc(b.id)+'</div>';
        h+='<div class="dup-path" style="word-break:break-all">'+esc(b.endpoint)+' / '+esc(b.bucket)+' · '+esc(b.region)+(b.pathStyle?' · path-style':'')+' · '+(lang==='zh'?'镜像上限 ':'max ')+fmt(b.mirrorMaxBytes)+'</div>';
        h+='<div class="dup-path">'+(lang==='zh'?'上次同步：':'last: ')+esc(fmtWhen(b.last&&b.last.t))+' · '+st+'</div>';
        h+='</div></div>';
      });
      h+='<div style="margin-top:12px;text-align:right"><button id="beCheck" class="btn small">'+(lang==='zh'?'检测连通性':'Check')+'</button></div>';
    }
    box.innerHTML=h;
    var cb=document.getElementById('beCheck');
    if(cb)cb.onclick=function(){beCheck()};
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}
function beCheck(){
  var btn=document.getElementById('beCheck');
  if(btn){btn.textContent=(lang==='zh'?'检测中...':'Checking...');btn.disabled=true}
  api('/api/backends/check',{method:'POST'}).then(function(d){
    var rs=d.results||[];
    var lines=rs.map(function(r){return r.id+': '+(r.ok?('OK '+r.ms+'ms'):('FAIL '+(r.error||'')))});
    alert(lines.join('\\n')||'-');
    showBackends();
  }).catch(function(){alert('Error');showBackends()});
}

// ===== 修改管理员密码 =====
document.getElementById('btnAdminPass').onclick=function(){showAdminPass()};
document.getElementById('apClose').onclick=function(){document.getElementById('apModal').classList.remove('show')};
document.getElementById('apModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showAdminPass(){
  var box=document.getElementById('apContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('apModal').classList.add('show');
  api('/api/admin-pass').then(function(d){
    var h='';
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:10px">'+(d.usingKv?(lang==='zh'?'当前：自定义密码（存于 KV）':'Using: custom password (KV)'):(lang==='zh'?'当前：环境变量 DRIVE_PASSWORD':'Using: env DRIVE_PASSWORD'))+'</div>';
    h+='<label style="font-size:13px;color:var(--sys-text-2);display:block;margin:8px 0 4px">'+(lang==='zh'?'当前密码':'Current')+'</label>';
    h+='<input id="apCur" type="password" autocomplete="off" style="width:100%;padding:10px 14px">';
    h+='<label style="font-size:13px;color:var(--sys-text-2);display:block;margin:10px 0 4px">'+(lang==='zh'?'新密码':'New password')+'</label>';
    h+='<input id="apNew" type="password" autocomplete="off" style="width:100%;padding:10px 14px">';
    h+='<div id="apMsg" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
    h+='<div style="margin-top:12px;text-align:right"><button id="apSave" class="btn small">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    box.innerHTML=h;
    document.getElementById('apSave').onclick=function(){
      var cur=document.getElementById('apCur').value, nw=document.getElementById('apNew').value;
      var msg=document.getElementById('apMsg');
      if(!nw){msg.style.color='var(--sys-red)';msg.textContent=(lang==='zh'?'新密码不能为空':'New password required');return}
      api('/api/admin-pass',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:cur,next:nw})}).then(function(r){
        if(r&&r.ok){msg.style.color='var(--sys-green)';msg.textContent=(lang==='zh'?'已修改，请用新密码重新登录':'Changed, please log in again');
          setTimeout(function(){tk='';try{sessionStorage.removeItem('dt')}catch(e){};document.getElementById('apModal').classList.remove('show');show('login')},1200);
        }else{msg.style.color='var(--sys-red)';msg.textContent=(r&&r.error)||(lang==='zh'?'修改失败':'Failed')}
      }).catch(function(){msg.style.color='var(--sys-red)';msg.textContent=(lang==='zh'?'修改失败':'Failed')});
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}

// ===== 二次验证（TOTP）=====
document.getElementById('btnTotp').onclick=function(){showTotp()};
function totpModal(){
  var box=document.getElementById('totpModal');
  if(!box){
    box=document.createElement('div');
    box.id='totpModal';box.className='modal-bg';
    box.innerHTML='<div class="modal" style="min-width:380px;max-width:560px"><button class="mclose" id="totpClose">✕</button><h3>🛡 '+(lang==='zh'?'二次验证':'Two-factor')+'</h3><div id="totpContent"></div></div>';
    document.body.appendChild(box);
    document.getElementById('totpClose').onclick=function(){box.classList.remove('show')};
    box.onclick=function(e){if(e.target===box)box.classList.remove('show')};
  }
  return box;
}
function totpCodesHtml(codes){
  if(!codes||!codes.length)return '';
  var h='<div style="margin-top:12px;padding:10px 12px;background:var(--sys-red-soft);border-radius:10px">';
  h+='<div style="font-size:12px;color:var(--sys-red);margin-bottom:6px">'+(lang==='zh'?'备用码（仅显示这一次，请立即保存）':'Backup codes (shown once)')+'</div>';
  h+='<pre style="margin:0;font-size:13px;white-space:pre-wrap;word-break:break-all">'+esc(codes.join('  '))+'</pre>';
  h+='<div style="margin-top:8px;text-align:right"><button id="totpCopyCodes" class="btn gray tiny">'+(lang==='zh'?'复制':'Copy')+'</button></div></div>';
  return h;
}
function showTotp(){
  var box=totpModal();
  var c=document.getElementById('totpContent');
  c.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  box.classList.add('show');
  api('/api/totp').then(function(d){
    var h='';
    h+='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.8;margin-bottom:12px">'+(lang==='zh'
      ?'开启后登录需要额外输入 6 位动态码（Google Authenticator / 1Password / Authy 等），并可生成一次性备用码。'
      :'After enabling, login requires a 6-digit code (Google Authenticator / 1Password / Authy).')+'</div>';
    if(d.enabled){
      h+='<div class="token-row"><span class="token-name">'+(lang==='zh'?'状态：已开启':'Status: enabled')+'</span><span class="dup-path">'+(lang==='zh'?'备用码剩余 ':'backup left ')+(d.backupLeft||0)+'</span></div>';
      h+='<label style="font-size:13px;color:var(--sys-text-2);display:block;margin:10px 0 4px">'+(lang==='zh'?'管理员密码':'Admin password')+'</label><input id="totpPw" type="password" autocomplete="off" style="width:100%;padding:10px 14px">';
      h+='<label style="font-size:13px;color:var(--sys-text-2);display:block;margin:10px 0 4px">'+(lang==='zh'?'动态码':'Code')+'</label><input id="totpCode2" inputmode="numeric" autocomplete="one-time-code" style="width:100%;padding:10px 14px">';
      h+='<div id="totpMsg" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
      h+='<div id="totpCodes"></div>';
      h+='<div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end"><button id="totpRegen" class="btn gray small">'+(lang==='zh'?'重新生成备用码':'New backup codes')+'</button><button id="totpOff" class="btn danger small">'+(lang==='zh'?'关闭二次验证':'Disable')+'</button></div>';
    }else if(d.pending){
      h+='<div class="dup-path" style="line-height:1.8">'+(lang==='zh'?'已生成密钥，请用验证器扫码并输入一次动态码完成绑定。':'Scan the QR and enter a code to finish setup.')+'</div>';
      h+='<div id="totpSetupBox"></div>';
      h+='<div style="margin-top:10px"><button id="totpAgain" class="btn gray small">'+(lang==='zh'?'重新生成密钥':'New secret')+'</button></div>';
    }else{      h+='<div style="margin-top:6px"><button id="totpStart" class="btn small">'+(lang==='zh'?'生成密钥并绑定':'Set up')+'</button></div>';
    }
    h+='<div id="totpMsg2" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
    c.innerHTML=h;
    var startBtn=document.getElementById('totpStart');
    if(startBtn)startBtn.onclick=function(){totpSetup()};
    var againBtn=document.getElementById('totpAgain');
    if(againBtn)againBtn.onclick=function(){totpSetup()};
    // pending（已有待确认密钥）时直接显示出二维码，省一次点击
    if(!d.enabled&&d.pending)try{totpSetup()}catch(e){}
    var offBtn=document.getElementById('totpOff');
    if(offBtn)offBtn.onclick=function(){
      var msg=document.getElementById('totpMsg');
      api('/api/totp/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('totpPw').value,code:document.getElementById('totpCode2').value})}).then(function(r){
        if(r&&r.ok){showTotp()}else{msg.style.color='var(--sys-red)';msg.textContent=(r&&r.error)||'failed'}
      });
    };
    var regenBtn=document.getElementById('totpRegen');
    if(regenBtn)regenBtn.onclick=function(){
      var msg=document.getElementById('totpMsg');
      api('/api/totp/backup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('totpPw').value,code:document.getElementById('totpCode2').value})}).then(function(r){
        if(r&&r.ok){
          var box2=document.getElementById('totpCodes');
          box2.innerHTML=totpCodesHtml(r.backupCodes);
          bindCopyCodes();
        }else{msg.style.color='var(--sys-red)';msg.textContent=(r&&r.error)||'failed'}
      });
    };
  }).catch(function(){c.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
function bindCopyCodes(){
  var b=document.getElementById('totpCopyCodes');
  if(b)b.onclick=function(){
    var pre=document.querySelector('#totpCodes pre');
    if(pre){try{navigator.clipboard.writeText(pre.textContent)}catch(e){};b.textContent=(lang==='zh'?'已复制':'Copied')}
  };
}
function totpSetup(){
  var host=document.getElementById('totpContent');
  var box=document.getElementById('totpSetupBox');
  if(!box){box=document.createElement('div');box.id='totpSetupBox';host.appendChild(box)}
  api('/api/totp/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:location.hostname||'PersonalDrive'})}).then(function(d){
    if(!d||!d.secret){var m=document.getElementById('totpMsg2');if(m){m.style.color='var(--sys-red)';m.textContent=(d&&d.error)||'failed'}return}
    var grouped=d.secret.replace(/(.{4})/g,'$1 ').trim();
    var h='<div style="text-align:center;margin:10px 0"><div id="totpQR" style="display:inline-block;padding:8px;background:#fff;border-radius:10px"></div></div>';
    h+='<div class="dup-path" style="word-break:break-all">'+esc(grouped)+'</div>';
    h+='<div style="margin-top:8px"><button id="totpCopySecret" class="btn gray tiny">'+(lang==='zh'?'复制密钥':'Copy secret')+'</button></div>';
    h+='<label style="font-size:13px;color:var(--sys-text-2);display:block;margin:10px 0 4px">'+(lang==='zh'?'输入验证器上的 6 位码':'6-digit code')+'</label>';
    h+='<input id="totpEnableCode" inputmode="numeric" autocomplete="one-time-code" style="width:100%;padding:10px 14px">';
    h+='<div style="margin-top:10px;text-align:right"><button id="totpDoEnable" class="btn small">'+(lang==='zh'?'启用':'Enable')+'</button></div>';
    h+='<div id="totpCodes"></div>';
    box.innerHTML=h;
    try{
      if(typeof QRCode!=='undefined'){new QRCode(document.getElementById('totpQR'),{text:d.otpauth,width:168,height:168,correctLevel:QRCode.CorrectLevel.M})}
      else{document.getElementById('totpQR').textContent='QR lib not loaded'}
    }catch(e){}
    document.getElementById('totpCopySecret').onclick=function(){try{navigator.clipboard.writeText(d.secret)}catch(e){};this.textContent=(lang==='zh'?'已复制':'Copied')};
    document.getElementById('totpDoEnable').onclick=function(){
      api('/api/totp/enable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:document.getElementById('totpEnableCode').value})}).then(function(r){
        if(r&&r.ok){
          document.getElementById('totpCodes').innerHTML=totpCodesHtml(r.backupCodes);
          bindCopyCodes();
          var btn=document.getElementById('totpDoEnable');if(btn){btn.disabled=true;btn.textContent=(lang==='zh'?'已启用':'Enabled')}
        }else{
          var m=document.getElementById('totpMsg2');if(m){m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
        }
      });
    };
  }).catch(function(){var m=document.getElementById('totpMsg2');if(m){m.style.color='var(--sys-red)';m.textContent='failed'}});
}

// ===== 防外链：限时直链 =====
function signedLink(path,base){
  base=base||cur;
  var full=path||'';
  if(full.indexOf('/')!==0)full=base+full;
  var ttl=prompt((lang==='zh'?'有效期（分钟，1–43200）：':'TTL (minutes):'),'60');
  if(ttl===null)return;
  var bind=(prompt((lang==='zh'?'绑定当前 IP？输入 1 绑定，其它为不绑定：':'Bind to my IP? 1=yes:'),'')||'')==='1';
  api('/api/sign',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:full,ttl:(parseInt(ttl,10)||60)*60,bindIp:bind})}).then(function(r){
    if(r&&r.url){
      var u=location.origin+r.url;
      try{navigator.clipboard.writeText(u)}catch(e){}
      prompt((lang==='zh'?'限时直链（已复制）：':'Signed link (copied):'),u);
    }else alert((r&&r.error)||'failed');
  });
}

// ===== 运维与配置（站点配置 / 目录规则 / 定时任务）=====
document.getElementById('btnOps').onclick=function(){showOps('config')};
document.getElementById('btnImport').onclick=function(){importWebdav()};
document.getElementById('btnSimilar').onclick=function(){showSimilar()};
document.getElementById('btnImgTools').onclick=function(){showImgTools()};
document.getElementById('btnQuery').onclick=function(){queryScope=cur;showQuery()};
document.getElementById('btnFavGroups').onclick=function(){showFavGroups()};
document.getElementById('btnMeta').onclick=function(){showMetaIO()};
function opsModal(){
  var m=document.getElementById('opsModal');
  if(!m){
    m=document.createElement('div');
    m.id='opsModal';m.className='modal-bg';
    m.innerHTML='<div class="modal" style="min-width:440px;max-width:760px"><button class="mclose" id="opsClose">✕</button><h3>🛠 '+(lang==='zh'?'运维与配置':'Ops &amp; Config')+'</h3><div class="filter-bar" style="border:0;padding:0 0 10px"><button class="fchip" data-opst="config">'+(lang==='zh'?'站点配置':'Config')+'</button><button class="fchip" data-opst="rules">'+(lang==='zh'?'目录规则':'Dir rules')+'</button><button class="fchip" data-opst="cron">'+(lang==='zh'?'定时任务':'Cron')+'</button></div><div id="opsContent"></div></div>';
    document.body.appendChild(m);
    document.getElementById('opsClose').onclick=function(){m.classList.remove('show')};
    m.onclick=function(e){if(e.target===m)m.classList.remove('show')};
  }
  return m;
}
function showOps(tab){
  var m=opsModal();
  var box=document.getElementById('opsContent');
  m.classList.add('show');
  m.querySelectorAll('[data-opst]').forEach(function(b){b.classList.toggle('active',b.getAttribute('data-opst')===tab);b.onclick=function(){showOps(b.getAttribute('data-opst'))}});
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  if(tab==='config')opsConfig(box);
  else if(tab==='rules')opsRules(box);
  else opsCron(box);
}
function opsConfig(box){
  api('/api/config').then(function(d){
    var eff=d.effective||{},src=d.sources||{};
    var groups=[
      [ '站点',[['title','标题','text'],['logo','Logo','text'],['notice','公告（显示在顶部）','text']] ],
      [ '配额与上传',[['quotaGB','总配额 (GB)','number'],['maxUploadMB','单文件上限 (MB)','number'],['maxDirItems','单目录条目上限','number'],['kvValueMB','目录元数据 KV 上限 (MB)','number']] ],
      [ '版本与回收站',[['versionMaxMB','保留历史版本的文件上限 (MB)','number'],['versionsMax','每个文件保留版本数','number'],['versionsTtlDays','版本索引 TTL (天)','number'],['hashTtlDays','秒传索引 TTL (天)','number'],['trashDays','回收站保留 (天)','number'],['chunkGcHours','分片回收 (小时)','number']] ],
      [ '备份',[['backupIncremental','增量快照','bool'],['backupKeep','保留份数','number'],['backupMaxMB','单份快照元数据上限 (MB)','number'],['backupTotalMB','快照总占用上限 (MB)','number']] ],
      [ '防爆与性能',[['telemetryMaxPerDay','每日遥测写预算','number'],['telemetryFlushMs','遥测合并窗口 (ms)','number'],['sessionCacheSec','会话缓存 (秒)','number'],['kvBudgetPerMin','KV 每分钟写预算','number'],['rlReadPerMin','读限流 (次/分)','number'],['rlWritePerMin','写限流 (次/分)','number']] ],
      [ '安全与风控',[['disableUrlFetch','禁用远程 URL 抓取','bool'],['ipAllow','IP 白名单','text'],['ipDeny','IP 黑名单','text'],['countryAllow','地区白名单','text'],['countryDeny','地区黑名单','text'],['uaAllow','UA 白名单','text'],['uaDeny','UA 黑名单','text'],['signTtlMin','直链默认有效期 (分)','number']] ],
      [ '公开上传 / 分享',[['publicUploadDir','公开上传目录','text'],['publicUploadMaxMB','公开上传单文件上限 (MB)','number'],['shareZipMaxMB','分享打包上限 (MB)','number']] ]
    ];
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:10px">'+(lang==='zh'?'这里保存的配置写入 KV，优先级高于环境变量；留空表示使用环境变量/默认值。':'KV overrides > env vars > defaults.')+'</div>';
    groups.forEach(function(g){
      h+='<div style="margin:10px 0 6px;font-size:13px;font-weight:600">'+g[0]+'</div>';
      g[1].forEach(function(f){
        var k=f[0],label=f[1],t=f[2];
        var v=eff[k];
        var badge=src[k]==='kv'?'<span style="color:var(--sys-blue)">KV</span>':(src[k]==='env'?'<span style="color:var(--sys-orange)">ENV</span>':'<span style="color:var(--sys-text-3)">默认</span>');
        h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+label+' <span style="font-size:11px">'+badge+'</span></span>';
        if(t==='bool')h+='<input type="checkbox" id="cfg_'+k+'" '+(v?'checked':'')+'>';
        else h+='<input id="cfg_'+k+'" type="'+(t==='number'?'number':'text')+'" value="'+esc(v==null?'':String(v))+'" style="flex:1;padding:6px 10px">';
        h+='</div>';
      });
    });
    h+='<div id="cfgMsg" style="font-size:13px;min-height:18px;margin:8px 0"></div>';
    h+='<div style="text-align:right;display:flex;gap:8px;justify-content:flex-end"><button id="cfgReset" class="btn gray small">'+(lang==='zh'?'全部恢复默认':'Reset')+'</button><button id="cfgSave" class="btn small">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    box.innerHTML=h;
    document.getElementById('cfgSave').onclick=function(){
      var patch={};
      groups.forEach(function(g){g[1].forEach(function(f){
        var el=document.getElementById('cfg_'+f[0]);if(!el)return;
        if(f[2]==='bool')patch[f[0]]=el.checked;
        else{var val=(el.value||'').trim();patch[f[0]]=val===''?null:(f[2]==='number'?Number(val):val)}
      })});
      var msg=document.getElementById('cfgMsg');
      api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({patch:patch})}).then(function(r){
        if(r&&r.ok){msg.style.color='var(--sys-green)';msg.textContent=(lang==='zh'?'已保存并立即生效':'Saved');showOps('config')}
        else{msg.style.color='var(--sys-red)';msg.textContent=(r&&r.error)||'failed'}
      });
    };
    document.getElementById('cfgReset').onclick=function(){
      if(!confirm(lang==='zh'?'清除所有 KV 配置覆盖？':'Clear all KV overrides?'))return;
      api('/api/config/reset',{method:'POST'}).then(function(){showOps('config')});
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
function opsRules(box){
  api('/api/dirrules').then(function(d){
    var rules=d.rules||[];
    var mine=null;
    rules.forEach(function(r){if(normP(r.path)===cur)mine=r});
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:8px">'+(lang==='zh'?'当前目录：':'Current folder: ')+esc(cur)+'</div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'文件数上限':'Max files')+'</span><input id="drItems" type="number" value="'+(mine&&mine.maxItems||'')+'" style="flex:1;padding:6px 10px"></div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'目录容量上限 (MB)':'Max MB')+'</span><input id="drBytes" type="number" value="'+(mine&&mine.maxBytes||'')+'" style="flex:1;padding:6px 10px"></div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'单文件上限 (MB)':'Max file MB')+'</span><input id="drFile" type="number" value="'+(mine&&mine.maxFileMB||'')+'" style="flex:1;padding:6px 10px"></div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'只允许扩展名（如 .jpg,.png）':'Allow ext')+'</span><input id="drAllow" value="'+esc(mine&&mine.extAllow||'')+'" style="flex:1;padding:6px 10px"></div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span style="flex:0 0 44%">'+(lang==='zh'?'拒绝扩展名':'Deny ext')+'</span><input id="drDeny" value="'+esc(mine&&mine.extDeny||'')+'" style="flex:1;padding:6px 10px"></div>';
    h+='<div id="drMsg" style="font-size:13px;min-height:18px"></div>';
    h+='<div style="text-align:right;display:flex;gap:8px;justify-content:flex-end"><button id="drDel" class="btn gray small">'+(lang==='zh'?'删除本目录规则':'Delete rule')+'</button><button id="drSave" class="btn small">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'全部规则':'All rules')+' ('+rules.length+')</div>';
    if(!rules.length)h+='<div class="dup-path">'+(lang==='zh'?'暂无规则':'No rules')+'</div>';
    rules.forEach(function(r){
      h+='<div class="token-row"><span class="token-name">'+esc(r.path)+'</span><span class="dup-path">'
        +(r.maxItems?('≤'+r.maxItems+' files '):'')+(r.maxBytes?('≤'+r.maxBytes+'MB '):'')+(r.maxFileMB?('file≤'+r.maxFileMB+'MB '):'')
        +(r.extAllow?('allow:'+esc(r.extAllow)+' '):'')+(r.extDeny?('deny:'+esc(r.extDeny)):'')+'</span>'
        +'<button class="btn tiny danger" data-drdel="'+esc(r.path)+'">✕</button></div>';
    });
    box.innerHTML=h;
    function post(extra){
      var body=Object.assign({path:cur,delete:extra&&extra.del?cur:undefined},{
        maxItems:parseInt(document.getElementById('drItems').value,10)||0,
        maxBytes:parseInt(document.getElementById('drBytes').value,10)||0,
        maxFileMB:parseInt(document.getElementById('drFile').value,10)||0,
        extAllow:document.getElementById('drAllow').value,
        extDeny:document.getElementById('drDeny').value
      });
      api('/api/dirrules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){
        if(r&&r.ok)showOps('rules');else{var m=document.getElementById('drMsg');if(m){m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}}
      });
    }
    document.getElementById('drSave').onclick=function(){post()};
    document.getElementById('drDel').onclick=function(){post({del:true})};
    box.querySelectorAll('[data-drdel]').forEach(function(b){b.onclick=function(){
      api('/api/dirrules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({delete:b.getAttribute('data-drdel')})}).then(function(){showOps('rules')});
    }});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
function opsCron(box){
  api('/api/cron').then(function(d){
    var jobs=d.jobs||[];
    var K={ 'ttl-dir':(lang==='zh'?'过期清理':'TTL clean'), 'clean-dir':(lang==='zh'?'清空目录':'Empty dir'), 'archive':(lang==='zh'?'自动归档':'Archive') };
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:8px">'+(lang==='zh'?'定时任务在 cron 触发时执行，也可手动运行；单次最多处理 500 个条目。':'Runs on cron; max 500 entries per run.')+'</div>';
    if(!jobs.length)h+='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'暂无任务':'No jobs')+'</div>';
    jobs.forEach(function(j){
      h+='<div class="token-row"><div style="flex:1;min-width:0"><div style="font-size:13.5px">'+esc(K[j.kind]||j.kind)+' · '+esc(j.path)+'</div><div class="dup-path">'+(lang==='zh'?'days ':'days ')+j.days+(j.toTrash?' → '+(lang==='zh'?'回收站':'trash'):' → '+(lang==='zh'?'彻底删除':'purge'))+' · '+esc(j.lastResult||(lang==='zh'?'未运行':'never'))+'</div></div>'
        +'<button class="btn gray tiny" data-crun="'+esc(j.id)+'">▶</button><button class="btn tiny danger" data-cdel="'+esc(j.id)+'">✕</button></div>';
    });
    h+='<div style="margin:14px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'新建任务':'New job')+'</div>';
    h+='<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">'
      +'<select id="cjKind" style="padding:6px 8px"><option value="ttl-dir">'+K['ttl-dir']+'</option><option value="archive">'+K['archive']+'</option><option value="clean-dir">'+K['clean-dir']+'</option></select>'
      +'<input id="cjPath" value="'+esc(cur)+'" style="flex:1;min-width:140px;padding:6px 10px">'
      +'<input id="cjDays" type="number" value="30" style="width:80px;padding:6px 10px" title="days">'
      +'<label style="display:flex;gap:4px;align-items:center;font-size:12.5px"><input type="checkbox" id="cjTrash" checked>'+(lang==='zh'?'进回收站':'to trash')+'</label>'
      +'<button id="cjAdd" class="btn small">'+(lang==='zh'?'添加':'Add')+'</button></div>';
    h+='<div id="cjMsg" style="font-size:13px;min-height:18px;margin-top:6px"></div>';
    box.innerHTML=h;
    document.getElementById('cjAdd').onclick=function(){
      var dv=parseInt(document.getElementById('cjDays').value,10);
      var body={kind:document.getElementById('cjKind').value,path:document.getElementById('cjPath').value,days:isNaN(dv)?30:Math.max(0,dv),toTrash:document.getElementById('cjTrash').checked};
      api('/api/cron',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){
        if(r&&r.ok)showOps('cron');else{var m=document.getElementById('cjMsg');if(m){m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}}
      });
    };
    box.querySelectorAll('[data-crun]').forEach(function(b){b.onclick=function(){
      b.textContent='…';
      api('/api/cron',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({run:b.getAttribute('data-crun')})}).then(function(r){
        if(r&&r.result)alert(JSON.stringify(r.result));showOps('cron');
      });
    }});
    box.querySelectorAll('[data-cdel]').forEach(function(b){b.onclick=function(){
      api('/api/cron',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({delete:b.getAttribute('data-cdel')})}).then(function(){showOps('cron')});
    }});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">Error</p>'});
}
// ===== 从 WebDAV 导入 =====
function importWebdav(){
  var url=prompt((lang==='zh'?'远程 WebDAV 地址（目录）:':'WebDAV folder URL:'),'https://example.com/dav/folder/');
  if(!url)return;
  var user=prompt((lang==='zh'?'用户名（可留空）:':'Username (optional):'),'')||'';
  var pass=user?(prompt((lang==='zh'?'密码:':'Password:'),'')||''):'';
  var maxFiles=parseInt(prompt((lang==='zh'?'本次最多导入文件数（≤200）:':'Max files (≤200):'),'100')||'100',10)||100;
  var div=makeUpItem((lang==='zh'?'WebDAV 导入':'WebDAV import'));
  div.querySelector('.upst').textContent='...';
  api('/api/import-webdav',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url,user:user,pass:pass,path:cur,maxFiles:maxFiles})}).then(function(r){
    if(r&&r.ok){
      div.querySelector('.upfill').style.width='100%';
      div.querySelector('.upst').textContent=(lang==='zh'?'完成 ':'done ')+r.imported;
      div.querySelector('.upst').style.color='var(--sys-green)';
      setTimeout(function(){if(div.parentNode)div.parentNode.removeChild(div)},2000);
      alert((lang==='zh'?'导入完成：':'Imported: ')+r.imported+' · '+(lang==='zh'?'跳过 ':'skipped ')+r.skipped+' · '+(lang==='zh'?'失败 ':'failed ')+r.failed+' · '+fmt(r.bytes));
      load();
    }else{
      div.querySelector('.upst').textContent=(r&&r.error)||t('upFail');
      div.querySelector('.upst').style.color='var(--sys-red)';
    }
  }).catch(function(){div.querySelector('.upst').textContent=t('upFail');div.querySelector('.upst').style.color='var(--sys-red)'});
}

// ===== 批量分享 / 批量移动 =====
document.getElementById('batchShare').onclick=function(){
  var keys=Object.keys(selected);if(!keys.length)return;
  var days=prompt(t('days'),'7');if(!days)return;
  var mx=prompt(t('maxAcc'),'0');if(mx===null)return;
  var pw=prompt(t('sharePw'),'');if(pw===null)return;
  api('/api/batch-share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys,days:parseInt(days),max:parseInt(mx)||0,password:pw||''})}).then(function(r){
    var items=(r&&r.items)||[];
    // 锁定/失败的条目服务端只返回 {path,error}（没有 url），必须过滤，否则会复制出 "域名undefined"
    var txt=items.filter(function(i){return i&&i.url}).map(function(i){return location.origin+i.url}).join('\\n');
    var bad=items.filter(function(i){return i&&!i.url}).length;
    if(txt){try{navigator.clipboard.writeText(txt)}catch(e){}}
    prompt((lang==='zh'?'已创建 ':'Created ')+((r&&r.created)||0)+'/'+keys.length+(bad?((lang==='zh'?'（'+bad+' 项失败）':' ('+bad+' failed)')):''),txt||'-');
    render();
  });
};
document.getElementById('batchMv').onclick=function(){
  var keys=Object.keys(selected);if(!keys.length)return;
  api('/api/search?q=&path=/').then(function(all){
    var dirs=[{path:'/',label:'/ (Root)'}];var seen={'/':true};
    (all.results||[]).forEach(function(r){if(r.type==='dir'){var p=r.path+r.name+'/';if(!seen[p]){seen[p]=true;dirs.push({path:p,label:p})}}});
    var box=document.getElementById('mvContent');var h='';
    dirs.forEach(function(d){h+='<div class="mi" data-bmp="'+esc(d.path)+'" style="padding:10px 14px;cursor:pointer;border-radius:8px;font-size:14px;color:var(--sys-blue);font-weight:500">'+esc(d.label)+'</div>'});
    box.innerHTML=h;document.getElementById('mvTitle').textContent=t('moveTo');document.getElementById('mvModal').classList.add('show');
    box.querySelectorAll('[data-bmp]').forEach(function(el){
      el.onclick=function(){
        api('/api/batch-move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys,target:el.getAttribute('data-bmp')})}).then(function(){
          document.getElementById('mvModal').classList.remove('show');selected={};load();
        });
      };
      el.onmouseenter=function(){el.style.background='var(--sys-fill)'};
      el.onmouseleave=function(){el.style.background=''};
    });
  });
};

// ===== 自动归档规则 =====
document.getElementById('btnAutoRule').onclick=function(){showAutoRule()};
document.getElementById('autoClose').onclick=function(){document.getElementById('autoModal').classList.remove('show')};
document.getElementById('autoModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showAutoRule(){
  var box=document.getElementById('autoContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('autoModal').classList.add('show');
  api('/api/auto-rule').then(function(r){
    var on=!!r.enabled,mode=r.mode||'date',base=r.base||'/';
    var h='<label style="display:flex;align-items:center;gap:8px;font-size:14px;margin-bottom:12px"><input type="checkbox" id="arOn" '+(on?'checked':'')+' style="width:16px;height:16px;accent-color:var(--sys-blue)">'+(lang==='zh'?'开启上传后自动归档':'Enable auto-archive')+'</label>';
    h+='<div style="font-size:13px;color:var(--sys-text-2);margin:8px 0 4px">'+(lang==='zh'?'归档方式':'Mode')+'</div>';
    h+='<select id="arMode" style="width:100%;padding:9px 12px"><option value="date"'+(mode==='date'?' selected':'')+'>'+(lang==='zh'?'按年月（2026/10/）':'By year-month')+'</option><option value="type"'+(mode==='type'?' selected':'')+'>'+(lang==='zh'?'按类型（图片/视频/文档…）':'By type')+'</option></select>';
    h+='<div style="font-size:13px;color:var(--sys-text-2);margin:10px 0 4px">'+(lang==='zh'?'生效目录':'Base folder')+'</div>';
    h+='<input id="arBase" value="'+esc(base)+'" placeholder="/" style="width:100%;padding:9px 12px">';
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-top:8px">'+(lang==='zh'?'上传到该目录（含子目录）的文件会自动归入子文件夹，原目录不受影响。':'Files uploaded into this folder (and below) get sorted into subfolders.')+'</div>';
    h+='<div id="arMsg" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
    h+='<div style="margin-top:12px;text-align:right"><button id="arSave" class="btn small">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    box.innerHTML=h;
    document.getElementById('arSave').onclick=function(){
      var m=document.getElementById('arMsg');
      api('/api/auto-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('arOn').checked,mode:document.getElementById('arMode').value,base:document.getElementById('arBase').value||'/'})}).then(function(r2){
        if(r2&&r2.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'已保存':'Saved');setTimeout(function(){document.getElementById('autoModal').classList.remove('show')},700)}
        else{m.style.color='var(--sys-red)';m.textContent=(r2&&r2.error)||'failed'}
      }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}
document.getElementById('btnClearPend').onclick=function(){showPending()};

// ===== 登录设备 / 会话管理 =====
document.getElementById('btnSessions').onclick=function(){showSessions()};
document.getElementById('sessClose').onclick=function(){document.getElementById('sessModal').classList.remove('show')};
document.getElementById('sessModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showSessions(){
  var box=document.getElementById('sessContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('sessModal').classList.add('show');
  api('/api/sessions').then(function(d){
    var arr=d.sessions||[];var others=arr.filter(function(s){return !s.current});
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:10px">'+arr.length+(lang==='zh'?' 个活跃会话':' sessions');
    if(d.ipAllow||d.ipDeny){h+=' · IP '+(lang==='zh'?'白名单':'allow')+' '+esc(d.ipAllow||'-')+' / '+(lang==='zh'?'黑名单':'deny')+' '+esc(d.ipDeny||'-')}
    h+='</div>';
    if(!arr.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'无':'None')+'</p>'}
    arr.forEach(function(s){
      h+='<div class="token-row"><div style="flex:1;min-width:0">';
      h+='<div style="font-weight:500;font-size:13.5px">'+esc([s.browser,s.os,s.device].filter(Boolean).join(' · ')||'Unknown')+(s.current?' <span style="color:var(--sys-green);font-size:12px">'+(lang==='zh'?'当前':'current')+'</span>':'')+'</div>';
      h+='<div class="dup-path">'+esc(s.ip||'-')+' · '+esc(fmtWhen(s.created))+'</div></div>';
      if(!s.current)h+='<button class="btn tiny danger" data-srev="'+esc(s.id)+'">'+(lang==='zh'?'踢下线':'Kick')+'</button>';
      h+='</div>';
    });
    if(others.length)h+='<div style="margin-top:12px;text-align:right"><button id="sessAll" class="btn danger small">'+(lang==='zh'?'踢出其他全部':'Kick all others')+'</button></div>';
    box.innerHTML=h;
    box.querySelectorAll('[data-srev]').forEach(function(b){b.onclick=function(){api('/api/session-revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:b.getAttribute('data-srev')})}).then(showSessions)}});
    var all=document.getElementById('sessAll');
    if(all)all.onclick=function(){
      if(!confirm('OK?'))return;
      var ids=others.map(function(s){return s.id});
      Promise.all(ids.map(function(id){return api('/api/session-revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})})).then(showSessions);
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
}

// ===== 备份与恢复 =====
document.getElementById('btnBackup').onclick=function(){showBackup()};
document.getElementById('bkClose').onclick=function(){document.getElementById('bkModal').classList.remove('show')};
document.getElementById('bkModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showBackup(){
  document.getElementById('bkModal').classList.add('show');
  loadBackups();
}
function loadBackups(){
  var box=document.getElementById('bkContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  api('/api/backups').then(function(d){
    var arr=d.backups||[];
    var h='<div style="display:flex;gap:10px;align-items:center;margin-bottom:10px"><button id="bkNow" class="btn small">'+(lang==='zh'?'立即备份':'Backup now')+'</button><span id="bkMsg" style="font-size:12px;color:var(--sys-text-3)"></span></div>';
    h+='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.75;margin-bottom:10px">'+(lang==='zh'?'快照包含<b>目录树、标签、备注、分享链接、上传链接、文件夹密码、收藏、最近、用量</b>，保存在 R2 的 <code>.backup/</code> 下（不出现在文件列表），保留份数与总占用均可在运维面板调整。增量快照只记录发生变化的目录，恢复时会自动沿快照链合并。<br><b style="color:var(--sys-orange)">注意：快照只含元数据，不含文件内容本身</b>。':'Metadata-only snapshots under R2 .backup/; incremental snapshots store only changed folders and are merged on restore.')+'</div>';
    if(d.last)h+='<div class="dup-path" style="margin-bottom:8px">'+(lang==='zh'?'最近一份：':'Latest: ')+esc(fmtWhen(Date.parse(d.last.created))||'')+' · '+(d.last.base?(lang==='zh'?'增量（链长 ':'incremental (chain ')+d.last.chain+')':(lang==='zh'?'全量':'full'))+' · '+(d.last.dirs||0)+(lang==='zh'?' 个目录':' dirs')+'</div>';
    if(!arr.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:16px">'+(lang==='zh'?'还没有快照，点「立即备份」创建第一份':'No snapshots yet')+'</p>'}
    else{
      h+='<div style="max-height:260px;overflow:auto">';
      arr.forEach(function(b){
        var nm=String(b.key).replace('.backup/','');
        var isLast=d.last&&d.last.key===b.key;
        h+='<div class="token-row"><div style="flex:1;min-width:0"><div style="font-size:13px;font-family:ui-monospace,Menlo,monospace">'+esc(nm)+(isLast?' <span style="color:var(--sys-blue);font-size:11px">'+(lang==='zh'?'最新':'latest')+'</span>':'')+'</div><div class="dup-path">'+fmt(b.size||0)+(b.uploaded?(' · '+esc(fmtWhen(Date.parse(b.uploaded)))):'')+(isLast&&d.last.base?(' · '+(lang==='zh'?'增量':'incr')):'')+'</div></div>';
        h+='<button class="btn gray tiny" data-bkdf="'+esc(b.key)+'">'+(lang==='zh'?'差异':'Diff')+'</button>';
        h+='<button class="btn gray tiny" data-bkdl="'+esc(b.key)+'">'+(lang==='zh'?'下载':'Download')+'</button>';
        h+='<button class="btn gray tiny" data-bkrs="'+esc(b.key)+'">'+(lang==='zh'?'恢复':'Restore')+'</button></div>';
      });
      h+='</div>';
    }
    h+='<div id="bkRs"></div>';
    box.innerHTML=h;
    document.getElementById('bkNow').onclick=function(){
      var m=document.getElementById('bkMsg');m.style.color='var(--sys-text-3)';m.textContent=(lang==='zh'?'备份中...':'Backing up...');
      api('/api/backup',{method:'POST'}).then(function(r){
        if(r&&r.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'完成：':'Done: ')+r.dirs+(lang==='zh'?' 个目录 / ':' dirs / ')+r.files+(lang==='zh'?' 个文件 / ':' files / ')+r.kvKeys+(lang==='zh'?' 条元数据':' keys');loadBackups()}
        else{m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
      }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
    };
    box.querySelectorAll('[data-bkdl]').forEach(function(b){b.onclick=function(){window.open('/api/backup-download?key='+encodeURIComponent(b.getAttribute('data-bkdl'))+'&token='+tk,'_blank')}});
    box.querySelectorAll('[data-bkrs]').forEach(function(b){b.onclick=function(){askRestore(b.getAttribute('data-bkrs'))}});
    box.querySelectorAll('[data-bkdf]').forEach(function(b){b.onclick=function(){
      var key=b.getAttribute('data-bkdf');b.textContent='…';
      api('/api/backup-diff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:key})}).then(function(r){
        b.textContent=(lang==='zh'?'差异':'Diff');
        if(r&&r.addedTotal!==undefined){
          alert((lang==='zh'?'相对当前状态：\\n新增目录 ':'vs now:\\nadded ')+r.addedTotal+'\\n'+(lang==='zh'?'删除目录 ':'removed ')+r.removedTotal+'\\n'+(lang==='zh'?'内容变化 ':'changed ')+r.changedTotal+'\\n'+(lang==='zh'?'快照目录 ':'snapshot dirs ')+r.snapshotDirs+' · '+(lang==='zh'?'链长 ':'chain ')+r.chain);
        }else alert((r&&r.error)||'failed');
      }).catch(function(){b.textContent=(lang==='zh'?'差异':'Diff');alert('failed')});
    }});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:14px">'+(lang==='zh'?'加载失败':'Failed')+'</p>'});
}
function askRestore(key){
  var el=document.getElementById('bkRs');
  el.innerHTML='<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--sys-separator)"><div style="font-size:12px;color:var(--sys-red);line-height:1.7;margin-bottom:8px">'+(lang==='zh'?'恢复会用该快照覆盖当前目录树与标签/备注/分享等元数据，<b>不可撤销</b>。请输入管理员密码确认。':'This overwrites current metadata and cannot be undone. Enter the admin password.')+'</div>'
    +'<input id="bkPw" type="password" placeholder="'+(lang==='zh'?'管理员密码':'Admin password')+'" style="width:100%;padding:9px 12px;margin-bottom:8px">'
    +'<div id="bkRsMsg" style="font-size:13px;min-height:18px"></div>'
    +'<div style="text-align:right;margin-top:8px"><button id="bkRsGo" class="btn danger small">'+(lang==='zh'?'确认恢复 ':'Restore ')+esc(String(key).split('/').pop())+'</button></div></div>';
  document.getElementById('bkRsGo').onclick=function(){
    var m=document.getElementById('bkRsMsg');
    api('/api/backup-restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:key,password:document.getElementById('bkPw').value})}).then(function(r){
      if(r&&r.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'已恢复 ':'Restored ')+r.dirs+(lang==='zh'?' 个目录 / ':' dirs / ')+r.kvKeys+(lang==='zh'?' 条元数据，正在刷新…':' keys, reloading…');setTimeout(function(){document.getElementById('bkModal').classList.remove('show');load()},900)}
      else{m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
    }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
  };
}

// ===== 健康检查 =====
document.getElementById('btnHealth').onclick=function(){showHealth()};
document.getElementById('hlClose').onclick=function(){document.getElementById('hlModal').classList.remove('show')};
document.getElementById('hlModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showHealth(){
  var box=document.getElementById('hlContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">检查中...</p>';
  document.getElementById('hlModal').classList.add('show');
  api('/api/health').then(function(d){
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:10px">'+(lang==='zh'?'版本 ':'version ')+esc(d.version||'')+' · '+fmt((d.usage||{}).used||0)+' / '+fmt((d.usage||{}).total||0)+'</div>';
    (d.checks||[]).forEach(function(c){
      h+='<div class="token-row"><span style="width:18px">'+(c.ok?'<span style="color:var(--sys-green)">●</span>':'<span style="color:var(--sys-red)">●</span>')+'</span>';
      h+='<div style="flex:1;min-width:0"><div style="font-size:13.5px">'+esc(c.name)+'</div>';
      h+='<div class="dup-path">'+esc(c.ok?(c.info||'ok'):(c.error||'failed'))+'</div></div>';
      h+='<span class="tr-meta">'+c.ms+'ms</span></div>';
    });
    h+='<div style="margin-top:12px;text-align:right"><button id="hlAgain" class="btn small">'+(lang==='zh'?'重新检查':'Re-check')+'</button></div>';
    // KV / R2 防爆面板：读写预算、内部占用与上限一览
    var g=d.guard;
    if(g){
      var kv=g.kv||{},lm=g.limits||{},r2=g.r2||{},inr=r2.internal||{};
      h+='<div style="margin:16px 0 6px;font-size:13px;font-weight:600">'+(lang==='zh'?'KV / R2 防爆状态':'KV / R2 guard')+'</div>';
      h+='<div class="dup-path" style="line-height:1.8">'
        +(lang==='zh'?'KV 写（近 1 分钟）':'KV writes/min')+' '+kv.writesLastMin+' / '+kv.budgetPerMin
        +' · '+(lang==='zh'?'缓存项':'cache')+' '+kv.cacheEntries
        +' · '+(lang==='zh'?'缓冲条目':'buffered')+' '+kv.telemetryBuffered+'</div>';
      h+='<div class="dup-path" style="line-height:1.8">'
        +(lang==='zh'?'R2 采样':'R2 sampled')+' '+fmt(r2.bytes||0)+' / '+(r2.objects||0)+(lang==='zh'?' 对象':' obj')+(r2.capped?(lang==='zh'?'（已截断）':' (capped)'):'')
        +' · '+(lang==='zh'?'用量计数':'tracked')+' '+fmt((g.usage||{}).tracked||0)+'</div>';
      h+='<div class="dup-path" style="line-height:1.8">'
        +(lang==='zh'?'内部分布：分片':'internal: chunks')+' '+fmt(inr.chunks||0)
        +' · '+(lang==='zh'?'缩略图':'thumbs')+' '+fmt(inr.thumbs||0)
        +' · '+(lang==='zh'?'版本':'versions')+' '+fmt(inr.versions||0)
        +' · '+(lang==='zh'?'回收站':'trash')+' '+fmt(inr.trash||0)
        +' · '+(lang==='zh'?'备份':'backup')+' '+fmt(inr.backup||0)+'</div>';
      h+='<div class="dup-path" style="line-height:1.8">'
        +(lang==='zh'?'单目录上限':'max items/dir')+' '+lm.maxDirItems
        +' · KV '+(lang==='zh'?'单值上限':'value max')+' '+lm.kvValueMaxMB+'MB'
        +' · '+(lang==='zh'?'版本上限':'version max')+' '+lm.versionMaxMB+'MB'
        +' · '+(lang==='zh'?'回收站保留':'trash days')+' '+lm.trashDays
        +' · '+(lang==='zh'?'分片回收':'chunk GC')+' '+lm.chunkGcHours+'h</div>';
    }
    box.innerHTML=h;
    document.getElementById('hlAgain').onclick=showHealth;
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'检查失败':'Failed')+'</p>'});
}

// ===== 孤儿扫描 =====
document.getElementById('btnOrphans').onclick=function(){showOrphans()};
document.getElementById('orClose').onclick=function(){document.getElementById('orModal').classList.remove('show')};
document.getElementById('orModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showOrphans(){
  var box=document.getElementById('orContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'扫描中...':'Scanning...')+'</p>';
  document.getElementById('orModal').classList.add('show');
  api('/api/scan-orphans',{method:'POST'}).then(function(d){
    var h='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:10px">'+(lang==='zh'?'已扫 ':'scanned ')+(d.scannedObjects||0)+(lang==='zh'?' 个对象 / ':' objects / ')+(d.scannedFiles||0)+(lang==='zh'?' 条文件记录':' entries')+(d.capped?(lang==='zh'?'（已达上限，分次清理）':' (capped)'):'')+'</div>';
    function sec(title,list,total,extra){
      var s='<div style="margin:10px 0 4px;font-size:13px;font-weight:600">'+title+' <span style="color:var(--sys-text-3);font-weight:400">'+(total||0)+'</span>'+(extra||'')+'</div>';
      if(!list||!list.length)return s+'<div class="dup-path">'+(lang==='zh'?'无':'none')+'</div>';
      s+='<div style="max-height:150px;overflow:auto">';
      list.slice(0,80).forEach(function(x){ s+='<div class="dup-path" style="font-family:ui-monospace,Menlo,monospace">'+esc(x.key)+'</div>'; });
      s+='</div>';
      return s;
    }
    h+=sec((lang==='zh'?'① 孤儿对象（R2 有、目录无记录）':'① Orphan objects'),d.orphans,d.orphansTotal,' <span style="color:var(--sys-text-3);font-weight:400">'+fmt(d.orphansBytes||0)+'</span>');
    h+=sec((lang==='zh'?'② 内部残留（缩略图/版本/分片）':'② Internal leftovers'),d.internal,d.internalTotal);
    h+=sec((lang==='zh'?'③ 失效记录（目录有、R2 无对象）':'③ Dangling entries'),d.missing,d.missingTotal);
    h+='<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap"><button id="orP1" class="btn danger small">'+(lang==='zh'?'清理①②':'Purge ①②')+'</button><button id="orP2" class="btn gray small">'+(lang==='zh'?'移除③失效记录':'Remove ③')+'</button><button id="orP3" class="btn danger small">'+(lang==='zh'?'全部处理':'Purge all')+'</button></div>';
    h+='<div id="orMsg" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
    box.innerHTML=h;
    function run(mode){
      var m=document.getElementById('orMsg');m.style.color='var(--sys-text-3)';m.textContent=(lang==='zh'?'处理中...':'working...');
      api('/api/purge-orphans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode})}).then(function(r){
        if(r&&r.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'已删除 ':'deleted ')+r.deleted+(lang==='zh'?' 个对象，移除 ':' objects, removed ')+r.removed+(lang==='zh'?' 条记录':' entries');load();}
        else{m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
      }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
    }
    document.getElementById('orP1').onclick=function(){if(confirm('OK?'))run('objects')};
    document.getElementById('orP2').onclick=function(){if(confirm('OK?'))run('missing')};
    document.getElementById('orP3').onclick=function(){if(confirm('OK?'))run('all')};
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'扫描失败':'Failed')+'</p>'});
}

// ===== Webhook 通知 =====
document.getElementById('btnWebhook').onclick=function(){showWebhook()};
document.getElementById('whClose').onclick=function(){document.getElementById('whModal').classList.remove('show')};
document.getElementById('whModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showWebhook(){
  var box=document.getElementById('whContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('whModal').classList.add('show');
  api('/api/webhook').then(function(w){
    var EV=[['up','上传','Upload'],['del','删除','Delete'],['shr','分享','Share'],['mov','移动','Move'],['res','恢复','Restore']];
    var h='<label style="display:flex;align-items:center;gap:8px;font-size:14px;margin-bottom:12px"><input type="checkbox" id="whOn" '+(w.enabled?'checked':'')+' style="width:16px;height:16px;accent-color:var(--sys-blue)">'+(lang==='zh'?'开启通知':'Enable')+'</label>';
    h+='<input id="whUrl" placeholder="https://... (接受 JSON POST)" value="'+esc(w.url||'')+'" style="width:100%;padding:9px 12px;margin-bottom:8px">';
    h+='<input id="whSecret" type="password" placeholder="'+(w.hasSecret?(lang==='zh'?'已配置签名密钥（留空表示不修改）':'Secret configured (leave blank to keep)'):(lang==='zh'?'签名密钥（可选，会带 X-Signature 头）':'Secret (optional)'))+'" value="" style="width:100%;padding:9px 12px;margin-bottom:8px">';
    if(w.hasSecret)h+='<label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--sys-text-3);margin-bottom:8px"><input type="checkbox" id="whClearSecret" style="width:14px;height:14px;accent-color:var(--sys-red)">'+(lang==='zh'?'清除已保存的密钥':'Clear saved secret')+'</label>';
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:6px">'+(lang==='zh'?'触发事件：':'Events: ')+'</div><div style="display:flex;gap:10px;flex-wrap:wrap">';
    EV.forEach(function(e){
      var on=(w.events||[]).indexOf(e[0])>=0;
      h+='<label style="display:flex;align-items:center;gap:5px;font-size:13px"><input type="checkbox" data-ev="'+e[0]+'" '+(on?'checked':'')+' style="width:15px;height:15px;accent-color:var(--sys-blue)">'+(lang==='zh'?e[1]:e[2])+'</label>';
    });
    h+='</div><div id="whMsg" style="margin-top:10px;font-size:13px;min-height:18px"></div>';
    h+='<div style="margin-top:12px;text-align:right;display:flex;gap:8px;justify-content:flex-end"><button id="whTest" class="btn gray small">'+(lang==='zh'?'发送测试':'Test')+'</button><button id="whSave" class="btn small">'+(lang==='zh'?'保存':'Save')+'</button></div>';
    box.innerHTML=h;
    function collect(){
      var evs=[];box.querySelectorAll('[data-ev]').forEach(function(c){if(c.checked)evs.push(c.getAttribute('data-ev'))});
      var clr=document.getElementById('whClearSecret');
      var sec=document.getElementById('whSecret').value;
      return {enabled:document.getElementById('whOn').checked,url:document.getElementById('whUrl').value.trim(),secret:(clr&&clr.checked)?null:sec,events:evs};
    }
    var m=document.getElementById('whMsg');
    document.getElementById('whSave').onclick=function(){
      api('/api/webhook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())}).then(function(r){
        if(r&&r.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'已保存':'Saved')}else{m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
      }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
    };
    document.getElementById('whTest').onclick=function(){
      m.style.color='var(--sys-text-3)';m.textContent=(lang==='zh'?'发送中...':'sending...');
      api('/api/webhook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())}).then(function(){
        return api('/api/webhook-test',{method:'POST'});
      }).then(function(r){
        if(r&&r.ok){m.style.color='var(--sys-green)';m.textContent=(lang==='zh'?'已发送，对方返回 ':'sent, HTTP ')+r.status}else{m.style.color='var(--sys-red)';m.textContent=(r&&r.error)||'failed'}
      }).catch(function(){m.style.color='var(--sys-red)';m.textContent='failed'});
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'加载失败':'Failed')+'</p>'});
}

// ===== 上传接口 / 脚本 =====
document.getElementById('btnApi').onclick=function(){showApi()};
document.getElementById('apiClose').onclick=function(){document.getElementById('apiModal').classList.remove('show')};
document.getElementById('apiModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showApi(){
  var box=document.getElementById('apiContent');
  var host=location.origin;
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('apiModal').classList.add('show');
  api('/api/tokens').then(function(d){
    var toks=d.tokens||[];
    var h='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.8;margin-bottom:10px">'+(lang==='zh'?'用下方令牌即可在脚本/手机上调用接口（令牌放在 <code>Authorization: Bearer</code> 里，也可用 <code>?token=</code>）。只读令牌只能读。':'Use a token below in scripts/phones via Authorization: Bearer.')+'</div>';
    h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px"><button id="apiNew" class="btn small">'+(lang==='zh'?'生成读写令牌':'New RW token')+'</button><span id="apiMsg" style="font-size:12px;color:var(--sys-text-3)"></span></div>';
    // 列表里的 id 是掩码（前 6 位 + ****），不能直接当令牌用，示例统一用占位符
    var cur='<TOKEN>';
    h+='<div style="font-size:12px;color:var(--sys-orange);margin-bottom:8px">'+(lang==='zh'?'注意：下方示例中的 &lt;TOKEN&gt; 请替换为创建时保存的真实令牌（列表里只显示前 6 位）。':'Replace &lt;TOKEN&gt; with the real token shown once at creation time.')+'</div>';
    function code(t){return '<pre class="hl-pre" style="max-height:none;margin:0 0 10px">'+esc(t)+'</pre>'}
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:4px">'+(lang==='zh'?'上传文件':'Upload')+'</div>';
    h+=code('curl -H "Authorization: Bearer '+cur+'" -F "file=@本地文件.zip" "'+host+'/api/upload?path=/"');
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin:6px 0 4px">'+(lang==='zh'?'列目录 / 下载':'List / Download')+'</div>';
    h+=code('curl -H "Authorization: Bearer '+cur+'" "'+host+'/api/list?path=/"\\ncurl -H "Authorization: Bearer '+cur+'" "'+host+'/api/download?path=/a.txt" -o a.txt');
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin:6px 0 4px">'+(lang==='zh'?'iOS 快捷指令':'iOS Shortcuts')+'</div>';
    h+='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.8">'+(lang==='zh'?'新建快捷指令 → 添加「获取文件」→ 添加「获取 URL 内容」，方法 POST、请求体选表单、字段名 <code>file</code> 选文件，URL 填 <code>'+host+'/api/upload?path=/</code>，请求头加 <code>Authorization: Bearer '+cur+'</code>。':'New Shortcut → Get File → Get Contents of URL (POST, form field file, header Authorization: Bearer '+cur+').')+'</div>';
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-top:12px;line-height:1.8">'+(lang==='zh'?'也可以用 WebDAV 挂载：<code>'+host+'/dav/</code>，用户名随便填、密码填令牌。':'WebDAV: '+host+'/dav/ with any username and the token as password.')+'</div>';
    box.innerHTML=h;
    document.getElementById('apiNew').onclick=function(){
      api('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'script',perm:'rw'})}).then(function(r){
        if(r&&r.token){prompt((lang==='zh'?'新令牌（请保存）：':'New token:'),r.token);showApi()}
        else document.getElementById('apiMsg').textContent='failed';
      });
    };
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'加载失败':'Failed')+'</p>'});
}

// ===== 公开相册 =====
document.getElementById('btnAlbums').onclick=function(){showAlbums()};
document.getElementById('albClose').onclick=function(){document.getElementById('albModal').classList.remove('show')};
document.getElementById('albModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showAlbums(){
  var box=document.getElementById('albContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('albModal').classList.add('show');
  api('/api/albums').then(function(d){
    var arr=d.albums||[];
    var h='<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px"><button id="albNew" class="btn small">'+(lang==='zh'?'把当前目录设为相册':'Publish current folder')+'</button><span id="albMsg" style="font-size:12px;color:var(--sys-text-3)"></span></div>';
    h+='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.8;margin-bottom:10px">'+(lang==='zh'?'相册链接<b>无需密码</b>即可浏览（图片/视频，递归收集，最多 300 项），适合发照片给朋友。目录被加密码后相册会自动失效。':'Public, no password. Recursive, max 300 items.')+'</div>';
    if(!arr.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:14px">'+(lang==='zh'?'还没有相册':'No albums')+'</p>'}
    arr.forEach(function(a){
      h+='<div class="token-row"><div style="flex:1;min-width:0"><div style="font-size:13.5px">'+esc(a.name)+'</div><div class="dup-path">'+esc(a.path)+' · '+esc(fmtWhen(Date.parse(a.created)))+'</div></div>';
      h+='<button class="btn gray tiny" data-albc="'+esc(a.id)+'">'+(lang==='zh'?'复制链接':'Copy')+'</button>';
      h+='<button class="btn gray tiny" data-albo="'+esc(a.id)+'">'+(lang==='zh'?'打开':'Open')+'</button>';
      h+='<button class="btn tiny danger" data-albd="'+esc(a.id)+'">✕</button></div>';
    });
    box.innerHTML=h;
    document.getElementById('albNew').onclick=function(){
      var n=prompt((lang==='zh'?'相册名称：':'Album name:'),cur.split('/').filter(Boolean).pop()||'相册');
      if(n===null)return;
      api('/api/albums',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur,name:n})}).then(function(r){
        if(r&&r.url){var u=location.origin+r.url;try{navigator.clipboard.writeText(u)}catch(e){};prompt((lang==='zh'?'相册链接（已复制）：':'Album link:'),u);showAlbums()}
        else if(r&&r.locked){alert(t('locked'))}
        else alert((r&&r.error)||'failed');
      });
    };
    box.querySelectorAll('[data-albc]').forEach(function(b){b.onclick=function(){var u=location.origin+'/a/'+b.getAttribute('data-albc');try{navigator.clipboard.writeText(u)}catch(e){};prompt((lang==='zh'?'相册链接：':'Link:'),u)}});
    box.querySelectorAll('[data-albo]').forEach(function(b){b.onclick=function(){window.open('/a/'+b.getAttribute('data-albo'),'_blank')}});
    box.querySelectorAll('[data-albd]').forEach(function(b){b.onclick=function(){if(!confirm('OK?'))return;api('/api/albums',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:b.getAttribute('data-albd')})}).then(showAlbums)}});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'加载失败':'Failed')+'</p>'});
}

if(tk){api('/api/list?path=/').then(function(){show('main');goHome();loadUsage()}).catch(function(){show('login')})}else show('login');
// 启动时恢复：未完成上传记录、上传队列栏、剪贴板栏
try{pendPrune()}catch(e){}
try{renderQueueBar()}catch(e){}
try{renderClipBar()}catch(e){}
var pendTip=pendList().length;
if(pendTip){setTimeout(function(){if(confirm(t('resumeTitle')+'\\n\\n'+(lang==='zh'?'查看并管理？':'Manage now?')))showPending()},600)}
</script></body></html>`;
}


// ===== WebDAV Protocol =====
async function handleWebDAV(req, env) {
  try {
    const url = new URL(req.url);
    const method = req.method.toUpperCase();
    let davPath;
    try { davPath = decodeURIComponent(url.pathname.replace(/^\/dav/, '') || '/'); }
    catch (e) { davPath = url.pathname.replace(/^\/dav/, '') || '/'; }
    const np = davPathNorm(davPath);

    const auth = req.headers.get('Authorization') || '';
    // 同时支持 Bearer（脚本/API）与 Basic（操作系统 WebDAV 客户端：用户名任意，密码填令牌）
    let tok = '';
    if (auth.startsWith('Bearer ')) tok = auth.substring(7).trim();
    else if (auth.startsWith('Basic ')) {
      try {
        const dec = atob(auth.substring(6).trim());
        const i = dec.indexOf(':');
        const u = i < 0 ? dec : dec.substring(0, i);
        const p = i < 0 ? '' : dec.substring(i + 1);
        tok = p || u;
      } catch (e) { tok = ''; }
    }
    const challenge = { 'WWW-Authenticate': 'Basic realm="WebDAV", Bearer' };
    if (!tok) return new Response('Unauthorized', { status: 401, headers: challenge });
    const tokens = await getAccessTokens(env);
    const found = tokens.find(t => safeEqual(t.token, tok));
    if (!found) return new Response('Unauthorized', { status: 401, headers: challenge });
    if (found.exp && Date.now() > new Date(found.exp).getTime()) return new Response('Unauthorized', { status: 401, headers: challenge });

    const WRITE_METHODS = ['PUT', 'DELETE', 'MKCOL', 'MOVE', 'COPY', 'PROPPATCH', 'LOCK', 'UNLOCK'];
    if (WRITE_METHODS.indexOf(method) >= 0 && found.perm !== 'rw') return new Response('Forbidden (read-only token)', { status: 403 });

    // 文件夹密码：WebDAV 无会话，锁定目录一律拒绝
    if (method !== 'OPTIONS' && await isPathLocked(env, np, '')) return new Response('Locked', { status: 423 });

    const davHeaders = { 'DAV': '1,2', 'Content-Type': 'application/xml; charset=utf-8' };

    if (method === 'OPTIONS') {
      return new Response('', { status: 200, headers: { 'DAV': '1,2', 'Allow': 'OPTIONS,HEAD,GET,PUT,DELETE,MKCOL,PROPFIND,MOVE,COPY' } });
    }

    if (method === 'PROPFIND') {
      const isDir = np.endsWith('/');
      const depth = String(req.headers.get('Depth') || '1').toLowerCase();
      if (isDir) {
        const items = depth === '0' ? [] : await getDir(env, np);
        let xml = '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        xml += '<D:response><D:href>' + xmlEsc(np) + '</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>' + xmlEsc(np === '/' ? 'Root' : np.split('/').filter(Boolean).pop()) + '</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        for (const item of items) {
          const href = np + item.name + (item.type === 'dir' ? '/' : '');
          xml += '<D:response><D:href>' + xmlEsc(href) + '</D:href><D:propstat><D:prop>';
          if (item.type === 'dir') xml += '<D:resourcetype><D:collection/></D:resourcetype>';
          else { xml += '<D:resourcetype/><D:getcontentlength>' + (item.size || 0) + '</D:getcontentlength><D:getcontenttype>' + xmlEsc(item.mime || 'application/octet-stream') + '</D:getcontenttype>'; }
          xml += '<D:displayname>' + xmlEsc(item.name) + '</D:displayname>';
          xml += '<D:getlastmodified>' + xmlEsc(item.time || new Date().toISOString()) + '</D:getlastmodified>';
          xml += '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        }
        xml += '</D:multistatus>';
        return new Response(xml, { status: 207, headers: davHeaders });
      } else {
        const key = np.replace(/^\//, '');
        try {
          const obj = await env.DRIVE.head(key);
          if (!obj) return new Response('Not Found', { status: 404 });
          let xml = '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
          xml += '<D:response><D:href>' + xmlEsc(np) + '</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>' + obj.size + '</D:getcontentlength><D:getlastmodified>' + xmlEsc(obj.uploaded.toISOString()) + '</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>';
          return new Response(xml, { status: 207, headers: davHeaders });
        } catch (e) { return new Response('Not Found', { status: 404 }); }
      }
    }

    if (method === 'HEAD') {
      const key = np.replace(/^\//, '');
      try {
        const h = await env.DRIVE.head(key);
        if (!h) return new Response('Not Found', { status: 404, headers: { 'Accept-Ranges': 'bytes' } });
        return new Response(null, { status: 200, headers: { 'Content-Type': (h.httpMetadata && h.httpMetadata.contentType) || 'application/octet-stream', 'Content-Length': String(h.size), 'Accept-Ranges': 'bytes' } });
      } catch (e) { return new Response('Error', { status: 500 }); }
    }

    if (method === 'GET') {
      const key = np.replace(/^\//, '');
      try {
        if (!await env.DRIVE.head(key)) return new Response('Not Found', { status: 404 });
        // M3: GET 增加文件名净化与附件下载语义
        const davName = key.split('/').filter(Boolean).pop() || 'download';
        return await serveObject(env, req, key, { sanitize: true, disposition: 'attachment; filename="' + encodeURIComponent(davName) + '"' });
      } catch (e) { return new Response('Error', { status: 500 }); }
    }

    if (method === 'PUT') {
      const dirPath = parentOf(np);
      const fileName = np.split('/').filter(Boolean).pop();
      if (!fileName) return new Response('Bad Request', { status: 400 });
      if (await isPathLocked(env, dirPath, '')) return new Response('Locked', { status: 423 });
      const safeName = sanitizeName(fileName);
      // H1: 上限与配额前置检查（流式写入，避免整块入内存）
      const clen = Number(req.headers.get('Content-Length') || 0);
      if (clen > 100 * 1024 * 1024) return new Response('File too large', { status: 413 });
      const existing = await findDirItem(env, dirPath, safeName);
      const oldItem = existing.item;
      const delta = oldItem ? (clen ? clen - (oldItem.size || 0) : 0) : clen;
      if (delta > 0) {
        const u = await getUsage(env);
        if ((u.used || 0) + delta > quotaTotal(env)) return new Response('Quota exceeded', { status: 413 });
      }
      const key = dirPath.replace(/^\//, '') + safeName;
      const contentType = req.headers.get('Content-Type') || 'application/octet-stream';
      if (clen > 0) {
        await putAndMirror(env, key, req.body, { httpMetadata: { contentType } });
        await addUsage(env, delta, oldItem ? 0 : 1);
        if (oldItem) await pushVersion(env, key, oldItem);
        if (oldItem && oldItem.hasThumb) await deleteThumb(env, key);
        const entry = { name: safeName, type: 'file', size: clen, mime: contentType, time: new Date().toISOString() };
        await upsertDirItem(env, dirPath, entry);
        await addLog(env, 'up', np, clen + ' bytes (WebDAV)');
        return new Response('', { status: 201 });
      }
      // Content-Length 缺失（chunked）：限 100MB 后落盘，仍做配额检查
      const buf = await req.arrayBuffer();
      if (buf.byteLength > 100 * 1024 * 1024) return new Response('File too large', { status: 413 });
      // 必须按实际写入的字节数算配额（此前的 delta 基于 Content-Length=0，覆盖上传会被少算）
      const realDelta = oldItem ? (buf.byteLength - (oldItem.size || 0)) : buf.byteLength;
      if (realDelta > 0) {
        const u2 = await getUsage(env);
        if ((u2.used || 0) + realDelta > quotaTotal(env)) return new Response('Quota exceeded', { status: 413 });
      }
      if (oldItem) await pushVersion(env, key, oldItem);
      await putAndMirror(env, key, buf, { httpMetadata: { contentType } });
      if (oldItem && oldItem.hasThumb) await deleteThumb(env, key);
      const entry2 = { name: safeName, type: 'file', size: buf.byteLength, mime: contentType, time: new Date().toISOString() };
      await upsertDirItem(env, dirPath, entry2);
      await addUsage(env, realDelta, oldItem ? 0 : 1);
      await addLog(env, 'up', np, buf.byteLength + ' bytes (WebDAV)');
      return new Response('', { status: 201 });
    }

    if (method === 'MOVE' || method === 'COPY') {
      const dest = req.headers.get('Destination');
      if (!dest) return new Response('Bad Request (no Destination)', { status: 400 });
      if (np.endsWith('/')) return new Response('Not Implemented (directory ' + method + ')', { status: 501 });
      let destNp;
      try {
        const du = new URL(dest, url.origin);
        destNp = davPathNorm(decodeURIComponent(du.pathname.replace(/^\/dav/, '') || '/'));
      } catch (e) { return new Response('Bad Request (bad Destination)', { status: 400 }); }
      const destDir = parentOf(destNp);
      const destName = sanitizeName(destNp.split('/').filter(Boolean).pop() || '');
      if (!destName) return new Response('Bad Request', { status: 400 });
      if (await isPathLocked(env, destDir, '')) return new Response('Locked', { status: 423 });
      // 目标已存在：按 Overwrite 头处理
      const existingDest = await findDirItem(env, destDir, destName);
      const overwrite = (req.headers.get('Overwrite') || 'T').toUpperCase() === 'T';
      if (existingDest.item && !overwrite) return new Response('Precondition Failed', { status: 412 });
      const srcDirNp = parentOf(np);
      const srcNameNp = sanitizeName(np.split('/').filter(Boolean).pop() || '');
      const srcKey = srcDirNp.replace(/^\//, '') + srcNameNp;
      let obj = null;
      try { obj = await env.DRIVE.get(srcKey); } catch (e) {}
      if (!obj) return new Response('Not Found', { status: 404 });
      if ((obj.size || 0) > 100 * 1024 * 1024) return new Response('Too large to ' + method, { status: 413 });
      const buf = new Uint8Array(await obj.arrayBuffer());
      const meta = obj.httpMetadata || {};
      const newKey = destDir.replace(/^\//, '') + destName;
      if (existingDest.item) {
        try { await pushVersion(env, newKey, existingDest.item); } catch (e) {}
      }
      await putAndMirror(env, newKey, buf, { httpMetadata: meta });
      await upsertDirItem(env, destDir, { name: destName, type: 'file', size: buf.byteLength, mime: meta.contentType || '', time: new Date().toISOString() });
      if (method === 'MOVE') {
        await removeDirItem(env, srcDirNp, srcNameNp);
        await deleteAndMirror(env, srcKey);
        await deleteThumb(env, srcKey);
        await deleteVersions(env, srcKey);
      } else {
        // COPY 会新增一份数据，必须计入用量（此前完全不记账，配额被绕过）
        const deltaCopy = buf.byteLength - (existingDest.item ? (existingDest.item.size || 0) : 0);
        await addUsage(env, (existingDest.item ? deltaCopy : buf.byteLength), existingDest.item ? 0 : 1);
      }
      return new Response(null, { status: existingDest.item ? 204 : 201 });
    }

    if (method === 'DELETE') {
      const dirPath = parentOf(np);
      const fn = np.split('/').filter(Boolean).pop();
      if (!fn) return new Response('Bad Request', { status: 400 });
      const existing = await findDirItem(env, dirPath, fn);
      if (!existing.item) return new Response('Not Found', { status: 404 });
      const delRes = await handleDelete(env, np.replace(/^\//, ''));
      let delBody = {};
      try { delBody = await delRes.clone().json(); } catch (e) {}
      if (!delBody || !delBody.ok) return new Response((delBody && delBody.error) || 'Delete failed', { status: delRes.status || 500 });
      return new Response(null, { status: 204 });
    }

    if (method === 'MKCOL') {
      const dirPath = parentOf(np);
      const folderName = np.split('/').filter(Boolean).pop();
      if (!folderName) return new Response('Bad Request', { status: 400 });
      if (await isPathLocked(env, dirPath, '')) return new Response('Locked', { status: 423 });
      const safeName = sanitizeName(folderName);
      const existing = await findDirItem(env, dirPath, safeName);
      if (existing.item) return new Response('Method Not Allowed', { status: 405 });
      await upsertDirItem(env, dirPath, { name: safeName, type: 'dir', time: new Date().toISOString() });
      return new Response('', { status: 201 });
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (e) {
    console.error('WebDAV error:', e);
    return new Response('Internal Server Error', { status: 500 });
  }
}

// ===== Router =====
export default {
  async fetch(req, env, ctx) {
    // 遥测（日志/下载明细/最近访问）走内存缓冲，请求结束时按时间窗口合并写入 KV
    const res = await this.handle(req, env, ctx);
    try {
      const flush = flushTelemetry(env);
      if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(flush);
      else await flush;
    } catch (e) {}
    return res;
  },

  async handle(req, env, ctx) {
    try {
      const url = new URL(req.url); const p = url.pathname;
      // 站点配置：KV 覆盖（30 秒缓存），供后续同步取上限的函数使用
      try { await loadConfig(env); } catch (e) {}

      // IP / 地区 / User-Agent 风控（可选环境变量，未配置则放行）
      const ra = requestAllowed(env, req);
      if (!ra.ok) return json({ error: 'Forbidden', reason: ra.reason }, 403);

      if (p === '/api/login' && req.method === 'POST') return await handleLogin(req, env);

      // 公开路由（无需登录）
      if (p === '/api/version') return json({ version: APP_VERSION, totp: await totpEnabled(env) });
      if (p === '/manifest.webmanifest') return new Response(JSON.stringify(manifestJSON(env)), { headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
      if (p === '/icon.svg') return new Response(iconSvg(), { headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } });
      if (p === '/sw.js') return new Response(swJS(), { headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache' } });
      if (p === '/upload' || p === '/upload/') {
        if (!publicUploadDir(env)) return html(errorPage('公开上传未开启'));
        return html(publicUploadPage(env));
      }
      if (p === '/api/public-upload' && req.method === 'POST') return await handlePublicUpload(req, env);
      // Web Share Target 兜底：Service Worker 未激活时，POST 会直接到这里
      if (p === '/share-target' && req.method === 'POST') {
        return new Response(null, { status: 303, headers: { Location: '/?shared=0' } });
      }

      if (p.startsWith('/a/')) {
        const id = p.substring(3);
        if (!id) return html(errorPage('相册不存在'));
        return html(albumPage(id.substring(0, 32)));
      }
      if (p.startsWith('/album/')) {
        const rest = p.substring(7);
        const slash = rest.indexOf('/');
        const id = slash < 0 ? rest : rest.substring(0, slash);
        const sub = slash < 0 ? '' : rest.substring(slash + 1);
        if (sub === 'list') return await handleAlbumList(env, req, id);
        if (sub === 'raw') return await handleAlbumRaw(env, req, id);
        return json({ error: 'Not found' }, 404);
      }

      if (p.startsWith('/s/')) {
        const rest = p.substring(3);
        const slash = rest.indexOf('/');
        const name = slash < 0 ? rest : rest.substring(0, slash);
        const sub = slash < 0 ? '' : rest.substring(slash + 1);
        if (!name) return html(errorPage('分享链接无效'));
        // 支持自定义短链：/s/<别名> 解析成真实 token
        const resolved = await resolveShareToken(env, name);
        const token = resolved ? resolved.token : name;
        if (sub === 'data') return await handleShareData(env, token, req);
        if (sub === 'list') return await handleShareList(env, token, req);
        if (sub === 'dl') return await handleShareDownload(env, token, req);
        if (sub === 'pv') return await handleSharePreview(env, token, req);
        if (sub === 'zip') {
          const g = await shareGuard(env, token, req, false, true);
          if (g.resp) return g.resp;
          return await handleShareZip(env, req, token, g);
        }
        if (sub === 'comment' && req.method === 'POST') return await handleShareComment(env, token, req);
        if (sub === 'comments' && req.method === 'GET') {
          const g = await shareGuard(env, token, req, false, true);
          if (g.resp) return g.resp;
          const d = g.data;
          let target;
          if (d.type === 'dir') {
            const base = normPath(d.path);
            const full = normPath(base + (url.searchParams.get('p') || ''));
            if (!full.startsWith(base)) return json({ error: 'Forbidden' }, 403);
            target = full.replace(/\/+$/, '') || '/';
          } else target = '/' + String(d.path || '').replace(/^\/+/, '');
          return json({ comments: await getComments(env, target), allowComment: d.allowComment !== false });
        }
        const sd = resolved ? resolved.data : null;
        if (!sd) return html(errorPage('分享链接无效或已过期'));
        if (sd.type === 'dir') return html(shareDirPage(token, sd));
        return html(sharePage(token, sd));
      }

      if (p.startsWith('/u/')) {
        const token = p.substring(3);
        const link = await env.STORE.get('ulink:' + token, 'json');
        if (!link || Date.now() > link.exp) return html(errorPage('上传链接无效或已过期'));
        return html(uploadPage(token));
      }
      if (p.startsWith('/api/upload-link/') && req.method === 'POST') return await handleUploadViaLink(req, env, p.substring('/api/upload-link/'.length));

      if (p.startsWith('/dav')) return await handleWebDAV(req, env);

      if (p.startsWith('/api/')) {
        let auth = await authInfo(env, req);
        // 防外链：下载/预览/缩略图允许用签名直链访问（?exp=&sig=&ip=），无需登录态
        if (!auth.ok && (p === '/api/download' || p === '/api/preview' || p === '/api/thumb')) {
          const sk = String(url.searchParams.get('path') || '').replace(/^\/+/, '');
          if (sk) {
            const v = await verifySignedUrl(env, req, sk);
            if (v.ok) auth = { ok: true, perm: 'ro', kind: 'sig' };
          }
        }
        if (!auth.ok) return json({ error: 'Unauthorized' }, 401);
        // 按会话/令牌限流（防单令牌刷爆 KV 读写配额）：写方法走写桶，读方法走读桶
        const rlRes = await rateLimitCheck(env, extractToken(req), req.method !== 'GET' && req.method !== 'HEAD');
        if (rlRes && rlRes.limited) {
          return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: rlRes.retryAfter }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', 'Retry-After': String(rlRes.retryAfter || 1) }
          });
        }
        if (auth.perm === 'ro' && req.method !== 'GET' && req.method !== 'HEAD') return json({ error: 'Read-only token' }, 403);
        const requireRw = (auth.perm === 'rw');
        const denyRo = () => json({ error: 'Read-only token' }, 403);
        try {
          if (p === '/api/list') return await handleList(env, url.searchParams.get('path') || '/', url.searchParams.get('size') === '1', extractToken(req));
          if (p === '/api/unlock' && req.method === 'POST') { const b = await req.json(); return await handleUnlockDir(env, extractToken(req), b.path, b.password); }
          if (p === '/api/upload' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleUpload(req, env, url.searchParams.get('path') || '/'); }
          if (p === '/api/download') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleDownload(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/preview') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handlePreview(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/thumb') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleThumb(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/save' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const content = await req.text(); return await handleSaveText(env, url.searchParams.get('path') || '', content); }
          if (p === '/api/delete' && req.method === 'DELETE') { const fp = url.searchParams.get('path') || ''; const np = '/' + String(fp).replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np)); if (g) return g; return await handleDelete(env, fp); }
          if (p === '/api/batch-delete' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const g = await guard(env, req, ...paths, ...paths.map(x => parentOf(x))); if (g) return g; return await handleBatchDelete(env, b.paths); }
          if (p === '/api/batch-rename' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const g = await guard(env, req, ...paths, ...paths.map(x => parentOf(x))); if (g) return g; return await handleBatchRename(env, b.paths, b.pattern); }
          if (p === '/api/batch-share' && req.method === 'POST') { const b = await req.json(); return await handleBatchShare(env, b.paths, b.days, b.max, b.password, extractToken(req)); }
          if (p === '/api/copy' && req.method === 'POST') {
            const b = await req.json();
            const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : [];
            const parents = paths.map(x => parentOf(x));
            const g = await guard(env, req, b.target, ...paths, ...parents);
            if (g) return g;
            return await handleCopy(env, b.paths, b.target, extractToken(req));
          }
          if (p === '/api/batch-move' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const parents = paths.map(x => parentOf(x)); const g = await guard(env, req, b.target, ...paths, ...parents); if (g) return g; return await handleBatchMove(env, b.paths, b.target); }
          if (p === '/api/admin-pass' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleAdminPassGet(env); }
          if (p === '/api/admin-pass' && req.method === 'POST') { const b = await req.json(); return await handleAdminPassSet(env, b.current, b.next); }
          // 二次验证（TOTP）
          if (p === '/api/totp' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleTotpGet(env); }
          if (p === '/api/totp/setup' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json().catch(() => ({})); return await handleTotpSetup(env, (b && b.label) || (env.DRIVE_TITLE || 'PersonalDrive')); }
          if (p === '/api/totp/enable' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleTotpEnable(env, b.code); }
          if (p === '/api/totp/disable' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleTotpDisable(env, b.password, b.code); }
          if (p === '/api/totp/backup' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleTotpBackup(env, b.password, b.code); }
          // 防外链：签发限时直链（可绑定请求 IP）
          if (p === '/api/sign' && req.method === 'POST') {
            const b = await req.json();
            const g = await guard(env, req, b.path);
            if (g) return g;
            return await handleSign(env, req, b.path, b.ttl, !!b.bindIp);
          }
          if (p === '/api/sessions' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListSessions(env, extractToken(req)); }
          if (p === '/api/session-revoke' && req.method === 'POST') { const b = await req.json(); return await handleRevokeSession(env, b.id, !!b.all); }
          if (p === '/api/duplicates') return await handleDuplicates(env);
          if (p === '/api/note' && req.method === 'GET') return await handleGetNote(env, url.searchParams.get('path') || '');
          if (p === '/api/note' && req.method === 'POST') { const b = await req.json(); return await handleSetNote(env, b.path, b.note); }
          if (p === '/api/tag' && req.method === 'POST') { const b = await req.json(); return await handleTagFile(env, b.path, b.tags); }
          if (p === '/api/tags' && req.method === 'GET') {
            const f = url.searchParams.get('filter');
            if (f === '__get__') return json({ tags: await getFileTags(env, '/' + String(url.searchParams.get('path') || '').replace(/^\/+/, '')) });
            if (f) return await handleTagFilter(env, f, url.searchParams.get('mode') || 'any', csvList(url.searchParams.get('more')));
            return await handleGetTags(env);
          }
          if (p === '/api/chunk-init' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path || '/'); if (g) return g; return await handleChunkInit(env, b.fileName, b.totalSize, b.hash, b.path || '/', b.mime); }
          if (p.startsWith('/api/chunk-upload/') && req.method === 'POST') { const parts = p.split('/'); return await handleChunkUpload(req, env, parts[3], parts[4]); }
          if (p === '/api/chunk-complete' && req.method === 'POST') { const b = await req.json(); return await handleChunkComplete(req, env, b.uploadId); }
          if (p === '/api/chunk-status') return await handleChunkStatus(env, url.searchParams.get('id') || '');
          if (p === '/api/instant-check' && req.method === 'POST') { const b = await req.json(); return await handleInstantCheck(env, b); }
          if (p === '/api/auto-rule' && req.method === 'GET') return await handleGetAutoRule(env);
          if (p === '/api/auto-rule' && req.method === 'POST') { const b = await req.json(); return await handleSetAutoRule(env, b); }
          if (p === '/api/mkdir' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const b = await req.json(); return await handleMkdir(env, url.searchParams.get('path') || '/', b.name); }
          if (p === '/api/rename' && req.method === 'PUT') { const b = await req.json(); const np = '/' + String(b.path || '').replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np)); if (g) return g; return await handleRename(env, b.path, b.newName); }
          if (p === '/api/move' && req.method === 'PUT') { const b = await req.json(); const np = '/' + String(b.path || '').replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np), b.target); if (g) return g; return await handleMove(env, b.path, b.target); }
          if (p === '/api/search') return await handleSearch(env, url.searchParams.get('q') || '', url.searchParams.get('path') || '/', extractToken(req));
          if (p === '/api/tree') return await handleTree(env, extractToken(req));
          if (p === '/api/zip') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleZip(env, url.searchParams.get('path') || '/', extractToken(req)); }
          if (p === '/api/unzip' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, parentOf(b.path)); if (g) return g; return await handleUnzip(env, b.path); }
          if (p === '/api/versions' && req.method === 'GET') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleListVersions(env, url.searchParams.get('path') || ''); }
          if (p === '/api/versions/restore' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return await handleRestoreVersion(env, b.path, b.ts); }
          if (p === '/api/share' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return await handleShare(env, b.path, b.days, b.max, b.password, b.dir, b); }
          if (p === '/api/share/update' && req.method === 'POST') { const b = await req.json(); return await handleShareUpdate(env, b.token, b); }
          if (p === '/api/share-stats' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleShareStats(env, url.searchParams.get('token') || ''); }
          if (p === '/api/comments' && (req.method === 'GET' || req.method === 'POST' || req.method === 'DELETE')) return await handleComments(env, req, url);
          // 运维与配置
          if (p === '/api/config' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleConfigGet(env); }
          if (p === '/api/config' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleConfigSet(env, b); }
          if (p === '/api/config/reset' && req.method === 'POST') { if (!requireRw) return denyRo(); return await handleConfigReset(env); }
          if (p === '/api/dirrules' && (req.method === 'GET' || req.method === 'POST')) { if (!requireRw) return denyRo(); return await handleDirRules(env, req); }
          if (p === '/api/cron' && (req.method === 'GET' || req.method === 'POST')) { if (!requireRw) return denyRo(); return await handleCron(env, req, url); }
          if (p === '/api/import-webdav' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); const g = await guard(env, req, b.path || '/'); if (g) return g; return await handleImportWebdav(env, b); }
          if (p === '/api/zip-multi' && req.method === 'POST') { const b = await req.json(); const parents = Array.isArray(b.paths) ? b.paths.map(x => parentOf('/' + String(x || '').replace(/^\/+/, ''))) : []; const g = await guard(env, req, ...parents); if (g) return g; return await handleZipPaths(env, b.paths); }
          if (p === '/api/fetch-url' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.dir || '/'); if (g) return g; return await handleFetchUrl(req, env, b); }
          if (p === '/api/shares' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListShares(env); }
          if (p === '/api/share' && req.method === 'DELETE') { const b = await req.json(); return await handleDeleteShare(env, b.token); }
          if (p === '/api/upload-link-create' && req.method === 'POST') { const b = await req.json(); return await handleCreateUploadLink(env, b.path, b.days, b.max); }
          if (p === '/api/upload-links' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListUploadLinks(env); }
          if (p === '/api/upload-link' && req.method === 'DELETE') { const b = await req.json(); return await handleDeleteUploadLink(env, b.token); }
          if (p === '/api/folder-pass' && req.method === 'POST') { const b = await req.json(); return await handleSetFolderPass(env, b.path, b.password); }
          if (p === '/api/folder-pass' && req.method === 'GET') return json({ has: !!(await env.STORE.get('dirpass:' + normPath(url.searchParams.get('path') || '/'), 'json')) });
          if (p === '/api/trash') return await handleTrash(env);
          if (p === '/api/restore' && req.method === 'POST') { const r = await handleRestore(env, url.searchParams.get('name') || ''); return json(r, r.status || 200); }
          if (p === '/api/batch-restore' && req.method === 'POST') { const b = await req.json(); return await handleBatchRestore(env, b.ids); }
          if (p === '/api/purge' && req.method === 'DELETE') return await handlePurge(env, url.searchParams.get('name') || '');
          if (p === '/api/batch-purge' && req.method === 'POST') { const b = await req.json(); return await handleBatchPurge(env, b.ids); }
          if (p === '/api/usage') { const u = await getUsage(env); return json({ used: u.used, files: u.files, total: quotaTotal(env) }); }
          if (p === '/api/recalc-usage' && req.method === 'POST') { const u = await recalcUsage(env); return json({ ok: true, used: u.used, files: u.files }); }
          if (p === '/api/log' && req.method === 'GET') {
            if (!requireRw) return denyRo();
            return await handleLogs(env, { action: url.searchParams.get('action') || '', q: url.searchParams.get('q') || '', from: url.searchParams.get('from') || '', to: url.searchParams.get('to') || '', limit: url.searchParams.get('limit') || '' });
          }
          if (p === '/api/log.csv' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleLogsCsv(env); }
          if (p === '/api/dl-stats' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleDlStats(env); }
          if (p === '/api/clear-dl-stats' && req.method === 'POST') return await handleClearDlStats(env);
          if (p === '/api/public-upload-info') return json({ enabled: !!publicUploadDir(env), dir: publicUploadDir(env) || '', max: publicUploadMax(env), turnstile: !!turnstileSecret(env) });
          if (p === '/api/backends' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListBackends(env); }
          if (p === '/api/backends/check' && req.method === 'POST') return await handleCheckBackends(env);
          if (p === '/api/tokens' && req.method === 'GET') { if (!requireRw) return denyRo(); return json({ tokens: (await getAccessTokens(env)).map(t => ({ id: t.token.substring(0, 6) + '****', name: t.name, perm: t.perm, exp: t.exp || null })) }); }
          if (p === '/api/tokens' && req.method === 'POST') { const b = await req.json(); const tokens = await getAccessTokens(env); const nt = { name: b.name || 'Token', token: randToken(), perm: b.perm === 'rw' ? 'rw' : 'ro', exp: b.exp || null }; tokens.push(nt); await saveAccessTokens(env, tokens); return json({ ok: true, token: nt.token }); }
          if (p === '/api/tokens' && req.method === 'DELETE') { const b = await req.json(); const id = String(b.id || b.token || ''); const mask = id.replace(/\*+$/, ''); const tokens = (await getAccessTokens(env)).filter(t => t.token !== id && !(mask.length >= 6 && t.token.startsWith(mask))); await saveAccessTokens(env, tokens); return json({ ok: true }); }
          if (p === '/api/stats') { if (!requireRw) return denyRo(); return await handleStatsFull(env); }
          if (p === '/api/dashboard') { if (!requireRw) return denyRo(); return await handleDashboard(env, extractToken(req)); }
          if (p === '/api/stats-trend') return await handleStatsTrend(env, url.searchParams.get('days') || '30');
          if (p === '/api/backup' && req.method === 'POST') return json(await createBackup(env, 'manual'));
          if (p === '/api/backup-diff' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleBackupDiff(env, b.key); }
          if (p === '/api/backups' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleBackupList(env); }
          if (p === '/api/backup-download') { if (!requireRw) return denyRo(); const bk = url.searchParams.get('key') || ''; if (bk.indexOf(BACKUP_PREFIX) !== 0) return json({ error: 'Bad key' }, 400); return await serveObject(env, req, bk, { disposition: 'attachment; filename="' + encodeURIComponent(String(bk).split('/').pop()) + '"' }); }
          if (p === '/api/backup-restore' && req.method === 'POST') { const b = await req.json(); return await handleBackupRestore(env, b.key, b.password); }
          if (p === '/api/health' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleHealth(env); }
          if (p === '/api/scan-orphans' && req.method === 'POST') return await handleScanOrphans(env);
          if (p === '/api/purge-orphans' && req.method === 'POST') { const b = await req.json(); return await handlePurgeOrphans(env, b.mode || 'objects'); }
          if (p === '/api/webhook' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleGetWebhook(env); }
          if (p === '/api/webhook' && req.method === 'POST') { const b = await req.json(); return await handleSetWebhook(env, b); }
          if (p === '/api/webhook-test' && req.method === 'POST') return await handleWebhookTest(env);
          if (p === '/api/albums' && req.method === 'GET') return await handleListAlbums(env);
          if (p === '/api/albums' && req.method === 'POST') { const b = await req.json(); return await handleCreateAlbum(env, b.path, b.name, b.password); }
          if (p === '/api/albums/update' && req.method === 'POST') { const b = await req.json(); return await handleAlbumUpdate(env, b.id, b); }
          if (p === '/api/media' && req.method === 'GET') return await handleMediaList(env, {
            path: url.searchParams.get('path') || '/',
            kind: url.searchParams.get('kind') || 'media',
            limit: url.searchParams.get('limit') || ''
          });
          if (p === '/api/phash' && req.method === 'POST') { const b = await req.json(); return await handleSetPhash(env, b); }
          // 检索与组织
          if (p === '/api/query' && req.method === 'GET') return await handleQuery(env, {
            path: url.searchParams.get('path') || '/',
            q: url.searchParams.get('q') || '',
            type: url.searchParams.get('type') || '',
            ext: url.searchParams.get('ext') || '',
            minSize: url.searchParams.get('minSize') || '',
            maxSize: url.searchParams.get('maxSize') || '',
            after: url.searchParams.get('after') || '',
            before: url.searchParams.get('before') || '',
            tags: url.searchParams.get('tags') || '',
            tagMode: url.searchParams.get('tagMode') || '',
            fav: url.searchParams.get('fav') || '',
            deep: url.searchParams.get('deep') || '1',
            sort: url.searchParams.get('sort') || 'name',
            order: url.searchParams.get('order') || 'asc',
            limit: url.searchParams.get('limit') || '',
            offset: url.searchParams.get('offset') || ''
          }, extractToken(req));
          if (p === '/api/tags/rename' && req.method === 'POST') { const b = await req.json(); return await handleTagRename(env, b.from, b.to, b.color); }
          if (p === '/api/tags/color' && req.method === 'POST') { const b = await req.json(); return await handleTagColor(env, b.name, b.color); }
          if (p === '/api/tags/batch' && req.method === 'POST') { const b = await req.json(); return await handleTagBatch(env, b.paths, b.add, b.remove, b.mode); }
          if (p === '/api/tags/auto' && req.method === 'POST') { const b = await req.json(); return await handleTagAuto(env, b); }
          if (p === '/api/favgroups' && (req.method === 'GET' || req.method === 'POST')) { if (!requireRw) return denyRo(); return await handleFavGroups(env, req); }
          if (p === '/api/export-meta' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleExportMeta(env, {
            path: url.searchParams.get('path') || '/',
            format: url.searchParams.get('format') || ''
          }); }
          if (p === '/api/import-meta' && req.method === 'POST') { if (!requireRw) return denyRo(); const b = await req.json(); return await handleImportMeta(env, b); }
          if (p === '/api/albums' && req.method === 'DELETE') { const b = await req.json(); return await handleDeleteAlbum(env, b.id); }
          if (p === '/api/recent' && req.method === 'GET') return await handleGetRecent(env);
          if (p === '/api/recent' && req.method === 'POST') { const b = await req.json(); await addRecent(env, b.path); return json({ ok: true }); }
          if (p === '/api/favs' && req.method === 'GET') { return json({ items: await enrichPathItems(env, await getFavs(env)) }); }
          if (p === '/api/fav' && req.method === 'POST') { const b = await req.json(); await toggleFav(env, b.path); return json({ ok: true }); }
        } catch (e) { console.error(e); return json({ error: 'Internal error' }, 500); }
        return json({ error: 'Not found' }, 404);
      }
      return html(page(env));
    } catch (e) {
      console.error('Fatal:', e);
      return json({ error: 'Internal error' }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        // 1) 回收站过期清理（TRASH_DAYS，默认 30 天）
        await gcTrash(env, 5000);
        // 1.5) 用户自定义定时任务（TTL 目录 / 清空目录 / 自动归档）
        try { await runAllCronJobs(env, 10); } catch (e) { console.error('cron jobs failed:', e); }
        // 2) 未完成上传的分片回收（CHUNK_GC_HOURS，默认 24 小时）
        const chunksGone = await gcChunks(env, 5000);
        // 3) 版本/缩略图等内部对象的失效回收
        const internalGone = await gcInternalObjects(env, 2000);
        // 4) 用量校准（避免计数漂移导致配额形同虚设）
        try { await recalcUsage(env); } catch (e) {}
        // 5) 遥测缓冲落盘
        try { await flushTelemetry(env); } catch (e) {}
        // 6) 每日自动快照（当天已有则跳过）
        try {
          const listed = await env.DRIVE.list({ prefix: BACKUP_PREFIX, limit: 200 });
          const objs = listed.objects || [];
          const recent = objs.some(function (o) { return o.uploaded && (Date.now() - new Date(o.uploaded).getTime() < 20 * 3600 * 1000); });
          if (!recent) await createBackup(env, 'auto');
        } catch (e) { console.error('Backup failed:', e); }
        console.log('scheduled: chunks=' + chunksGone + ' internal=' + internalGone);
      } catch (e) { console.error('Scheduled cleanup failed:', e); }
    })());
  }
};
