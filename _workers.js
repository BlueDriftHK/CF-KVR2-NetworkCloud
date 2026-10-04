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
const MAX_VERSIONS = 5;
const MAX_UPLOAD_SIZE = 500 * 1024 * 1024;
const UNZIP_MAX_BYTES = 50 * 1024 * 1024;
const USAGE_DO_NAME = '__usage__';

// ===== Helpers =====
function json(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json' } });
}
function html(body, status) {
  return new Response(body, { status: status || 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
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
  const d = env && env.PUBLIC_UPLOAD_DIR;
  if (!d || typeof d !== 'string' || !d.trim()) return null;
  return normPath(d.trim());
}
function publicUploadMax(env) {
  const n = env ? Number(env.PUBLIC_UPLOAD_MAX) : NaN;
  return (Number.isFinite(n) && n > 0) ? n : 100 * 1024 * 1024;
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
  try {
    const list = (await env.STORE.get('meta:dllog', 'json')) || [];
    list.unshift(e);
    if (list.length > 300) list.length = 300;
    await env.STORE.put('meta:dllog', JSON.stringify(list));
    const agg = (await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 };
    agg.total = (agg.total || 0) + 1;
    agg.bytes = (agg.bytes || 0) + (e.size || 0);
    await env.STORE.put('meta:dlstat', JSON.stringify(agg));
    await addDailyStat(env, 'dl', e.size || 0);
  } catch (err) {}
}

// 按前缀列出 KV key（用于分享/上传链接管理）
async function listKV(env, prefix, max) {
  const out = [];
  const cap = max || 500;
  try {
    let cursor;
    do {
      const res = await env.STORE.list({ prefix, cursor });
      for (const k of res.keys) { out.push(k.name); if (out.length >= cap) break; }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor && out.length < cap);
  } catch (e) {}
  return out;
}

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
  const url = cfg.endpoint + canonicalUri + (canonicalQuery ? '?' + canonicalQuery : '');
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

    if (op === 'get') {
      let items = await this.state.storage.get('items');
      if (items === undefined) {
        try {
          const kv = await this.env.STORE.get('dir:' + this.name, 'json');
          items = kv || [];
        } catch (e) { items = []; }
        await this.state.storage.put('items', items);
      }
      return json(items);
    }
    if (op === 'set' && req.method === 'PUT') {
      const items = await req.json();
      await this.state.storage.put('items', items);
      return json({ ok: true });
    }
    if (op === 'upsert' && req.method === 'POST') {
      const { item } = await req.json();
      const items = await this.state.storage.get('items') || [];
      const idx = items.findIndex(i => i.name === item.name);
      if (idx >= 0) items[idx] = item; else items.push(item);
      await this.state.storage.put('items', items);
      return json({ ok: true, existed: idx >= 0 });
    }
    if (op === 'remove' && req.method === 'POST') {
      const { name } = await req.json();
      const items = await this.state.storage.get('items') || [];
      const filtered = items.filter(i => i.name !== name);
      await this.state.storage.put('items', filtered);
      return json({ ok: true, removed: items.length - filtered.length });
    }
    if (op === 'rename' && req.method === 'POST') {
      const { oldName, newName } = await req.json();
      const items = await this.state.storage.get('items') || [];
      const idx = items.findIndex(i => i.name === oldName);
      if (idx < 0) return json({ error: 'not found' }, 404);
      if (items.find(i => i.name === newName)) return json({ error: 'exists' }, 409);
      items[idx] = { ...items[idx], name: newName, time: new Date().toISOString() };
      await this.state.storage.put('items', items);
      return json({ ok: true, item: items[idx] });
    }
    if (op === 'find' && req.method === 'GET') {
      const name = url.searchParams.get('name');
      const items = await this.state.storage.get('items') || [];
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
      const u = await this.state.storage.get('usage') || { used: 0, files: 0 };
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
      await this.state.storage.deleteAll();
      return json({ ok: true });
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
  try { await env.STORE.put('dir:' + np, JSON.stringify(items)); } catch (e) {}
}

// DO 成功变更后，把最新目录镜像回 KV，避免 DO 故障时读到陈旧数据
async function mirrorDirToKV(env, np) {
  if (!hasDO(env)) return;
  try {
    const r = await withTimeout(dirStub(env, np).fetch('https://dir/get'), 3000);
    if (r && r.ok) await env.STORE.put('dir:' + np, JSON.stringify(await r.json()));
  } catch (e) {}
}

async function upsertDirItem(env, path, item) {
  const np = normPath(path);
  if (hasDO(env)) {
    try {
      const r = await withTimeout(dirStub(env, np).fetch('https://dir/upsert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item })
      }), 3000);
      if (r && r.ok) { const out = await r.json(); await mirrorDirToKV(env, np); return out; }
    } catch (e) { console.warn('DO upsert → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const idx = items.findIndex(i => i.name === item.name);
  if (idx >= 0) items[idx] = item; else items.push(item);
  await env.STORE.put('dir:' + np, JSON.stringify(items));
  return { ok: true, existed: idx >= 0 };
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
      if (r && r.ok) { const out = await r.json(); await mirrorDirToKV(env, np); return out; }
    } catch (e) { console.warn('DO remove → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const filtered = items.filter(i => i.name !== name);
  await env.STORE.put('dir:' + np, JSON.stringify(filtered));
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
      if (r && r.ok) { const out = await r.json(); await mirrorDirToKV(env, np); return out; }
      if (r && r.status === 404) return { error: 'not found' };
      if (r && r.status === 409) return { error: 'exists' };
    } catch (e) { console.warn('DO rename → KV:', e && e.message); }
  }
  const items = await getDir(env, np);
  const idx = items.findIndex(i => i.name === oldName);
  if (idx < 0) return { error: 'not found' };
  if (items.find(i => i.name === newName)) return { error: 'exists' };
  items[idx] = { ...items[idx], name: newName, time: new Date().toISOString() };
  await env.STORE.put('dir:' + np, JSON.stringify(items));
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
      if (it.type === 'file' && !dirPath.startsWith('/.trash/')) { used += it.size || 0; files++; }
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
      if (locked && locked.has(sub)) continue;
      const nested = await searchDir(env, sub, query, locked);
      results.push(...nested);
    }
  }
  return results;
}

// ===== Recent & Favorites =====
async function addRecent(env, path) {
  try {
    let list = await env.STORE.get('meta:recent', 'json') || [];
    list = list.filter(i => i.path !== path);
    list.unshift({ path, time: Date.now() });
    if (list.length > 50) list = list.slice(0, 50);
    await env.STORE.put('meta:recent', JSON.stringify(list));
  } catch (e) {}
}
async function getRecent(env) { try { return await env.STORE.get('meta:recent', 'json') || []; } catch (e) { return []; } }
async function toggleFav(env, path) {
  let favs = await env.STORE.get('meta:favs', 'json') || [];
  const idx = favs.indexOf(path);
  if (idx >= 0) favs.splice(idx, 1); else favs.push(path);
  await env.STORE.put('meta:favs', JSON.stringify(favs));
  return favs;
}
async function getFavs(env) { try { return await env.STORE.get('meta:favs', 'json') || []; } catch (e) { return []; } }

// ===== Auth =====
// 统一鉴权：会话令牌（rw）或访问令牌（ro/rw）；也支持 Authorization: Bearer
async function authInfo(env, req) {
  let t = '';
  try { t = new URL(req.url).searchParams.get('token') || ''; } catch (e) {}
  if (!t) {
    const a = req.headers.get('Authorization') || '';
    if (a.startsWith('Bearer ')) t = a.substring(7).trim();
  }
  if (!t) return { ok: false, perm: '' };
  try {
    const s = await env.STORE.get('session:' + t, 'json');
    if (s && Date.now() < s.exp) return { ok: true, perm: 'rw', kind: 'session' };
  } catch (e) {}
  try {
    const tokens = await getAccessTokens(env);
    const found = tokens.find(x => safeEqual(x.token, t));
    if (found) {
      if (found.exp && Date.now() > new Date(found.exp).getTime()) return { ok: false, perm: '' };
      return { ok: true, perm: found.perm === 'ro' ? 'ro' : 'rw', kind: 'token' };
    }
  } catch (e) {}
  return { ok: false, perm: '' };
}
async function checkAuth(env, req) {
  const a = await authInfo(env, req);
  return a.ok;
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
  const allow = String((env && env.IP_ALLOW) || '').split(',').map(s => s.trim()).filter(Boolean);
  const deny = String((env && env.IP_DENY) || '').split(',').map(s => s.trim()).filter(Boolean);
  for (let i = 0; i < deny.length; i++) { if (ipMatch(ip, deny[i])) return false; }
  if (allow.length) { for (let i = 0; i < allow.length; i++) { if (ipMatch(ip, allow[i])) return true; } return false; }
  return true;
}

// ===== 会话 / 设备管理 =====
async function handleListSessions(env, currentToken) {
  const keys = await listKV(env, 'session:', 300);
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
  return json({ ok: true, revoked: n });
}

// ===== Folder lock =====
async function isPathLocked(env, dirPath, sessionToken) {
  dirPath = normPath(dirPath);
  const parts = dirPath.split('/').filter(Boolean);
  let check = '/';
  const locked = [];
  for (const seg of parts) {
    check = check === '/' ? '/' + seg + '/' : check + seg + '/';
    const pass = await env.STORE.get('dirpass:' + check, 'json');
    if (pass) locked.push(check);
  }
  if (!locked.length) return false;
  if (!sessionToken) return true;
  for (const lp of locked) {
    try {
      const u = await env.STORE.get('unlock:' + sessionToken + ':' + lp, 'json');
      if (!u || Date.now() >= u.exp) return true;
    } catch (e) { return true; }
  }
  return false;
}
async function guard(env, req, ...paths) {
  const st = new URL(req.url).searchParams.get('token') || '';
  for (const p of paths) {
    if (!p) continue;
    const np = normPath(p);
    if (await isPathLocked(env, np, st)) return json({ locked: true, path: np }, 423);
  }
  return null;
}

// 收集被密码保护的目录，用于全局扫描接口过滤，避免泄露锁定目录内容
async function getLockedPrefixes(env) {
  const set = new Set();
  try {
    let cursor;
    do {
      const res = await env.STORE.list({ prefix: 'dirpass:', cursor });
      for (const k of res.keys) set.add(k.name.substring('dirpass:'.length));
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch (e) {}
  return set;
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
  for (const lp of locked) { if (p !== lp && p.startsWith(lp)) return true; }
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
    const ts = Date.now();
    const vKey = VERSIONS_PREFIX + key + '/' + ts;
    await env.DRIVE.put(vKey, oldObj.body, { httpMetadata: oldObj.httpMetadata });
    let list = await listVersions(env, key);
    list.unshift({ ts, size: (entry && entry.size) || 0, mime: (entry && entry.mime) || '' });
    while (list.length > MAX_VERSIONS) {
      const old = list.pop();
      try { await env.DRIVE.delete(VERSIONS_PREFIX + key + '/' + old.ts); } catch (e) {}
    }
    await env.STORE.put('versions:' + key, JSON.stringify(list));
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
    await env.STORE.put('versions:' + newKey, JSON.stringify(list));
    await env.STORE.delete('versions:' + oldKey);
  } catch (e) {}
}

// ===== API =====
async function handleLogin(req, env) {
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
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
    return json({ error: 'Wrong password' }, 401);
  }
  await env.STORE.delete('login:' + ip); if (loginUser) { try { await env.STORE.delete('login:u:' + loginUser); } catch (e) {} }
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
  if (file.size > MAX_UPLOAD_SIZE) return json({ error: 'File too large', max: MAX_UPLOAD_SIZE }, 413);

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

  const oldRes = await findDirItem(env, uploadDir, safeName);
  const oldItem = oldRes.item;
  const upDelta = file.size - (oldItem ? (oldItem.size || 0) : 0);
  if (upDelta > 0) {
    const u = await getUsage(env);
    if ((u.used || 0) + upDelta > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  }
  if (oldItem) await pushVersion(env, key, oldItem);

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
    await upsertDirItem(env, uploadDir, entry);
    if (isHex64(clientHash)) { try { await env.STORE.put('hash:' + clientHash, JSON.stringify({ key, time: Date.now() })); } catch (e) {} }
    if (oldItem) {
      if (oldItem.hasThumb && !hasThumb) await deleteThumb(env, key);
      await addUsage(env, file.size - (oldItem.size || 0), 0);
    } else {
      await addUsage(env, file.size, 1);
      await addLog(env, 'up', uploadDir + safeName, file.size + ' bytes');
    }
  } catch (e) {
    try { await env.DRIVE.delete(key); } catch (e2) {}
    await deleteThumb(env, key);
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
  const size = new TextEncoder().encode(content).byteLength;

  const oldRes = await findDirItem(env, dir, name);
  if (oldRes.item) await pushVersion(env, key, oldRes.item);

  await putAndMirror(env, key, content, { httpMetadata: { contentType: 'text/plain' } });

  const old = oldRes.item || {};
  const entry = {
    name, type: 'file', size, mime: 'text/plain',
    time: new Date().toISOString(),
    hash: old.hash || '',
    hasThumb: !!old.hasThumb
  };
  await upsertDirItem(env, dir, entry);
  if (oldRes.item) {
    await addUsage(env, size - (oldRes.item.size || 0), 0);
  } else {
    await addUsage(env, size, 1);
  }
  return json({ ok: true });
}

async function handleDelete(env, path) {
  path = '/' + path.replace(/^\/+/, '');
  const dir = parentOf(path); const name = path.split('/').filter(Boolean).pop();
  const res = await findDirItem(env, dir, name);
  const entry = res.item;
  if (!entry) return json({ error: 'Not found' }, 404);

  await removeDirItem(env, dir, name);

  if (entry.type === 'dir') {
    // M4: 删除目录前检查子孙锁定子树，防止绕过锁定
    const lockedSub = await hasLockedSubtree(env, path + '/');
    if (lockedSub) return json({ error: 'Locked', path: lockedSub }, 423);
    await recursiveDeleteDir(env, path + '/');
    return json({ ok: true });
  }
  await deleteThumb(env, path.replace(/^\//, ''));
  await deleteVersions(env, path.replace(/^\//, ''));
  const trash = await getDir(env, '/.trash/');
  trash.push({ name, type: 'file', size: entry.size || 0, mime: entry.mime || '', originalPath: path, deletedAt: new Date().toISOString(), id: randToken().substring(0, 8) });
  await putDir(env, '/.trash/', trash);
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
  const items = await getDir(env, '/.trash/');
  const now = Date.now();
  const enriched = items.map(it => {
    const dt = it.deletedAt ? new Date(it.deletedAt).getTime() : now;
    const daysLeft = Math.max(0, 30 - Math.floor((now - (Number.isFinite(dt) ? dt : now)) / 86400000));
    return { ...it, daysLeft };
  });
  return json({ items: enriched });
}

async function handleRestore(env, id) {
  const trash = await getDir(env, '/.trash/');
  let idx = trash.findIndex(i => i.id === id);
  if (idx < 0) idx = trash.findIndex(i => i.name === id);
  if (idx < 0) return { error: 'Not in trash', status: 404 };
  const entry = trash[idx]; const dir = parentOf(entry.originalPath);
  const existing = await findDirItem(env, dir, entry.name);
  if (existing.item) return { error: 'Name exists', status: 409 };
  await upsertDirItem(env, dir, { name: entry.name, type: entry.type, size: entry.size, mime: entry.mime, time: entry.deletedAt });
  trash.splice(idx, 1); await putDir(env, '/.trash/', trash);
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
  const trash = await getDir(env, '/.trash/');
  if (id === 'ALL') {
    let sz = 0, ct = 0;
    for (const item of trash) {
      const k = item.originalPath.replace(/^\//, '');
      await deleteAndMirror(env, k);
      await deleteThumb(env, k);
      await deleteVersions(env, k);
      sz += item.size || 0; ct++;
    }
    await putDir(env, '/.trash/', []); await addUsage(env, -sz, -ct); return json({ ok: true });
  }
  let idx = trash.findIndex(i => i.id === id);
  if (idx < 0) idx = trash.findIndex(i => i.name === id);
  if (idx < 0) return json({ error: 'Not in trash' }, 404);
  const entry = trash[idx];
  const k = entry.originalPath.replace(/^\//, '');
  await deleteAndMirror(env, k);
  await deleteThumb(env, k);
  await deleteVersions(env, k);
  trash.splice(idx, 1); await putDir(env, '/.trash/', trash); await addUsage(env, -(entry.size || 0), -1); return json({ ok: true });
}

async function handleBatchPurge(env, ids) {
  for (const id of ids) { try { await handlePurge(env, id); } catch (e) {} }
  return json({ ok: true });
}

async function handleMkdir(env, path, name) {
  path = normPath(path);
  const safeName = sanitizeName(name);
  if (!safeName) return json({ error: 'Bad name' }, 400);
  await upsertDirItem(env, path, { name: safeName, type: 'dir', time: new Date().toISOString() });
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
    if (dp) { await env.STORE.put('dirpass:' + newPrefix, JSON.stringify(dp)); await env.STORE.delete('dirpass:' + oldPrefix); }
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

async function handleBatchDelete(env, paths) {
  let ok = 0, fail = 0;
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
        if (locked.has(sub)) continue;
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
  try {
    const day = new Date().toISOString().substring(0, 10);
    const all = (await env.STORE.get('meta:daily', 'json')) || {};
    const d = all[day] || { up: 0, upBytes: 0, dl: 0, dlBytes: 0 };
    if (kind === 'up') { d.up = (d.up || 0) + 1; d.upBytes = (d.upBytes || 0) + (bytes || 0); }
    else if (kind === 'del') { /* 只累计，不展示 */ }
    else { d.dl = (d.dl || 0) + 1; d.dlBytes = (d.dlBytes || 0) + (bytes || 0); }
    all[day] = d;
    const keys = Object.keys(all).sort();
    while (keys.length > 90) { delete all[keys.shift()]; }
    await env.STORE.put('meta:daily', JSON.stringify(all));
  } catch (e) {}
}
async function handleStatsTrend(env, days) {
  const n = Math.min(Math.max(parseInt(days, 10) || 30, 7), 90);
  const all = (await env.STORE.get('meta:daily', 'json')) || {};
  const out = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().substring(0, 10);
    const v = all[d] || {};
    out.push({ date: d, up: v.up || 0, dl: v.dl || 0, upBytes: v.upBytes || 0, dlBytes: v.dlBytes || 0 });
  }
  return json({ days: out });
}
async function addLog(env, action, path, detail) {
  try {
    const logs = (await env.STORE.get('meta:log', 'json')) || [];
    logs.unshift({ action, path, detail: detail || '', time: new Date().toISOString() });
    if (logs.length > 200) logs.length = 200;
    await env.STORE.put('meta:log', JSON.stringify(logs));
  } catch (e) {}
  if (action === 'up') {
    const m = /^(\d+)/.exec(String(detail || ''));
    await addDailyStat(env, 'up', m ? Number(m[1]) : 0);
  }
  await notifyWebhook(env, { event: action, path: path || '', detail: detail || '' });
}
async function getLogs(env) {
  try { return (await env.STORE.get('meta:log', 'json')) || []; } catch (e) { return []; }
}

// ===== Access Tokens =====
async function getAccessTokens(env) {
  try { return (await env.STORE.get('meta:tokens', 'json')) || []; } catch (e) { return []; }
}
async function saveAccessTokens(env, tokens) {
  await env.STORE.put('meta:tokens', JSON.stringify(tokens));
}
// ===== Note =====
async function handleGetNote(env, filePath) {
  try { return json({ note: (await env.STORE.get('note:' + filePath, 'json')) || '' }); }
  catch (e) { return json({ note: '' }); }
}
async function handleSetNote(env, filePath, note) {
  await env.STORE.put('note:' + filePath, JSON.stringify(note || ''));
  return json({ ok: true });
}

// ===== Tag =====
async function getFileTags(env, filePath) { try { return await env.STORE.get('tags:' + filePath, 'json') || []; } catch (e) { return []; } }
async function setFileTags(env, filePath, tags) { await env.STORE.put('tags:' + filePath, JSON.stringify(tags)); }
async function getAllTags(env) { try { return await env.STORE.get('meta:tags', 'json') || []; } catch (e) { return []; } }
async function addGlobalTag(env, tag) { const tags = await getAllTags(env); if (!tags.find(t => t.name === tag.name)) tags.push(tag); await env.STORE.put('meta:tags', JSON.stringify(tags)); }
async function handleTagFile(env, filePath, tags) {
  filePath = '/' + filePath.replace(/^\/+/, '');
  await setFileTags(env, filePath, tags);
  for (const t of tags) await addGlobalTag(env, t);
  return json({ ok: true });
}
async function handleGetTags(env) { return json({ tags: await getAllTags(env) }); }
async function handleTagFilter(env, tagName) {
  const locked = await getLockedPrefixes(env);
  const results = [];
  const seen = new Set();
  async function scanDir(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file') { const ft = await getFileTags(env, dirPath + it.name); if (ft.find(t => t.name === tagName)) { const k = dirPath + it.name; if (!seen.has(k)) { seen.add(k); results.push({ ...it, path: dirPath }); } } }
      else if (it.type === 'dir') {
        const sub = dirPath + it.name + '/';
        if (locked.has(sub)) continue;
        await scanDir(sub);
      }
      if (results.length >= 500) return;
    }
  }
  await scanDir('/');
  return json({ items: results });
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
async function handleChunkInit(env, fileName, totalSize, hash, dirPath) {
  const uploadId = randToken().substring(0, 16);
  dirPath = normPath(dirPath);
  const size = parseInt(totalSize, 10) || 0;
  if (size > MAX_UPLOAD_SIZE) return json({ error: 'File too large', max: MAX_UPLOAD_SIZE }, 413);
  if (size > 0) {
    const u = await getUsage(env);
    if ((u.used || 0) + size > quotaTotal(env)) return json({ error: 'Quota exceeded' }, 413);
  }
  await env.STORE.put('chunk:' + uploadId, JSON.stringify({ fileName: sanitizeName(fileName), totalSize: size, hash: hash || '', dirPath, chunks: 0, created: Date.now() }), { expirationTtl: 86400 });
  if (isHex64(hash)) {
    try {
      const r = await instantStore(env, hash, fileName, dirPath, size);
      if (r.hit) { try { await env.STORE.delete('chunk:' + uploadId); } catch (e) {} return json({ instant: true, name: r.name }); }
    } catch (e) {}
  }
  return json({ uploadId, chunkSize: 5 * 1024 * 1024 });
}
// 分片上传：每个分片用独立 KV 键记录已上传状态，避免并发覆盖
async function handleChunkUpload(req, env, uploadId, chunkIndex) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Upload not found' }, 404);
  const st = new URL(req.url).searchParams.get('token') || '';
  if (await isPathLocked(env, meta.dirPath, st)) return json({ locked: true, path: meta.dirPath }, 423);
  const idx = parseInt(chunkIndex, 10);
  if (!Number.isFinite(idx) || idx < 0 || idx > 100000) return json({ error: 'Bad chunk index' }, 400);
  const body = await req.arrayBuffer();
  if (body.byteLength > 5 * 1024 * 1024) return json({ error: 'Chunk too large' }, 413);
  await env.DRIVE.put('chunks/' + uploadId + '/' + idx, body);
  // 每个分片独立 key，避免并发写入互相覆盖
  try { await env.STORE.put('chunkgot:' + uploadId + ':' + idx, '1', { expirationTtl: 86400 }); } catch (e) {}
  if ((meta.chunks || 0) <= idx) {
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
  const st = new URL(req.url).searchParams.get('token') || '';
  if (await isPathLocked(env, meta.dirPath, st)) return json({ locked: true, path: meta.dirPath }, 423);

  const name = sanitizeName(meta.fileName);
  const outDir = await applyAutoArchive(env, normPath(meta.dirPath), name, '');
  const key = outDir.replace(/^\//, '') + name;
  const total = Math.max(0, parseInt(meta.chunks, 10) || 0);
  if (!total) return json({ error: 'No chunks uploaded' }, 400);

  const oldRes = await findDirItem(env, outDir, name);
  const oldItem = oldRes.item;
  if (oldItem) await pushVersion(env, key, oldItem);

  let done = false;
  if (total > 1) {
    try {
      const multipart = await env.DRIVE.createMultipartUpload(key, { httpMetadata: { contentType: 'application/octet-stream' } });
      try {
        const uploaded = [];
        for (let i = 0; i < total; i += 10) {
          const batch = [];
          for (let j = i; j < Math.min(i + 10, total); j++) {
            batch.push((async () => {
              const chunk = await env.DRIVE.get('chunks/' + uploadId + '/' + j);
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
      const chunk = await env.DRIVE.get('chunks/' + uploadId + '/' + i);
      if (!chunk) return json({ error: 'Missing chunk ' + i }, 400);
      const ab = await chunk.arrayBuffer();
      totalLen += ab.byteLength;
      if (totalLen > 50 * 1024 * 1024) return json({ error: 'File too large for assembly (max 50MB without multipart)' }, 413);
      parts.push(new Uint8Array(ab));
    }
    const buf = new Uint8Array(totalLen); let offset = 0;
    for (const p of parts) { buf.set(p, offset); offset += p.byteLength; }
    try { await env.DRIVE.put(key, buf, { httpMetadata: { contentType: 'application/octet-stream' } }); }
    catch (e) { return json({ error: 'Assembly failed' }, 500); }
  }
  try { await mirrorPut(env, key); } catch (e) {}

  const delPromises = [];
  for (let i = 0; i < total; i++) { delPromises.push(env.DRIVE.delete('chunks/' + uploadId + '/' + i).catch(() => {})); }
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
  if (meta.hash) { try { await env.STORE.put('hash:' + meta.hash, JSON.stringify({ key, time: Date.now() })); } catch (e) {} }

  const finalSize = meta.totalSize || 0;
  const entry = { name, type: 'file', size: finalSize, mime: '', time: new Date().toISOString(), hash: meta.hash || '' };
  await upsertDirItem(env, outDir, entry);
  if (oldItem) await addUsage(env, finalSize - (oldItem.size || 0), 0);
  else await addUsage(env, finalSize, 1);
  await addLog(env, 'up', key, finalSize + ' bytes (chunked)');
  return json({ ok: true, key });
}
async function handleChunkStatus(env, uploadId) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Not found' }, 404);
  const got = await listGotChunks(env, uploadId);
  return json({
    chunks: meta.chunks, total: Math.ceil(meta.totalSize / (5 * 1024 * 1024)),
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
      if (locked.has(childPath)) { node.children.push({ name: d.name, path: childPath, children: [] }); continue; }
      const child = await buildNode(childPath, depth + 1);
      if (child) node.children.push(child);
    }
    return node;
  }
  const tree = await buildNode('/', 0);
  return json({ tree });
}

// ===== Share（修复：访问计数在 /data 处 +1，/pv 和 /dl 仅检查配额） =====
async function createShare(env, filePath, days, maxAccesses, password, isDir) {
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
    const obj = await env.DRIVE.get(filePath.replace(/^\//, ''));
    size = obj ? obj.size : 0;
    mime = (obj && obj.httpMetadata && obj.httpMetadata.contentType) || '';
  }
  const rec = { path: filePath, type: isDir ? 'dir' : 'file', exp: Date.now() + ttl * 1000, max: clampCount(maxAccesses), hits: 0, pwHash, pwSalt, name, size, mime };
  await env.STORE.put('share:' + t, JSON.stringify(rec), { expirationTtl: ttl + 60 });
  try { await addLog(env, 'shr', filePath, isDir ? '文件夹分享' : '文件分享'); } catch (e) {}
  return { ok: true, url: '/s/' + t, hasPassword: !!pwHash, path: filePath, name };
}
async function handleShare(env, filePath, days, maxAccesses, password, isDir) {
  const r = await createShare(env, filePath, days, maxAccesses, password, !!isDir);
  if (r && r.ok === false && r.locked) return json({ error: 'Locked', path: r.path }, 423);
  return json(r);
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
// 分享访问校验：过期 / 次数 / 密码（可选），返回 {data} 或 {resp}
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
  if (countHit) {
    const before = data.hits || 0;
    if (data.max > 0 && before >= data.max) return { resp: json({ error: 'Access limit reached', hits: data.max, max: data.max, name: data.name }, 403) };
    const atom = await counterAdd(env, 'share:' + shareToken, 1);
    const hits = (atom == null) ? (before + 1) : atom;
    data.hits = hits;
    try { await env.STORE.put('share:' + shareToken, JSON.stringify(data), { expirationTtl: Math.max(60, Math.ceil((data.exp - Date.now()) / 1000) + 60) }); } catch (e) {}
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
async function handleShareData(env, shareToken, req) {
  try {
    const pw = new URL(req.url).searchParams.get('pw') || '';
    const hasPw = pw !== '';
    // 未带 pw 视为"首次打开"，计一次访问；带 pw 视为"验证尝试"，不重复计数
    const g = await shareGuard(env, shareToken, req, !hasPw, false);
    if (g.resp) return g.resp;
    const d = g.data;
    const stats = { hits: d.max > 0 ? Math.min(d.hits || 0, d.max) : (d.hits || 0), max: d.max || 0 };
    if (d.pwHash && !await verifyPassword(pw, { hash: d.pwHash, salt: d.pwSalt })) {
      return json(Object.assign({ needPassword: true, hasPassword: true }, stats));
    }
    return json(Object.assign({
      type: d.type || 'file', name: d.name, size: d.size || 0, mime: d.mime || ''
    }, stats));
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
    return await serveObject(env, req, key, { disposition: 'inline', sanitize: true, cacheControl: 'private, max-age=3600' });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}
async function handleShareDownload(env, shareToken, req) {
  try {
    const g = await shareGuard(env, shareToken, req, false, true);
    if (g.resp) return g.resp;
    const key = shareRelKey(g.data, new URL(req.url).searchParams.get('p') || '');
    if (!key) return json({ error: 'Not found' }, 404);
    const name = key.split('/').pop();
    const resp = await serveObject(env, req, key, { disposition: 'attachment; filename="' + encodeURIComponent(name) + '"' });
    if (resp.status === 200) {
      await addDownloadLog(env, Object.assign({ time: new Date().toISOString(), path: '/' + key, name, size: g.data.size || 0, source: 'share' }, clientInfo(req)));
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
      const r = await createShare(env, fp, days, maxAccesses, password);
      items.push({ path: fp, name: r.name, url: r.url });
      created++;
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

function sharePage(token) {
  const title = '文件分享';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--text3:#8c959f;--accent:#0969da;--accent-h:#0860c4;--fill:#f6f8fa;--red:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#2f81f7;--accent-h:#58a6ff;--fill:#21262d;--red:#f85149}}
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
</style></head><body>
<div class="card">
<h2>📎 文件分享</h2>
<div class="meta" id="meta">加载中...</div>
<div class="ficon" id="ficon">📄</div>
<div class="name" id="fname">—</div>
<div class="pv hidden" id="pvBox"></div>
<div class="row hidden" id="pwRow"><input type="password" id="pwInput" placeholder="请输入访问密码" autocomplete="off"><button id="btnPw">确定</button></div>
<div class="row hidden" id="dlRow"><button id="btnDl">下载文件</button></div>
<div class="msg" id="msg"></div>
</div>
<script>
var tk=${JSON.stringify(token)};
var pw='';
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
    document.getElementById('dlRow').classList.remove('hidden');
    tryPreview();
  }).catch(function(){setMsg('加载失败',true)});
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
    document.getElementById('dlRow').classList.remove('hidden');
    tryPreview();
  }).catch(function(){setMsg('密码错误或加载失败',true)});
};
document.getElementById('pwInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnPw').click()};
document.getElementById('btnDl').onclick=function(){
  window.location='/s/'+tk+'/dl?pw='+encodeURIComponent(pw);
};
loadData();
</script></body></html>`;
}

function shareDirPage(token) {
  const tk = JSON.stringify(token);
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>文件夹分享</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--text3:#8c959f;--accent:#0969da;--accent-h:#0860c4;--fill:#f6f8fa;--red:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#2f81f7;--accent-h:#58a6ff;--fill:#21262d;--red:#f85149}}
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
</style></head><body>
<div class="card">
  <h2>📁 文件夹分享</h2>
  <div class="meta" id="meta">加载中...</div>
  <div class="name" id="fname">—</div>
  <div class="pwrow hidden" id="pwRow"><input type="password" id="pwInput" placeholder="请输入访问密码" autocomplete="off"><button class="btn" id="btnPw">确定</button></div>
  <div class="hidden" id="box"><div class="bc" id="bc"></div><div id="list"></div></div>
  <div class="msg" id="msg"></div>
</div>
<script>
var tk=${tk},pw='',rel='';
function esc(s){return String(s==null?'':s).replace(/[&<>"'\`]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\`':'&#96;'}[c]})}
function fmt(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i]}
function setMsg(s,isErr){var m=document.getElementById('msg');m.textContent=s||'';m.className='msg'+(isErr?' err':'')}
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
</script></body></html>`;
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
:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--text3:#8c959f;--accent:#0969da;--accent-h:#0860c4;--fill:#f6f8fa;--red:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#2f81f7;--accent-h:#58a6ff;--fill:#21262d;--red:#f85149}}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:32px;max-width:440px;width:100%;text-align:center}
h2{font-size:18px;color:var(--text);margin-bottom:8px;font-weight:600}
p{font-size:14px;color:var(--text2);margin-bottom:24px}
.zone{border:1px dashed var(--border);border-radius:8px;padding:36px 20px;cursor:pointer;transition:all .15s;background:var(--fill)}
.zone:hover,.zone.over{border-color:var(--accent);background:rgba(9,105,218,.08)}
.zone p{margin:0;font-size:15px;color:var(--text2)}
.list{margin-top:16px;text-align:left;font-size:14px}.list div{padding:8px 0;border-bottom:1px solid var(--border)}
.ok{color:var(--accent)}.err{color:var(--red)}</style></head><body>
<div class="card"><h2>📤 文件上传</h2><p>有人给你分享了一个上传链接</p>
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
</`+`script></body></html>`;
}

function errorPage(msg) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>访问受限</title>
<style>:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--red:#cf222e}@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--red:#f85149}}body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.c{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:36px;max-width:400px;width:100%;text-align:center}h1{font-size:20px;margin-bottom:8px;color:var(--red)}p{font-size:14px;color:var(--text2)}</style></head><body>
<div class="c"><h1>⚠️ 链接不可用</h1><p>${escHtml(msg)}</p></div></body></html>`;
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
:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--text3:#8c959f;--accent:#0969da;--accent-h:#0860c4;--fill:#f6f8fa;--red:#cf222e;--warn:#9a6700}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#2f81f7;--accent-h:#58a6ff;--fill:#21262d;--red:#f85149;--warn:#d29922}}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:32px;max-width:460px;width:100%;text-align:center}
h2{font-size:18px;color:var(--text);margin-bottom:8px;font-weight:600}
p{font-size:14px;color:var(--text2);margin-bottom:20px}
code{background:var(--fill);border:1px solid var(--border);padding:2px 6px;border-radius:4px;font-size:13px;font-family:ui-monospace,Menlo,monospace}
.zone{border:1px dashed var(--border);border-radius:8px;padding:36px 20px;cursor:pointer;transition:all .15s;background:var(--fill)}
.zone:hover,.zone.over{border-color:var(--accent);background:rgba(9,105,218,.08)}
.zone p{margin:0;font-size:15px;color:var(--text2)}
.list{margin-top:16px;text-align:left;font-size:14px}.list div{padding:8px 0;border-bottom:1px solid var(--border)}
.ok{color:var(--accent)}.err{color:var(--red)}</style></head><body>
<div class="card"><h2>📤 公开上传</h2><p>文件将保存到 <code>${escHtml(dir)}</code></p>
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
</scr` + `ipt></body></html>`;
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
  const singles = ['meta:tags', 'meta:favs', 'meta:recent', 'meta:tokens', 'meta:autorule', 'meta:usage', 'meta:dlstat'];
  const prefixes = ['note:', 'tags:', 'share:', 'ulink:', 'dirpass:', 'versions:'];
  const kv = {};
  for (const key of singles) {
    try { const v = await env.STORE.get(key); if (v !== null && v !== undefined) kv[key] = v; } catch (e) {}
  }
  for (const p of prefixes) {
    const keys = await listKV(env, p, 2000);
    for (const k of keys) {
      try { const v = await env.STORE.get(k); if (v !== null && v !== undefined) kv[k] = v; } catch (e) {}
    }
  }
  return kv;
}
async function createBackup(env, reason) {
  const dirs = await collectDirs(env);
  const kv = await collectMeta(env);
  let dirCount = 0, fileCount = 0;
  for (const p of Object.keys(dirs)) {
    dirCount++;
    for (const it of dirs[p]) { if (it && it.type === 'file') fileCount++; }
  }
  const snap = { version: APP_VERSION, created: new Date().toISOString(), reason: reason || 'manual', dirs, kv };
  const body = JSON.stringify(snap);
  const key = BACKUP_PREFIX + new Date().toISOString().substring(0, 10) + '-' + Date.now().toString(36) + '-' + randToken().substring(0, 6) + '.json';
  await env.DRIVE.put(key, body, { httpMetadata: { contentType: 'application/json' } });
  try {
    const listed = await env.DRIVE.list({ prefix: BACKUP_PREFIX, limit: 1000 });
    const objs = (listed.objects || []).slice().sort(function (a, b) {
      const ta = a.uploaded ? new Date(a.uploaded).getTime() : 0;
      const tb = b.uploaded ? new Date(b.uploaded).getTime() : 0;
      if (ta !== tb) return tb - ta;
      return String(b.key).localeCompare(String(a.key));
    });
    for (const o of objs.slice(14)) { try { await env.DRIVE.delete(o.key); } catch (e) {} }
  } catch (e) {}
  return { ok: true, key, size: body.length, dirs: dirCount, files: fileCount, kvKeys: Object.keys(kv).length, created: snap.created, version: APP_VERSION };
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
  return json({ backups: items, version: APP_VERSION });
}
async function handleBackupRestore(env, key, password) {
  if (!await checkAdminPassword(env, password || '')) return json({ error: 'Wrong password' }, 403);
  if (!key || String(key).indexOf(BACKUP_PREFIX) !== 0) return json({ error: 'Bad key' }, 400);
  let obj = null;
  try { obj = await env.DRIVE.get(String(key)); } catch (e) {}
  if (!obj) return json({ error: 'Not found' }, 404);
  let snap = null;
  try { snap = JSON.parse(new TextDecoder().decode(await obj.arrayBuffer())); } catch (e) { return json({ error: 'Bad snapshot' }, 400); }
  if (!snap || typeof snap !== 'object') return json({ error: 'Bad snapshot' }, 400);
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
  return json({ ok: true, dirs, kvKeys: kvN, snapshot: snap.created || '' });
}

// ===== 健康自检 =====
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
  return json({ version: APP_VERSION, checks, usage: { used: u.used || 0, files: u.files || 0, total: quotaTotal(env) } });
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
    if (referenced.has(k) || k.indexOf(BACKUP_PREFIX) === 0) continue;
    if (k.indexOf(THUMB_PREFIX) === 0) {
      const base = k.substring(THUMB_PREFIX.length);
      if (!referenced.has(base)) orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base });
    } else if (k.indexOf(VERSIONS_PREFIX) === 0) {
      const rest = k.substring(VERSIONS_PREFIX.length);
      const base = rest.substring(0, rest.lastIndexOf('/'));
      if (!base || !referenced.has(base)) orphanInternal.push({ key: k, size: listed.sizes[k] || 0, base });
    } else if (k.indexOf('chunks/') === 0) {
      // M5: chunks/ 由上传会话管理，24 小时内视为活跃，不归孤儿
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
async function handlePurgeOrphans(env, mode) {
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
  try {
    const r = await env.STORE.get('meta:webhook', 'json');
    if (r && typeof r === 'object') return { enabled: !!r.enabled, url: String(r.url || ''), secret: String(r.secret || ''), events: Array.isArray(r.events) ? r.events : ['up', 'del', 'shr', 'mov'] };
  } catch (e) {}
  return { enabled: false, url: '', secret: '', events: ['up', 'del', 'shr', 'mov'] };
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
  const w = {
    enabled: !!(b && b.enabled), url,
    secret: String((b && b.secret) || ''),
    events: Array.isArray(b && b.events) ? b.events.filter(function (x) { return typeof x === 'string' && x.length < 12; }).slice(0, 10) : []
  };
  await env.STORE.put('meta:webhook', JSON.stringify(w));
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
async function getAlbums(env) { try { const a = await env.STORE.get('meta:albums', 'json'); return Array.isArray(a) ? a : []; } catch (e) { return []; } }
async function handleListAlbums(env) { return json({ albums: await getAlbums(env) }); }
async function handleCreateAlbum(env, path, name) {
  const dir = normPath(path || '/');
  if (await isPathLocked(env, dir, '')) return json({ locked: true, path: dir }, 423);
  const albums = await getAlbums(env);
  const id = randToken().substring(0, 16);
  const nm = sanitizeName(name || dir.split('/').filter(Boolean).pop() || '相册');
  albums.push({ id, path: dir, name: nm, created: new Date().toISOString() });
  await env.STORE.put('meta:albums', JSON.stringify(albums));
  return json({ ok: true, id, url: '/a/' + id, name: nm });
}
async function handleDeleteAlbum(env, id) {
  await env.STORE.put('meta:albums', JSON.stringify((await getAlbums(env)).filter(a => a.id !== id)));
  return json({ ok: true });
}
async function collectMedia(env, dirPath, out, depth) {
  if (depth > 8 || out.length >= 300) return;
  let items = [];
  try { items = await getDir(env, dirPath); } catch (e) {}
  for (const it of items) {
    if (out.length >= 300) return;
    if (!it || !it.name) continue;
    if (it.type === 'dir') { await collectMedia(env, dirPath + it.name + '/', out, depth + 1); continue; }
    const m = String(it.mime || '');
    if (m.indexOf('image/') === 0 || m.indexOf('video/') === 0) {
      out.push({ k: (dirPath + it.name).replace(/^\//, ''), name: it.name, mime: m, size: it.size || 0, time: it.time || '', hasThumb: !!it.hasThumb });
    }
  }
}
async function handleAlbumList(env, id) {
  const a = (await getAlbums(env)).find(x => x.id === id);
  if (!a) return json({ error: 'Not found' }, 404);
  if (await isPathLocked(env, a.path, '')) return json({ error: 'Locked' }, 423);
  const out = [];
  await collectMedia(env, a.path, out, 0);
  out.sort(function (x, y) { return String(y.time).localeCompare(String(x.time)); });
  return json({ name: a.name, count: out.length, items: out });
}
async function handleAlbumRaw(env, req, id) {
  const a = (await getAlbums(env)).find(x => x.id === id);
  if (!a) return json({ error: 'Not found' }, 404);
  if (await isPathLocked(env, a.path, '')) return json({ error: 'Locked' }, 423);
  const k = String(new URL(req.url).searchParams.get('k') || '');
  const base = a.path.replace(/^\/+/, '');
  if (!k || k.indexOf(base) !== 0 || k.indexOf('..') >= 0) return json({ error: 'Forbidden' }, 403);
  return await serveObject(env, req, k, { disposition: 'inline', sanitize: true, cacheControl: 'public, max-age=3600' });
}

// ===== 公开相册页 =====
function albumPage(id) {
  const aid = JSON.stringify(id);
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>相册</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f6f8fa;--card:#fff;--border:#d8dee4;--text:#1f2328;--text2:#57606a;--text3:#8c959f;--accent:#0969da;--fill:#f6f8fa;--red:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#2f81f7;--fill:#21262d;--red:#f85149}}
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
</style></head><body>
<div class="hd"><h1 id="ttl">相册</h1><div class="sub" id="sub"></div></div>
<div class="grid" id="grid"></div>
<div class="msg" id="msg" style="display:none"></div>
<div class="lb" id="lb"><span class="x" id="lbx">✕</span><div id="lbbody" style="max-width:100%;max-height:100%;display:flex;align-items:center;justify-content:center"></div></div>
<script>
var ID=${aid};
function esc(s){return String(s==null?'':s).replace(/[&<>"'\`]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\`':'&#96;'}[c]})}
function closeLb(){document.getElementById('lb').classList.remove('show');document.getElementById('lbbody').innerHTML=''}
fetch('/album/'+ID+'/list',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
  if(d.error){document.getElementById('msg').style.display='block';document.getElementById('msg').textContent=d.error;return}
  document.getElementById('ttl').textContent=d.name||'相册';
  document.getElementById('sub').textContent=(d.count||0)+' 项';
  var g=document.getElementById('grid');var h='';
  (d.items||[]).forEach(function(it){
    var isV=String(it.mime||'').indexOf('video/')===0;
    var src='/album/'+ID+'/raw?k='+encodeURIComponent(it.k);
    h+='<div class="it" data-k="'+esc(it.k)+'" data-v="'+(isV?1:0)+'">';
    h+=isV?('<video src="'+src+'" muted preload="metadata"></video>'):('<img loading="lazy" src="'+src+'" alt="">');
    h+='<div class="nm">'+esc(it.name)+'</div></div>';
  });
  g.innerHTML=h;
  g.querySelectorAll('.it').forEach(function(el){
    el.onclick=function(){
      var src='/album/'+ID+'/raw?k='+encodeURIComponent(el.getAttribute('data-k'));
      var isV=el.getAttribute('data-v')==='1';
      document.getElementById('lbbody').innerHTML=isV?('<video src="'+src+'" controls autoplay></video>'):('<img src="'+src+'" alt="">');
      document.getElementById('lb').classList.add('show');
    };
  });
}).catch(function(){document.getElementById('msg').style.display='block';document.getElementById('msg').textContent='加载失败'});
document.getElementById('lbx').onclick=closeLb;
document.getElementById('lb').onclick=function(e){if(e.target===this)closeLb()};
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeLb()});
</script></body></html>`;
}

// ===== PWA：manifest / 图标 / Service Worker =====
function manifestJSON(env) {
  const title = String((env && env.DRIVE_TITLE) || '云端网盘');
  return {
    name: title, short_name: title.slice(0, 12),
    start_url: '/', scope: '/', display: 'standalone',
    background_color: '#0d1117', theme_color: '#0d1117',
    icons: [{ src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }]
  };
}
function iconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="42" fill="#2f81f7"/><path d="M58 130h76a25 25 0 0 0 3-49.8A35 35 0 0 0 66 74a28 28 0 0 0-8 56z" fill="#ffffff"/></svg>';
}
function swJS() {
  return [
    "const C='bluedrift-v1';",
    "self.addEventListener('install',()=>self.skipWaiting());",
    "self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));",
    "self.addEventListener('fetch',e=>{",
    "  const r=e.request;",
    "  if(r.method!=='GET')return;",
    "  const u=new URL(r.url);",
    "  if(u.origin!==location.origin)return;",
    "  if(u.pathname!=='/')return;",
    "  e.respondWith(fetch(r).then(x=>{try{const c=x.clone();caches.open(C).then(k=>k.put('/',c))}catch(_){}return x}).catch(()=>caches.match('/')));",
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

    const dirPath = normPath(data.path);
    if (await isPathLocked(env, dirPath, '')) return json({ locked: true, path: dirPath }, 423);

    const safeName = sanitizeName(file.name);
    const key = dirPath.replace(/^\//, '') + safeName;

    const oldRes = await findDirItem(env, dirPath, safeName);
    const oldItem = oldRes.item;
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
    await upsertDirItem(env, dirPath, entry);
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
  const keys = await listKV(env, 'share:', 500);
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
  const keys = await listKV(env, 'ulink:', 500);
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
  const logs = (await env.STORE.get('meta:dllog', 'json')) || [];
  const agg = (await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 };
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
  const dl = (await env.STORE.get('meta:dlstat', 'json')) || { total: 0, bytes: 0 };
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
  try { await env.STORE.delete('meta:dllog'); } catch (e) {}
  try { await env.STORE.put('meta:dlstat', JSON.stringify({ total: 0, bytes: 0 })); } catch (e) {}
  return json({ ok: true });
}

// ===== Folder Password =====
async function handleSetFolderPass(env, dirPath, password) {
  dirPath = normPath(dirPath);
  if (!password) { await env.STORE.delete('dirpass:' + dirPath); return json({ ok: true, removed: true }); }
  const salt = randToken().substring(0, 16);
  const hash = await hashPassword(password, salt);
  await env.STORE.put('dirpass:' + dirPath, JSON.stringify({ hash, salt }));
  return json({ ok: true });
}

// ===== ZIP =====
function crc32(buf) {
  let table = crc32.table;
  if (!table) { table = crc32.table = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; table[n] = c; } }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}
function buildZip(files) {
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
async function handleZip(env, dirPath, sessionToken) {
  dirPath = normPath(dirPath);
  const prefix = dirPath.replace(/^\//, '');
  const locked = await unlockedPrefixes(env, sessionToken || '');
  const files = [];
  let totalBytes = 0;
  let cursor;
  const MAX_FILES = 200;
  const MAX_BYTES = 25 * 1024 * 1024;
  let hitLimit = false;
  const pending = [];
  do {
    const listed = await env.DRIVE.list({ prefix: prefix, limit: 500, cursor });
    for (const obj of listed.objects) {
      const rel = obj.key.slice(prefix.length);
      if (!rel || rel.startsWith('chunks/') || rel.startsWith('.trash/') || rel.startsWith(THUMB_PREFIX) || rel.startsWith(VERSIONS_PREFIX)) continue;
      // 过滤掉被密码保护的子目录内容
      if (insideLocked('/' + obj.key, locked)) continue;
      if (files.length + pending.length >= MAX_FILES || totalBytes >= MAX_BYTES) { hitLimit = true; break; }
      totalBytes += obj.size;
      pending.push(env.DRIVE.get(obj.key).then(o => o ? o.arrayBuffer().then(buf => ({ name: rel, data: buf })) : null));
      if (pending.length >= 10) {
        const done = await Promise.all(pending.splice(0));
        for (const f of done) if (f) files.push(f);
      }
    }
    if (hitLimit) break;
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  const done = await Promise.all(pending);
  for (const f of done) if (f) files.push(f);
  if (!files.length) return json({ error: 'Empty folder' }, 404);
  if (hitLimit) return json({ error: 'Too large to zip (max 200 files, 25MB)' }, 413);
  const zip = buildZip(files);
  const folderName = dirPath.replace(/\/+$/, '').split('/').pop() || 'files';
  return new Response(zip, { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="' + encodeURIComponent(folderName) + '.zip"' } });
}
// 多选打包下载：把选中的若干个文件打成一个 zip
async function handleZipPaths(env, paths) {
  const list = Array.isArray(paths) ? paths.filter(Boolean) : [];
  if (!list.length) return json({ error: 'No files' }, 400);
  const MAX_FILES = 200, MAX_BYTES = 25 * 1024 * 1024;
  const files = []; let totalBytes = 0, hitLimit = false;
  const used = {};
  for (const p of list) {
    if (files.length >= MAX_FILES || totalBytes >= MAX_BYTES) { hitLimit = true; break; }
    const key = String(p).replace(/^\/+/, '').replace(/\/+$/, '');
    if (!key) continue;
    let obj = null;
    try { obj = await env.DRIVE.get(key); } catch (e) {}
    if (!obj) continue;
    const size = obj.size || 0;
    if (totalBytes + size > MAX_BYTES) { hitLimit = true; break; }
    totalBytes += size;
    let name = key.split('/').pop() || 'file';
    if (used[name]) { used[name]++; name = used[name] + '_' + name; } else used[name] = 1;
    try { files.push({ name, data: await obj.arrayBuffer() }); } catch (e) {}
  }
  if (!files.length) return json({ error: 'Empty' }, 404);
  if (hitLimit) return json({ error: 'Too large to zip (max 200 files, 25MB)' }, 413);
  const zip = buildZip(files);
  return new Response(zip, { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="files.zip"' } });
}

// ===== 远程 URL 抓取（离线下载）：带 SSRF 防护 =====
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
  try {
    const dns = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(h) + '&type=A', { headers: { 'accept': 'application/dns-json' } });
    if (!dns.ok) return false;
    const dj = await dns.json();
    const answers = (dj && dj.Answer) || [];
    for (const a of answers) {
      if (a && a.type === 1 && isBlockedHost(String(a.data))) return true;
    }
  } catch (e) {}
  return false;
}
// 手动跟随重定向，逐跳校验主机（防 SSRF）
async function handleFetchUrl(req, env, b) {
  if (env && env.DISABLE_URL_FETCH === '1') return json({ error: 'URL fetch disabled' }, 403);
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
  try {
    if (key !== idx.key) await putAndMirror(env, key, obj.body, { httpMetadata: obj.httpMetadata });
  } catch (e) { return { hit: false }; }
  await upsertDirItem(env, dir, { name: finalName, type: 'file', size: sz, mime, time: new Date().toISOString(), hash, hasThumb: false });
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
  try {
    const r = await env.STORE.get('meta:autorule', 'json');
    if (r && typeof r === 'object') return { enabled: !!r.enabled, mode: r.mode === 'type' ? 'type' : 'date', base: normPath(r.base || '/') };
  } catch (e) {}
  return { enabled: false, mode: 'date', base: '/' };
}
async function handleGetAutoRule(env) { return json(await getAutoRule(env)); }
async function handleSetAutoRule(env, b) {
  const rule = { enabled: !!(b && b.enabled), mode: (b && b.mode) === 'type' ? 'type' : 'date', base: normPath((b && b.base) || '/') };
  await env.STORE.put('meta:autorule', JSON.stringify(rule));
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

  const parentDir = parentOf(zipPath);
  const zipName = key.split('/').pop();
  const folderName = sanitizeName(zipName.replace(/\.zip$/i, '')) || 'unzipped';
  await ensureDir(env, parentDir, folderName);
  const targetDir = parentDir + folderName + '/';

  let created = 0, totalSize = 0;
  for (const e of parsed.entries) {
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
      await upsertDirItem(env, curDir, { name: fname, type: 'file', size: e.size, mime: '', time: new Date().toISOString() });
      await addUsage(env, e.size, 1);
    }
    created++; totalSize += e.size;
  }
  return json({ ok: true, created, totalSize, dir: targetDir });
}

// ===== Frontend (Apple Style, refined toolbar) =====
function page(env) {
  const brand = {
    title: env.DRIVE_TITLE || '云端网盘',
    logo: env.DRIVE_LOGO || '☁️'
  };
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0d1117">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">
<title>${brand.title}</title>
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

/* ===== 专业深色风（GitHub / Vercel）：去毛玻璃 / 小圆角 / 描边分隔 / 极简工具栏 ===== */
.card,.card.flat,.modal,.login-card,.sidebar,.upitem,.batch-bar,.ctxmenu,.stats-card,
.btn,.btn.gray,.input,.input-group,.search-box,.tag-chip,.note-badge,.hdr-menu{
  backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
body::before{display:none!important}
body{background:var(--sys-bg)}
.card,.usage,.sidebar,.upitem{border:1px solid var(--sys-separator);box-shadow:none}
.card.flat{background:var(--sys-card)}

/* 圆角收敛 */
.card,.card.flat,.modal,.login-card,.usage,.upitem,.ctxmenu,.hdr-menu{border-radius:10px!important}
.brand-logo,.login-logo{border-radius:9px!important}
.btn,.chip,.input,.input-group,.search-box,.sort-group,.sort-btn,.input-addon,.search-box button,
input,select,textarea,.tag-chip,.file-list input[type=checkbox],.gitem input[type=checkbox],.batch-bar{
  border-radius:6px!important}
.gitem,.gthumb,.gicon,.drop-icon{border-radius:8px!important}
.mclose,.pv-nav,.fav-star,.tag-dot{border-radius:50%!important}

/* 按钮：描边式 */
.btn{background:var(--sys-fill);color:var(--sys-text);border:1px solid var(--sys-separator);
  box-shadow:none;font-weight:500;padding:8px 14px}
.btn:hover{background:var(--sys-fill-2);border-color:var(--sys-separator-opaque)}
.btn:active{transform:none}
.btn.primary{background:var(--sys-blue);border-color:var(--sys-blue);color:#fff}
.btn.primary:hover{background:var(--sys-blue-hover);border-color:var(--sys-blue-hover)}
.btn.danger{background:var(--sys-card-solid);border-color:var(--sys-separator);color:var(--sys-red)}
.btn.danger:hover{background:var(--sys-red);border-color:var(--sys-red);color:#fff}
.btn.gray{background:var(--sys-fill);color:var(--sys-text)}
.btn.small{padding:6px 11px;font-size:12.5px}
.btn.tiny{padding:4px 9px;font-size:12px}

/* 输入：描边式 */
.input,input[type=text],input[type=password],input[type=search],select,textarea{
  background:var(--sys-card-solid);border:1px solid var(--sys-separator)}
.input:focus,input:focus,select:focus,textarea:focus{border-color:var(--sys-blue);box-shadow:0 0 0 3px var(--sys-blue-soft)}
.input-group,.search-box{background:var(--sys-card-solid);border:1px solid var(--sys-separator)}
.input-group:focus-within,.search-box:focus-within{border-color:var(--sys-blue);box-shadow:0 0 0 3px var(--sys-blue-soft)}
.input-group input,.search-box input{background:transparent;border:none}
.input-group input:focus,.search-box input:focus{box-shadow:none}
.input-addon,.search-box button{border-left:1px solid var(--sys-separator);background:transparent;color:var(--sys-text-2)}
.input-addon:hover,.search-box button:hover{background:var(--sys-fill);color:var(--sys-blue)}

/* 顶部工具栏：极简三入口 */
.toolbar-card{padding:12px 14px}
.toolbar-row.main{margin-bottom:0;position:relative;gap:8px}
.toolbar-row.main .btn.primary{padding:9px 18px}
.toolbar-row.main #btnMore{margin-left:auto;min-width:40px;font-size:17px;line-height:1;padding:6px 10px}

/* 「⋯」下拉菜单 */
.hdr-menu{position:absolute;top:calc(100% + 8px);right:0;z-index:600;width:274px;max-height:72vh;overflow:auto;
  background:var(--sys-card-solid);border:1px solid var(--sys-separator);box-shadow:var(--sys-shadow-lg);padding:6px;display:none}
.hdr-menu.show{display:block}
.hdr-menu .mgroup{padding:2px 0}
.hdr-menu .mgroup+.mgroup{border-top:1px solid var(--sys-separator);margin-top:4px;padding-top:6px}
.hdr-menu .mlabel{font-size:11px;color:var(--sys-text-3);font-weight:600;padding:5px 10px 4px}
.hdr-menu .chip{display:flex;width:100%;justify-content:flex-start;align-items:center;gap:9px;
  background:transparent;border:1px solid transparent;color:var(--sys-text);
  font-size:13.5px;font-weight:400;padding:6px 10px;text-align:left}
.hdr-menu .chip:hover{background:var(--sys-fill);border-color:transparent}
.hdr-menu .chip.enc-active{background:var(--sys-green);color:#fff}
.btn.active{background:var(--sys-fill-2);border-color:var(--sys-separator-opaque)}

/* 拖拽区 */
#dropZone{margin-top:10px;padding:11px 16px;gap:9px;border:1px dashed var(--sys-separator-opaque);border-radius:8px;background:transparent}
#dropZone .drop-icon{width:26px;height:26px;font-size:13px;background:var(--sys-fill)}
#dropZone:hover,#dropZone.over{border-color:var(--sys-blue);background:var(--sys-blue-soft)}
#dropZone:hover .drop-icon,#dropZone.over .drop-icon{background:var(--sys-blue);color:#fff}

/* 面包屑 + 排序 */
.card.flat .bc{display:flex;align-items:center;gap:14px;justify-content:space-between;
  flex-wrap:wrap;padding:8px 18px;white-space:normal;overflow:visible;font-size:13px}
.card.flat .bc .bc-path{flex:1;min-width:0;overflow-x:auto;white-space:nowrap;scrollbar-width:none}
.card.flat .bc .bc-path::-webkit-scrollbar{display:none}
.card.flat .bc .sort-wrap{flex-shrink:0}
.sort-group{background:var(--sys-fill);border:1px solid var(--sys-separator);padding:2px}
.sort-btn{border:1px solid transparent;color:var(--sys-text-2)}
.sort-btn.active{background:var(--sys-card-solid);border-color:var(--sys-separator);color:var(--sys-text);box-shadow:none}

/* 列表：桌面按表格列对齐 + 列标题 */
.list-head{display:none}
.row-actions{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.file-list li{padding:9px 18px;gap:10px;border-bottom:1px solid var(--sys-separator)}
.file-list li:hover{background:var(--sys-fill)}
.file-list li.selected{background:var(--sys-blue-soft)}
.file-list .fname{font-weight:400}
.file-list .fdate{display:block}
.file-list .fdate,.file-list .fsize{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
@media(min-width:821px){
  .list-head{display:grid;grid-template-columns:22px 24px minmax(120px,1fr) 26px 92px 76px 212px;
    align-items:center;gap:10px;padding:7px 18px;font-size:12px;color:var(--sys-text-3);
    border-bottom:1px solid var(--sys-separator)}
  .list-head .lh-r{text-align:right}
  .file-list li{display:grid;grid-template-columns:22px 24px minmax(120px,1fr) 26px 92px 76px 212px;align-items:center;gap:10px}
  .file-list .fsize,.file-list .fdate{text-align:right}
  .row-actions .btn.extra{display:none}
}

/* 网格 */
.file-grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;padding:16px}
.gitem{background:var(--sys-fill);border:1px solid var(--sys-separator);padding:10px 8px 9px}
.gitem:hover{background:var(--sys-card);border-color:var(--sys-blue);transform:none;box-shadow:none}
.gthumb{height:104px;margin-bottom:9px;border:1px solid var(--sys-separator)}
.gicon{height:104px;line-height:104px;font-size:38px;background:var(--sys-card-solid);border:1px solid var(--sys-separator);margin-bottom:9px}
.gname{font-size:12.5px;line-height:1.4;max-height:2.8em}
.gmeta{display:flex;justify-content:space-between;gap:6px;font-size:11px;color:var(--sys-text-3);
  margin-top:5px;padding:0 4px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.gitem input[type=checkbox]{opacity:0;transition:opacity .15s}
.gitem:hover input[type=checkbox],.gitem.selected input[type=checkbox]{opacity:1}

/* 侧栏：扁平导航 */
.sidebar{width:236px;padding:10px}
.tree-item{padding:6px 9px;font-size:13px}
.tree-item:hover{background:var(--sys-fill)}
.tree-item.active{background:var(--sys-blue-soft);color:var(--sys-blue);font-weight:600}
.tree-item.active .tw{color:var(--sys-blue)}
.tag-filter-item{padding:5px 9px;font-size:12.5px}
.tag-section{border-top:1px solid var(--sys-separator);margin-top:10px;padding-top:10px}

/* 面板与登录 */
.batch-bar{background:var(--sys-blue-soft);border:1px solid var(--sys-blue);padding:9px 13px}
.stats-card{background:var(--sys-fill);border:1px solid var(--sys-separator);border-radius:8px!important}
.hl-pre,.md-body pre,pre{border:1px solid var(--sys-separator);border-radius:8px}
#loginPage{padding:24px}
.login-card{max-width:400px;padding:24px;box-shadow:var(--sys-shadow-lg)}
.login-logo,.brand-logo{box-shadow:none}
.login-card .row{gap:8px;flex-wrap:wrap}
.login-card input{flex:1;min-width:0}
.modal{border:1px solid var(--sys-separator);box-shadow:var(--sys-shadow-lg)}
.modal-bg{background:rgba(1,4,9,.55);backdrop-filter:none;-webkit-backdrop-filter:none}
::-webkit-scrollbar-thumb{background:var(--sys-fill-3);border:3px solid transparent;background-clip:padding-box}

/* 去渐变，统一为纯色强调 */
.brand-logo,.login-logo{background:var(--sys-blue);background-image:none}
.ufill,.upfill{background:var(--sys-blue);background-image:none}
.ubar{background:var(--sys-fill-2)}

/* 筛选条 */
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 18px;border-bottom:1px solid var(--sys-separator);font-size:12px}
.filter-bar .chip-label{font-size:11px;color:var(--sys-text-3);font-weight:600;text-transform:none;letter-spacing:.2px}
.filter-bar .chip-sep{height:18px}
.fchip{padding:4px 10px;border-radius:6px;border:1px solid var(--sys-separator);background:transparent;color:var(--sys-text-2);font-size:12px;cursor:pointer;font-family:inherit;transition:all .15s}
.fchip:hover{background:var(--sys-fill);color:var(--sys-text)}
.fchip.active{background:var(--sys-blue-soft);border-color:var(--sys-blue);color:var(--sys-blue);font-weight:600}

/* 图库视图 */
.file-grid.gallery{grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;padding:16px}
.file-grid.gallery .gitem{padding:6px 6px 8px}
.file-grid.gallery .gthumb{height:158px;object-fit:cover;margin-bottom:8px;background:var(--sys-fill-2);border:none}
.file-grid.gallery .gname{font-size:12.5px}

/* 骨架屏 + 轻动效 */
@keyframes skShim{0%{opacity:.5}50%{opacity:1}100%{opacity:.5}}
@keyframes fadeUp{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.file-list.sk li{display:flex;align-items:center;gap:10px;padding:12px 18px}
.sk{background:var(--sys-fill-2);border-radius:6px;animation:skShim 1.2s ease-in-out infinite}
.sk-ic{width:20px;height:20px;flex:none}
.sk-bar{height:12px}
.file-list li,.gitem{animation:fadeUp .18s ease both}
@media (prefers-reduced-motion: reduce){.sk{animation:none}.file-list li,.gitem{animation:none}}

/* 日志 / 下载明细 增强 */
.log-day{font-size:11px;color:var(--sys-text-3);font-weight:600;margin:12px 0 4px;letter-spacing:.3px}
.log-action{font-weight:500;min-width:66px;font-size:12.5px;flex-shrink:0}
.src-badge{padding:1px 6px;border-radius:4px;background:var(--sys-fill);color:var(--sys-text-3);font-size:11px;flex-shrink:0}
.dl-days{max-height:160px;overflow:auto;margin-bottom:6px;border:1px solid var(--sys-separator);border-radius:8px;padding:4px 10px}
.dl-day{display:flex;justify-content:space-between;padding:4px 2px;font-size:12px;color:var(--sys-text-2);border-bottom:1px solid var(--sys-separator)}
.dl-day:last-child{border-bottom:none}
.dl-day b{color:var(--sys-blue)}
.stats-grid{gap:10px}
.stats-card{padding:12px 8px}
.stats-card .sv{font-size:20px}
.stats-card .sl{font-size:11px}
.ver{font-size:10.5px;color:var(--sys-text-3);font-family:ui-monospace,Menlo,monospace;margin-left:8px;letter-spacing:.2px}
.login-ver{margin-top:16px;margin-left:0}

@media(max-width:820px){
  .toolbar-row.main{flex-wrap:wrap}
  .filter-bar{padding:8px 12px}
  .file-grid.gallery{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}
  .file-grid.gallery .gthumb{height:110px}
  .card.flat .bc{padding:8px 14px}
  .gthumb,.gicon{height:92px;line-height:92px}
}
</style></head><body>
<div class="wrap">
<div id="loginPage">
<div class="login-logo">${brand.logo}</div>
<div class="login-title">${brand.title}</div>
<div class="login-sub">安全 · 私密 · 快速</div>
<div class="login-card">
<div class="row"><input id="pw" type="password" placeholder="输入访问密码" style="flex:1" autocomplete="current-password"><button id="btnLogin" class="btn">登录</button></div>
<div class="login-err" id="loginErr">密码错误，请重试</div>
</div>
<div class="ver login-ver">${APP_VERSION}</div>
</div>
<div id="mainPage">
<div class="page-header">
<div class="brand"><span class="brand-logo">${brand.logo}</span><span class="brand-title">${brand.title}</span></div>
<div class="hdr-right">
<button id="btnTheme" class="btn gray" title="切换主题">🌗</button>
<button id="btnSidebar" class="btn gray sidebar-toggle">☰</button>
<button id="btnLang" class="btn gray">EN</button>
<button id="btnView" class="btn gray">网格</button>
<button id="btnLogout" class="btn gray">退出</button>
</div>
</div>
<div class="layout">
<div class="card sidebar" id="sidebar"><div class="s-title">目录</div><div id="treeBox"></div><div class="tag-section" id="tagSection"><div class="s-title">标签</div><div id="tagBox"></div></div></div>
<div class="main">

<div class="card toolbar-card">
  <div class="toolbar-row main">
    <button id="btnUp" class="btn primary">上传文件</button>
    <div class="input-group">
      <input id="folderInput" placeholder="文件夹名">
      <button id="btnMk" class="input-addon" title="新建文件夹">＋</button>
    </div>
    <div class="search-box">
      <input id="searchInput" placeholder="搜索文件...">
      <button id="btnSearch">搜索</button>
    </div>
    <button id="btnMore" class="btn" title="更多功能" aria-haspopup="true" aria-expanded="false">⋯</button>
    <div class="hdr-menu" id="hdrMenu">
      <div class="mgroup"><div class="mlabel" data-l="browse">浏览</div>
        <button id="btnFav" class="chip">★ 收藏</button>
        <button id="btnRecent" class="chip">🕐 最近</button>
        <button id="btnTag" class="chip">🏷 标签</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="actions">操作</div>
        <button id="btnZip" class="chip">📦 打包当前目录</button>
        <button id="btnShareDir" class="chip">📁 分享当前目录</button>
        <button id="btnFetchUrl" class="chip">⬇ 抓取链接</button>
        <button id="btnAutoRule" class="chip">🗂 自动归档</button>
        <button id="btnULink" class="chip">🔗 传链</button>
        <button id="btnEnc" class="chip">🔐 加密</button>
        <button id="btnComp" class="chip" onclick="window.toggleCompress&&window.toggleCompress(this)">🗜 压缩</button>
        <button id="btnLock" class="chip">🔒 密码</button>
        <button id="btnTrash" class="chip">🗑 回收站</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="data">数据</div>
        <button id="btnStats" class="chip">📊 统计</button>
        <button id="btnLog" class="chip">📋 日志</button>
        <button id="btnDlStats" class="chip">📥 下载明细</button>
        <button id="btnDup" class="chip">📋 重复</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="links">链接</div>
        <button id="btnShareMgmt" class="chip">🔗 分享管理</button>
        <button id="btnULinkMgmt" class="chip">📤 上传链接</button>
      </div>
      <div class="mgroup"><div class="mlabel" data-l="system">系统</div>
        <button id="btnBackends" class="chip">☁️ 存储后端</button>
        <button id="btnWebDAV" class="chip">🌐 WebDAV</button>
        <button id="btnTokens" class="chip">🔑 令牌</button>
        <button id="btnAdminPass" class="chip">🔐 改密码</button>
        <button id="btnClearPend" class="chip">🧹 清除断点记录</button>
        <button id="btnSessions" class="chip">🖥 登录设备</button>
        <button id="btnBackup" class="chip">💾 备份与恢复</button>
        <button id="btnHealth" class="chip">🩺 健康检查</button>
        <button id="btnOrphans" class="chip">🧹 孤儿扫描</button>
        <button id="btnWebhook" class="chip">🔔 通知</button>
        <button id="btnApi" class="chip">⚡ 上传接口</button>
        <button id="btnAlbums" class="chip">🖼 公开相册</button>
      </div>
    </div>
  </div>
  <div id="dropZone">
    <span class="drop-icon">⬇</span>
    <span>拖拽文件 / 文件夹到此处，或点击上传</span>
  </div>
</div>

<div class="uplist" id="upList"></div>
<div class="batch-bar" id="batchBar"><span id="batchCount"></span><button id="batchDel" class="btn danger small">批量删除</button><button id="batchDl" class="btn gray small">批量下载</button><button id="batchZip" class="btn gray small">打包下载</button><button id="batchShare" class="btn gray small">批量分享</button><button id="batchMv" class="btn gray small">移动</button><button id="batchRen" class="btn gray small">重命名</button><button id="batchClr" class="btn gray small">取消</button></div>
<div class="card flat"><div class="bc"><span class="bc-path" id="bcPath"></span><div class="sort-wrap"><span class="sort-label" data-l="sort">排序</span><div class="sort-group"><button class="sort-btn" data-s="name">名称</button><button class="sort-btn" data-s="size">大小</button><button class="sort-btn" data-s="time">日期</button></div></div></div><div class="filter-bar" id="filterBar"><div class="chip-group"><span class="chip-label" data-l="type">类型</span><button class="fchip active" data-ft="">全部</button><button class="fchip" data-ft="image">图片</button><button class="fchip" data-ft="video">视频</button><button class="fchip" data-ft="audio">音频</button><button class="fchip" data-ft="doc">文档</button><button class="fchip" data-ft="zip">压缩包</button><button class="fchip" data-ft="other">其他</button></div><span class="chip-sep"></span><div class="chip-group"><span class="chip-label" data-l="time">时间</span><button class="fchip active" data-fa="">全部</button><button class="fchip" data-fa="today">今天</button><button class="fchip" data-fa="7">7 天</button><button class="fchip" data-fa="30">30 天</button></div></div><div id="fileList"></div></div>
<div class="usage"><div class="ulabel"><span id="uUsed">...</span><span class="ver">${APP_VERSION}</span><span style="display:flex;gap:8px;align-items:center"><span id="uFiles"></span><button id="btnRecalc" class="btn gray tiny" title="重新统计">↻</button></span></div><div class="ubar"><div class="ufill" id="uFill" style="width:0%"></div></div></div>
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
var tk=sessionStorage.getItem('dt')||'',cur='/',viewMode=localStorage.getItem('dv')||'list',sortKey=localStorage.getItem('ds')||'name',sortAsc=true,selected={},searchMode=false,searchResults=[],favMode=false,recentMode=false,filterType='',filterAge='';
var lang=localStorage.getItem('dl')||'zh';
var currentItems=[];
var previewIdx=-1;
var uploadQueue=0;
var CHUNK_SIZE=5*1024*1024;
var T={zh:{upload:'上传',folder:'文件夹名',search:'搜索文件...',go:'搜索',fav:'收藏',recent:'最近',zip:'打包',ulink:'传链',lock:'密码',trash:'回收站',view:'网格',viewList:'列表',logout:'退出',home:'首页',empty:'此文件夹为空',noResult:'无结果',del:'删除',ren:'改名',move:'移动',share:'分享',download:'下载',edit:'编辑',rename:'重命名为:',delete:'确定删除？',batchDel:'批量删除',batchDl:'批量下载',clear:'取消',sort:'排序',drop:'拖拽文件 / 文件夹到此处，或点击上传',trashEmpty:'回收站为空',restore:'恢复',purge:'彻底删除',emptyTrash:'清空回收站',moveTo:'移动到...',save:'保存',saved:'已保存',days:'有效天数:',link:'分享链接（复制）：',used:'已用',files:'个文件',maxAcc:'最大访问次数(0=不限):',maxUp:'最大上传数(0=不限):',setPw:'设置密码(留空取消):',pwSet:'密码已设置',pwRm:'密码已移除',title:'云端网盘',sidebar:'目录',locked:'该文件夹已加密',enterPw:'请输入文件夹密码:',wrongPw:'密码错误',upDone:'完成',upFail:'失败',upLocked:'已锁',sharePw:'分享密码(留空则不设):',unzip:'解压',unzipping:'解压中...',unzipDone:'解压完成',history:'历史版本',restoreV:'恢复此版本',noVers:'无历史版本',confirmRestore:'确定用此版本覆盖当前文件？',daysLeft:'天后过期',batchRestore:'批量恢复',batchPurge:'批量彻底删除',tag:'标签',tags:'标签管理',addTag:'添加标签',tagColor:'颜色',noTags:'暂无标签',dup:'重复',duplicates:'重复文件',noDup:'无重复文件',enc:'加密',encrypt:'加密文件',decrypt:'解密文件',encPw:'加密密码:',encDone:'加密完成',encFail:'加密失败',decDone:'解密完成',note:'备注',noteSaved:'备注已保存',paste:'粘贴上传',shortcuts:'快捷键',renderMd:'渲染',raw:'原文',stats:'统计',log:'日志',tokens:'令牌',webdav:'WebDAV',brRen:'批量重命名',brPattern:'替换规则 (支持 {n} 序号, {d} 日期):',brPreview:'预览',slideshow:'幻灯片',screenshot:'截图',qrCode:'二维码'},en:{upload:'Upload',folder:'Folder',search:'Search...',go:'Go',fav:'Fav',recent:'Recent',zip:'ZIP',ulink:'ULink',lock:'Lock',trash:'Trash',view:'Grid',viewList:'List',logout:'Out',home:'Home',empty:'Empty folder',noResult:'No results',del:'Del',ren:'Ren',move:'Move',share:'Share',download:'Download',edit:'Edit',rename:'Rename:',delete:'Delete?',batchDel:'Del All',batchDl:'Download',clear:'Clear',sort:'Sort',drop:'Drop files or folder here, or click to upload',trashEmpty:'Empty',restore:'Restore',purge:'Del',emptyTrash:'Empty All',moveTo:'Move to...',save:'Save',saved:'Saved',days:'Days:',link:'Link:',used:'Used',files:'files',maxAcc:'Max accesses (0=unlimited):',maxUp:'Max uploads (0=unlimited):',setPw:'Set password (empty to remove):',pwSet:'Password set',pwRm:'Password removed',title:'Cloud Drive',sidebar:'Folders',locked:'Folder is locked',enterPw:'Enter folder password:',wrongPw:'Wrong password',upDone:'Done',upFail:'Fail',upLocked:'Locked',sharePw:'Share password (empty=none):',unzip:'Unzip',unzipping:'Unzipping...',unzipDone:'Unzipped',history:'History',restoreV:'Restore',noVers:'No versions',confirmRestore:'Overwrite current file with this version?',daysLeft:'days left',batchRestore:'Restore All',batchPurge:'Delete All',tag:'Tag',tags:'Tags',addTag:'Add tag',tagColor:'Color',noTags:'No tags',dup:'Dups',duplicates:'Duplicates',noDup:'No duplicates',enc:'Encrypt',encrypt:'Encrypt',decrypt:'Decrypt',encPw:'Password:',encDone:'Encrypted',encFail:'Encrypt failed',decDone:'Decrypted',note:'Note',noteSaved:'Note saved',paste:'Paste upload',shortcuts:'Shortcuts',renderMd:'Render',raw:'Source',stats:'Stats',log:'Log',tokens:'Tokens',webdav:'WebDAV',brRen:'Rename',brPattern:'Pattern ({n}=index, {d}=date):',brPreview:'Preview',slideshow:'Slideshow',screenshot:'Snap',qrCode:'QR'}};
function t(k){return(T[lang]&&T[lang][k])||k}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function show(id){document.getElementById('loginPage').style.display=id==='login'?'flex':'none';document.getElementById('mainPage').style.display=id==='main'?'block':'none'}
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
    else if(filterType==='doc')ok=m.indexOf('text/')===0||m.indexOf('json')>=0||/\.(md|txt|log|csv|docx?|xlsx?|pptx?|pdf)$/.test(n);
    else if(filterType==='zip')ok=m.indexOf('zip')>=0||/\.(zip|rar|7z|tar|gz)$/.test(n);
    else if(filterType==='other')ok=!(m.indexOf('image/')===0||m.indexOf('video/')===0||m.indexOf('audio/')===0||m.indexOf('text/')===0||m.indexOf('json')>=0||/\.(md|txt|log|csv|docx?|xlsx?|pptx?|pdf|zip|rar|7z|tar|gz)$/.test(n));
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
  bcEl.querySelectorAll('a').forEach(function(a){a.onclick=function(){cur=a.getAttribute('data-p');searchMode=false;favMode=false;recentMode=false;load()}});
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
    var CL={zh:{browse:'浏览',actions:'操作',data:'数据',links:'链接',system:'系统',sort:'排序',type:'类型',time:'时间'},en:{browse:'Browse',actions:'Actions',data:'Data',links:'Links',system:'System',sort:'Sort',type:'Type',time:'Time'}};
    document.querySelectorAll('.chip-label[data-l],.mlabel[data-l],.sort-label[data-l]').forEach(function(el){var k=el.getAttribute('data-l');el.textContent=(CL[lang]&&CL[lang][k])||k});
  })();
  document.getElementById('btnDup').textContent='📋 '+(lang==='zh'?'重复':'Dups');
  document.getElementById('btnEnc').textContent='🔐 '+(lang==='zh'?'加密':'Encrypt');
  document.getElementById('btnTrash').textContent='🗑 '+(lang==='zh'?'回收站':'Trash');
  document.getElementById('btnLogout').textContent=t('logout');
  document.querySelectorAll('.sort-btn').forEach(function(b){var k=b.getAttribute('data-s');b.textContent=lang==='zh'?(k==='name'?'名称':k==='size'?'大小':'日期'):(k==='name'?'Name':k==='size'?'Size':'Date');b.classList.toggle('active',k===sortKey)});
  renderTree();
  renderTagSidebar();

  var promise;
  if(tagFilterMode){promise=api('/api/tags?filter='+encodeURIComponent(tagFilterName)).then(function(d){return{items:d.results||[]}})}
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
    if(!searchMode&&!favMode&&!recentMode&&!tagFilterMode&&items.length>500){items=items.slice(0,500);truncated=true;}
    currentItems=items;
    var container=document.getElementById('fileList');
    if(!items.length){container.innerHTML='<p class="empty">'+(searchMode||favMode||recentMode?t('noResult'):((filterType||filterAge)?(lang==='zh'?'没有符合条件的文件':'No matching files'):t('empty')))+'</p>';return}
    var html='';
    if(viewMode==='gallery'){
      var media=items.filter(function(it){return it.type==='file'&&((it.mime||'').indexOf('image/')===0||(it.mime||'').indexOf('video/')===0)});
      if(!media.length){container.innerHTML='<p class="empty">'+(lang==='zh'?'此目录没有图片或视频':'No images or videos here')+'</p>';return}
      html='<div class="file-grid gallery">';
      media.forEach(function(it){
        var gsrc=(it.hasThumb?'/api/thumb?path=':'/api/preview?path=')+encodeURIComponent((it.path||cur)+it.name)+'&token='+tk;
        html+='<div class="gitem" data-n="'+esc(it.name)+'" data-t="file" data-m="'+esc(it.mime||'')+'">';
        html+='<img class="gthumb" loading="lazy" src="'+gsrc+'" alt="">';
        html+='<div class="gname">'+esc(it.name)+'</div>';
        html+='<div class="gmeta"><span>'+fmt(it.size)+'</span><span>'+esc(it.time?new Date(it.time).toLocaleDateString():'')+'</span></div></div>';
      });
      html+='</div>';
    }else if(viewMode==='grid'){
      html='<div class="file-grid">';
      items.forEach(function(it){
        html+='<div class="gitem" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">';
        html+='<input type="checkbox" data-chk="'+esc(it.name)+'" />';
        if(it.type==='file'&&it.hasThumb){
          html+='<img class="gthumb" src="/api/thumb?path='+encodeURIComponent((it.path||cur)+it.name)+'&token='+tk+'" loading="lazy" />';
        }else if(it.type==='file'&&isImage(it)){
          html+='<img class="gthumb" src="/api/preview?path='+encodeURIComponent((it.path||cur)+it.name)+'&token='+tk+'" loading="lazy" />';
        }else{
          html+='<div class="gicon">'+getIcon(it)+'</div>';
        }
        html+='<div class="gname">'+esc(it.name)+'</div>';
        var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
        var gdt=it.time?new Date(it.time).toLocaleDateString():'';
        html+='<div class="gmeta"><span>'+sz+'</span><span>'+esc(gdt)+'</span></div></div>';
      });
      html+='</div>';
    }else{
      html='<div class="list-head"><span></span><span></span><span>'+(lang==='zh'?'名称':'Name')+'</span><span></span><span class="lh-r">'+(lang==='zh'?'大小':'Size')+'</span><span class="lh-r">'+(lang==='zh'?'日期':'Date')+'</span><span></span></div><ul class="file-list">';
      items.forEach(function(it){
        var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
        var dt=it.time?new Date(it.time).toLocaleDateString():'';
        html+='<li data-li="'+esc(it.name)+'" draggable="true" data-drag="'+esc(cur+it.name)+'"><input type="checkbox" data-chk="'+esc(it.name)+'" /><span class="file-icon">'+getIcon(it)+'</span>';
        html+='<span class="fname" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">'+esc(it.name);
        if((searchMode||favMode||recentMode||tagFilterMode)&&it.path)html+='<span class="fpath">'+esc(it.path)+'</span>';
        html+='</span>';
        html+='<button class="fav-star" data-fav="'+esc(it.name)+'">☆</button>';
        html+='<span class="fsize">'+sz+'</span><span class="fdate">'+dt+'</span>';
        html+='<span class="row-actions">';
        html+='<button data-ren="'+esc(it.name)+'" class="btn gray tiny">'+t('ren')+'</button>';
        html+='<button data-mv="'+esc(it.name)+'" class="btn gray tiny">'+t('move')+'</button>';
        if(it.type==='file')html+='<button data-shr="'+esc(it.name)+'" class="btn gray tiny">'+t('share')+'</button>';
        else html+='<button data-shrd="'+esc(it.name)+'" class="btn gray tiny">'+t('share')+'</button>';
        if(it.type==='file'&&isZip(it.name))html+='<button data-unz="'+esc(it.name)+'" class="btn gray tiny extra">'+t('unzip')+'</button>';
        if(it.type==='file'&&isText(it))html+='<button data-ed="'+esc(it.name)+'" class="btn gray tiny extra">'+t('edit')+'</button>';
        if(it.type==='file')html+='<button data-his="'+esc(it.name)+'" class="btn gray tiny extra">'+t('history')+'</button>';
        if(it.type==='file')html+='<button data-tag="'+esc(it.name)+'" class="btn gray tiny extra">🏷</button>';
        if(it.type==='file')html+='<button data-nt="'+esc(it.name)+'" class="btn gray tiny extra">📝</button>';
        html+='<button class="btn tiny danger" data-del="'+esc(it.name)+'">'+t('del')+'</button>';
        html+='</span></li>';
      });
      if(truncated)html+='<li class="list-tip">'+(lang==='zh'?'目录较大，仅显示前 500 项，请使用搜索或筛选定位':'Directory truncated to 500 items, use search/filter to locate')+'</li>';
      html+='</ul>';
    }
    container.innerHTML=html;bindEvents(container);
  });
}


// ===== Tag sidebar =====
var tagFilterMode=false,tagFilterName='';
function renderTagSidebar(){
  api('/api/tags').then(function(d){
    var tags=d.tags||[];
    var box=document.getElementById('tagBox');
    if(!tags.length){box.innerHTML='<div style="color:var(--sys-text-3);font-size:12px;padding:8px 10px">'+t('noTags')+'</div>';return}
    var h='';
    tags.forEach(function(tg){
      var isActive=tagFilterMode&&tagFilterName===tg.name;
      h+='<div class="tag-filter-item'+(isActive?' active':'')+'" data-tf="'+esc(tg.name)+'"><span class="tag-dot" style="background:'+(tg.color||'#0a84ff')+'"></span>'+esc(tg.name)+'</div>';
    });
    box.innerHTML=h;
    box.querySelectorAll('[data-tf]').forEach(function(el){
      el.onclick=function(){
        var n=el.getAttribute('data-tf');
        if(tagFilterMode&&tagFilterName===n){tagFilterMode=false;tagFilterName='';favMode=false;recentMode=false;searchMode=false;load()}
        else{tagFilterMode=true;tagFilterName=n;favMode=false;recentMode=false;searchMode=false;load()}
      };
    });
  }).catch(function(){});
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
        cur=tp;searchMode=false;favMode=false;recentMode=false;load();
      };
    });
  }).catch(function(){});
}
document.getElementById('btnSidebar').onclick=function(){document.getElementById('sidebar').classList.toggle('show')};

function bindEvents(c){
  c.querySelectorAll('[data-drag]').forEach(function(el){el.addEventListener('dragstart',function(e){e.dataTransfer.setData('text/plain',el.getAttribute('data-drag'))})});
  c.querySelectorAll('[data-chk]').forEach(function(cb){cb.onchange=function(){var n=cb.getAttribute('data-chk');if(cb.checked)selected[n]=true;else delete selected[n];updateBatch();var li=cb.closest('li')||cb.closest('.gitem');if(li)li.classList.toggle('selected',cb.checked)}});
  c.querySelectorAll('.fname').forEach(function(el){el.onclick=function(){var n=el.getAttribute('data-n'),tp=el.getAttribute('data-t'),m=el.getAttribute('data-m')||'';if(tp==='dir'){cur=normP(cur)+n+'/';searchMode=false;favMode=false;recentMode=false;load()}else{doPreview(n,m)}}});
  c.querySelectorAll('.gitem').forEach(function(el){el.onclick=function(e){if(e.target.type==='checkbox')return;var n=el.getAttribute('data-n'),tp=el.getAttribute('data-t'),m=el.getAttribute('data-m')||'';if(tp==='dir'){cur=normP(cur)+n+'/';searchMode=false;favMode=false;recentMode=false;load()}else doPreview(n,m)};el.oncontextmenu=function(e){e.preventDefault();showCtx(e.clientX,e.clientY,el.getAttribute('data-n'),el.getAttribute('data-t'),el.getAttribute('data-m')||'')}});
  c.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){if(!confirm(t('delete')))return;api('/api/delete?path='+encodeURIComponent(cur+b.getAttribute('data-del')),{method:'DELETE'}).then(load)}});
  c.querySelectorAll('[data-ren]').forEach(function(b){b.onclick=function(){var o=b.getAttribute('data-ren');var n=prompt(t('rename'),o);if(!n||n===o)return;api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+o,newName:n})}).then(load)}});
  c.querySelectorAll('[data-shr]').forEach(function(b){b.onclick=function(){doShare(b.getAttribute('data-shr'))}});
  c.querySelectorAll('[data-shrd]').forEach(function(b){b.onclick=function(){doShareDir(cur+b.getAttribute('data-shrd')+'/')}});
  c.querySelectorAll('[data-mv]').forEach(function(b){b.onclick=function(){showMove(b.getAttribute('data-mv'))}});
  c.querySelectorAll('[data-ed]').forEach(function(b){b.onclick=function(){editText(b.getAttribute('data-ed'))}});
  c.querySelectorAll('[data-unz]').forEach(function(b){b.onclick=function(){doUnzip(b.getAttribute('data-unz'))}});
  c.querySelectorAll('[data-his]').forEach(function(b){b.onclick=function(){showVersions(b.getAttribute('data-his'))}});
  c.querySelectorAll('[data-tag]').forEach(function(b){b.onclick=function(){doTagFile(b.getAttribute('data-tag'))}});
  c.querySelectorAll('[data-nt]').forEach(function(b){b.onclick=function(){showNote(b.getAttribute('data-nt'))}});
  c.querySelectorAll('[data-fav]').forEach(function(b){b.onclick=function(){var n=b.getAttribute('data-fav');api('/api/fav',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+n})}).then(function(){b.classList.toggle('on')})}});
}

function updateBatch(){var keys=Object.keys(selected);var bar=document.getElementById('batchBar');if(keys.length){bar.classList.add('show');document.getElementById('batchCount').textContent=keys.length+' selected'}else bar.classList.remove('show')}

// ===== Batch Rename =====
document.getElementById('batchRen').onclick=function(){
  var keys=Object.keys(selected);
  if(!keys.length)return;
  var box=document.getElementById('brContent');
  var h='<div style="margin-bottom:12px"><input id="brPattern" value="{n}_{d}" style="width:100%;padding:10px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px" placeholder="'+t('brPattern')+'"></div>';
  h+='<div class="br-preview" id="brPreview">';
  keys.forEach(function(k,i){
    var ext=k.lastIndexOf('.')>=0?k.substring(k.lastIndexOf('.')):'';
    var base=k.lastIndexOf('.')>=0?k.substring(0,k.lastIndexOf('.')):k;
    var newName=(i+1)+'_'+new Date().toISOString().substring(0,10)+ext;
    h+='<div class="br-row"><span class="br-old">'+esc(k)+'</span><span>→</span><span class="br-new">'+esc(newName)+'</span></div>';
  });
  h+='</div><div style="margin-top:12px;text-align:right"><button id="brApply" class="btn small">Apply</button></div>';
  box.innerHTML=h;
  document.getElementById('brModal').classList.add('show');
  document.getElementById('brApply').onclick=function(){
    var pattern=document.getElementById('brPattern').value;
    var paths=keys.map(function(k){return cur+k});
    api('/api/batch-rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:paths,pattern:pattern})}).then(function(r){
      document.getElementById('brModal').classList.remove('show');
      selected={};load();
    });
  };
};
document.getElementById('brClose').onclick=function(){document.getElementById('brModal').classList.remove('show')};
document.getElementById('brModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

document.getElementById('batchClr').onclick=function(){selected={};render()};
document.getElementById('batchDel').onclick=function(){var keys=Object.keys(selected);if(!keys.length||!confirm('Delete '+keys.length+'?'))return;api('/api/batch-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys.map(function(k){return cur+k})})}).then(function(){selected={};load()})};
document.getElementById('batchDl').onclick=function(){Object.keys(selected).forEach(function(n){window.open('/api/download?path='+encodeURIComponent(cur+n)+'&token='+tk,'_blank')})};
document.getElementById('batchZip').onclick=function(){
  var keys=Object.keys(selected);if(!keys.length)return;
  fetch('/api/zip-multi?token='+tk,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys.map(function(k){return cur+k})})})
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
    if(r&&r.url){var u=location.origin+r.url;try{navigator.clipboard.writeText(u)}catch(e){};prompt(t('link'),u)}
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
function doSearch(){var q=document.getElementById('searchInput').value.trim();if(!q){searchMode=false;load();return}api('/api/search?q='+encodeURIComponent(q)+'&path=/').then(function(d){searchMode=true;favMode=false;recentMode=false;searchResults=d.results||[];render()})}
document.getElementById('btnFav').onclick=function(){favMode=!favMode;searchMode=false;recentMode=false;render()};
document.getElementById('btnRecent').onclick=function(){recentMode=!recentMode;searchMode=false;favMode=false;render()};
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

function doShare(name){
  var days=prompt(t('days'),'7');if(!days)return;
  var mx=prompt(t('maxAcc'),'0');if(mx===null)return;
  var pw=prompt(t('sharePw'),'');
  if(pw===null)return;
  api('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name,days:parseInt(days),max:parseInt(mx)||0,password:pw||''})}).then(function(r){
    if(r.url){var u=location.origin+r.url;prompt(t('link'),u);try{navigator.clipboard.writeText(u)}catch(e){};try{showQR(u)}catch(qe){}}
    else if(r.locked){alert(t('locked'))}
    else if(r.error){alert(r.error)}
  });
}

function doUnzip(name){
  if(!confirm(t('unzip')+' '+name+'?'))return;
  api('/api/unzip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name})}).then(function(r){
    if(r.ok){alert(t('unzipDone')+': '+r.created+' files');load()}
    else{alert(r.error||t('upFail'))}
  });
}

function showVersions(name){
  api('/api/versions?path='+encodeURIComponent(cur+name)).then(function(d){
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
        api('/api/versions/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name,ts:parseInt(b.getAttribute('data-ver'))})}).then(function(r){
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
document.getElementById('btnView').onclick=function(){viewMode=viewMode==='list'?'grid':(viewMode==='grid'?'gallery':'list');localStorage.setItem('dv',viewMode);render()};
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
      box.innerHTML+='<div class="mtitle"><span>'+esc(name)+'</span><span style="display:flex;gap:6px"><button class="mdl" id="pvDl">'+t('download')+'</button></span></div>';
      document.getElementById('pvDl').onclick=function(){window.open(src.replace('/api/preview','/api/download'),'_blank')};
    });
  }).catch(function(e){
    box.innerHTML='<div class="pdf-status">PDF preview failed: '+esc(e.message)+'</div>';
  });
}


// ===== Music Playlist =====
function getAudioItems(){
  return currentItems.filter(function(it){return it.type==='file'&&(it.mime||'').indexOf('audio/')===0});
}
var playlistIdx=-1;
function playPlaylist(idx){
  var audios=getAudioItems();
  if(!audios.length)return;
  playlistIdx=idx;
  var it=audios[idx];
  var src='/api/preview?path='+encodeURIComponent(cur+it.name)+'&token='+tk;
  var box=document.getElementById('pvContent');
  var h='<audio controls autoplay src="'+src+'" id="plAudio" style="width:100%"></audio>';
  h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px"><button class="mdl" id="plPrev">⏮ Prev</button><span style="font-size:13px;color:var(--sys-text-2)">'+(idx+1)+' / '+audios.length+'</span><button class="mdl" id="plNext">Next ⏭</button></div>';
  h+='<div class="playlist">';
  audios.forEach(function(a,i){h+='<div class="pl-item'+(i===idx?' active':'')+'" data-pli="'+i+'">'+getIcon(a)+'<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(a.name)+'</span></div>'});
  h+='</div>';
  box.innerHTML=h;
  var audio=document.getElementById('plAudio');
  if(audio)audio.onended=function(){if(playlistIdx<audios.length-1)playPlaylist(playlistIdx+1)};
  var prev=document.getElementById('plPrev');if(prev)prev.onclick=function(){if(playlistIdx>0)playPlaylist(playlistIdx-1)};
  var next=document.getElementById('plNext');if(next)next.onclick=function(){if(playlistIdx<audios.length-1)playPlaylist(playlistIdx+1)};
  box.querySelectorAll('[data-pli]').forEach(function(el){el.onclick=function(){playPlaylist(parseInt(el.getAttribute('data-pli')))}});
  var active=box.querySelector('.pl-item.active');
  if(active)active.scrollIntoView({block:'nearest',behavior:'smooth'});
}


// ===== Image Slideshow + EXIF =====
var slideshowTimer=null;
function startSlideshow(){
  var imgs=currentItems.filter(function(it){return it.type==='file'&&(it.mime||'').indexOf('image/')===0});
  if(!imgs.length)return;
  var idx=0;
  function showNext(){
    var it=imgs[idx];
    var src='/api/preview?path='+encodeURIComponent(cur+it.name)+'&token='+tk;
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

function doPreview(name,mime,idx){
  if(idx===undefined){idx=currentItems.findIndex(function(it){return it.type==='file'&&it.name===name});}
  if(idx<0||idx>=currentItems.length){return}
  previewIdx=idx;
  var it=currentItems[idx];
  if(it.type!=='file'){return}
  name=it.name;mime=it.mime||'';
  var path=encodeURIComponent(cur+name);var src='/api/preview?path='+path+'&token='+tk;var box=document.getElementById('pvContent');var html='';
  if((mime||'').indexOf('image/')===0){html='<img src="'+src+'" /><button class="mdl screenshot-btn" onclick="startSlideshow();closePv()" style="position:absolute;top:14px;left:18px;z-index:20">▶ '+t('slideshow')+'</button>'}
  else if((mime||'').indexOf('video/')===0)html='<video controls autoplay src="'+src+'" id="pvVideo"></video><button class="mdl screenshot-btn" onclick="takeScreenshot()">📷 '+t('screenshot')+'</button>';
  else if((mime||'').indexOf('audio/')===0){playPlaylist(getAudioItems().findIndex(function(a){return a.name===name}));return}
  else if(isPDF(name)){html='<div class="pdf-status">Loading...</div>'}
  else if(isText({mime:mime})){var isMd=name.toLowerCase().endsWith('.md');html='<div id="pvTextWrap"><div style="margin-bottom:8px;display:flex;gap:8px;justify-content:flex-end">'+(isMd?'<button id="pvMdToggle" class="mdl">'+t('renderMd')+'</button>':'')+'</div><pre id="pvT" class="hl-pre">Loading...</pre></div>'}
  else html='<p style="color:var(--sys-text-3);padding:40px;text-align:center">'+t('noResult')+'</p>';
  html+='<div class="mtitle"><span>'+esc(name)+'</span><span style="display:flex;gap:6px"><button class="mdl" id="pvHis">'+t('history')+'</button><button class="mdl" id="pvEdit" style="display:'+(isText({mime:mime})?'inline-block':'none')+'">'+t('edit')+'</button><button class="mdl" id="pvDl">'+t('download')+'</button></span></div>';
  box.innerHTML=html;
  if(isPDF(name)){previewPDF(src,name)}
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
  document.getElementById('pvEdit').onclick=function(){closePv();editText(name)};
  document.getElementById('pvHis').onclick=function(){closePv();showVersions(name)};
  updatePreviewNav();
  api('/api/recent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name})}).catch(function(){});
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
function closePv(){document.getElementById('pvModal').classList.remove('show');previewIdx=-1;document.querySelectorAll('.modal video,.modal audio').forEach(function(el){el.pause();el.removeAttribute('src');el.load()})}
document.addEventListener('keydown',function(e){
  if(!document.getElementById('pvModal').classList.contains('show'))return;
  if(e.key==='ArrowLeft'){previewNav(-1)}
  else if(e.key==='ArrowRight'){previewNav(1)}
  else if(e.key==='Escape'){closePv()}
});

function editText(name){
  var path=encodeURIComponent(cur+name);var src='/api/preview?path='+path+'&token='+tk;
  var box=document.getElementById('pvContent');
  box.innerHTML='<textarea id="edArea" spellcheck="false">Loading...</textarea><div class="mtitle"><span>'+esc(name)+'</span><button class="mdl" id="edSave">'+t('save')+'</button></div>';
  document.getElementById('pvModal').classList.add('show');
  document.getElementById('pvPrev').classList.add('hidden');
  document.getElementById('pvNext').classList.add('hidden');
  document.getElementById('pvCounter').textContent='';
  fetch(src).then(function(r){return r.text()}).then(function(txt){document.getElementById('edArea').value=txt});
  document.getElementById('edSave').onclick=function(){
    var content=document.getElementById('edArea').value;
    fetch('/api/save?path='+path+'&token='+tk,{method:'POST',body:content}).then(function(){closePv();load()});
  };
}

function showMove(name){
  api('/api/search?q=&path=/').then(function(all){
    var dirs=[{path:'/',label:'/ (Root)'}];var seen={'/':true};
    all.results.forEach(function(r){if(r.type==='dir'){var p=r.path+r.name+'/';if(!seen[p]){seen[p]=true;dirs.push({path:p,label:p})}}});
    var box=document.getElementById('mvContent');var h='';
    dirs.forEach(function(d){h+='<div class="mi" data-mp="'+esc(d.path)+'" style="padding:10px 14px;cursor:pointer;border-radius:8px;font-size:14px;color:var(--sys-blue);font-weight:500">'+esc(d.label)+'</div>'});
    box.innerHTML=h;document.getElementById('mvModal').classList.add('show');document.getElementById('mvTitle').textContent=t('moveTo');
    box.querySelectorAll('[data-mp]').forEach(function(el){el.onclick=function(){api('/api/move',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name,target:el.getAttribute('data-mp')})}).then(function(){document.getElementById('mvModal').classList.remove('show');load()})};el.onmouseenter=function(){el.style.background='var(--sys-fill)'};el.onmouseleave=function(){el.style.background=''}});
  });
}
document.getElementById('mvClose').onclick=function(){document.getElementById('mvModal').classList.remove('show')};
document.getElementById('mvModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

function showCtx(x,y,name,type,mime){
  var menu=document.getElementById('ctxMenu');var h='';
  if(type==='file'){
    h+='<div class="mi" data-a="dl">'+t('download')+'</div><div class="mi" data-a="shr">'+t('share')+'</div><div class="mi" data-a="tag">🏷 '+t('tag')+'</div><div class="mi" data-a="note">📝 '+t('note')+'</div><div class="mi" data-a="enc">🔐 '+t('enc')+'</div>';
    h+='<div class="mi" data-a="his">'+t('history')+'</div>';
    if(isZip(name))h+='<div class="mi" data-a="unz">'+t('unzip')+'</div>';
    if(isText({mime:mime}))h+='<div class="mi" data-a="ed">'+t('edit')+'</div>';
  }
  h+='<div class="mi" data-a="ren">'+t('ren')+'</div><div class="mi" data-a="mv">'+t('move')+'</div><div class="mi danger" data-a="del">'+t('del')+'</div>';
  if(type==='dir')h+='<div class="mi" data-a="shrd">📁 '+t('share')+'</div>';
  menu.innerHTML=h;menu.style.left=Math.min(x,window.innerWidth-190)+'px';menu.style.top=Math.min(y,window.innerHeight-260)+'px';menu.classList.add('show');
  menu.onclick=function(e){var a=e.target.getAttribute('data-a');if(!a)return;menu.classList.remove('show');
    if(a==='dl')window.open('/api/download?path='+encodeURIComponent(cur+name)+'&token='+tk,'_blank');
    else if(a==='shr')doShare(name);
    else if(a==='shrd')doShareDir(cur+name+'/');
    else if(a==='his')showVersions(name);
    else if(a==='tag')doTagFile(name);
    else if(a==='note')showNote(name);
    else if(a==='enc')showEncrypt(name);
    else if(a==='unz')doUnzip(name);
    else if(a==='ed')editText(name);
    else if(a==='ren'){var n=prompt(t('rename'),name);if(n&&n!==name)api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+name,newName:n})}).then(load)}
    else if(a==='mv')showMove(name);
    else if(a==='del'){if(confirm(t('delete')))api('/api/delete?path='+encodeURIComponent(cur+name),{method:'DELETE'}).then(load)}
  };
}
document.addEventListener('click',function(){var m=document.getElementById('ctxMenu');if(m)m.classList.remove('show')});


// ===== Tag management =====
document.getElementById('btnTag').onclick=function(){showTagModal()};
document.getElementById('tagClose').onclick=function(){document.getElementById('tagModal').classList.remove('show')};
document.getElementById('tagModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showTagModal(fileName){
  var path=fileName?cur+fileName:'';
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
        h+='<span class="tag-chip" data-tc="'+esc(tg.name)+'"'+(has?' style="outline:2px solid var(--sys-accent)"':'')+'><span class="tag-dot" style="background:'+(tg.color||'#0a84ff')+'"></span>'+esc(tg.name);
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
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName);renderTagSidebar()});
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
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName);renderTagSidebar()});
        };
      });
      box.querySelectorAll('[data-tx]').forEach(function(el){
        el.onclick=function(e){
          e.stopPropagation();
          var tn=el.getAttribute('data-tx');
          var merged=fileTags.filter(function(ft){return ft.name!==tn});
          api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:merged})}).then(function(){showTagModal(fileName);renderTagSidebar()});
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
function doTagFile(name){showTagModal(name)}


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
function showNote(name){
  var path=cur+name;
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
    box.querySelectorAll('[data-rst]').forEach(function(b){b.onclick=function(){api('/api/restore?name='+encodeURIComponent(b.getAttribute('data-rst')),{method:'POST'}).then(function(){showTrash();load()})}});
    box.querySelectorAll('[data-pg]').forEach(function(b){b.onclick=function(){api('/api/purge?name='+encodeURIComponent(b.getAttribute('data-pg')),{method:'DELETE'}).then(showTrash)}});
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
  fetch('/api/login',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(d){
    if(d.token){tk=d.token;sessionStorage.setItem('dt',tk);show('main');load()}
    else document.getElementById('loginErr').style.display='block';
  });
};
document.getElementById('pw').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnLogin').click()};
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
          resolve(new File([blob],file.name,{type:'image/jpeg'}));
        }else{resolve(file)}
      },'image/jpeg',0.85);
    };
    img.onerror=function(){URL.revokeObjectURL(url);resolve(file)};
    img.src=url;
  });
}

function uploadFiles(files){if(!files||!files.length)return;for(var i=0;i<files.length;i++){(function(file){var div=makeUpItem(file.name);uploadQueue++;compressImage(file).then(function(file){return Promise.all([Promise.resolve(file),makeThumb(file)])}).then(function(arr){var file=arr[0],thumb=arr[1];if(file.size>CHUNK_SIZE){uploadChunked(file,div,thumb)}else{uploadSimple(file,div,thumb)}})})(files[i])}}
function makeUpItem(name){var list=document.getElementById('upList');var div=document.createElement('div');div.className='upitem';div.innerHTML='<span class="upname">'+esc(name)+'</span><div class="upbar"><div class="upfill" style="width:0%"></div></div><span class="upst">0%</span>';list.appendChild(div);return div}
function setProgress(div,pct){div.querySelector('.upfill').style.width=pct+'%';div.querySelector('.upst').textContent=pct+'%'}
function setDone(div){div.querySelector('.upfill').style.width='100%';div.querySelector('.upst').textContent=t('upDone');div.querySelector('.upst').style.color='var(--sys-green)';uploadQueue--;setTimeout(function(){if(div.parentNode)div.parentNode.removeChild(div)},1500);if(uploadQueue===0)load()}
function setFail(div,msg){div.querySelector('.upst').textContent=msg||t('upFail');div.querySelector('.upst').style.color='var(--sys-red)';uploadQueue--}
// ===== Upload dedup =====
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
async function uploadSimple(file,div,thumb){
  try{
    var dirItems=await api('/api/list?path='+encodeURIComponent(cur));
    if(dirItems.items&&dirItems.items.some(function(r){return r.name===file.name&&r.size===file.size})){setDone(div);return}
  }catch(e){}
  var hash=await sha256File(file);
  if(hash){
    try{
      var ic=await api('/api/instant-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hash:hash,name:file.name,size:file.size,dir:cur})});
      if(ic&&ic.hit){setDone(div);return}
    }catch(e){}
  }
  var fd=new FormData();fd.append('file',file);
  if(thumb)fd.append('thumb',thumb,'thumb.jpg');
  if(file._relPath)fd.append('relPath',file._relPath);
  if(hash)fd.append('hash',hash);
  var xhr=new XMLHttpRequest();xhr.open('POST','/api/upload?path='+encodeURIComponent(cur)+'&token='+tk);
  xhr.upload.onprogress=function(e){if(e.lengthComputable){setProgress(div,Math.round(e.loaded/e.total*100))}};
  xhr.onload=function(){if(xhr.status>=200&&xhr.status<300){setDone(div)}else if(xhr.status===423){setFail(div,t('upLocked'))}else{setFail(div,t('upFail'))}};
  xhr.onerror=function(){setFail(div,t('upFail'))};
  xhr.send(fd);
}
async function uploadChunked(file,div,thumb){
  var totalChunks=Math.ceil(file.size/CHUNK_SIZE);
  try{
    var hash=await sha256File(file);
    var uploadId=null,got=[];
    var pend=pendFind(file,cur);
    if(pend){
      try{
        var st=await api('/api/chunk-status?id='+encodeURIComponent(pend.uploadId));
        if(st&&st.chunks){uploadId=pend.uploadId;got=st.got||[];}
      }catch(e){}
    }
    if(!uploadId){
      var init=await api('/api/chunk-init',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fileName:file.name,totalSize:file.size,hash:hash,path:cur})});
      if(init.instant){setDone(div);return}
      if(!init.uploadId){setFail(div,t('upFail'));return}
      uploadId=init.uploadId;
      pendAdd({uploadId:uploadId,name:file.name,size:file.size,dir:cur,ts:Date.now()});
    }
    var gotSet={};got.forEach(function(i){gotSet[i]=1});
    var CONC=Math.min(4,totalChunks);
    var next=0,doneCount=got.length,aborted=false;
    setProgress(div,Math.round(doneCount/totalChunks*100));
    async function worker(){
      while(!aborted){
        var i=next++;
        if(i>=totalChunks)return;
        if(gotSet[i])continue;
        var chunk=file.slice(i*CHUNK_SIZE,(i+1)*CHUNK_SIZE);
        var r=await fetch('/api/chunk-upload/'+uploadId+'/'+i+'?token='+tk,{method:'POST',body:chunk});
        if(!r.ok){aborted=true;throw new Error('chunk '+i)}
        doneCount++;setProgress(div,Math.round(doneCount/totalChunks*100));
      }
    }
    var workers=[];for(var w=0;w<CONC;w++)workers.push(worker());
    try{await Promise.all(workers)}catch(e){setFail(div,t('upFail'));return}
    pendRemove(uploadId);
    var done=await api('/api/chunk-complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uploadId:uploadId})});
    if(done&&done.ok){setDone(div)}else{setFail(div,t('upFail'))}
  }catch(e){setFail(div,t('upFail'))}
}

document.getElementById('btnMk').onclick=function(){var n=document.getElementById('folderInput').value.trim();if(!n)return;api('/api/mkdir?path='+encodeURIComponent(cur),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(function(){document.getElementById('folderInput').value='';load()})};
document.getElementById('folderInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnMk').click()};

function load(){render();loadUsage()}
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
  if(files.length){e.preventDefault();uploadFiles(files)}
});


// ===== Keyboard shortcuts =====
document.addEventListener('keydown',function(e){
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
    api('/api/batch-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:Object.keys(selected).map(function(k){return cur+k})})}).then(function(){selected={};load()});
    return;
  }
  if(e.key==='F2'){
    var keys=Object.keys(selected);
    if(keys.length===1){var o=keys[0];var n=prompt(t('rename'),o);if(n&&n!==o)api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+o,newName:n})}).then(load)}
    return;
  }
  if(e.key==='Backspace'&&cur!=='/'){
    e.preventDefault();
    var parts=cur.split('/').filter(Boolean);parts.pop();
    cur=parts.length?'/'+parts.join('/')+'/':'/' ;
    searchMode=false;favMode=false;recentMode=false;load();
    return;
  }
  if((e.ctrlKey||e.metaKey)&&e.key==='f'){
    e.preventDefault();
    document.getElementById('searchInput').focus();
    return;
  }
});


// ===== AES-GCM Client Encryption =====
document.getElementById('btnEnc').onclick=function(){showEncryptPrompt()};
document.getElementById('encClose').onclick=function(){document.getElementById('encModal').classList.remove('show')};
document.getElementById('encModal').onclick=function(e){if(e.target===this)this.classList.remove('show')};
function showEncrypt(name){showEncryptPrompt(name)}
function showEncryptPrompt(name){
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
    var path=cur+name;
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
      newName=name.replace(/\.enc$/,'');
    }
    var fd=new FormData();
    fd.append('file',blob,newName);
    var xhr=new XMLHttpRequest();
    xhr.open('POST','/api/upload?path='+encodeURIComponent(cur)+'&token='+tk);
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
var logFilter='',logCache=[];
function showLog(){
  var box=document.getElementById('logContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('logModal').classList.add('show');
  api('/api/log').then(function(d){logCache=d.logs||[];renderLog()}).catch(function(){
    box.innerHTML='<p style="text-align:center;color:var(--sys-red);padding:16px">'+(lang==='zh'?'加载失败':'Failed')+'</p>';
  });
}
function renderLog(){
  var box=document.getElementById('logContent');
  var ACT={up:{zh:'上传',en:'upload',c:'var(--sys-green)',i:'⬆'},del:{zh:'删除',en:'delete',c:'var(--sys-red)',i:'🗑'},shr:{zh:'分享',en:'share',c:'var(--sys-orange)',i:'🔗'},mov:{zh:'移动',en:'move',c:'var(--sys-blue)',i:'➡'},res:{zh:'恢复',en:'restore',c:'var(--sys-green)',i:'↩'},sec:{zh:'安全',en:'security',c:'var(--sys-red)',i:'🔒'}};
  var counts={};
  logCache.forEach(function(l){counts[l.action]=(counts[l.action]||0)+1});
  var tabs=[['','全部','All'],['up','上传','Upload'],['del','删除','Delete'],['shr','分享','Share'],['mov','移动','Move']];
  var h='<div class="filter-bar" style="border:0;padding:0 0 10px">';
  tabs.forEach(function(x){
    var n=x[0]?counts[x[0]]||0:logCache.length;
    h+='<button class="fchip'+(logFilter===x[0]?' active':'')+'" data-lf="'+x[0]+'">'+(lang==='zh'?x[1]:x[2])+' '+n+'</button>';
  });
  h+='</div>';
  var list=logCache.filter(function(l){return !logFilter||l.action===logFilter});
  if(!list.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'暂无记录':'No logs')+'</p>'}
  else{
    h+='<div style="font-size:12px;color:var(--sys-text-3);margin-bottom:4px">'+list.length+(lang==='zh'?' 条记录':' records')+'</div>';
    h+='<div style="max-height:440px;overflow:auto">';
    var curDay='';
    list.slice(0,200).forEach(function(l){
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
  box.querySelectorAll('[data-lf]').forEach(function(b){b.onclick=function(){logFilter=b.getAttribute('data-lf');renderLog()}});
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
        if(t.exp)h+='<span style="font-size:11px;color:var(--sys-text-3)">'+t.exp+'</span>';
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
        h+='<button class="btn tiny danger" data-shdel="'+esc(s.token)+'">✕</button></div>';
      });
    }
    h+='<div id="shareExtra" style="margin-top:14px;padding-top:12px;border-top:.5px solid var(--sys-separator);font-size:12px;color:var(--sys-text-3)"></div>';
    box.innerHTML=h;
    box.querySelectorAll('[data-shcopy]').forEach(function(b){b.onclick=function(){var u=location.origin+'/s/'+b.getAttribute('data-shcopy');try{navigator.clipboard.writeText(u)}catch(e){}prompt(t('link'),u)}});
    box.querySelectorAll('[data-shdel]').forEach(function(b){b.onclick=function(){if(!confirm(t('delete')))return;api('/api/share',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:b.getAttribute('data-shdel')})}).then(showShareMgmt)}});
    api('/api/public-upload-info').then(function(pi){
      var el=document.getElementById('shareExtra');if(!el)return;
      el.textContent=pi.enabled?('公开上传：'+location.origin+'/upload → '+pi.dir+'（'+(pi.turnstile?'已开启人机验证':'未开启人机验证')+'）'):'公开上传未开启：设置环境变量 PUBLIC_UPLOAD_DIR 后可用 /upload 页面接收文件。';
    }).catch(function(){});
  }).catch(function(){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Error</p>'});
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

// ===== 批量分享 / 批量移动 =====
document.getElementById('batchShare').onclick=function(){
  var keys=Object.keys(selected);if(!keys.length)return;
  var days=prompt(t('days'),'7');if(!days)return;
  var mx=prompt(t('maxAcc'),'0');if(mx===null)return;
  var pw=prompt(t('sharePw'),'');if(pw===null)return;
  api('/api/batch-share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys.map(function(k){return cur+k}),days:parseInt(days),max:parseInt(mx)||0,password:pw||''})}).then(function(r){
    var items=r.items||[];
    var txt=items.map(function(i){return location.origin+i.url}).join('\\n');
    if(txt){try{navigator.clipboard.writeText(txt)}catch(e){}}
    prompt((lang==='zh'?'已创建 ':'Created ')+(r.created||0)+'/'+keys.length,txt||'-');
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
        api('/api/batch-move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:keys.map(function(k){return cur+k}),target:el.getAttribute('data-bmp')})}).then(function(){
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
document.getElementById('btnClearPend').onclick=function(){
  if(!confirm(lang==='zh'?'清除本机未完成的上传记录？':'Clear local upload records?'))return;
  try{localStorage.removeItem('du_pending')}catch(e){}
  alert(lang==='zh'?'已清除':'Cleared');
};

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
    h+='<div style="font-size:12px;color:var(--sys-text-3);line-height:1.75;margin-bottom:10px">'+(lang==='zh'?'快照包含<b>目录树、标签、备注、分享链接、上传链接、文件夹密码、收藏、最近、用量</b>，保存在 R2 的 <code>.backup/</code> 下（不出现在文件列表），最多保留 14 份。开启 Cron 触发器后每日自动备份一次。<br><b style="color:var(--sys-orange)">注意：快照只含元数据，不含文件内容本身</b>（文件已在 R2 里，无需重复备份；若文件被彻底删除，恢复后只能找回目录记录，文件本体无法找回）。':'Snapshots contain metadata only (tree, tags, notes, shares, links, folder passwords, favs, recents, usage) under R2 .backup/, keep 14. Daily auto-backup needs a Cron trigger. <b>File contents are not duplicated.</b>')+'</div>';
    if(!arr.length){h+='<p style="text-align:center;color:var(--sys-text-3);padding:16px">'+(lang==='zh'?'还没有快照，点「立即备份」创建第一份':'No snapshots yet')+'</p>'}
    else{
      h+='<div style="max-height:260px;overflow:auto">';
      arr.forEach(function(b){
        var nm=String(b.key).replace('.backup/','');
        h+='<div class="token-row"><div style="flex:1;min-width:0"><div style="font-size:13px;font-family:ui-monospace,Menlo,monospace">'+esc(nm)+'</div><div class="dup-path">'+fmt(b.size||0)+(b.uploaded?(' · '+esc(fmtWhen(Date.parse(b.uploaded)))):'')+'</div></div>';
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
    h+='<input id="whSecret" type="password" placeholder="'+(lang==='zh'?'签名密钥（可选，会带 X-Signature 头）':'Secret (optional)')+'" value="" style="width:100%;padding:9px 12px;margin-bottom:10px">';
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
      return {enabled:document.getElementById('whOn').checked,url:document.getElementById('whUrl').value.trim(),secret:document.getElementById('whSecret').value,events:evs};
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
    var cur=toks.length?toks[0].id:'YOUR_TOKEN';
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

if(tk){api('/api/list?path=/').then(function(){show('main');load()}).catch(function(){show('login')})}else show('login');
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
    if (!auth.startsWith('Bearer ')) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
    const tok = auth.substring(7).trim();
    const tokens = await getAccessTokens(env);
    const found = tokens.find(t => safeEqual(t.token, tok));
    if (!found) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
    if (found.exp && Date.now() > new Date(found.exp).getTime()) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });

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
      if (isDir) {
        const items = await getDir(env, np);
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
      const u2 = await getUsage(env);
      if ((u2.used || 0) + buf.byteLength > quotaTotal(env)) return new Response('Quota exceeded', { status: 413 });
      await putAndMirror(env, key, buf, { httpMetadata: { contentType } });
      const entry2 = { name: safeName, type: 'file', size: buf.byteLength, mime: contentType, time: new Date().toISOString() };
      await upsertDirItem(env, dirPath, entry2);
      await addUsage(env, buf.byteLength, 1);
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
      }
      return new Response(null, { status: existingDest.item ? 204 : 201 });
    }

    if (method === 'DELETE') {
      const dirPath = parentOf(np);
      const fn = np.split('/').filter(Boolean).pop();
      if (!fn) return new Response('Bad Request', { status: 400 });
      const existing = await findDirItem(env, dirPath, fn);
      if (!existing.item) return new Response('Not Found', { status: 404 });
      await handleDelete(env, np.replace(/^\//, ''));
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
  async fetch(req, env) {
    try {
      const url = new URL(req.url); const p = url.pathname;

      // IP 黑/白名单（可选环境变量，未配置则放行）
      if (!ipAllowed(env, req.headers.get('CF-Connecting-IP') || '')) return json({ error: 'Forbidden' }, 403);

      if (p === '/api/login' && req.method === 'POST') return await handleLogin(req, env);

      // 公开路由（无需登录）
      if (p === '/api/version') return json({ version: APP_VERSION });
      if (p === '/manifest.webmanifest') return new Response(JSON.stringify(manifestJSON(env)), { headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
      if (p === '/icon.svg') return new Response(iconSvg(), { headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } });
      if (p === '/sw.js') return new Response(swJS(), { headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache' } });
      if (p === '/upload' || p === '/upload/') {
        if (!publicUploadDir(env)) return html(errorPage('公开上传未开启'));
        return html(publicUploadPage(env));
      }
      if (p === '/api/public-upload' && req.method === 'POST') return await handlePublicUpload(req, env);

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
        if (sub === 'list') return await handleAlbumList(env, id);
        if (sub === 'raw') return await handleAlbumRaw(env, req, id);
        return json({ error: 'Not found' }, 404);
      }

      if (p.startsWith('/s/')) {
        const rest = p.substring(3);
        const slash = rest.indexOf('/');
        const token = slash < 0 ? rest : rest.substring(0, slash);
        const sub = slash < 0 ? '' : rest.substring(slash + 1);
        if (!token) return html(errorPage('分享链接无效'));
        if (sub === 'data') return await handleShareData(env, token, req);
        if (sub === 'list') return await handleShareList(env, token, req);
        if (sub === 'dl') return await handleShareDownload(env, token, req);
        if (sub === 'pv') return await handleSharePreview(env, token, req);
        let sd = null;
        try { sd = await env.STORE.get('share:' + token, 'json'); } catch (e) {}
        if (sd && sd.type === 'dir') return html(shareDirPage(token));
        return html(sharePage(token));
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
        const auth = await authInfo(env, req);
        if (!auth.ok) return json({ error: 'Unauthorized' }, 401);
        if (auth.perm === 'ro' && req.method !== 'GET' && req.method !== 'HEAD') return json({ error: 'Read-only token' }, 403);
        const requireRw = (auth.perm === 'rw');
        const denyRo = () => json({ error: 'Read-only token' }, 403);
        try {
          if (p === '/api/list') return await handleList(env, url.searchParams.get('path') || '/', url.searchParams.get('size') === '1', url.searchParams.get('token') || '');
          if (p === '/api/unlock' && req.method === 'POST') { const b = await req.json(); return await handleUnlockDir(env, url.searchParams.get('token') || '', b.path, b.password); }
          if (p === '/api/upload' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleUpload(req, env, url.searchParams.get('path') || '/'); }
          if (p === '/api/download') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleDownload(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/preview') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handlePreview(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/thumb') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleThumb(env, req, url.searchParams.get('path') || ''); }
          if (p === '/api/save' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const content = await req.text(); return await handleSaveText(env, url.searchParams.get('path') || '', content); }
          if (p === '/api/delete' && req.method === 'DELETE') { const fp = url.searchParams.get('path') || ''; const np = '/' + String(fp).replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np)); if (g) return g; return await handleDelete(env, fp); }
          if (p === '/api/batch-delete' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const g = await guard(env, req, ...paths, ...paths.map(x => parentOf(x))); if (g) return g; return await handleBatchDelete(env, b.paths); }
          if (p === '/api/batch-rename' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const g = await guard(env, req, ...paths, ...paths.map(x => parentOf(x))); if (g) return g; return await handleBatchRename(env, b.paths, b.pattern); }
          if (p === '/api/batch-share' && req.method === 'POST') { const b = await req.json(); return await handleBatchShare(env, b.paths, b.days, b.max, b.password, url.searchParams.get('token') || ''); }
          if (p === '/api/batch-move' && req.method === 'POST') { const b = await req.json(); const paths = Array.isArray(b.paths) ? b.paths.map(x => '/' + String(x || '').replace(/^\/+/, '')) : []; const parents = paths.map(x => parentOf(x)); const g = await guard(env, req, b.target, ...paths, ...parents); if (g) return g; return await handleBatchMove(env, b.paths, b.target); }
          if (p === '/api/admin-pass' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleAdminPassGet(env); }
          if (p === '/api/admin-pass' && req.method === 'POST') { const b = await req.json(); return await handleAdminPassSet(env, b.current, b.next); }
          if (p === '/api/sessions' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListSessions(env, url.searchParams.get('token') || ''); }
          if (p === '/api/session-revoke' && req.method === 'POST') { const b = await req.json(); return await handleRevokeSession(env, b.id, !!b.all); }
          if (p === '/api/duplicates') return await handleDuplicates(env);
          if (p === '/api/note' && req.method === 'GET') return await handleGetNote(env, url.searchParams.get('path') || '');
          if (p === '/api/note' && req.method === 'POST') { const b = await req.json(); return await handleSetNote(env, b.path, b.note); }
          if (p === '/api/tag' && req.method === 'POST') { const b = await req.json(); return await handleTagFile(env, b.path, b.tags); }
          if (p === '/api/tags' && req.method === 'GET') {
            const f = url.searchParams.get('filter');
            if (f === '__get__') return json({ tags: await getFileTags(env, '/' + String(url.searchParams.get('path') || '').replace(/^\/+/, '')) });
            if (f) return await handleTagFilter(env, f);
            return await handleGetTags(env);
          }
          if (p === '/api/chunk-init' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path || '/'); if (g) return g; return await handleChunkInit(env, b.fileName, b.totalSize, b.hash, b.path || '/'); }
          if (p.startsWith('/api/chunk-upload/') && req.method === 'POST') { const parts = p.split('/'); return await handleChunkUpload(req, env, parts[3], parts[4]); }
          if (p === '/api/chunk-complete' && req.method === 'POST') { const b = await req.json(); return await handleChunkComplete(req, env, b.uploadId); }
          if (p === '/api/chunk-status') return await handleChunkStatus(env, url.searchParams.get('id') || '');
          if (p === '/api/instant-check' && req.method === 'POST') { const b = await req.json(); return await handleInstantCheck(env, b); }
          if (p === '/api/auto-rule' && req.method === 'GET') return await handleGetAutoRule(env);
          if (p === '/api/auto-rule' && req.method === 'POST') { const b = await req.json(); return await handleSetAutoRule(env, b); }
          if (p === '/api/mkdir' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const b = await req.json(); return await handleMkdir(env, url.searchParams.get('path') || '/', b.name); }
          if (p === '/api/rename' && req.method === 'PUT') { const b = await req.json(); const np = '/' + String(b.path || '').replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np)); if (g) return g; return await handleRename(env, b.path, b.newName); }
          if (p === '/api/move' && req.method === 'PUT') { const b = await req.json(); const np = '/' + String(b.path || '').replace(/^\/+/, ''); const g = await guard(env, req, np, parentOf(np), b.target); if (g) return g; return await handleMove(env, b.path, b.target); }
          if (p === '/api/search') return await handleSearch(env, url.searchParams.get('q') || '', url.searchParams.get('path') || '/', url.searchParams.get('token') || '');
          if (p === '/api/tree') return await handleTree(env, url.searchParams.get('token') || '');
          if (p === '/api/zip') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleZip(env, url.searchParams.get('path') || '/', url.searchParams.get('token') || ''); }
          if (p === '/api/unzip' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, parentOf(b.path)); if (g) return g; return await handleUnzip(env, b.path); }
          if (p === '/api/versions' && req.method === 'GET') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return await handleListVersions(env, url.searchParams.get('path') || ''); }
          if (p === '/api/versions/restore' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return await handleRestoreVersion(env, b.path, b.ts); }
          if (p === '/api/share' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return await handleShare(env, b.path, b.days, b.max, b.password, b.dir); }
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
          if (p === '/api/log' && req.method === 'GET') { if (!requireRw) return denyRo(); return json({ logs: await getLogs(env) }); }
          if (p === '/api/dl-stats' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleDlStats(env); }
          if (p === '/api/clear-dl-stats' && req.method === 'POST') return await handleClearDlStats(env);
          if (p === '/api/public-upload-info') return json({ enabled: !!publicUploadDir(env), dir: publicUploadDir(env) || '', max: publicUploadMax(env), turnstile: !!turnstileSecret(env) });
          if (p === '/api/backends' && req.method === 'GET') { if (!requireRw) return denyRo(); return await handleListBackends(env); }
          if (p === '/api/backends/check' && req.method === 'POST') return await handleCheckBackends(env);
          if (p === '/api/tokens' && req.method === 'GET') { if (!requireRw) return denyRo(); return json({ tokens: (await getAccessTokens(env)).map(t => ({ id: t.token.substring(0, 6) + '****', name: t.name, perm: t.perm, exp: t.exp || null })) }); }
          if (p === '/api/tokens' && req.method === 'POST') { const b = await req.json(); const tokens = await getAccessTokens(env); const nt = { name: b.name || 'Token', token: randToken(), perm: b.perm === 'rw' ? 'rw' : 'ro', exp: b.exp || null }; tokens.push(nt); await saveAccessTokens(env, tokens); return json({ ok: true, token: nt.token }); }
          if (p === '/api/tokens' && req.method === 'DELETE') { const b = await req.json(); const id = String(b.id || b.token || ''); const mask = id.replace(/\*+$/, ''); const tokens = (await getAccessTokens(env)).filter(t => t.token !== id && !(mask.length >= 6 && t.token.startsWith(mask))); await saveAccessTokens(env, tokens); return json({ ok: true }); }
          if (p === '/api/stats') { if (!requireRw) return denyRo(); return await handleStatsFull(env); }
          if (p === '/api/stats-trend') return await handleStatsTrend(env, url.searchParams.get('days') || '30');
          if (p === '/api/backup' && req.method === 'POST') return json(await createBackup(env, 'manual'));
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
          if (p === '/api/albums' && req.method === 'POST') { const b = await req.json(); return await handleCreateAlbum(env, b.path, b.name); }
          if (p === '/api/albums' && req.method === 'DELETE') { const b = await req.json(); return await handleDeleteAlbum(env, b.id); }
          if (p === '/api/recent' && req.method === 'GET') return json({ items: await getRecent(env) });
          if (p === '/api/recent' && req.method === 'POST') { const b = await req.json(); await addRecent(env, b.path); return json({ ok: true }); }
          if (p === '/api/favs' && req.method === 'GET') { const favs = await getFavs(env); return json({ items: favs.map(path => ({ name: path.split('/').filter(Boolean).pop() || path, type: 'file', path: parentOf(path), size: 0, mime: '' })) }); }
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
        const trash = await getDir(env, '/.trash/');
        const now = Date.now();
        const keep = [];
        let purged = 0, totalSize = 0;
        for (const item of trash) {
          const deletedTime = item.deletedAt ? new Date(item.deletedAt).getTime() : 0;
          if (!Number.isFinite(deletedTime) || deletedTime <= 0) { keep.push(item); continue; }
          if (now - deletedTime > 30 * 86400 * 1000) {
            const k = item.originalPath.replace(/^\//, '');
            await deleteAndMirror(env, k);
            await deleteThumb(env, k);
            await deleteVersions(env, k);
            totalSize += item.size || 0; purged++;
          } else { keep.push(item); }
        }
        if (purged > 0) { await putDir(env, '/.trash/', keep); await addUsage(env, -totalSize, -purged); }
        // 每日自动快照（当天已有则跳过）
        try {
          const listed = await env.DRIVE.list({ prefix: BACKUP_PREFIX, limit: 200 });
          const objs = listed.objects || [];
          const recent = objs.some(function (o) { return o.uploaded && (Date.now() - new Date(o.uploaded).getTime() < 20 * 3600 * 1000); });
          if (!recent) await createBackup(env, 'auto');
        } catch (e) { console.error('Backup failed:', e); }
      } catch (e) { console.error('Scheduled cleanup failed:', e); }
    })());
  }
};
