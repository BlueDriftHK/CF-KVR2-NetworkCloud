/**
 * Personal Drive v5.1 - R2 + KV + Durable Object
 * UI: Apple / macOS Sonoma style, refined toolbar layout
 * Fix: 分享链接访问次数限制现在覆盖"打开页面"而非仅"下载"
 * Bindings: R2="DRIVE", KV="STORE", DO="DIR"(可选), Env: DRIVE_PASSWORD
 */

const SESSION_TTL = 86400 * 7;
const THUMB_PREFIX = '.thumb/';
const VERSIONS_PREFIX = '.versions/';
const MAX_VERSIONS = 5;
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
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ===== Durable Object: 目录元数据 + 用量统计 =====
export class DirStore {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.name = (state.id && state.id.name) ? state.id.name : '';
  }

  async fetch(req) {
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

    return json({ error: 'Unknown op' }, 404);
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
      if (r && r.ok) return;
    } catch (e) { console.warn('DO putDir → KV:', e && e.message); }
  }
  await env.STORE.put('dir:' + np, JSON.stringify(items));
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
      if (r && r.ok) return await r.json();
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
      if (r && r.ok) return await r.json();
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
      if (r && r.ok) return await r.json();
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
async function searchDir(env, dirPath, query) {
  const results = []; const items = await getDir(env, dirPath); const q = query.toLowerCase();
  for (const it of items) {
    if (q && it.name.toLowerCase().includes(q)) results.push({ ...it, path: dirPath });
    if (!q && it.type === 'dir') results.push({ ...it, path: dirPath });
    if (it.type === 'dir') { const sub = await searchDir(env, dirPath + it.name + '/', query); results.push(...sub); }
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
async function checkAuth(env, req) {
  const t = new URL(req.url).searchParams.get('token') || '';
  if (!t) return false;
  try { const s = await env.STORE.get('session:' + t, 'json'); return s && Date.now() < s.exp; } catch (e) { return false; }
}
async function makeSession(env) { const t = randToken(); await env.STORE.put('session:' + t, JSON.stringify({ exp: Date.now() + SESSION_TTL * 1000 }), { expirationTtl: SESSION_TTL + 60 }); return t; }
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
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
  if (form.get('password') !== env.DRIVE_PASSWORD) {
    try {
      const attempts = JSON.parse(await env.STORE.get('login:' + ip) || '{"n":0,"t":0}');
      attempts.n = Date.now() - attempts.t > 300000 ? 1 : attempts.n + 1;
      attempts.t = Date.now();
      await env.STORE.put('login:' + ip, JSON.stringify(attempts), { expirationTtl: 600 });
    } catch (e) {}
    return json({ error: 'Wrong password' }, 401);
  }
  await env.STORE.delete('login:' + ip);
  return json({ token: await makeSession(env) });
}

async function handleList(env, path, withSize, sessionToken) {
  path = normPath(path);
  const locked = await isPathLocked(env, path, sessionToken);
  if (locked) return json({ locked: true, path });
  const items = await getDir(env, path);
  if (withSize) { for (const it of items) { if (it.type === 'dir') it.dirSize = await calcDirSize(env, path + it.name + '/'); } }
  return json({ path, items });
}

async function handleUnlockDir(env, sessionToken, dirPath, password) {
  dirPath = normPath(dirPath);
  const pass = await env.STORE.get('dirpass:' + dirPath, 'json');
  if (!pass) return json({ ok: true });
  const hash = await sha256(password || '');
  if (hash !== pass.hash) return json({ error: 'Wrong password' }, 403);
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
  const key = uploadDir.replace(/^\//, '') + safeName;

  const oldRes = await findDirItem(env, uploadDir, safeName);
  const oldItem = oldRes.item;
  if (oldItem) await pushVersion(env, key, oldItem);

  const putRes = await env.DRIVE.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
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
    if (oldItem) {
      if (oldItem.hasThumb && !hasThumb) await deleteThumb(env, key);
      await addUsage(env, file.size - (oldItem.size || 0), 0);
    } else {
      await addUsage(env, file.size, 1);
    await addLog(env, 'up', (path || '/') + safeName, file.size + ' bytes');
    }
  } catch (e) {
    try { await env.DRIVE.delete(key); } catch (e2) {}
    await deleteThumb(env, key);
    return json({ error: 'Metadata update failed' }, 500);
  }
  return json({ ok: true, hasThumb, dir: uploadDir });
}

async function handleDownload(env, path) {
  const key = path.replace(/^\/+/, ''); const obj = await env.DRIVE.get(key);
  if (!obj) return json({ error: 'Not found' }, 404);
  return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + encodeURIComponent(key.split('/').pop()) + '"' } });
}

async function handlePreview(env, path) {
  const key = path.replace(/^\/+/, ''); const obj = await env.DRIVE.get(key);
  if (!obj) return json({ error: 'Not found' }, 404);
  return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', 'Content-Disposition': 'inline', 'Cache-Control': 'private, max-age=3600' } });
}

async function handleThumb(env, path) {
  const key = path.replace(/^\/+/, '');
  const obj = await env.DRIVE.get(THUMB_PREFIX + key);
  if (!obj) return json({ error: 'Not found' }, 404);
  return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg', 'Cache-Control': 'private, max-age=86400' } });
}

async function handleSaveText(env, path, content) {
  const key = path.replace(/^\/+/, '');
  const size = new TextEncoder().encode(content).byteLength;
  const dir = parentOf('/' + key);
  const name = key.split('/').pop();

  const oldRes = await findDirItem(env, dir, name);
  if (oldRes.item) await pushVersion(env, key, oldRes.item);

  await env.DRIVE.put(key, content, { httpMetadata: { contentType: 'text/plain' } });

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
    await recursiveDeleteDir(env, path + '/');
    return json({ ok: true });
  }
  await deleteThumb(env, path.replace(/^\//, ''));
  await deleteVersions(env, path.replace(/^\//, ''));
  const trash = await getDir(env, '/.trash/');
  trash.push({ name, type: 'file', size: entry.size || 0, mime: entry.mime || '', originalPath: path, deletedAt: new Date().toISOString(), id: randToken().substring(0, 8) });
  await putDir(env, '/.trash/', trash);
  return json({ ok: true });
}

async function recursiveDeleteDir(env, dirPath) {
  const items = await getDir(env, dirPath);
  const BATCH = 10;
  const fileOps = items.filter(it => it.type === 'file');
  for (let i = 0; i < fileOps.length; i += BATCH) {
    const batch = fileOps.slice(i, i + BATCH);
    await Promise.all(batch.map(async it => {
      const k = dirPath.replace(/^\//, '') + it.name;
      try { await env.DRIVE.delete(k); } catch (e) {}
      await deleteThumb(env, k);
      await deleteVersions(env, k);
    }));
  }
  await addUsage(env, -fileOps.reduce((s, it) => s + (it.size || 0), 0), -fileOps.length);
  for (const it of fileOps) { await addLog(env, 'del', path, ''); }
  const dirOps = items.filter(it => it.type === 'dir');
  for (let i = 0; i < dirOps.length; i += BATCH) {
    const batch = dirOps.slice(i, i + BATCH);
    await Promise.all(batch.map(it => recursiveDeleteDir(env, dirPath + it.name + '/')));
  }
  await destroyDir(env, dirPath);
}

async function handleTrash(env) {
  const items = await getDir(env, '/.trash/');
  const now = Date.now();
  const enriched = items.map(it => {
    const dt = it.deletedAt ? new Date(it.deletedAt).getTime() : now;
    const daysLeft = Math.max(0, 30 - Math.floor((now - dt) / 86400000));
    return { ...it, daysLeft };
  });
  return json({ items: enriched });
}

async function handleRestore(env, id) {
  const trash = await getDir(env, '/.trash/');
  let idx = trash.findIndex(i => i.id === id);
  if (idx < 0) idx = trash.findIndex(i => i.name === id);
  if (idx < 0) return json({ error: 'Not in trash' }, 404);
  const entry = trash[idx]; const dir = parentOf(entry.originalPath);
  const existing = await findDirItem(env, dir, entry.name);
  if (!existing.item) {
    await upsertDirItem(env, dir, { name: entry.name, type: entry.type, size: entry.size, mime: entry.mime, time: entry.deletedAt });
  }
  trash.splice(idx, 1); await putDir(env, '/.trash/', trash); return json({ ok: true });
}

async function handleBatchRestore(env, ids) {
  let ok = 0;
  for (const id of ids) {
    try { await handleRestore(env, id); ok++; } catch (e) {}
  }
  return json({ ok: true, restored: ok });
}

async function handlePurge(env, id) {
  const trash = await getDir(env, '/.trash/');
  if (id === 'ALL') {
    let sz = 0, ct = 0;
    for (const item of trash) {
      const k = item.originalPath.replace(/^\//, '');
      try { await env.DRIVE.delete(k); } catch (e) {}
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
  try { await env.DRIVE.delete(k); } catch (e) {}
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
  await upsertDirItem(env, path, { name, type: 'dir', time: new Date().toISOString() });
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
    if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); }
    await moveThumb(env, oldKey, newKey);
    await moveVersions(env, oldKey, newKey);
    try {
      const tags = await env.STORE.get('tags:/' + oldKey, 'json');
      if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
    } catch (e) {}
  } else {
    await recursiveMoveDir(env, oldPath + '/', dir.replace(/^\//, '') + newName + '/');
  }
  return json({ ok: true });
}

async function recursiveMoveDir(env, oldPrefix, newPrefix) {
  const items = await getDir(env, oldPrefix);
  for (const it of items) {
    if (it.type === 'file') {
      const oldKey = oldPrefix.replace(/^\//, '') + it.name;
      const newKey = newPrefix.replace(/^\//, '') + it.name;
      const obj = await env.DRIVE.get(oldKey);
      if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); }
      await moveThumb(env, oldKey, newKey);
      await moveVersions(env, oldKey, newKey);
      try {
        const tags = await env.STORE.get('tags:/' + oldKey, 'json');
        if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
      } catch (e) {}
    } else if (it.type === 'dir') {
      await recursiveMoveDir(env, oldPrefix + it.name + '/', newPrefix + it.name + '/');
    }
  }
  if (items && items.length) await putDir(env, newPrefix, items);
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
    if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); }
    await moveThumb(env, oldKey, newKey);
    await moveVersions(env, oldKey, newKey);
    try {
      const tags = await env.STORE.get('tags:/' + oldKey, 'json');
      if (tags) { await env.STORE.put('tags:/' + newKey, JSON.stringify(tags)); await env.STORE.delete('tags:/' + oldKey); }
    } catch (e) {}
  } else {
    await recursiveMoveDir(env, srcPath + '/', targetDir.replace(/^\//, '') + name + '/');
  }

  await removeDirItem(env, srcDir, name);
  await upsertDirItem(env, targetDir, entry);
  return json({ ok: true });
}

async function handleBatchDelete(env, paths) { let ok = 0, fail = 0; for (const fp of paths) { try { await handleDelete(env, fp); ok++; } catch (e) { fail++; } } return json({ ok: true, deleted: ok, failed: fail }); }

async function handleBatchRename(env, paths, pattern) {
  let renamed = 0;
  for (let i = 0; i < paths.length; i++) {
    const fp = '/' + paths[i].replace(/^\/+/, '');
    const dir = parentOf(fp); const name = fp.split('/').filter(Boolean).pop();
    let newName = name;
    const dotIdx = name.lastIndexOf('.');
    const base = dotIdx > 0 ? name.substring(0, dotIdx) : name;
    const ext = dotIdx > 0 ? name.substring(dotIdx) : '';
    if (pattern.type === 'prefix') newName = pattern.value + base + ext;
    else if (pattern.type === 'suffix') newName = base + pattern.value + ext;
    else if (pattern.type === 'replace') newName = name.split(pattern.value).join(pattern.replace || '').replace(new RegExp(pattern.value, 'g'), pattern.replace || '');
    else if (pattern.type === 'counter') { const n = (pattern.start || 1) + i; const pad = String(n).padStart(pattern.pad || 2, '0'); newName = (pattern.value || '') + pad + ext; }
    newName = sanitizeName(newName);
    if (newName === name) continue;

    const r = await renameDirItem(env, dir, name, newName);
    if (r.error) continue;
    const entry = r.item;
    if (entry.type === 'file') {
      const oldKey = fp.replace(/^\//, ''); const newKey = dir.replace(/^\//, '') + newName;
      const obj = await env.DRIVE.get(oldKey);
      if (obj) { await env.DRIVE.put(newKey, obj.body, { httpMetadata: obj.httpMetadata }); await env.DRIVE.delete(oldKey); }
      await moveThumb(env, oldKey, newKey);
      await moveVersions(env, oldKey, newKey);
    }
    renamed++;
  }
  return json({ ok: true, renamed });
}

async function handleDuplicates(env) {
  const hashMap = {};
  async function scanDir(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file' && it.hash) {
        if (!hashMap[it.hash]) hashMap[it.hash] = [];
        hashMap[it.hash].push({ name: it.name, path: dirPath, size: it.size });
      } else if (it.type === 'dir') await scanDir(dirPath + it.name + '/');
    }
  }
  await scanDir('/');
  const dupes = Object.entries(hashMap).filter(([h, files]) => files.length > 1);
  return json({ groups: dupes.map(([hash, files]) => ({ hash, count: files.length, size: files[0].size, files })) });
}

// ===== Activity Log =====
async function addLog(env, action, path, detail) {
  try {
    const logs = (await env.STORE.get('meta:log', 'json')) || [];
    logs.unshift({ action, path, detail: detail || '', time: new Date().toISOString() });
    if (logs.length > 200) logs.length = 200;
    await env.STORE.put('meta:log', JSON.stringify(logs));
  } catch (e) {}
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
  const results = [];
  async function scanDir(dirPath) {
    const items = await getDir(env, dirPath);
    for (const it of items) {
      if (it.type === 'file') { const ft = await getFileTags(env, dirPath + it.name); if (ft.find(t => t.name === tagName)) results.push({ ...it, path: dirPath }); }
      else if (it.type === 'dir') await scanDir(dirPath + it.name + '/');
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
  await env.DRIVE.put(key, buf, { httpMetadata: obj.httpMetadata });
  return json({ ok: true });
}

// ===== Chunked Upload =====
async function handleChunkInit(env, fileName, totalSize, hash, dirPath) {
  const uploadId = randToken().substring(0, 16);
  dirPath = normPath(dirPath);
  await env.STORE.put('chunk:' + uploadId, JSON.stringify({ fileName, totalSize, hash, dirPath, chunks: 0, created: Date.now() }), { expirationTtl: 86400 });
  if (hash) {
    const existing = await env.STORE.get('hash:' + hash, 'json');
    if (existing) {
      const key = dirPath.replace(/^\//, '') + sanitizeName(fileName);
      const obj = await env.DRIVE.get(existing.key);
      if (obj) { await env.DRIVE.put(key, obj.body, { httpMetadata: obj.httpMetadata }); return json({ instant: true, key }); }
    }
  }
  return json({ uploadId, chunkSize: 5 * 1024 * 1024 });
}
async function handleChunkUpload(req, env, uploadId, chunkIndex) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Upload not found' }, 404);
  const chunkKey = 'chunks/' + uploadId + '/' + chunkIndex;
  const body = await req.arrayBuffer();
  await env.DRIVE.put(chunkKey, body);
  meta.chunks = Math.max(meta.chunks || 0, parseInt(chunkIndex) + 1);
  await env.STORE.put('chunk:' + uploadId, JSON.stringify(meta), { expirationTtl: 86400 });
  return json({ ok: true, received: meta.chunks });
}
async function handleChunkComplete(env, uploadId) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Upload not found' }, 404);
  const name = sanitizeName(meta.fileName);
  const key = meta.dirPath.replace(/^\//, '') + name;

  const oldRes = await findDirItem(env, meta.dirPath, name);
  const oldItem = oldRes.item;
  if (oldItem) await pushVersion(env, key, oldItem);

  try {
    const multipart = await env.DRIVE.createMultipartUpload(key, { httpMetadata: { contentType: 'application/octet-stream' } });
    const partPromises = [];
    for (let i = 0; i < meta.chunks; i++) {
      partPromises.push(
        env.DRIVE.get('chunks/' + uploadId + '/' + i).then(chunk => {
          if (!chunk) return null;
          return chunk.arrayBuffer().then(buf => multipart.uploadPart(i + 1, buf));
        })
      );
      if (partPromises.length >= 10) { await Promise.all(partPromises); partPromises.length = 0; }
    }
    if (partPromises.length) await Promise.all(partPromises);
    await multipart.complete();
  } catch (e) {
    const parts = [];
    for (let i = 0; i < meta.chunks; i++) {
      const chunk = await env.DRIVE.get('chunks/' + uploadId + '/' + i);
      if (chunk) parts.push(await chunk.arrayBuffer());
    }
    const totalLen = parts.reduce((s, p) => s + p.byteLength, 0);
    if (totalLen > 100 * 1024 * 1024) return json({ error: 'File too large for assembly (max 100MB without multipart)' }, 413);
    const buf = new Uint8Array(totalLen); let offset = 0;
    for (const p of parts) { buf.set(new Uint8Array(p), offset); offset += p.byteLength; }
    await env.DRIVE.put(key, buf, { httpMetadata: { contentType: 'application/octet-stream' } });
  }

  const delPromises = [];
  for (let i = 0; i < meta.chunks; i++) { delPromises.push(env.DRIVE.delete('chunks/' + uploadId + '/' + i).catch(() => {})); }
  await Promise.all(delPromises);
  await env.STORE.delete('chunk:' + uploadId);
  if (meta.hash) await env.STORE.put('hash:' + meta.hash, JSON.stringify({ key, time: Date.now() }));

  const entry = { name, type: 'file', size: meta.totalSize, mime: '', time: new Date().toISOString(), hash: meta.hash || '' };
  await upsertDirItem(env, meta.dirPath, entry);
  if (oldItem) {
    await addUsage(env, meta.totalSize - (oldItem.size || 0), 0);
  } else {
    await addUsage(env, meta.totalSize, 1);
  }
  return json({ ok: true, key });
}
async function handleChunkStatus(env, uploadId) {
  const meta = await env.STORE.get('chunk:' + uploadId, 'json');
  if (!meta) return json({ error: 'Not found' }, 404);
  return json({ chunks: meta.chunks, total: Math.ceil(meta.totalSize / (5 * 1024 * 1024)) });
}

async function handleSearch(env, query, path) { path = normPath(path); return json({ results: await searchDir(env, path, query) }); }

async function handleTree(env) {
  async function buildNode(dirPath, depth) {
    if (depth > 6) return null;
    const items = await getDir(env, dirPath);
    const node = { name: dirPath === '/' ? 'root' : dirPath.split('/').filter(Boolean).pop(), path: dirPath, children: [] };
    const dirs = items.filter(i => i.type === 'dir');
    if (!dirs.length) return node.children.length ? node : { ...node, children: [] };
    for (const d of dirs) {
      const child = await buildNode(dirPath + d.name + '/', depth + 1);
      if (child) node.children.push(child);
    }
    return node;
  }
  const tree = await buildNode('/', 0);
  return json({ tree });
}

// ===== Share（修复：访问计数在 /data 处 +1，/pv 和 /dl 仅检查配额） =====
async function handleShare(env, filePath, days, maxAccesses, password) {
  filePath = '/' + filePath.replace(/^\/+/, '');
  const t = randToken();
  const ttl = (days || 7) * 86400;
  const pwHash = password ? await sha256(password) : '';
  const name = filePath.split('/').filter(Boolean).pop() || 'file';
  const obj = await env.DRIVE.get(filePath.replace(/^\//, ''));
  const size = obj ? obj.size : 0;
  const mime = (obj && obj.httpMetadata && obj.httpMetadata.contentType) || '';
  await env.STORE.put('share:' + t, JSON.stringify({ path: filePath, exp: Date.now() + ttl * 1000, max: maxAccesses || 0, hits: 0, pwHash, name, size, mime }), { expirationTtl: ttl + 60 });
  return json({ ok: true, url: '/s/' + t, hasPassword: !!pwHash });
}

async function handleShareData(env, shareToken) {
  try {
    const data = await env.STORE.get('share:' + shareToken, 'json');
    if (!data) return json({ error: 'Not found' }, 404);
    if (Date.now() > data.exp) return json({ error: 'Expired' }, 410);
    // 打开页面即算一次访问：先检查是否超额，再 hits+1
    if (data.max > 0 && (data.hits || 0) >= data.max) {
      return json({ error: 'Access limit reached', hits: data.hits, max: data.max, name: data.name }, 403);
    }
    data.hits = (data.hits || 0) + 1;
    await env.STORE.put('share:' + shareToken, JSON.stringify(data), {
      expirationTtl: Math.ceil((data.exp - Date.now()) / 1000) + 60
    });
    return json({ name: data.name, size: data.size, mime: data.mime, hasPassword: !!data.pwHash, hits: data.hits, max: data.max || 0 });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}

async function handleSharePreview(env, shareToken, req) {
  try {
    const data = await env.STORE.get('share:' + shareToken, 'json');
    if (!data) return json({ error: 'Not found' }, 404);
    if (Date.now() > data.exp) return json({ error: 'Expired' }, 410);
    // 预览不计数，只检查配额（hits 已在 /data 时 +1，用 > 而非 >=）
    if (data.max > 0 && (data.hits || 0) > data.max) return json({ error: 'Access limit reached' }, 403);
    if (data.pwHash) {
      const pw = new URL(req.url).searchParams.get('pw') || '';
      const h = await sha256(pw);
      if (h !== data.pwHash) return json({ error: 'Wrong password' }, 403);
    }
    const key = data.path.replace(/^\//, ''); const obj = await env.DRIVE.get(key);
    if (!obj) return json({ error: 'Not found' }, 404);
    return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', 'Content-Disposition': 'inline', 'Cache-Control': 'private, max-age=3600' } });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}

async function handleShareDownload(env, shareToken, req) {
  try {
    const data = await env.STORE.get('share:' + shareToken, 'json');
    if (!data) return json({ error: 'Not found' }, 404);
    if (Date.now() > data.exp) { await env.STORE.delete('share:' + shareToken); return json({ error: 'Expired' }, 410); }
    // 下载不计数，只检查配额
    if (data.max > 0 && (data.hits || 0) > data.max) return json({ error: 'Access limit reached' }, 403);
    if (data.pwHash) {
      const pw = new URL(req.url).searchParams.get('pw') || '';
      const h = await sha256(pw);
      if (h !== data.pwHash) return json({ error: 'Wrong password' }, 403);
    }
    const key = data.path.replace(/^\//, ''); const obj = await env.DRIVE.get(key);
    if (!obj) return json({ error: 'Not found' }, 404);
    return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + encodeURIComponent(key.split('/').pop()) + '"' } });
  } catch (e) { return json({ error: 'Invalid' }, 400); }
}

function sharePage(token) {
  const title = '文件分享';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:#f2f2f7;color:#000;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
@media (prefers-color-scheme: dark){body{background:#0a0a0b;color:#fff}}
.card{background:rgba(255,255,255,0.7);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-radius:20px;padding:32px;max-width:560px;width:100%;text-align:center;box-shadow:0 12px 32px rgba(0,0,0,0.1);border:.5px solid rgba(60,60,67,0.13)}
@media (prefers-color-scheme: dark){.card{background:rgba(28,28,30,0.72);border-color:rgba(84,84,88,0.55);box-shadow:0 12px 32px rgba(0,0,0,0.5)}}
h2{font-size:16px;color:#007aff;margin-bottom:6px;font-weight:600}
.meta{font-size:13px;color:rgba(60,60,67,0.6);margin-bottom:20px}
@media (prefers-color-scheme: dark){.meta{color:rgba(235,235,245,0.6)}}
.name{font-size:16px;word-break:break-all;margin-bottom:6px;font-weight:600}
.pv{margin:16px 0;max-height:60vh;overflow:auto;background:rgba(120,120,128,0.1);border-radius:12px;padding:12px}
.pv img,.pv video{max-width:100%;max-height:55vh;border-radius:10px}
.pv audio{width:100%}
.pv pre{text-align:left;font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-all;margin:0;font-family:ui-monospace,Menlo,monospace}
input,button{padding:11px 16px;border-radius:11px;border:none;background:rgba(120,120,128,0.1);color:inherit;font-size:15px;outline:none;font-family:inherit}
input{flex:1;min-width:0}
button{cursor:pointer;background:#007aff;color:#fff;font-weight:600;padding:11px 24px;transition:transform .12s,background .15s}
button:hover{background:#0a84ff}
button:active{transform:scale(0.96)}
.row{display:flex;gap:8px;margin-top:16px}
.msg{font-size:13px;margin-top:12px;min-height:18px}
.err{color:#ff3b30}
.hidden{display:none!important}
</style></head><body>
<div class="card">
<h2>📎 文件分享</h2>
<div class="meta" id="meta">加载中...</div>
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
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function fmt(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(1)+' '+u[i]}
function setMsg(s,isErr){var m=document.getElementById('msg');m.textContent=s||'';m.className='msg'+(isErr?' err':'')}

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
    fname=d.name||'';fmime=d.mime||'';fsize=d.size||0;
    document.getElementById('fname').textContent=fname;
    document.getElementById('meta').textContent=fmt(fsize)+' · '+(d.max>0?('已访问 '+d.hits+'/'+d.max):'');
    if(d.hasPassword){
      document.getElementById('pwRow').classList.remove('hidden');
    }else{
      document.getElementById('dlRow').classList.remove('hidden');
      tryPreview();
    }
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
  fetch('/s/'+tk+'/pv?pw='+encodeURIComponent(pw)).then(function(r){
    if(r.status===403){setMsg('密码错误或访问次数已达上限',true);return}
    if(r.status===410){setMsg('链接已过期',true);return}
    document.getElementById('pwRow').classList.add('hidden');
    document.getElementById('dlRow').classList.remove('hidden');
    tryPreview();
  });
};
document.getElementById('pwInput').onkeydown=function(e){if(e.key==='Enter')document.getElementById('btnPw').click()};
document.getElementById('btnDl').onclick=function(){
  window.location='/s/'+tk+'/dl?pw='+encodeURIComponent(pw);
};
loadData();
</script></body></html>`;
}

// ===== Upload Links =====
async function handleCreateUploadLink(env, dirPath, days, maxFiles) {
  dirPath = normPath(dirPath); const t = randToken(); const ttl = (days || 7) * 86400;
  await env.STORE.put('ulink:' + t, JSON.stringify({ path: dirPath, exp: Date.now() + ttl * 1000, max: maxFiles || 0, count: 0 }), { expirationTtl: ttl + 60 });
  return json({ ok: true, url: '/u/' + t });
}

function uploadPage(token) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件上传</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",system-ui,sans-serif;background:#f2f2f7;color:#000;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
@media (prefers-color-scheme: dark){body{background:#0a0a0b;color:#fff}}
.card{background:rgba(255,255,255,0.7);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-radius:20px;padding:40px;max-width:440px;width:100%;text-align:center;box-shadow:0 12px 32px rgba(0,0,0,0.1);border:.5px solid rgba(60,60,67,0.13)}
@media (prefers-color-scheme: dark){.card{background:rgba(28,28,30,0.72);border-color:rgba(84,84,88,0.55)}}
h2{font-size:20px;color:#007aff;margin-bottom:8px;font-weight:600}
p{font-size:14px;color:rgba(60,60,67,0.6);margin-bottom:28px}
@media (prefers-color-scheme: dark){p{color:rgba(235,235,245,0.6)}}
.zone{border:2px dashed rgba(120,120,128,0.3);border-radius:14px;padding:40px 20px;cursor:pointer;transition:all .2s}
.zone:hover,.zone.over{border-color:#007aff;background:rgba(0,122,255,0.06)}
.zone p{margin:0;font-size:15px;color:rgba(60,60,67,0.7)}
@media (prefers-color-scheme: dark){.zone p{color:rgba(235,235,245,0.7)}}
.list{margin-top:16px;text-align:left;font-size:14px}.list div{padding:8px 0;border-bottom:.5px solid rgba(60,60,67,0.15)}
.ok{color:#007aff}.err{color:#ff3b30}</style></head><body>
<div class="card"><h2>📤 文件上传</h2><p>有人给你分享了一个上传链接</p>
<div class="zone" id="zone"><p>点击或拖拽文件到此处</p></div>
<input type="file" id="fi" multiple style="display:none">
<div class="list" id="list"></div></div>
<script>
var tk='` + token + `';
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

async function handleUploadViaLink(req, env, linkToken) {
  try {
    const data = await env.STORE.get('ulink:' + linkToken, 'json');
    if (!data) return json({ error: 'Link not found' }, 404);
    if (Date.now() > data.exp) { await env.STORE.delete('ulink:' + linkToken); return json({ error: 'Link expired' }, 410); }
    if (data.max > 0 && data.count >= data.max) return json({ error: 'Upload limit reached' }, 403);

    const form = await req.formData(); const file = form.get('file');
    if (!file || typeof file === 'string') return json({ error: 'No file' }, 400);

    const dirPath = normPath(data.path);
    const safeName = sanitizeName(file.name);
    const key = dirPath.replace(/^\//, '') + safeName;
    const putRes = await env.DRIVE.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    const etag = (putRes && putRes.etag) ? String(putRes.etag).replace(/"/g, '') : '';

    const oldRes = await findDirItem(env, dirPath, safeName);
    const entry = { name: safeName, type: 'file', size: file.size, mime: file.type || '', time: new Date().toISOString(), hash: etag };
    await upsertDirItem(env, dirPath, entry);
    if (oldRes.item) { await addUsage(env, file.size - (oldRes.item.size || 0), 0); }
    else { await addUsage(env, file.size, 1); }

    data.count = (data.count || 0) + 1;
    await env.STORE.put('ulink:' + linkToken, JSON.stringify(data), { expirationTtl: Math.ceil((data.exp - Date.now()) / 1000) + 60 });
    return json({ ok: true });
  } catch (e) { return json({ error: 'Failed' }, 500); }
}

// ===== Folder Password =====
async function handleSetFolderPass(env, dirPath, password) {
  dirPath = normPath(dirPath);
  if (!password) { await env.STORE.delete('dirpass:' + dirPath); return json({ ok: true, removed: true }); }
  const hash = await sha256(password);
  await env.STORE.put('dirpass:' + dirPath, JSON.stringify({ hash }));
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
async function handleZip(env, dirPath) {
  dirPath = normPath(dirPath);
  const prefix = dirPath.replace(/^\//, '');
  const files = [];
  let totalBytes = 0;
  let cursor;
  const MAX_FILES = 200;
  const MAX_BYTES = 50 * 1024 * 1024;
  let hitLimit = false;
  const pending = [];
  do {
    const listed = await env.DRIVE.list({ prefix: prefix, limit: 500 });
    for (const obj of listed.objects) {
      const rel = obj.key.slice(prefix.length);
      if (!rel || rel.startsWith('chunks/') || rel.startsWith('.trash/') || rel.startsWith(THUMB_PREFIX) || rel.startsWith(VERSIONS_PREFIX)) continue;
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
  if (hitLimit) return json({ error: 'Too large to zip (max 200 files, 50MB)' }, 413);
  const zip = buildZip(files);
  const folderName = dirPath.replace(/\/+$/, '').split('/').pop() || 'files';
  return new Response(zip, { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="' + encodeURIComponent(folderName) + '.zip"' } });
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
    await env.DRIVE.put(targetKey, e.data, { httpMetadata: { contentType: 'application/octet-stream' } });
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
<meta name="theme-color" content="#0a0a0b">
<title>${brand.title}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js" defer></script>
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
</script>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root, :root.light{
  --sys-bg:#f2f2f7;
  --sys-card:rgba(255,255,255,0.72);
  --sys-card-solid:#ffffff;
  --sys-fill:rgba(120,120,128,0.10);
  --sys-fill-2:rgba(120,120,128,0.18);
  --sys-fill-3:rgba(120,120,128,0.26);
  --sys-text:#000000;
  --sys-text-2:rgba(60,60,67,0.72);
  --sys-text-3:rgba(60,60,67,0.45);
  --sys-blue:#007aff;
  --sys-blue-hover:#0a84ff;
  --sys-blue-soft:rgba(0,122,255,0.10);
  --sys-red:#ff3b30;
  --sys-red-soft:rgba(255,59,48,0.10);
  --sys-green:#34c759;
  --sys-orange:#ff9500;
  --sys-separator:rgba(60,60,67,0.13);
  --sys-separator-opaque:#c6c6c8;
  --sys-shadow-sm:0 1px 2px rgba(0,0,0,0.04), 0 1px 1px rgba(0,0,0,0.03);
  --sys-shadow-md:0 2px 8px rgba(0,0,0,0.06), 0 1px 3px rgba(0,0,0,0.04);
  --sys-shadow-lg:0 12px 32px rgba(0,0,0,0.10), 0 4px 12px rgba(0,0,0,0.06);
  --sys-blur:saturate(180%) blur(24px);
  --bg-grad-1:radial-gradient(900px 500px at 12% -10%, rgba(0,122,255,0.08), transparent 60%);
  --bg-grad-2:radial-gradient(800px 450px at 100% 0%, rgba(175,82,222,0.06), transparent 55%);
}
:root.dark{
  --sys-bg:#0a0a0b;
  --sys-card:rgba(28,28,30,0.72);
  --sys-card-solid:#1c1c1e;
  --sys-fill:rgba(120,120,128,0.18);
  --sys-fill-2:rgba(120,120,128,0.26);
  --sys-fill-3:rgba(120,120,128,0.36);
  --sys-text:#ffffff;
  --sys-text-2:rgba(235,235,245,0.72);
  --sys-text-3:rgba(235,235,245,0.42);
  --sys-blue:#0a84ff;
  --sys-blue-hover:#409cff;
  --sys-blue-soft:rgba(10,132,255,0.18);
  --sys-red:#ff453a;
  --sys-red-soft:rgba(255,69,58,0.18);
  --sys-green:#30d158;
  --sys-orange:#ff9f0a;
  --sys-separator:rgba(84,84,88,0.55);
  --sys-separator-opaque:#38383a;
  --sys-shadow-sm:0 1px 2px rgba(0,0,0,0.5);
  --sys-shadow-md:0 2px 8px rgba(0,0,0,0.4);
  --sys-shadow-lg:0 12px 32px rgba(0,0,0,0.6);
  --bg-grad-1:radial-gradient(900px 500px at 12% -10%, rgba(10,132,255,0.14), transparent 60%);
  --bg-grad-2:radial-gradient(800px 450px at 100% 0%, rgba(175,82,222,0.08), transparent 55%);
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
.gname{font-size:13px;font-weight:500;word-break:break-all;line-height:1.35;max-height:2.7em;overflow:hidden;color:var(--sys-text);padding:0 4px}
.gsize{font-size:11px;color:var(--sys-text-3);margin-top:4px;font-variant-numeric:tabular-nums}
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
  </div>
  <div class="toolbar-row tools">
    <div class="chips">
      <div class="chip-group"><span class="chip-label">浏览</span><button id="btnFav" class="chip">★ 收藏</button><button id="btnRecent" class="chip">🕐 最近</button><button id="btnTag" class="chip">🏷 标签</button></div>
      <span class="chip-sep"></span>
      <div class="chip-group"><span class="chip-label">操作</span><button id="btnZip" class="chip">📦 打包</button><button id="btnULink" class="chip">🔗 传链</button><button id="btnEnc" class="chip">🔐 加密</button><button id="btnComp" class="chip" onclick="window.toggleCompress&&window.toggleCompress(this)">🗜 压缩</button></div>
      <span class="chip-sep"></span>
      <div class="chip-group"><button id="btnLock" class="chip">🔒 密码</button><button id="btnTrash" class="chip">🗑 回收站</button><button id="btnMore" class="chip">⚙ 管理 ▾</button></div>
    </div>
    <div class="admin-row" id="adminRow" style="display:none">
      <button id="btnStats" class="chip small-chip">📊 统计</button><button id="btnLog" class="chip small-chip">📋 日志</button><button id="btnDup" class="chip small-chip">📋 重复</button><button id="btnTokens" class="chip small-chip">🔑 令牌</button><button id="btnWebDAV" class="chip small-chip">🌐 WebDAV</button>
    </div>
    <div class="sort-wrap">
      <span class="sort-label">排序</span>
      <div class="sort-group">
        <button class="sort-btn" data-s="name">名称</button>
        <button class="sort-btn" data-s="size">大小</button>
        <button class="sort-btn" data-s="time">日期</button>
      </div>
    </div>
  </div>
  <div id="dropZone">
    <span class="drop-icon">⬇</span>
    <span>拖拽文件 / 文件夹到此处，或点击上传</span>
  </div>
</div>

<div class="uplist" id="upList"></div>
<div class="batch-bar" id="batchBar"><span id="batchCount"></span><button id="batchDel" class="btn danger small">批量删除</button><button id="batchDl" class="btn gray small">批量下载</button><button id="batchRen" class="btn gray small">重命名</button><button id="batchClr" class="btn gray small">取消</button></div>
<div class="card flat"><div class="bc" id="bc"></div><div id="fileList"></div></div>
<div class="usage"><div class="ulabel"><span id="uUsed">...</span><span style="display:flex;gap:8px;align-items:center"><span id="uFiles"></span><button id="btnRecalc" class="btn gray tiny" title="重新统计">↻</button></span></div><div class="ubar"><div class="ufill" id="uFill" style="width:0%"></div></div></div>
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
<div class="ctxmenu" id="ctxMenu"></div>
<script>
var tk=sessionStorage.getItem('dt')||'',cur='/',viewMode=localStorage.getItem('dv')||'list',sortKey=localStorage.getItem('ds')||'name',sortAsc=true,selected={},searchMode=false,searchResults=[],favMode=false,recentMode=false;
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
function isPreviewable(it){return it.type==='file'&&((it.mime||'').indexOf('image/')===0||(it.mime||'').indexOf('video/')===0||(it.mime||'').indexOf('audio/')===0||isText(it))}
function api(p,o){o=o||{};var s=p.indexOf('?')>=0?'&':'?';return fetch(p+s+'token='+tk,o).then(function(r){if(r.status===401){show('login');throw 0}return r.json()})}

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

function render(){
  selected={};updateBatch();
  var parts=cur.split('/').filter(Boolean);var h='<a data-p="/">'+t('home')+'</a>';var acc='/';
  parts.forEach(function(p){acc+=p+'/';h+=' <span style="opacity:.4">/</span> <a data-p="'+acc+'">'+esc(p)+'</a>'});
  document.getElementById('bc').innerHTML=h;
  document.getElementById('bc').querySelectorAll('a').forEach(function(a){a.onclick=function(){cur=a.getAttribute('data-p');searchMode=false;favMode=false;recentMode=false;load()}});
  document.getElementById('btnView').textContent=viewMode==='grid'?t('view'):t('viewList');
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
  document.getElementById('btnMore').textContent='⚙ '+(lang==='zh'?'管理':'Admin')+' ▾';
  document.querySelectorAll('.chip-label').forEach(function(el){
    var zh=['浏览','操作'];var en=['Browse','Actions'];
    var idx=Array.prototype.indexOf.call(document.querySelectorAll('.chip-label'),el);
    if(idx>=0)el.textContent=lang==='zh'?zh[idx]:en[idx];
  });
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

  promise.then(function(d){
    if(d&&d.locked){
      document.getElementById('fileList').innerHTML='<p class="empty">🔒 '+t('locked')+'</p>';
      var pw=prompt(t('enterPw'));
      if(pw===null||pw==='')return;
      api('/api/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:d.path,password:pw})}).then(function(r){
        if(r&&r.ok){load()}else{alert(t('wrongPw'))}
      });
      return;
    }
    var items=sortItems((d.items||[]).slice());
    currentItems=items;
    var container=document.getElementById('fileList');
    if(!items.length){container.innerHTML='<p class="empty">'+(searchMode||favMode||recentMode?t('noResult'):t('empty'))+'</p>';return}
    var html='';
    if(viewMode==='grid'){
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
        html+='<div class="gsize">'+sz+'</div></div>';
      });
      html+='</div>';
    }else{
      html='<ul class="file-list">';
      items.forEach(function(it){
        var sz=it.type==='dir'?fmt(it.dirSize||0):fmt(it.size);
        var dt=it.time?new Date(it.time).toLocaleDateString():'';
        html+='<li data-li="'+esc(it.name)+'" draggable="true" data-drag="'+esc(cur+it.name)+'"><input type="checkbox" data-chk="'+esc(it.name)+'" /><span class="file-icon">'+getIcon(it)+'</span>';
        html+='<span class="fname" data-n="'+esc(it.name)+'" data-t="'+it.type+'" data-m="'+esc(it.mime||'')+'">'+esc(it.name)+'</span>';
        if((searchMode||favMode||recentMode||tagFilterMode)&&it.path)html+='<span class="fpath">'+esc(it.path)+'</span>';
        html+='<button class="fav-star" data-fav="'+esc(it.name)+'">☆</button>';
        html+='<span class="fdate">'+dt+'</span><span class="fsize">'+sz+'</span>';
        html+='<button data-ren="'+esc(it.name)+'" class="btn gray tiny">'+t('ren')+'</button>';
        html+='<button data-mv="'+esc(it.name)+'" class="btn gray tiny">'+t('move')+'</button>';
        if(it.type==='file')html+='<button data-shr="'+esc(it.name)+'" class="btn gray tiny">'+t('share')+'</button>';
        if(it.type==='file'&&isZip(it.name))html+='<button data-unz="'+esc(it.name)+'" class="btn gray tiny">'+t('unzip')+'</button>';
        if(it.type==='file'&&isText(it))html+='<button data-ed="'+esc(it.name)+'" class="btn gray tiny">'+t('edit')+'</button>';
        if(it.type==='file')html+='<button data-his="'+esc(it.name)+'" class="btn gray tiny">'+t('history')+'</button>';
        if(it.type==='file')html+='<button data-tag="'+esc(it.name)+'" class="btn gray tiny">🏷</button>';
        if(it.type==='file')html+='<button data-nt="'+esc(it.name)+'" class="btn gray tiny">📝</button>';
        html+='<button class="btn tiny danger" data-del="'+esc(it.name)+'">'+t('del')+'</button></li>';
      });
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
  var div=document.createElement('div');
  div.className='qr-box';
  div.id='qrBox';
  box.appendChild(div);
  try{
    if(typeof QRCode!=='undefined'){
      new QRCode(div,{text:url,width:180,height:180,correctLevel:QRCode.CorrectLevel.M});
    }else{div.textContent='QR library not loaded'}
  }catch(e){div.textContent='QR generation failed'}
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
document.getElementById('btnView').onclick=function(){viewMode=viewMode==='grid'?'list':'grid';localStorage.setItem('dv',viewMode);render()};


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
  // Scroll active into view
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
          var rendered=marked.parse(txt);
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
  menu.innerHTML=h;menu.style.left=Math.min(x,window.innerWidth-190)+'px';menu.style.top=Math.min(y,window.innerHeight-260)+'px';menu.classList.add('show');
  menu.onclick=function(e){var a=e.target.getAttribute('data-a');if(!a)return;menu.classList.remove('show');
    if(a==='dl')window.open('/api/download?path='+encodeURIComponent(cur+name)+'&token='+tk,'_blank');
    else if(a==='shr')doShare(name);
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
    var h='';
    if(fileName){
      title.textContent=t('tags')+' · '+fileName;
      api('/api/tags?filter=__get__&path='+encodeURIComponent(path)).then(function(ft){
        fileTags=ft.tags||[];
      }).catch(function(){});
    }else{
      title.textContent=t('tags');
    }
    h+='<div style="margin-bottom:14px"><div style="font-size:13px;color:var(--sys-text-2);margin-bottom:8px">'+t('addTag')+'</div>';
    h+='<div style="display:flex;gap:8px"><input id="newTagInput" placeholder="Tag name" style="flex:1;padding:8px 12px;border-radius:8px;border:none;background:var(--sys-fill);color:var(--sys-text);font-size:14px">';
    h+='<input id="newTagColor" type="color" value="#0a84ff" style="width:36px;height:36px;border:none;border-radius:8px;cursor:pointer">';
    h+='<button id="addTagBtn" class="btn small">+</button></div></div>';
    h+='<div style="font-size:13px;color:var(--sys-text-2);margin-bottom:8px">All tags:</div>';
    h+='<div style="display:flex;flex-wrap:wrap;gap:6px">';
    allTags.forEach(function(tg){
      h+='<span class="tag-chip" data-tc="'+esc(tg.name)+'"><span class="tag-dot" style="background:'+(tg.color||'#0a84ff')+'"></span>'+esc(tg.name);
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
      var tags=[{name:name,color:color}];
      if(fileName){
        api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:tags})}).then(function(){showTagModal(fileName);renderTagSidebar()});
      }else{
        api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:'/.tag-register/',tags:tags})}).then(function(){showTagModal();renderTagSidebar()});
      }
    };
    box.querySelectorAll('[data-tc]').forEach(function(el){
      el.onclick=function(){
        if(!fileName)return;
        var tn=el.getAttribute('data-tc');
        api('/api/tag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,tags:[{name:tn,color:el.querySelector('.tag-dot').style.background||'#0a84ff'}]})}).then(function(){showTagModal(fileName)});
      };
    });
    box.querySelectorAll('[data-tx]').forEach(function(el){
      el.onclick=function(e){e.stopPropagation()};
    });
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

document.getElementById('btnMore').onclick=function(){
  var row=document.getElementById('adminRow');
  var show=row.style.display==='none';
  row.style.display=show?'flex':'none';
  this.textContent='⚙ '+(lang==='zh'?'管理':'Admin')+' '+(show?'▴':'▾');
};
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

document.getElementById('btnLogin').onclick=function(){var fd=new FormData();fd.append('password',document.getElementById('pw').value);fetch('/api/login',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(d){if(d.token){tk=d.token;sessionStorage.setItem('dt',tk);show('main');load()}else document.getElementById('loginErr').style.display='block'})};
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
async function uploadSimple(file,div,thumb){
  // Dedup check: skip if same name+size exists in current dir
  try{
    var dirItems=await api('/api/list?path='+encodeURIComponent(cur));
    if(dirItems.items&&dirItems.items.some(function(r){return r.name===file.name&&r.size===file.size})){setDone(div);return}
  }catch(e){}
  var fd=new FormData();fd.append('file',file);
  if(thumb)fd.append('thumb',thumb,'thumb.jpg');
  if(file._relPath)fd.append('relPath',file._relPath);
  var xhr=new XMLHttpRequest();xhr.open('POST','/api/upload?path='+encodeURIComponent(cur)+'&token='+tk);
  xhr.upload.onprogress=function(e){if(e.lengthComputable){setProgress(div,Math.round(e.loaded/e.total*100))}};
  xhr.onload=function(){if(xhr.status>=200&&xhr.status<300){setDone(div)}else if(xhr.status===423){setFail(div,t('upLocked'))}else{setFail(div,t('upFail'))}};
  xhr.onerror=function(){setFail(div,t('upFail'))};
  xhr.send(fd);
}
async function uploadChunked(file,div,thumb){
  var totalChunks=Math.ceil(file.size/CHUNK_SIZE);
  try{
    var init=await api('/api/chunk-init',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fileName:file.name,totalSize:file.size,hash:'',path:cur})});
    if(init.instant){setDone(div);return}
    if(!init.uploadId){setFail(div,t('upFail'));return}
    var uploadId=init.uploadId;
    for(var i=0;i<totalChunks;i++){
      var chunk=file.slice(i*CHUNK_SIZE,(i+1)*CHUNK_SIZE);
      var r=await fetch('/api/chunk-upload/'+uploadId+'/'+i+'?token='+tk,{method:'POST',body:chunk});
      if(!r.ok){setFail(div,t('upFail'));return}
      setProgress(div,Math.round((i+1)/totalChunks*100));
    }
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
  // Ctrl+A: select all
  if((e.ctrlKey||e.metaKey)&&e.key==='a'){
    e.preventDefault();
    var cbs=document.querySelectorAll('[data-chk]');
    var allChecked=true;
    cbs.forEach(function(cb){if(!cb.checked)allChecked=false});
    cbs.forEach(function(cb){cb.checked=!allChecked;cb.dispatchEvent(new Event('change'))});
    return;
  }
  // Delete: delete selected
  if(e.key==='Delete'&&Object.keys(selected).length){
    if(!confirm('Delete '+Object.keys(selected).length+'?'))return;
    api('/api/batch-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths:Object.keys(selected).map(function(k){return cur+k})})}).then(function(){selected={};load()});
    return;
  }
  // F2: rename first selected
  if(e.key==='F2'){
    var keys=Object.keys(selected);
    if(keys.length===1){var o=keys[0];var n=prompt(t('rename'),o);if(n&&n!==o)api('/api/rename',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:cur+o,newName:n})}).then(load)}
    return;
  }
  // Backspace: go up
  if(e.key==='Backspace'&&cur!=='/'){
    e.preventDefault();
    var parts=cur.split('/').filter(Boolean);parts.pop();
    cur=parts.length?'/'+parts.join('/')+'/':'/' ;
    searchMode=false;favMode=false;recentMode=false;load();
    return;
  }
  // Ctrl+F: focus search
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
    var h='<div class="stats-grid">';
    h+='<div class="stats-card"><div class="sv">'+fmt(u.used||0)+'</div><div class="sl">'+t('used')+'</div></div>';
    h+='<div class="stats-card"><div class="sv">'+(u.files||0)+'</div><div class="sl">'+t('files')+'</div></div>';
    h+='<div class="stats-card"><div class="sv">'+(d.logCount||0)+'</div><div class="sl">'+(lang==='zh'?'操作记录':'Actions')+'</div></div>';
    h+='<div class="stats-card"><div class="sv">'+fmt(Math.max(0,(u.total||10*1024*1024*1024)-(u.used||0)))+'</div><div class="sl">'+(lang==='zh'?'剩余':'Free')+'</div></div>';
    h+='</div>';
    h+='<canvas id="statsChart" style="max-height:200px;margin-top:8px"></canvas>';
    box.innerHTML=h;
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
function showLog(){
  var box=document.getElementById('logContent');
  box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">Loading...</p>';
  document.getElementById('logModal').classList.add('show');
  api('/api/log').then(function(d){
    var logs=d.logs||[];
    if(!logs.length){box.innerHTML='<p style="text-align:center;color:var(--sys-text-3);padding:20px">'+(lang==='zh'?'暂无记录':'No logs')+'</p>';return}
    var h='';
    logs.slice(0,100).forEach(function(l){
      var dt=new Date(l.time);
      var ts=('0'+(dt.getMonth()+1)).slice(-2)+'/'+('0'+dt.getDate()).slice(-2)+' '+('0'+dt.getHours()).slice(-2)+':'+('0'+dt.getMinutes()).slice(-2);
      var cls=l.action==='up'?'up':l.action==='del'?'del':l.action==='shr'?'shr':'';
      h+='<div class="log-entry"><span class="log-time">'+ts+'</span><span class="log-action '+cls+'">'+l.action+'</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(l.path)+'</span></div>';
    });
    box.innerHTML=h;
  });
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
        h+='<button class="btn tiny danger" data-tkdel="'+esc(t.token||'')+'">✕</button></div>';
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
        api('/api/tokens',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:b.getAttribute('data-tkdel')})}).then(showTokens);
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

if(tk){api('/api/list?path=/').then(function(){show('main');load()}).catch(function(){show('login')})}else show('login');
</script></body></html>`;
}


// ===== WebDAV Protocol =====
async function handleWebDAV(req, env) {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  const davPath = decodeURIComponent(url.pathname.replace(/^\/dav/, '') || '/');
  const np = normPath(davPath);

  // Auth check via Authorization header
  const auth = req.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    const tok = auth.substring(7);
    const tokens = await getAccessTokens(env);
    const found = tokens.find(t => t.token === tok);
    if (!found) return new Response('Unauthorized', { status: 401 });
  } else {
    return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
  }

  const davHeaders = { 'DAV': '1,2', 'Content-Type': 'application/xml; charset=utf-8' };

  if (method === 'OPTIONS') {
    return new Response('', { status: 200, headers: { 'DAV': '1,2', 'Allow': 'OPTIONS,GET,PUT,DELETE,MKCOL,PROPFIND' } });
  }

  if (method === 'PROPFIND') {
    const isDir = np.endsWith('/');
    if (isDir) {
      const items = await getDir(env, np);
      let xml = '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
      xml += '<D:response><D:href>' + np + '</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>' + (np === '/' ? 'Root' : np.split('/').filter(Boolean).pop()) + '</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
      for (const item of items) {
        const href = np + item.name + (item.type === 'dir' ? '/' : '');
        xml += '<D:response><D:href>' + escHtml(href) + '</D:href><D:propstat><D:prop>';
        if (item.type === 'dir') xml += '<D:resourcetype><D:collection/></D:resourcetype>';
        else { xml += '<D:resourcetype/><D:getcontentlength>' + (item.size || 0) + '</D:getcontentlength><D:getcontenttype>' + (item.mime || '') + '</D:getcontenttype>'; }
        xml += '<D:displayname>' + escHtml(item.name) + '</D:displayname>';
        xml += '<D:getlastmodified>' + (item.time || new Date().toISOString()) + '</D:getlastmodified>';
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
        xml += '<D:response><D:href>' + np + '</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>' + obj.size + '</D:getcontentlength><D:getlastmodified>' + (obj.uploaded.toISOString()) + '</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>';
        return new Response(xml, { status: 207, headers: davHeaders });
      } catch (e) { return new Response('Not Found', { status: 404 }); }
    }
  }

  if (method === 'GET') {
    const key = np.replace(/^\//, '');
    try {
      const obj = await env.DRIVE.get(key);
      if (!obj) return new Response('Not Found', { status: 404 });
      return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream' } });
    } catch (e) { return new Response('Error', { status: 500 }); }
  }

  if (method === 'PUT') {
    const dirPath = parentOf(np);
    const fileName = np.split('/').filter(Boolean).pop();
    if (!fileName) return new Response('Bad Request', { status: 400 });
    const safeName = sanitizeName(fileName);
    const buf = await req.arrayBuffer();
    await env.DRIVE.put(np.replace(/^\//, ''), buf);
    const entry = { name: safeName, type: 'file', size: buf.byteLength, mime: req.headers.get('Content-Type') || '', time: new Date().toISOString() };
    await upsertDirItem(env, dirPath, entry);
    await addUsage(env, buf.byteLength, 1);
    await addLog(env, 'up', np, buf.byteLength + ' bytes (WebDAV)');
    return new Response('', { status: 201 });
  }

  if (method === 'DELETE') {
    return handleDelete(env, np.replace(/^\//, ''));
  }

  if (method === 'MKCOL') {
    const dirPath = parentOf(np);
    const folderName = np.split('/').filter(Boolean).pop();
    if (!folderName) return new Response('Bad Request', { status: 400 });
    return handleMkdir(env, dirPath, sanitizeName(folderName));
  }

  return new Response('Method Not Allowed', { status: 405 });
}

// ===== Router =====
export default {
  async fetch(req, env) {
    const url = new URL(req.url); const p = url.pathname;

    if (p === '/api/login' && req.method === 'POST') return handleLogin(req, env);

    if (p.startsWith('/s/')) {
      const rest = p.substring(3);
      const slash = rest.indexOf('/');
      const token = slash < 0 ? rest : rest.substring(0, slash);
      const sub = slash < 0 ? '' : rest.substring(slash + 1);
      if (sub === 'data') return handleShareData(env, token);
      if (sub === 'dl') return handleShareDownload(env, token, req);
      if (sub === 'pv') return handleSharePreview(env, token, req);
      return html(sharePage(token));
    }

    if (p.startsWith('/u/')) return html(uploadPage(p.substring(3)));
    if (p.startsWith('/api/upload-link/') && req.method === 'POST') return handleUploadViaLink(req, env, p.substring('/api/upload-link/'.length));

    if (p.startsWith('/dav')) return handleWebDAV(req, env);

    if (p.startsWith('/api/')) {
      if (!await checkAuth(env, req)) return json({ error: 'Unauthorized' }, 401);
      try {
        if (p === '/api/list') return handleList(env, url.searchParams.get('path') || '/', url.searchParams.get('size') === '1', url.searchParams.get('token') || '');
        if (p === '/api/unlock' && req.method === 'POST') { const b = await req.json(); return handleUnlockDir(env, url.searchParams.get('token') || '', b.path, b.password); }
        if (p === '/api/upload' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handleUpload(req, env, url.searchParams.get('path') || '/'); }
        if (p === '/api/download') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handleDownload(env, url.searchParams.get('path') || ''); }
        if (p === '/api/preview') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handlePreview(env, url.searchParams.get('path') || ''); }
        if (p === '/api/thumb') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handleThumb(env, url.searchParams.get('path') || ''); }
        if (p === '/api/save' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const content = await req.text(); return handleSaveText(env, url.searchParams.get('path') || '', content); }
        if (p === '/api/delete' && req.method === 'DELETE') { const fp = url.searchParams.get('path') || ''; const g = await guard(env, req, parentOf('/' + fp.replace(/^\/+/, ''))); if (g) return g; return handleDelete(env, fp); }
        if (p === '/api/batch-delete' && req.method === 'POST') { const b = await req.json(); return handleBatchDelete(env, b.paths); }
        if (p === '/api/batch-rename' && req.method === 'POST') { const b = await req.json(); return handleBatchRename(env, b.paths, b.pattern); }
        if (p === '/api/duplicates') return handleDuplicates(env);
        if (p === '/api/note' && req.method === 'GET') return handleGetNote(env, url.searchParams.get('path') || '');
        if (p === '/api/note' && req.method === 'POST') { const b = await req.json(); return handleSetNote(env, b.path, b.note); }
        if (p === '/api/tag' && req.method === 'POST') { const b = await req.json(); return handleTagFile(env, b.path, b.tags); }
        if (p === '/api/tags' && req.method === 'GET') { if (url.searchParams.get('filter')) return handleTagFilter(env, url.searchParams.get('filter')); return handleGetTags(env); }
        if (p === '/api/chunk-init' && req.method === 'POST') { const b = await req.json(); return handleChunkInit(env, b.fileName, b.totalSize, b.hash, b.path || '/'); }
        if (p.startsWith('/api/chunk-upload/') && req.method === 'POST') { const parts = p.split('/'); return handleChunkUpload(req, env, parts[3], parts[4]); }
        if (p === '/api/chunk-complete' && req.method === 'POST') { const b = await req.json(); return handleChunkComplete(env, b.uploadId); }
        if (p === '/api/chunk-status') return handleChunkStatus(env, url.searchParams.get('id') || '');
        if (p === '/api/mkdir' && req.method === 'POST') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; const b = await req.json(); return handleMkdir(env, url.searchParams.get('path') || '/', b.name); }
        if (p === '/api/rename' && req.method === 'PUT') { const b = await req.json(); const g = await guard(env, req, parentOf('/' + b.path.replace(/^\/+/, ''))); if (g) return g; return handleRename(env, b.path, b.newName); }
        if (p === '/api/move' && req.method === 'PUT') { const b = await req.json(); const g = await guard(env, req, parentOf('/' + b.path.replace(/^\/+/, '')), b.target); if (g) return g; return handleMove(env, b.path, b.target); }
        if (p === '/api/search') return handleSearch(env, url.searchParams.get('q') || '', url.searchParams.get('path') || '/');
        if (p === '/api/tree') return handleTree(env);
        if (p === '/api/zip') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handleZip(env, url.searchParams.get('path') || '/'); }
        if (p === '/api/unzip' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, parentOf(b.path)); if (g) return g; return handleUnzip(env, b.path); }
        if (p === '/api/versions' && req.method === 'GET') { const g = await guard(env, req, url.searchParams.get('path')); if (g) return g; return handleListVersions(env, url.searchParams.get('path') || ''); }
        if (p === '/api/versions/restore' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return handleRestoreVersion(env, b.path, b.ts); }
        if (p === '/api/share' && req.method === 'POST') { const b = await req.json(); const g = await guard(env, req, b.path); if (g) return g; return handleShare(env, b.path, b.days, b.max, b.password); }
        if (p === '/api/upload-link-create' && req.method === 'POST') { const b = await req.json(); return handleCreateUploadLink(env, b.path, b.days, b.max); }
        if (p === '/api/folder-pass' && req.method === 'POST') { const b = await req.json(); return handleSetFolderPass(env, b.path, b.password); }
        if (p === '/api/folder-pass' && req.method === 'GET') return json({ has: !!(await env.STORE.get('dirpass:' + normPath(url.searchParams.get('path') || '/'), 'json')) });
        if (p === '/api/trash') return handleTrash(env);
        if (p === '/api/restore' && req.method === 'POST') return handleRestore(env, url.searchParams.get('name') || '');
        if (p === '/api/batch-restore' && req.method === 'POST') { const b = await req.json(); return handleBatchRestore(env, b.ids); }
        if (p === '/api/purge' && req.method === 'DELETE') return handlePurge(env, url.searchParams.get('name') || '');
        if (p === '/api/batch-purge' && req.method === 'POST') { const b = await req.json(); return handleBatchPurge(env, b.ids); }
        if (p === '/api/usage') { const u = await getUsage(env); return json({ used: u.used, files: u.files, total: 10 * 1024 * 1024 * 1024 }); }
        if (p === '/api/recalc-usage' && req.method === 'POST') { const u = await recalcUsage(env); return json({ ok: true, used: u.used, files: u.files }); }
        if (p === '/api/log' && req.method === 'GET') return json({ logs: await getLogs(env) });
        if (p === '/api/tokens' && req.method === 'GET') return json({ tokens: (await getAccessTokens(env)).map(t => ({ name: t.name, perm: t.perm, exp: t.exp || null })) });
        if (p === '/api/tokens' && req.method === 'POST') { const b = await req.json(); const tokens = await getAccessTokens(env); const nt = { name: b.name || 'Token', token: randToken(), perm: b.perm || 'ro', exp: b.exp || null }; tokens.push(nt); await saveAccessTokens(env, tokens); return json({ ok: true, token: nt.token }); }
        if (p === '/api/tokens' && req.method === 'DELETE') { const b = await req.json(); const tokens = (await getAccessTokens(env)).filter(t => t.token !== b.token); await saveAccessTokens(env, tokens); return json({ ok: true }); }
        if (p === '/api/stats') { const u = await getUsage(env); const logs = await getLogs(env); const tree = await handleTree(env); const treeData = await tree.json(); const typeCount = { image: 0, video: 0, audio: 0, doc: 0, other: 0 }; function countTypes(node) { (node.children || []).forEach(function(c) { if (c.children) countTypes(c); }); } try { countTypes(treeData.tree || {}); } catch(e) {} return json({ usage: u, logCount: logs.length, types: typeCount }); }
        if (p === '/api/recent' && req.method === 'GET') return json({ items: await getRecent(env) });
        if (p === '/api/recent' && req.method === 'POST') { const b = await req.json(); await addRecent(env, b.path); return json({ ok: true }); }
        if (p === '/api/favs' && req.method === 'GET') { const favs = await getFavs(env); return json({ items: favs.map(path => ({ name: path.split('/').filter(Boolean).pop() || path, type: 'file', path: parentOf(path), size: 0, mime: '' })) }); }
        if (p === '/api/fav' && req.method === 'POST') { const b = await req.json(); await toggleFav(env, b.path); return json({ ok: true }); }
      } catch (e) { console.error(e); return json({ error: 'Internal error' }, 500); }
      return json({ error: 'Not found' }, 404);
    }
    return html(page(env));
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const trash = await getDir(env, '/.trash/');
        const now = Date.now();
        const keep = [];
        let purged = 0, totalSize = 0;
        for (const item of trash) {
          const deletedTime = new Date(item.deletedAt).getTime();
          if (now - deletedTime > 30 * 86400 * 1000) {
            const k = item.originalPath.replace(/^\//, '');
            try { await env.DRIVE.delete(k); } catch (e) {}
            await deleteThumb(env, k);
            await deleteVersions(env, k);
            totalSize += item.size || 0; purged++;
          } else { keep.push(item); }
        }
        if (purged > 0) { await putDir(env, '/.trash/', keep); await addUsage(env, -totalSize, -purged); }
      } catch (e) { console.error('Scheduled cleanup failed:', e); }
    })());
  }
};
