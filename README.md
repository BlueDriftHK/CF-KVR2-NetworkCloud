# CF-KVR2-NetworkCloud

基于 Cloudflare Workers 的个人网盘，单文件部署，零外部依赖。

A personal cloud drive on Cloudflare Workers. Single-file deploy, zero external dependencies.

**Live Demo** → [cloud.bjhr.space](https://cloud.bjhr.space)

---

## Features

### Core

- File upload (drag & drop, folder upload, paste screenshot, chunked for large files)
- Download, preview (image / video / audio / text / Markdown / PDF)
- Directory management: create, rename, move, delete, batch operations
- Search, favorites, recent files, tree sidebar
- Usage stats with recalculation
- Dark / Light / Auto theme, responsive layout
- Bilingual UI (中文 / English)

### Sharing & Security

- Share links with expiry, access count limit, password
- Upload links (let others upload to a folder)
- Folder password lock
- Client-side AES-256-GCM encryption (`.enc` files)
- Access token management (Read / Read+Write permissions)
- WebDAV protocol (`/dav/` — PROPFIND, GET, PUT, DELETE, MKCOL)

### Media & Tools

- Markdown rendering + code syntax highlighting
- Music playlist player (continuous playback)
- Image slideshow with EXIF metadata
- Video frame screenshot
- ZIP download (folder packaging) + ZIP extract
- Batch rename with `{n}` index / `{d}` date patterns
- Image compression before upload (client-side)
- Upload deduplication (name + size check)
- QR code for share links
- File notes / annotations
- Activity log (last 200 operations)
- Storage stats with Chart.js visualization

---

## Tech Stack

| Layer | Tech |
|-------|------|
| Runtime | Cloudflare Workers (V8 isolates) |
| Storage | R2 (files) + Workers KV (metadata) + Durable Objects (optional, directory cache) |
| Frontend | Vanilla HTML/CSS/JS, Apple-style UI |
| CDN libs | marked.js, highlight.js, PDF.js (ESM), Chart.js, QRCode.js, ExifReader |

---

## Deployment

### 1. Create Resources

- **R2 Bucket** — for file storage
- **Workers KV Namespace** — for metadata (directory index, sessions, tags, notes, logs)
- **Durable Object** *(optional)* — for faster directory operations; falls back to KV if not configured

### 2. Create Worker

Go to Cloudflare Dashboard → Workers → Create Worker → paste `_workers.js` → Deploy.

### 3. Configure Bindings

| Binding | Type | Name | Required |
|---------|------|------|----------|
| R2 Bucket | R2 | `DRIVE` | Yes |
| KV Namespace | KV | `STORE` | Yes |
| Durable Object | DO | `DIR` | No (KV fallback) |

### 4. Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DRIVE_PASSWORD` | Login password | Yes |
| `DRIVE_TITLE` | Custom page title | No |
| `DRIVE_LOGO` | Custom logo emoji | No |

### 5. Custom Domain (optional)

Add a route in Worker Settings → Domains & Routes, e.g. `drive.yourdomain.com`.

---

## WebDAV

Mount the drive as a local disk using any WebDAV client (Raidrive, Cyberduck, Windows Explorer, macOS Finder):

```
URL:  https://yourdomain.com/dav/
Auth: Bearer <access-token>
```

1. Create a token in the drive UI (🔑 Tokens panel)
2. Configure your WebDAV client with the Bearer token
3. Supported methods: PROPFIND, GET, PUT, DELETE, MKCOL, OPTIONS

---

## Project Structure

```
_workers.js    # Single file, ~3400 lines
├── Helpers (auth, path, KV/DO access)
├── Durable Object (DirStore class)
├── Backend Handlers (upload, delete, zip, share, tags, notes, WebDAV...)
├── Frontend (HTML template with embedded CSS + JS)
└── Router (export default { fetch, scheduled })
```

---

## Scheduled Tasks

The Worker includes a `scheduled` handler that auto-purges trash files older than 30 days. Configure a cron trigger in CF Dashboard → Triggers → Cron Schedules (e.g. `0 3 * * *`).

---

## License

MIT License
