# CloudDrive · Personal Drive

> 文档版本：2026-11 · 对应代码 `v5.2.0`（UI build `flat-1`）
>
> **把整个网盘，装进一个文件。**
>
> 一个运行在 Cloudflare Workers 上的单文件个人网盘：R2 存文件、KV 存元数据、Durable Object 保证目录一致性。
> 零 npm 运行时依赖，无构建步骤，粘贴即上线；上传、下载、分享、媒体预览、备份、WebDAV、PWA 全部收在同一个 JavaScript 文件里。

<p>
  <code>v5.2.0</code> · <code>UI build: flat-1</code> · <code>12,719 行</code> · <code>769,493 bytes</code> · <code>0 npm deps</code> · <code>1 file</code>
</p>

---

## 目录

- [项目简介](#项目简介)
- [亮点总览](#亮点总览)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [绑定与配置](#绑定与配置)
- [功能详解](#功能详解)
- [API 参考](#api-参考)
- [WebDAV 使用](#webdav-使用)
- [安全模型](#安全模型)
- [限制与配额](#限制与配额)
- [单文件内部结构](#单文件内部结构)
- [项目文件](#项目文件)
- [展示页](#展示页)
- [验证与测试](#验证与测试)
- [版本历史](#版本历史)
- [常见问题](#常见问题)
- [路线图](#路线图)
- [贡献指南](#贡献指南)
- [安全披露](#安全披露)
- [许可与免责声明](#许可与免责声明)
- [致谢](#致谢)

---

## 项目简介

**CloudDrive（Personal Drive）** 是一个自托管的个人云盘。它不依赖任何服务器、数据库、Docker 或 npm 包，只依赖 Cloudflare 的三样东西：

- **R2** —— 对象存储，存放文件本体；
- **KV** —— 键值存储，存放目录元数据、索引、会话与配置；
- **Durable Object（可选）** —— 目录一致性与用量的强一致层，不绑定会自动回退到 KV。

之所以做成「单文件」，是因为部署体验本身就是产品的一部分：在 Cloudflare Dashboard 里新建一个 Worker，把 `_workers.js` 的全部内容粘贴进去、绑定三个资源、设置一个密码，网盘就上线了。没有 `package.json`，没有构建缓存，没有需要定期升级的依赖树。

它适合这样的使用者：

- 想完全掌控自己的数据，但不想维护一台 NAS 或 VPS；
- 需要一个自己的文件 API / WebDAV 挂载点，给脚本、工具链或 AI 工作流用；
- 想要「链接分享 + 密码 + 过期 + 权限」这种可控的外发方式；
- 喜欢单文件、可审计、可迁移的工程美学。

> 它不是多用户团队盘，也不追求替代商业网盘的全部功能。它是一个「单管理员的个人网盘」，在这个边界内把能力做满。

---

## 亮点总览

| 分类 | 能力 |
|---|---|
| 🔐 安全 | TOTP 二次验证 + 备用码、PBKDF2 口令派生、目录密码锁、只读访问令牌、限时签名直链、媒体短令牌、IP / 国家 / UA 风控、登录限频、审计日志 CSV、会话与设备管理、CSP + SRI |
| 📁 文件 | 虚拟目录、四种视图、虚拟滚动、拖拽上传/移动、批量重命名/移动/删除/分享、收藏分组、标签、备注、回收站、版本历史、重复文件、元数据导入导出 |
| 🚀 传输 | 上传队列（并发/暂停/取消/重试）、5MB 分片上传、断点续传、秒传、Range 流式下载、流式 ZIP 打包、ZIP 解压、远程 URL 抓取、S3 兼容镜像 |
| 🔗 分享 | 文件 / 目录分享、自定义短链、密码、一次性链接、访问次数、禁止下载、评论开关、IP / 国家 / UA 限制、访问统计、访客评论、上传链接、公开上传页、公开相册、二维码 |
| 🎬 媒体 | Office 预览、PDF 预览、音乐播放器（封面/歌词/随机循环）、图片幻灯片 + EXIF、视频截图、缩略图、相似图片（dHash）、图片批处理、图片压缩 |
| 🔎 检索 | ⌘K 命令面板、`/api/query` 高级筛选（大小/日期/类型/标签）、标签系统、收藏分组、最近访问、重复文件、全文式输入体验 |
| 🛠 运维 | 可视化配置面板、目录级规则、定时任务、增量备份 + 差异预览 + 恢复、健康自检、孤儿扫描、用量校准、下载统计、Webhook、S3 后端检查、自动内务回收 |
| 📱 前端 | 文件优先的扁平界面、四视图、移动端底部标签栏与手势、PWA（可安装 / 分享即上传 / 离线只读）、主题 / 密度 / 语言、离线缓存、快捷键 |
| 🔌 集成 | WebDAV 挂载、REST API、Bearer Token、签名直链、公开页面路由、PWA Share Target、Webhook |

---

## 技术架构

### 请求路径

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Browser / PWA / WebDAV client / API script / <img>                   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTPS
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Cloudflare Worker · _workers.js                                     │
│                                                                     │
│  Router ──► Auth ──► Rate limit ──► Handler ──► Stream / JSON       │
│             │           │              │                            │
│             │           │              ├──► HTML UI（内联）          │
│             │           │              ├──► REST API                 │
│             │           │              ├──► Public share / album     │
│             │           │              └──► WebDAV                   │
│             │           └── isolate 内存令牌桶 + 公开路由 IP 限流     │
│             └── 会话 / 访问令牌 / TOTP / 目录锁 / 签名校验            │
└──────────┬──────────────────┬───────────────────────┬───────────────┘
           │                  │                       │
           ▼                  ▼                       ▼
   ┌───────────────┐  ┌───────────────┐      ┌──────────────────────┐
   │ R2 · DRIVE    │  │ KV · STORE    │      │ Durable Object · DIR │
   │ 文件字节       │  │ 元数据/索引    │      │ 目录一致性 + 用量     │
   │ 版本/备份/分片 │  │ 会话/配置/缓存 │      │ （可选，不绑回退 KV） │
   └───────────────┘  └───────────────┘      └──────────────────────┘
```

### 数据模型

- **文件对象**：R2 key 就是去掉前导 `/` 的路径，例如 `/Photos/2026/a.jpg` → `Photos/2026/a.jpg`。
- **目录元数据**：每个目录一份条目数组，存在 KV（和 DO 缓存）中，包含名称、类型、大小、MIME、时间、标签、备注、收藏等信息。
- **内部命名空间**（对用户不可见、API 不可访问）：
  - `.thumb/` 缩略图
  - `.versions/` 历史版本
  - `.trash/` 回收站
  - `.chunks/` 上传分片
  - `.backup/` 元数据备份快照
- **强一致层**：目录写操作优先走 Durable Object（默认 3 秒超时后降级 KV），避免大目录缓存退出时的并发丢条目问题。
- **读缓存**：会话 10s、配置 30s、标签计数 60s 等隔离级短 TTL 缓存，降低 KV 读放大。
- **写预算**：日志 / 下载明细 / 每日统计 / 最近访问走内存缓冲合并写，并受每分钟写预算与每日遥测预算限制。

### 一次上传的生命周期

```text
浏览器选择文件
   │  ≤ 100MB ──────────────► POST /api/upload（multipart）
   │  > 5MB 自动分片
   ▼
POST /api/chunk-init  ──► 返回 uploadId + 分片数（5MB/片）
POST /api/chunk-upload/<uploadId>/<index>   × N
POST /api/chunk-status/<uploadId>           （刷新/重连后恢复）
POST /api/chunk-complete                    （合并、校验大小、计配额）
   │
   ├── 命中内容哈希 ──► 秒传：只写元数据，不重复上传
   └── 写入 R2 + 更新目录元数据 + 镜像到可选 S3 后端
```

### 防 KV / R2 爆

代码里贯穿始终的硬约束：

- KV 读：隔离级缓存 + 目录锁前缀列表，无锁场景几乎零额外读；
- KV 写：每分钟写预算（默认 600）+ 每日遥测写预算（默认 500）+ 内存缓冲合并；
- KV 上限：单目录 20,000 条目、路径 ≤ 400 字符、KV key ≤ 480、目录元数据默认 8MB；
- R2 上限：大文件不保留历史版本、分片与回收站定期回收、备份份数 + 总占用双限、分享打包流式写入；
- 可观测：`GET /api/health` 返回 guard 信息（缓存条目、写入计数、预算、上限、R2 内部占用采样）。

---

## 快速开始

### 前置要求

- 一个 Cloudflare 账号（免费计划即可开始）；
- 一个 R2 桶、一个 KV 命名空间；
- 可选：一个 Durable Object 命名空间（强烈建议绑定，用于目录一致性）；
- 可选的 Worker 自定义域名（使用 `*.workers.dev` 也可以）。

### 方式一：Dashboard 粘贴部署（最快）

1. 打开 Cloudflare Dashboard → **Workers & Pages** → 创建 Worker（例如 `cloud-drive`）。
2. 编辑代码，把 `_workers.js` 的**全部内容**粘贴进去，保存并部署。
3. 创建 **R2 桶**（例如 `my-drive`），在 Worker 的 **Bindings** 中添加：
   - R2 bucket binding：变量名 `DRIVE`；
   - KV namespace binding：变量名 `STORE`；
   - Durable Object binding：变量名 `DIR`，class name `DirStore`（可选但推荐）。
4. 在 Worker 的 **Settings → Variables and Secrets** 添加 Secret：
   - `DRIVE_PASSWORD`：管理员密码（必填）。
   - 可选：`URL_SIGN_SECRET`（签名直链专用密钥；不设则回退到 `DRIVE_PASSWORD`）。
5. 打开 Worker 域名，用管理员密码登录，完成初始化。
6. 建议在 **Triggers → Cron Triggers** 添加每日任务（例如 `0 2 * * *`），用于回收站清理、分片回收、自动备份与用量校准。
7. 访问 `GET /api/version` 确认版本与绑定自检：

```json
{
  "version": "v5.2.0",
  "ui": "flat-1",
  "bindings": { "store": true, "drive": true, "dir": true }
}
```

### 方式二：Wrangler 部署

```toml
# wrangler.toml
name = "cloud-drive"
main = "_workers.js"
compatibility_date = "2025-01-01"

[[r2_buckets]]
binding = "DRIVE"
bucket_name = "my-drive"

[[kv_namespaces]]
binding = "STORE"
id = "<your-kv-namespace-id>"

[[durable_objects.bindings]]
name = "DIR"
class_name = "DirStore"

[[migrations]]
tag = "v1"
new_classes = ["DirStore"]

[triggers]
crons = ["0 2 * * *"]

[vars]
DRIVE_TITLE = "My Cloud"
# DRIVE_PASSWORD 请用 secret 注入，不要写进 wrangler.toml
```

```bash
# 安装并登录（只需要一次）
npm install -g wrangler
wrangler login

# 创建资源（也可以用 Dashboard 创建后把 id 填进 toml）
wrangler r2 bucket create my-drive
wrangler kv namespace create STORE

# 注入密码
wrangler secret put DRIVE_PASSWORD

# 部署
wrangler deploy

# 看日志（排查部署问题很有用）
wrangler tail
```

> 不绑定 `DIR` 也能运行：目录访问层会在 DO 不可用时降级到 KV（超时 3 秒），但建议绑定以获得更稳的并发目录写入体验。

### 首次配置建议

1. 登录后立即在设置中开启 TOTP 二次验证，并保存好备用码；
2. 为敏感目录设置目录密码；
3. 根据需要进行 IP / 国家 / UA 风控；
4. 开启自动备份，并手动执行一次「备份 → 差异预览 → 恢复」验证；
5. 检查 `/api/health` 中的 KV 写预算与 R2 体积上限；
6. 如需公开上传，先设置 `PUBLIC_UPLOAD_DIR`，再考虑开启 Turnstile。

---

## 绑定与配置

### 必需的绑定

| 绑定 | 类型 | 说明 |
|---|---|---|
| `DRIVE` | R2 Bucket | 文件本体、版本、回收站、分片、备份快照 |
| `STORE` | KV Namespace | 目录元数据、索引、会话、配置、缓存 |
| `DIR` | Durable Object（可选） | 目录一致性与用量；class name 必须为 `DirStore` |
| `DRIVE_PASSWORD` | Secret | 管理员密码（必填） |

### 环境变量 / Secrets

> 配置优先级：**网页配置面板（KV `meta:config`） > 环境变量 > 内置默认值**。  
> 面板中的 MB 类配置优先；同名旧环境变量按历史单位（字节）解释，以保持向后兼容。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DRIVE_PASSWORD` | —（必填） | 管理员密码；同时作为无状态会话的派生密钥（若未设 `URL_SIGN_SECRET`） |
| `DRIVE_TITLE` | `云端网盘` | 站点标题（≤ 60 字符） |
| `DRIVE_LOGO` | `☁️` | 站点 Logo（emoji，≤ 8 字符） |
| `DRIVE_NOTICE` | 空 | 登录页 / 站点公告（≤ 300 字符） |
| `DRIVE_QUOTA` | `10` | 总配额（GB），默认 10GB；面板里可改 |
| `MAX_UPLOAD_MB` | `500` | 单文件上传上限（MB） |
| `MAX_DIR_ITEMS` | `20000` | 单目录条目上限 |
| `KV_VALUE_MAX` | `8388608`（8MB） | 单目录元数据 KV 值上限（字节，旧变量） |
| `VERSION_MAX_BYTES` | `67108864`（64MB） | 保留历史版本的文件大小上限（字节，旧变量） |
| `BACKUP_MAX_BYTES` | `8388608`（8MB） | 单份备份元数据快照上限（字节，旧变量） |
| `TRASH_DAYS` | `30` | 回收站保留天数（0 表示不移除） |
| `CHUNK_GC_HOURS` | `24` | 未完成分片回收时间 |
| `VERSIONS_MAX` | `5` | 每个文件保留历史版本数 |
| `VERSIONS_TTL_DAYS` | `90` | 版本索引 TTL |
| `HASH_TTL_DAYS` | `30` | 秒传哈希索引 TTL |
| `BACKUP_KEEP` | `14` | 备份保留份数 |
| `BACKUP_TOTAL_MB` | `200` | 备份总占用上限（MB） |
| `BACKUP_INCREMENTAL` | `true` | 是否使用增量快照链 |
| `SIGN_TTL_MIN` | `60` | 签名直链默认有效期（分钟） |
| `PUBLIC_UPLOAD_DIR` | 空 | 公开上传目录；留空则关闭公开上传功能 |
| `PUBLIC_UPLOAD_MAX` | `100` | 公开上传单文件上限（MB） |
| `TURNSTILE_SITE_KEY` | 空 | 公开上传 / 登录的人机验证 Site Key（可选） |
| `TURNSTILE_SECRET` | 空 | Turnstile Secret；配置后公开上传强制验证 |
| `RATE_LIMIT_MODE` | `memory` | `memory`（isolate 令牌桶，默认）/ `do`（跨 isolate 精确限流） |
| `RL_READ_PER_MIN` | `150` | 每 IP 每分钟读请求上限 |
| `RL_WRITE_PER_MIN` | `30` | 每 IP 每分钟写请求上限 |
| `KV_BUDGET_PER_MIN` | `600` | 每分钟非关键 KV 写预算 |
| `DIR_PREFETCH` | `12` | 目录树按层并行的预取宽度（1–32） |
| `TELEMETRY_MAX_PER_DAY` | `500` | 每日遥测类 KV 写上限 |
| `TELEMETRY_FLUSH_MS` | `15000` | 遥测缓冲落盘间隔 |
| `SESSION_CACHE_SEC` | `10` | 会话缓存秒数 |
| `KV_MIRROR_DIR` | `true` | 是否把目录元数据镜像到 KV（关闭后仅 DO） |
| `IP_ALLOW` / `IP_DENY` | 空 | IP 白 / 黑名单，逗号分隔，支持 CIDR |
| `COUNTRY_ALLOW` / `COUNTRY_DENY` | 空 | 国家 / 地区代码名单（Cloudflare GeoIP） |
| `UA_ALLOW` / `UA_DENY` | 空 | User-Agent 关键词名单 |
| `DISABLE_URL_FETCH` | `false` | 禁用远程 URL 抓取（离线下载） |
| `FETCH_MAX_BYTES` | `209715200`（200MB） | 远程 URL 抓取的大小上限 |
| `URL_SIGN_SECRET` | 回退 `DRIVE_PASSWORD` | 签名直链 HMAC 密钥，建议单独生成 |
| `MAX_NOTE_BYTES` | `65536` | 单文件备注大小上限 |
| `MAX_TAGS_BYTES` | `8192` | 单文件标签数据上限 |
| `DRIVE_BACKENDS` | 空 | S3 兼容镜像后端，JSON 数组，见下文 |

#### S3 兼容镜像后端（可选）

`DRIVE_BACKENDS` 接受 JSON 数组（也接受以 id 为 key 的对象）：

```json
[
  {
    "id": "backup-s3",
    "endpoint": "https://s3.us-east-1.amazonaws.com",
    "region": "us-east-1",
    "bucket": "my-mirror-bucket",
    "accessKey": "...",
    "secretKey": "...",
    "prefix": "drive/",
    "pathStyle": true,
    "mirrorMaxBytes": 26214400
  }
]
```

- 未配置时全部空转，不影响主流程；
- 仅对不超过 `mirrorMaxBytes`（默认 25MB）的对象做镜像；
- 使用纯 JS 实现 AWS SigV4 签名，不依赖 AWS SDK。

---

## 功能详解

### A. 安全与认证

- **管理员密码**：PBKDF2-SHA256（20,000 次迭代 + 随机盐），记录中保存 `kdf/iter` 便于后续提高强度；兼容历史单轮 SHA-256 记录，验证成功后自动迁移。
- **TOTP 二次验证**：RFC 6238，30 秒窗口 ±1 step；开启 / 关闭需管理员口令；**同一验证码 120 秒内只能使用一次**（覆盖 ±1 窗口，防重放）；备用码一次性，服务端只存哈希。
- **会话**：默认 7 天；改密 / 更换 `DRIVE_PASSWORD` / 更换 `URL_SIGN_SECRET` 会使旧无状态会话全部失效；支持逐设备注销。
- **访问令牌**：创建时要求管理员口令，默认 30 天过期；支持只读 / 读写；请求头 `Authorization: Bearer <TOKEN>`。
- **目录密码锁**：任意目录可上锁；搜索、复制、删除、恢复、WebDAV、媒体扫描都会检查锁定前缀；设置 / 清除锁需要旧密码或已解锁会话。
- **签名直链**：HMAC-SHA256，带过期时间，可选绑定请求 IP；用于外发下载链接。
- **媒体短令牌**：10 分钟、只读，用于 `<img>`、`<video>` 和下载 URL，避免把 7 天会话令牌暴露在 URL 中。
- **审计日志**：登录、上传、删除、配置变更等事件留痕，支持筛选与 CSV 导出。
- **风控**：登录按 IP + 用户名双维度限频；公开路由有 IP 令牌桶；支持 IP / 国家 / UA 名单；可接入 Turnstile。
- **输出防护**：CSP、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`；7 个 CDN 静态资源带 SRI；上传内容默认沙箱预览，HTML / SVG 等不可信类型强制降级。

### B. 文件与目录

- 虚拟目录，目录元数据存 KV / DO；
- 四种视图：**网格 / 列表 / 列 / 图库**，配合虚拟滚动，单目录几千条目依然顺滑；
- 行高 38px 的密集列表，一屏多看 15 行；
- 拖拽上传、拖拽移动、目录树；
- 批量操作：重命名、移动、复制、删除、恢复、分享、打标签；
- 收藏、收藏分组、最近访问、备注；
- 回收站保留 30 天，可恢复或彻底清除；
- 版本历史：每个文件最多 5 个版本，旧对象 ≤ 64MB 才保留；
- 重复文件查找、孤儿文件扫描；
- 元数据导入 / 导出（标签、备注、收藏、分享等）。

### C. 上传与传输

- **上传队列**：并发 1–6（默认 2，可在界面切换），可暂停、取消、重试；
- **分片上传**：5MB/片，`chunk-init → chunk-upload → chunk-status → chunk-complete`；
- **断点续传**：刷新页面或重开浏览器后可恢复未完成任务；
- **秒传**：内容哈希命中且大小一致时只写元数据；哈希索引默认保留 30 天；
- **简单上传**：请求体上限 `min(MAX_UPLOAD_MB, 100MB)`，超过请走分片；
- **Range 流式下载**：支持拖动、断点；
- **流式 ZIP 打包**：边读边写，最多 2000 文件 / 2GB；
- **ZIP 解压**：仅支持 STORE（无压缩）条目，zip ≤ 50MB、≤ 1000 条目、解压后 ≤ 200MB；
- **远程 URL 抓取**：带 SSRF 防护（DNS fail-closed、A/AAAA 双查、私网与 IPv6 映射拦截、不跟随重定向），默认上限 200MB；
- **S3 兼容镜像**：主写入后尝试镜像到配置的 S3 后端（best-effort，失败不影响主流程）。

### D. 分享与协作

- 文件分享、目录分享（可浏览子目录并流式打包）；
- 自定义短链：`/s/<alias>`，2–32 字符；
- 权限细项：禁止下载、仅预览、一次性链接、最大访问次数、评论开关、访问密码、IP / 国家 / UA 限制；
- 一次性链接的消费是 **DO 原子计数**：并发、Range、HEAD 都不能绕过；
- 访问统计：浏览 / 下载计数、最近访问明细；
- 评论留言：站内与访客共用评论；公开接口只返回 id / 时间 / 昵称 / 正文，不返回 IP 与国家；
- 上传链接：`/u/<token>`，用于收集文件，默认不覆盖同名文件；
- 公开上传页：`/upload/`，需显式配置 `PUBLIC_UPLOAD_DIR`，可选 Turnstile；
- 公开相册：加密 / 分页 / EXIF / GPS，适合家庭照片外发；
- 分享二维码。

### E. 媒体预览

- **Office**：docx / xlsx / csv 等在线渲染（按需从 CDN 加载解析库，带 SRI / crossorigin）；
- **PDF**：内置 PDF 预览；
- **音乐播放器**：播放列表、封面、歌词、随机 / 循环、音量记忆；
- **图片**：幻灯片、EXIF、GPS、缩略图、相似图片（dHash + 汉明距离）；
- **视频**：视频截图；
- **图片批处理**：缩放 / 压缩 / 水印 / 旋转；
- **客户端加密**：浏览器内 AES-GCM 生成 `.enc` 副本（注意：这是副本，不是端到端加密产品，详见安全模型）。

### F. 检索与整理

- `⌘K` / `Ctrl+K` 命令面板：命令与文件混排搜索；
- `POST /api/query` 高级筛选：大小、日期、类型、标签组合；
- 标签：计数、改色、重命名合并、批量打标、自动打标；
- 收藏分组、最近访问、重复文件；
- 侧边栏目录树 + 标签栏；
- 元数据导入 / 导出。

### G. 运维与自动化

- **可视化配置面板**：写入 KV，优先于环境变量，改完即生效（无需重新部署）；
- **目录级规则**：目录体积、数量、类型限制；
- **定时任务**：TTL 目录、清空目录、自动归档；
- **备份**：元数据快照写入 R2 `.backup/`，默认保留 14 份 / 总占用 200MB；
  - 全量 + 增量链；
  - **差异预览**：恢复前对比新增 / 删除 / 变更；
  - **完整性校验**：链基缺失时拒绝恢复（409），不会静默部分回滚；
- **健康自检**：R2 / KV / DO / S3 后端逐项检查；
- **孤儿扫描**：只读扫描 + 二次确认清理；扫描不完整时拒绝 purge；
- **用量校准**、下载统计、审计日志；
- **Webhook**：上传、删除、分享、恢复等事件推送（不跟随重定向，host 校验）；
- **自动内务**：定时清理回收站、分片、内部对象，触发自动备份，刷新遥测。

### H. 前端体验

- 文件优先的扁平界面，外壳全屏、侧栏 184px；
- 单行工具栏常显 11 个入口：上传 / 新建 / 搜索 / 刷新 / 视图 / 排序 / 打包 / 分享 / 多选 / 回收站 / 设置；
- 移动端：底部标签栏（文件 / 收藏 / 最近 / 上传 / 我的）+ 选择模式 + 批量操作栏；
- 手势：右滑返回、左滑多选、长按菜单、下拉刷新；
- PWA：可安装、Share Target 分享即上传、离线只读；
- 主题：浅色 / 深色 / 跟随系统；密度、主题色、中英双语；
- 快捷键与命令面板；
- 空目录引导态、拖拽提示条、状态栏版本号（方便确认线上是否更新）。

---

## API 参考

### 认证方式

| 方式 | 用法 | 适用 |
|---|---|---|
| 会话 Cookie | 登录后由浏览器自动携带 | 网页 UI |
| Bearer Token | `Authorization: Bearer <TOKEN>` | 脚本 / 第三方 |
| 签名直链 | `?exp=...&sig=...` | 外发下载 |
| 媒体短令牌 | `?token=m1.xxx` | `<img>` / `<video>` / 下载 URL |
| WebDAV Basic | 用户名任意，密码填访问令牌 | 挂载 |

> 除 `/api/login`、`/api/version` 以及公开分享 / 上传路由外，绝大多数 API 都需要管理员会话或有效访问令牌。

### 主要端点（按能力分组）

#### 认证与安全

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 密码 / TOTP 登录，建立会话 |
| POST | `/api/logout` | 注销当前会话 |
| GET/POST | `/api/totp/setup`、`/api/totp/enable`、`/api/totp/disable`、`/api/totp/backup` | TOTP 生命周期 |
| POST | `/api/admin-pass` | 修改管理员密码（会使旧会话失效） |
| GET | `/api/sessions`、`/api/session-revoke` | 设备会话列表 / 注销 |
| GET/POST/DELETE | `/api/tokens` | 访问令牌管理 |
| POST | `/api/folder-pass`、`/api/unlock` | 目录密码锁 / 解锁会话 |
| GET | `/api/log` | 审计日志（支持筛选 / CSV） |

#### 文件与目录

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/list?path=/` | 目录列表 |
| GET | `/api/tree` | 目录树 |
| POST | `/api/mkdir`、`/api/save` | 新建目录 / 保存文本 |
| POST | `/api/delete`、`/api/rename`、`/api/move`、`/api/copy` | 单文件操作 |
| GET | `/api/download?path=...` | 原始下载（支持 Range） |
| GET | `/api/preview`、`/api/thumb` | 预览 / 缩略图（会话解锁前缀过滤） |
| GET | `/api/versions`、`/api/versions/restore` | 版本历史 / 恢复 |
| GET/POST | `/api/trash`、`/api/restore`、`/api/purge` | 回收站 |
| POST | `/api/batch-delete`、`/api/batch-move`、`/api/batch-rename`、`/api/batch-restore`、`/api/batch-purge`、`/api/batch-share` | 批量操作 |

#### 上传与传输

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/upload` | 简单上传（multipart，≤ 100MB） |
| POST | `/api/chunk-init` | 初始化分片上传 |
| POST | `/api/chunk-upload/<id>/<index>` | 上传单个分片 |
| GET | `/api/chunk-status/<id>` | 查询已上传分片 |
| POST | `/api/chunk-complete` | 合并分片、校验、落元数据 |
| POST | `/api/instant-check` | 秒传检查 |
| POST | `/api/fetch-url` | 远程 URL 抓取（离线下载） |
| GET | `/api/zip?path=...`、`/api/zip-multi` | 流式打包 |
| POST | `/api/unzip` | 解压（仅 STORE） |

#### 分享与公开页

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/share`、`/api/share/update` | 创建 / 修改分享 |
| GET | `/api/shares`、`/api/share-stats` | 分享列表 / 统计 |
| POST | `/api/sign` | 生成签名直链 |
| POST | `/api/media-token` | 换取 10 分钟媒体令牌 |
| GET/POST | `/api/comments` | 文件评论 / 访客评论 |
| GET/POST | `/api/upload-links`、`/api/upload-link-create` | 上传链接管理 |
| POST | `/api/public-upload` | 公开上传（需配置目录） |
| GET/POST | `/api/albums`、`/api/albums/update` | 公开相册 |
| GET | `/s/<token>` | 分享页 |
| GET | `/u/<token>` | 上传链接页 |
| GET | `/upload/` | 公开上传页 |
| GET | `/album/…`、`/a/…` | 公开相册 |

#### 检索 / 标签 / 收藏

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/query` | 高级筛选 |
| GET | `/api/search` | 快速搜索 |
| GET/POST | `/api/tags`、`/api/tags/color`、`/api/tags/rename`、`/api/tags/batch`、`/api/tags/auto` | 标签 |
| GET/POST | `/api/favs`、`/api/favgroups`、`/api/fav` | 收藏 / 分组 |
| GET | `/api/recent` | 最近访问 |
| GET | `/api/duplicates`、`/api/phash` | 重复文件 / 相似图片 |
| POST | `/api/export-meta`、`/api/import-meta` | 元数据导入导出 |

#### 运维 / 配置 / 监控

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/api/config`、`/api/config/reset` | 站点配置（KV 覆盖 env） |
| GET/POST | `/api/dirrules` | 目录级规则 |
| GET/POST | `/api/cron` | 定时任务管理 |
| POST | `/api/backup`、`/api/backup-diff`、`/api/backup-restore`、`/api/backup-download` | 备份 / 差异 / 恢复 / 下载 |
| GET | `/api/backups` | 备份列表 |
| GET | `/api/health` | 健康自检 + guard |
| GET | `/api/dashboard`、`/api/stats`、`/api/stats-trend`、`/api/dl-stats` | 仪表盘 / 统计 |
| POST | `/api/scan-orphans`、`/api/purge-orphans` | 孤儿扫描 / 清理 |
| POST | `/api/recalc-usage` | 用量校准 |
| GET/POST | `/api/webhook`、`/api/webhook-test` | Webhook |
| GET/POST | `/api/backends`、`/api/backends/check` | S3 后端管理 / 检查 |
| POST | `/api/import-webdav` | 从 WebDAV 导入（深度 ≤ 3 / ≤ 200 文件 / ≤ 500MB） |
| GET | `/api/version` | 版本 + 绑定自检（公开） |
| GET | `/api/usage` | 用量统计 |

> 完整端点列表以源码路由为准（100+ JSON API）。所有 JSON 响应默认 `Cache-Control: private, no-store` 与 `X-Content-Type-Options: nosniff`。

### curl 示例

```bash
BASE="https://your-worker.example.com"

# 1) 登录（保存 cookie）
curl -c cookies.txt -H "Content-Type: application/json" \
  -d '{"password":"your-admin-password"}' \
  "$BASE/api/login"

# 2) 列目录
curl -b cookies.txt "$BASE/api/list?path=/"

# 3) 上传（≤100MB 简单上传）
curl -b cookies.txt -F "file=@photo.jpg" \
  "$BASE/api/upload?path=/Photos/"

# 4) 创建访问令牌
curl -b cookies.txt -H "Content-Type: application/json" \
  -d '{"name":"ci","readonly":true,"days":30}' \
  "$BASE/api/tokens"

# 5) 用令牌调 API
curl -H "Authorization: Bearer <TOKEN>" "$BASE/api/list?path=/"

# 6) 创建分享
curl -b cookies.txt -H "Content-Type: application/json" \
  -d '{"path":"/Docs/brand.pdf","alias":"brand-2026","allowDl":true}' \
  "$BASE/api/share"

# 7) 健康检查
curl -b cookies.txt "$BASE/api/health"
```

> 上传大文件请使用分片流程（前端已自动处理）；脚本可以按 `chunk-init → chunk-upload → chunk-complete` 顺序调用。

---

## WebDAV 使用

### 挂载地址

```text
https://your-worker.example.com/dav/
```

- **用户名**：任意（例如 `me`）；
- **密码**：访问令牌（在设置 → 访问令牌中创建；不要使用管理员密码）；
- 支持方法：`OPTIONS / PROPFIND / GET / PUT / DELETE / MKCOL / MOVE / COPY`，以及 `LOCK / UNLOCK / PROPPATCH` 的声明式响应；
- 目录密码锁与配额同样生效；单次 `MOVE / COPY` 的源对象上限为 100MB。

### macOS Finder

1. Finder → 前往 → 连接服务器（`⌘K`）；
2. 输入 `https://your-worker.example.com/dav/`；
3. 用户名任意，密码填访问令牌。

### Windows 资源管理器

1. 此电脑 → 映射网络驱动器；
2. 文件夹填 `https://your-worker.example.com/dav/`；
3. 使用访问令牌作为密码（Windows 可能提示 HTTP Basic，选择"使用其他凭据"）。

### rclone 示例

```ini
[clouddrive]
type = webdav
url = https://your-worker.example.com/dav/
vendor = other
user = me
pass = <访问令牌>
```

```bash
rclone ls clouddrive:
rclone copy ./local clouddrive:Backup/
```

### 限制

- 不支持 WebDAV 的目录级 `MOVE / COPY`（返回 501）；
- 大文件写入受 Worker 请求体与配额限制，极端大文件建议走 HTTP 分片上传；
- 导入 WebDAV 源时有界：深度 ≤ 3、文件数 ≤ 200、总量 ≤ 500MB。

---

## 安全模型

### 默认安全层

| 层 | 措施 |
|---|---|
| 传输 | 全站 HTTPS（Cloudflare 边缘）；HTML `no-store` 防部署后旧页面缓存 |
| 认证 | 管理员密码 + 可选 TOTP；PBKDF2-SHA256 加盐；会话 / 令牌分离；改密即吊销 |
| 授权 | 访问令牌只读 / 读写；目录密码锁；分享权限细化到下载、评论、IP、国家、UA、次数、一次性 |
| 路径 | 统一路径规范化；内部命名空间（`.backup` 等）在下载 / 预览 / 上传 / WebDAV / 相册 / 恢复等所有入口被拦截 |
| 输入 | 文件名清洗、路径长度 / 目录条目 / KV 值大小上限、内容类型 essence 判定、HTML / SVG 降级 |
| 输出 | CSP、`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy`、7 个 CDN 资源 SRI |
| 限流 | 登录 IP + 用户名双维度；公开路由 IP 令牌桶；读 / 写每分钟令牌桶；KV 写预算；每日遥测预算 |
| 审计 | 关键操作留痕 + CSV 导出，异常便于回溯 |

### 一次代码审查后的加固（v5.1.2）

在 2026 年的一次系统性代码审查中，原始版本被修复了 **197 个 hunk（+946 / −1,506 行）**：

- **12 类 P1 全部修复**：公开相册绕过目录锁、备份链断裂静默回滚、DO 缓存退出并发丢条目、孤儿清理误删、分片上传绕过配额、秒传投毒、ZIP 解压放大、流式打包无背压、改密不吊销令牌、公开面无限流、目录锁整体旁路、TOTP 可重放 / DOM 泄露；
- **32 类 P2 中 28 类修复或显著缓解**：MIME 参数绕过、内部前缀可读、限流键绕过、备份含明文凭据、一次性链接原子消费、分享 / 相册密码限频、PBKDF2 迁移、WebDAV 覆盖 / 类型冲突、SSRF、大请求体早拒绝、CSP / SRI、危险配置钳制等；
- **13 项 P3 修复**，并删除 **1,089 行前端重复代码**（同时消除两个真实 ReferenceError）。

详细记录见仓库/工作区中的：

- `review/FIX-REPORT.md` —— 修复报告（含逐项对照、行为变更、验证记录、残余风险）；
- `review/REVIEW-REPORT.md` —— 原始审查基线；
- `review/findings-*.md` —— 分域审查明细。

### 残余风险（已知且已记录）

| 项 | 现状 / 说明 |
|---|---|
| `?token=` 仍接受会话令牌 | 前端已全部改用 10 分钟媒体令牌；保留 query 会话令牌是为了兼容脚本，可在未来版本移除 |
| 简单上传整块缓冲 | ≤ 100MB，且前端 > 5MB 自动分片；如需 500MB 单请求需改为流式 multipart |
| 配额检查非原子 | 高并发下可能短暂超出配额；建议未来用 DO 做配额预留 |
| 回收站对象不计入用量展示 | 产品语义问题，恢复 / 清理后用量会重新校准 |
| `createBackup` 非流式 | 已加目录数与快照体积上限，超限明确报错 |
| DNS rebinding | 已 fail-closed + 双查 + 私网拦截，理论上仍有解析竞态；生产环境可给 Workers 出站加允许列表 |
| once 链接消费后元数据仍可读 | 产品语义：once 约束的是下载 / 打包；如需"整体失效"需额外删除或隐藏分享 |
| 客户端 AES 是副本 | 生成 `.enc` 副本而非端到端加密；真加密需只上传密文并禁用缩略图 / 版本 / 镜像 |
| 公开上传 Turnstile 可跳过 | 保持原产品行为，已加 IP 限流；建议默认强制 Turnstile |

---

## 限制与配额

| 项目 | 默认值 | 可配置 |
|---|---|---|
| 单文件上传 | 500 MB | `MAX_UPLOAD_MB` / 面板 |
| 简单上传请求体 | 100 MB（`min(MAX_UPLOAD_MB,100MB)`） | — |
| 分片大小 | 5 MB | 代码常量 |
| 目录条目 | 20,000 | `MAX_DIR_ITEMS` / 面板 |
| 路径长度 | 400 字符 | 代码常量 |
| KV key | 480 字符 | 代码常量 |
| 单目录元数据 KV 值 | 8 MB | 面板 `kvValueMB` / `KV_VALUE_MAX` |
| 历史版本数 | 5 | `VERSIONS_MAX` |
| 单版本原文件 | 64 MB | 面板 `versionMaxMB` / `VERSION_MAX_BYTES` |
| 版本索引 TTL | 90 天 | `VERSIONS_TTL_DAYS` |
| 秒传索引 TTL | 30 天 | `HASH_TTL_DAYS` |
| 回收站 | 30 天 | `TRASH_DAYS` |
| 未完成分片 | 24 小时 | `CHUNK_GC_HOURS` |
| 分享打包 | 2000 文件 / 2GB | 代码常量 |
| ZIP 解压 | ≤ 50MB、≤ 1000 条目、≤ 200MB 输出 | 代码常量 |
| 签名直链 | 60 分钟（默认） | `SIGN_TTL_MIN` |
| 媒体令牌 | 10 分钟 | 代码常量 |
| 会话 | 7 天 | 代码常量（`SESSION_TTL`） |
| 备份 | 14 份 / 200MB / 单份 8MB | `BACKUP_KEEP`、`BACKUP_TOTAL_MB`、面板 |
| 读限流 | 150 次 / 分钟 / IP | `RL_READ_PER_MIN` |
| 写限流 | 30 次 / 分钟 / IP | `RL_WRITE_PER_MIN` |
| KV 写预算 | 600 次 / 分钟 | `KV_BUDGET_PER_MIN` |
| 每日遥测写 | 500 次 | `TELEMETRY_MAX_PER_DAY` |
| WebDAV 导入 | 深度 ≤ 3 / 200 文件 / 500MB | 代码常量 |
| 远程抓取 | 200 MB | `FETCH_MAX_BYTES` |
| 公开上传 | 100 MB（需配置目录） | `PUBLIC_UPLOAD_MAX` |

> 以上为默认值，实际以当前版本代码与配置面板为准。

---

## 单文件内部结构

`_workers.js` 按注释分区组织，便于在一个文件内定位：

```text
_workers.js
├── Header 注释 / 版本 / 能力说明
├── ===== Helpers =====                 通用工具、路径、JSON / HTML 响应
├── ===== Hardening helpers =====       内部路径拦截、MIME essence、路径规范化
├── ===== KV / R2 防爆 =====            配额、缓存、写预算、放大保护
├── ===== 站点配置 =====                KV 覆盖 > env > 默认值
├── ===== Range / 流式响应 =====
├── ===== Turnstile / 公开上传 =====
├── ===== S3 兼容多后端 =====           纯 JS AWS SigV4
├── ===== Durable Object: DirStore ===== 目录条目 + 用量
├── ===== Dir 访问层 =====             DO 优先，3s 超时降级 KV
├── ===== Recent / Favorites / 收藏分组 / 元数据导入导出 =====
├── ===== Auth / 签名直链 / 媒体令牌 / 审计 / 限流 / TOTP / 风控 =====
├── ===== 会话 / 目录锁 / 缩略图 / 版本历史 =====
├── ===== API =====                    100+ 端点路由
├── ===== 分享 / 评论 / 上传链接 / 相册 / PWA / 公开上传 =====
├── ===== Folder Password / ZIP / 流式打包 / 远程抓取 / 秒传 / 解压 =====
├── ===== Frontend =====               内联 HTML/CSS/JS（文件优先扁平 UI）
├── ===== 前端功能：标签 / 筛选 / 拖拽 / 批量 / 媒体 / ⌘K =====
└── export default { fetch, scheduled } / export class DirStore
```

关键实现点：

- **DO 串行化 KV 改写**：数据库条目超过上限、缓存不可用时，由 DO 内部串行执行 upsert / remove / rename，避免并发 RMW 丢更新；
- **Range 合成**：支持 `bytes=` 多段范围与 `If-Range`；
- **流式 ZIP**：pull 驱动的状态机，每次只读一块，内存占用与文件数无关；
- **分享 once 原子消费**：DO 计数，Range / HEAD / 并发请求都不能绕过；
- **签名 URL**：HMAC-SHA256，常量时间比较，可选 IP 绑定；
- **定时任务**：分步 try/catch，任一步失败不影响后续步骤。

---

## 项目文件

| 文件 | 大小 / 行数 | 说明 |
|---|---|---|
| `_workers.js` | 769,493 bytes / 12,719 行 | **主交付物**：单文件 Worker（v5.2.0） |
| `index-v2.html` | 182,222 bytes / 2,672 行 | 苹果风可交互展示页（本项目配套） |
| `index.html` | 97,389 bytes | 展示页第一版（作者原版，保留不覆盖） |
| `_workers.js.bak-20261109-012824` | 795,494 bytes / 13,279 行 | 修复前备份，用于回滚 |
| `README.md` | 本文件 | 项目说明 |

相关文档 / 测试（位于开发工作区，未随展示页目录分发）：

```text
review/FIX-REPORT.md         # 代码审查修复报告（逐项对照 + 验证）
review/REVIEW-REPORT.md      # 原始审查基线
review/findings-*.md         # 分域审查明细
lead-crosscut.md             # 跨域问题汇总
fix/smoke.mjs                # 基础冒烟测试（101/101）
fix/smoke-extra.mjs          # 对抗扩展测试（104/104，3 项 OBSERVE）
fix/diff.patch               # 197 hunk 的修复补丁
```

> 回滚方法：把 `_workers.js.bak-20261109-012824` 覆盖 `_workers.js`，重新部署即可。

---

## 展示页

本目录包含一个与 Worker 能力对应的**静态展示页** `index-v2.html`，纯 HTML / CSS / JS 单文件，**零外部依赖**，离线可直接打开：

- **风格**：苹果发布会式一页式页面，暗色极光 Hero + 浅色内容区 + 深色安全章节；系统字体栈（SF Pro / 苹方）；
- **动画**：滚动进度、导航玻璃化、滚动进入（位移 + 模糊 + 错开）、数字滚动、条 / 环形动画、Hero 鼠标视差、无限 marquee、TOTP 倒计时环、流水线流动；
- **交互**：
  - `⌘K` / `Ctrl+K` 全局命令面板（11 条命令，可搜索、↑↓ 选择、Enter 执行）；
  - 可筛选的 41 项功能矩阵（7 类）；
  - 交互式 Demo：列表 / 网格切换、侧栏筛选、文件预览弹窗、模拟上传队列；
  - API 三标签示例（REST / WebDAV / 分享公开页）+ 一键复制；
  - 安全清单：6 项可勾选，进度条 + `localStorage` 持久化；
  - 右侧章节快捷点导航（桌面端）、主题三态切换、移动端菜单；
- **响应式**：390 / 600 / 768 / 820 / 860 / 900 / 1024 / 1100 / 1280 / 1440 均验证无横向溢出；
- **无障碍**：语义化标签、键盘焦点、`prefers-reduced-motion` 降级；
- **验证**：Chrome DevTools Protocol 自检通过 11 项（无 console 异常、无重复 id、筛选 / API 标签 / 清单持久化 / 圆点导航 / 主题切换 / 预览弹窗等）。

打开方式：

```bash
# 直接双击文件，或
start index-v2.html            # Windows
open index-v2.html             # macOS
```

展示页中所有交互均为前端模拟，不会请求你的 Worker，也不包含任何真实凭据。

`index.html` 是作者的第一版展示页，保持原样未动；如需替换，可自行重命名。

---

## 验证与测试

### 语法检查

```bash
node --check _workers.js
```

> 当前版本通过；内联前端脚本也已单独抽出做 `node --check`。

### Mock 端到端测试

测试脚本使用内存版 R2 / KV / DO 模拟 Cloudflare 运行时，不依赖真实账号：

```bash
# 在开发工作区中（测试脚本会读取 _w.mjs / _w2.mjs 副本）
export DRIVE_PASSWORD="test-pass-123"     # Windows PowerShell: $env:DRIVE_PASSWORD="test-pass-123"
node fix/smoke.mjs           # 基础冒烟：101/101
node fix/smoke-extra.mjs     # 对抗扩展：104/104，3 项 OBSERVE
```

覆盖内容包括：

- 登录 / TOTP / 会话 / 令牌 / 改密吊销；
- 上传 / 分片 / 断点 / 秒传 / 配额；
- 下载 Range / 流式 ZIP / 解压；
- 分享权限 / 一次性 / 次数 / 评论；
- 目录锁 / 内部命名空间 / 路径穿越；
- WebDAV / 备份链 / 恢复 / 孤儿扫描；
- 媒体令牌的可读 / 不可写 / 伪造拒绝；
- 限流与预算。

> 这是**行为级回归测试**，不能替代真实 Cloudflare 环境压测。测试中的 3 项 OBSERVE 为已知产品语义（见残余风险表）。

### 安全审查

- 原始审查：6 个领域的独立审查报告（`review/findings-*.md`）；
- 修复后复测：见 `review/FIX-REPORT.md` 第 5 节（两轮验证 + 第三轮残余架构项）；
- 建议：上线前按「首次配置建议」与展示页中的安全清单逐项确认。

---

## 版本历史

> 以下按当前代码能力整理，详细逐项记录以 `review/FIX-REPORT.md` 与代码头注释为准。

### v5.2.0（当前）

- 文件优先的扁平密排 UI，移动端底部标签栏 + 手势；
- 四视图 + 虚拟滚动、⌘K 命令面板；
- 媒体能力：Office / PDF 预览、音乐播放器、相册 EXIF、相似图片、图片批处理；
- 安全与数据传输加固：PBKDF2、TOTP 防重放、媒体令牌、备份链完整性、逐设备注销；
- 101 项基础冒烟 + 104 项对抗扩展测试通过。

### v5.1.2

- 系统性代码审查：24 项安全 / 数据完整性修复（H1-H4、M1-M7、L1-L5）；
- 197 hunk、+946 / −1,506 行；删除 1,089 行重复前端代码。

### v5.1.0

- WebDAV 挂载与导入、增量备份与差异预览、收藏分组、元数据导入导出；
- 目录级规则、定时任务、健康自检。

### v5.0.0

- 单文件重构：R2 + KV + Durable Object 架构；
- KV / R2 防爆预算、流式 ZIP、断点续传、秒传。

---

## 常见问题

**Q：文件存在哪里？我真的拥有它们吗？**  
A：文件存在你自己的 R2 桶里，元数据在你自己的 KV 命名空间里。Worker 只是访问入口，不经过第三方服务；你可以随时导出、迁移或删除整个桶。

**Q：为什么坚持单文件？**  
A：部署体验是产品的一部分：粘贴即上线，不需要 Node、构建缓存或依赖审计。代价是仓库内需要更严格的分区与测试，这一点由分区注释、200+ 项断言和审查记录补足。

**Q：免费额度够用吗？**  
A：个人使用通常足够。项目内置了 KV 写预算、遥测预算、R2 体积上限、版本 / 回收站自动回收等"防爆"机制，避免误把额度刷爆；超限时会优先"省着用"或明确报错，而不是静默失败。

**Q：能当团队盘用吗？**  
A：它是单管理员设计，没有多用户账号体系。团队场景可以给成员签发只读 / 读写访问令牌，或通过分享链接、上传链接、公开上传页协作。

**Q：手机能用吗？**  
A：可以。响应式前端、PWA 安装、系统分享面板直接上传、移动端手势、离线只读浏览。

**Q：Durable Object 必须绑定吗？**  
A：不必须。不绑定会自动回退 KV，但绑定后并发目录写入更稳（DO 串行化 RMW），建议绑定。

**Q：如何迁移到另一台 Cloudflare 账号 / 另一个域名？**  
A：R2 对象可以复制到新桶，KV 可以导出导入；或者直接用 R2 / KV 的迁移工具，绑定到新 Worker 即可。路径就是对象 key，迁移不需要转换格式。

**Q：如何升级？**  
A：替换 `_workers.js` 并重新部署；部署后访问 `/api/version` 确认，再打开页面看状态栏版本号是否更新。升级前建议先做一次备份。

**Q：数据安全吗？**  
A：默认值已经做了多层防护（见安全模型），但这不是经过独立第三方审计的安全产品；请按自己的风险模型使用，并保持 TOTP、备份与访问令牌卫生。

**Q：能把页面部署到别处吗？**  
A：`index-v2.html` 是纯静态单文件，可以放到任何静态托管（Cloudflare Pages、GitHub Pages、本地文件）上。

---

## 路线图

按优先级大致排列，均未承诺时间：

- [ ] **多用户与权限组**：在保持单管理员简单性的前提下，增加有限成员与目录级授权；
- [ ] **全文搜索索引**：为文本类文件建立可选索引，让 ⌘K 支持按内容搜索；
- [ ] **桌面同步客户端**：基于现有 API / WebDAV 提供增量同步；
- [ ] **流式 multipart 上传**：支持 500MB 单请求，去除简单上传的 100MB 限制；
- [ ] **DO 配额预留**：把配额检查做成原子操作；
- [ ] **备份流式写入**：支持超大元数据树；
- [ ] **移除 `?token=` 会话令牌兼容**：仅保留签名直链与媒体令牌；
- [ ] **更完整的端到端加密产品形态**（如需要）。

---

## 贡献指南

欢迎提交改进，但请遵守这个项目的核心约束：

1. **保持单文件**：除非有充分理由，不拆分构建链、不新增 npm 运行时依赖；
2. **保持可部署**：修改后至少 `node --check _workers.js`，并尽量补充 smoke 用例；
3. **安全默认值**：新增端点默认需要鉴权，公开路由必须限流并考虑输入上限；
4. **不破坏部署兼容**：环境变量与面板配置的优先级、旧单位兼容需要保持；
5. **更新版本号**：修改后同步更新文件头、`/api/version` 可读的版本与 UI build；
6. **描述清楚**：PR / 提交信息说明"改了什么、为什么、如何验证"，涉及安全修复请不要公开利用细节。

如果你要提交较大的架构改动，建议先开 issue 讨论边界，避免做成一个"另一个项目"。

---

## 安全披露

如果你发现安全问题：

- 请**不要**在公开 issue 中贴出可直接利用的 PoC；
- 通过作者提供的私密渠道报告，附上版本、复现步骤、影响范围；
- 在修复发布前，请给项目合理的处理时间。

这个项目维护者为个人，响应时间可能有限，但会认真对待每一份报告。

---

## 许可与免责声明

- 本仓库**未附带开源许可证（LICENSE）**。在没有明确授权的情况下，请勿公开再分发或商用；你可以在自己的 Cloudflare 账号内部署和使用。
- 代码按"现状"提供，不附带任何明示或暗示的担保。因使用本项目造成的数据丢失、费用、服务中断或合规问题，由使用者自行承担。
- 使用 Cloudflare Workers / R2 / KV / Durable Object 时，还需遵守 Cloudflare 的服务条款与计费规则。
- 前端预览功能会按需从公共 CDN 加载部分开源库（marked、DOMPurify、highlight.js、qrcode、exifreader、chart.js、XLSX、mammoth、PDF.js 等）；请自行确认目标环境的 CSP 与合规要求，相关库版权归各自作者。
- 如果你要公开分发本项目，请先补上合适的许可证，并保留安全说明与免责声明。

---

## 致谢

- [Cloudflare Workers](https://developers.cloudflare.com/workers/)、[R2](https://developers.cloudflare.com/r2/)、[KV](https://developers.cloudflare.com/kv/)、[Durable Objects](https://developers.cloudflare.com/durable-objects/) —— 让「一个文件的后端」成为可能；
- 所有为此项目做过代码审查、测试与反馈的人；
- 前端媒体预览所依赖的开源库作者。

---

<p align="center">
  <sub>Built with a single file, and a lot of care.</sub><br>
  <sub>CloudDrive · Personal Drive v5.2.0 · flat-1</sub>
</p>
