<div align="center">

# ☁️ CF-KVR2-NetworkCloud

**一个文件，一个 Worker，一个属于你自己的云。**

`~3400 行 JavaScript` · `零构建` · `零服务器` · `全球边缘部署`

[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-orange)](https://workers.cloudflare.com)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-green)]()
[![File Size](https://img.shields.io/badge/Size-~190KB-yellow)]()

[功能](#-功能全景) · [部署](#-快速部署) · [架构](#-技术架构) · [API](#-api-端点) · [WebDAV](#-webdav-挂载) · [FAQ](#-常见问题)

**Live Demo** → [cloud.bjhr.space](https://cloud.bjhr.space)

</div>

---

## 💡 为什么做这个

市面上的网盘要么贵（iCloud 200GB 要 ¥21/月），要么慢（国内某盘限速到 KB/s），要么不放心（你的照片别人也能看）。

Cloudflare 免费层给你：

| 资源 | 免费额度 |
|------|----------|
| Worker 请求 | 10 万次/天 |
| R2 存储 | 10 GB |
| R2 写入操作 | 100 万/月 |
| R2 读取操作 | 1000 万/月 |
| 出口流量 | **$0**（R2 无出口费） |
| KV 读取 | 10 万/天 |

个人使用绑绑有余。全球 300+ 边缘节点，从东京到纽约都是毫秒级响应。数据完全在你手里，没人审查、没人限速、没人删你文件。

**适合场景：** 个人文件备份、跨设备同步、给家人分享照片、WebDAV 挂载当本地盘、代码项目存档、临时文件交换。

---

## 🎯 功能全景

### 📁 文件管理

| 功能 | 说明 |
|------|------|
| 上传 | 拖拽 / 点击 / `Ctrl+V` 粘贴截图 / 整个文件夹上传 / 大文件自动分片 (5MB chunks) |
| 预览 | 图片 / 视频 / 音频 / 文本 / Markdown 渲染 / PDF 在线 / 代码高亮 (hljs) |
| 编辑 | 文本文件在线编辑，保存即覆盖，自动保留最多 5 个历史版本 |
| 操作 | 重命名 / 移动 / 复制 / 删除 / 批量操作 / 批量重命名 (`{n}` 序号 `{d}` 日期) |
| 压缩 | 上传前客户端图片压缩 (>2048px 自动缩放) / ZIP 打包下载 / ZIP 在线解压 |
| 去重 | 上传时自动检测同名同大小文件，跳过重复 |
| 加密 | 客户端 AES-256-GCM，密钥只在你浏览器里，服务端只看到密文 `.enc` |
| 回收站 | 删除进回收站，30 天自动清理，支持恢复 / 批量彻底删除 |

### 🔗 分享与协作

| 功能 | 说明 |
|------|------|
| 分享链接 | 设定有效天数 + 最大访问次数 + 可选密码，自动生成二维码 |
| 上传链接 | 让别人往你的文件夹上传文件，不需要登录你的网盘 |
| 文件夹加密 | 给任意文件夹设独立密码，访问需解锁 |
| 访问令牌 | 生成独立 Token（只读 / 读写权限），用于 API 或 WebDAV |
| 文件备注 | 给任意文件添加文字说明，KV 存储 |

### 🎵 媒体增强

| 功能 | 说明 |
|------|------|
| 音乐播放 | 连续播放列表，自动切歌，上一首/下一首，进度条 |
| 图片幻灯片 | 全屏轮播 (4s 间隔) + EXIF 信息（相机/光圈/快门/ISO/焦距/尺寸） |
| 视频截图 | 播放中一键截取当前帧保存为 PNG |
| Markdown | 实时渲染 + 原文切换，支持表格/代码块/引用/图片 |
| PDF | PDF.js 在线渲染（最多 50 页），无需下载即可查看 |

### 📊 管理面板

| 功能 | 说明 |
|------|------|
| 目录树 | 侧栏递归展示，支持拖拽文件到目录树直接移动 |
| 标签系统 | 给文件打彩色标签，侧栏按标签筛选 |
| 收藏 / 最近 | 快速访问常用文件 |
| 活动日志 | 记录最近 200 条操作（上传/删除/分享），带时间线 |
| 存储统计 | 用量环形图 (Chart.js) + 文件数 + 剩余空间 |
| 重复检测 | 按文件 hash 查找重复文件，分组展示 |

### 🎨 界面体验

| 特性 | 说明 |
|------|------|
| 设计风格 | Apple / macOS Sonoma 风格，毛玻璃卡片，SF Pro 字体 |
| 主题 | 深色 / 浅色 / 跟随系统 三档，一键切换 |
| 视图 | 列表 / 网格 两种布局 |
| 语言 | 中文 / English 双语，自动记忆偏好 |
| 响应式 | 移动端完全适配，侧栏折叠为汉堡菜单 |
| 快捷键 | `Ctrl+A` 全选 · `Delete` 删除 · `F2` 重命名 · `Backspace` 返回 · `Ctrl+F` 搜索 |
| 右键菜单 | 下载 / 分享 / 标签 / 备注 / 加密 / 历史 / 重命名 / 移动 / 删除 |
| PWA | 支持添加到手机桌面 |

---

## 🚀 快速部署

> 从零到上线，5 分钟。

### 前提

- Cloudflare 账号（免费注册）
- 可选：一个托管在 CF DNS 的域名

### Step 1 — 创建存储

```
Dashboard → R2 → Create Bucket → 命名 "drive"
Dashboard → Workers → KV → Create Namespace → 命名 "STORE"
```

### Step 2 — 创建 Worker

```
Dashboard → Workers → Create Worker → 粘贴 _workers.js → Deploy
```

### Step 3 — 绑定资源

Worker Settings → Bindings → Add：

| 类型 | 变量名 | 绑定到 | 必须 |
|------|--------|--------|------|
| R2 Bucket | `DRIVE` | drive | ✅ |
| KV Namespace | `STORE` | STORE | ✅ |
| Durable Object | `DIR` | DirStore | ⬜ 可选 |

### Step 4 — 设置密码

Settings → Variables and Secrets → Add：

```
DRIVE_PASSWORD = 你的密码
DRIVE_TITLE    = 我的网盘        (可选)
DRIVE_LOGO     = ☁️              (可选)
```

### Step 5 — 绑定域名（可选）

Settings → Domains & Routes：

```
drive.yourdomain.com → your-worker-name
```

### Step 6 — 定时清理（推荐）

Settings → Triggers → Cron：

```
0 3 * * *    ← 每天凌晨3点清理回收站超期文件
```

**完成。** 打开域名，输入密码，开始用。

### Wrangler CLI 部署（进阶）

```bash
# wrangler.toml
name = "network-cloud"
main = "_workers.js"

[vars]
DRIVE_TITLE = "我的网盘"

[[r2_buckets]]
binding = "DRIVE"
bucket_name = "drive"

[[kv_namespaces]]
binding = "STORE"
id = "your-kv-namespace-id"

[durable_objects]
bindings = [{ name = "DIR", class_name = "DirStore" }]

[[migrations]]
tag = "v1"
new_classes = ["DirStore"]

[triggers]
crons = ["0 3 * * *"]
```

```bash
npx wrangler deploy
```

---

## 🏗️ 技术架构

```
┌────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge Network                   │
│                     300+ PoP 全球节点                        │
├────────────────────────────────────────────────────────────┤
│                                                              │
│   _workers.js (单文件 ~3400 行，~190KB)                      │
│                                                              │
│   ┌────────────────────────────────────────────────────┐    │
│   │  Router: fetch() + scheduled()                      │    │
│   ├────────────────────────────────────────────────────┤    │
│   │  API Handlers (30+ endpoints)                       │    │
│   │  upload / download / zip / share / tags / notes /   │    │
│   │  versions / duplicates / WebDAV / tokens / stats    │    │
│   ├────────────────────────────────────────────────────┤    │
│   │  Storage Abstraction Layer                          │    │
│   │  DO 优先 (3s 超时) → KV 兜底 → R2 读写              │    │
│   ├────────────────────────────────────────────────────┤    │
│   │  Frontend: HTML Template Literal                    │    │
│   │  内联 CSS (Apple 风格) + 内联 JS (SPA)              │    │
│   │  外部 CDN: marked / hljs / pdfjs / chart / qrcode   │    │
│   └────────────────────────────────────────────────────┘    │
│                                                              │
├──────────────────────────────────┬─────────────────────────┤
│   R2 Bucket    │   Workers KV     │  Durable Object         │
│   文件二进制    │   元数据/索引     │  (可选) 目录缓存        │
│   无出口流量费  │   会话/标签/日志  │  原子用量计数           │
└──────────────────────────────────┴─────────────────────────┘
```

### KV 存储结构

| Key 模式 | 内容 |
|----------|------|
| `dir:/path/` | 目录索引 JSON 数组 |
| `session:<ts>:<random>` | 登录会话 |
| `share:<token>` | 分享链接配置 |
| `tags:<filepath>` | 文件标签 |
| `note:<filepath>` | 文件备注 |
| `dirpass:<path>` | 文件夹密码 hash |
| `meta:usage` | 用量统计 |
| `meta:log` | 活动日志 (max 200) |
| `meta:tags` | 全局标签注册表 |
| `meta:tokens` | 访问令牌列表 |
| `.thumb/<key>` | 缩略图 |
| `.versions/<key>/<ts>` | 历史版本 |

---

## 📡 API 端点

所有 API 需 `?token=<session>` 认证（分享和上传链接除外）。

| Method | Endpoint | 说明 |
|--------|----------|------|
| POST | `/api/login` | 密码登录，返回 token |
| GET | `/api/list?path=` | 列目录 |
| POST | `/api/upload?path=` | 上传文件 |
| GET | `/api/download?path=` | 下载文件 |
| GET | `/api/preview?path=` | 预览（inline） |
| GET | `/api/thumb?path=` | 缩略图 |
| POST | `/api/save?path=` | 保存文本 |
| DELETE | `/api/delete?path=` | 删除（进回收站） |
| POST | `/api/batch-delete` | 批量删除 |
| PUT | `/api/rename` | 重命名 |
| PUT | `/api/move` | 移动 |
| POST | `/api/mkdir?path=` | 创建目录 |
| GET | `/api/search?q=&path=` | 搜索 |
| GET | `/api/tree` | 目录树 |
| GET | `/api/zip?path=` | 打包下载 |
| POST | `/api/unzip` | 解压 |
| POST | `/api/share` | 创建分享链接 |
| POST | `/api/upload-link-create` | 创建上传链接 |
| POST | `/api/folder-pass` | 设置/移除文件夹密码 |
| GET | `/api/trash` | 回收站列表 |
| POST | `/api/restore` | 恢复文件 |
| DELETE | `/api/purge` | 彻底删除 |
| GET | `/api/versions?path=` | 历史版本列表 |
| POST | `/api/versions/restore` | 恢复版本 |
| POST | `/api/tag` | 设置文件标签 |
| GET | `/api/tags` | 标签列表/筛选 |
| GET/POST | `/api/note` | 文件备注 |
| GET | `/api/duplicates` | 重复检测 |
| GET | `/api/usage` | 用量统计 |
| GET | `/api/log` | 活动日志 |
| GET/POST/DELETE | `/api/tokens` | 令牌管理 |
| GET | `/api/stats` | 统计数据 |
| POST | `/api/chunk-init` | 分片上传初始化 |
| POST | `/api/chunk-upload/:id/:idx` | 上传分片 |
| POST | `/api/chunk-complete` | 完成分片组装 |

---

## 🔌 WebDAV 挂载

把网盘变成本地磁盘。

### 配置方法

1. 打开网盘 → 点 **🔑 令牌** → 创建一个 Token（权限选 Read+Write）
2. 复制生成的 Token
3. 在你的 WebDAV 客户端配置：

| 参数 | 值 |
|------|----|
| URL | `https://yourdomain.com/dav/` |
| 认证方式 | Bearer Token |
| Token | 你复制的那个 |

### 各平台挂载

**Windows：** 此电脑 → 映射网络驱动器 → 输入 URL + Token

**macOS：** Finder → 前往 → 连接服务器 → `https://yourdomain.com/dav/`

**Raidrive（推荐）：** 添加云存储 → WebDAV → 填 URL + Bearer Token

**Cyberduck：** 打开连接 → 协议选 WebDAV → 填信息

### 支持的操作

- ✅ 浏览目录 (PROPFIND)
- ✅ 下载文件 (GET)
- ✅ 上传文件 (PUT)
- ✅ 创建文件夹 (MKCOL)
- ✅ 删除文件/目录 (DELETE)
- ⬜ 重命名/移动 (MOVE) — 未来版本

---

## 🛡️ 安全设计

| 层面 | 措施 |
|------|------|
| 认证 | 密码 → Session Token (7天有效) → sessionStorage 存储 |
| XSS 防护 | 所有用户输入 `escHtml()` 转义后拼入 DOM |
| 路径穿越 | `normPath()` 解析 `..`，限制在根目录内 |
| 文件名注入 | `sanitizeName()` 过滤 `\ / : * ? " < > | \x00-\x1f` |
| 文件夹锁 | SHA-256 hash 存储，解锁后 session 内免密 |
| 分享安全 | 链接可设密码 + 访问次数上限 + 过期自动失效 |
| 客户端加密 | PBKDF2 (100K iterations) → AES-256-GCM，服务端零知识 |
| WebDAV | 独立 Bearer Token，可设只读，不暴露主密码 |
| 令牌管理 | 可随时撤销，支持过期时间 |

---

## ❓ 常见问题

**Q: 免费版够用吗？**
A: 10GB R2 + 10万请求/天，日常存文档、照片完全够用。视频多了可能超存储，但请求量很难超。

**Q: 为什么 R2 不要出口流量费？**
A: Cloudflare R2 的设计就是零 egress 费。这是它比 S3 + CloudFront 便宜的核心原因。

**Q: 不配 Durable Object 能用吗？**
A: 完全可以。DO 只是缓存加速层，不配的话所有操作走 KV，功能不受影响，只是大目录加载稍慢。

**Q: 怎么备份数据？**
A: R2 控制台可以直接浏览和下载文件。或者用 WebDAV 挂载后 `rsync`。

**Q: 上传大文件限制？**
A: Worker 请求体上限 100MB（付费版）。超过 5MB 的文件自动走分片上传，理论无上限。

**Q: 为什么用 AGPL 而不是 MIT？**
A: 如果你 fork 了这个项目部署给别人用，你需要开源你的修改。自用不限。

**Q: 能多用户吗？**
A: 当前是单密码模式。可以通过创建多个只读令牌实现"分享访问"，但没有独立用户空间。

---

## 📝 更新日志

### v5.1 — 2026.09.11

- ✨ 新增 WebDAV 协议支持 (`/dav/`)
- ✨ 新增多令牌管理（只读/读写权限）
- ✨ 新增音乐播放列表（连续播放 + 上下曲）
- ✨ 新增图片幻灯片 + EXIF 信息展示
- ✨ 新增视频帧截图
- ✨ 新增 PDF 在线预览 (PDF.js ESM)
- ✨ 新增上传前图片压缩（客户端 Canvas）
- ✨ 新增上传去重检测
- ✨ 新增批量重命名 UI (`{n}` `{d}` 模式)
- ✨ 新增活动日志面板
- ✨ 新增存储统计图表 (Chart.js)
- ✨ 新增树目录拖拽移动文件
- ✨ 新增 PWA 支持（添加到桌面）
- 🎨 工具栏重新分组排版（浏览/操作/管理三组）

### v5.0 — 2026.09.11

- ✨ 标签系统完整 UI + 侧栏筛选
- ✨ Markdown 渲染 + 代码语法高亮
- ✨ 粘贴上传 (`Ctrl+V`)
- ✨ 键盘快捷键体系
- ✨ 右键菜单增强（标签/备注/加密）
- ✨ 客户端 AES-256-GCM 加密
- ✨ 文件备注功能
- ✨ 重复文件检测 UI

### v4.4

- 🔧 分享链接访问计数修复（覆盖打开页面而非仅下载）
- 🎨 工具栏布局优化

---

## 🗺️ Roadmap

- [ ] 多用户空间（独立文件夹 + 配额）
- [ ] 文件版本 diff 对比
- [ ] 全局搜索增强（文件内容搜索）
- [ ] 移动端手势操作（滑动删除、长按多选）
- [ ] 自定义文件图标
- [ ] 批量下载为 ZIP（跨目录选择）
- [ ] 回收站预览
- [ ] 分享页面自定义样式
- [ ] 文件夹排序（拖拽调整目录树顺序）
- [ ] 国际化扩展（日语、韩语）

---

## 🙏 Acknowledgments

- [Cloudflare Workers](https://workers.cloudflare.com) — 免费全球边缘计算
- [marked.js](https://marked.js.org) — Markdown 渲染
- [highlight.js](https://highlightjs.org) — 代码高亮
- [PDF.js](https://mozilla.github.io/pdf.js/) — PDF 渲染
- [Chart.js](https://www.chartjs.org) — 数据可视化
- [ExifReader](https://exifreader.org) — EXIF 解析

---

<div align="center">

## ☕ 联系

[GitHub](https://github.com/BlueDriftHK) · [X @BlueDriftHK](https://x.com/BlueDriftHK) · [Telegram @BlueDriftHK](https://t.me/BlueDriftHK)

**Made with ☁️ by BlueDriftHK**

</div>
