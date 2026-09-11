# ☁️ CF-KVR2-NetworkCloud

> 一个文件，一个 Cloudflare Worker，一个属于你自己的云。

基于 Cloudflare Workers + R2 + KV 构建的个人网盘，无需服务器、无需数据库、无需构建工具。把 `_workers.js` 粘贴进 Workers 编辑器，配好 Bindings，点击部署——你的网盘就上线了。

**Live Demo** → [cloud.bjhr.space](https://cloud.bjhr.space)

---

## ✨ 为什么做这个

市面上的网盘要么贵、要么慢、要么审查你的文件。Cloudflare 免费层给你 10GB R2 存储 + 10万次/天 Worker 请求，速度覆盖全球，数据完全在你手里。一个 JS 文件就能跑起来，不用 Docker、不用 VPS、不用维护。

适合：个人文件备份、跨设备同步、给家人分享照片、挂 WebDAV 当本地盘用。

---

## 🎯 功能一览

### 📁 文件管理

| 功能 | 说明 |
|------|------|
| 上传 | 拖拽 / 点击 / 粘贴截图 / 文件夹整体上传 / 大文件分片（5MB chunks） |
| 预览 | 图片 / 视频 / 音频 / 文本 / Markdown 渲染 / PDF 在线查看 / 代码高亮 |
| 编辑 | 文本文件在线编辑，保存即覆盖，自动保留历史版本（最多5个） |
| 操作 | 重命名 / 移动 / 复制 / 删除 / 批量操作 / 批量重命名（支持 `{n}` `{d}` 模式） |
| 压缩 | 上传前客户端图片压缩（>2048px 自动缩放）/ ZIP 打包下载 / ZIP 解压 |
| 去重 | 上传时自动检测同名同大小文件，跳过重复 |
| 加密 | 客户端 AES-256-GCM 加密，密钥只在你浏览器里，服务端只看到密文 |

### 🔗 分享与协作

| 功能 | 说明 |
|------|------|
| 分享链接 | 设定有效天数 + 最大访问次数 + 可选密码，支持二维码 |
| 上传链接 | 让别人往你的文件夹上传，不需要登录你的网盘 |
| 文件夹加密 | 给任意文件夹设密码，访问需解锁 |
| 访问令牌 | 生成独立 Token（只读/读写），用于 API 调用或 WebDAV 挂载 |

### 🎵 媒体增强

| 功能 | 说明 |
|------|------|
| 音乐播放 | 连续播放列表，自动切歌，上一首/下一首 |
| 图片幻灯片 | 全屏轮播 + EXIF 信息（相机/光圈/快门/ISO/焦距） |
| 视频截图 | 播放中一键截取当前帧保存为 PNG |
| Markdown | 实时渲染 + 原文切换，支持表格/代码块/引用 |
| PDF | 在线渲染（PDF.js），无需下载即可查看 |

###  WebDAV

把网盘挂载为本地磁盘。支持 Windows 资源管理器、macOS Finder、Raidrive、Cyberduck 等客户端。

```
协议: WebDAV (Class 1, 2)
端点: https://yourdomain.com/dav/
认证: Bearer Token
方法: PROPFIND / GET / PUT / DELETE / MKCOL / OPTIONS
```

### 📊 管理面板

| 功能 | 说明 |
|------|------|
| 目录树 | 侧栏递归展示，支持拖拽文件到目录移动 |
| 标签系统 | 给文件打彩色标签，按标签筛选 |
| 收藏 / 最近 | 快速访问常用文件 |
| 活动日志 | 记录最近 200 条操作（上传/删除/分享） |
| 存储统计 | 用量环形图 + 文件数 + 操作计数 |
| 重复检测 | 按文件 hash 查找重复文件 |
| 回收站 | 删除进回收站，30天自动清理，支持批量恢复/彻底删除 |

### 🎨 界面

- Apple / macOS Sonoma 风格 UI
- 深色 / 浅色 / 跟随系统 三档主题
- 列表 / 网格 两种视图
- 中英双语（自动记忆）
- 移动端完全适配
- 键盘快捷键：`Ctrl+A` 全选 / `Delete` 删除 / `F2` 重命名 / `Backspace` 返回上级 / `Ctrl+F` 搜索
- 右键上下文菜单

---

## 🏗️ 技术架构

```
┌─────────────────────────────────────────────────────┐
│                  Cloudflare Edge                      │
├─────────────────────────────────────────────────────┤
│                                                       │
│   _workers.js (单文件 ~3400 行)                       │
│   ┌─────────────────────────────────────────┐        │
│   │  Router (fetch / scheduled)              │        │
│   ├─────────────────────────────────────────┤        │
│   │  API Handlers                            │        │
│   │  upload / download / zip / share /       │        │
│   │  tags / notes / versions / WebDAV / ...  │        │
│   ├─────────────────────────────────────────┤        │
│   │  Storage Layer                           │        │
│   │  R2 (文件) + KV (元数据) + DO (缓存)     │        │
│   ├─────────────────────────────────────────┤        │
│   │  Frontend (HTML Template)                │        │
│   │  CSS + JS 全部内联，零外部构建           │        │
│   └─────────────────────────────────────────┘        │
│                                                       │
├──────────┬──────────────┬────────────────────────────┤
│ R2       │ Workers KV   │ Durable Object (optional)  │
│ 文件存储  │ 元数据/索引   │ 目录缓存/用量统计           │
└──────────┴──────────────┴────────────────────────────┘
```

**存储模型：**

- **R2** — 实际文件二进制，无出口流量费
- **KV** — 目录索引 (`dir:/path/`)、会话、标签、备注、分享链接、活动日志、用量统计
- **DO (可选)** — 热目录缓存 + 原子用量计数，不配也能跑（自动降级到 KV）

**前端 CDN 依赖（全部 defer，加载失败不崩）：**

- marked.js — Markdown 渲染
- highlight.js — 代码高亮
- PDF.js v4 (ESM) — PDF 预览（动态 import）
- Chart.js — 统计图表
- QRCode.js — 分享二维码
- ExifReader — 图片 EXIF 读取

---

## 🚀 部署指南

### 前提

- Cloudflare 账号（免费即可）
- 一个域名托管在 Cloudflare DNS（可选，用 Workers 子域也行）

### Step 1：创建 R2 存储桶

Dashboard → R2 Object Storage → Create Bucket → 命名 `drive`（或任意名称）

### Step 2：创建 KV 命名空间

Dashboard → Workers → KV → Create Namespace → 命名 `STORE`

### Step 3：创建 Durable Object（可选）

`wrangler.toml` 中配置：

```toml
[durable_objects]
bindings = [{ name = "DIR", class_name = "DirStore" }]

[[migrations]]
tag = "v1"
new_classes = ["DirStore"]
```

> 不配置也能用，系统会自动降级为纯 KV 模式。

### Step 4：创建 Worker

Dashboard → Workers → Create → 粘贴 `_workers.js` 内容 → Deploy

### Step 5：绑定资源

Worker Settings → Bindings → Add：

| 类型 | 变量名 | 绑定到 |
|------|--------|--------|
| R2 Bucket | `DRIVE` | 你创建的 bucket |
| KV Namespace | `STORE` | 你创建的 namespace |
| Durable Object | `DIR` | 你创建的 DO（可选） |

### Step 6：环境变量

Settings → Variables：

| 变量 | 值 | 说明 |
|------|----|------|
| `DRIVE_PASSWORD` | 你的密码 | 登录用，必须设 |
| `DRIVE_TITLE` | 我的网盘 | 页面标题（可选） |
| `DRIVE_LOGO` | ☁️ | 左上角图标（可选） |

### Step 7：绑定域名

Settings → Domains & Routes → Add Route：

```
drive.yourdomain.com  →  your-worker-name
```

访问域名，输入密码，开始使用。

### 定时清理（推荐）

Settings → Triggers → Cron Schedules → `0 3 * * *`

每天凌晨 3 点自动清理回收站中超期文件。

---

## 📐 配额参考

| 项目 | 免费版 | 付费版 ($5/mo) |
|------|--------|----------------|
| Worker 请求 | 10 万/天 | 无限 |
| R2 存储 | 10 GB | 10 GB + $0.015/GB·月 |
| R2 Class A 操作 (写) | 100 万/月 | $4.50/百万 |
| R2 Class B 操作 (读) | 1000 万/月 | $0.36/百万 |
| KV 读取 | 10 万/天 | $0.50/百万 |
| KV 写入 | 1000/天 | $5.00/百万 |
| 出口流量 | $0 (R2 无出口费) | $0 |

个人使用免费版绑绑有余。

---

## 🔧 开发说明

单文件架构，没有构建步骤。修改流程：

1. 编辑 `_workers.js`
2. 粘贴到 Workers 编辑器（或 `wrangler deploy`）
3. 部署即生效

文件内部分区：

```
// ===== Helpers =====          工具函数
// ===== Durable Object =====   DO 类定义
// ===== Dir 访问层 =====       KV/DO 双写抽象
// ===== Recent & Favorites ===== 收藏/最近
// ===== Auth =====             认证
// ===== API =====              所有后端 handler
// ===== WebDAV =====           WebDAV 协议
// ===== Frontend =====         HTML 模板（含 CSS + 客户端 JS）
// ===== Router =====           路由入口
```

---

## 🛡️ 安全设计

- 密码认证 + 7天 Session Token（sessionStorage 存储，非 Cookie）
- 所有用户输入 HTML 转义（防 XSS）
- 路径规范化 + `..` 解析（防路径穿越）
- 文件名 sanitize（过滤非法字符）
- 文件夹独立密码（bcrypt-like SHA256 hash 存储）
- 分享链接可设密码 + 访问次数限制
- 客户端加密：PBKDF2 派生密钥 + AES-256-GCM，服务端零知识
- WebDAV 使用独立 Bearer Token，可设只读权限

---

## 📝 更新日志

### v5.1
- 新增 WebDAV 协议支持
- 新增多令牌管理（只读/读写）
- 新增音乐播放列表、图片幻灯片 + EXIF、视频截图
- 新增 PDF 在线预览、上传前图片压缩、上传去重
- 新增批量重命名 UI、活动日志、统计图表
- 新增树目录拖拽移动、PWA 支持
- 工具栏重新分组排版

### v5.0
- 标签系统 UI + 筛选
- Markdown 渲染 + 代码语法高亮
- 粘贴上传 (Ctrl+V)
- 键盘快捷键
- 右键菜单增强
- AES-GCM 客户端加密
- 文件备注
- 重复文件检测 UI

### v4.4
- 分享链接访问计数修复
- 工具栏布局优化

---

## 💬 联系

- GitHub: [@BlueDriftHK](https://github.com/BlueDriftHK)
- X: [@BlueDriftHK](https://x.com/BlueDriftHK)
- Telegram: [@BlueDriftHK](https://t.me/BlueDriftHK)

---

## License

[AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) — 如果你 fork 或修改后部署了，必须开源你的版本。
