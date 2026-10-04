# PersonalDrive

> 部署在 Cloudflare Workers 上的私人网盘，单文件 Worker（约 6500 行），R2 + KV + Durable Object 架构，内置完整 Web 前端（Apple / macOS Sonoma 风格，PWA 支持）。
> 当前版本：**v5.1.2**（v5.1.1 代码审查全量修复版）。

PersonalDrive 是一个开箱即用的自托管云盘：把一份 Worker 脚本部署到 Cloudflare，即可获得登录鉴权、目录管理、文件分享、WebDAV 挂载、版本管理、备份恢复等能力。全部代码（前端 + 后端）内嵌在单个 JavaScript 文件中，无需额外构建步骤。

---

## 功能特性

以下功能均来自 v5.1.2 源码实际实现。

### 认证与访问控制

- **管理员密码登录**：使用环境变量 `DRIVE_PASSWORD` 或 KV 中自定义密码（`meta:adminpass`）；无盐历史记录自动迁移为带盐哈希。
- **会话管理**：登录后生成会话 Token（有效期 7 天），支持会话列表查看与按会话撤销。
- **可选 TOTP 两步验证**：登录时额外校验动态验证码（主版本支持，详见"已知限制"中的 nototp 变体说明）。
- **访问令牌**：可生成只读（ro）/ 读写（rw）令牌，用于 API 调用与 WebDAV 认证；Token 通过 `Authorization: Bearer` 请求头传递（兼容 URL 参数）。
- **目录锁**：目录可设置独立密码，解锁后才能访问其内容；分享链路同样受目录锁约束。
- **IP 黑白名单**：可选环境变量 `IP_DENY` / `IP_ALLOW`，基于 `CF-Connecting-IP` 过滤。
- **登录限频**：IP 与用户名双维度限频（5 次失败 / 5 分钟），防密码爆破。
- **Turnstile 人机验证**：可选，需同时配置 `TURNSTILE_SITE_KEY` 与 `TURNSTILE_SECRET`。

### 文件管理

- 上传 / 下载 / 在线预览 / 删除 / 重命名 / 移动（含递归移动目录）。
- 批量操作：批量删除、批量重命名（模式替换）、批量移动、批量分享。
- 回收站：删除进回收站，支持单个/批量恢复与永久清理。
- 目录树、关键词搜索、标签搜索与标签管理、最近访问、收藏夹。
- 文件备注（Note）、客户端加密文件（浏览器端派生密钥加密）。
- 文本在线编辑保存（上限 2MB）。

### 传输与上传增强

- **分片上传与断点续传**：`chunk-init / chunk-upload / chunk-complete`，失败任务保存在浏览器 localStorage，可续传。
- **秒传**：按文件 SHA-256 哈希去重，命中直接生成对象。
- **URL 抓取**：输入远程 URL 直接保存到网盘（10s 超时、最多 5 跳重定向、逐跳 host 校验、`FETCH_MAX_BYTES` 限额、超限回滚）。
- **上传链接**：生成 `{域名}/u/<token>` 匿名上传页，可设有效期与文件数上限。
- **公开上传**：配置 `PUBLIC_UPLOAD_DIR` 后开放 `/upload` 匿名上传页（默认单文件 100MB，可配合 Turnstile 保护）。
- 拖拽上传（含整个目录结构）、上传前图片压缩、缩略图生成。

### 分享与协作

- **分享链接**：文件/目录生成 `{域名}/s/<token>`，支持分享密码、有效期（TTL）、最大访问次数、目录分享；支持批量分享。
- 分享访问受目录锁约束（锁定目录不可分享、分享访问实时校验锁）。
- **相册**：从目录收集图片/视频生成相册页（`/a/<id>`），支持幻灯片放映、播放列表、EXIF 信息与截图。
- 下载统计（按文件维度记录下载次数与明细）。

### 内容处理

- 在线预览：图片 / 视频 / 音频 / PDF / 文本，含 PDF 预览、音频播放列表、图片幻灯片。
- **ZIP 打包与解压**：目录打包下载、多选文件打包、ZIP 解压（上限 50MB）；支持按 MIME 类型的自动解压归档规则。
- **版本管理**：覆盖写入保留历史版本（最多 5 个），可查看与恢复任意历史版本。
- **重复文件检测**：按哈希找出重复文件（哈希组上限 2000）。

### 数据保护与运维

- **全量备份**：一键创建备份、备份列表、下载备份、密码保护恢复。
- **健康检查**：`/api/health` 返回各项绑定/存储检查状态（错误信息已脱敏）。
- **孤儿对象扫描与清理**：扫描未被元数据引用的对象，截断时拒绝清理（防误删）。
- 用量统计与重算、下载统计、访问趋势、操作日志。
- **Webhook 通知**：配置 URL 后触发事件通知（发送前二次校验目标 host）。
- **多后端 S3 镜像**：配置 `DRIVE_BACKENDS` 后，写入对象同步镜像到多个 S3 兼容存储（默认镜像 ≤25MB 文件）。

### WebDAV

- 端点 `{域名}/dav/`，支持挂载到 Windows / macOS / 手机等 WebDAV 客户端。
- 认证方式：用户名任意，密码填 rw 访问令牌。
- WebDAV PUT 单文件上限 100MB，执行配额前置检查与流式写入；GET 返回文件名净化与 `attachment` 语义。

---

## 架构与技术栈

| 组成 | 说明 |
|---|---|
| 运行环境 | Cloudflare Workers（单文件 `export default { fetch }`） |
| 对象存储 | **R2 = DRIVE**：文件内容、缩略图（`.thumb/`）、版本（`.versions/`）、备份（`.backup/`） |
| 元数据存储 | **KV = STORE**：目录列表、会话、分享、上传链接、目录密码、标签、统计、日志、备份索引等 |
| 计数器/目录镜像 | **DO = DIR（可选）**：原子计数（`__counter__:<id>`）、用量统计（`__usage__`）；未配置时自动回退本地/KV 累加 |
| 前端 | 内嵌原生 JavaScript SPA（Apple / macOS Sonoma 风格 UI），支持中英文、明暗主题、PWA（manifest / icon / sw.js） |

### Bindings（wrangler.toml 参考）

```toml
name = "personal-drive"
main = "PersonalDrive_v5.1.2.js"
compatibility_date = "2024-11-01"

[[r2_buckets]]
binding = "DRIVE"
bucket_name = "personal-drive"

[[kv_namespaces]]
binding = "STORE"
id = "<你的 KV namespace id>"

# DO 可选；如启用需声明 migration
[[durable_objects.bindings]]
name = "DIR"
class_name = "DirObject"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["DirObject"]
```

### 环境变量与 Secret

| 变量 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `DRIVE_PASSWORD` | Secret | 推荐 | 管理员登录密码（未配置时首次需通过 KV `meta:adminpass` 设置） |
| `DRIVE_QUOTA` | 变量 | 否 | 总配额字节数，默认 10GB |
| `DRIVE_TITLE` | 变量 | 否 | 站点标题 |
| `DRIVE_LOGO` | 变量 | 否 | 站点 Logo（URL） |
| `PUBLIC_UPLOAD_DIR` | 变量 | 否 | 设置后开启公开上传，值为目标目录路径 |
| `PUBLIC_UPLOAD_MAX` | 变量 | 否 | 公开上传单文件上限（字节），默认 100MB |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET` | 变量 / Secret | 否 | Turnstile 人机验证，两者必须同时配置才生效 |
| `FETCH_MAX_BYTES` | 变量 | 否 | URL 抓取单文件上限（字节） |
| `IP_ALLOW` / `IP_DENY` | 变量 | 否 | IP 白名单 / 黑名单（基于 `CF-Connecting-IP`） |
| `DRIVE_BACKENDS` | Secret | 否 | S3 兼容镜像配置 JSON（数组，字段见下） |

`DRIVE_BACKENDS` 示例（数组或对象均可）：

```json
[
  {
    "id": "backup-s3",
    "endpoint": "https://s3.example.com",
    "bucket": "drive-mirror",
    "accessKey": "AKIA...",
    "secretKey": "xxxx",
    "region": "auto",
    "pathStyle": true,
    "prefix": "mirror/",
    "mirrorMaxBytes": 26214400
  }
]
```

### 关键常量（源码内置）

| 常量 | 值 | 说明 |
|---|---|---|
| `MAX_UPLOAD_SIZE` | 500MB | 单文件上传上限 |
| `UNZIP_MAX_BYTES` | 50MB | ZIP 解压上限 |
| `MAX_VERSIONS` | 5 | 文件历史版本保留数 |
| `SESSION_TTL` | 7 天 | 会话有效期 |
| WebDAV PUT | 100MB | WebDAV 单文件上限（H1 修复） |
| 分片内存拼装 | 50MB | 分片组装内存上限（R5 修复） |
| 文本保存 | 2MB | 在线文本编辑上限（R8 修复） |

---

## 安全特性与 v5.1.2 修复记录

v5.1.2 基于 v5.1.1 代码审查报告（审查范围覆盖认证/授权、路径安全、XSS、SSRF、注入、敏感信息、上传/下载边界、分享链路、分片并发、ZIP 解压、WebDAV、配额与版本、错误处理）完成 **33 处代码替换**，覆盖 H1-H4 / M1-M7 / L1-L5 / R1-R8 全部问题项，修复原则为 **fail-closed、原子计数、流式限额、锁定边界全覆盖**。修复后接口保持兼容，前端与既有 API 调用无需改动。

### 高危（H1-H4）

| 问题项 | 修复内容 |
|---|---|
| H1 WebDAV PUT 无大小/配额检查 | PUT 增加 100MB 上限与配额前置检查；带 Content-Length 时流式写入（`req.body`），避免整块入内存；重名时增量计算配额、保留旧版本 |
| H2 URL 抓取无 Content-Length 时绕过限额 | 无 Content-Length 先 HEAD 探测体积；写后校验实际 size，超限/超配额时删除已写对象并返回 413 |
| H3 分享链接绕过目录锁 | 创建分享前校验目录/父目录锁；分享访问链路（目录分享查目录、文件分享查父目录）实时校验锁，锁定结果转为 423 |
| H4 分享密码可无限爆破 | 密码校验失败分支增加 `share:pw:<token>` 计数限频（5 次 / 5 分钟） |

### 中危（M1-M7）

| 问题项 | 修复内容 |
|---|---|
| M1 登录仅 IP 限频 | 增加用户名级限频（`login:u:<username>`，5 次 / 5 分钟），预检、密码失败、TOTP 失败均计数，登录成功清空；与 IP 限频并存 |
| M2 Turnstile 缺 secret 静默放行 | 配置了 site key 但缺 secret 视为配置不完整返回 false；完全未配置保持跳过（向后兼容） |
| M3 WebDAV GET 无净化 | GET 响应增加文件名净化与 `Content-Disposition: attachment` 语义 |
| M4 删除目录不查子孙锁 | 新增 `hasLockedSubtree` 递归探测；删除目录前预检（返回 423），递归删除时跳过锁定子树 |
| M5 chunks/ 被误判孤儿 | `listAllKeys` 采集上传时间；chunks/ 24 小时内视为活跃不归孤儿 |
| M6 分享上传计数非原子 | 上传计数改用 `counterAdd` 原子累加（KV 退化时回退本地累加） |
| M7 分享 TTL 与 exp 偏差 | 访问检测到过期即删除分享记录；列表接口过滤过期项并同步清理 |

### 低危（L1-L5）

| 问题项 | 修复内容 |
|---|---|
| L1 密码无盐回退 | 管理员密码与目录密码无盐验证通过后自动写入带盐哈希（迁移式修复，不改变接口） |
| L2 token 明文拼 URL | 前端 `api()` 改为 `Authorization: Bearer` 请求头传输 |
| L3 前端属性注入 | 面包屑累积路径 `data-p` 用 `esc()` 转义 |
| L4 Webhook 未二次校验 host | 发送前用 URL 解析 + `resolveAndCheckHost` 二次校验目标 host，失败跳过 |
| L5 错误响应泄露内部细节 | 健康检查错误信息统一脱敏为 `check failed` |

### 逻辑/健壮性（R1-R8）

| 问题项 | 修复内容 |
|---|---|
| R1 抓取/重定向无超时 | fetch 增加 10s 超时（`AbortSignal.timeout`），保留 5 跳上限与每跳 host 校验 |
| R2 扫描无上限 | 标签过滤结果上限 500；重复检测哈希组上限 2000 |
| R3 孤儿截断误判 | 扫描截断（capped）时拒绝清理并返回 409 |
| R4 目录删除非幂等 | 删除后残留检查 + 最多 3 次重试（间隔递增），规避 KV 最终一致残留 |
| R5 分片内存 OOM | 分片内存拼装上限由 100MB 收紧至 50MB |
| R6 前端目录渲染无上限 | 普通目录渲染截断至 500 项并提示；解锁弹窗由 `prompt()` 改为内联表单 |
| R7 递归移动（无需修改） | 已具备批次/锁检查，保留原实现 |
| R8 文本写入无限制 | `handleSaveText` 增加 2MB 上限与类型校验 |

---

## 部署方式

### 前置条件

- Cloudflare 账号（免费版可用 R2 10GB / KV / DO）
- 已创建 R2 存储桶与 KV Namespace（名称任意，绑定名分别为 `DRIVE`、`STORE`）

### 方式一：Wrangler CLI

1. 安装 Wrangler 并登录：`npm i -g wrangler`、`wrangler login`。
2. 创建存储资源：

```bash
wrangler r2 bucket create personal-drive
wrangler kv namespace create STORE
```

3. 将 `PersonalDrive_v5.1.2.js` 放入项目目录，按上文"Bindings 参考"编写 `wrangler.toml`（填入 KV id；DO 可选）。
4. 设置 Secret 与变量：

```bash
wrangler secret put DRIVE_PASSWORD
wrangler secret put DRIVE_BACKENDS   # 可选
wrangler secret put TURNSTILE_SECRET # 可选
wrangler deploy
```

5. 访问部署后的 Worker 域名，使用 `DRIVE_PASSWORD` 登录。

### 方式二：控制台粘贴部署

1. 登录 Cloudflare Dashboard → Workers & Pages → 创建 Worker。
2. 打开代码编辑器，将 `PersonalDrive_v5.1.2.js` 全部内容粘贴到 `worker.js`，点击"部署"。
3. 在 Worker 设置 → 绑定中依次添加：
   - R2 存储桶绑定：变量名 `DRIVE`
   - KV Namespace 绑定：变量名 `STORE`
   - Durable Object 绑定（可选）：变量名 `DIR`，类名按你创建的 DO 类填写，并添加对应 migration
4. 在"设置 → 变量与机密"中添加环境变量与 Secret（见上表）。
5. 访问 Worker 域名完成首次登录。

> 提示：Durable Object 为可选组件。未配置时计数器与用量功能自动降级为 KV/本地累加，其余功能不受影响。

---

## 使用说明

### 登录

- 访问站点首页，输入管理员密码登录（用户名可任意，用于限频维度；如启用 TOTP 需额外输入动态码）。
- 会话有效期 7 天；可在"会话管理"中查看并撤销任意会话。

### 目录锁

- 对目录设置独立密码后，该目录内容需解锁才能访问（列表、下载、预览均校验）。
- 被锁定目录不可生成分享链接；已存在的分享在访问时也会实时校验锁状态。

### 分享链接

- 文件/目录右键或选中后"分享"：可设置密码、有效期（天）、最大访问次数，生成 `{域名}/s/<token>`。
- 目录分享为可浏览页面，文件分享为下载/预览页。
- 分享密码错误 5 次后该分享锁定 5 分钟。

### 上传链接

- 选中目录生成上传链接 `{域名}/u/<token>`，可设有效期与文件数上限；任何人可打开该链接向对应目录上传文件。

### 公开上传

- 配置 `PUBLIC_UPLOAD_DIR` 后，`{域名}/upload` 开放匿名上传页；如需防机器人，同时配置 Turnstile 两键。

### WebDAV 挂载

- 地址：`https://<你的域名>/dav/`
- 账号：任意用户名；密码：**rw 访问令牌**（在"访问令牌"中生成，不要使用登录密码）
- 单文件 PUT 上限 100MB；不支持部分 WebDAV 扩展操作，以实际响应为准。

### 访问令牌与 API

- 在"访问令牌"中生成 rw / ro 令牌；ro 令牌仅允许 GET/HEAD 请求。
- 所有 `/api/*` 接口支持 `Authorization: Bearer <token>` 认证；部分管理接口要求 rw 权限。

### 备份与恢复

- "备份"页可一键创建全量备份（元数据 + 对象索引），备份记录保留在 `.backup/`；可下载备份文件并在恢复时输入备份密码。
- 建议定期备份并在重大变更前手动创建。

---

## 已知限制与注意事项

- **去 TOTP 变体**：`PersonalDrive_v5.1.2-nototp.js` 为移除 TOTP 动态验证码功能的变体（删除 TOTP 接口、登录分支与前端两步验证，其余功能不变）。使用该变体时登录仅依赖密码 + 限频保护。
- **上传上限**：常规上传单文件 500MB；WebDAV PUT 100MB；公开上传默认 100MB（`PUBLIC_UPLOAD_MAX` 可调）；ZIP 解压 50MB；文本编辑 2MB；分片内存拼装 50MB。
- **结果截断**：目录渲染、标签过滤结果上限 500 项；重复检测哈希组上限 2000 组；孤儿扫描截断时拒绝清理（返回 409）。
- **KV 最终一致**：目录删除依赖残留检查与重试（最多 3 次）；极端情况下元数据与对象可能存在短暂不一致。
- **限频固定值**：登录与分享密码限频均为 5 次 / 5 分钟，源码内置不可配置。
- **Turnstile**：必须同时配置 site key 与 secret 才生效；只配其一视为配置不完整，验证会拒绝放行（fail-closed）。
- **镜像同步**：`DRIVE_BACKENDS` 默认仅同步 ≤25MB 文件（每后端 `mirrorMaxBytes` 可调）；镜像为尽力同步，异常记录在镜像检查结果中。
- **IP 过滤**：依赖 `CF-Connecting-IP` 请求头，仅对经 Cloudflare 代理的请求有效。
- **系统前缀对象**：`.thumb/`（缩略图）、`.versions/`（历史版本）、`.backup/`（备份）对象不建议手动删除，否则对应功能数据丢失。
- **PWA 缓存**：Service Worker 启用离线缓存，更新版本后请刷新或重新加载以获取最新前端资源。

---

## 版本历史

| 版本 | 说明 |
|---|---|
| v5.1.1 | 基线版本（单文件 Worker，R2 + KV + DO）。 |
| **v5.1.2** | 基于代码审查报告完成全量安全修复：33 处替换，覆盖 H1-H4 / M1-M7 / L1-L5 / R1-R8；接口兼容，前端无需改动；验证通过（括号/圆括号平衡校验、替换锚点全部唯一命中）。 |
| v5.1.2-nototp | v5.1.2 的变体：移除 TOTP 两步验证功能，其余功能与 v5.1.2 一致。 |

---

## 文件清单

- `PersonalDrive_v5.1.2.js`：主部署文件（单文件 Worker）。
- `PersonalDrive_v5.1.1_代码审查报告.md`：v5.1.1 代码审查报告（问题项与修复建议来源）。
- `PersonalDrive_v5.1.2_修复对照清单.md`：v5.1.2 修复对照清单（问题项 → 修复方式 → 行号）。
*（内容由AI生成，仅供参考）*
