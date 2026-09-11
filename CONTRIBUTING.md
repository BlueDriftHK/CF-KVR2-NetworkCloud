# 贡献指南 (Contributing Guide)

感谢你有兴趣为 CF-KVR2-NetworkCloud 做贡献！无论是报错、提建议、还是写代码，都非常欢迎。本文说明如何高效地参与。

阅读前请先了解 [安全策略](SECURITY.md)——**安全漏洞请勿公开提交**。

## 目录

- [行为准则](#行为准则)
- [我能贡献什么](#我能贡献什么)
- [报告问题](#报告问题)
- [提出功能建议](#提出功能建议)
- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [提交 Pull Request](#提交-pull-request)
- [提交信息规范](#提交信息规范)
- [测试清单](#测试清单)
- [常见问题](#常见问题)

## 行为准则

参与本项目即表示你同意遵守 [Contributor Covenant 行为准则](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)。核心原则：**友善、尊重、就事论事**。请对使用不同母语、不同水平的贡献者保持耐心。不接受骚扰、人身攻击或贬低性言论。

## 我能贡献什么

- 🐛 **报 Bug** — 发现异常行为？提交 Issue
- 💡 **提建议** — 想要新功能或改进？开一个 Feature Request
- 📝 **改文档** — README、Wiki、注释、翻译，都欢迎
- 🔧 **写代码** — 修 Bug、加功能、性能优化
-  **UI/UX** — 界面、交互、无障碍改进
- 🌍 **翻译** — 界面 i18n 或其他语言的文档

「good first issue」标签是新手友好的起点，欢迎从这里入手。

## 报告问题

提交 Issue 前，先搜索是否已有相同问题。一个好的 Bug 报告应包含：

- **环境**：部署域名 / Worker 名 / 使用的版本
- **复现步骤**：一步步的操作，最好能稳定复现
- **期望 vs 实际**：你以为是怎样的，实际发生了什么
- **截图 / 录屏**：UI 问题尤其需要
- **控制台报错**：按 `F12` 打开浏览器控制台的红色错误信息
- **Worker 日志**：Dashboard → Workers → Observability → Logs 里的 error 行

## 提出功能建议

请说明：

1. **你想解决什么问题**（不是直接给方案，先讲痛点）
2. **你期望的行为**
3. **你考虑过的替代方案**
4. **这个功能是否通用**（个人向的定制可能更适合你自己 fork）

维护者会评估是否符合项目定位。不是所有建议都会被采纳——单文件、零依赖是本项目的设计约束，会引入重依赖或破坏简洁性的提议大概率会被婉拒。

## 开发环境搭建

本项目是**单文件**架构，没有构建步骤，开发极其轻量：

```bash
# 1. Fork 并 clone
git clone https://github.com/你的用户名/CF-KVR2-NetworkCloud.git
cd CF-KVR2-NetworkCloud

# 2. 安装 wrangler（Cloudflare 官方 CLI）
npm install -g wrangler

# 3. 登录 Cloudflare
wrangler login

# 4. 本地起模拟环境（自动模拟 R2 / KV / DO）
npx wrangler dev
# 访问 http://localhost:8787，改 _workers.js 自动热重载
```

准备一个 `wrangler.toml`（本地开发用，勿提交你的真实 kv id）：

```toml
name = "network-cloud"
main = "_workers.js"

[[r2_buckets]]
binding = "DRIVE"
bucket_name = "drive"

[[kv_namespaces]]
binding = "STORE"
id = "your-local-kv-id"
```

> 只想改代码不部署？直接在 Cloudflare 网页 Workers 编辑器里粘贴测试也行，但本地 `wrangler dev` 迭代更快。

## 代码规范

项目是原生 JS 单文件，请遵循以下约定：

### 通用

- **缩进** 2 空格
- **字符串** 用单引号；HTML 属性用双引号
- **命名** 函数 `camelCase`，常量 `UPPER_SNAKE_CASE`，类 `PascalCase`
- 不引入构建工具、不引入需要打包的依赖；外部库一律走 CDN + `defer`

### 后端（服务端）

- 所有 KV / R2 读取必须包 `try/catch`，异常返回 JSON 而非崩溃
- 新增 API 端点：在 `handleXxx` 里实现，在 Router 的 `try` 块里注册，**两端字段名保持一致**
- 路径操作先 `normPath()`，文件名先 `sanitizeName()`
- R2 读内容用 `env.DRIVE.get(key)` 再 `.arrayBuffer()`——`list()` 返回的对象没有 `arrayBuffer()`

### 前端（page() 模板内）

- HTML 拼接用字符串 `+`，**不要用模板字面量**（避免嵌套反引号冲突）
- 模板字面量里的 `${}` 插值**只能用服务端变量**（如 `brand.title`），绝不能引用客户端变量（如 `lang`、`cur`），否则 ReferenceError 崩整个 Worker
- 所有用户输入拼入 DOM 前必须 `esc()` 转义（防存储型 XSS）
- 事件一律用 `addEventListener` + 事件委托（`data-*` 属性），**不要用内联 onclick**（引号嵌套易截断）
- 新增按钮文字写死中文，由 `render()` 动态更新多语言

### 常见坑（务必避开）

| 坑 | 后果 |
|----|------|
| 模板里插客户端变量 | Worker 崩溃 Error 1101 |
| 内联 onclick 里用单引号 | JS 语法截断，全站崩 |
| 直接对 R2 list() 对象调 arrayBuffer() | `is not a function` 运行时错误 |
| 往函数里插代码用了不存在的变量 | 运行时 ReferenceError |
| 改完没逐函数核对括号闭合 | 语法错误，白屏 |

## 提交 Pull Request

1. **先开 Issue 讨论**（新功能或较大改动）——避免做了不被合并的工作
2. 从 `main` 切一个描述性分支：`fix/zip-arraybuffer-crash`、`feat/file-preview-audio-waveform`
3. 小步提交，一个 PR 只做一件事
4. 本地 `wrangler dev` 自测通过（见下方测试清单）
5. 如涉及新功能，更新 [Wiki 文档](../../wiki) 和 CHANGELOG
6. 提交 PR，描述里：
   - 做了什么、为什么
   - 关联的 Issue（`Closes #123`）
   - 截图（UI 变更）
7. 等待 Review，按反馈修改。维护者可能要求调整，请耐心沟通

### PR 标题规范

用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/) 风格：

```
feat: 支持音频波形预览
fix: 修复 ZIP 打包空目录误报
docs: 补充 WebDAV 挂载章节
perf: ZIP 读取改为并行
style: 统一工具栏按钮间距
refactor: 抽取目录读写抽象层
chore: 升级 marked.js 版本
```

## 提交信息规范

同 PR 标题，前缀含义：

| 前缀 | 用途 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档 |
| `perf` | 性能优化 |
| `refactor` | 重构（不改行为） |
| `style` | 格式（不影响逻辑） |
| `test` | 测试 |
| `chore` | 构建/杂项 |

正文说清「为什么」而非只说「改了什么」。

## 测试清单

提交前手动过一遍：

- [ ] 登录 / 退出
- [ ] 上传：小文件、大文件（分片）、粘贴截图、拖拽文件夹
- [ ] 下载 / 预览：图片、视频、音频、文本、Markdown、PDF
- [ ] 目录：新建、重命名、移动、删除、回收站恢复
- [ ] 批量：删除、下载、重命名
- [ ] 分享链接（带密码 / 过期 / 次数限制）
- [ ] 客户端加密 / 解密
- [ ] WebDAV 挂载读写
- [ ] 深色 / 浅色 / 中英切换
- [ ] 移动端布局（缩到 < 820px）
- [ ] 你这次改动本身的功能

## 常见问题

**Q：我没 Cloudflare 账号能贡献吗？**
A：报 Bug、改文档、提建议都不需要。写代码建议注册一个免费账号本地测试。

**Q：我的 PR 会被合并吗？**
A：符合项目定位（单文件、零依赖、个人自托管）且质量过关的会。请理解维护者精力有限，可能需要几轮 review。

**Q：能改架构 / 拆分多文件吗？**
A：单文件是刻意的设计取舍（部署简单）。大重构请先开 Issue 充分讨论。

**Q：贡献的代码版权怎么算？**
A：向本项目提交贡献即表示你同意它在 [AGPL-3.0](LICENSE) 下发布。

**Q：多久会有回复？**
A：尽力在 1 周内响应 Issue / PR。若超时，可在 Issue 里礼貌 ping。

## 许可证

通过向本项目提交贡献，即表示你同意你的贡献将遵循本项目的 [AGPL-3.0](LICENSE) 许可证。

---

再次感谢！每一个 Issue、每一次 PR、每一处翻译，都让这个「一个文件的云」更好用一点。☁️
