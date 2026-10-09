# 老壳通解机 · OlderShellsCK

[English](README.en.md) · [API / MCP](docs/API.md) · [架构](docs/ARCHITECTURE.md) · [更新记录](CHANGELOG.md)

面向二进制分析人员与 AI 工具的本地优先 PE 分析、静态脱壳工作台。浏览器、HTTP API 和 MCP 复用同一套 JavaScript 核心。

**当前是技术预览，尚未完成“老壳通解”目标。** 已接通十条引擎（核心 MPRESS、FSG、UPX 三条限定变体静态链，加服务器端 UPX 官方工具、动态调试、模拟执行、异常观察、ASPack、MEW、Armadillo 七条路由），以及覆盖七个壳族的 DIE 规则子集；完整 DIE 引擎、WASM 与其他变体属于后续阶段。应用版本以 [package.json](package.json) 为唯一维护源，接口返回实际版本。

## 当前能力

- **PE 静态分析**：PE32 / PE32+ 头、架构、入口、节表、普通导入、数据目录、overlay、SHA-256、整体与节区熵，以及结构警告。
- **有来源的有限识别**：固定 DIE 提交中的 44 条 FSG 模式，ASPack／Petite／MEW／PECompact／RLPack／tElock／PELock／NsPack／(Win)Upack 共 61 条直接入口模式，加上 UPX 入口与 MPRESS DOS-stub 分支。相对跳转模式、完整脚本逻辑等未迁入；节名启发式另标 `section-heuristic`。未命中不证明文件未加壳。
- **实际 MPRESS 重建**：`mpress-pe32-lzmat`，纯 JS 解码 LZMAT，恢复 CALL/JMP、OEP 与导入，重建磁盘 PE 布局并复查结构。
- **FSG／UPX 分析解包**：`fsg-pe32` 解出 1.31／1.33 的代码数据与 OEP；`upx-pe32-nrv` 解出已验证 NRV2B short-stub 变体，并恢复 CALL/JMP、OEP 与导入。输出严格标为 `analysis-pe`，不冒充可运行程序。
- **UPX 官方工具直出**：`upx-official`（服务器端、win32）。进程调用官方 `upx -d`（GPL 工具，按需下载、不随仓库分发、不链接其代码），覆盖官方解码器接受的全部 UPX 格式；输出 `rebuilt-pe`。
- **动态调试直出（受控执行）**：`dynamic-debug-dump`（服务器端、win32）。Python ctypes 调试器运行样本（`DEBUG_ONLY_THIS_PROCESS` + Job Object 兜底 + 超时），三种用法：显式 `oepRva` 在精确 OEP 断点抓取内存映像；`mode: 'auto-oep'` 自动定位 OEP；`mode: 'extract'` 在固定时机提取（输出等级 dump-pe → extract-pe）；竞态失败时降级 late-dump 并标 `dump-after-entry`。注意：执行样本仅在用户明确授权时可用。
- **官方 Material 3 界面**：Google `@material/web` 组件、Material Symbols Rounded 图标、官方 Material Color Utilities 的 HCT 动态色；固定砖红主题（`#8f3d33` 种子），顶部导航，中文 / English，跟随系统 / 浅色 / 深色。文件计算放入 Web Worker。
- **自动化入口**：Node 本地 HTTP API、官方 MCP SDK 的 stdio 工具；通过 base64 传入文件内容。

### 引擎总表（10 条）

| 引擎 id | 路由（route/mode） | 输出等级 | 选择方式 | 平台 |
| --- | --- | --- | --- | --- |
| `mpress-pe32-lzmat` | static-js 静态解码 | `rebuilt-pe` | 自动识别 + 显式 | 任意（纯 JS） |
| `fsg-pe32` | static-js 静态解码 | `rebuilt-pe` | 自动识别 + 显式 | 任意（纯 JS） |
| `upx-pe32-nrv` | static-js 静态解码 | `analysis-pe` | 自动识别 + 显式 | 任意（纯 JS） |
| `upx-official` | external-tool（官方 `upx -d`） | `rebuilt-pe` | 仅显式 | win32 服务器 |
| `dynamic-debug-dump` | dynamic-debug 受控执行 | `dump-pe` → `extract-pe` | 仅显式（`oepRva` / `auto-oep` / `extract`） | win32 + py -3.11 |
| `emulated-pe32` | emulated 模拟执行 | `dump-pe` | 仅显式 | 服务器（纯 JS） |
| `instrumented-exception-dump` | instrument/debug 观察器 | `extract-pe` | 仅显式 | win32 + py -3.11 |
| `aspack-pe32-huffman` | static-js（有界锚定 `2.x-ep437`） | `analysis-pe` | 仅显式 | 任意（纯 JS） |
| `mew-pe32-lzma1` | static-js（有界锚定 `11-SE-154`） | `analysis-pe` | 仅显式 | 任意（纯 JS） |
| `armadillo-nanomites` | native 动态调试 oracle | `dump-pe` | 仅显式（需 `probePlan` / `probes`） | win32 + py -3.11 |

全部引擎均为 `experimental`；`runtimeVerified` 仅 `mpress-pe32-lzmat`、`fsg-pe32`、`upx-official` 为 `true`。"自动识别"仅在核心三条静态链中生效；服务器端七条一律显式指定 `engine` id。两点如实说明：`instrumented-exception-dump` 是 **extract-pe 观察器**——一次性 INT3 上下文观察加内存提取与导入快照修复，`oepConfirmed` 恒 `false`，不冒充重建；`armadillo-nanomites` 需显式 `probePlan` / `probes`（缺省时合成降级探针，跑满超时后仍可 dump），**无真实 Armadillo 样本验证**，dump 产物路径未实测，仅有参数校验与快速拒绝路径的测试。

### MPRESS 的准确边界

| 项目 | 当前状态 |
| --- | --- |
| 引擎 | `mpress-pe32-lzmat`，`experimental` |
| 输入 | x86 PE32 原生 EXE、LZMAT、stub `0x29f`、fix `0x35` |
| 来源分组 | RetDec 的 **2.12–2.19** 源码分支，不代表该区间逐版本实测 |
| 实样证据 | 一个 MPRESS **2.19** fixture；重建后 OEP `0x1110`、4 个导入模块 |
| 输出等级 | `rebuilt-pe`；`runtimeVerified: false`，只完成结构验证 |
| 不支持 | DLL、TLS、PE32+、.NET、LZMA、其他 stub / fix 与不符合约束的布局 |

### FSG 与 UPX 的准确边界

| 引擎 | 已验变体 | 输出与缺失结构 |
| --- | --- | --- |
| `fsg-pe32` | FSG 1.31、1.33 明文 stub；两个同程序不同壳版本实样 | `rebuilt-pe`；导入目录／IAT 已按原 RVA 重建（11 DLL、343 函数与独立 golden 逐组一致）；TLS、重定位仍未恢复 |
| `upx-pe32-nrv` | NRV2B LE32、short EXE stub、filter `0x26`；两个实样 | 按样本分级：lbop20 恢复资源／重定位目录后 `rebuilt-pe`（与 golden 逐字节一致）；lab18-01 无目录记录，`analysis-pe` |

FSG 每份实样 **295326 字节**解码内容与独立 golden 一致，导入按 DLL 分组的函数名集合逐组一致；UPX 一份实样整段 `.text` **45568 字节**及资源／重定位目录与独立 golden 一致。NRV2D／2E 仅有流解码器，不等于支持对应 PE。各引擎及其具体缺失结构见 [FSG](docs/research/fsg-implementation.md) / [UPX](docs/research/upx-implementation.md)。

分析返回的 `candidates` 只是初筛，完整检查在脱壳时执行。输出不是原始文件逐字节复原。三条链均为 `experimental`、`runtimeVerified: false`；结构校验与实际运行验收分开。

输入上限 **64 MiB**，解码 / 重建及内部结果分析上限 **128 MiB**。具体限制和能力可查询 `GET /api/v1/capabilities`。

## 从源码启动

需要 **Node.js 22+** 和 npm。在项目根目录执行：

```sh
npm ci
npm run build
npm start
```

开发时也可用 `npm install` 安装依赖；`npm ci` 按已提交的 lockfile 复现安装。打开 <http://127.0.0.1:8787>。Node 服务同时提供 `dist/` 页面和 `/api/v1/*`；设置环境变量 `PORT` 可更换端口。

浏览器需要 ES modules、Web Worker 和 WebCrypto；部署使用 HTTPS，本机可用 localhost。宿主是现代浏览器，待分析对象可以是历史 Windows PE；这不表示页面能在 Win98 浏览器运行。

### 纯静态部署与可选 Python 启动器

`npm run build` 生成 `dist/`，可部署到 GitHub Pages 或任意能正确提供静态文件的 HTTPS 主机。浏览器直接在 Worker 内处理所选文件，不依赖 HTTP 分析 API，也不上传文件内容。构建将前端依赖本地打包，不需要运行时 CDN。

已提供 `点我启动.py`（Python 3.9+），面向已构建的 `dist/`：启动静态服务并自动打开浏览器。Windows 可双击或执行 `py 点我启动.py`；其他平台执行 `python3 点我启动.py`。其范围是静态启动，不安装依赖、不替代构建，也不提供 `/api/v1/*`。源码构建、HTTP API 和 MCP 仍需 Node；Python 不是核心运行依赖。

## Web 使用

1. 选择或拖入 PE 文件，查看结构、检测证据与可用引擎。
2. 查看报告中的检测来源和警告；需要时导出 JSON。
3. 自动选择或指定候选引擎，尝试静态脱壳；按页面显示的“分析用 PE／重建 PE”下载产物并保留 JSON 报告。

文件分析是静态字节处理，不执行待分析 EXE / DLL。界面主题和语言偏好保存在本机浏览器；API 客户端则把内容显式发送给本地 Node 服务。

## HTTP API 与 MCP

HTTP 入口：

```text
GET  /api/v1/capabilities
POST /api/v1/analyze
POST /api/v1/unpack
```

POST 使用 `Content-Type: application/json`，字段为 `dataBase64`、可选 `name`。脱壳默认 `engine: "auto"`（仅核心三条静态链参与自动选择），也可显式指定上表任意引擎 id；可用列表以 `GET /api/v1/capabilities` 返回为准。输出字节为 `dataBase64`，`metadata.outputKind` 区分产物等级。不接收任意本机文件路径。

MCP 客户端配置示例，替换为实际的**绝对脚本路径**：

```json
{
  "mcpServers": {
    "oldershellsck": {
      "command": "node",
      "args": ["/path/to/OlderShellsCK/src/server/mcp.js"]
    }
  }
}
```

工具：`list_capabilities`、`analyze_file`、`unpack_file`。文件通过 `dataBase64` 传入，`name` 仅作显示名；MCP 使用 stdio，不要求 HTTP 服务同时运行。完整请求、返回值、错误码和直接 JS 调用见 [API 文档](docs/API.md)。

## 验证与样本

在项目根目录按顺序执行：

```sh
 node scripts/fetch-fixtures.mjs
 node scripts/fetch-fsg-fixtures.mjs
 node scripts/fetch-upx-fixtures.mjs
 node scripts/fetch-aspack-fixtures.mjs
 node scripts/fetch-mew-fixtures.mjs
 node scripts/fetch-upx-tool.mjs
 npm test
node scripts/check-mpress.mjs
```

下载脚本按固定上游提交、长度和 SHA-256 核对实样，保存到忽略目录 `test-results/fixtures/`。只读样本字节，不运行样本；fixture 不随项目发布。正例包括一份 MPRESS、两份 FSG、两份 UPX；其中包含恶意软件实验室样本，仅用于静态数据验证。不能据此推导全版本兼容。

浏览器检查使用 Playwright，覆盖 Chromium、Firefox、WebKit 和移动视口：

```sh
npm run build
npx playwright install chromium firefox webkit
npm run test:e2e
```

这些是复现命令；具体执行结果以当次测试输出为准。

## 研究依据与路线图

 - [DIE 与历史壳研究完整报告](docs/research/die-and-packers.md)：**34 个候选分组**，含上游源码、提交、许可、版本、执行方式与输出等级。
 - [归档静态盘点完整报告](docs/research/archive-inventory.md)：**340 文件、253 PE、64 个候选家族名称**；其中 **42** 个有工具路径 / 插件证据，**22** 个仅来自作者随附测试声明。
 - [GUI 工具静态拆解报告](docs/research/gui-unpackers-reverse.md)：Ghidra 实际反汇编／选取反编译，覆盖五份原件；126008 条指令字节与 8988 条直接 CALL 位移复核通过。发现部分“静态” GUI 工具实际执行输入 stub，不能直接搬入浏览器。
  - [ASPack 状态](docs/research/aspack-implementation.md)／[MEW 状态](docs/research/mew-implementation.md)：研究结论是锚定布局之外不可猜、检测后明确拒绝；后续获得 ep437 精确样本，已按有界锚定实施 `aspack-pe32-huffman`（`2.x-ep437`）与 `mew-pe32-lzma1`（`11-SE-154`），命中锚定才解码，产物与独立 golden 逐段一致。
 - [保护器能力边界](docs/research/protector-boundaries.md)：分级能力模型（rebuilt-pe / dump-pe / extract-pe / 仅分析）与各壳族一键重建的现实边界研究表。

这些数字是研究与素材计数，不是产品支持数。研究目标覆盖 Win9x 时代至 2025 年已存在的候选，资料检索日期与工具收录日期单独记录。

后续分阶段推进：

1. **样本与验收基线**：扩展来源清晰的 MPRESS 良性样本集，按版本、架构、算法、参数记录哈希；分别验收结构与真实运行行为。
2. **DIE 兼容检测**：补齐规则所需的格式对象、地址转换、搜索、反汇编、脚本加载和结果宿主函数；与固定 DIE 引擎 / 数据库差分验证后才扩大覆盖声明。
3. **更多静态引擎**：补齐 FSG 导入与 UPX 资源／重定位目录，增加 MPRESS 分支；按许可、完整 stub 与独立样本验证推进 ASPack、Petite、PEArmor。检测规则与脱壳实现独立验收。
4. **WASM 与扩展路线**：在实际性能需要时引入可复现的 headless WASM 构建，并核对依赖许可；bundle 提取、仿真与原生动态调试分别定义能力边界。

## 目录与许可

```text
src/core/          通用 JS 分析、检测、解码、重建
src/web/           官方 M3 界面、HCT 主题、Web Worker
src/server/        Node HTTP、MCP、任务 Worker、传输序列化
vendor/die/        固定原始规则、派生直接入口模式、清单与 MIT 许可
licenses/          RetDec / XStaticUnpacker 原始 MIT 许可
scripts/           构建、fixture、静态盘点与核验脚本
tests/             核心、接口及浏览器测试
docs/              接口、架构与完整研究报告
dist/              构建产物（忽略）
test-results/      测试产物与下载 fixture（忽略）
资料/             私有研究素材（忽略，不发布）
```

Copyright 2026 Henglie。项目采用完整 [Apache-2.0](LICENSE)，第三方归属与许可见 [NOTICE](NOTICE)。官方 Material Web 上游目前处于 **maintenance mode pending new maintainers**；这是所选依赖的维护状态记录。
