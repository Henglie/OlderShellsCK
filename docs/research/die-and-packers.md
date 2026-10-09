# DIE 与历史壳自动解包研究

研究日期：**2026-10-05**。目标文件范围：Win98/Win9x 时代至 **2025-12-31** 已存在的壳、保护器、打包器。资料检索采用研究日可见的上游源码；2026 年新增的工具实现不倒算成 2025 年已有能力。

本文保留启动阶段的调研证据等级。后续工程已接通 MPRESS 重建链及 FSG／UPX 分析解包链；当前实装及验收范围见 [README](../../README.md)，不以本报告候选数量计算支持数量。

本报告只做在线文档、许可证、源码与仓库目录检查；未下载压缩包，未运行加壳器、脱壳器或样本，未编译或浏览器实测任何第三方模块。下文的“支持”必须结合证据等级阅读，不代表本项目已经实现。

## 1. 可直接用于决策的结论

1. **DIE 自有代码和规则库的根许可证是 MIT**：`Detect-It-Easy`、`DIE-engine`、`die_script`、`die_library` 均已核对许可证正文。Qt、反汇编器、压缩库、GUI 附属模块有独立许可，不能把整个递归构建都标为 MIT。[D1] · [D2] · [D3] · [D4]
2. **已有第三方浏览器 DIE**：`xoreaxlmbdx/die-in-browser` 在 v86 内运行 Linux + 原生 diec；`secnotes/onlinedie` 仓库确有 `.wasm/.data/.js` 产物与调用 `callMain` 的前端。后者文档和构建脚本存在冲突，不能据其“100% coverage”宣传直接验收。[B1] · [B2]
3. **未核实到可直接采用、许可和真实样本效果均过关的 MIT/BSD/Apache 现成 JS/WASM 通用原生 PE 脱壳库**。有明确 MIT 的可移植 C++ 实现：RetDec 的 UPX/MPRESS，以及 horsicq 的 `XStaticUnpacker`。它们需要移植和样本验证，不是现成浏览器组件。[R1] · [X1]
4. **首个完整 PE 重建目标推荐 MPRESS 2.19、PE32/x86、LZMAT 路径**，以 RetDec 的 MIT 插件为依据：版本分支明确，包含解压、CALL/JMP 还原、imports/OEP/relocations 修复。先锁定此配置建立正反样本，再扩展版本和算法。若当前只交付 FSG 分析镜像，必须标为 `analysis-pe`，不能标为可运行原程序。[R2] · [X2]
5. **成熟原生 UPX CLI 可作后续独立对照工具；不适合直接抄进 Apache-only 内核**。UPX/UCL 是 GPL-2.0-or-later，压缩产物例外不等于解压库例外。`hi098123/upx-wasm` 的现成 WASM 也没有消除 GPL。[P1] · [P2]
6. **bundle 提取有真正的 MIT 浏览器先例**：`pyinstxtractor-go` 使用 Go + GopherJS，提取 PyInstaller 内容；这不能算 UPX/FSG/ASPack 意义上的原生 PE 脱壳。[G1]
7. 下表是 **34 个研究候选分组**，不是“支持 34 壳”，更不是全球总数。全球精确总量不可知：私有壳、改壳、别名、版本、保护选项和组合壳没有统一登记与计数口径。

## 2. DIE：仓库边界、许可证与依赖

### 2.1 直接核实的许可证

| 仓库 | 职责 | 根 LICENSE 正文 | 本次读取的版权行 |
|---|---|---|---|
| `horsicq/Detect-It-Easy` | 规则数据库、帮助、项目入口 | MIT | `Copyright (c) 2012-2026 hors<horsicq@gmail.com>` |
| `horsicq/DIE-engine` | GUI、console、构建与发行 | MIT | `Copyright (c) 2012-2026 hors<horsicq@gmail.com>` |
| `horsicq/die_script` | JS 引擎适配、规则执行 | MIT | `Copyright (c) 2019-2026 hors<horsicq@gmail.com>` |
| `horsicq/die_library` | 可嵌入原生库 | MIT | `Copyright (c) 2019-2026 hors<horsicq@gmail.com>` |
| `horsicq/Formats` | 二进制格式读取与对象 API | MIT | `Copyright (c) 2017-2026 hors<horsicq@gmail.com>` |
| `horsicq/XArchive` | 压缩/归档解码与适配 | MIT 根许可；子目录逐项核实 | `Copyright (c) 2019-2026 hors<horsicq@gmail.com>` |
| `horsicq/XStaticUnpacker` | 部分壳的静态解包器、bundle 提取 | MIT | `Copyright (c) 2019-2026 hors<horsicq@gmail.com>` |

MIT 允许并入 Apache-2.0 项目，但保留原版权、许可与免责声明；不要将第三方原文件的 MIT 声明换成项目 Apache 声明。表中不是整个传递依赖树的许可审计。[D1] · [D2] · [D3] · [D4] · [D5] · [D6] · [X1]

### 2.2 `DIE-engine/.gitmodules` 的直接依赖

本次读取的路径均在 `dep/` 下，URL 基本为 `https://github.com/horsicq/<名称>`（部分带 `.git`）。完整名称如下；以 `.gitmodules` 和锁定提交的 gitlink 为准，不用不同仓库的浮动 master 拼一个“同版本”。[D7]

```text
Detect-It-Easy Formats SpecAbstract StaticScan XArchive XQwt
XOptions XStyles XTranslation XDEX FormatDialogs FormatWidgets
Controls XMemoryMapWidget XEntropyWidget XCapstone XHashWidget
die_script die_widget nfd_widget archive_widget XMIME XSingleApplication
XMIMEWidget XHexView XDisasmView XGithub XShortcuts XHexEdit signatures
XDemangle XDemangleWidget XCppfilt XDynStructs XDynStructsEngine
XDynStructsWidget XFileInfo XPDF XInfoDB XSymbolsWidget XOnlineTools
XAboutWidget hex_templates XExtractorWidget XExtractor XUpdate
XVisualizationWidget XDecompiler XYara yara_widget XDataConvertorWidget
XScanEngine XDisasmCore XRegionsWidget XStaticUnpacker XPEID
build_tools peid_widget
```

`die_library/.gitmodules` 有历史遗留重复声明：既有根路径 `Formats`，也有 `dep/Formats`，多个模块旧名与 `dep/*` 名重复指向同一路径。实际 `src/CMakeLists.txt` 使用 `dep/` 布局，不能把重复声明计成独立依赖。[D8]

其唯一仓库名称集合为：

```text
Formats die_script XArchive Detect-It-Easy build_tools XCapstone
XDEX XPDF XOptions XExtractor XScanEngine XDisasmCore XStaticUnpacker
```

当前源码调用链：[D9] · [D10] · [D11]

```text
die_library
  Qt Core + Concurrent
  Qt5 -> Script / QScriptEngine
  Qt6 -> Qml / QJSEngine
  XCapstone/x86, XArchive, Formats/xsimd
  die_script -> XDisasmCore + XScanEngine + Detect-It-Easy
  XDisasmCore -> Formats/xbinary + XCapstone
  XScanEngine -> Formats + XDEX + XPDF + XArchive
               + XStaticUnpacker + XOptions + XDisasmCore
  XStaticUnpacker -> Formats + XArchive
                    + optional XEmulator when WITH_XEMULATOR
```

这说明“只编译 library”也不是只需一个 `.cpp`。`WITH_XEMULATOR` 的代码路径还需单独核实实际引入的模块、许可及构建选项。当前 `DIE-engine/.gitmodules` 列表没有直接声明 `XEmulator`，不能据源码中的相对路径假定克隆后必定齐全。

三方依赖注意点：

- `XCapstone` 封装不替代内嵌 Capstone 的 BSD-3-Clause 与 LLVM 来源声明；其树中有 `3rdparty/Capstone/src/LICENSE.TXT`、`LICENSE_LLVM.TXT`。[D12]
- `XArchive` 包含独立算法许可目录，如 LZ4、Brotli、bzip2、zstd、WavPack、libarchive-derived、unarc-rs，以及 `xlha_legacy.LICENSE`。只保留实际编入的依赖也仍需逐文件核对。[D6]
- GUI 的 Qwt、YARA、反编译器等不应因检测任务被无差别携入；有无链接及具体许可取决于固定构建配置。
- `XUCLDecoder` 当前文件是 horsicq 2026 MIT 实现；名称含 UCL 不代表它就是原版 GPL UCL。反过来，不能凭同名算法把原版 UCL 许可改写为 MIT。[X9] · [P1]

### 2.3 脚本引擎与 JS 移植边界

`die_script/xscriptengine.h` 明确选择 `QScriptEngine` 或 `QJSEngine`。上游 README 将规则运行时称为 DiE-JS ES5；`.sg` 不是普通正则列表，也不是可原样扔进浏览器就能完整工作的脚本。[D13] · [D14]

规则依赖宿主提供的 `PE`、`Binary`、`ELF` 等格式对象、RVA/VA/文件偏移转换、结构读取、搜索、反汇编、`includeScript()`、结果变量及扫描选项。DIE 的字节匹配语法有通配和相对地址表达式，不等于 JS 正则。[D15]

纯 JS 复用需实现并差分验证宿主 API、边界读取、整数/地址语义、规则加载顺序、`result()`、heuristic/deep scan 和递归识别行为。只抽几个签名或节名做匹配，应明确叫“启发式/规则子集”，不能标“完整 DIE”。规则执行放 Worker，错误与超时单独报告，避免未实现 API 静默返回假结果。

## 3. 已有 DIE 浏览器构建：证据与限制

| 项目 | 已核实证据 | 架构、时间与可采用程度 |
|---|---|---|
| `xoreaxlmbdx/die-in-browser` | README、Dockerfile、MIT LICENSE；仓库创建 `2025-12-28` | v86 JS/WASM 模拟 x86；Linux guest 中运行原生 diec，不是 DIE 直接编译成 WASM。当前 Dockerfile 指向 DIE `3.21`、Buildroot `2025.11`、Qt5。README 称压缩快照约 17 MB，研究中未实测。[B1] |
| `secnotes/onlinedie` | git tree 有 `docs/wasm/diec.wasm` **10,507,776 字节**、`diec.data` **2,924,795 字节**、`diec.js` **316,320 字节**；`docs/js/app.js` 使用 `FS.writeFile` + `callMain` | 仓库创建 `2026-05-11`；README 声称 Qt `6.11.1` / Emscripten `4.0.7` 的直接移植。可作移植线索，当前产物的来源、完整性、API 一致性、可复现性未验证。[B2] |

关键反证/保留意见：

1. 官方 `DIE-engine` 当前最新 release `3.21` 发布于 **2026-04-21**；所查 release 资产是 Windows/Linux/macOS 和源包，未见官方 WASM 资产。仓库递归 tree 未见 wasm/emscripten/webassembly 命名构建文件。这仅是本次官方树与最新发行核查，不是宣称全网没有移植。[D16]
2. `die-in-browser` 建仓时间不证明当前 DIE 3.21 快照在 2025 年就存在；当前版本已涉及 2026 发布的 DIE。
3. `onlinedie` 的 `wasm-build/README.md` 仍写“WASM 未编译”和“简化版”；`src/die_wasm.cpp` 明确写“简化版、独立文件检测引擎”，并非完整 DIE。不能用这一条构建路径替代真实 DIE。[B3]
4. 其 `build-wasm.sh` 生成的包装调用 `XScriptEngine::detect(filename)`，而本次核对的上游 `XScriptEngine` 声明没有该方法；脚本还混用旧目录、`-sUSE_QT=6` 与不同 Qt 路径。因此不把该脚本当作已证实可复现配方。前端使用的是 `callMain`，也与脚本中的 `_die_detect` 接口不同。[B3] · [D13]
5. 根 README 的签名数量表与“100%”缺少同一提交的完整性/差分测试依据。**签名数不是壳族数，更不是脱壳能力数。**

### Qt 许可：直接 WASM 路线的实际门槛

- Qt 6.8 的 `qglobal.h` 和 `qjsengine.h` SPDX 包含 `LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`。可以研究只使用 Core/Qml 的 headless 路线，但须处理 LGPL 分发、修改和重新链接要求。[Q1] · [Q2]
- Qt 6.8 的 WASM GUI 平台插件 `qwasmintegration.cpp` 是 **`LicenseRef-Qt-Commercial OR GPL-3.0-only`**；Qt 官方 WASM 文档也说明 GPLv3/商业许可。不能把完整 Qt WASM GUI 默认为 LGPL。[Q3] · [Q4]
- Headless `QCoreApplication` 不必然使用 GUI 平台插件；是否避开 GPL-only 组件要用实际链接清单证明。对 `onlinedie` 现成产物，本次没有完成此证明。
- Qt WASM 常用静态链接；仅附 LGPL 文本或把 `.wasm` 放进 Worker 并不自动满足重新链接要求。需提供相应源、构建材料/应用目标文件等合规路径，或采用匹配的商业许可。Apache 主项目可保留自身许可，但第三方组件许可不能消失。
- v86 guest 路线同样包含 Linux、BusyBox、Qt、固件等；其 `licenses.tar.gz` 是有用起点，但许可证文本集合不等于所有 GPL 对应源码义务已完成，且 Dockerfile 从 Alpine 手动复制的 DIE/Qt 不应假定被 Buildroot 自动完整登记。

**推荐检测迁移方向**：固定 DIE 引擎+规则提交，研究 headless library/C API 到 Worker 的构建；官方 M3 UI 保持独立。需要全 permissive 内核时，实施格式 API 与 ES5 规则兼容层是独立工程，不能计作已移植。

## 4. 可复用脱壳实现：静态、仿真、原生调试分开

### 4.1 静态可移植候选与已存在浏览器实现

| 实现 | 许可与实际内容 | 浏览器状态、结论 |
|---|---|---|
| RetDec `retdec-unpacker` | 自有代码 MIT；PeLib 原始部分 zlib。实际插件为 **UPX、MPRESS**；`example` 不是第三个壳。NRV2B/2D/2E、LZMA、LZMAT 与 PE 重建有源码。[R1] · [R2] · [R3] · [R5] | 原生跨平台 C++，本次未发现/验证上游现成 WASM。可抽取特定插件/算法移植，避免整套反编译器。完整树另有 Keystone GPLv2+FOSS exception、Eigen MPL 等，须核实际依赖闭包。[R4] |
| horsicq `XStaticUnpacker` | 根与本次查看的 FSG/ASPack/MEW/Petite/NsPack/Yoda 文件为 MIT；采用 Qt/Formats/XArchive。[X1] | 强候选源，不是现成 JS/WASM。FSG/Petite 明确是分析镜像；ASPack/NsPack 头注释仍提示未以真实样本验证，不能按文件名认定稳定支持。[X2] · [X3] · [X5] · [X6] |
| `orcastor/unpack` | 根 MIT、Go；README 列出多壳支持。[O1] | **不采信其列表为可用解包证据**。核对 `fsg/fsg.go`：复制原文件、猜 OEP、修改头/导入字段，没有 FSG bitstream 解压；ASPack 也含近似偏移、零解压块仍输出等路径。不是经验证的静态库，更未证明 WASM。[O2] |
| 官方 UPX / `hi098123/upx-wasm` | UPX/UCL GPL-2.0-or-later；fork 树有 `upx.js/upx.wasm`，`src/version.h` 为 **5.0.0 / 2025-02-20**。[P1] · [P2] | 现成 WASM 线索，但非 permissive；产物未运行，支持范围仍依特定 UPX 版本、格式、算法与是否改壳。 |
| `GHFear/Steamstub-v3-Unpacker` | **CC-BY-NC-4.0**，README 支持 x64 `3.0.0/3.1.0/3.1.2`，x86 列入计划。[S1] | 有 WASM 构建说明与在线演示；NC 限制不满足 Apache 开源核心要求。只能作存在性证据，不能按公开源码默认复用。 |
| `atom0s/Steamless` | **CC-BY-NC-ND-4.0**；C#，支持若干 SteamStub 1/2/3 变体。[S2] | 原生/.NET 静态工具，非 JS/WASM；ND/NC 限制阻止作为常规 Apache 移植源。作者说明版本编号为观测命名，不是 Valve 官方语义版本。 |
| `pyinstxtractor-go` | **MIT**；Go + GopherJS，web demo 与构建说明齐全。[G1] | 真正 permissive 浏览器 **bundle extractor**。Python 2 的 PYZ 不提取、加密 PYZ 不支持、移动端大文件内存有限。原 Python `pyinstxtractor` 是 GPLv3，不能混淆两仓库许可。[G2] |
| `innoextract` | zlib；C++，README 支持 Inno Setup `1.2.10–6.3.3`；Boost、压缩、可选 iconv 独立许可。[G3] | 静态跨平台安装器提取，非原生 PE 代码恢复；WASM 需移植，采用该版本范围中的截止 2025 子集另行锁样本。 |
| `unshield` | MIT；C 库/CLI，面向 InstallShield CAB，README 目标 `5 and later`。[G4] | 静态可移植库；不等于所有 `setup.exe`、所有 MSI、所有新版 InstallShield 均支持。 |

来源注意：XStaticUnpacker 多个头文件声称基于 ClamAV 格式研究进行 clean-room 重写。这里记录的是**作者声明和文件 MIT 授权**，不是独立确认了隔离重写过程。直接翻译 GPL ClamAV 实现不会因换语言或变量名变成 MIT；正式采用应保留来源历史并核实拟复用代码。ClamAV `pe.c` 头部明确 GPL version 2，不能只看到其中某个 Apache 来源片段便把全文件当 Apache。[X2] · [X3] · [C1]

补充：`XUPX` 中 `_runUPXDecompress` 名称看似调用外部 UPX，但固定快照实际函数仅返回 `false`，注释明确不 shell out；当前走内部实现或失败。不要把历史实现/函数名当成当前依赖证据。[X10]

### 4.2 仿真与原生调试工具

| 工具 | 证据与能力边界 | 集成判断 |
|---|---|---|
| `unipacker/unipacker` | `setup.py` 声明 `GPL-2.0`，Unicorn CPU 仿真 + Windows API 模型；README 列 ASPack、FSG、MEW、MPRESS、Petite、UPX、YZPack。测试只覆盖指定样本，非版本全集。[U1] · [U2] | 跨宿主 Python 工具，**执行样本指令的仿真解包**，不是纯静态解压，也不是现成浏览器库。不可把 GPL 核心改名后并入 Apache 内核。 |
| Unicorn | 核心 GPLv2 文本，另有组件/例外需按版本核实；unipacker 固定 `unicorn-unipacker==1.0.3b7`。[U3] | 即使某 JS binding 为 MIT，底层许可证也不因此变 MIT；CPU 能运行不代表 Windows loader/API/OEP/IAT 已解决。 |
| Mandiant Speakeasy | 本体 MIT；模型化 Windows API、PE/shellcode 运行环境。[E1] | 通用仿真框架，不是已验收全族 unpacker；后端依赖、dump 触发、导入修复及成功标准仍需实现和审计。 |
| `ergrelet/unlicense` | GPLv3；动态执行 Themida/WinLicense `2.x/3.x`，支持若干 PE32/PE32+ EXE/DLL；README 明示通常不生成可运行 dump。[E2] | 需要 Windows 运行环境与动态插桩；不应承诺浏览器静态支持。有效许可证需求不会被脱壳器自动消除。 |
| TitanEngine CE | x64dbg 分支 LGPLv3；Windows 调试引擎。[E3] | API/断点/调试事件依赖 Windows，不是把 C++ 编成 WASM 就能调用；SDK/脚本示例不能全部计作可移植脱壳算法。 |
| Scylla | GPLv3，Windows 进程 imports reconstruction / dump；README 记有 OS 相关解析限制。[E4] | 重建辅助工具，不是独立的多壳静态解压库。 |
| `anpa1200/Unpacker` | MIT 外壳，README 明示 UPX 调系统 CLI，其他用 Unipacker/Qiling；MPRESS/generic 为 stub，部分路径清零 IAT 仍 dump。[E5] | 排除“MIT 一键全壳库”误判；低熵、文件变大、成功写文件都不足以证明恢复正确。 |

**许可结论**：GPLv3 可以接收 Apache-2.0 代码，不代表 GPLv3 代码可以重新许可为 Apache-only；GPLv2-only 与 Apache-2.0 也不是普通直接合并关系。独立外部 CLI 的进程边界和独立分发可另行设计，但不能用 JS/WASM、Worker 或插件名字自动推导“隔离就没许可问题”。[L1]

## 5. 候选矩阵：34 个分组，不是已支持清单

### 读表方式

- **类型**：`P` 文件压缩壳；`R` 保护器/cryptor；`V` 指令虚拟化；`B` bundle/脚本容器/安装器。类型可重叠。
- **方式**：`S` 不执行目标指令的静态转换；`E` 仿真执行；`N` 原生动态执行/调试；`D` 仅识别或目录线索；`?` 方式尚未核实。原生编译的静态 CLI 仍属于 `S`，不能因 `.exe` 后缀判成 `N`。
- **证据**：`SRC` 已核具体源码路径；`TEST` 上游存在特定回归测试，不代表本次运行过；`DOC` 作者说明；`LIST` 镜像目录文件名；`DETECT` 仅检测器规则。
- **版本列**是工具证据实际约束，不能从 `2.12` 泛化为整个 `2.x`；凡写“候选”，都没有本次核实的自动成功承诺。
- 历史分组覆盖 Win9x PE32 到 2025 的 PE32/PE32+ 生态；不宣称 Web 页面可以在 Win98 浏览器运行，也不宣称同族各代均支持 Win98。

| # | 家族/分组 | 类型、版本限定 | 自动工具证据与方式 | 浏览器/许可/输出判断 |
|---|---|---|---|---|
| 01 | UPX | P；从老 Win32 PE 到 2025 `5.0.0`；各格式分别限定 | 官方 `upx -d`：S/DOC；RetDec UPX：S/SRC；fork 有 WASM 产物。[P1] · [P2] · [R3] | 原版 GPL；RetDec MIT 路线可移植。NRV 解码成功不等于 PE imports/reloc/resources 已重建。 |
| 02 | ASPack | P；源码重点 `2.12`、`>2.12且<2.42`、`2.42` | XASPACK S/SRC；ClamAV S/SRC；unipacker E/TEST 的 `lbop20_aspack.exe` 未标准确壳版本。[X3] · [C1] · [U2] | XASPACK MIT，但头注释称未实样本验证；只能作为分析 PE 候选。目录 `UnPacker 1.13` 是工具名，不能直接当壳支持版本。 |
| 03 | FSG | P；`1.0/1.3`、`1.1/1.2`、`1.31`、`1.33`、`2.0` 的源码分支 | XFSG S/SRC；unipacker `1.31/1.33` E/TEST；ClamAV `1.31/1.33/2.0` S/SRC。[X2] · [U2] · [C1] | MIT XFSG 可移植；明确未重新修复 imports，输出 analysis PE。早期加密 stub 路径另验。 |
| 04 | MEW | P；`10`、`11/11 SE`；区分 aPLib-style 与 LZMA | XMEW S/SRC；ClamAV `unmew11` S/SRC；unipacker 特定样本 E/TEST。[X4] · [C1] · [U2] | MIT 移植候选；LZMA 路径还有容器 framing/可选 x86 filter，不能用普通 LZMA 解压替代整体恢复。 |
| 05 | Petite | P；ClamAV `2.x` 中 `1–9` 分支，level zero 明确不支持 | ClamAV S/SRC；XPETITE S/E/SRC；unipacker 特定样本 E/TEST。[C1] · [X5] · [U2] | MIT XPETITE 的新 decoder 变体使用 bounded XEmulator；imports 未 unmangle。不是所有路径纯静态。 |
| 06 | MPRESS | P；`1.01–1.05`、`1.07–1.27`、`2.01`、`2.05`、`2.12–2.19` stub 分组 | RetDec MPRESS S/SRC：LZMAT/LZMA、imports/OEP/relocations；明确拒绝 PE32+。[R2] | **优先移植**；MIT。列表是源码分支范围，不代表区间每个发行版已实测；首个样本锁 `2.19 PE32 LZMAT`。 |
| 07 | YZPack | P；`1.1` 样本 | unipacker E/TEST；`2.0` 样本存在但被 `test_yzpack` 排除。[U2] | GPL；不能把 `2.0` 存在于 Sample 目录算成功覆盖。未核实 permissive 静态实现。 |
| 08 | NsPack | P；旧 PE32 布局、含 2.x loader 相关路径；无可信完整版本区间 | ClamAV `unspack` S/SRC；XNSPACK S/SRC。[C1] · [X6] | MIT 候选。头注释“未真实样本验证”与下方修复样本注释并存；按未验证处理，不承诺 runnable。 |
| 09 | Upack / WinUpack | P；`0.39` 两/三节布局、`1.1/1.2 Beta` 少量样本分支 | ClamAV `unupack` S/SRC，注释说明 Beta 分支仅由两个样本建立。[C1] | GPL 实现，只作格式/范围证据；没有本次核实的 permissive 浏览器实现。两名称合并计数。 |
| 10 | WWPack32 | P；老 PE32，DIE 规则为 `1.XX` | ClamAV `wwunpack` S/SRC；准确自动支持小版本未给出。[C1] · [DDB] | GPL 静态候选；不包含 DOS WWPack 的自动承诺。 |
| 11 | PESpin | R/P；**1.1** | ClamAV `pe.c` 明示 `PESpin 1.1`，调用 `unspin`：S/SRC。[C1] | GPL，需独立实现或单独 GPL 工具；不扩展为 1.x 全版本。 |
| 12 | y0da's Crypter / yC | R；`1.3` 及匹配变体 | XYODA S/E/SRC：byte-VM 解 poly decryptor；头注释称对照 `clam-yc.exe` 与 ClamAV 输出。[X7] | MIT 候选；含受限指令解释，应标为受限仿真路径。不要与 y0da's Protector 混为同一支持能力。 |
| 13 | PECompact | P；候选 `3.02.2`（镜像）；其他版本另证 | 镜像有 `Unpacker_PECompact.7z` LIST；unipacker 有 Sample 但不在 README fully supported/test 方法中。[A1] · [A2] · [U1] · [U2] | D/?；没有本次核实的版本限定静态可移植成功证据。样本和工具文件名不足以启用“脱壳”按钮。 |
| 14 | ASProtect | R；候选 `SKE 2.51 build 09.22 beta` | 镜像 `ASProtect Unpacker.rar` LIST，未给支持范围/许可；DIE 有规则。[A1] · [A2] · [DDB] | D/?；与 ASPack 分开，不能拿 ASPack 解压器声称支持 ASProtect。 |
| 15 | Armadillo / SoftwarePassport | R；DIE 检测范围含 `3.X–9.X`，不是脱壳范围 | 镜像 `Armageddon_v2.3.zip` LIST；`2.3` 是工具版本，受保护文件版本未知。[A2] · [DDB] | D/?；本次未核作者级完整支持表，Windows 工具的具体动态路径与许可待核。 |
| 16 | RLPack | P/R；检测规则 `0.7.3 beta`、`1.0 beta`、`1.11–1.21` 若干分支 | DIE DETECT；本次未核实版本限定自动解包器。[DDB] | D；保留历史候选，不能把检测范围当静态支持。 |
| 17 | tElock | R；检测规则含 `0.35` 至 `1.00` 若干离散版本 | DIE DETECT。[DDB] | D；原生调试案例不等于可移植静态实现，本次不填自动支持。 |
| 18 | PELock | R；检测规则 `2.X`；官方产品说明支持 Win95/98 等 | 官方说明 encryption/licensing 与运行时集成；DIE DETECT。[V1] · [DDB] | D；没有经核实的通用静态完整恢复。需授权密钥的加密代码不能由“解压”凭空恢复。 |
| 19 | ACProtect | R；检测规则 `1.09g`、`1.41`、`1.90g`、`2.0.X` 等 | DIE DETECT；Scylla changelog 有相关 imports 修复问题，但不是 ACProtect 自动解包器。[DDB] · [E4] | D；不能把导入重建辅助能力算作整族支持。 |
| 20 | Strongbit EXECryptor | R；检测规则 `2.0/2.1`、`2.1.17`、`2.2.4`、`2.3.9` 等 | DIE DETECT。[DDB] | D；未核实 permissive 静态通用实现。 |
| 21 | Obsidium | R；候选 `1.3.6.4`、`1.5.2.11`、`1.6.7.1`、`1.6.9.1` | 镜像 LIST；官方说明 protection/licensing；未核实自动范围。[A1] · [V2] | D；原生调试/人工恢复研究项，不能承诺 Web 通解。 |
| 22 | Themida / WinLicense | R/V；**2.x、3.x**，PE32/PE32+ 分条件 | unlicense N/DOC，明确大多数 dump 不可运行；WinLicense 仍需有效运行许可。[E2] | GPLv3、Windows 动态；非静态便携。两产品共享保护技术，保守合并一组。 |
| 23 | VMProtect | R/V；候选 `1.53`、`1.70`、`2.x/3.x` | unipacker 存 `1.53` 样本，但未列 fully supported；DIE DETECT；generic emulation dump 不构成脱虚拟化证据。[U1] · [U2] · [DDB] · [E5] | D/E 实验；没有本次核实的跨版本自动原代码恢复。外层解包与还原虚拟化函数分开。 |
| 24 | Enigma Protector | R/V/B；候选 `6.70`、`6.80`、`7.40` | 镜像 LIST；官方说明许可、VM、捆绑；EVB unpacker 不是本产品通用 unpacker。[A1] · [V3] | D；能提取某些 VFS 文件也不代表保护代码已还原。 |
| 25 | Code Virtualizer | V；2025 候选含官方 demo `3.2.4.0`（`2025-09-08`） | 官方说明把 x86/x64/ARM64 指令转成独有虚拟指令，且可外叠 compressor；没有本次核实的通用逆变换。[V4] | D；这是指令虚拟化，不是普通文件压缩解码。2026 当前版本不纳入目标版本范围。 |
| 26 | ZProtect | R；候选 `1.4.9.0 Preview 2` | 镜像 LIST，未核实自动工具/支持范围。[A1] | D；许可及实现待证，不借 AZProtect 相似名称混计支持。 |
| 27 | SteamStub | R；观察命名的 variant 1、2、3 | Steamless S/DOC，x86 多版本；GHFear WASM S/DOC 明确 x64 `3.0.0/3.1.0/3.1.2`。[S1] · [S2] | 已有 WASM，但 NC/ND 许可不满足核心复用；不包括 Steamworks API 或 Valve CEG。 |
| 28 | Enigma Virtual Box | B；作者 `0.63` unpacker 新增 **10.70/10.80**；更早版本按对应 changelog | kao S/DOC；XEnigmaVB S/SRC 为 `.enigma1/.enigma2` + EVB 包结构 VFS 提取。[K1] · [X11] | 原工具复用许可未核实；MIT XEnigmaVB 是候选。仅提取内嵌文件与还原主 EXE 是两件事。 |
| 29 | MoleBox 2.x / Virtualization Studio | B；`2.x` 与 `4.x` 两代分别处理 | kao `demoleition 0.65` 面向旧 2.x；`demoleition VS` 作者明示静态 4.x 路线，S/DOC。[K2] | 原生静态工具，不是调试器；源码/再分发许可未核实。隐藏文件名只存哈希时不能保证恢复原名。两代保守合并一组。 |
| 30 | BoxedApp Packer | B；匹配 `.bxpck/.main` 和 `BoxedApp::` 的布局，版本范围未知 | XBoxedApp S/SRC：STORE/zlib VFS 提取。[X12] | MIT 可移植候选；没有以准确产品版本建立的验证矩阵，不宣称全版本。 |
| 31 | AutoIt 编译容器 | B；v2/JB01、v3 **EA05/EA06** | XAUTOIT S/SRC：对应容器/流生成器；镜像另有 AutoIt Extractor/UnAutoIt LIST。[X13] · [A2] | MIT 候选；提取脚本/字节码不等于完全反混淆/恢复原源码。 |
| 32 | PyInstaller | B；原 Python 工具列 `2.0` 起离散测试版；Go web 自身范围另验 | pyinstxtractor-go S/DOC + JS 浏览器构建；原 Python 测试清单不能直接转给 Go 实现。[G1] · [G2] | **MIT 现成浏览器 bundle 路线**；不支持加密 PYZ，Python 2 的 PYZ 受限；不算原生壳。 |
| 33 | Inno Setup | B；innoextract README `1.2.10–6.3.3`，目标仍截到 2025 | innoextract S/DOC；不执行安装脚本，静态提取文件。[G3] | zlib，WASM 需移植及传递依赖审计；不把 2026 镜像新工具版本作为 2025 支持依据。 |
| 34 | InstallShield CAB | B；作者目标 `5 and later`，非所有未来变体 | unshield S/DOC/SRC，库与 CLI 分离。[G4] | MIT+C/zlib 适合移植；只覆盖对应 CAB，不承诺任意 installer、MSI 或自解压 stub。 |

## 6. 吾爱目录记录与证据强度

`down.52pojie.cn` 按用户要求**单请求串行访问**：先读取 `/Tools/Packers/`，完成后读取 `/Tools/Unpackers/`；各一页，没有并发抓取该 host，也没有下载归档。[A1] · [A2]

目录只证明在研究日存在该文件名、显示时间与大小。不能证明：归档内容真实版本、工具来源、作者授权、支持完整范围、可运行性、算法许可。

- Packers 页含 `ASPack_v2.42.rar`、`PECompact_v3.02.2_Final.7z`、多个 Obsidium/Themida/WinLicense/Code Virtualizer/Enigma Protector 版本。
- `UPX_v5.2.1_x32.zip`、`UPX_v5.2.1_x64.zip` 显示 **2026-09-01**，不用于证明 2025 UPX 范围；本报告另用上游 `v5.0.0` 发布记录作 2025 锚点。
- Unpackers 页的 `Enigma_Virtual_Box_Unpacker_v0.63.zip`、`unlicense-py3.11-x86.zip` 有上游作者/仓库可交叉核实；ASPack/ASProtect/PECompact 等目录项只有 LIST 等级时不升级。
- `InnoExtractor_v12.0.0.181.7z`、`InnoUnpacker_v2.2.12.1.zip`、`pyinstxtractor-ng.7z` 显示 2026 更新；收录日期不是加壳器版本发布日期。
- 目录 `Molebox_Virtualization_Studio_unpacker_v0.65.zip` 与作者“demoleition 0.65 属于 MoleBox 2.x”的命名存在歧义；应检查归档说明后再决定，不能因文件名把 2.x/VS 支持混为一谈。

## 7. 第一条真实脱壳链的实施路线

### MPRESS 2.19 / PE32 / LZMAT

选择依据：RetDec 插件有准确 `MPRESS_UNPACKER_STUB_212_219_LZMAT` 分支和整个转换链，直接看 `mpress.cpp`，不依赖运行 Windows 样本，也不依赖 Qt。源本体 MIT，可按需移植纯算法和结构逻辑。[R2]

1. 固定 RetDec 提交，只移植必需 decoder、stub 定位和重建行为；避免把全部 decompiler 及无关三方库引入 WASM。
2. 输入先限定 `Machine=I386`、`OptionalHeader.Magic=0x10B`、已知 stub、准确算法/版本。节名只作辅助证据；PE32+ 与未知 stub 返回 `unsupported-variant`。
3. 实现解压后 CALL/JMP filter、imports/OEP/relocations 修复，以及真实磁盘布局重建；不能直接把 RVA 内存镜像当磁盘 PE 导出。
4. 样本验收记录：加壳器准确版本与参数、原始文件及 packed 文件 SHA-256、输出 SHA-256、架构、imports/exports/resources/TLS/relocs 对比。先由 M 使用来源清晰的良性样本建立基准；本次未执行样本。
5. 验收分层：`payload-decoded` → `analysis-pe` → `rebuilt-pe` → `runtime-verified`。结构解析通过只能到 `rebuilt-pe`；最后一级需要针对良性样本、适当 Windows 环境的实际行为测试。
6. 必须有截断/坏偏移/坏距离/扩张超限/不支持变体拒绝用例；不能把失败后的原文件拷贝、零填充 dump、熵下降或取消壳节名标为成功。

后续优先级：RetDec UPX 的 PE 重建 → FSG 1.33/2.0 分析镜像及导入修复 → ASPack 2.12/2.42 严格样本验证。FSG 的 MIT 源路径明确且轻量，但它当前的 imports 缺口决定了不能用它替代首个“可运行原程序恢复”承诺。[R3] · [X2] · [X3]

建议每个能力条目独立存：`family`、`variant`、`arch`、`mode(static/emulated/native)`、`sourceCommit`、`license`、`evidence`、`outputKind`、`validation`。检测命中、存在算法、已编译 WASM、已过样本四项分别呈现；本报告的 34 行不直接写入 supported count。

## 8. 可复核的上游快照与遗留

以下是本次 GitHub API 返回的提交，用于复核浮动链接：

```text
horsicq/Detect-It-Easy   11cb5cb00f8763426005914ed3d983e729760749
horsicq/DIE-engine       37d832e0043778c0b9b1ee883bd1b216cf5896ec
horsicq/die_library      63c1d67784b8f7287609ba97d4b56061c0c07402
horsicq/die_script       145f7f4a5ad28ce27702ee71cadde4e548174454
horsicq/XStaticUnpacker  746fb24433c29b6460edebac83fdad19909d9e81
avast/retdec             9450585772e6f1c18e5f0b2ad5518a18d6bce71e
xoreaxlmbdx/die-in-browser b518be299b85b3d1a8e6fcd1bc58b0147cfc18dc
secnotes/onlinedie      1ef9fe82a1c5a18a626c967348c1b96ebb9fc807
orcastor/unpack         56fd9698d991330f5c3e904cae141c6b9cc74d77
```

遗留：尚未构建/实测 WASM，未完成完整传递许可审计，未验证原生输出可运行性，未审计所有 clean-room 声明的来源历史；目录型历史工具的归档说明与许可证仍未知。以上都不会被“调研完成”状态消除。M 采用具体模块时应复核本报告链接与固定源码，建立逐版本良性样本验收。

## 9. 来源索引（均于 2026-10-05 访问）

引用以作者仓库源码、许可证、官方文档为主；A1/A2 是用户指定的镜像目录，证据等级较低。GitHub 搜索用于发现项目，**未把搜索结果数当作工具总数或覆盖数**。检索包括 `detect-it-easy wasm`、`"Detect It Easy" wasm in:readme`、`upx wasm`、`unpacker wasm`、`PE unpacker javascript`、`aspack unpacker`、`FSG javascript`；README 内检索补找到了名称搜索遗漏的 DIE 浏览器项目。

DDB 中本次核对的历史规则路径包括 `packer_RLPack.2.sg`、`packer_WWPack32.2.sg`、`packer_PECompact.2.sg`、`protector_tElock.2.sg`、`protector_ACProtect.2.sg`、`protector_PELock.2.sg`、`protector_Strongbit_EXECryptor.2.sg`、`protector_VMProtect.2.sg`、`protector_Armadillo.2.sg`；这是规则作者的检测证据，不是厂商支持表或自动脱壳成功表。

[D1]: https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/LICENSE
[D2]: https://raw.githubusercontent.com/horsicq/DIE-engine/master/LICENSE
[D3]: https://raw.githubusercontent.com/horsicq/die_script/master/LICENSE
[D4]: https://raw.githubusercontent.com/horsicq/die_library/master/LICENSE
[D5]: https://raw.githubusercontent.com/horsicq/Formats/master/LICENSE
[D6]: https://github.com/horsicq/XArchive
[D7]: https://raw.githubusercontent.com/horsicq/DIE-engine/master/.gitmodules
[D8]: https://raw.githubusercontent.com/horsicq/die_library/master/.gitmodules
[D9]: https://raw.githubusercontent.com/horsicq/die_library/master/src/CMakeLists.txt
[D10]: https://raw.githubusercontent.com/horsicq/die_script/master/die_script.cmake
[D11]: https://raw.githubusercontent.com/horsicq/XScanEngine/master/xscanengine.cmake
[D12]: https://github.com/horsicq/XCapstone/tree/master/3rdparty/Capstone/src
[D13]: https://raw.githubusercontent.com/horsicq/die_script/master/xscriptengine.h
[D14]: https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/README.md
[D15]: https://github.com/horsicq/Detect-It-Easy/tree/master/help
[D16]: https://api.github.com/repos/horsicq/DIE-engine/releases/latest
[DDB]: https://github.com/horsicq/Detect-It-Easy/tree/11cb5cb00f8763426005914ed3d983e729760749/db/PE
[B1]: https://github.com/xoreaxlmbdx/die-in-browser/tree/b518be299b85b3d1a8e6fcd1bc58b0147cfc18dc
[B2]: https://github.com/secnotes/onlinedie/tree/1ef9fe82a1c5a18a626c967348c1b96ebb9fc807
[B3]: https://github.com/secnotes/onlinedie/tree/1ef9fe82a1c5a18a626c967348c1b96ebb9fc807/wasm-build
[Q1]: https://github.com/qt/qtbase/blob/6.8/src/corelib/global/qglobal.h
[Q2]: https://github.com/qt/qtdeclarative/blob/6.8/src/qml/jsapi/qjsengine.h
[Q3]: https://github.com/qt/qtbase/blob/6.8/src/plugins/platforms/wasm/qwasmintegration.cpp
[Q4]: https://doc.qt.io/qt-6/wasm.html
[R1]: https://github.com/avast/retdec/tree/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool
[R2]: https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/mpress/mpress.cpp
[R3]: https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/pe/pe_upx_stub.cpp
[R4]: https://raw.githubusercontent.com/avast/retdec/master/LICENSE-THIRD-PARTY
[R5]: https://raw.githubusercontent.com/avast/retdec/master/LICENSE
[X1]: https://github.com/horsicq/XStaticUnpacker/tree/746fb24433c29b6460edebac83fdad19909d9e81
[X2]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xfsg.h
[X3]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xaspack.h
[X4]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xmew.h
[X5]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xpetite.h
[X6]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xnspack.h
[X7]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xyoda.h
[X8]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xstaticunpacker.cmake
[X9]: https://raw.githubusercontent.com/horsicq/XArchive/master/Algos/xucldecoder.h
[X10]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xupx.cpp#L3393-L3401
[X11]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xenigmavb.h
[X12]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xboxedapp.h
[X13]: https://github.com/horsicq/XStaticUnpacker/blob/746fb24433c29b6460edebac83fdad19909d9e81/xautoit.h
[U1]: https://github.com/unipacker/unipacker
[U2]: https://github.com/unipacker/unipacker/blob/master/Tests/test_unpacker.py
[U3]: https://github.com/unipacker/unipacker/blob/master/setup.py
[C1]: https://github.com/Cisco-Talos/clamav/blob/main/libclamav/pe.c
[P1]: https://raw.githubusercontent.com/upx/upx/devel/LICENSE
[P2]: https://github.com/hi098123/upx-wasm/tree/main
[S1]: https://github.com/GHFear/Steamstub-v3-Unpacker
[S2]: https://github.com/atom0s/Steamless
[G1]: https://github.com/pyinstxtractor/pyinstxtractor-go
[G2]: https://github.com/extremecoders-re/pyinstxtractor
[G3]: https://github.com/dscharrer/innoextract
[G4]: https://github.com/twogood/unshield
[E1]: https://github.com/mandiant/speakeasy
[E2]: https://github.com/ergrelet/unlicense
[E3]: https://github.com/x64dbg/TitanEngine/tree/x64dbg
[E4]: https://github.com/NtQuery/Scylla
[E5]: https://github.com/anpa1200/Unpacker
[O1]: https://github.com/orcastor/unpack/tree/56fd9698d991330f5c3e904cae141c6b9cc74d77
[O2]: https://github.com/orcastor/unpack/blob/56fd9698d991330f5c3e904cae141c6b9cc74d77/fsg/fsg.go
[K1]: https://lifeinhex.com/another-update-to-enigma-virtual-box-unpacker/
[K2]: https://lifeinhex.com/tag/molebox/
[V1]: https://www.pelock.com/products/pelock
[V2]: https://www.obsidium.de/
[V3]: https://www.enigmaprotector.com/en/about.html
[V4]: https://www.oreans.com/codevirtualizer.php
[A1]: https://down.52pojie.cn/Tools/Packers/
[A2]: https://down.52pojie.cn/Tools/Unpackers/
[L1]: https://www.apache.org/licenses/GPL-compatibility.html
