# GUI 脱壳器静态拆解

日期：2026-10-05。交付：研究证据；引擎实现与接入由主线独立完成。

## 结论

- **PEArmorUnpack 有独立字节流解码器**，可分离研究解压、导入修复、PE 写回三个边界；尚非已许可、已验收的移植源。
- **Petite 有可核对的 ASM 源码**，且 ENLARGE.EXE 外层 Petite stub 的位读取、literal XOR、回溯复制与源码语义对应。内层 GUI 程序仍被压缩，源码标签不能冒充已恢复的二进制 VA。
- **UpxUnpacker 0.2 不是纯静态解码器**：它修改输入映像里的 stub，再间接调用该输入代码。未创建目标进程不等于未执行目标代码。
- **Armageddon 2.3 是 Windows 调试流程**：GUI → 工作线程 → CreateProcessA 调试标志 → WaitForDebugEvent / ContinueDebugEvent → 远程内存读取与重建。
- 已实际分析 4 个主研究 GUI 工具，另保留 RL!deUPX 的补充反汇编。所有目标均作为数据加载，未运行目标、目标 GUI、目标 DLL 或重建产物。

## 1. 分析器、版本与证据层级

实际使用 **Ghidra 12.0.2 PUBLIC** 的 `AnalyzeHeadless`、x86 反汇编器与 native decompiler；语言 ID `x86:LE:32:default`。
版本由安装包 `Ghidra/application.properties` 的 `application.version=12.0.2`、执行日志及导出元数据共同核对。
启动器使用工具箱已有 **OpenJDK 24.0.1，build 24.0.1+9-30，64-Bit Server VM**；`java -version` 原文保存在每个 `run.json`。
自动化解释器：**CPython 3.11.4**；仅标准库，无新增包依赖。
Ghidra 自有代码 Apache-2.0，见 [Ghidra LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0.2_build/LICENSE)；此许可证不授予被分析程序源码的再分发权。

本轮未使用 IDA 或 DIE，未改分析器安装目录、许可证或激活状态。
Java home、临时文件、Ghidra 缓存、设置、项目数据库、反编译文本均定向至 `资料/reverse/<case>/`。
日志含本机路径，只留私有资料目录；公开脚本、报告只用相对路径和占位符。

证据分级：

1. **字节实证**：原 PE 哈希、文件映射、指令字节、直接 CALL 位移；独立 Python 复核。
2. **控制流实证**：Ghidra 指令、调用/数据引用、GUI 回调参数与消息表；手工沿数据流解释。
3. **语义推断**：自命名函数用途、aPLib-like 分类、可移植边界；不等于版本全覆盖或运行验证。
4. **附带源码**：Petite ZIP 提取原字节与行号；未编译、未证明与 GUI 内层完整构建一致。

Ghidra C 输出只是辅助：Petite 的 CF 位传递和非标准调用约定被错误简化为 `return`/恒假条件；报告中的位流语义以汇编为准。
MFC42 序号名由 Ghidra 附带 exports 表推定；分析日志明确提示可能不是精确 DLL 版本，消息表字段和目标地址是更直接证据。

## 2. 原件与 SHA-256

输入根均为 `资料/老旧壳脱壳工具/`。下列哈希与 `资料/archive-inventory.json` 匹配，分析前后及最终复核相等。

| 私有 case | 原件相对路径 | 字节数 | SHA-256 |
|---|---|---:|---|
| `petite` | `UnPETite/ENLARGE.EXE` | 11264 | `ed3d6a0a80dd6b1fb52b51b04b73f0106c5b929a6a5d65d4f35593eaac7d346a` |
| `pearmor` | `PEArmorUnpack.exe` | 210390 | `4100ea3554940ce76adf8a3630a398bedb9bd940667aeb56882a087d83345ea8` |
| `upx-unpacker` | `Universal Extractor/bin/UpxUnpacker.exe` | 176128 | `f5a703c6d1c8434eb1a524a2649457aef80ff017ed82e8a19de764410a7454f2` |
| `armageddon` | `Armageddon_v2.3/Armageddon.exe` | 648704 | `9cc693a229c455a03c09703aeabf2e3fd8a1ffdee5c99519044999b7bd395744` |
| `upx-ascii` | `万用脱壳机 RL!deUPX 1.x-2.x.exe` | 135966 | `1e12cb1a644eddc7134db69be0e871b4a56b8d23ab57de2ac1c48a24d7febb3f` |

Petite 源 ZIP：`UnPETite/UNP_SRC.ZIP`，23606 字节；SHA-256 `06c1c886c06633faba24c4029c218413bdf1c819a2fb76d288509d20b3f88cef`，前后相等。
各 EXE 的 ImageBase 均为 `0x00400000`。以下 VA 是首选装载 VA，raw 是**原始文件偏移**；不是运行时 ASLR 地址。

### Petite ZIP 已列出并提取为数据

提取位置 `资料/reverse/petite/source/`；zipfile 校验 CRC，限制总解压大小、拒绝路径穿越与符号链接，只提取 ASM/TXT/RES。

| 成员 | 字节数 | SHA-256 |
|---|---:|---|
| `unpacker.asm` | 9250 | `f8d8022e430be0ba4b83dca177d652e91c7e646e3133818908a79c17753ce899` |
| `petite.l1_to_9.asm` | 7730 | `eba3e7ad77cb6b290d24e397307dd0f04b5a80ba1dee815bb204ad08939b6073` |
| `petite.l0.asm` | 69260 | `1d7b04517bae828e46daa843de1e2ed6ac85b1ff5a3d3b723e31ff7e514f5776` |
| `petite.asm` | 27433 | `f15229237dc52857dc1e1642868461f38ccf6929ea247b5d26ed50e0a01a5b8a` |
| `readme.txt` | 137 | `9b89af0faac79c8c2ab960880c1a08a1f402f642d3433baddcb04e8c38e34f88` |
| `PETITE.RES` | 1540 | `fd640fd581689dcdcdd9c7559138e6405b64284a32b0921e20187d37465389dc` |

ZIP README 只有作者关于源码风格的说明，没有授权条款；外层 README 标称 r!sc enlarger v1.3，支持 Petite 2.1/2.2。**有源代码不等于可并入 Apache 项目**。

## 3. Petite：外层 stub 与内层源码分开定位

ENLARGE.EXE 是 Windows GUI 子系统 PE，本身经过 Petite 压缩。入口 VA `0x00424042` / raw `0x442`；不能把外层 stub 当作内层 GUI 的处理函数。
末节映射：RVA `0x24000`、raw `0x400`；下列 stub 地址均可直接回查原件。

| VA / raw | 实际观察与用途 |
|---|---|
| `00424042 / 442` | 外层入口；建立解包上下文，`00424047` 推入 `00404400` 作为异常处理相关地址；该内层地址此时不是已恢复代码证据 |
| `00424068 / 468` | `ADD DI,0x780`，字节 `6681c78007`；与附带源 `petite.l1_to_9.asm:21` 的 2.2 分支检测吻合 |
| `004240ab…004240df / 4ab…4df` | 块表分派；带高位记录向后 MOVSD，记录前进 `0x0c`；解压记录前进 `0x10`，读输出长度、目的 RVA、压缩数据指针，再跳 `004240f8` |
| `004240ec / 4ec` | 位读取 helper：`ADD DL,DL`，空桶则读取 `[ESI]`、推进 ESI、`ADC DL,DL`，通过 CF 返回一位 |
| `004240f8 / 4f8` | 按输出块长度 `<0x10000`、`<0x40000`、其余选择距离阈值及 5/7/8 位参数 |
| `00424144 / 544`、`00424145 / 545` | literal MOVSB 后 `XOR [EDI-1],BL`；BL 是剩余输出长度低字节，随后递减 EBX |
| `0042414b / 54b` | 双位循环构造变长整数；调用 `004240ec`，用 `ADC ECX,ECX` 累积 |
| `004241ad / 5ad`、`004241b0 / 5b0` | `LEA ESI,[EAX+EDI]`，`REP MOVSB` 回溯复制；须保留逐字节重叠复制语义 |

源码对应的算法边界：

- `unpacker.asm:110–145`：申请输入缓冲 → 选文件/读文件 → `load_pe_into_vmem` → `unpack_file` → 写输出 → 提示与释放。
- `unpacker.asm:249–289`：命令行选择与 `GetOpenFileNameA` 回退。此 GUI 是文件对话框驱动，不要求存在自定义 DialogProc；未将这些源码调用硬贴到压缩内层 VA。
- `petite.l1_to_9.asm:61–76,96–212`：块表、literal/XOR、bit reader、重复距离、变长长度、回溯复制。阈值常量及结构与上述真实 stub 对照。
- `petite.l0.asm:4–51`：独立 level-0 入口、2.1/2.2 分支；`+0x14e` 与 `+0x12d` 探测位置不同。不能用 level-1..9 解码器覆盖 level-0。
- `petite.asm:12–41`：`unpack_petite` → 版本化元数据定位 → `crc_2nd_layer` → `fix_offsets` → 由导入表解密 OEP → `rebuild_pe`。
- `petite.asm:174–433,458–541`：重建 imports/sections、资源、exports/TLS；这些步骤解释为何“解出字节”尚不能称可运行 PE。

移植边界：先做有界字节流/块表模型，单列 level-0 与 level-1..9，随后处理分支过滤、导入、OEP、TLS/资源；原源码里的全局状态、固定分配和异常式兜底不适合作为安全边界。尚缺许可证及逐版本良性样本/golden。

## 4. PEArmor：GUI → 固定解码器 → 文件重建

版本证据：资源/字符串显示 `prjPEArmorUnpack Version 1.1`；错误提示针对 `PEArmor V0.46` / `Hying 0.46`。后者是目标壳族/版本声明，不是测试覆盖结论。
本样本 `.text`/`.rdata` 的 RVA 与 raw 相同，所列地址满足 `raw=VA-0x400000`。

### GUI 分派的直接数据证据

`0x004053e0 / raw 0x53e0` 是 6 个 DWORD 的 MFC 消息映射项：
`[0x111, 0, 0x3eb, 0x3eb, 0x0c, 0x00401540]`。
相邻 `0x004053f8 / raw 0x53f8`：
`[0x111, 0, 0x3e9, 0x3e9, 0x0c, 0x004027a0]`。
即 `WM_COMMAND`、通知码 0、控件 ID 范围、签名标记、成员函数指针；原字节窗口另存 `pearmor/queries.json`。

- `004027a0 / 27a0`：文件选择回调；`00402805` → thunk `00403ff4` → IAT `00405184`（CFileDialog 构造）；`0040280e` → `00403fee` → `00405180`（DoModal）；取路径后更新控件并启用 `0x3eb`。
- `00401540 / 1540`：解包回调；`004015a1` 调 `004022b0`，后者调用 `004023f0` 读文件/构造内存映像。
- `00402422 / 2422` 的 `CreateFileA`、`0040249a / 249a` 的 `ReadFile` 是实际调用点，非仅导入存在性。

### 解码与重建边界

| VA / raw | 证据与语义 |
|---|---|
| `004011d0 / 11d0` | 模式扫描包装，逐地址调 `00401190`；异常处理兜底，不是显式输入长度校验 |
| `004016da / 16da` | 第一次模式查找；后续从命中点相对位置读取压缩区和长度 |
| `0040177a / 177a` | `CALL 00403d10`，解第一层数据 |
| `0040180b / 180b` | 同一解码器处理后续块；表项按 `0x0c` 前进，将解出数据复制回映像 |
| `00403d10 / 3d10` | 固定缓冲区解码入口，ESI=输入、EDI=输出；PUSHAD/POPAD 包装，返回写出长度 |
| `00403d93 / 3d93` | `ADD DL,DL` / 取新字节 / `ADC DL,DL` 位桶 |
| `00403d9d / 3d9d`、`00403d9f / 3d9f` | 变长整数辅助；长匹配、重复距离路径 |
| `00403d5d / 3d5d` | 一字节短匹配，右移距离为 0 时结束；`00403d71` 比较 `0x7d00`，`00403d78` 比较 AH=5，`00403d7d` 比较 `0x7f` |
| `00403d89…00403d8e / 3d89…3d8e` | 将输出指针减距离作为复制源，`REP MOVSB`；该解码路径无 Windows API 调用 |
| `0040204b / 204b` | 输出 `CreateFileA`；`00402078`、`004020c5`、`0040210a` 调 `WriteFile` 写头、节、修正头 |

解码形态是 **aPLib-like LZ 位流**：literal、4-bit 单字节回引/零字节、短匹配终止、gamma 类长度、重复距离及距离相关长度增量。这是结构识别，未建立准确上游版本/授权归属。
主处理器还增加 `0x2400` 工作区、重建导入描述符/名字/序号、修正 `FF25`/`FF15` 间接跳转/调用形式，再写节布局；不是只对某一整节做 inflate。
`VirtualAlloc` 只证明分配行为；本例“可静态化”的正面依据是已追到固定解码器及字节读写路径，不能推广为整个程序绝无其他动态路径。

## 5. UpxUnpacker 0.2：不创建进程，也执行输入代码

版本字符串 `ver0.2` 在 raw `0xb221`、`0xb26a`；`Upx Unpacker` 在 raw `0xb2a4`。此样本 `.text` 同样 `raw=VA-0x400000`。

1. `00402f33 / 2f33` 把回调 `00402daf` 压栈；`00402f42 / 2f42` 通过 IAT `0040a100` 调 `DialogBoxParamA`，资源 ID `0x65`。
2. 回调识别 `WM_INITDIALOG=0x110`、`WM_COMMAND=0x111`、**WM_DROPFILES=0x233**；`00402de5 / 2de5` 调 `DragQueryFileA`；`00402df3 / 2df3` 调处理器 `00402877`。
3. `00402905 / 2905` 调 `00402070`：读磁盘文件，按 SizeOfImage 分配并映射节。`004020ea / 20ea` 是 ReadFile；这里 VirtualAlloc 保护值为 **4（PAGE_READWRITE）**，不能误写成 RWX。
4. `0040298a / 298a`、`00402a00 / 2a00` 调模式扫描器 `004022e3`；分别找恢复段标志和 `60 BE ?? ?? ?? ?? 8D BE` 一类 stub 起点。
5. **`00402a2a / 2a2a` 写 `0x61`；`00402a37 / 2a37` 写 `0xc3`** 到输入映像的命中位置，即 `POPAD; RET`；另调节 stub 中绝对地址以适应本地缓冲区。
6. **`00402a56 / 2a56`，字节 `ff55e8`，`CALL [EBP-0x18]`**；该局部指针来自扫描结果加输入映像基址。解压工作被交给输入携带的机器码，不是工具自己的纯字节解码函数。
7. 返回后 `00402b3f` → `00401d83` 重建导入；`00402b48` → `004018d2` 处理 reloc；`00402b7d` → `00401bf7` 整理资源；最后重写文件。

可研究的纯数据部分：`00401d83 / 1d83` 将 DLL 名称、按名/序号/转引条目恢复到导入表，序号使用 `0x80000000` 高位；`004018d2 / 18d2` 重建 relocation 元数据；`00401bf7 / 1bf7` 遍历资源数据；`0040204e / 204e` 只是 DOS/NT 头指针定位，不能误标为解码器。

重要边界：这是对程序**意图与静态控制流**的判断，不宣称它在现代 DEP 策略下实际运行成功。代码里 PAGE_READWRITE 与间接执行并存，说明有旧环境执行权限假设。
处理器 `00402c23 / 2c23` 调 `SetEndOfFile`，随后 `00402c4e` 等写回原打开文件；若未来人工试用，必须使用副本。本轮未执行此流程。
浏览器静态引擎必须替换“执行输入 stub”这一层为有界 NRV/LZMA 等已许可解码实现，不能照搬间接执行流程。

## 6. Armageddon：GUI → 工作线程 → Windows 调试事件

字符串 `ArmaGeddon V2.3 (final) - ARTeam` 在 VA `00455fe0` / raw `53fe0`。
`.text` 映射 RVA `0x1000` → raw `0x400`，所列代码地址满足 `raw=VA-0x400000-0xc00`；IAT 位于其他节，应按节映射。

| 函数/调用点 VA | raw | 调用证据与职责 |
|---|---|---|
| `0041dba0` | `1cfa0` | GUI 初始化；`0041dc7c` 压入回调 `0041bdb0`；`0041dc85 / 1d085` 调 DialogBoxParamA（IAT `0044d3a0`），资源 ID `0x64` |
| `0041bdb0` | `1b1b0` | 主对话框回调，处理 `0x110`/`0x111`；命令 ID `0x82` 分支启动工作线程 |
| `0041d9f8`、`0041d9ff` | `1cdf8`、`1cdff` | 压入线程函数 `00417660`；CALL `00403985`（`_beginthreadex`）；另一路在 `0041c381`/`0041c38a` |
| `004039fa` | `2dfa` | CRT 线程包装最终调用 CreateThread，形成完整回调到工作线程连接 |
| `00417660` | `16a60` | 调试工作函数；目标 EXE/DLL 启动分支、事件循环、状态机与收尾 |
| `004178f7`、`00417a4b` | `16cf7`、`16e4b` | CreateProcessA（IAT `0044d084`），`dwCreationFlags=3` = DEBUG_PROCESS \| DEBUG_ONLY_THIS_PROCESS |
| `00417cd3` | `170d3` | WaitForDebugEvent（IAT `0044d0d8`），随后按 DEBUG_EVENT 代码分派 |
| `0041ba19` | `1ae19` | ContinueDebugEvent（IAT `0044d0d4`），推进同一调试会话 |
| `0040efa3` | `e3a3` | GetThreadContext（IAT `0044d1b4`），所属 `0040ef90`；与远程修正流程相关 |
| `0040ef47` | `e347` | WriteProcessMemory（IAT `0044d0e8`），所属 `0040ecc0` |
| `00413745` | `12b45` | ReadProcessMemory（IAT `0044d07c`），所属 dump/rebuild 函数 `004135c0 / 129c0` |

`00417660` 的反编译还显示异常/单步事件、远程保护修改、上下文读取及 nanomite 状态分支；`004135c0` 将远程映像读回本地缓冲再整理 PE。
这些是调试器行为，不能当作一条文件字节流解码算法直接移到浏览器。
可分离研究 dump 后的 PE 布局/导入重建语义；事件驱动、远程地址、线程上下文依赖属于 Windows 宿主层。即使改为模拟器，也需另建完整执行模型，不能归入“已有静态引擎”。

## 7. RL!deUPX 补充检查

原名首次被 Ghidra `checkValidFilename` 拒绝，失败日志保留在 `资料/reverse/upx/`；通过 `--stage-ascii` 在私有目录生成等哈希 `target.exe` 后分析成功。原件未改名。
所得 30143 条文件映射指令、752 个内部函数及 3 个初选反编译函数属于补充基线；选出的写文件函数含 Delphi 运行库，**没有据此宣称已定位其 UPX 解码器或 GUI 全链**。
其 `.reloc` 原始数据为空，Ghidra 报 `Invalid file index for a21000`；不以分析退出码 0 掩盖此告警。
完整 UPX 对照结论采用上一节 UpxUnpacker 的实际 handler→输入 stub 证据。

## 8. 可移植候选及待补证据

| 候选 | 可分离边界 | 当前阻塞 |
|---|---|---|
| Petite 2.1/2.2 level-1..9 | 块描述符、位读取、literal XOR、回溯复制；再接 filter/import/OEP 重建 | ASM 授权不明；内层二进制未恢复；缺逐版本/参数样本与独立 golden |
| Petite level-0 | 单独的解码及版本元数据分支 | 不可复用 level-1..9 的覆盖声明；同样缺许可和测试 |
| PEArmor/Hying 0.46 | 固定 aPLib-like 解码器与宿主 I/O 可拆开，导入/间接指令/节写回分层 | 工具闭源/许可未知；解码家族需与许可明确来源独立对照；原扫描器无可靠边界 |
| UpxUnpacker | 导入/重定位/资源格式语义有价值 | 解压通过执行目标 stub；必须以独立已许可静态 codec 替换；目标版本矩阵未测 |
| Armageddon | dump 后 PE 结构整理 | 核心依赖进程/线程/异常事件；不列为浏览器纯静态解包候选 |

“没有 CreateProcess/调试 API 导入”只是一条弱阴性线索：动态解析 API、间接调用、嵌入解释器、执行复制 stub 都会漏检。本轮 UpxUnpacker 给出了直接反例。
支持判断应分开记录：识别到壳 → codec 适配 → 解压字节正确 → PE 结构正确 → Windows 实际运行；本报告只完成研究层，不增加应用支持数。

## 9. 可复现命令与私有产物

仓库根执行；`<TOOLS>` 指用户授权的工具箱根，`<JAVA_HOME>` 可选覆盖自动发现，`<GHIDRA>` 指其 Ghidra 安装目录。
输出必须是新 case 目录；已有项目重导出用 `--reuse`，不重写原件。

```powershell
$Tools = '<TOOLS>'
$InputRoot = '资料/老旧壳脱壳工具'
$Inventory = '资料/archive-inventory.json'
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/UnPETite/ENLARGE.EXE" --output 资料/reverse/petite --inventory "$Inventory" --source-zip "$InputRoot/UnPETite/UNP_SRC.ZIP"
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/PEArmorUnpack.exe" --output 资料/reverse/pearmor --inventory "$Inventory"
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/Universal Extractor/bin/UpxUnpacker.exe" --output 资料/reverse/upx-unpacker --inventory "$Inventory"
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/Armageddon_v2.3/Armageddon.exe" --output 资料/reverse/armageddon --inventory "$Inventory"
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/万用脱壳机 RL!deUPX 1.x-2.x.exe" --output 资料/reverse/upx-ascii --inventory "$Inventory" --stage-ascii
```

实际追加的最终函数选取命令：

```powershell
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/PEArmorUnpack.exe" --output 资料/reverse/pearmor --reuse --function 00403d10 --function 004022b0 --function 004023f0 --function 004011d0 --function 004027a0
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/Universal Extractor/bin/UpxUnpacker.exe" --output 资料/reverse/upx-unpacker --reuse --function 00402daf --function 0040204e --function 00401d83 --function 004018d2 --function 00401335 --function 004027cc --function 00401bf7 --function 004022e3 --function 00402070
py -3.11 scripts/reverse/analyze.py --toolroot "$Tools" --input "$InputRoot/Armageddon_v2.3/Armageddon.exe" --output 资料/reverse/armageddon --reuse --function 0041bdb0 --function 0041dba0
```

启动器直接调用 Java 的 `ghidra.Ghidra ghidra.app.util.headless.AnalyzeHeadless`，而不是会保存全局 Java 选择的交互 launcher。
完整实际 Java argv 经 `<JAVA_HOME>`、`<GHIDRA>`、`<INPUT>`、`<OUTPUT>`、`<SCRIPTS_REVERSE>` 替换后记录在 `run.json` / `run-reuse.json`，含隔离目录 JVM 参数、`-max-cpu 2`、每输入 600 秒分析预算、每函数 45 秒反编译预算。
`--function` 只在分析数据库为指定入口补建函数；命名 `research_<VA>` 是研究者标注，不是原始符号。

每 case 交付：

- `run.json` / `run-reuse.json`：输入前后哈希、版本、命令、退出码；Petite 另含 ZIP 成员清单/哈希。
- `instructions.tsv`：VA、raw、所属函数、原字节、真实反汇编。
- `references.tsv`：来源 VA/raw、引用类型、目的 VA、符号、目的函数；包含调用与数据引用，不限 imports。
- `functions.tsv`、`decompilation.txt`：内部函数范围概要与选取函数的 C 辅助视图。
- `mapping.tsv`、`strings.tsv`、`queries.json`（有窗口查询时）：映射、带地址的字符串、原字节窗口。
- `verification.json`：独立字节/直接调用校验及 6 份文本产物 SHA-256。
- `ghidra.log`、`script.log`、`console.log`、`projects/`：私有分析现场。

验证命令：

```powershell
$Cases = @(
  @('petite', 'UnPETite/ENLARGE.EXE'),
  @('pearmor', 'PEArmorUnpack.exe'),
  @('upx-unpacker', 'Universal Extractor/bin/UpxUnpacker.exe'),
  @('armageddon', 'Armageddon_v2.3/Armageddon.exe'),
  @('upx-ascii', '万用脱壳机 RL!deUPX 1.x-2.x.exe')
)
foreach ($Case in $Cases) {
  py -3.11 scripts/reverse/verify.py --input "$InputRoot/$($Case[1])" --output "资料/reverse/$($Case[0])"
}
py -3.11 scripts/reverse/verify.py --input "$InputRoot/PEArmorUnpack.exe" --output 资料/reverse/pearmor --pointer 0x401540 --dump 0x4053e0:24 --dump 0x4053f8:24
py -3.11 scripts/reverse/verify.py --input "$InputRoot/Universal Extractor/bin/UpxUnpacker.exe" --output 资料/reverse/upx-unpacker --dump 0x402a2a:48
```

## 10. 实际验证与限制

| case | 文件映射指令逐字节一致 | E8 直接 CALL 位移一致 | 内部函数行数 | 选取反编译 / 失败 |
|---|---:|---:|---:|---:|
| Petite | 167 | 8 | 5 | 5 / 0 |
| PEArmor | 4084 | 169 | 79 | 6 / 0 |
| UpxUnpacker | 11502 | 456 | 199 | 13 / 0 |
| Armageddon | 80112 | 5837 | 1322 | 34 / 0 |
| RL!deUPX | 30143 | 2518 | 752 | 3 / 0 |

五份原件 **126008 条**文件映射指令、**8988 条**直接 CALL 校验通过；无无法映射的已导出指令。内部函数数不含外部库符号，故不同于 Ghidra FunctionManager 的总计数。
独立校验直接重新解析原始 PE 节表，核 VA→raw→字节及 E8 相对位移，不把导出工具的成功标记当正确性证明；六个 Petite 提取成员再次核哈希通过。
原始四个主样本分析日志均有 `REPORT: Analysis succeeded`，无分析超时；RL!deUPX 保留上述 relocation 告警。

尚未完成：Petite GUI 内层静态恢复、level-0 全算法逐条核对、任一新引擎实现、逐版本良性样本解包 golden、Windows 运行验收、未知工具/附带 ASM 授权核清。
反编译成功不证明 C 类型/CF/函数边界完全正确；指令字节吻合也不证明所有可执行路径均已发现。
研究产物与源码 ZIP 仅在被忽略的 `资料/` 中保存；公开交付仅原创分析自动化与本语义报告，没有把未知许可解码器或反编译闭源代码并入 Apache runtime。
复核脚本已对五份原件的文件映射指令字节、直接 CALL 位移及输入哈希独立验证；详细解包逻辑移植仍需逐格式与样本验收。
