# 通用/自动脱壳 GUI：宣称 vs 真实能力拆解

日期：2026-10-07。任务：核清工具集内"通用脱壳机"类 GUI 的宣称与技术内核；只做研究，不改引擎。
方法承接 `docs/research/gui-unpackers-reverse.md`（Ghidra 12.1.2 headless、`scripts/reverse/analyze.py`、`verify.py` 独立字节复核）。
**全程未运行任何样本本体**（目标 EXE/DLL 均只作数据加载；`upx -l` 仅只读列举且未解包任何文件）。

## 0. 目标对齐：文件名考古

任务所指三个文件名在库内均无精确同名，实际对应关系如下（穷举依据：全库文件名 + 60 余个 EXE/DLL 的 GBK/UTF-16 标题字符串扫描，见 §7 局限）：

| 任务描述 | 实际最佳对应 | 依据 |
| --- | --- | --- |
| "支持 45 种保护壳 42 种加壳的自动识别通用脱壳工具" | `支持 45 种编译器和 42 种加壳、加密类型查壳工具.exe` | 唯一含 45/42 宣称的文件；**注意原名是"查壳工具"（识别），不是脱壳工具** |
| "高级动态脱壳机.exe" | 库内不存在此名/此标题 | 全库标题串扫描无"高级动态脱壳机"；两个语义近邻：GUnPacker 0.5（"通用"命名，§2）、超级巡警虚拟机自动脱壳机 V1.5（"动态"=VM 仿真，§4） |
| "通用脱壳机*V1.5*.exe" | 两个含 V1.5 的实体：UnpkT0l v1.5（§3）、超级巡警虚拟机自动脱壳机 V1.5（§4） | 字面 universal unpacker / 文件名 V1.5 |

另附对照组 CoolDumpper（§5，库内第三种"通用"架构）。

## 1. 工具 A：Language 2000 v4.5.1.144 —— "45/42" 宣称本体

原件：`支持 45 种编译器和 42 种加壳、加密类型查壳工具.exe`，1308356 字节，
SHA-256 `c686ffdacd82e0ecdcacb334f7cc3e6136bda5cf3687390aaffebef6aa653345`。

### 1.1 身份（字节实证）

`.rsrc` 内 VS_VERSION_INFO 完整可读：

- ProductName `Language 2000`，ProductVersion `4.5`，FileVersion `4.5.1.144`，OriginalFilename `language.exe`
- FileDescription `Language - 最终编译器检测工具`，CompanyName `farrokhi.net Internetwork Consulting`，`(C) 1996 - 2000 Babak Farrokhi`

即 1996-2000 年的编译器/壳检测器；当前副本是 **2023-04-22（COFF 时间戳 1682154587）用 MPRESS 重打包**的老工具：节表 `.MPRESS1/.MPRESS2/.rsrc`，入口 RVA `0x16f398`。

### 1.2 能力面（导入表实证）

导入仅 `GetModuleHandleA`、`GetProcAddress` 两个内核 API（MPRESS stub 所需）。无文件写、无进程/线程/调试/内存 API 证据面。与"检测器"身份一致：**不存在脱壳执行面**。

### 1.3 "42 种加壳识别"的实现方式（Q4）

资源树（`.rsrc` raw `0x115000`）解析出命名资源 `SCRIPT`，含两个 RCDATA 叶：

| 资源 | 数据 RVA | 大小 |
| --- | --- | ---:|
| `SCRIPT/#101/2052` | `0xdf2f0` | `0xe04` |
| `SCRIPT/#103/2052` | `0xe00f4` | `0x8cc83`（约 576KB） |

两个数据 RVA 均超出该 PE 映像范围（节止于 `0x172000`），证明原资源数据已被压入 `.MPRESS1`，但**体积与命名实证了一个内置签名/脚本库**（约 576KB）。判定：**签名库驱动的识别，非启发式**；逐条签名内容未能提取（见下）。

### 1.4 静态解压尝试（失败，如实记录）

对 `.MPRESS1`（raw `0x200`，`0x114600` 字节）做了暴力静态 LZMA 探测：起始偏移 0..0x8000 × 7 组 props（含 `0x5d/0x03`）共 229,376 次 `FORMAT_ALONE` 解码尝试，无一产出 ≥0x800 字节输出。结论：MPRESS 的 LZMA 流不在扫描窗口或容器格式与猜测不符，**本轮未破解**。

### 1.5 判定

- 宣称：45 种编译器 + 42 种加壳/加密类型（识别）。
- 实测：**纯查壳器**。识别库存在（资源实证），库内容未解出。
- Q1（壳名单与压缩/保护占比）：**无法从本二进制提取**。仅有时代推断：Language 2000 终版为 2000 年，其加壳/加密类型以当时的压缩壳与安装器为主（UPX/ASPack/PECompact/Petite 一类），ASProtect 刚起步、Themida/VMProtect 尚不存在——此句为**推断**，非字节证据。
- 产物等级：**analysis-only report**（对照 `protector-boundaries.md` 等级表；连 `extract-pe` 都不适用，因为根本不脱壳）。
- 对我们引擎：无可移植增量（识别能力已被 DIE 规则库覆盖）。

## 2. 工具 B：GUnPacker 0.5 —— 字面"通用脱壳机"，静态 PE 级

原件：`GUnPacker0.5/GUnPacker.exe`，2091520 字节，SHA-256 `2f9f29b22f552a6a4a082c23d5641b69b26d3fe00e08cde0bc312793eca4404d`。

- Delphi 程序（CODE/DATA/BSS/.idata/.tls/.rsrc/.reloc），COFF 时间戳伪值 1992。
- **`.ecode0/.ecode1/.ecode2` 三个加密节**，入口 RVA `0x44f888` 落在 `.ecode2` 尾部；该区代码含 `0f 85`/`e9` 交错跳转与运行时写 `0xe9` 字节的多态形态。
- 节名与库内 EncryptPE 样本（`EPE0/EPE1`）不同，亦非 UPX/MPRESS：**保护壳未识别**。
- `.rsrc` 与全文件无 TPF0 明文、无版本串、无可用界面文案（低位偏移字符串均为位图字形数据）。

判定：宣称、内核、产物等级**全部无法验证**。"通用脱壳机"四字（仅存在于目录名）当前无证据支撑，也无反证。仅静态 PE 级诚实入档。不列为增量来源。

## 3. 工具 C：UnpkT0l v1.5 —— 纯 PE 结构修正器

原件：`UnpkT0l_Unpacked_Hanzified_English_2in1/UnpkT0l Unpacked v1.5.exe`，913408 字节，
SHA-256 `1251f678a086f93e387ff19a32dd73361922c62c955195de26fb0c68e99d622b`（此副本本身已被脱壳，故名 Unpacked）。
作者自述：`UnpkT0l v1.5 [Coded in 7 hours by Spirit // 04 apr 2oo8]`，问候语含 `CrackL@b * Unpack.Cn`。

### 3.1 界面即功能边界（DFM 实证，raw `0xa7000` 起）

主窗体控件：`File name`、**`New EP RVA:`**、**`Import table RVA:`**、**`Import table Size:`** 三个十六进制输入框（默认 `00000000`）、节表 ListView（Name/V.Offset/V.Size/R.Offset/R.Size/Flags）、`Change`、`Save Res` 按钮、`Delete section`/`Restore resource` 菜单。
自述 features（raw `0xa7f6e`）：

```
Auto-correcting SizeOfImage, Checksum, TLS and Relocation Table
Manual deleting unimportant sections. :-)
Auto-rebuilding resources. :-P
```

即：OEP 与 IAT 位置**由用户手工输入**（从别处找好），工具负责落盘时的结构修正。

### 3.2 导入重建语义（代码实证）

- `0040d71c`：SEH 保护的 `LoadLibraryA`——按 DLL 名加载以解析真实模块（`资料/reverse/unpkt0l`）。
- `0040e0f4`：`GetProcAddress(hMod, name)`，失败回退原值——IAT 穿针解析。
- 导入表整体仅 `LoadLibraryA/LoadLibraryExA/GetProcAddress/FreeLibrary/GetModuleHandleA/VirtualAlloc`。无进程、线程、调试、远程内存 API。

### 3.3 判定

- 技术内核：**dump 后 PE 修正器**（改 EP、按用户给的 RVA/size 重建导入表、修 SizeOfImage/Checksum/TLS/重定位、节删减、资源重建）。
- 不含任何解码器、不做 OEP 搜索、不区分压缩壳/保护壳——它假定你已经有 dump。
- 产物等级：服务于 **dump-pe** 等级的最后一英里；对保护壳无专门处理，无 stolen OEP/Nanomites/代码变异能力。
- 对我们引擎：可移植的是**语义清单**（EP/IAT/TLS/Checksum 修正顺序与输入面），无新算法。
- 拆解深度：2835 内部函数、114126 条文件映射指令、11243 条直接 CALL 独立复核通过；选取 4 函数反编译（2 处 API 解析 + 2 处自动挑选）。

## 4. 工具 D：超级巡警虚拟机自动脱壳机 V1.5 —— 唯一的真增量（仿真执行）

原件组（2008-03-17 同日构建，`超级巡警脱壳机1.5 专版/`）：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `VMUnpacke.exe`（MFC GUI） | 1881570 | `a55455b9ce1e97e94580a72071d4ac96f776d4395f9ff45dae2349338652ffc7` |
| `VUnpackSDK.dll`（引擎） | 700416 | `c389950e5612899dca926af3e228ef80046df10baa86693de9d748775903cdb8` |
| `unpack.avd`（加密库） | 31016 | `ae85273e93959ede3fc457303338a56059874777d94f6f8297b2089febf5b584` |

另有 2022-08-08 UPX 重打包的单文件版 `超级巡警虚拟机自动脱壳机 V1.5(卡饭社区专版).exe`（SHA-256 `839d03f3…575110`），标题串相同，未用其分析。
窗口标题（GBK）：`超级巡警虚拟机自动脱壳机 V1.5(卡饭社区专版)`、`关于 超级巡警虚拟机自动脱壳机 V1.5(卡饭社区专版)`。

### 4.1 GUI → SDK 调用链（代码实证）

- `0040a500`（OnInitDialog）：界面链接 `www.unnoo.com` / `www.dswlab.com` / `bbs.kafan.cn`（卡饭专版实证）；构造 `.\VUnpackSDK.dll` 并调 `00409b70`。
- `00409b70`：`LoadLibraryA` + `GetProcAddress("InitVM"/"SetOEPCallBack"/"GetUnpackFun")` → **`InitVM()`** → **`SetOEPCallBack(004113a0)`**；随后 GUI 另行加载 `.\unpack.avd`（`00409c80`→`00410a00`，库在场与否切换状态文案）。
- `004113a0`（OEP 回调）：遍历内部列表调 `00410eb0(OEP_VA, 0, ctx)`——把仿真找到的 OEP 送回界面确认。

### 4.2 引擎结构（VUnpackSDK.dll，6 导出）

`InitVM`、`SetOEPCallBack`、`GetUnpackFun`、`GetUnpackFunArray`、`GetASTUnpackFun`、`GetASTUnpackFunArray`、`GetStaticUnpackFun`（导出目录 6 项）。

**壳类型计数（Q1 口径实证）**：

- `GetUnpackFun(10002f70)`：`id - 40000 < 0x73` → 主 ID 段 **40000–40072，共 115 个壳类型**，函数指针表在 `0x1001bd04`；
- `GetASTUnpackFun(100030f0)`：附加段 `0xa029–0xa032`（10 个），指针表 `0x1001c09c`；
- `GetASTUnpackFunArray(10002fa0)`：复制 `0xe6` dword 的指针/数据对数组，返回计数 **`0x7d` = 125 个脱壳驱动**；
- 驱动可外扩：三个 Get* 均先尝试 `LoadLibraryA("SUnpackSDK.dll")`（扩展 SDK）。

**unpack.avd**：头部明文 `Antivirus Database.T.(c)dswlab 2006-2008.` + 构建时间 `2008/03/15 16:53:19` + magic `asun`（raw `0x84`），其余为高熵加密体。即每壳签名/驱动库加密在库文件里，**逐壳名单未能解出**。

### 4.3 仿真执行核心（本轮核心新证据）

- **影子内存装载**（`FUN_100034c0`，raw `0x34c0`）：校验 MZ/PE 与节表 → `malloc(SizeOfImage+0x400+…)` → 映射节 → 在影子栈区铺 0x1000 自引用链，写 SEH 链锚 `0xffffffff` 与记录 `0x83bb7020`。双装载器（`param[8] >= 2` 走 `FUN_10005060`，否则 `FUN_100034c0`）。
- **假 Win32 环境**（`FUN_10037fa0`，raw `0x37fa0`）：`GetModuleHandleA("kernel32.dll")` 后**把真 kernel32 镜像整体 memcpy 进影子空间**，按影子基址重算导出表，并登记约 20 个 API 的影子地址：GetProcAddress、VirtualProtect/VirtualAlloc/VirtualFree(/Ex)、LoadLibraryA(/ExA)、GetModuleHandleA、GetModuleFileNameA、CreateFileA、ReadFile、CloseHandle、CreateMutexA、GetCurrentProcessId、OpenProcess、VirtualProtectEx、CreateThread、GetExitCodeThread——供被解释的壳代码"调用"。
- **OEP 判定**（`FUN_1002f000`）：仿真推进后检查 OEP 候选处字节 `ff 64 24`（`jmp [esp+x]` thunk 形态）→ `FUN_100040f0(1)` 收尾 → 经 `DAT_1007529c`（SetOEPCallBack 所存）通知 GUI。
- **交付**：`malloc`+`memcpy` 影子影像 → 用户回调 `(status, image, size, ctx)`，`param[9] = OEP_RVA`；`param[8]==0` 分支走 `FUN_10004b20`（**静态重建路径**），否则直接交影子 dump；`param[5]` 选择第二引擎链（`FUN_10004930`+`FUN_1001be10`）。
- **无 Windows 调试器 API**：全 DLL 导入无 CreateProcess/WaitForDebugEvent/GetThreadContext/WriteProcessMemory/ReadProcessMemory。OpenProcess/VirtualProtectEx 仅出现在影子 API 表中。

结论：它是**进程内 x86 解释执行 VM + 影子内存 + 最小 Win32 仿真面**的脱壳机，不是调试器、也不是静态解码器。x86 解释器本体位于 `.SuCop0/.SuCop1` 自保节与 VMProtect 标记的 `InitVM` 内（GUI 亦含 `VMProtect begin/end` 串），**未逐指令复原——本轮到架构证据为止**。

### 4.4 判定

- 宣称：通用自动脱壳（125 驱动计数为字节实证）。
- 技术内核：仿真执行替代"运行目标"，天然免疫常规反调试（IsDebuggerPresent 对解释器无意义）。
- 产物等级：**dump-pe**——交付物是 OEP 时点的影子内存影像 + OEP RVA；部分壳走重建路径（`FUN_10004b20`），逐壳覆盖因 `.avd` 加密未知。不到 rebuilt-pe 的普适承诺。
- 增量技术（Q3）：**x86 仿真执行是【OEP 定位 + 内存 dump + IAT 重建】之外的真实增量**；stolen OEP 修复、Nanomites 处理、代码变异还原本轮**均无证据**（不宣称有，也不断言无——库未解密）。
- 拆解深度：SDK 1909 内部函数、105015 条指令、6554 条直接 CALL；GUI 3137 函数、124706 条指令、7976 条直接 CALL；全部独立复核通过；反编译 13+16 个函数。

## 5. 对照组：CoolDumpper —— "通用"的第三种含义

`CoolDumpper/loader.exe` 明文串：`CoolDumpper - All Packers Generic Unpacker`、界面文案 `选择脱壳插件`。`plugin/` 下 37 个每壳 DLL（Acprotect、armadillo、ArmProtector、aspack、Asprotect、BeRoExePacker、dbpe、EXECryptor、exPressor、fsg、hmimys、hying(04x)、jdpack、KByS、KenPack、Mew、morphine、NsPack、orien、packMan、PCSHRINK、PECompact、pelock、PEncrypt、pespin、petite、polyENE、rlpack、shoooo、starforce、super(穿山甲)、telock、upack、upx、vcasm、VFP、yoda），每个导出 `StartUnpack`；`tool/` 内置 `ImpREC.dll` 与 `Disasm.dll`。
即：**"通用"= 插件式每壳 dump + ImpREC 重建，GUI 只是调度器**——通用性来自插件数量，不来自算法。（字符串级证据，未做函数级拆解。）

## 6. 总结论：GUI 为什么敢标"通 XX 种壳"

1. **偷换概念**：最狂的 45/42 宣称属于**查壳器**（Language 2000，文件名自证"查壳工具"），识别壳 ≠ 会脱壳；用户记成"脱壳工具"正是这类命名的误导效果。
2. **计数口径**：125/115 的数字来自壳类型 ID 段与每壳驱动/签名库条目（含压缩壳、安装器甚至编译器），不是"125 种保护壳全自动重建"。
3. **产物等级天花板**：库内所有"通用"工具的产物都是 **dump-pe 或其后处理**（UnpkT0l 连 dump 都不做，只修结构），无一给出普适 rebuilt-pe。对照 `protector-boundaries.md`：ASProtect 2.x+、Themida、VMProtect、穿山甲这些保护壳的自动重建线，2008 年的工具与我们今天一样停在 dump/extract 级。
4. **真增量只有仿真执行**（超级巡警 VM）。其"支持多壳"的本质是 125 个每壳驱动堆人力（同 CoolDumpper 的 37 插件范式），不是通用算法突破。
5. 对我们引擎的可移植增量候选（研究候选，非已验收实现）：
   - x86 指令级仿真执行壳 stub（替代"运行目标"，免疫反调试，可与纯静态引擎互补）；
   - 影子 kernel32 + 约 20 API 重定向的最小 Win32 仿真面设计；
   - OEP thunk 形态签名（`ff 64 24` 类）作为仿真终止条件之一。

## 7. 方法、复核与局限

- 未运行任何样本；Ghidra 12.1.2 headless + JDK 21（`C:\tools`），流程照抄 `gui-unpackers-reverse.md` §9；`upx -l` 只读列举（两个 RL!dePacker 均 `NotPackedException`，其 `.UPX1` 节名为伪装）。
- 三个新 case 私有产物：`资料/reverse/vmunpack-sdk/`、`资料/reverse/vmunpack-gui/`、`资料/reverse/unpkt0l/`；`verify.py` 全部 `passed=true`，指令 0 条未映射，反编译 0 失败。
- 局限与推断标注：
  - Language 2000 签名库内容未提取（MPRESS 未破，229,376 次静态 LZMA 尝试失败）；§1.5 的时代名单构成是推断；
  - `unpack.avd` 加密未解，125 驱动的逐壳名称、是否有 stolen OEP/Nanomites 处理，未知；
  - 超级巡警 x86 解释器本体（SuCop/VMProtect 节内）未逐指令复原，"VM"判定依据是影子内存+假 kernel32+无调试 API 的架构证据组合；
  - GUnPacker 的 `.ecode*` 保护壳未识别，其能力无任何结论；
  - "高级动态脱壳机"不存在于本库（标题串穷举为证），相关判断转移至 §2/§4 两个近邻。
