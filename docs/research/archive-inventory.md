# 老旧壳工具归档：解压与静态盘点

日期：2026-10-05。任务：MT2。清单版本：`schema_version = 1`。

## 结论与证据位置

用户指定的 `老旧壳脱壳工具.7z` 已按原目录结构解压至项目的 **`资料/老旧壳脱壳工具/`**。

- 全量清单：`资料/archive-inventory.json`。每个外层文件都有相对路径、字节数、SHA-256、CRC32；PE 文件附架构、节表、普通/延迟导入、导出、版本资源和字符串证据。
- 可复现脚本：`scripts/inventory.py`，Python 3.10+ 标准库，无 pip 依赖。外部 7-Zip 仅用于读取归档目录。
- 解压前已检查完整目录：388 个条目，未检出绝对路径、`..` 穿越或链接；外层加密条目 0。解压使用外部 7-Zip 26.00，返回 `Everything is Ok`。
- 本次没有执行、加载或调用任何解压得到的 EXE、DLL、脚本、插件，包括归档自带的 7-Zip。
- 内层 ZIP 只读取目录元数据，没有展开、读取源代码正文或计算成员内容哈希。未解决密码问题：**0**；已知内层 ZIP 的 6 个条目也均未设置加密标志。
- 引用材料均标记 `release_eligible: false`；仓库现有 `.gitignore` 排除整个 `资料/`。

## 归档标识与精确数量

归档文件名：`老旧壳脱壳工具.7z`。归档大小：**41,800,933 字节**。

```text
SHA-256 396b951592287beb5d77a6903566c35918eb2182a7c70284435e1db60d45d77b
```

| 项目 | 数量 / 口径 |
| --- | --- |
| 外层目录条目 | 388 = 340 文件 + 48 目录 |
| 解压文件 | 340，合计 99,177,633 字节 |
| 解压目录 | 48，包含 `老旧壳脱壳工具` 根目录；不包含项目的 `资料` 目录 |
| SHA-256 去重文件 | 334；6 组完全相同的文件，每组 2 个 |
| 归档最顶层 | 1 个目录：`老旧壳脱壳工具` |
| 该目录直接子项 | 59 = 34 目录 + 25 文件 |
| `.exe` / `.dll` | 127 / 88；扩展名不代表格式或独立工具数 |
| PE 文件 | 253：x86 251，x64 2 |
| PE 的 DLL 标志 | 127 个；包含非 `.dll` 后缀的插件 |
| 带 CLR 目录的 PE | 9；不等于 9 个跨平台 .NET 应用 |
| 成功取得 RT_VERSION 的 PE | 124 |
| 带解析警告的 PE | 19，清单保留具体失败位置和原因 |
| MZ 但未识别为 PE | 1：`Universal Extractor/bin/Uharc02.exe` |
| 文本/配置/脚本文件 | 75，按脚本的扩展名集合统计；其中 `.txt` 25、`.nfo` 2、`.diz` 1、`.htm` 2、`.ini` 39 |
| 独立源码/脚本后缀文件 | 1：`Universal Extractor/bin/MSIUnPack.vbs` |
| 内层独立归档 | 1：`UnPETite/UNP_SRC.ZIP`，目录中 4 个 ASM 源文件 |
| CoolDumpper 插件目录文件 | 41；包含通用/辅助插件和目标名称变体 |
| 归一化候选壳/保护家族名称 | 64；其中 22 个仅来自随附作者测试声明 |
| 按名称找到的独立许可证文档 | 0；`license.key` 不计入许可证文档 |
| 本次获准随项目发布的材料 | 0 |

完整扩展名计数：

```text
.avd 1       .bin 1      .chm 1       .cnt 1       .config 1
.diz 1       .dll 88     .exe 127     .hlp 1       .htm 2
.ini 39      .jpg 2      .key 1       .manifest 3  .nfo 2
.skn 1       .so 18      .trd 1       .txt 25      .unp 11
.url 1       .vbs 1      .wcx 10      .zip 1
```

两个 x64 工具分别是 `AutoEye_v2.0.0.1000/AutoEye64.exe` 与 `UnAutoIt/UnAutoIt-windows-amd64.exe`。这仅说明工具自身的目标架构，不能推断可处理的壳或样本架构。

计数不包含生成的 JSON，也不把内层 ZIP 的 6 个目录条目当作已解压文件。加壳样本、依赖库、语言文件、同名改版和汉化版均包含在 340 个文件中。

## 顶层名称

下列名称均相对于 `资料/老旧壳脱壳工具/`，大小写及空格保留。

### 34 个直接子目录

```text
AoRE_Unpacker_0.4
Armageddon_v2.3
ArmInline0.96 最终版
AutoEye_v2.0.0.1000
AutoIt Extractor
CoolDumpper
DDeM Protector 脱壳机
DeShrink v1.6
EncryptPE UnPacker
EPE V2 Stripper 高级版 rc4
EPE121脱壳机
EPE_stripper无壳版
GUnPacker0.5
Molebox_Virtualization_Studio_unpacker_v0.65
Nanofixer
UnAutoIt
UnFSG1.33
Universal Extractor
UnObSiDium
Unpacker ExeCryptor 2.x.x. RC1 [Public]
Unpacker_ExeCryptor_RC2_chs
Unpacker_PECompact
unPESpin v11
UnPETite
UnpkT0l_Unpacked_Hanzified_English_2in1
UnSafeDisc_4.60_fixed
WinUpack Stripper v0.3
WinUpack_KiLLeR
WSDP116
yoda's Protector
Zp_Unpacker1.1
北斗3.X系列脱壳机
穿山甲脱壳机-1.6
超级巡警脱壳机1.5 专版
```

### 25 个直接子文件

```text
DeAutoIt.exe
EUnpacker_RemoveNAG.exe
ORiEN.exe
PEArmorUnpack.exe
RL!dePacker.exe
tElock脱壳机.exe
万用脱壳机 RL!deASPack 2.x.exe
万用脱壳机 RL!deFSG 2.0.exe
万用脱壳机 RL!deMEW 1.x.exe
万用脱壳机 RL!deNsPack 3.x.exe
万用脱壳机 RL!dePacker.exe
万用脱壳机 RL!dePacker_x86.exe
万用脱壳机 RL!dePackMan 1.x.exe
万用脱壳机 RL!dePeX 0.99.exe
万用脱壳机 RL!deUPX 1.x-2.x.exe
完美静态脱壳机.exe
支持 45 种编译器和 42 种加壳、加密类型查壳工具.exe
易语言伪装精灵还原.exe
穿山甲Nanomites修复器.exe
穿山甲脱壳机-.exe
编译工具.exe
脱壳工具tmdunpacker.exe
脱壳机Themnet Unpacker_original.exe
超级巡警.exe
超级巡警虚拟机自动脱壳机 V1.5(卡饭社区专版).exe
```

## 候选壳族：64 个去重名称

来源限定为工具路径、CoolDumpper 明确命名的目标插件和 `AoRE_Unpacker_0.4/tested.packers.txt` 的 32 条作者声明。JSON 的 `probable_families[].evidence` 给出每个名称的路径、证据类型及声明行号；`verified_supported_versions` 全部为空。

```text
!EP (EXE Pack), ACProtect, antiOllyDBG, Armadillo, ArmProtector,
ASDPack, ASPack, ASProtect, AverCryptor, BeRoExePacker, CryptX,
DBPE, DDeM Protector, dePack, DexCrypt, EncryptPE, EXECryptor,
eXPressor, FSG, GHF Protector, HidePE, HidePX, Hmimys, Hying,
JDPack, JeyJey UPX Protector, KByS, KenPack, MEW, MoleBox,
Morphine, Morphnah, Mucki's Protector, NsPack, Obsidium, ORiEN,
PackMan, PC Shrinker, PE Lock NT, PE Pack, PEArmor, PECompact,
PELock, PEncrypt, PESpin, Petite, PeX, Pohernah, PolyEnE,
RCryptor, ReCrypt, RLPack, SafeDisc, Shoooo, SimplePack, StarForce,
Ste@lth PE, tElock, The Best Cryptor, Upack/WinUpack, UPX,
UPXScramb, VCasm, yoda's Protector
```

42 个名称有工具路径或插件文件证据，另 22 个只有随附测试列表证据。`hying` / `hying04x` 合并为 Hying，WinUpack / Upack 合并；其他未证实的别名关系不强行合并。这是可追溯的候选名称集合，不是穷尽的壳签名库或已验证支持矩阵。

AutoIt 提取、易语言还原、MSI/安装包提取、查壳器、调试辅助工具另有用途，不增加上述壳族计数。`AntiDebugLib`、`null`、`super`、`VFP` 等插件名也不直接视作独立壳族。`Themnet` 或 `tmdunpacker` 的工具名称不足以独立确认完整 Themida 支持范围。

## 代表性静态观察与迁移可行性

本节路径均相对于解压根目录。JSON 区分真实导入与仅在字符串中出现的 API；导出函数的名称只证明接口线索，不证明实现行为。

| 对象 | 实际静态证据 | 对浏览器 / JS / WASM 的意义 |
| --- | --- | --- |
| `Universal Extractor/bin/upx.exe` | x86；RT_VERSION 为 `3.91 (2013-09-30)`；可见文件操作导入及 `inflate`、`uncompress` 字符串，未命中本脚本的调试/远程内存 API | 值得沿官方源码调查静态算法移植；该二进制不是现成 WASM，未验证任何版本样本 |
| `UnPETite/ENLARGE.EXE` | 描述 `petite 2.1/2.2 decompressor`，字符串版本 `1.3`，固定版本 `1.0.0.0`；`UG2000.NFO` 第 33 行称模拟 Petite 在自身地址空间中的解包过程 | 源码 ZIP 和模拟解包说明使其成为静态研究候选；不能推断一定不运行目标 stub，许可证仍未明确 |
| `Molebox_Virtualization_Studio_unpacker_v0.65/demoleition.exe` | 描述 `de-mole-ition - static Molebox 2.x unpacker`，版本 `0.6.5.0`；同时导入 `VirtualQueryEx`、`ResumeThread` | “static” 是作者元数据声明；进程相关导入可能来自运行库或辅助逻辑，需源码/调用关系核验，不能仅凭导入否定或确认静态性 |
| `PEArmorUnpack.exe` / `完美静态脱壳机.exe` | 两者 SHA-256 完全相同；内部名 `prjPEArmorUnpack`，版本 `1.0.0.1`；命中文件操作，未命中调试/进程控制集合 | 实际是同一文件的两个名称，不是两套引擎；属于静态候选，缺少授权源码及样本验收 |
| `穿山甲脱壳机-1.6/dilloDIE.exe` | 导入 `CreateProcessA`、`DebugActiveProcess`、`WaitForDebugEvent`、`ContinueDebugEvent`、`ReadProcessMemory`、`WriteProcessMemory`、`GetThreadContext`、`SetThreadContext` | 强烈指向 Windows 原生调试工作流；浏览器不能直接提供这些 OS 调试 API |
| `Armageddon_v2.3/Armageddon.exe`、`ArmInline0.96 最终版/Nanolib.dll` | 调试事件循环、进程创建和远程内存 API；Nanolib 导出 `DoNanomites` / `Populate`；ArmInline 文档描述需要磁盘上的加壳 EXE 和内存中的解包进程 | 将 PE 解析移植到 JS 不等于移植 Nanomites/调试修复流程；需独立模拟器或受控宿主设计 |
| `CoolDumpper/plugin/aspack.dll`、`upx.dll`、`PECompact.dll` | 导出 `AboutPlugin`、`InitPlugin`、`StartUnpack`；导入 `ReadProcessMemory`、`WriteProcessMemory`、线程上下文或挂起/恢复 API | 插件数不等于静态算法数；同为 UPX，工具实现仍可依赖动态调试 |
| `Universal Extractor/bin/AspackDie.exe` | `CreateProcessA`、`WaitForDebugEvent`、`ContinueDebugEvent`、`ReadProcessMemory`、`WriteProcessMemory` | ASPack 的此份实现有明确动态路线证据，不能直接当作跨平台静态实现 |
| `Unpacker_PECompact/Unpacker_PECompact.exe` | 版本资源称处理 `PECompact (2.X - 3.X)`；可见 API 证据不足，但 `Readme.txt` 第 22、27 行明确谈到 Delphi debugger、调试进程期间重建重定位 | 缺少可见调试导入不代表静态。文本证据补足了加壳/隐藏导入的局限 |
| `UnSafeDisc_4.60_fixed/UnSafeDisc 4.60 fixed.exe` | 导入 `CreateProcessA`、`ReadProcessMemory`、`WriteProcessMemory`、`NtReadVirtualMemory` 及线程上下文 API | 原生进程操作线索明确；文件名中的 `4.60` 不是本次验收结果 |
| `超级巡警脱壳机1.5 专版/VUnpackSDK.dll` | 导出 `GetStaticUnpackFun`、`GetUnpackFun`、`InitVM`、`SetOEPCallBack` 等；导入 `VirtualProtectEx`、`OpenProcess`，资源含 DSW Lab 的 `All Rights Reserved` | 存在静态/VM 接口线索，但 ABI、实现和授权均未公开核实，不能按导出名认定可移植 |
| `UnAutoIt/UnAutoIt-windows-amd64.exe` | x64；含 `GetThreadContext`、`SetThreadContext`、`SuspendThread`、`ResumeThread` | 这些导入也可能来自语言运行库；不能把脚本提取器直接归为“必须调试目标”的脱壳机 |
| `Universal Extractor/bin/MSIUnPack.vbs` | 21,480 字节源脚本；第 33、34、53 行创建 `Scripting.FileSystemObject`、`WScript.Shell`、`WindowsInstaller.Installer` | 有可读代码，但依赖 Windows COM/脚本宿主，不是浏览器原生 MSI 提取实现 |

### 自动 API 证据桶

按优先级互斥分类，覆盖 254 个 MZ 文件（253 PE + 1 未识别 PE 的 MZ）：

- 68：实际导入了至少一个调试/线程上下文/远程内存 API。
- 5：仅字符串中出现调试/远程内存 API，导入表未命中相应组。
- 85：导入进程控制/启动 API，但前两组未命中。包含仅有 `TerminateProcess` 的运行库，不能解释为 85 个动态脱壳器。
- 38：仅可见文件操作/解压类导入的候选。
- 58：可见证据不足，包含上述非 PE 的 MZ 文件。

这些数字是筛选线索计数。API 缺失、单一 `VirtualQueryEx`、线程上下文函数、`ShellExecuteA` 或 `inflate` 均不能单独证明实际脱壳方式。

### 版本与重复文件的陷阱

- `AoRE_Unpacker_0.4/tested.packers.txt` 第 17 行列举 NsPack `2.9/3.0/3.3/3.4/3.6/3.7`，第 31 行列举 UPX `1.25/1.91/2.00/2.01/2.02/2.90/3.00/3.01`：仅为作者随附声明。
- `Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe` 的目录/ReadMe 写 v1.2，资源却是 `1.1.0.0` 和 `PrivateBuild = 1.1.c`。版本证据有冲突，不可直接按目录记作已验证 v1.2。
- CoolDumpper 的 `PECompact.dll` 资源保留 `OriginalFilename = Mew.DLL`；资源模板也会误导家族识别。
- `支持 45 种编译器和 42 种加壳、加密类型查壳工具.exe` 的资源标识为 `Language 2000` / `4.5.1.144`。检测类别数量不是自动脱壳能力数量。
- 6 组重复还包括两份 `ImpREC.dll`、两个 manifest、两份 EPE 主程序，以及 `bin/7z.exe` / `bin/7z_New/7z.exe` 和对应的 `7z.dll`。完整 SHA-256 与路径组见 JSON 的 `duplicates`。

## 源码、文本与许可证

### 内层源码归档

`UnPETite/UNP_SRC.ZIP`：23,606 字节。

```text
SHA-256 06c1c886c06633faba24c4029c218413bdf1c819a2fb76d288509d20b3f88cef
```

只读取 ZIP 中央目录，成员如下；大小为目录声明的未压缩大小，尚未解压核实：

| 成员 | 字节 |
| --- | ---: |
| `unpacker.asm` | 9,250 |
| `petite.l1_to_9.asm` | 7,730 |
| `petite.l0.asm` | 69,260 |
| `petite.asm` | 27,433 |
| `readme.txt` | 137 |
| `PETITE.RES` | 1,540 |

6 个成员无加密标志、无目录穿越、无 symlink 标志。没有单独命名的 LICENSE/COPYING 成员，但源码头部或内层 README 是否包含许可，本次未读，仍待确认。

### 可读文本中的代码线索

- `Universal Extractor/bin/MSIUnPack.vbs` 是独立可读源脚本；其 SHA-256 为 `04e29676e2570a6600bc54e868bebaf9f857bc6bd81f44a3d2b9752a36b9eda4`。
- `Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/NanoLib.dll Bug.txt` 第 4、142 行明确引出源代码及修正片段；`Nanofixer/NanoLib.dll Bug.txt` 也有对应片段。
- `UnPETite/README.TXT` 有汇编消息定义片段。不能因为没有独立 `.c` / `.asm` 文件而称整个资料包“完全无源码”。
- 文本编码仅自动猜测；部分俄文、NFO 制表字符会失真。原始字节及文件哈希保留，英文 API/版本证据优先采用可直接确认的片段。

### 发布许可判定

外层没有按名称识别到独立 LICENSE/LICENCE/COPYING/COPYRIGHT 文档；这不等于所有组件都没有上游许可证。

可见证据包括：UPX 的内嵌 `UPX License Agreement` / `see the file LICENSE` 提示；7-Zip 的 Igor Pavlov 版权信息；DSW Lab 的保留所有权利声明；RSI、r!sc、ARTeam 等作者/版权字符串。版权署名、免费发布、源码可见、工具名称或 `BSD` 字符串均不自动授予本项目重新分发或移植许可。

`超级巡警脱壳机1.5 专版/license.key` 是授权数据文件名，不是再分发条款。清单仅记录其元数据和哈希，不把它视为开源许可证。

**全部资料维持研究用途、排除发布。** 若后续采用 UPX、7-Zip 或其他可复用组件，应从对应上游获取已核实版本、完整许可证和来源；本项目 Apache-2.0 不覆盖归档第三方材料。Petite 源码 ZIP、NanoLib 代码片段、MSIUnPack.vbs 等许可未明材料不得直接并入发布代码。

## 复现与核验

在项目根目录运行。通过环境变量指定本机归档和可信外部 7-Zip 路径；机器绝对路径不写入本文件或脚本。

```powershell
$Archive = $env:OLDER_SHELLS_ARCHIVE
$SevenZip = $env:SEVENZIP_EXE
$env:PYTHONIOENCODING = 'utf-8'

if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw 'Archive missing' }
if (-not (Test-Path -LiteralPath $SevenZip -PathType Leaf)) { throw 'External 7-Zip missing' }
if (-not (Test-Path -LiteralPath '资料' -PathType Container)) { throw 'Extraction root missing' }

py -B scripts/inventory.py --archive $Archive --root '资料' --sevenzip $SevenZip --output '资料/archive-inventory.json'
if ($LASTEXITCODE -ne 0) { throw 'Inventory failed' }

py -B scripts/inventory.py --archive $Archive --root '资料' --sevenzip $SevenZip --output '资料/archive-inventory.json' --verify
if ($LASTEXITCODE -ne 0) { throw 'Inventory verification failed' }
```

首次解压流程是：先 `7z l -slt -sccUTF-8`，核查所有条目及加密/链接信息；用 `Test-Path` 确认项目父目录；再 `7z x -aos -o资料` 保留目录。`-aos` 避免覆盖已有文件；后续脚本会拒绝条目集合、文件大小或 CRC32 不一致的提取结果。

`--verify` 重新列出外层目录，检查路径安全、文件/目录集合、340 个文件的大小与 CRC32，重新计算归档及逐文件 SHA-256，重新解析 PE/文本及内层目录，最后比较整个 JSON 对象；不写文件。JSON 路径均相对于 `--root`，生成时间不参与结果，因此相同输入与工具版本可得到确定性结果。`--details` 可输出紧凑证据供人工复核。

已执行：完整清单复算比对；内存构造的 PE32/PE32+ 架构与名称/序号导入测试；非法 RVA、截断 MZ、路径穿越、绝对路径、ADS、保留设备名拒绝测试。

## 边界与未完成验证

1. 340 个文件、127 个 EXE、41 个插件或 64 个候选家族名称，均不等于已支持的壳版本数。
2. 19 个 PE 有结构/目录警告，涉及导入终止符、无效 RVA、版本节点、异常导出计数或节边界。清单不把解析不完整解释为没有相应能力。
3. 字符串采样限每文件 100 条身份/版本片段、80 条许可片段；API 名集合单独扫描，不受该采样上限影响。只扫描 ASCII 和 ASCII 子集的 UTF-16LE 字符串；不完整反汇编，不分析控制流或 CLR P/Invoke。
4. 未递归展开 ZIP、自解压程序或嵌入 payload，也未做内层源码审阅、病毒判定、Authenticode 验真或运行测试。已列 ZIP 的“无加密”结论不覆盖未分析的嵌入数据。
5. PE/归档时间戳和工具收录时间不是目标壳版本年代。工具版本、宣称目标版本、实际验收版本分别记录；本次实际验收版本为空。
6. 面向浏览器的可行路径仍需有许可的源码或独立算法实现、合法样本和逐版本产物验证；将原生调试 DLL 编译成 WASM 并不能自动获得 Windows 进程调试能力。
