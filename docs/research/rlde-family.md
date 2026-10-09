# RL!de 家族：源码级静态研究与 ASPack/MEW 候选闭环

日期：2026-10-07；任务 MT27；执行者 D。**MT29（2026-10-08，@A）补齐**：tElock L3/L4+loader 核心、RL!deFSG 2.0 内层提取与拆解、RL!deUPX 内层拆解、ASPack/MEW 引擎↔GUI 锚点交叉核对（§8a/§8b/§16/§17；证据 `资料/reverse/mt29-*`）。下文算法是原创语义/伪代码，不是闭源反编译 C 的复制。原 GUI、原 DLL、输入样本和重建 PE 全部只作为数据，均未运行。

## 1. 原件、真实身份与研究层级

先按实际目录核对文件名，再核 `资料/archive-inventory.json`；本轮 **340 个外层文件 SHA-256 全量复算一致**。逐 GUI/插件/CLI/独立算法任务见 [tool-replication-matrix.md](tool-replication-matrix.md)：MT29 后 **260 条**任务记录，未研究条目保持 OPEN。

| 原件，相对于资料/老旧壳脱壳工具 | 字节数 | SHA-256 |
|---|---:|---|
| `万用脱壳机 RL!deASPack 2.x.exe` | 135835 | `e33899af26f7692454a8595abaa952479a0114d89839ff849d1a406d4773f56b` |
| `万用脱壳机 RL!deMEW 1.x.exe` | 135872 | `ff612ce167a9352100dd0a8c598574a567cce07c59e5c96c320aee11905c0de2` |
| `万用脱壳机 RL!deNsPack 3.x.exe` | 135854 | `c887d8767cdda38ee4f6c72cfe58ea283829373db39986ec385a675172721813` |
| `万用脱壳机 RL!dePeX 0.99.exe` | 135873 | `366d2d9dfe890355a5c381d028c6beec8400109f26c66c7db78364e3a4f062c9` |
| `万用脱壳机 RL!dePackMan 1.x.exe` | 135926 | `867ca8d018810f44dd97e747448d70789f0fce5f083bde24c51e8443be976348` |
| `万用脱壳机 RL!dePacker_x86.exe` | 307051 | `6c9a31e2edc9698baf952d01b0b93dc531655a83f8f614775b5f1d5bf7e34a77` |
| `万用脱壳机 RL!dePacker.exe` | 242888 | `b015131f86b59476a20fc1136568f9dd566a17dc221c8651e8414535b07825aa` |
| `RL!dePacker.exe` | 346682 | `2c5dbc974909339609f7180575184f7cac49d3e6f9bcb2da08105bdaff7c5f61` |
| `tElock脱壳机.exe` | 578016 | `3c70bf02d83265f6a126f8cfa38a19096421268dbe54e9401f05e93d38e889b2` |
| `ORiEN.exe` | 231900 | `25b5085843115272c6aea2feedf52fabe0d81748ed162c8017995cb3c2c8aa1d` |
| `DeAutoIt.exe` | 288768 | `c1ce4759c0ac40071c1027dd369a5e0855c9bff7f0aeb3117805b7792e7aabb1` |
| `EUnpacker_RemoveNAG.exe` | 948700 | `79e4103accf21ceba0c27a371ea4c8b9c447ea0a3d6cc2d4c93609f499e07347` |
| `易语言伪装精灵还原.exe` | 1051912 | `6370656eefe07799613a5fef412f9452a028ff7af7c000b0ec245697e31196bb` |
| `PEArmorUnpack.exe` / `完美静态脱壳机.exe` | 各210390 | `4100ea3554940ce76adf8a3630a398bedb9bd940667aeb56882a087d83345ea8` |

上表以本轮 hash 校验产物为准，不能从工具版本/路径直接推出已支持壳版本。标题声称 2.x、1.x、3.x 的 RL!de 专壳 GUI，不等于浏览器引擎全族支持。

研究层级区分：原件字节 → 外层静态解码 → 内层函数链 → 格式算法 → 产品有界实现 → 固定 fixture/golden → Windows 运行验收。当前 ASPack/MEW 到 fixture/golden，输出 **analysis-pe、runtimeVerified:false**；未知 GUI 内层或驱动仍明确阻塞。

## 2. RL!de 外层其实是共享自解压启动器

ASPack、MEW、NsPack、PeX、PackMan、UPX 等外层：ImageBase `0x400000`，入口 `0x419acc`；末节后 overlay 起于 raw `0x1ec00`。此前围绕外层 Delphi WriteFile 运行库的三处反编译，不能当作已找到专壳算法。

复用并克隆旧 case 到 `mt27-rlde-aspack`；关键 VA/raw：

| 函数 | raw | 已追到的职责 |
|---|---:|---|
| `00419acc` | `18ecc` | 容器入口、成员/压缩分支/写出与校验调度 |
| `004189a4` | `17da4` | GetTempPathA；临时目录准备 |
| `00413eb8` | `132b8` | 压缩输入→解出缓冲，申请/扩充输出；与独立 zlib 还原对应 |
| `00417df0` | `171f0` | **逐字节加和**，不是 CRC32；容器末校验还叠加该种 sum |
| `00418c3c` | `1803c` | 成员收尾/文件相关路径整理 |
| `00418fc0` | `183c0` | 最终 ShellExecuteA("open", path, parameters, directory, show)；外层是启动器 |

本轮独立从原件重新找每记录小头后的 zlib 流，设输出上限为声明成员大小+1，要求 zlib EOF、完整解出字节与前代提取件逐字节相等；**25 个成员**通过。未执行 ShellExecute。

ASPack/MEW/NsPack 共有三库，PeX/PackMan 的 Debugger 是另一 build，UPX 又是第三 build：

| 成员 | 解出字节 | SHA-256 |
|---|---:|---|
| 共用 `Debugger.dll` | 6656 | `f05efa3321cb63919a9333adcf9ccff93bfbcf08492b6307b547a99e824cd476` |
| `Dumper.dll` | 2560 | `a23183af8089caacbe74acaf0f807a3d70513b2f48d99722e0735ec4f3826add` |
| `Importer.dll` | 4608 | `b9a195ddcf9ed7ad698b23fc37d9dadcca646f1eb3c46327389ec323560e79ce` |
| `RL!deASPack 2.x.exe` | 10240 | `90d44f0dc8b2a66bfe8d671dedd4877c1b9c68212ec619085620c85a7406f7ad` |
| `RL!deMEW 1.x.exe` | 10752 | `e08bc7cd8f22a189a14f93f960090dc3958e9da4f0da8caeadbff6f74c8ad859` |
| `RL!deNsPack 3.x.exe` | 10240 | `59fe021138775660c587de4fbd303274834ef16d340e6d2a39cb849304465940` |
| `RL!dePeX 0.99.exe` | 10240 | `de8e737fff4a1d058bf4e6da4d081933213ef8ed2866f6030c10d83ea72ea7bb` |
| `RL!dePackMan 1.x.exe` | 10752 | `a2e410b599d4f58a4785fadaf41544f797ceb7052f8fe84f80539e5b142cc984` |

ASPack zlib 起点：Debugger raw `0x1edbe`、Dumper `0x1f886`、Importer `0x1fbca`、主程序 `0x2027b`；消耗分别 2721/795/1665/4107。MEW 主程序 `0x20278`，消耗4147；NsPack主程序 `0x2027b`，消耗4126。其他记录精确头窗口、起点、原件与解出 hash 在 `mt27-research/container-verification.json`。

原创容器伪代码：

```text
verify outer hash and PE extents
locate bounded overlay and recognized record header
for each declared member:
    require safe member name and bounded compressed/uncompressed lengths
    if compressed: decode one framed zlib stream, require EOF and exact output size
    else: copy only declared input span
    retain member hash and consumed count
    verify container's actual additive checksum separately from zlib checksum
return inert members and provenance          # no launch/load of extracted code
```

此前 `container.json` 的 `crc_field/crc_calc` 命名会误导：该 field 未等于 CRC32，不应因 CRC32 不同认定提取失败，也不能伪称 CRC 校验已通过。

## 3. 共用调试、dump、导入组件

证据：`mt27-rlde-debugger`、`mt27-rlde-dumper`、`mt27-rlde-importer` 的 TSV、C辅助视图、独立 verification.json。

### Debugger.dll

| 导出入口 VA / raw | 语义 |
|---|---|
| `10001083 / 483` InitDebug | CreateProcessA 的 creation flags=3；调试目标进程 |
| `1000130a / 70a` SetBPX | ReadProcessMemory保存原字节，WriteProcessMemory写INT3；记录回调/一次性模式 |
| `10001223 / 623` RestoreBPX | 恢复保存字节 |
| `10001293 / 693` DeleteBPX | 删除断点记录与原字节恢复 |
| `10001459 / 859` GetContextData | GetThreadContext(ContextFlags=0x10007)；编号读寄存器 |
| `10001593 / 993` SetBPXContextData | SetThreadContext回写EIP/状态 |
| `100015da / 9da` DebugLoop | WaitForDebugEvent/ContinueDebugEvent；INT3、single-step、异常分派、回调与重新布点 |
| `100013c0 / 7c0` GetNextInstructionAddress | 读32字节，有限指令长度/相对分支处理；不是完整x86 VM |

寄存器编号从 CONTEXT 字段偏移实证：`1=EAX, 2=EBX, 3=ECX, 4=EDX, 5=EDI, 6=ESI, 7=EBP, 9=EIP, 10=ESP`。PUSHAD/POPAD 与手工参数压栈导致 C 视图漏参数；回调解释以指令为准。

```text
set_breakpoint(address, mode, callback):
    save original byte; write INT3; record callback and persistence
on breakpoint event:
    correct stopped EIP to trapped instruction
    restore original byte
    call driver's callback with current context
    if persistent: arrange one-step/reinsert transition
    continue debugger event with the selected status
```

这是原 GUI 的意图/静态控制流；未运行目标验证旧系统异常行为，未移植闭源调试库。

### Dumper.dll 与 Importer.dll

- Dumper `10001094/raw494`：先读0x1000头，按SizeOfImage分配并读整映像，再写磁盘；`1000102e/raw42e` 写 OEP=传入VA−ImageBase，节 rawOffset=RVA、rawSize=VirtualSize。
- Importer `100012c2/raw6c2`：ImporterInit(size, ImageBase)，固定容量及100项DLL数组；`10001335/raw735`：增加DLL名与FirstThunk；`100013ab/raw7ab`：按名/序号记录API，遇不连续IAT槽就拆一个同名DLL描述符；`100014b7/raw8b7`：写描述符、名字、hint-name、ILT和原IAT槽。
- 原工具用“name pointer > ImageBase”区分名字/序号，缺少可靠边界；不是可直接照搬的健壮格式解析器。固定 `0x7800` 空间、16位e_lfanew、100字节远程名字缓冲和1000步无文件extent扫描均须改为显式限额。

```text
collect_import(dll, name_or_ordinal, original_slot):
    validate text/ordinal and original-slot span
    split descriptor when slots for this DLL are not consecutive
    retain original FirstThunk for code compatibility
rebuild:
    allocate bounded descriptor/ILT/hint-name payload
    write RVA-based disk thunks, ordinal uses bit31
    initialize original IAT slots from ILT and append null terminators
    update directories 1 and 12; reparse and compare import semantics
```

## 4. RL!deASPack 2.x：三个扫描锚与四个回调

内层不是 Huffman 解码器；它捕获目标 stub 的导入解析/OEP时点。所有代码 VA→raw 关系为 `raw=VA−0x400000−0xc00`。

| 函数 / raw | 已核调用/字节 |
|---|---|
| `00401000 / 400` | DialogBoxParamA("TESTWIN", callback00401066) |
| `00401066 / 466` | WM_COMMAND 0x6b→0040102c；0x6c选择文件；0x6d关于；0x6e退出 |
| `0040102c / 42c` | DLL加载→目标检查→ImporterInit→InitDebug→布BP→DebugLoop |
| `004015ec / 9ec` | LoadLibrary/GetProcAddress明确解析三共用DLL导出 |
| `004019df / ddf` | 顺序扫描 `8b 88 50 ff`、`85 db`、`ff 7f 53 ff`、`c2 0c 00 68`；各循环最多1000次，**无可靠文件extent** |
| `00401179 / 579` | 三初始断点：导入名读取→004011fc、DLL阶段返回、API→00401271、OEP→004012fe |
| `004011fc / 5fc` | 从EAX所指远程名字读100字节，增加下一DLL回调0040125a |
| `0040125a / 65a` | GetContextData(5)=EDI，ImporterAddNewDll用缓存DLL名与IAT槽 |
| `00401271 / 671` | 取EDI槽、EBX名字/序号；ReadProcessMemory或序号支路，ImporterAddNewAPI |
| `004012fe / 6fe` | 读取OEP跳转处立即数→DumpProcess→StopDebug→估算imports→增加`.ap0x`节→ImporterExportIAT |
| `004013f3 / 7f3`、`0040145c / 85c` | 对齐尾部、追加节/SizeOfImage；C类型/指针折叠不可靠，以节字段写指令为准 |

```text
validate packed-PE shape and expected complete stub build
scan only bounded mapped entry-region for four ordered patterns
prepare DLL/API/OEP breakpoint addresses from validated displacements
on DLL-name event: read bounded remote string; arrange post-call slot event
on DLL/API event: collect names or ordinals plus original IAT slots
on OEP event: validate immediate target in executable mapped region
    capture image; stop debugger; append bounded import payload; rebuild PE
```

下阶段 A05 是这个动态 driver 的复刻。§12 的新静态引擎直接解析样本格式，未复制此 GUI 的调试流程，也未宣称 ASPack 全2.x。

## 5. RL!deMEW 1.x：跳入头部loader后的分阶段捕获

证据 `mt27-rlde-mew-engine`。`004019e1/rawde1` 要求入口E9，按 rel32 跟随，再按序扫 `50`、`97 56`、`50 55`、`c3`，安装四断点。

| VA/raw | 职责 |
|---|---|
| `00401066/466`、`0040102c/42c` | 与ASPack相同命令骨架，专用处理器与DLL表不同 |
| `004015ee/9ee` | 三DLL导出解析 |
| `00401179/579` | 布断点至00401224、00401234、00401293、0040132c |
| `00401224/624` | GetContextData(1)=EAX，缓存OEP VA |
| `00401234/634` | Get(5)=EDI槽、Get(6)=ESI DLL名，远程读名字→ImporterAddNewDll |
| `00401293/693` | EDI槽、EAX名字/序号；空名路径直接返回；API加入imports |
| `0040132c/72c` | 缓存OEP→DumpProcess→StopDebug→追加节与Exporter |
| `0040150d/90d`、`0040156a/96a` | VA/RVA/raw互换，16位e_lfanew假设必须替换 |

原创 driver 模型：`bounded E9 follow → validate complete loader generation → OEP cache → DLL/API slot collection → final RET event → dump/rebuild`。没有独立MEW动态事件样本，不给原GUI V 状态。

## 6. RL!deNsPack 3.x：解包返回序列与跳转目标

证据 `mt27-rlde-nspack-engine`。没有证据表明此 GUI 自己包含 NsPack LZMA codec；目标 stub 解包由目标进程执行。

- `00401988/rawd88`：若入口前0x25位置有E9先跟随；在最多1000步窗口找 `61 9d` 序列，考虑后接E9分支；读 rel32 计算OEP。随后找 `57 ff`、`51 50` 两导入阶段模式。
- `00401179/raw579`：初始BP→004012d3（OEP）、DLL阶段004011fc、API阶段0040125b。
- `004011fc/raw5fc`：EBX槽与EDI名字，远程读100字节→AddNewDll；`0040125b/raw65b`：槽/名字或序号→AddNewAPI。
- `004012d3/raw6d3`：由扫描已算出的OEP走 DumpProcess + ImporterExportIAT；`00401595/raw995` 明确三DLL依赖。

```text
follow only validated, bounded entry trampoline
find expected post-depack POPAD/POPF + JMP rel32 generation
derive OEP from the actual displacement, not a section-name guess
install DLL/API and final-branch events
collect original IAT slots; capture/rebuild with common host components
```

版本3.x只是工具标题。LZMA codec、NsPack 3.x各build/资源/TLS/导入变体仍待样本证明。

## 7. PeX 0.99 与 PackMan 1.x

### PeX

`mt27-rlde-pex-engine`：`00401a8c/rawe8c` 直接设 `EP+0x228`、`EP+0x2fa`、`EP+0x3c`；不是通用壳识别器。

- `00401179/raw579`：两初始事件到00401212/0040126f。
- `00401212/raw612`：由当前EAX派生 `+0xf2/+0x160/+0x204/+0x364` 位置；0040126f继续安排导入与转移阶段。
- `004012ab/raw6ab` / `00401309/raw709` / `00401320/raw720`：DLL名字读、返回slot、API名字/序号采集。
- `00401259/raw659`：下一阶段布点；`004013b9/raw7b9`：读取上下文OEP并累计事件，计数达到目标阶段后 dump/import 重建。
- `00401699/rawa99`：Debugger/Importer/Dumper依赖。该副本 Debugger 与ASPack build哈希不同。

```text
require the exact PeX generation and bounded EP-relative fields
stage1 event: derive stage2 addresses from live register plus vetted offsets
stage2: collect DLL/API events and count OEP-transfer events
on the vetted final count: capture image and rebuild original slots
```

固定偏移不应无锚推广到所有PeX 0.99修改版；独立golden/原工具运行未做。

### PackMan

`mt27-rlde-packman-engine`：`00401a2b/rawe2b` 按序扫描 `6a 04`、`50 ff`、`03 3b`、`51 50`、`61 e9`。`00401179/raw579` 五BP分派。

回调准确入口是 `00401222/raw622`、`0040125c/raw65c`、`004012a7/raw6a7`、`004012e9/raw6e9`、`00401376/raw776`。此前以附近字节强建的00401223/00401281等辅助视图不作为函数边界证据。最终 `00401376` 从保存OEP走DumpProcess、StopDebug、`.ap0x`与Exporter；`00401638/rawa38` 解析依赖。

```text
find all five ordered patterns within one known stub's mapped extent
derive stage/branch addresses and validate expected operands
install five event callbacks; capture DLL/API identities and original slots
at validated POPAD/JMP handoff: use saved original entry, dump and rebuild
```

PackMan不是被证明的静态字节流decoder；名字/壳版本宣称与这条已观察动态驱动分开记录。

## 8. tElock 与 ORiEN：先解外层，不能编内层算法

### tElock：两层算术恢复，第三层仍阻塞

原件入口 `00401000/raw400`：`PUSH 00436001; CALL 0040100b; RET`，helper也是RET，实际跳入 `00436001/raw10601`。末`.data/.adata`中的ASPack-like入口不是目标tElock脱壳代码。

真实读取/写入链在 `telock-wrapper.tsv`：`004360e5`取return literal `0x4360cf`，加 `0x8a6` → 首地址`0x436975`；`0x33d35a96+0xcc2ca76b` → `0x201` DWORD；每次地址减4。

```text
for address from 0x436975 down by 4, exactly 0x201 words:
    word = ((word + 0x1c7081e5) mod 2^32) XOR 0x7f9944ba XOR 0x690f1f6b
```

解出的第二层入口 `00436175/raw10775`：CALL返回literal `0x436184` 加 `0x7ef` → `0x436973`；EDI每轮减4，直到`0xfffff8d4`，共459 DWORD。变换：

```text
for address from 0x436973 down by 4, exactly 0x72c/4 words:
    word = ((word XOR 0x1609a670 XOR 0x7d722de9) - 0x5ed0ba6e) mod 2^32
```

下一入口 `0043624b/raw1084b` 是第三个CALL/算术/重叠junk层；尚未恢复其后的loader及tElock GUI。两层解码 hash分别：`73eb373a9a860e7489ef3f5f3bdf883020c1a998858671750432ed7224b26bd8`、`e3df4acb48926083b868d0f0ccff725f8f3f7143e18f705b18258bdf32749901`。**972次DWORD变换是局部数据恢复，不是tElock引擎完成。**

### 8a. MT29：L3/L4 全解 + loader 核心 + aPLib codec（mt29-telock）

受限文法静态执行器 `mt29-telock/chase.py`（Capstone 解码 + 自实现 ZF/SF/OF/PF/CF；未知指令/未定义标志/越界访问即停；不运行目标代码）从 0x43624b 续跑：

- **L3（0x43624b）**：392 dword，0x436973 每轮 −4 至 0x436357；`w' = w + 0xfd03cb06`（0x4362be/c7/cf 三常量）。出口 junk（`jp 0x436351`→`xor [ecx+0x655ccf2e],ch`，ecx=0 必越界）不执行真实语义；层间衔接用**窗口下沿定律**：next_entry=本层最低写入地址（L1→L2、L2→L3 字节级双验；L3→L4 以可执行性+结构连续验证，强推断）。
- **L4（0x436357）**：331 dword（`cmp edx,0xfffffad4` 出口），[edi+edx]、edi=0x436973；`w' = ((w+0x43cbbce4) ^ 0x6da5154d) + 0x255b802`（0x43639f/a8/ae）。
- **L4 尾部即 tElock loader 核心**：0x436451 四 pop 恢复 L1 pushal 藏的原寄存器（静态不可知）→ 0x43646d `push fs:[0]/mov fs:[eax],esp` SEH 安装 → 0x436761 **kernel32 MZ 回走**（`and eax,0xffff0000;±0x10000;cmp 'MZ'`，种子 [esp+0x24] 运行时返回地址）+ 导出表解析运行时填 API 槽（静态读槽全 0，实证）→ 0x4364d8 `rep movsb 0xc` 补丁 VA 0x401000 → VirtualAlloc(0,0x52000,0,0x1000) 形调用 → **0x436624 aPLib 族位流解码器**（`mov dl,0x80`/`add dl,dl`/`adc dl,dl` 位桶、literal/短匹配/gamma，与 PEArmor 00403d10、ORiEN 00427147 同族）。
- 状态：L2 镜像 + L3 + L4 全写后整文件 SHA `ff7e93f1c572430a9951a61de22ef6a44c71f407d19c7c8aefed861b91409490`；19162 步执行流 TSV 与独立重放 `verify-telock.py` 均过。
- **静态阻塞**：pushal 运行时寄存器、kernel32 回走种子、运行时 API 槽、SEH 驱动流——需 x86 仿真+影子 kernel32（emulated-pe32 路线，P1）。tElock 目标样本/golden 仍无 → 不注册引擎；4 层密钥/窗口可作检测签名候选。

### ORiEN：66次常量变换后出现aPLib loader

入口 `0042a615/rawd815` 建SEH后跳 `004270cd/rawa2cd`，设置基址`0x427000`、数据地址`0x4270ea`，通过PUSH/RET进入 `004274ee/rawa6ee`。只沿已验证的直接JMP跳过重叠junk，对 `[ESI]` 的立即数XOR/ADD/SUB/NOT及ESI+4重建有限数据变换。

66次变换恢复264字节；在 `0042807a` 的 `INC [ESP]` 停止数据模型，未擅自执行或忽略该栈行为。`orien-plain-head.tsv`显示：

- `004270ec/rawa2ec`：分配解出空间，保存指针，按基址+metadata源偏移定位压缩数据；以后还会跳入解出的输入代码。
- `00427147/rawa347`：固定aPLib样式解码；literal、短匹配/结束、gamma长度、重复距离、重叠REP MOVSB。
- `004271ca/rawa3ca`：ADD DL,DL / reload / ADC DL,DL；`004271d4/rawa3d4`：gamma整数；`004271e6/rawa3e6`：返回写出长度。

该层可用独立许可aPLib decoder研究；压缩内层驱动/ORiEN版本/导入修复语义仍未知。不得把“ORiEN外层用了aPLib”写成“ORiEN目标壳已复刻”。

所有word变换与前后值保存 `mt27-research/polymorphic-decoding.json`；原件没有被改写。**MT29 注**：`INC [ESP]` 是对栈上返回地址的修补（push/ret 链手法）；mt29-telock/chase.py 的栈内存模型已可表达此类指令，但 ORiEN 停点处的完整寄存器/栈状态需从 0x42751f–0x42807a junk 流逐段重建，本轮未做——阻塞点更新为"状态重建工作量大"而非"指令不可表达"。

## 8b. MT29：RL!deFSG 2.0 与 RL!deUPX 内层驱动

证据：`资料/reverse/mt29-rlde-fsg/`（提取+README+container.json）、`mt29-rlde-fsg-engine/`、`mt29-rlde-upx-engine/`（两案 verify.py 全过：712+869 指令、92+103 直接 CALL、44 反编译 0 失败）。

### RL!deFSG 2.0（G51 wrapper 内层，新实体 N13）

wrapper 成员格式修正一处：name 后**无 NUL**，"00"是后随 rawlen2 dword 低位（MT27 头窗误读）。三共用 DLL 哈希与 ASPack/MEW/NsPack 完全一致；内层主程序 10240 字节 SHA `f4307f224ea3cfa4420dc17b9915e0a403ddb202bd69d57025a7c704dfb60a5d`。

- `00401902/raw d02`：限 200 字节双探针——word `ad 50`（LODSD;PUSH EAX，导入名循环）→BP1=命中+1；dword `ff 63 0c 50`（JMP [EBX+0xC];PUSH EAX，2.0 尾跳）→BP3=命中、BP2=命中+3。
- `00401179`：SetBPX×3（前二持久、OEP 一次性 004012d3）。
- `004011fc`/`0040125b`：LoadLibraryA/GetProcAddress 名 RPM 读取 → Importer 登记。
- `004012d3`：GetContextData(2)=EBX，**OEP = dword [EBX+0xC]**（与尾跳操作数同槽）→ DumpProcess → 00401744 修正 → ImporterExportIAT → Success。

产物等级（原 GUI）：dump+导入追加节（`.ap0x` 式），同族；对我们 fsg.js（1.31/1.33）：**P1**——FSG 2.0 的 OEP 槽位与导入循环锚是未来静态化 2.0 的定位证据；无 2.0 样本/golden，不宣称支持。

### RL!deUPX 1.x-2.x（N06，I→F）

身份补证：对话框标题 `RL!deUPX 1.x - 2.x - coded by ap`（RL!de=ap0x 署名）。

- `00401a85/raw e85` 四探针（≤1000 步）：dword `50 83 c7 08`（PUSH EAX;ADD EDI,8 导入循环）→BP1；扫到 `57 48` 止，途经 `50 47` 记可选按名循环 BP；byte `e9`（尾跳）→BP4；**OEP = e9 处 + rel32 + 5 静态计算**。
- `00401179`：BP1→00401218（DLL 名）、BP2→00401304（API 名/序号）、可选→00401277（序号支路 %08X）、BP4 一次性。
- 对我们 upx.js/upx-official：无算法增量（静态直解已覆盖）；价值=家族驱动模式完整（四锚+静态 OEP）。

```text
# FSG 2.0 / UPX 共同骨架（RL!de 专壳驱动第 11/12 个成员实证）
scan bounded entry window for shell-specific import-loop + tail-jump patterns
compute OEP: FSG=[EBX+0xC] at jmp site; UPX=e9 displacement statically
break on name-push sites to collect DLL/API names into Importer
one-shot at tail jump: Dumper.dll capture + Importer.dll rebuild
```

## 9. RL!dePacker(x86)、EUnpacker、伪装还原的真实阻塞与进展

### 三份RL!dePacker不能混成一个已恢复通用引擎

- G56 wrapper里找到单成员 `RL!dePacker.exe`，zlib raw `0x1edc1`、消耗180629、解出219136字节，SHA `8782a3b882059ab3cf1728f35d73cf21c53ffc229aaef1f28df2342f8183ea25`。官方UPX4.2.4静态解码返回 CantUnpackException；Ghidra头结构也有 `Insufficent memory at address 004001f8`。该case反编译导出超时未完成，不能按Analysis succeeded升级为完成。
- G55 overlay116936字节未匹配上述明文成员记录；不能套G56的容器布局。原件只有外层画像。
- 根目录G23是另一hash/结构。`mt27-rlde-packer-root` 文件映射的 `00401000/raw200` 调解码/工作区；`004b3de7/raw521e7` 有5字节range init、0x400初始概率、总量0x800、移动5、0x1000000归一化及literal/match/reps：是LZMA1-like边界。模型0x30736 words与完整8bit literal context有关，当前产品codec的lc+lp≤4子集不接受它。
- `004b4e29/raw53229`、`004b4ef0/raw532f0` 是后处理候选；若helper `raw=-`，Ghidra根据未填充空间生成的巨量C不可作为真实函数内容。此case102条未映射指令单列保留。

阻塞：必须恢复上层初始化/metadata/分支过滤/受保护helpers，再定位通用驱动表与真实壳名单。没有这些就只能交外层模型+拒绝，不创造虚构“支持全部壳”算法。

### EUnpacker_RemoveNAG：官方拒绝后，继续静态恢复成功

原件ImageBase `0x30000000`、入口 `3012dfe0/rawb53e0`，CODE空目的节、DATA源节。官方UPX报告 modified/hacked/protected，仅否定其这次解码，不代表没有静态算法。

入口字节实证给出：源 `0x30079000`，跳过2字节；compressed=`0xb4fd2`；output=`0x12b58d`；props字段`0x20003`对应lc3/lp0/pb2。按已独立验证的LZMA1 decoder，从raw`0x402`有界解出 **1226125字节**，消耗 **741330字节**，无EOS但终态code=0。raw解出SHA `ae89484cb762e971a6d065b2ef42971359015a277a6d12d779e3ee6e588767ff`。

`3012eac3/rawb5ec3` filter count=`0x1235`，`3012ead1/rawb5ed1` marker=5；SHR AX/ROL16/XCHG AH,AL等价于读取后三字节大端target，再减operand位置。按精确count恢复 **4661个CALL/JMP**；SHA `972cee9826489ac3dd8f1168f62f7c7aed75a664ce8570c553e32910265d439c`。`3012eb82/rawb5f82` 最终E9目标是`3001464b`。

通过合成分析头（**非原始PE头、非运行验收产物**）定位内层：`CEUnpackerApp/CEUnpackerDlg/CUnpacker`，fOx版权串，EUnpacker 1.0/V1.2并存，Themida/Armadillo是界面列表声明。关键函数地址在该映像中：

| VA / 合成映像raw | 证据与局限 |
|---|---|
| `30026f60 / 26360` | creation flags=4的进程创建调用；Inject process failed路径；以300291e0作远程启动相关回调；需恢复准确API绑定 |
| `300291e0 / 285e0` | RemoteMain初始化，PID/回调句柄/引擎上下文，失败终止路径 |
| `30027fd0 / 273d0` | 0xbc6/0xbc7/0x7c8/0xbcd消息，完成、资源修复、overlay修复回传分支 |
| `30028cb0 / 280b0` | ECode链长度、资源枚举/回传、overlay回传与完成消息 |
| `30028450 / 27850` | 目标类型列表与GUI初始化、日志回调 |

第一次未反过滤的C辅助视图有畸形CALL目标/Bad instruction，不能复制或当高级算法证明。私有目录保留raw与filtered两份数据及其hash；后续卡要在filtered数据上恢复准确头/导入和所有核心调用。当前已确认**挂起进程/注入/远程回调/回传重建的架构线索**，未确认RemoveNAG修改范围、被列举保护壳全版本或高级代码恢复能力。复刻 A18 为 OPEN，专壳细节仍需函数/样本闭环。

### 易语言伪装精灵还原

原件入口 `0050593e/rawb3e`：PUSHAD→`MOV EAX,00400024; CALL EAX`，代码转入头部；`00505960`以后能见参数/位流工作区。`.zzage`源节熵约8，目的节raw=0；两个可见导入只用于外层。Ghidra此输入没有可靠内部函数边界，不能报“已反编译0函数=成功破解”。

`disguise-entry.tsv`379条线性指令校字节通过，不等于发现379条真实可达代码。阻塞在头部转移/流props/metadata定位，原伪装还原GUI与目标版本未恢复。当前保持拒绝；没有用名称编造IAT/OEP恢复流程。

## 10. DeAutoIt：UPX外层恢复后可重建EA06算法边界

只运行另行钉住的官方UPX4.2.4作为**文件解码器**，未启动DeAutoIt。解出656896字节，SHA `a5f32a2d17861862bfd2668e839f4df0cd67dd726562c28dd0c49c4f44d59bb3`；原件hash前后一致。证据 `mt27-deautoit`、`mt27-research/upx-static-decoding.json`。

函数/字节定位：

| VA/raw | 边界 |
|---|---|
| `00402480/1880`、`00402330/1730` | DialogBoxParamW/拖放/GUI命令；进入处理路径 |
| `004021c0/15c0` | 打开输入、找EA06、生成`.au3`输出路径、调用主提取 |
| `00401340/740` | 定位容器标记，校验EA06头并跳元数据 |
| `004013d0/7d0` | FILE记录、UTF16 metadata、`>>>AUTOIT SCRIPT<<<`筛选 |
| `00401000/400` | 17word种子表，LCG `seed=seed*0xac564b05+1`，tap初始化与warmup |
| `00401110/510` | 两tap ROL13/ROL9加和、tap递减回绕，浮点构造映射到字节 |
| `00401200/600` | 用给定seed重置PRNG，对payload逐字节XOR |
| `00402040/1440` | 长度XOR与分配、解密、校验、可选LZ、token→文本 |
| `00401fe0/13e0` | Adler32：模0xfff1，(sum2<<16)|sum1 |
| `00401da0/11a0` | EA06压缩流；MSB16位桶，literal/15bit距离，分档长度与重叠复制 |
| `00401620/a20` | token formatter：整数/十六进制/浮点、字符串、运算符、换行 |

```text
find framed EA06 stream within bounded input
for each FILE record:
    decrypt four-byte magic with PRNG(seed=0x18ee); require FILE
    nameChars = storedNameLength XOR 0xadbc
    decrypt UTF16 name with seed nameChars+0xb33f
    otherChars = storedLength XOR 0xf820
    decrypt other UTF16 metadata with seed otherChars+0xf479
    if name != >>>AUTOIT SCRIPT<<<: bounded-skip payload and continue
    packedLength = storedPackedLength XOR 0x87bc
    unpackedLength = storedUnpackedLength XOR 0x87bc
    expectedAdler = storedChecksum XOR 0xa685
    decrypt payload with seed 0x2477; require Adler32 match
    if compressed: decode EA06 bitstream to exact bounded size
    decode typed tokens to AU3 text, rejecting unknown/truncated tokens
```

LZ原创伪代码：

```text
require EA06 + big-endian output-length header
while output not complete:
    if next_bit == 1: emit next_8_bits literal
    else:
        distance = next_15_bits
        x = next_2_bits; base = 0
        if x == 3:
            x = next_3_bits; base = 3
            if x == 7:
                x = next_5_bits; base = 10
                if x == 31:
                    x = next_8_bits; base = 41
                    if x == 255:
                        base = 296
                        repeatedly add 255 while next_8_bits == 255
        length = x + base + 3
        require distance in produced history, length within exact output
        overlap-copy distance,length
```

token字符串在0x30–0x3f段，UTF16字符与字符串长度做XOR；0x7f为行结束相关分支。formatter原文的部分类型/宽度推断须从指令复核，不把C的`undefined8`直接当文件规格。本轮未取得合法EA06源码/编译样本对，PRNG浮点/FPU语义、Unicode、token完整表及压缩边界独立oracle仍待补 → 产品未实现，但不再只有“UPX藏住”的画像。

## 11. PEArmorUnpack / 完美静态脱壳机：同一程序三算法边界

复用`pearmor`项目快照到`mt27-pearmor`，逐字节复核4084条指令/169条CALL。详细控制流补证可查旧 [gui-unpackers-reverse.md](gui-unpackers-reverse.md) §4。

- `004053e0/raw53e0` MFC消息项 `[0x111,0,0x3eb,0x3eb,0x0c,00401540]`；选择回调 `004027a0`，处理回调 `00401540`→`004022b0`→`004023f0` 文件/映像准备。
- `00401190/004011d0` 是扫描器；0040177a与0040180b直接CALL `00403d10`，第一层和0x0c记录后续块都走**工具自己的固定decoder**。
- `00403d10/raw3d10`、bit helper `00403d93`、gamma `00403d9d`：literal、短匹配结束、4bit单字节回引/零、重复距离、距离阈值0x7d00/0x500/0x7f、逐字节重叠copy。
- 主处理器还有名字/序号导入、FF15/FF25修复、工作区增加与OEP/PE节头写回；`0040204b`输出CreateFile，00402078/004020c5/0040210a写头/节/修正头。

```text
map input as bounded PE image; locate exact known PEArmor metadata
decode first-stage blob with independently implemented bounded aPLib-like codec
for each validated 12-byte block record: decode and copy into unique image span
recover DLL/API/ordinal records and restore indirect call/jump slots
validate OEP and rebuild section/header/directories; reparse output
```

固定decoder是静态复刻候选的正证据；原工具无CreateProcess的阴性线索不是证明。原件/附带材料许可未知、没有PEArmor golden，因此未把其闭源decoder或C输出加入产品。ASPack/MEW的新引擎是另外两条许可明确的格式实现。

## 12. ASPack实际样本：修正“没有明文compB”并完成闭环

旧 `aspack-implementation.md` 的“现代文件没有明文compB”对本fixture不成立。实盘确有114字节表，只是尾部距离参数与旧参考常量不完全相同，且基址/偏移不同。不是靠放宽签名猜OEP。

固定输入/独立oracle，unipacker commit `160baa9447c91d53b75e5e108b196d389fa0b06e`：

- packed `test-results/fixtures/aspack/aspack-lbop20.bin`，43520字节，SHA `a7a2f792185842ea20f100f8a0059842bc299a2e5c0318751840fdd38224800a`。
- golden `golden-lbop20.bin`，176128字节，SHA `4de460a6f7658f9c6233c9be3f9be70cf893d2010276c1b5c7521cfc42e15ce7`。这是独立发布的内存dump，IAT/描述符已有运行态/重建变动，不是原磁盘文件。

重要函数/字段直接回查原件，VA−0x400000−RVA节映射得到raw：

| VA / raw | 真实语义 |
|---|---|
| `00417001 / 9801` | 入口全锚；CALL/POP后EBP=`AEP+0x12`，不是旧布局AEP−1 |
| `004170ad / 98ad` | LEA ESI,[EBP+0x5dd] → block table RVA0x175f0 |
| `00417108 / 9908` | CALL固定decoder004176e0 |
| `00417131…0041715b / 9931…995b` | 第一块E8/E9 marker7 → 三字节target−opcode offset |
| `0041727c / 9a7c` | MOV ESI,0x122d4，原import descriptor位置 |
| `00417418 / 9c18` | MOV EAX,0x1252，OEP立即数 |
| `00417438 / 9c38` | push0/ret标记，AEP+0x437 |
| `0041774a / 9f4a` | 明文114字节length/distance表；AEP+0x749 |
| `00417782 / 9f82` | 58个distance bit参数；AEP+0x781 |
| `004177bc / 9fbc` | MSB位读取；先维持32bit lookahead |
| `0041784c / a04c` | canonical Huffman树，最大15bit、完整Kraft sum=0x1000000 |
| `004179c8 / a1c8` | 逐字典取符号 |
| `00417a9c / a29c` | 721/28/8/19字典和distance bases；PC算术定位表 |
| `00417b7b / a37b` | 757个delta/repeat字典长度，重建三主字典 |
| `00417d18 / a518` | literal/match/history-LZ/字典刷新 |

Ghidra对offcut/PC trick给出的部分C失真，误把0x175ff数据当函数；这些视图**不作算法依据**。本轮另用已安装Capstone导出989条线性原字节窗口，按上述真实入口/操作读语义。

```text
inspect exact entry, ordered loader anchors, full 114-byte table and helper arithmetic
validate bounded 12-byte block table and non-overlapping destinations
for each block:
    build 19-symbol code-length tree
    decode 757 delta/repeat lengths; build 721/28/8 trees
    emit literals or bounded history-distance matches
    allow dictionary refresh with explicit update limit
    require exactly declared output length; never pad missing compressed bytes
    for first block: restore tagged E8/E9 operands
restore disk IAT from original ILT (or validated disk thunk fallback)
rebuild original section RVAs, recorded flags, OEP, header/layout and imports
reparse and compare import identities/counts; grade analysis-pe
```

真实块/消耗/对照：

| 目的RVA | 解出 | 消耗 | 独立golden逐字节 |
|---:|---:|---:|---|
| 0x1000 | 45568 | 24891 | 100%（整段代码） |
| 0xd000 | 23040 | 8656 | 99.375%；144个差异在IAT/重新定位的import描述符字段 |
| 0x13000 | 2560 | 386 | 100% |
| 0x15060 | 416 | 25 | 100%；资源树前0x60保持文件原字节 |
| 0x16000 | 3584 | 2953 | 100% |

共75168解出字节，直接同值75024（99.81%）；**仅排除明确IAT槽264字节+descriptor array60字节，74844稳定字节100%**。另按名字/序号/FirstThunk完整比较2 DLL、64函数，不靠忽略导入差异冒充恢复。

输出SHA `b08f368b4cbc71fbcfc9e82312908d9c036005ed4e6d62821c37b2a27f6b4e3b`；严格parser无warnings。实现 `src/core/unpackers/aspack.js`；只接受完整ep437 generation，旧六布局、2.11加密头、DLL/x64/.NET/TLS/未知stub明确拒绝。没有逐版本/运行验收 → 不升级rebuilt-pe或全族声明。

## 13. MEW实际样本：专用重叠头 + aPLib + LZMA1 + imports

固定输入 `test-results/fixtures/mew/lbop20-mew.bin`，34185字节，SHA `42e83208184d5ef0ebfced4347540b4629fe2d6c901295dd0dc9eb18a5b96af5`。严格 `parsePE` 继续拒绝e_lfanew=`0x0c`；`parseMewPE` **只有全loader、头/两节/指针布局验证通过才返回**。

- AEP `00420370/raw8570` 的E9准确跳到`00400154/raw154`；loader完整字节模式区分MEW11 SE，MEW10/non-SE不混用。
- 元数据 `0041801c/raw21c`：helper pointer、OEP VA `0x401252`、第一目的VA `0x417b9e`。
- scattered bit helper：`0040012c/raw12c` ADD DL,DL/JNZ/LOAD/JMP；头部`00400108/raw108` INC ESI/ADC DL,DL/RET。节名中嵌代码不能被当成原节名称。
- gamma `00418000/raw200`。分块aPLib解出1118字节imports blob和1335字节LZMA loader，消耗602/1076；后者位于源节file-backed末端之后的合法zero-fill。
- `004001cf/raw1cf` 的CALL→`004205ec`；只接受已恢复loader的非special prologue `55 8b ec 83 ec 40 53 ad 89 45 d8 89`。
- container位于工作映像offset`0x176be`；每条 `{outputSize, destinationVA, compressedSize, skippedByte, rawLzma}`，非special list以outputSize=0结束。第一块size75890，csize31856，流原件raw`0x8cf`。

```text
validate exact special PE header + full MEW11-SE-154 loader and helper pointers
map only two bounded sections into an inert image
decode each aPLib loader stream; consume next-destination word until zero
    forbid overlap with unread source/container or earlier loader
locate decoded fixed LZMA loader; reject special/unknown shape
for each bounded container record:
    decode stock LZMA1 props0x5e, lc4/lp0/pb2, declared dictionary budget
    require exact source consumption, exact output, normalized final code=0
locate imports blob through the explicit container pointer
    per DLL: original IAT VA, DLL name
    functions: 0x80 + name, big-endian ordinal-1, or ffffffff next-DLL
    final 0x80 is an empty-name sentinel in loader zero-fill
build new IJID/ILT/hint-name, initialize original IAT slots, restore OEP
write conventional PE header and analysis sections; verify import semantics
```

两DLL/64函数与独立ASPack同程序dump的名字/顺序/FirstThunk一致。代码RVA0x1000、45568字节与该独立golden **100%**。全75890字节与该不同壳dump直接同值74410，**98.05%**；不把导入metadata等差异抹掉来报整PE 100%。另用Python/liblzma对原raw stream独立解码，与新引擎解出数据（只扣除产品写回的IAT槽）**75626稳定字节100%**，证明LZMA字节流闭环。

输出SHA `30cda5d33689a4cda6a12a33550e05adfcdaeb643aae34893061d6fc40915e19`；严格输出parser无warnings。原始section layout/permissions推定、资源/重定位未重建，metadata显式警告；保持analysis-pe/false。

LZMA1 实现 `src/core/compression/lzma.js` 是原创JS转写格式模型，参考Igor Pavlov **LzmaDec.c，2023-04-07，Public domain**，固定 [7-Zip 24.09 source](https://raw.githubusercontent.com/ip7z/7zip/24.09/C/LzmaDec.c)。保留来源/credits于文件头；无未知许可反编译C进入产品。

范围：raw LZMA1、lc+lp≤4、有界props/dictionary/output、EOS或精确长度code=0终态。不是XZ/LZMA2/.lzma容器解码器；MEW10、non-SE、special/BCJ、多build版、DLL/x64/.NET仍拒绝。

## 13a. MT29：ASPack/MEW 静态引擎与 RL!de GUI 动态锚点交叉核对

问题：GUI 驱动（§4/§5）与我们静态引擎是否覆盖同一 stub 代际？OEP/导入锚证据差异？

**ASPack（fixture=lbop20 ep437 代）**，GUI 四探针在样本中的静态落点（`8b 88 50 ff`、`85 db`、`ff 7f 53 ff`、`c2 0c 00 68` 全文件检索）：

| GUI 模式 | 命中 | 位置 |
|---|---:|---|
| `8b 88 50 ff` | 0 | **缺席**——GUI 首探针属另一 ASPack build |
| `85 db` | 2 | 0x9ade/0xa71b（stub 区） |
| `ff 7f 53 ff` | 1 | 0x9af7（stub 导入循环） |
| `c2 0c 00 68` | 1 | **0x9c35 = ep+0x434**；aspack.js push0/ret 标记 ep+0x437（0x9c38）**同址相邻** |

结论：① GUI 与 aspack.js 对 OEP 交接点锚定**同一指令现场**（`ret 0xc` 后的 `push/ret` 尾跳），一个用模式扫描、一个用固定偏移+立即数（ep+0x418 的 `mov eax,0x1252`）；② 但 GUI 的导入首探针 `8b 88 50 ff` 在 ep437 代缺席 → RL!deASPack 2.x 与 ep437 不完全同代，GUI 不能整体照搬到该样本；③ 导入重建语义一致收敛：GUI 运行时收集名字后保留原 IAT 槽重建（Importer.dll），aspack.js 磁盘 ILT→IAT 原位恢复——两条独立路线支持"原槽保留"设计。

**MEW（fixture=lbop20 MEW11 SE）**：GUI 四锚 `50`/`97 56`/`50 55`/`c3` 在 mew.js 已字节级验证的 0x154 loader 窗口内**全部命中**（0x1d7/0x1f3/0x1fd 等）→ GUI 动态断点集与 mew.js 的整段 loader 校验覆盖**同一 loader 代际**。OEP 差异：GUI 运行时从 EAX 缓存捕获；mew.js 读静态 header+4 字段（0x401252）——同一值两个来源，静态读法成立。

差异清单（对我们引擎的缺口反馈）：无——两引擎锚点证据反而被 GUI 佐证；唯一提醒是 ASPack 家族 build 离散度大（GUI 首探针都非万能），未来扩代际须逐 build 锚定，与 A25 立场一致。

## 14. 方法、复现、数量与失败保留

- 实际工具：**Ghidra12.1.2 headless + Temurin21.0.12+8**；Capstone5.0.7；CPython3.11.4；Node26.4.0。Ghidra/IDA入口先查规范资产册第一节，实际使用的是现存Ghidra，不重新安装分析器；本轮IDA未使用。
- 旧项目先克隆到 `mt27-*` 再用 `--reuse/-noanalysis` 挑关键函数；新解出的内层是新数据，不能拿旧hash项目冒充已分析。没有重跑已有GUI几十万指令基线。
- `verify.py` 独立从原PE节表回算VA→raw、逐字节和E8 CALL位移；Capstone线性窗口也逐指令与原件/明确标记的derived bytes比对。**相等只证明字节/映射，不证明所有控制流或C类型正确**。
- 旧原件/旧case不改。私有 `mt27-research/audit.py`、`disassemble.py`、`unwrap-upx.py`、`unwrap-polymorphic.py`、`eunpacker-lzma.mjs`、`engine-check.mjs`、`verify-cases.py`、`verify-docs.py` 保存静态复现路径。
- 可选 `MT27Functions.java/run-select.py` 在该私有脚本目录的OSGi加载失败；不把退出码0当脚本成功。ASPack算法转以独立字节窗口核语义；失败日志保留。
- MEW fixture Ghidra头重叠告警与反编译导出超时保留；没有用未完成case充数。MEW算法证据来自完整header/loader原字节+独立codec参考+fixture/liblzma oracle。
- RL!dePacker_x86内层case的头告警/导出未完成保留；根目录Packer的raw=-函数/102条未映射指令不纳入文件字节通过量。

MT29 补充（@A 2026-10-08）：

- 新 case：`mt29-rlde-fsg-engine`（全新分析+两轮 reuse，712 指令/21 反编译 0 失败）、`mt29-rlde-upx-engine`（全新+两轮 reuse，869 指令/23 反编译 0 失败）——verify.py 均 passed、0 未映射。
- `mt29-telock/chase.py` 受限文法执行器 + `verify-telock.py` 重放；L3 手工/追 chasing 双路径哈希一致（ef1423e0…/ff7e93f1…）。
- `mt29-rlde-fsg/extract-fsg.py` 提取 4 成员；共享 DLL 三哈希与既有交叉一致。
- 原工具/成员仍未运行；mt27-* 目录只读未动。

核心命令（机器入口使用规范册实值替换占位符）：

```powershell
py -3.11 -B scripts/reverse/analyze.py --toolroot "<GHIDRA>" --java-home "<JAVA_HOME>" --input "资料/reverse/rlde-family/rlde-aspack--RL!deASPack 2.x.exe" --output "资料/reverse/mt27-rlde-aspack-engine" --reuse --stage-ascii --function 004011fc --function 0040125a --function 00401271 --function 004012fe
py -3.11 -B 资料/reverse/mt27-research/verify-cases.py
py -3.11 -B 资料/reverse/mt27-research/verify-docs.py
node 资料/reverse/mt27-research/engine-check.mjs
node --test tests/aspack.test.js tests/mew.test.js tests/lzma.test.js
```

当前受限产品测试 **25 PASS / 0 FAIL / 0 SKIP**：ASPack9、MEW10、LZMA6。首次ASPack oracle比较在RVA0x122d4失败，确认是独立dump重定位descriptor而非decoder错误；保留完整导入语义比较并仅显式扣除IAT/descriptor范围，复跑通过。原项目这两个指定测试文件实盘不存在，新建；既有全局拒绝用例未删除、公共parser未改。

最终字节/函数数量以 `mt27-research/verification-totals.json` 为准；选取反编译数是辅助视图数量，不能写成“全部函数准确还原”。矩阵独立核211个行内hash前缀对应完整真身，259个ID唯一且计数一致。

## 15. 交付、接入与遗留

产品独占：`src/core/unpackers/aspack.js`、`mew.js`、`src/core/compression/lzma.js`；测试独占：`tests/aspack.test.js`、`mew.test.js`、`lzma.test.js`；两份研究文档与私有`mt27-*`。

M待并：

```js
import { ASPACK_ENGINE, supportsAspack, unpackAspack } from './unpackers/aspack.js';
import { MEW_ENGINE, supportsMew, unpackMew, parseMewPE } from './unpackers/mew.js';
```

1. 引擎注册/候选枚举、catalog及Web/HTTP/MCP允许值；两engine id为`aspack-pe32-huffman`、`mew-pe32-lzma1`，限定variant见代码。
2. strict parsePE失败后增加**MEW专用fallback**；只有完整inspect成功才返回；不放宽通用PE头。
3. 更新旧implementation/README/拒绝断言中的过时“未实现/无compB”状态，只改真正已通过fixture的入口；未知变体仍拒绝。
4. 新warning键/credits/NOTICE、共享入口独验；不把研究目录或未知许可材料打包发行。

遗留：原RL!de动态driver/完整工具功能未复刻；NsPack/PeX/PackMan无golden；tElock loader核心（SEH+kernel32回走+运行时API槽，mt29-telock已定位到0x4364c0/0x436761/0x436624）与ORiEN内层（0x42807a INC [ESP] 前状态重建）未恢复——两者均需仿真路线；RL!dePacker通用驱动表、伪装还原内层未恢复；EUnpacker专壳修复/RemoveNAG协议未穷尽；DeAutoIt缺合法EA06独立样本；PEArmor/Petite缺许可与golden；ASPack旧布局、MEW10/non-SE/special多build、TLS/x64/DLL等未实现；RL!deFSG 2.0/RL!deUPX内层已拆（mt29）但无各自目标壳样本验收。两个新引擎没有Windows运行验收，不能升级runtimeVerified或宣传整个保护壳族的自动重建上限。
