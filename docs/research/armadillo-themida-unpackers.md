# 穿山甲（Armadillo）与 Themida 专用脱壳机静态拆解

日期：2026-10-07。交付：研究证据与移植草案；不改动 src/，引擎接入由主线独立完成。
方法论沿用 [gui-unpackers-reverse.md](gui-unpackers-reverse.md)（Ghidra 12.1.2 headless + `scripts/reverse/analyze.py` + 独立字节复核）；本轮全部目标仅作数据加载，未运行任何目标本体、目标 GUI 或其产物。

## 0. 结论速览

| 工具 | 身份 | 技术内核一句话 | 产物等级 | 版本边界 |
|---|---|---|---|---|
| 穿山甲脱壳机（穿山甲脱壳机-.exe + dilloDIE 1.6） | Delphi 汉化壳 + mr_magic dilloDIE 引擎 | 双进程（DebugBlocker）调试器：hook master 的 kernel32 调试 API 构成"master 行为预言机"（oracle），逐 CC 用多组 EFLAGS 探针推断原 Jcc 并**在转储前回写原指令** | **rebuilt-pe**（运行时修补后转储；Emulate 选项退化为补丁级） | Armadillo 3.xx–4.xx（Readme 与字符串双证） |
| 穿山甲Nanomites修复器.exe | ArmNF（NeVaDa/UnReal-RCE, 2007）汉化版，引擎藏于加密 overlay | 本体为带保护壳的 dump-only 变体；以未加密原版 v1.1/v1.2 完成代码级拆解 | dump-pe → **nanomite 维度 rebuilt**（`x_ArmNF.exe` 静态回写 Jcc） | Armadillo v4.xx–6.40（v1.1）/ v4.xx–7（v1.2） |
| 脱壳工具tmdunpacker.exe | Themida/WinLicense unpacker v2.0（okdodo, 2007.11, C++Builder） | CREATE_SUSPENDED + 注入/进程内 hook（KiUserExceptionDispatcher/NtContinue），对壳内 IAT 处理例程下 bp，找 vm oep→真实 OEP→IAT 重建→转储 | **dump-pe + 导入重建**（非完整还原；ImpREC 兜底提示） | 无显式版本矩阵（2007 年代，推断面向 Themida 1.x–2.x/WinLicense，**推断**） |
| 脱壳机Themnet Unpacker_original.exe | Delphi GUI，引擎同样藏于 overlay | 仅字符串级 triage，未深拆 | 未知 | 未知 |

**最重要的增量——Nanomites 还原（我们动态引擎没有的技术）已完整拆出数据结构与算法**，三种实现流派与移植草案见第 4 节。核心认知修正：壳内并没有一张可直接提取的"(INT3 地址→原 opcode)明文表"；历代工具都是把 **Armadillo master 进程的异常处理行为当作黑箱预言机**，用受控 EFLAGS 探针穷举出每个 CC 的原条件跳转语义。

## 1. 分析环境与证据层级

- Ghidra 12.1.2 PUBLIC（`C:\tools\ghidra_12.1.2_PUBLIC`），OpenJDK 21.0.12+8（`C:\tools\jdk-21.0.12+8`），与上一轮 12.0.2 不同版本，均为工具箱既有安装。
- 证据分级沿用前一轮：字节实证（指令字节、立即数、写点）＞控制流实证（Ghidra 引用/反编译）＞语义推断（自命名函数用途）＞附带文档（Readme/.nan 格式说明）。
- 全部 5 个 case 经 `scripts/reverse/verify.py` 独立复核通过（见第 6 节）。
- 所有工具均**未运行**；"它如何处理目标"的结论来自静态读码 + 附带文档交叉，不含运行验证。

## 2. 原件与 SHA-256

输入根 `资料/老旧壳脱壳工具/`（注意：任务描述的"老壳脱壳机工具集"实际目录名如此）。

| case | 原件相对路径 | 字节数 | SHA-256（前 16 位） |
|---|---|---:|---|
| dillo-die | `穿山甲脱壳机-1.6/dilloDIE.exe` | 219136 | `656b5d9bb334bf3b` |
| dillo-wrapper | `穿山甲脱壳机-.exe` | 214381 | `305bdc5ebda29bec` |
| armnf-cn | `穿山甲Nanomites修复器.exe` | 349245 | `7178e92ea3962627` |
| armnf-v12 | `Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe` | 434176 | `0bde1ba6446c40ea` |
| tmd-unpacker | `脱壳工具tmdunpacker.exe` | 1019904 | `d45f6d4e5a3fba6b` |
| （未入管线） | `Nanofixer/Armadillo Nanomites Fixer.exe`（v1.1 未加密原版） | 385028 | `1df3d804a70e5d74` |
| （未入管线） | `脱壳机Themnet Unpacker_original.exe` | 1885128 | `009ef2c9fe914da7` |

完整哈希与命令记录在各 `资料/reverse/<case>/run.json`；除 ArmNF v1.2 外均与 `资料/archive-inventory.json` 匹配（ArmNF v1.2 不在清单，analyze.py 未传 --inventory）。

配套文本证据（同目录附带，作为文档级佐证）：

- `穿山甲脱壳机-1.6/Readme.txt`（dilloDIE 1.6 官方说明：特性、Nanomarker、Emulate 选项）
- `ArmInline0.96 最终版/Readme.txt`（Admiral 2006：**.nan 文件格式规范原文**、VEH 修复原理、"spoof INT3"方法论文档）
- `Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/{ReadMe,Feature,History,NanoLib.dll Bug}.txt`（ArmNF 版本史 + `IdentifyNano()` 源码片段：`ConditionTable[64]` 探针表）
- `Nanofixer/*`（v1.1 汉化版说明，Feature 与 History）

## 3. 穿山甲脱壳机 = Delphi 包装器 + dilloDIE 1.6 引擎

### 3.1 结构定性

- `穿山甲脱壳机-.exe`：Delphi 6/7 程序（CODE/DATA/BSS 布局，Delphi 异常类字符串），引用 `dilloDIE.exe`、`DllLoader.exe` 字符串，经 `ShellExecuteA`（调用点 0x00401917c）拉起真引擎——**它只是汉化启动器，不含脱壳逻辑**。
- `穿山甲脱壳机-1.6/dilloDIE.exe`：真引擎。仅导入 gdi32/user32/kernel32/comdlg32；全部调试 API 以 ASCII 名表（VA 0x0040a324–0x0040a5e0：CloseHandle/ContinueDebugEvent/CreateProcessA/CreateThread/DebugActiveProcess/GetThreadContext/OpenProcess/OpenThread/ReadProcessMemory/SetThreadContext/SuspendThread/VirtualAllocEx/VirtualProtectEx/VirtualQueryEx/WaitForDebugEvent/WriteProcessMemory…）在运行时经 GetModuleHandleA+GetProcAddress 解析（解析点 0x00402249/0x00402254 等）。
- 版本声明：字符串 `dilloDIE 1.6 - Armadillo 3.xx - 4.xx Unpacker`（0x0040e807）、`Armadillo 4.xx exe/dll`（0x0040e770），与 Readme 一致。作者 mr_magic，汉化 wzdbzd（2007）。
- 附带 `ArmAccess.dll`（穿山甲注册机接口库，脱壳机用它取 key 喂引擎，属配套而非脱壳本体——语义推断级）。

### 3.2 主流程（引擎 FUN_00402056，raw 0x1456，13998 字节；日志串全序列为字节实证）

GBD 日志序列（.data 0x00410ca5–0x00411190 原文）：`创建进程 → LoadLibrary...（文件名/进程 ID）→ 发现 Debugblocker...进入子进程... → 初始 IAT 被捕获 → 发现输入表消除/修复 IAT 参考(Call Ref/Jump Ref/Mov R32,[) → 发现代码拼接(指示于/基位址/内存大小/长度过大，排除)/改写长跳转/修复 JMP → 发现 CopyMemII...解码包含输入表的代码页 → 调用 OEP 钩子...确定 OEP 为 → 注入 CC 中断处理器... → 扫描潜在的 CC 中断...分析 Int3 @/解决 CC 中断 @([Size=/[Dest=/--> Jcc) → 转储 PE 区段 → 完成`。另有一条关键失败分支：`无法附加父进程，跳过 CopyMemII 和 CC 中断处理`。

代码证据（VA 可回查 instructions.tsv）：

1. **启动与双进程**：`CreateProcessA` 标志 = `4`（CREATE_SUSPENDED）或 `0x84`（+DEBUG_PROCESS，由选项位 0x0040f200 决定）（0x004021c9–0x004021f6，字节实证）。DLL 目标改用附带 `DllLoader.exe` + `C:\dilloDIE.tmp/.bak` 宿主进程（调用点 0x00402370，flags=4）。
2. **DebugBlocker 穿透**（0x004025dc–0x0040255e 一带）：把自建 PROCESS_INFORMATION 复制为 master（DAT_0040f910/0040f914），从子进程 PEB→ProcessParameters 读出真 slave 的 PID/TID，`OpenProcess(0x1f0fff)`/`OpenThread(0x1f03ff)` 全权句柄（DAT_0040f900/0040f904）。CopyMemII/CC 阶段若尚无调试关系则 `DebugActiveProcess(master)`（0x00403bf3–0x00403bf9，字节实证）。
3. **初始 IAT 捕获**：加载期对 IAT thunk 写 `EB FE`（0x004022f2：`MOV word ptr [ESI],0xfeeb`）把线程park在 thunk 上等壳填充，再回读。
4. **Import Elimination 修复**：扫描 `FF15`(call [x])、`FF25`(jmp [x])、`8B /r`（mod=disp32）、`A1` 四类 IAT 引用并改指向重建 IAT（FUN_00405dc3 后半，日志对应 0x00410f18/0x00410f2e/0x00410f44）。
5. **Code Splicing**：对每个 `E9` 目标做 VirtualQueryEx，命中"整页 MEM_COMMIT RWX(0x20|0x40)、MEM_PRIVATE、PAGE_SIZE 对齐、RegionSize=0x20000"特征的拼接页（0x00406d03 起），把跨页长跳转按 delta 重写（`改写长跳转`，0x00407052 段），转储时把拼接页物理收进新增 `.spliced` 节（节名拼字 0x6c70732e+0x64656369，字节实证于 0x004074xx 段）。
6. **CopyMemII**：VirtualQueryEx 找 `PAGE_NOACCESS` 页（`DAT_0040fd34>>8 == 1`）；在 master 的 `kernel32!ContinueDebugEvent` 首字节种 CC，SetThreadContext 重定 master EIP 强制其走解码路径，页页解密后回写 slave（0x00403c16 段，字节实证）。
7. **OEP**：OEP 钩子 + `确定 OEP 为`；`注入 CC 中断处理器...` 对应 Emulate 选项。
8. **转储**：逐节 ReadProcessMemory → `WriteFile` 追加到 `<原名>.dIE.exe`；节表补 `.idata`（0x6164692e）等新节；SizeOfImage/NumberOfSections 相应修正（0x00407278 起）。Armadillo 自身节（`.text1/.adata/.data1/.pdata`）**保留不删**（Readme 明言用 CFF Explorer 手动清理）。

### 3.3 Nanomites 还原（dilloDIE 流派 = master-API-断点预言机）

这是本报告核心，全部为字节/控制流实证：

**记录结构（变长，stride = 5 + Size）**，由写入点 0x00404a6c（`MOV byte [EAX+5],0x71`）、0x00404a8d（`MOV word [EAX+5],0x810f`）等直接证明：

```
+0      u32   Address        ; 目标映像中 CC 的 VA
+4      u8    Size           ; 原指令长度 2 / 5 / 6
+5      u8/u16 Opcode        ; size=2: 短 Jcc(0x70-0x7F)/EB/E0-E3
                             ; size=5: E9 (JMP rel32)
                             ; size=6: 0F 8x (近 Jcc)
+6/+7   i8/i32 disp          ; size=2: +6; size=5: +6; size=6: +7
                             ; Dest = Address + Size + disp
Address==0 的记录 = NanoBegin/NanoEnd 区界标记（FUN_00405dc3 中
  `*(int*)pbVar16==0` 分支，切换 DAT_0040f84c 状态并写 `E9 00000000`）
```

**还原算法**（FUN_00402056 扫描循环 raw 0x15xx–0x1bxx + FUN_00404229）：

1. LDE（FUN_00407ad7）线性扫代码段找 0xCC；
2. 对每个 CC@A：保存 slave 线程 CONTEXT（ContextFlags=0x10007），置 `Eip=A`、`EFlags=探针值` 写回 [0x00410230]（= CONTEXT+0xC0 的 EFlags 槽，字节实证）后 ResumeThread；
3. **探针值集合（字节实证）**：`0x202`（全条件位清）、`0xAC7`（OF|SF|ZF|PF|CF 全置）、`0x282`、`0xA02`、`0xA82`、`0xAC2`（中间态组合）——对 16 种 Jcc 构成判定决策树；三次粗探针的最小正向偏移 = 指令长度（fall-through），另一落点 = Dest；
4. **结果读取（预言机实现，FUN_00404229）**：预先在 **master 进程**的 `kernel32!ContinueDebugEvent` 与 `kernel32!GetThreadContext` 首字节写 CC；slave 在 A 触发真异常后由 master 模拟 Jcc 并准备对 slave SetThreadContext——此刻 master 撞上种下的 CC，异常上报到 dilloDIE 的调试循环；dilloDIE 从 master 栈读 `[masterEsp+8]` 指针再 `+0xB8`（x86 CONTEXT.Eip 偏移，字节实证 0x00404229 反编译）拿到 **master 即将写给 slave 的 Eip** = 本次探针落点；
5. 决策树比对落点 → 判定 Jcc 类型 → FUN_00405dad 追加记录（opcode 立即数见上）→ `--> JNO/JNZ/.../JMP` 日志；
6. **假 Nanomite（Nanomarker）识别**：FUN_00405dc3 对 opcode 字段为 0xFFFFFFFF 的候选，反查"是否有任何跳转（代码流中的 Jcc 或已建记录的 Dest）落在该地址"；有 → 写 `EB 03` 中和并记 `--> Excepted...`（这就是 Readme 里"用 Nanomarker 排除假 Nanomite"的实现语义）；
7. **回写**：FUN_00405e25 直接 `WriteProcessMemory(hSlave, Address, rec+5, Size)`——**在转储前把原 Jcc 字节写回目标映像**，随后 dump 出的文件即为含真实条件跳转的 rebuilt PE。

**Emulate 选项（补丁级）**：不解决 CC，而是给 dump 加 `.nano` 节（节名 0x6e616e2e+0x6f）：前 0x1000 字节为 handler 代码（模板在 dilloDIE .text 0x00407929，内含 `AddVectoredExceptionHandler` 字符串@+0x1F——运行时 LoadLibrary+GetProcAddress 解析；模板内 3 处 dword 重定位 + `*(int*)(code+0x86)=OEP`、新入口=节基址+0x85），随后跟记录表本体。对应 Readme"注入 handler 在执行期解析，仅 XP+"。

### 3.4 产物等级判定

- 默认路径：**rebuilt-pe**（运行时完成 Jcc/IAT/拼接/CopyMemII 修复后转储；但壳节保留、需外部 ImpREC 补 stolen imports 的场景在 Readme 有暗示——"Dumps are 100% working"为作者声明，非我方验证）。
- Emulate 路径：**补丁级**（VEH 运行时解释 CC）。

## 4. Nanomites 修复器（ArmNF 家族）与三种流派

### 4.1 汉化版本体（穿山甲Nanomites修复器.exe）定性

- Delphi 程序；版本资源 `InternalName=ArmNF.dll`、`OriginalFilename=ArmNF.dll`、`UnREal-RCE ArmNF`、Copyright 2007——即 NeVaDa ArmNF 的 DLL 形态改造 + 汉化（含错拼 `Armadillo Nnomites Fixer`，与原版 v1.2 同款错拼，佐证同源）。
- **引擎不可静态直达**：文件尾部 overlay（raw 0x1f000 起，0x3643D 字节）为高熵块（4KB 分块熵 7.93–7.95，首 dword `01 00 00 00`），内含 `disasm.dll`、`Armadillo Nanomites Fixer.exe.manifest` 等字符串——真实引擎被加密/压缩封装在 overlay。可见 Delphi 代码仅有 GUI/RTL/内嵌 zlib inflate（FUN_004156b0/00416a5c，puff.c 特征串 `invalid block type`）。
- 可见导入表**无任何进程/调试 API**（CreateFile/ReadFile/WriteFile 级文件 I/O + VirtualAlloc/VirtualQuery）→ 该构建仅支持 dump 文件静态修复模式（对应 v1.1 Feature "No more child process needed"）。
- 深拆改以**未加密原版**为代码级证据源。

### 4.2 ArmNF v1.2 代码级拆解（case armnf-v12）

流程（FUN_0040a070 主控，字符串与调用链实证）：

1. **候选收集**：读 dump（或子进程内存）代码段 → 统计 0xCC（`Total ... Before Optimize`）；
2. **优化器**（FUN_0040b7b0，内嵌 OllyDbg 风格反汇编器 FUN_00405fe0，CondZero 汇编/反汇编包——v1.2 字符串 `Internal OLLYDBG error`、About 致谢双重佐证）：线性反汇编剔除"指令内部数据字节"型 CC → `After Optimize`；
3. **反模式过滤**（字节实证，FUN_0040a070 内）：CC 前一字节为 `0x25/0x15` 且更前一字节为 `0xFF`（即落在 `FF25/FF15 disp32` 的立即数里）→ 排除；连续双 CC → 排除；
4. **记录数组**：16 字节/项 `{u32 Address; u32 Destination; u32 Size; u32 JumpType}`——与 ArmInline `.nan` 格式完全一致（ArmNF 基于 Admiral 引擎，Readme 明言）；JumpType 枚举沿用 ArmInline（`JUnknown=0, NotNanomite=1, JMP=2, JNZ=3 … JCXZ=19`）；
5. **标记识别**（FUN_0040a9d0）：相邻记录 `Dest-Addr==5 && Size字段==5 && 状态==2` 等组合 → 置 `JumpType=0x19`（复用 JCXZ 枚举位作 **NanoBegin/NanoEnd 区界标记**，语义等同 dilloDIE 的 Address==0 记录）；若最终仍残留 JCXZ 型 → 弹 `Unsupported version of Nanomites detected`（版本护栏）；
6. **过程模式预言机**（FUN_00401ee0/00401350/004014c0/00401bb0）：
   - `CreateProcessA(原始加壳 exe, dwCreationFlags=2=DEBUG_PROCESS)`（0x00401f08，字节实证；无 DEBUG_ONLY_THIS_PROCESS → DebugBlocker 的 slave 也纳入本工具调试域）；
   - 调试循环 `WaitForDebugEvent(1000)`：EXCEPTION_DEBUG_EVENT+0x80000003 → FUN_00401bb0；OUTPUT_DEBUG_STRING_EVENT 计满 3 次 → FUN_00401180 动态解析 WaitForDebugEvent/ContinueDebugEvent/Get/SetThreadContext（对应 master 就绪时机）；
   - **OEP 探针 stub**（FUN_00401350，14 字节，指令立即数字节实证于 0x00401372–0x004013ae）：`64 A1 18 00 00 00 / 8B 40 30 / C6 40 02 CC / CC`＝`mov eax,fs:[18h]; mov eax,[eax+30h]; mov byte[eax+2],0CCh; int3`——把 slave PEB.BeingDebugged 改写为 0xCC 后立即 INT3，用作推进/同步状态机；
   - **结果通道**（FUN_00401bb0 字节实证）：候选探针异常两次未被 master 处理 → 判假 CC（`JumpType=1`，计数进 `Total False 0xCC`）；master 处理时，从 **master 内存中一个 0xC 字节步进的队列**（`[ptr+8]` 解引用 → 0x2CC 字节寄存器快照）读取本次修复记录，并从快照中一个 u16（param+0xefc）按位重建 EFLAGS 结果（`bit1→PF(4)、bit2→OF(0x800)、bit3→SF(0x80)、bit4→ZF(0x40)、bit5→CF(1)`，移位掩码指令实证）——即 master 内部维护的 nanomite 修复记录队列被 ArmNF 直接截流；
7. **产物**：命中表整理为 12 字节/项结果数组（FUN_0040ae30，`(df8-df4)/0xc` 计数）→ 保存 `.anf`（Armadillo Nanomites Fixer file）/`.txt` 日志，或 `Apply Patch To Dumped_` 生成 `x_ArmNF.exe`（把 Jcc 静态写回 dump）/`Apply Patch To Memory` 写回子进程。

版本史（附带文档）：v1.1 测试 Armadillo 4.xx–6.40；v1.2 至 7。

### 4.3 三种流派对比（同源技术演化）

| 流派 | 代表 | 预言机接口 | 假 CC 排除 | 修复产物 |
|---|---|---|---|---|
| VEH 注入 | ArmInline 0.96（Admiral） | 挂 debugged master，OEP 后逐 CC"spoof INT3 + 变化 EFLAGS"观察 master 响应（Readme 原文 + `ConditionTable[64]`，NanoLib Bug.txt 源码） | 无法从死列表判定真伪（Readme 明言）→ 表含全部 CC | dump 加节 + 1.6KB VEH（**补丁级**） |
| master-API 断点 | **dilloDIE 1.6** | CC 种在 master 的 kernel32 GetThreadContext/ContinueDebugEvent 上，从 master 栈上的待写 CONTEXT+0xB8 直接读落点 | 跳转目标落点反查 + EB03 中和 + NanoBegin/End 标记 | **转储前回写原 Jcc**（rebuilt） |
| master 队列截流 + 静态扫描 | **ArmNF v1.1/v1.2** | master 内部 0xC 字节修复队列 + 0x2CC 寄存器快照直接读 | LDE 优化器 + FF25/FF15 反模式 + 双 CC + 稀有条件启发（`JS/JP→Maybe Not`、`JCXZ→Not`） | dump 静态回写（`x_ArmNF.exe`） |

共性结论：**三家都没有破解壳内加密的 nanomite 表本身，而是把 master 的修复行为当预言机**；差异只在"怎么偷听 master"。

### 4.4 数据结构汇总（可直接入引擎文档）

```
; 1) ArmInline .nan 文件（磁盘格式，文档原文）
u32 Count
Count × { u32 Address; u32 Destination; u32 Size; u32 JumpType }  ; 16B/项
JumpType: 0=JUnknown 1=NotNanomite 2=JMP 3=JNZ 4=JZ 5=JB 6=JBE 7=JA 8=JNB
          9=JG 10=JGE 11=JL 12=JLE 13=JP 14=JPE 15=JNP 16=JPO
          17=JS 18=JNS 19=JCXZ 20=JNCXZ 21=JC 22=JNC 23=JO 24=JNO

; 2) dilloDIE 内存记录（变长流，stride=5+Size）
{ u32 Address; u8 Size; u8/le16 Opcode; i8/i32 disp }
;   Size=2: Opcode@+5(0x70-7F/EB/E0-E3), disp8@+6, stride 7
;   Size=5: E9@+5, disp32@+6, stride 10
;   Size=6: 0F8x@+5(2B), disp32@+7, stride 11
;   Address==0 → NanoBegin/NanoEnd 标记

; 3) ArmNF 结果表（内存）：12B/项 { Address, Destination, JumpType }
;    master 内部队列：12B(0xC)/项，配套 0x2CC 字节寄存器快照

; 4) 语义等价式：Dest = Address + Size + disp；fall-through = Address + Size
```

### 4.5 移植到本项目 dynamic 引擎的实现草案（伪代码）

现有 `scripts/dynamic/dump_oep.py` 已具备 CreateProcessW(DEBUG|SUSPENDED)+WaitForDebugEvent 循环+CONTEXT 操作，预言机可增量接入（Windows 宿主层，非浏览器静态引擎）：

```python
PROBES = [0x202, 0xAC7, 0x282, 0xA02, 0xA82, 0xAC2]   # 决策树中间集
JCC_TRUTH = {...}                                      # 每种 Jcc 对 (OF,SF,ZF,CF,PF) 的布尔函数表

def resolve_nanomites(slave, code_lo, code_hi, read, lde):
    table = []
    for addr in scan_cc(read, code_lo, code_hi, lde):   # LDE 步进，非逐字节
        if false_positive(read, addr):                  # FF25/FF15 邻域/双 CC/跳入点
            continue
        outcomes = {}
        for flags in PROBES:
            outcomes[flags] = probe(slave, addr, flags) # 见下
        size = min_positive({v - addr for v in outcomes.values()})
        dest = other_outcome(outcomes, addr, size)
        jcc  = classify(outcomes)                       # 匹配 JCC_TRUTH
        table.append((addr, dest, size, jcc))
    return table

def probe(slave, addr, flags):
    # 前置（一次性）：在 master 的 kernel32!GetThreadContext 首字节种 CC
    #   （master = DebugBlocker 父进程；经 PEB->ProcessParameters 拿 slave 句柄，
    #    DebugActiveProcess(master) 或创建期 DEBUG_PROCESS 继承）
    ctx = get_context(slave); ctx.Eip = addr; ctx.EFlags = flags
    set_context(slave, ctx); resume(slave)
    ev = wait_master_bp()          # master 调 GetThreadContext 时撞 CC 上报
    eip = read_master_context_eip()# [masterEsp+8] -> +0xB8（x86 CONTEXT.Eip）
    restore_master_bp(); suspend(slave)
    return eip

# 修复（dump 前）：按 (size, jcc, dest) 重编码
#   size==2: emit 0x70|(cond) rel8 ; size==6: emit 0F 80|(cond) rel32 ; JMP: E9 rel32
```

要点与边界：

- 探针常量与决策树以 dilloDIE 实证值为基准；ArmNF 的 64 项 ConditionTable（NanoLib Bug.txt）是等价的穷举版，决策树是其压缩。
- **必须先过 DebugBlocker 双进程**（本草案第 probe 前置步），否则预言机不成立。
- 假 CC 过滤三件套（LDE 步进、FF25/FF15 邻域、跳入点反查）缺一不可，否则会把数据字节当 Nanomite 修复（ArmInline Readme 的原版警告）。
- Emulate/VEH 兜底路径（补丁级）不建议移植——它使产物依赖注入 handler，且 XP+ 语义。
- 未验证项：本草案未在任何 Armadillo 样本上运行；`[masterEsp+8]` 栈布局依赖 master 未被混淆的调用序（ArmNF 的 master 内部队列法是备选通道，但队列定位逻辑本次未完全逆出——FUN_00401580/004015c0 段未深拆，标注为推断级）。

## 5. tmdunpacker（Themida/WinLicense）

- 身份：`Themida/WinLicense unpacker v2.0 [by okdodo 2007.11]`（0x004701bc 等 4 处副本），C++Builder 程序（`@@Unpack@Initialize/Finalize` Borland 修饰名、TForm/TListBox 控件名），联系串 `okdodo@126.com`。附带 `tmdstripper.exe` 引用。
- 七步流水线（GBK 日志串，0x0056a1xx–0x0056f8xx 字节实证）：
  1. EP；2. `vmsecsize`；3. kernel32 基址/大小；4. **`bp_iatprocstart/bp_iatprocend`**（对壳内 IAT 处理例程下软件断点）；5. `查找 vm oep` → `查找真实 oep`；6. `iat 修复并转储`（iat 开始/大小；含 `iat replace code fixing error!` 错误分支）；7. `转储文件...重建输入表...全部完成! 如果它不正确, 请用 imprec 手动修复!`。
- 驱动方式（控制流实证）：`CreateProcessA`（调用点 0x004028a8，flags 槽=0x4=CREATE_SUSPENDED）+ Get/SetThreadContext + Read/WriteProcessMemory + VirtualAllocEx（7/5/3/3/3 处引用）；**无 WaitForDebugEvent/DebugActiveProcess 导入** → 非外置调试循环，而是注入式进程内插桩：字符串证据 `ntdll.dll!KiUserExceptionDispatcher`、`NtContinue`、`NtAllocateVirtualMemory`、`NtUnmapViewOfSection`（以 GetProcAddress 动态解析，0x0056a0ad 一带名表）——语义推断：hook 异常分发器承载 bp 状态机（与外部调试器流派相反，类似 dilloDIE Emulate 思路的受控版）。
- `vm oep`/`vmsecsize` 表明对 Themida/WinLicense 的 VM 化入口有专门处理路径（找到 VM 版 OEP 再退到真实 OEP）；**是否剥离/保留 VM 段未从代码确证**（转储循环未逐行拆）。
- 版本边界：无显式版本矩阵字符串；2007.11 时间点 + WinLicense 支持声明 → 推断面向 Themida 1.x–2.x 世代（**推断，不可作覆盖承诺**）。
- 产物等级：**dump-pe + IAT 重建**（自身重建失败时明示 ImpREC 手动兜底）→ 不属"完整还原"。

## 6. 验证与限制

| case | 文件映射指令逐字节一致 | 直接 CALL 校验 | 函数数 | 反编译（追加选取） | verify 结论 |
|---|---:|---:|---:|---:|---|
| dillo-die | 7177 | 1026 | 92 | 34 / 0 失败 | passed |
| dillo-wrapper | 30243 | 2520 | 753 | 3 / 0 | passed |
| armnf-cn | 30243 | 2520 | 753 | 12 / 0 | passed |
| armnf-v12 | 52851 | 3081 | 1070 | 21 / 0 | passed |
| tmd-unpacker | 126477 | 11831 | 3452 | 9 / 0 | passed |

关键字节另做窗口复核：ArmNF OEP stub（`--dump 0x401366:56`，得到 14 字节立即数序列原文）；dilloDIE 的 EFlags 探针常量与 opcode 写入点均以 instructions.tsv 原字节引证。

拆解深度诚实表：

| 结论 | 级别 |
|---|---|
| dilloDIE 记录结构/EFLAGS 探针/master-API 断点/回写/Emulate 注入 | 字节+控制流实证 |
| dilloDIE CopyMemII 解码细节、`.JGLong` 节来历 | 控制流实证/未查 |
| ArmNF v1.2 主流程、stub 字节、master 队列截流、反模式过滤 | 字节+控制流实证 |
| ArmNF master 队列定位（FUN_00401580/004015c0） | 未深拆，存在推断 |
| 汉化版 overlay 引擎 | 未解密，仅结构性结论 |
| tmdunpacker 注入式插桩细节、VM 段处理 | 字符串+导入面实证，内部未深拆 |
| Themnet Unpacker | 仅 triage |

尚未完成：任一工具的运行验证、Armadillo/Themida 逐版本样本 golden、`.anf` 磁盘格式的逐字段落盘核对（仅文档+内存结构对应）、汉化版 overlay 解密。

## 7. 可复现命令

```powershell
$Ghidra = 'C:\tools\ghidra_12.1.2_PUBLIC'; $Java = 'C:\tools\jdk-21.0.12+8'
$InputRoot = '资料/老旧壳脱壳工具'
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/穿山甲脱壳机-1.6/dilloDIE.exe" --output 资料/reverse/dillo-die --inventory 资料/archive-inventory.json --stage-ascii
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/穿山甲脱壳机-.exe" --output 资料/reverse/dillo-wrapper --inventory 资料/archive-inventory.json --stage-ascii
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/穿山甲Nanomites修复器.exe" --output 资料/reverse/armnf-cn --inventory 资料/archive-inventory.json --stage-ascii
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/脱壳工具tmdunpacker.exe" --output 资料/reverse/tmd-unpacker --inventory 资料/archive-inventory.json --stage-ascii
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe" --output 资料/reverse/armnf-v12

# 追加反编译（--reuse 不重分析）
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/穿山甲Nanomites修复器.exe" --output 资料/reverse/armnf-cn --inventory 资料/archive-inventory.json --stage-ascii --reuse --function 0040195c --function 00402248 --function 00402390 --function 0040253c --function 00402714 --function 00402ca8 --function 00402e74 --function 004034f4 --function 004037cc
py -3.11 scripts/reverse/analyze.py --toolroot $Ghidra --java-home $Java --input "$InputRoot/Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe" --output 资料/reverse/armnf-v12 --reuse --function 00401180 --function 00401350 --function 00401ee0 --function 00401bb0 --function 004014c0 --function 004094d0 --function 0040a070 --function 0040a9d0 --function 0040ae30 --function 0040b7b0 --function 0040e0b0 --function 0040e3c0 --function 0040da20

# 独立校验
py -3.11 scripts/reverse/verify.py --input "$InputRoot/穿山甲脱壳机-1.6/dilloDIE.exe" --output 资料/reverse/dillo-die
py -3.11 scripts/reverse/verify.py --input "$InputRoot/穿山甲脱壳机-.exe" --output 资料/reverse/dillo-wrapper
py -3.11 scripts/reverse/verify.py --input "$InputRoot/穿山甲Nanomites修复器.exe" --output 资料/reverse/armnf-cn
py -3.11 scripts/reverse/verify.py --input "$InputRoot/脱壳工具tmdunpacker.exe" --output 资料/reverse/tmd-unpacker
py -3.11 scripts/reverse/verify.py --input "$InputRoot/Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe" --output 资料/reverse/armnf-v12 --dump 0x401366:56
```

各 case 目录交付物同上一轮（run.json/instructions.tsv/references.tsv/functions.tsv/decompilation.txt/mapping.tsv/strings.tsv/ghidra.log 等），均在被忽略的 `资料/` 内。

## 8. 许可边界

ArmInline 声明"source is available"但未见具体条款；dilloDIE/ArmNF/tmdunpacker 均闭源未知许可。本报告只产出原创静态分析与算法语义描述；第 4.5 节草案为独立伪代码表达，未复制任何反编译代码文本进运行时。Nanolib.dll Bug.txt 中的 IdentifyNano 片段为他人发布文档的引证。
