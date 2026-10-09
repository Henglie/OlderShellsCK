# MT24：Nanomites 与穿山甲 master/slave 预言机独立实现

日期：2026-10-07。执行者：A。阶段：独占模块候选，待 M 接入与独验。

## 1. 已闭环的能力

- 纯 JS：严格解析 ArmInline `.nan` 和 dilloDIE 变长记录；在 raw=RVA 映像副本上修复 JMP、16 种 Jcc、LOOPNE/LOOPE/LOOP/JECXZ；返回 `repaired`、`unresolved`、新 `bytes`。
- 条件分类：32 组完整 CF/PF/ZF/SF/OF 真值 × ECX 的四个类别，共 128 次差分；长度由调用方提供独立证据，禁止由“最小正向落点”猜测。
- Windows 原生：x86 master 是本 backend 唯一 debuggee；master 自己调试 slave。捕获 master 的四种调试 API 的入口/成功返回，从 master 的 `CONTEXT.Eip` 读取处理结果，并输出 JSON sidecar。
- 原生良性验证：真实父调试子，完整 128 次 JLE 观察；false CC 拒绝；超时/事件预算；两个原生作业并发隔离；Job Object 清理含未被调试的孙进程。
- 指定测试命令：**52/52 PASS，0 FAIL，0 SKIP**。其中 JS 36 项、Python ABI/状态机/原生链路 16 项，最终复跑 7.88 秒。

这是依据反汇编证据编写的原创实现。没有恢复、获得或逐行复制原工具源码。运行验证对象仅为本任务原创良性宿主；参考 GUI、参考工具本体及其输出均只作静态证据。

## 2. 原 GUI 的证据与前报告勘误

先读 [armadillo-themida-unpackers.md](armadillo-themida-unpackers.md)，再以专用路径 glob/grep/read 核对被 ignore 的 `资料/reverse/dillo-die/`、`资料/reverse/armnf-v12/`。本轮所需函数已有反编译，未重写这些共享证据目录，也未新增反编译任务。

原件 SHA-256（由既有 `verification.json`、`run.json` 标识）：

```text
dilloDIE.exe  656b5d9bb334bf3bd650cc8378c1fbd5aa04e9e5f41a60a6476977403859a1da
ArmNF.exe     0bde1ba6446c40ea6717fdeb9ebf6a6e16dec2f2c675a613327230ffd9c1081a
```

既有独立字节校验分别覆盖 7177/52851 条文件映射指令、1026/3081 条直接 CALL，`passed=true`。这是既有证据管线结果；本轮没有把重新读取 TSV 冒充重新执行全量 verify。

### 2.1 dilloDIE 字节实证

证据文件：`资料/reverse/dillo-die/{instructions.tsv,strings.tsv,decompilation.txt}`。

- `FUN_00402056`，VA `00404a6c`，raw `0x3e6c`，字节 `c6400571`：向记录 `+5` 写短 JNO opcode `71`。
- VA `00404a8d`，raw `0x3e8d`，字节 `66c740050f81`：向记录 `+5` 写 `0F 81`；结合 `+4` 的 Size 与写入跨度，证明 `5+Size` 变长结构。
- `FUN_00405e25`，VA `00405e7f–00405e98`：`[EBX]` 为 Address，`MOVZX ECX,byte[EBX+4]` 取 Size，`ADD ESI,5` 取指令起点，随后 `WriteProcessMemory(hSlave, Address, rec+5, Size)`。这是转储前回写原跳转的控制流/字节证据。
- `FUN_00404229`，VA `0040452b/00404530/0040454d`，字节分别 `a134064100`、`83c008`、`05b8000000`：master ESP 槽 → `ESP+8` → 待写 `CONTEXT+0xB8` → Eip。

**勘误：最终 Eip 观察点是 master 的 SetThreadContext，不是 GetThreadContext 入口。**

解析名与地址的证据链：

```text
strings.tsv:
0x410bc5 GetThreadContext
0x410bb4 SetThreadContext
0x410ba1 ContinueDebugEvent

instructions.tsv:
00403f77 PUSH 0x410bc5  -> 00403f82 MOV [0x40f82c],EAX
00403fab PUSH 0x410bb4  -> 00403fb6 MOV [0x40f830],EAX
00403fdf PUSH 0x410ba1  -> 00403fea MOV [0x40f834],EAX
```

`FUN_00404229` 先在 GetThreadContext 与 ContinueDebugEvent 下断点，再在 Get 分支恢复 Get、植入 Set 断点，最终在 `DAT_0040f830` 分支读取上述 Eip。前报告把整个两阶段流程压缩成 Get 入口观察，省略了关键 Set 阶段。本实现按 API ABI 与成功返回分别关联。

### 2.2 ArmNF v1.2 字节实证

证据文件：`资料/reverse/armnf-v12/{instructions.tsv,decompilation.txt}`。

- `FUN_00401bb0`：读 master 内 `queue+8` 指向的 `0x2CC` 字节寄存器快照，队列指针每次增加 `0xC`。原实现是队列截流，并非从本工具的一次单进程 INT3 直接得到预言机结果。
- VA `00401d04–00401d5d`：读 `param+0xEFC` 的 u16，按位生成 PF/OF/SF/ZF/CF；快照基址 `param+0x560`，`param+0x60C` 是 `CONTEXT.Ecx`，写 0/1。64 组是 32 flags × 2 个 ECX 类别的控制流佐证。
- `FUN_00401350`：14 字节同步 stub 的立即数写入证据仍成立；本候选没有移植 PEB 改写/注入 stub。
- `FUN_0040a9d0`，VA `0040ab7b`，字节 `c744010c19000000`：记录 `+0xC` 写的是 **0x19=25**。前报告将其称为 ArmInline 的 JCXZ=19，混淆了十进制与十六进制。尚不能把内部 25 直接当磁盘枚举 19；本解析器拒绝未知 25，不推断区界。
- `FUN_00401ee0`，VA `00401efe` 字节 `6a02`，VA `00401f08` 调 CreateProcess：creation flags 的确为 `2`。Win32 中 **DEBUG_ONLY_THIS_PROCESS=0x2，DEBUG_PROCESS=0x1**。前报告“2=DEBUG_PROCESS，slave 自动纳入调试域”的解释错误；不能据此建立我们的 PID 归属模型。

### 2.3 文档级证据与推断边界

`资料/老旧壳脱壳工具/ArmInline0.96 最终版/Readme.txt:104–155` 明确给出 Count、16 字节字段和 EOF 要求；同时警告 Size 存在怪值，以及表可能包含假 CC。它是**格式文档证据**，不是所有记录都安全可回写的运行证明。

`NanoLib.dll Bug.txt` 说明负向分支被有符号 Offset 启发式误认成 JMP 的问题。本实现用完整落点真值匹配，反向分支不走“最小正向偏移”启发式。

master 的具体队列定位、跨版本 DebugBlocker 内部布局仍未确证；函数用途命名与版本兼容范围不能提升为实测事实。

## 3. 纯 JS API 与算法

文件：`src/core/unpackers/nanomites.js`。依赖仅为现有 `errors.js`；无 UI、Node、注册表、原生进程或跨任务可变状态。

出口：

```js
parseArmInlineNan(bytes, { maxRecords } = {})
parseDilloDieRecords(bytes, { maxRecords } = {})
createFlagProbes()                       // 32 个 EFLAGS
createNanomiteProbes()                   // 128 个 { eflags, ecx }
classifyNanomite(observations, { address, size, destination })
repairNanomites(image, records, options)
parseNanomiteSidecar(jsonOrObject)
applyNanomiteSidecar(image, jsonOrObject, options)
```

常量出口：`NANOMITE_LIMITS`、`NANOMITE_SCHEMA`、`FLAG_MASK`、`NANOMITE_CONDITIONS`。

### 3.1 格式

```text
ArmInline .nan（全部 little-endian）：
u32 Count
Count * { u32 Address, u32 Destination, u32 Size, u32 JumpType }
总长度必须恰好为 4+16*Count；未知类型保留供 unresolved 诊断。

dilloDIE（调用方提供精确流切片，不猜终止符）：
u32 Address; u8 Size; u8 instruction[Size]
Size=2/5/6，跨度 5+Size。
短：70..7F / EB / E0..E3 + rel8
近 JMP：E9 + rel32
近 Jcc：0F 80..8F + rel32
Destination = Address + Size + signed displacement
Address=0 保留为 marker-record，不产生写入。
```

规范化记录为小写字段 `{address,destination,size,condition}` 或 `{address,destination,size,jumpType}`；dillo 记录附带独立复制的 `encoding`。两种解析器仅结构损坏时抛稳定 `AnalysisError`；unknown opcode、marker、未知 enum 不生成猜测指令。

ArmInline 的 JP/JPE、JNP/JPO、JB/JC、JNB/JNC 是语义别名。enum 19 的 JCXZ 命名存在计数器宽度歧义：只有显式 `counterBits:32` 才映射为 PE32 的无前缀 `E3`/JECXZ；enum 20 的 JNCXZ 没有单条 x86 对应指令，返回 `unsupported-jncxz`。16 位 CX 前缀形式、rel16、其他前缀均未实现。

### 3.2 回写约束

必填 `options.layout='raw-rva'`、数值 `options.imageBase`。`sizeOfImage` 默认输入长度，可向下收紧。每条记录检查：

1. 32 位 VA、合法 Size、原址仍为 `CC`、site 与目标位于映像范围。
2. JMP 仅 2/5 字节；Jcc 仅 2/6 字节；LOOP/JECXZ 仅 2 字节。精确计算 rel8/rel32，越界拒绝，禁止地址回绕。
3. 所有写区间先排序；重复、嵌套、链式重叠的**所有成员**均拒绝，不能按输入顺序取赢家。
4. 若给出 dillo `encoding`，重新编码结果必须逐字节一致；JSON 的 byte 值必须 0..255，禁止截断/取模把坏值变好值。
5. 保守拒绝处于已知 `FF15/FF25 disp32` 槽内的 CC。
6. 可传独立反汇编的 `instructionSpans:[{address,size}]`，拒绝操作数内部或未被证明的指令边界；可传 `executableRanges` 收紧写范围。

局部 FF15/FF25 检查**不是完整 LDE**。没有 `instructionSpans` 时，不能证明任意立即数/数据中的 CC 都是假 CC；输入记录的来源与指令边界仍须调用方确证。模块不自动逐字节扫描、不套用双 CC/Nanomarker 启发式、也不将 NotNanomite 写成 EB03。

返回 `{bytes,repaired,unresolved,complete}`：合法的互不重叠记录可独立成功，其余保留具体 reason；输入映像始终不变。`complete` 只表示本次记录处理无 unresolved，**不表示 PE 重建或运行成功**。

### 3.3 完整条件辨识

五个条件位产生 32 种 EFLAGS（固定基底 `0x202`）；ECX 取 `0,1,2,0x10000`，既区分 LOOP 与常量分支，也排除把 CX/ECX 宽度混为一谈。

分类流程：

```text
检查每个 (condition-flags, ECX) 的重复观察是否一致
要求完整 128 类，六值快捷集/固定 ECX 返回 incomplete-probes
fall-through = Address + independently supplied Size
要求恰好一个不同于 fall-through 的目标；全 fall-through 返回 ambiguous-target
逐条件比较所有 EIP == (truth(flags,ecx) ? target : fall-through)
同时验证该条件可编码成指定长度、位移不溢出
只有唯一候选才返回 resolved record；零候选/多候选不写入
```

支持 16 种标准 Jcc 的完整真值、JMP、LOOPNE/LOOPE/LOOP/JECXZ。128 次观察中 JMP 可以全到 target；Jcc 到 target 与 fall-through 两点；若 target 等于 fall-through，指令语义无法由 EIP 区分，拒绝。

`classifyNanomite` 本身只研究观察值；目标映像范围与原址 CC 的最终约束由 `repairNanomites` 执行。

## 4. Windows backend 的实际状态机

文件：`scripts/dynamic/armadillo.py`。

Python 出口：`OracleStateMachine`（纯状态）、`MasterOracleBackend`（一次性原生作业）、`validate_plan`、`supplied_records`、`context_values`、`main`；ctypes ABI 为独立定义，不导入/改写 `dump_oep.py`。

```text
starting
  -> observing-master             本 backend 只收到 master CREATE_PROCESS
  -> master-debugging-slave        master 的 WaitForDebugEvent 成功返回 slave CREATE_PROCESS
  -> probing                      匹配显式地址的 slave first-chance INT3
  -> observations-complete        每个样本完成 Get / Set / Continue 成功链
```

实际步骤：

1. 创建带 KILL_ON_JOB_CLOSE、8 个活动进程上限、256 MiB Job 内存上限的 Job；以 `DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED` 创建 x86 master，确认 Assign 成功后才 Resume。
2. 从 master 的 kernel32/kernelbase **远程 PE32 导出**定位 WaitForDebugEvent/GetThreadContext/SetThreadContext/ContinueDebugEvent。跳过 forwarder 字符串，等待真正实现模块；不假定本 Python 的 x64 API 地址等于远程 x86 地址。
3. master API 入口读取 x86 stdcall 栈参数，返回地址下临时断点。恢复一字节、校正 **master** Eip 并 TF 单步再重设断点；期间暂停已知其他 master 线程，避免恢复窗口竞态。识别普通及 WOW64 的 `80000003/80000004/4000001F/4000001E`。
4. master Wait 返回 BOOL 成功后读取 master 自己的 96 字节 x86 DEBUG_EVENT。从 CREATE_PROCESS 的远程 handle Duplicate，核真实 PID、Toolhelp parent PID 与 Job 归属。必须是 master 的直接 slave。
5. slave 已由 master 调试；本 backend 从不对其调用 DebugActiveProcess。Get/Set 的远程线程 handle 再经 DuplicateHandle + GetProcessIdOfThread/GetThreadId 核 PID/TID，不能凭线程号猜归属。
6. 对显式计划中的地址，要求真实 slave 异常地址匹配且原址为 CC。master Get 成功返回后，仅更改 **master 输出 CONTEXT 缓冲区**里的条件位与 ECX；保持 slave Eip 不变，不劫持 slave 调试所有权。
7. master 自己算出新落点。Set 入口从参数指向的 `CONTEXT+0xB8` 取 Eip，Set 成功且该 slave PID/TID 的 Continue 成功、status=DBG_CONTINUE 后才提交 observation。重复 Get 重施同一输入，采用最终成功 Set；同一地址出现多 PID/TID owner 返回 `ambiguous-probe-owner`。
8. 完成/失败均 Query Job 进程列表，保留可同步的进程句柄，TerminateJobObject，排空自己的 master debug events，Close Job，再逐 PID 句柄确认退出。未确认全部退出时 `complete=false`、`probe-unavailable`。

本实现是**自然命中驱动**：只有程序本来执行到计划地址时才 probe。它不会反复把 slave Eip 拉回每个 CC。因此没有自然重复执行、Get 输出缓冲区通道不成立、版本改用内部队列/直接系统调用、句柄归属不明确时，不会宣称 Nanomite 已解决。

### 4.1 JSON 协议与 CLI

```json
{
  "schema": "armadillo-oracle/v1",
  "layout": "raw-rva",
  "imageBase": 4194304,
  "mode": "probe",
  "status": "observations-ready",
  "complete": true,
  "nanRecords": [],
  "probes": [{
    "address": 4198400,
    "size": 2,
    "status": "observations-ready",
    "observations": [{
      "eflags": 514, "ecx": 0, "eip": 4198402,
      "masterPid": 100, "slavePid": 200, "slaveTid": 201,
      "source": "master-set-context/continue-success"
    }]
  }],
  "processes": [],
  "apiEvents": [],
  "cleanup": {"verified": true, "survivors": []}
}
```

示例只展示一条观察；JS 分类必须有完整 128 类。真实 sidecar 的 processes 有 master/slave 角色、parentPid/debuggerPid/insideJob；cleanup 另有 `processTreePids`，包括不被调试的后代。`apiEvents` 记录 API 阶段与 BOOL 返回；`masterExceptions` 是最多 64 条诊断样本，不是观察结果。

```powershell
$env:PYTHONIOENCODING='utf-8'
py -3.11 -B scripts/dynamic/armadillo.py --mode records --records <records.json> --sidecar <records.sidecar.json>
py -3.11 -B scripts/dynamic/armadillo.py --mode probe --sample <benign-master.exe> --probe-plan <plan.json> --sidecar <observations.json> --timeout 15 --max-events 20000
```

`records.json` 为 `{imageBase,nanRecords}`，只做规范化记录输送，返回 `records-ready,complete:false`；实际字节修复归 JS。binary `.nan`/dillo framing 不在 Python 重复实现。

`plan.json` 为 `{imageBase,probes:[{address,size,samples:[{eflags,ecx}]}]}`。通过 `createNanomiteProbes()` 生成 samples；地址与 Size 必须是调用方已证明的候选。最多 32 个地址、4096 次输入，单地址最多 128；原生单次事件上限默认 20000、硬上限 50000，API 日志 4096，活动 master 线程 64，超时默认 15 秒、最大 60 秒。

CLI mode 必须显式选择 records 或 probe。正常记录/观察出口码 0；unsupported/probe-unavailable 出口码 3。没有 plan 为 `missing-probe-plan`，x64 master 为 `unsupported/unsupported-architecture`，没有足够自然命中为 `probe-unavailable/probe-timeout`；完整观察仍需 JS 判为 resolved，不能把 `observations-ready` 直接当修复成功。

JS 限额：记录 65536、二进制表/JSON 字符数 2 MiB、映像 128 MiB、单组观察 4096、sidecar 观察总数 65536、独立反汇编 spans 131072。SharedArrayBuffer 映像/二进制表拒绝。options 只能降低记录上限。

## 5. 实测证据

```powershell
node --test tests/nanomites.test.js tests/armadillo.test.js
# tests 52; pass 52; fail 0; skipped 0
```

测试不会调用产品注册表。原生原创 fixture 源码嵌入 `tests/armadillo.test.js` 的 `fixtureSource`，保持 MT24 五文件写锁。编译路径从规范库 `3）项目资产与工具路径.md` 的 `<VS根>` 实值提取，使用 `vcvars32.bat` + MSVC，`/Od /MT /DYNAMICBASE:NO /BASE:0x400000`。源与二进制/计划/sidecar 放 `<temp预批准目录>/armadillo-mt24-*/`，不修改共享 fixture 或参考工具目录。

良性 fixture：master 以自己的 DEBUG_ONLY_THIS_PROCESS 调试 child，child 调用导出 Nanomite 的 `CC 90 C3 ... C3` 布局 128 次。master 用独立 `ZF || (SF != OF)` 真值计算 `A+2/A+16`。另生成不被调试的 grandchild，永久等待直到 Job 清理。

一次完整本轮记录（目录名 `armadillo-mt24-aVEFHj`，PID 仅为当次值）：

```text
master PID=17188; slave PID=30972; parentPid=debuggerPid=17188
128 observations; 1052 master API entry/return records; 2118 backend debug events
Job processTreePids=[17188,30972,38068]
cleanup.verified=true; survivors=[]
独立修复 golden：7E 0E（JLE +14），原输入仍为 CC 90
```

覆盖：所有 Jcc 的短/近独立 byte golden 与真/假两落点；LOOP/JECXZ；反向 rel8/rel32；伪 CC/操作数 CC；bad Size、原址非 CC、区间/位移越界、unknown/marker/计数器宽度歧义、重叠成员全拒绝、六值/缺探针/冲突观察拒绝、JSON byte 不截断、32 个 JS 作业隔离。原生还验证失败 Set/Continue、错误 PID/TID、事件预算、x64 预拒绝、真实 false CC、真实超时、并发两棵不同三进程树。

## 6. M 接入清单与未闭环项

需要 M 单写接入：

1. 新 engine/操作描述与 HTTP/MCP/GUI schema；显式 records/probe 模式、地址/Size 来源、执行属性与作业预算。
2. `.nan`/dillo 上传内容在 core 解析后调用 `repairNanomites`；sidecar 调用 `applyNanomiteSidecar`。映像必须已是 raw=RVA；磁盘 PE 先转换，不得用文件 rawOffset 冒充 RVA。
3. 原生 probe 在独立 Python 子进程中执行；消费 stdout 或 sidecar JSON，映射稳定 unsupported/probe-unavailable。每作业新建 backend，不复用调试对象。
4. 给出匹配来源/阶段/VA 基址的独立 dump 与指令边界证据。当前 backend 返回观察后即清理进程树，**没有输出 dump**；不能等其退出后再从旧 PID 转储。若要同次运行 dump，需单独设计快照出口与阶段锁，并补原生验证。
5. 合并 `unresolved` 和 `cleanup` 诊断。当前产物是修复后的 memory image；只有 M 的 OEP/IAT/PE 重建与验证全部成立，才能升级最终 artifact 等级。接口实载、错误传输、取消与服务并发由 M 独验。

未实施/未实测：实际 Armadillo 加壳样本与逐版本矩阵；自动 DebugBlocker/OEP 发现；强制 INT3 重放；完整 LDE 与真假 Nanomite 判别；master 私有队列截流；CopyMemII、Code Splicing、IAT/PE 转储重建；VEH 注入；跨架构、rel16/前缀、CX16、`.anf` 私有磁盘格式与汉化 overlay 引擎。

原生成功链的运行实证限定为原创 x86 JLE 宿主，其他条件在纯 JS 的独立差分/golden 中验证；不能把此结果解释为 dilloDIE/ArmNF 全功能、穿山甲全版本或原 GUI 源码已恢复。
