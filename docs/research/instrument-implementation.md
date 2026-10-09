# Instrument 独立引擎：证据、实现与验证

日期：2026-10-07。责任代理：C。入口：`src/core/unpackers/instrument.js`。

## 1. 结论与证据修正

本实现是 **x86 PE32 一次性异常/上下文观察器 + 内存映像提取 + 导入修复 adapter**。可独立运行；尚无 Themida/WinLicense 脱壳覆盖承诺。

`armadillo-themida-unpackers.md` 第 5 节只有 GUI 导入面、日志串及字符串证据，不能据此认定原工具在 `KiUserExceptionDispatcher`、`NtContinue` 入口种软件断点。复核嵌入的真实 `inject.dll` 后，结论修正为：

1. 原 GUI 释放 DLL、重映射目标映像、重定线程到 loader stub；DLL 在目标进程内运行。
2. 原 DLL 沿 `KiUserExceptionDispatcher` 内部相对 CALL 链定位 **嵌套 SEH handler 调用路径**，按 OS 5.0/5.1 分支写 E9/E8 相对跳转到自建桥接器。
3. 状态机写的是 x86 `CONTEXT.Dr0/Dr1/Dr7`，包含 `0x80000004` 单步异常分支；其 IAT/VM/OEP 追踪依赖硬件断点状态。
4. `NtContinue` 被动态解析、保存并在“已处理”分支调用；这条代码链没有证据表明它被作为第二个入口软件断点 patch。

因此，“soft-BP 观察器完全复刻 tmdunpacker”不成立。独立引擎只复用两个可观测的系统控制流边界，未移植原保护器专用状态机。

### 1.1 原件与静态处理

- GUI：`资料/老旧壳脱壳工具/脱壳工具tmdunpacker.exe`，1019904 bytes。
- GUI SHA-256：`d45f6d4e5a3fba6b40bf856d8e5a21ef56c7cac67a9cfac9f8a389d85cd30e35`。
- 既有证据：`资料/reverse/tmd-unpacker/{run.json,instructions.tsv,references.tsv,decompilation.txt}`。
- DLL 资源：`.rsrc/0/FILE/INJECT`，194048 bytes，独立 PE32 DLL。
- DLL SHA-256：`1966b09b15bc32351f18202b419481fbbc8abe5056ebbd1675c03aa988ab6ef2`。
- 本轮暂存证据位于 `%LOCALAPPDATA%/Temp/opencode/instrument-tmd-{static,evidence,gui}`。GUI/DLL 仅作为数据交给 7-Zip、Ghidra 12.1.2、独立字节校验器；**未执行 GUI、DLL 或其生成物**。
- GUI 独立校验：126477 条文件映射指令、11831 个直接 CALL 与原件匹配；原件哈希不变。
- DLL 补充校验：37601 条文件映射指令、2096 个直接 CALL 与资源匹配。人工指定反编译入口以真实指令边界为准；`0x4017a0` 是数据尾部，初始化代码实际从 `0x4017a4` 开始，不能将前者的错误函数签名当 ABI 证据。

### 1.2 可回查的控制流与写点

以下 DLL VA 均按首选基址 `0x400000` 标注，不能与外层 GUI VA 混用。

**GUI `FUN_004026a4`：**

- `FindResourceA("inject", "FILE") → LoadResource/LockResource → WriteFile`，输出路径由系统目录与 `\inject.dll` 拼成。
- `0x402899: 6a04` 是 `CREATE_SUSPENDED` 标志；`0x4028a8` 调用 `CreateProcessA`。
- `NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory` 重映射目标；读取 x86 线程 CONTEXT、等待 park、SuspendThread。
- `0x402989: 68c4000000` 分配 `0xc4` bytes loader stub；`0x4029aa` 写入、`0x4029c3/0x4029da` 修补 `+0x2c/+0x32` 槽，`0x4029df` 改保存的 EIP，`0x4029f2/0x4029fb` SetThreadContext/ResumeThread。
- 模板 `0x471ad0` 的原始窗口包含 `ebfe60...64a130000000...`、手工 PE export 查找、`LoadLibraryA` 与 `inject.dll` 字符串。反编译临时变量存在栈重叠，stub 布局以原始字节和写点为准。

**DLL 初始化 `0x4017a4`：**

- 解析 `ntdll!NtContinue` 存入 `DAT_0042c46c`；同时解析 `LoadLibraryA`、`VirtualAlloc`、`NtAllocateVirtualMemory`。
- 对后两者扫描 RET 位置，设置状态机观察地址；尾部调用安装器 `0x4030f4`。

**安装器 `0x4030f4`：**

- 解析 `KiUserExceptionDispatcher`，查第一个 E8 CALL 的目标；在该目标里寻找 CALL 后紧跟 `f6 05` 的形状，再沿 rel32 定位下一层路径。
- `GetVersion().AX == 5` / `0x105` 两支；`0x40316f` 与 `0x4031eb` 装入桥接器 `0x403094`，计算 `bridge - (patch + 5)`。
- `0x423ba2` 原字节 `e9 00 e8 00`：5.0 分支取 E9，5.1 分支取 E8；先写 opcode，再保存旧 rel32 到 `0x42c474` 并写新 rel32。
- 这是基于旧版 ntdll 指令形状的**内部 SEH 调用点重定向**，不是两个导出入口 INT3。

**桥接器 `0x403094`：**

- `5589e5608b45088b4d105150e8d3e9ffff`：保存寄存器，取 `[EBP+8]` exception record 与 `[EBP+0x10]` context，调用 `FUN_00401a78`。
- 未处理分支重新建立 `FS:[0]` 链，转调原 handler 指针 `[EBP+0x18]`，`RET 0x14`。这组参数是 handler 调用 ABI，不能当成 KUED 入口栈。
- 已处理分支 `0x4030e3/0x4030e5/0x4030e8` 字节：`6a00 / ff7510 / 3eff156cc44200`，即 `NtContinue(context, FALSE)`。

**状态机 `FUN_00401a78`：**

- `CONTEXT+4/+8/+0x18` 分别是 `Dr0/Dr1/Dr7`，不是 EIP 或 EFLAGS。
- `0x401bf4: c7461805050000`、多处 `c7461801050000`、`0x402909: c7461801050100` 对应 `Dr7=0x505/0x501/0x10501`。
- `param_1[3]` 是 exception address；单步异常分支检查 `0x80000004`，推进 IAT 处理入口/出口、VM OEP 与实际入口状态。
- `FUN_004013c0` 对保护器编码的引用记录解码，回写 `FF15/FF25 + abs32`；其后执行转储/输入表修复。本引擎未实现这条保护器专用链。

## 2. 独立实现的 ABI 与断点生命周期

### 2.1 真正的字节布局

`FLOATING_SAVE_AREA`：7 个 DWORD、80-byte `RegisterArea`、DWORD `Cr0NpxState`。总长 **112**。旧半成品额外的 `ErrorOperand[2]` 会把后续寄存器整体移后 8 bytes。

`CONTEXT/WOW64_CONTEXT`：总长 **716**；`FloatSave=0x1c`、`SegGs=0x8c`、`Eip=0xb8`、`SegCs=0xbc`、`EFlags=0xc0`、`Esp=0xc4`、`ExtendedRegisters=0xcc`。

Python `--self-test` 检查 `ctypes.sizeof` 和真实字段 `.offset`，而非只检查常量自洽。原创 C 宿主另用 Windows SDK `C_ASSERT(sizeof/ FIELD_OFFSET)` 交叉验证。宿主调试 ABI 与远程 x86 ABI 分开：x64 `DEBUG_EVENT` 为 176 bytes、union 偏移 16；`CREATE_PROCESS_DEBUG_INFO` 的两个 debug-info 字段都是 DWORD，不是指针。

**Wow64 KUED32：**内核转移，无普通 CALL 返回地址。`[ESP] = EXCEPTION_RECORD*`，`[ESP+4] = CONTEXT*`。本机真实入口字节：

```text
fc 8b 4c 24 04 8b 1c 24 51 53 e8 0e 29 ff ff 0a
   mov ecx,[esp+4]  mov ebx,[esp]
```

**NtContinue32：**stdcall。`[ESP] = return address`，`[ESP+4] = CONTEXT*`，`[ESP+8] = TestAlert`。它的 CONTEXT 可合法位于堆/静态区，不能因“不紧邻当前栈”而否定。

CONTEXT 校验包含 i386/CONTROL flags、用户态 CS、EFLAGS 固定位、EIP/ESP 范围、指针对齐与完整读取。观察值单独附 `executableLanding`；既不扫描栈猜指针，也不提供未验证的 x64 fallback。

### 2.2 一次性 hook

1. CreateProcessW 使用 `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED`；成功加入 Job 后 ResumeThread，才能收到首个创建调试事件。
2. 输入文件入口种一个独立同步 INT3。此处只是输入 EP，**不是 OEP**。同步完成后才种两个 ntdll hook，避免 loader 自身的 `NtContinue(..., TRUE)` 提前消耗观察点。
3. 只有异常地址精确匹配 armed hook，且异常码是 `0x80000003` 或 Wow64 `0x4000001f`，才增加 `bpHits`。
4. 调试事件已停止所有线程；先读取待分发/恢复的上下文，再恢复原 byte、FlushInstructionCache、核对 byte、回拨 EIP。
5. 该点永久 consumed。没有 6ms 重植、TF 重植或去重“伪装成没有循环”。上限两次真实 hook hits。
6. 未拥有的应用异常以 **`DBG_EXCEPTION_NOT_HANDLED=0x80010001`** 续行。旧半成品的 `0x40010004` 是 `DBG_TERMINATE_PROCESS`，不能用于合法异常分发。

`events` 是观察阶段实际收到的 DEBUG_EVENT 数，包括 loader、DLL、线程、同步点、hook 和应用异常；不包含内存采样次数或清理阶段 drain。`startupSyncHits` 单列；`bpHits` 只含两个 ntdll hook。纯 UPX 未主动制造异常/调用恢复上下文时，`bpHits=0` 正常，`events>0` 不能证明插桩命中。

ntdll patch 仅改变导出入口第一 byte。**没有隐藏 DEBUG_PORT、debug object、PEB 调试状态或计时信息**；metadata 固定 `debugPortHidden:false`、`singleStep:false`。

## 3. 输入、资源与输出协议

`--stat <sample>` 静态读取并拒绝 PE32+、非 i386、DLL、CLR、driver、非法入口/节/目录范围和截断文件；运行路径同样在 CreateProcessW 前执行 stat。当前上限 128 MiB。

Job 必须先创建并设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE=0x2000`，分配成功后才放行 suspended 目标。Job 无名、句柄不继承、未设 breakaway。所有自有 process/thread/job HANDLE 与调试事件的 file/额外 process/thread HANDLE 都有关闭路径；退出线程的 OpenThread HANDLE 单独释放。

normal exit、timeout、event-limit、second-chance、输入入口同步/植点失败、父管道 EOF 都经过同一 finally 清理：TerminateJobObject/TerminateProcess、继续 pending event、drain 终止事件、关闭 Job、等待主进程、关闭余下 HANDLE。成功 JSON 在清理后输出。

dump 在 debug-stop 或成功 NtSuspendProcess 后读取，临时放开不可读/guard 页后恢复原权限；任何不可读映像区域使本次读取失败。周期性保留完整 live cache；exit/second-chance 当实时读取失败时允许回退，明确 `captureSource:'cached-live'` 与 `captureAgeMs`。没有映像 cache 的早退报错。

CLI：

```powershell
py -3.11 -X utf8 scripts/dynamic/dump_instrument.py --self-test
py -3.11 -X utf8 scripts/dynamic/dump_instrument.py --stat C:\path\benign.exe
py -3.11 -X utf8 scripts/dynamic/dump_instrument.py C:\path\benign.exe C:\existing-dir\dump.bin 2 2000 '["--quiet"]'
```

成功 stdout 最后一行：

```js
{
  ok: true, imageBase: 0x400000, size: 49152, late: true, stage: 'instrumented',
  events: 19, bpHits: 2, observations: [/* validated or explicitly invalid hook contexts */],
  oepCandidates: [], oepConfirmed: false, oepQuality: 'observed-landing-only',
  instrumented: true, hookMode: 'one-shot', singleStep: false, debugPortHidden: false,
  startupSync: 'input-entry-one-shot', startupSyncHits: 1,
  hookSites: [/* VA, original entry bytes, armed, hits */],
  imports: { snapshot: true, modules: 5, exports: 6159 },
  exitReason: 'timeout', captureSource: 'live', captureAgeMs: 15, pid: 32736
}
```

`entryPoint` 省略：未确证 OEP。`oepCandidates` 只保留有效 hook context 中映像内、可执行、输入入口节以外的 **精确 RVA**；不将 16-byte bucket 起点冒充指令边界。

旁路 `<dump>.imports.json`：`{modules:[{dll,imageBase:'0x...',exports:[{rva:'0x...',name}|{rva:'0x...',ordinal}]}]}`。这里只是解析运行时 IAT 的 export map，尚不是重建后的导入表。

## 4. JS adapter 与 M 接入清单

导出：`INSTRUMENT_ENGINE`、`unpackInstrumented(bytes, name, options)`。

- ID：`instrumented-exception-dump`；mode `instrument`；route `instrument/debug`；runtime `server`；platform `win32`；requiresSampleExecution `true`。
- 默认选项：`timeoutSeconds:20`、`maxEvents:2000`、`timeoutMs:timeoutSeconds*1000+10000`、`sampleArgs:[]`。Python timeout 范围 0.1–120s，事件上限 16–100000；JS transport deadline 范围 50–180000ms。
- 每任务 `mkdtemp(tmpdir()/older-shells-instrument-*)`，独立输入、dump、snapshot、进程及观察状态；finally 删除目录，带短重试。
- spawn 为 `py -3.11 -X utf8`。transport deadline 先关闭 stdin，Python 用 PeekNamedPipe 识别 EOF 并清理；750ms 后未退出则针对 launcher PID 执行 `taskkill /T /F`。只在 child `close` 后结束 Promise、删除目录。
- 复用 `dynamic.js` **已有纯函数 exports**：`rebuildMemoryImagePe` 与 `applyImportSnapshot`；导入此模块不调用它的动态 runner。
- OEP 未确证，固定 `extract-pe`；即使 `importsRebuilt:true`，也不采用 import helper 返回的 `rebuilt-pe` 等级，不写回猜测的 OEP，不标 runtime verified。
- 返回 metadata 含 `events/bpHits/hookHits/observations/hookSites/oepCandidates/oepConfirmed/startupSyncHits`，便于 M 展示“植点数/真命中/候选质量”。
- 稳定 `AnalysisError`：`engine-unavailable`、`instrument-unsupported-input`、`invalid-options`、`instrument-failed`、`tool-timeout`、`tool-error`；PE 静态解析错误保留现有 AnalysisError code。

M 的接入动作：

1. 在 server registry 导入上述两个 export，按显式用户选择注册；`supports` 设为总是 false，避免静态分析自动执行样本。
2. catalog/capabilities 暴露 `instrument/debug`、一次性覆盖、x86、sample execution、`extract-pe`。
3. 将 options 原样传入；展示 debug events 和 hook hits 两项，不用前者推导后者。
4. 产物等级读取 adapter metadata；不要以“已重建 IAT”提升为完整还原，也不要把输入 EP 当 `originalEntryPoint`。
5. 将第 1 节的新 DLL 指令证据并回主研究报告第 5 节，修正原“软件 BP”推断。

与当前 `registerServerEngine` API 对齐的 M 接入片段（server-only）：

```js
import { INSTRUMENT_ENGINE, unpackInstrumented } from '../core/unpackers/instrument.js';
registerServerEngine({
  metadata: INSTRUMENT_ENGINE,
  supports: () => false,
  unpack: unpackInstrumented,
});
rebuildCatalog();
```

## 5. 已完成运行验证

仅运行原创 `tests/fixtures/instrument-host.c` 及可信 `tools/upx/upx.exe` 对它生成的 packed 版本。外部存量 fixture 未执行。C host 无 CRT、无网络/持久化/用户文件写入；只进行合法 VEH/UD2/NtContinue、Sleep、OutputDebugString、受控子进程和退出。

环境：Python 3.11.4 x64、Node v26.4.0、MSVC 14.51.36231 x86、Windows SDK 10.0.26100.0、官方 UPX 4.2.4。测试可用 `INSTRUMENT_CL/INSTRUMENT_SDK/INSTRUMENT_SDK_VERSION` 覆盖编译器/SDK 路径；编译和 packed/golden 产物仅在测试 mkdtemp 内。

```powershell
node --test tests/instrument.test.js
```

最终 focused：**9 tests / 9 pass / 0 fail / 0 skipped**；self-test 另含 8 项 ABI/范围检查。

- **真实 hook**：`events=19, bpHits=2`；KUED `eip=0x401056`、`code=0xc000001d`；NtContinue `eip=0x401058`、`TestAlert=0`。两次读取同一有效 CONTEXT，后者落在 handler 改写后的 `UD2+2`。
- **真实进展**：`sehCount=3`、`continueCount=1`、`phase=3`；证明原 byte 恢复/EIP 回拨后继续执行了三次异常和一次显式 NtContinue，未循环重陷。
- **UPX golden**：quiet 路径 `events=14, bpHits=0`，解压后的 **673-byte `.text` 与独立未加壳构建 100% 相同**；`phase=2`；`importsRebuilt:true`，产物仍是 `extract-pe`。
- **并发**：两个任务同时执行，两个不同目录/PID；quiet 的 hits=0、异常路径 hits=2，phase 分别 2/3；结束后目录消失、主进程无存活。
- **进程树**：exit、engine timeout、event-limit、second-chance 四条路径均实际创建子进程；每条完成后查询 parent/child 存活数为 0。
- **transport deadline**：见证 parent 与 child 同时存活后触发 JS deadline；返回 `AnalysisError('tool-timeout')`，结束时两者存活数为 0、任务目录消失。

OEP 质量：以上实验验证了解压映像和控制流观察，**没有确证 OEP**。两个示例 `oepCandidates=[]` 都正常；该数组为空不否定解压成功，也不意味着获得完整可执行还原。

## 6. 未实现项

- tmdunpacker 原 DLL 的 DRx/IAT/VM 状态机、保护器编码引用表解码、stolen imports 修复。
- Themida/WinLicense 真实版本样本矩阵、VM 去虚拟化及 OEP 证实。
- 连续异常 hook、可靠 TF 重植；现有机制每导出至多观察一次。
- 输入 EP 之前的 TLS/loader 活动追踪、DLL/CLR/driver/native x64 运行。
- DEBUG_PORT/其他反调试隐藏、产物运行正确性验证；Job Object 是生命周期控制，不是安全沙箱。

静态研究数据未复制为 runtime handler；Python、JS、benign host 都是独立实现。
