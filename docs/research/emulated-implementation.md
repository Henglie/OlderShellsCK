# MT25：原创 x86 PE32 仿真与影子 Win32

日期：2026-10-07。执行者：B。阶段：候选模块；共享入口接入、独验由 M 完成。

## 1. 已实现与实测结论

原创纯 JavaScript IA-32 部分解释器，逐条执行真实 UPX stub；PE 读取复用项目公共工具，解码、filter、重定位由客体 stub 指令完成。产品模块不导入 `upx.js`、NRV 解码器、研究产物或测试 fixture，不调用 `unpackUpx`。

- `lbop20.upx.bin`：955,810 fuel steps，解码 93,445 字节，OEP RVA `0x1252`，输出 106,496 字节。
- 对独立 `lbop20.golden.bin`，按双方节表 raw/RVA 映射比较：102,124 / 102,400 = **99.73046875%**；代码 RVA `[0x1000, 0xc200)` 共 45,568 字节 **100%**。
- 第二个真实样本 `lab18-01.upx.bin`：306,319 steps，解码 29,793 字节，OEP RVA `0x154f`，输出 45,056 字节。该样本无独立 golden，本轮只验终止状态和严格 PE 结构。
- 产物等级 **dump-pe**，`runtimeVerified: false`。磁盘导入表、原资源目录及完整原 PE 布局尚未重建；影子 IAT 地址不是宿主地址。
- 单次 lbop20 仿真含解析/装载/输出验证约 166–216 ms；最终验收测试诊断 169.99 ms。35/35 PASS，0 跳过，整套约 1.93 s。环境：Windows、Node `v26.4.0`。时间受 JIT、GC、并行任务影响；步数确定。

## 2. 对 SDK 原始函数/反编译的核查

已通读 `generic-unpacker-claims.md`，并用 grep 复核下述磁盘产物，不仅引用先前报告。私有研究根：`资料/reverse/vmunpack-sdk/`。这些路径仅在研究文档中出现。

SDK SHA-256：`c389950e5612899dca926af3e228ef80046df10baa86693de9d748775903cdb8`。
`verification.json`：105,015 条文件映射指令、0 条未映射；13 次反编译、0 次失败，`passed: true`。

### 2.1 装载与 fuel

- `functions.tsv:103`：`FUN_100034c0`，VA `0x100034c0`，raw `0x34c0`，1,945 字节。
- `decompilation.txt:77-123`：MZ/PE/节表及地址溢出检查，`malloc(DAT_10070ad4 + 0x400)`，`FUN_1001c200` 装载影像。
- `decompilation.txt:142-218`：影子栈、自引用链、SEH 记录；这里是 SDK 的环境构造证据，不是本实现照搬的宿主栈。
- `decompilation.txt:229`：默认 fuel `30000000`。
- `FUN_10003f00`、`FUN_100040f0` 在推进解释器时递减 fuel；后者支持指定推进次数。

SDK 的 `DAT_*` 全局状态不能直接满足多实例并行。本实现把寄存器、FLAGS、栈、映像、写入位图、API 字典与预算归属到每个执行对象。

### 2.2 影子 API

- `functions.tsv:497`：`FUN_10037fa0`，VA `0x10037fa0`，raw `0x37fa0`，509 字节。
- `decompilation.txt:1417-1431` 与 `instructions.tsv:53814-53855`：真实 `kernel32.dll` 的模块获取、镜像复制、导出地址区间重定位。
- `decompilation.txt:1432-1449`：登记影子地址。这里实际可数 **18 项**：`GetProcAddress`、`VirtualProtect`、`VirtualAlloc`、`VirtualFree`、`LoadLibraryA`、`GetModuleHandleA`、`GetModuleFileNameA`、`CreateFileA`、`ReadFile`、`CloseHandle`、`CreateMutexA`、`GetCurrentProcessId`、`OpenProcess`、`VirtualProtectEx`、`CreateThread`、`GetExitCodeThread`、`VirtualFreeEx`、`LoadLibraryExA`。`GetModuleHandleA` 使用保存的 `pcVar3`，其余大部分用 `*_exref`。

本轮移植的是地址重定向/ABI 的架构语义，独立实现为符号 DLL 与调用门；不复制任何真实 DLL，不连接宿主 API，不照搬 SDK 反编译代码。

### 2.3 OEP 与交付：对原报告的精确化

- `functions.tsv:419`：`FUN_1002f000`，raw `0x2f000`，716 字节。
- `instructions.tsv:46964-46985`：先调 `FUN_10004580` 推进/定位候选，再在映像地址范围内读候选 DWORD；`0x1002f1a3` 掩码 `0x00ffffff`，`0x1002f1a9` 比较 `0x002464ff`，匹配后 `0x1002f1b6` 调 `FUN_100040f0(1)` 推进一步。
- `decompilation.txt:1338-1373`：此三字节检查是**已到候选阶段后的特定驱动分支**；不匹配时还有 dump/重建路径，不能称通用 OEP 签名。
- `decompilation.txt:1352,1363`：OEP RVA 写入 `param[9]`；交付回调实际由 `param[6]` 调用，参数包含状态、影像、大小及上下文。
- `SetOEPCallBack` raw `0x2f60` 为 `8b442404 a39c520710 c3`：保存回调到 `DAT_1007529c`。该全局回调在另一条推进路径 `FUN_10004930` 的 VA `0x100049ec` 调用；不要把两种回调混成同一处直接调用。
- `FUN_10004b20` raw `0x4b20` 实际仅 25 字节，VA `0x10004b30` 调 `FUN_1001be10`；它是重建入口包装器，单凭包装器不能宣称已经复原其内部完整 PE 修复算法。

SDK 受保护的 SuCop/VMProtect 解释器本体没有逐指令恢复。本轮 CPU 按 IA-32 指令语义原创，已验覆盖不能等同 SDK 的 125 个驱动覆盖。

## 3. 模块分工与执行

- `src/core/emulation/memory.js`：32 位有界映射、页级读/写/执行权限、小端访存、写入位图与内存/写入预算。
- `alu.js`：8/16/32 位整数运算与 CF/PF/AF/ZF/SF/OF；ADC/SBB 消费 CF，INC/DEC 保留 CF，shift/rotate 处理有效计数。
- `cpu.js`：独立寄存器、EIP/FLAGS、ModRM/SIB、指令取译执行、调用深度与 REP 元素 fuel。
- `win32.js`：每实例符号 DLL、影子地址、stdcall 调用门、错误码、分配及模块引用计数。
- `pe-loader.js`：装载头/节/BSS、栈、初始 IAT；生成 raw=RVA 的严格 PE dump。
- `profiles.js`：有界 UPX 终止 profile 与运行状态监视器。
- `limits.js`：只读政策与每次运行独立预算对象。
- `src/core/unpackers/emulated.js`：无全局可变执行状态的公共适配器。

```js
import { supportsEmulated, unpackEmulated } from './src/core/unpackers/emulated.js';

supportsEmulated(bytes, pe); // noexcept 初筛；不承诺每条指令/全部数据都可解释
const { bytes: output, metadata } = unpackEmulated(bytes, 'input.exe', {
  maxSteps: 10000000,
  maxMemory: 128 * 1024 * 1024,
  stackSize: 1024 * 1024,
});
```

产品无 DOM/Node 依赖。`Worker` 的创建/调度归调用端；并行实例不共享 CPU、memory、stack、API 或输出 buffer。
证明包含同一 JS realm 内两状态按 997 步交替推进，以及两个真正 `worker_threads` 同时处理不同输入。Worker 测试 fixture 为 `tests/fixtures/emulator-worker.js`，产品不引用它。

## 4. 已验证指令语义

32 位 ModRM/SIB 全部常见寻址形态：寄存器、绝对地址、无 base 的 SIB、比例 index、带符号 disp8、disp32。支持 8 位高寄存器及 `66` 操作数宽度覆盖。

已实现 MOV/MOVZX/MOVSX/LEA/XCHG、PUSH/POP/PUSHAD/POPAD、ADD/ADC/SUB/SBB/CMP/TEST/AND/OR/XOR/INC/DEC/NEG/NOT、全部 16 个 Jcc 短/近形式、JMP/CALL/RET、LOOP/LOOPE/LOOPNE/JECXZ、MOVS/CMPS/STOS/LODS/SCAS 及 REP/REPE/REPNE、SHL/SHR/SAR/ROL/ROR/RCL/RCR、IMUL/MUL/DIV/IDIV、BSWAP、CMOVcc/SETcc、LEAVE、CBW/CWDE/CWD/CDQ、有限 FLAGS 保存/恢复与 NOP。

REP 按元素执行，前向重叠复制保留真实逐元素语义，不用 `Uint8Array.set` 冒充 MOVS；每个元素消耗 fuel。count=0 不访问串内存。未定义的 FLAGS 位采用确定性保留/清理策略，不用它们作终止证据。

FS/GS、`67` 地址宽度、LOCK、FPU/SSE、RDTSC、INT/SEH 分发、特权指令及其他未实现 opcode 明确拒绝：

```js
AnalysisError('unsupported-opcode', {
  eip: 0x418b6a,
  opcode: '0f31',
  reason: 'opcode',
  steps: 6,
})
```

此错误来自真实入口首次位流 refill 的故障注入；测试逐字验证 EIP 与 `0f31`，不将未实现指令当 NOP。

## 5. UPX 停机证据

lbop20 实际入口 VA `0x418b50`；解码结束 VA `0x418c1a`；filter 退出 VA `0x418c4e`；POPAD VA `0x418cf6`；最终 JMP VA `0x418d04` → VA `0x401252`。

profile 仅在入口所在 raw 节的后续最多 2,048 字节中寻找唯一标记，检查源/目标区、映射与最后 rel32 跳转。运行时同时要求：

1. 实际执行 NRV EOF 条件分支，EAX 为 0；EDI 得到有界解码范围，该范围所有字节均由客体写过。
2. 实际抵达 filter 后的 import 阶段，ECX 已耗尽。
3. 执行已验证尾桩 POPAD，ESP 恢复到初始值。
4. 实际执行尾桩精确位置的 `E9`，目标为 profile OEP；清栈后 ESP 仍匹配、调用深度为 0、OEP 16 字节已写入。

最终跳转完成立即停机，不执行目标程序。`stopReason: 'verified-upx-tail-transfer'`。出目标节/进目标节的调用不构成 OEP，目标区子调用继续由 CPU 解释；孤立 `ff 64 24` 不构成任何通用终止条件。终止状态不满足、opcode 不支持或预算超限时抛错，不返回伪 dump。

UPX `0x26` filter 的 `SHR AX,8 / ROL EAX,16 / XCHG AH,AL / SUB / ADD` 及重定位循环均逐条解释执行。独立 golden 的代码段完全一致，包含 filter 和重定位修复后的字节。

## 6. 影子 API 与 ABI 边界

本实现 21 个调用门，仅识别 `kernel32.dll` / `kernelbase.dll` 中的名称：

- `LoadLibraryA/W`、`LoadLibraryExA/W`、`GetModuleHandleA/W`、`GetProcAddress`、`FreeLibrary`。
- `VirtualProtect`、`VirtualAlloc`、`VirtualFree`、`FlushInstructionCache`。
- `GetCurrentProcess`、`GetCurrentProcessId`、`GetCurrentThreadId`、`IsDebuggerPresent`。
- `GetLastError`、`SetLastError`、`SetErrorMode`、`GetModuleFileNameA/W`。

所有门读 `[ESP+4...]` 实参，EAX 返回，弹出返回地址并清理 `argc*4` 字节；调用者额外压入的保护值暂存不被清掉。VirtualProtect 回写旧 PAGE 权限；VirtualAlloc 只支持 commit 或 reserve+commit，释放只支持 `MEM_RELEASE`；reserve-only/decommit、特殊 LoadLibraryEx flags 等明确 `unsupported-api-operation`。

GetProcAddress 的**符号登记**与函数执行分开：目标程序导入名/ordinal 得到独立影子 token，metadata 标注 `implemented: false`；未知门被实际 CALL/JMP 时立即 `unsupported-api`，包含 dll/api/eip。因此能记录 lbop20 的 64 个目标导入，而不假装实现 CRT、文件、线程或 USER32 API。

lbop20 实际调用：LoadLibraryA 2 次、GetProcAddress 64 次、VirtualProtect 2 次，共 68 次。SDK 中的文件/进程/线程 API 没有在本模块实现。

符号地址区间：DLL handle 从 `0xe0000000`、调用门从 `0xf0000000` 分配。它们不是真实 DLL 映像，没有可读取的 kernel32 导出目录；手工遍历 PEB/导出表的 stub 不在支持范围。

## 7. 资源预算

| 参数 | 默认 | 硬上限 |
| --- | ---: | ---: |
| maxInput | 64 MiB | 64 MiB |
| maxOutput | 128 MiB | 128 MiB |
| maxMemory | 128 MiB | 256 MiB |
| stackSize | 1 MiB | 8 MiB |
| maxSteps | 10,000,000 | 100,000,000 |
| maxWriteBytes | 256 MiB | 1 GiB |
| maxApiEntries | 4,096 | 16,384 |
| maxApiCalls | 16,384 | 65,536 |

预算均要求正的安全整数；stackSize 至少 256 字节且 16 字节对齐。内存预算计 guest buffer、权限页与写入位图；API 名累计最多 1 MiB、DLL handle 最多 256、映射 region 最多 1,024。输出另受 maxOutput 约束。JS 对象/GC 开销不等于 guest byte 计数，但由上述实体数量上限约束。

lbop20：guest 分配及位图/权限共 1,168,666 字节，累计写入 120,879 字节。steps 包括 shadow dispatch，REP 的每个元素计一次；不是单纯硬件 retired-instruction 计数。失败代码含 `emulation-step-limit`、`emulation-memory-limit`、`emulation-stack-limit`、`emulation-write-limit`、`emulation-output-limit`、`emulation-api-limit`、`emulation-api-call-limit`。

## 8. 输出与独立判据

装载头及所有 raw 节到 RVA，BSS 初始化为零。仅对已观察的三节 UPX `SizeOfHeaders=0x1000 / first raw=0x400` 约定使用本模块的精确适配器。普通共享 `parsePE` 继续严格解析。

dump 保持各节 RVA，rawOffset=RVA；重建 rawSize/virtualSize/节表，写入 OEP，清 checksum/COFF 原磁盘记录及未重建目录，固定 image base。输出必须通过 `parsePE(output, maxOutput)` 且没有 warning、没有 unmapped EP/节重叠。

metadata 明确 `importsRebuilt: false`、`resourcesRebuilt: false`；warning 含 `imports-not-rebuilt`、`resources-not-rebuilt`、`symbolic-iat-addresses`、`unrestored-metadata-cleared`、`fixed-image-base`、`runtime-not-verified`。资源字节仍可在原影像区分析，但不承诺原资源目录/原始磁盘布局已修复。

独立 UPX fixture 来源均为 unipacker revision `160baa9447c91d53b75e5e108b196d389fa0b06e`，路径与 SHA 在 `test-results/fixtures/upx/manifest.json`；测试直接核哈希：

- `lbop20.upx.bin`：`e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158`。
- `lbop20.golden.bin`：`5b8cc03b22d3bf8d00e600300ece15359dc10148d474f988b643c5ae863d0163`。
- `lab18-01.upx.bin`：`2ac6635a26049d354c0c46243f6451e6594b130745a08c5a99e96a64fbbbec0f`。

99.73046875% 的分母为输出三个节的完整 102,400 字节，包含客体映像原有填充；不包含独立 golden 后来追加的约 68 KiB 导入重建区域。另设独立代码段 100% 断言，防止只靠大量零填充通过。测试还把 golden 的 raw offsets 整体平移 `0x200`，证明比较函数用实际节表 RVA 映射而非碰巧 raw=RVA。

## 9. FSG 尝试：研究推进，不宣称支持

实际核过本地 FSG 1.31 / 1.33 / Lab18-02 fixture。当前产品 loader/profile 都拒绝：1.31 有 overstated headers、TLS 及缺失 EXECUTE 节标志；1.33 PE header 位于 `0x0c` 且有 TLS；Lab18-02 不是当前 vetted 1.31/1.33 布局。

额外用 `parseFsgPE` **只读解析工具**装载两份样本做 CPU 覆盖探针：每次独立 Memory/CPU，最多 10,000,000 steps；研究探针把影像页临时标 RWX、跳过初始 IAT/TLS，以定位解码指令是否受支持。它不是产品 loader，也不返回产品产物。

- 1.31：4,482,533 steps 后在 `EIP=0x195` 遇 execute memory fault，约 546 ms。
- 1.33：4,482,355 steps 后在 `EIP=0x161` 遇 execute memory fault，约 583 ms。
- 各写过 300,475 个独立影像字节；目的节按 golden 的 raw/RVA 映射相同 326,297 / 327,680 = 99.57794189453125%，此数包含零填充，仅作指令覆盖研究证据。
- 故障落在未绑定的原始 IAT RVA 调用地址；没有验证完整 IAT/TLS/OEP 收尾，产品 `supportsEmulated` 对三份 FSG 均为 false，`unpackEmulated` 拒绝。FSG 2.0 未测。

## 10. 接入回执

公共函数：`supportsEmulated(bytes, pe?)`、`unpackEmulated(bytes, name, options={})`；metadata 模板 `EMULATED_ENGINE`。注册 id `emulated-pe32`，route/mode `emulated`，architecture `x86`，family/catalog 目前 UPX，outputKind `dump-pe`，experimental。

M 接入注意现有 `engines.js` 的 `define` 会固定覆盖 mode 为 `static-js`，需采用 metadata 指定的 mode。UPX 同时能被既有静态引擎与仿真引擎识别，自动选择需保留既有优先级/显式 route，避免触发 `ambiguous-engine`。本模块初筛会重新核 bytes，允许主线已带 `upx-sizeofheaders-normalized` warning 的 cached PE 提示，但不依赖它放宽自己的验证。

验证命令：

```powershell
node --test tests/emulator.test.js
```

35/35 PASS，0 skipped；覆盖指令、API ABI、真实黄金字节、raw/RVA 差异、同 realm 交替实例、真正双 Worker、输入/输出所有权、预算超限与 unsupported 拒绝。终止负例包含真正解释执行的目标区 CALL/RET 与 `ff 64 24` 间接 JMP。全量测试和共享接入由 M 统一安排。

验收代码/只读依赖 SHA-256（文档自身不纳入自引用哈希）：

| 文件 | SHA-256 |
| --- | --- |
| `src/core/bytes.js` | `048848d5aa79298e330183b9d21b9b520c09baffe917ea79d0332e3a71eab854` |
| `src/core/pe.js` | `1d7fb9770924c42f7793af570306c28402ce7f7447c67150e2e70ed0fe1447f1` |
| `src/core/errors.js` | `c69409dfbe9b499b1f437fa717a2ee04a116b15a99a4adc60aa55d15097bf5bf` |
| `src/core/emulation/limits.js` | `2cfcffa648b80d132ab81823ed294eca07acb2f14b7ddfb005fc5b37ae1f4427` |
| `src/core/emulation/memory.js` | `77cd8fe704da278df86457dd68258a81e3534ca2027f252d493f9b0682183844` |
| `src/core/emulation/alu.js` | `a8fa653e0758972c47ef8b33fb42d789a6614fdcbf385744578f6e2f6c87c497` |
| `src/core/emulation/cpu.js` | `548c76db49b51b40debf6326950663eedd0bd4c1ab967bf53b62c95adf1ba062` |
| `src/core/emulation/win32.js` | `4ea7245617bfd4d138c77a223bb4838e9cae9c14925d1b27f08b8aaabbfa81d7` |
| `src/core/emulation/pe-loader.js` | `d583e9ce37751f70da7d79f1ce7d8324600f8948f36b46e44db64ff596421de1` |
| `src/core/emulation/profiles.js` | `597414431b6361a1685f0bffe82949cdacc6391483ba707dfdb8c5bc772d1a6b` |
| `src/core/unpackers/emulated.js` | `405e276d07f6cfd6c8effb2bc97391d502d29d31d6dde42d302282d71d76ea90` |
| `tests/emulator.test.js` | `96bad4a155fee444a15613c9fbcda7235c94356f68a506e443af80791d3e1dae` |
| `tests/fixtures/emulator-worker.js` | `347287e7e37abbcaae93c980dd8a70aa308f3e8b081a9ed3ae3df655d36f5b00` |

限制：PE32 x86 EXE、常规 `0x200/0x1000` 对齐、image base 下方地址空间；TLS/delay import/PE32+/DLL/.NET、未知尾桩、复杂保护壳与 kernel32/PEB 导出遍历不支持。仿真不是通用 Windows 环境，候选不承诺完整可运行 PE 重建或 SDK 全驱动覆盖。
