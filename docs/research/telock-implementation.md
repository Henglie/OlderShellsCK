# tElock 0.9x 引擎实现记录（T41 / F9）

日期：2026-10-08。执行：F9 @T41。前置：MT27（L1/L2，`资料/reverse/mt27-research`）、
MT29（L3/L4 + loader 核心定位，`资料/reverse/mt29-telock`，见 docs/research/rlde-family.md §8/§8a）。
本文与 `src/core/unpackers/telock.js`、`tests/telock.test.js` 配套。

## 1. 样本挖掘结论（无加壳目标样本）

- `rg --files 资料 | rg -i telock` 命中三类：①工具本体 `资料/老旧壳脱壳工具/tElock脱壳机.exe`
  （578016 字节，SHA-256 `3c70bf02…889b2`）；②MT27/MT29 研究产物（layer2/after-L3-only/layer3
  三个 golden 镜像 + trace/chase）；③CoolDumpper 的 `telock.dll` 插件（脱壳插件非样本）。
- `资料/reverse/rlde-telock/target.exe` 与 `资料/reverse/mt27-rlde-telock/target.exe` 经哈希核对
  **与工具本体同文件**（`3c70bf02…`）——Ghidra 工程的研究对象就是工具自身。
- `test-results/fixtures/` 无 tElock 条目；`test-results/dynamic/` 全部 exe/bin 对 L3/L4 六常量
  （`fd03cb06`/`43cbbce4`/`6da5154d`/`0255b802`/`2a325f19`/`36c24bde`）零命中。
- 260 工具目录内无 tElock 加壳器（仅有脱壳机与 telock.dll 插件），无法离线生成加壳样本。
- **结论**：库内唯一 tElock 包体是脱壳机工具自身。它是合法的层变换验证素材（真实 tElock 0.9x
  包裹），但不构成"第三方加壳目标样本 + golden"——按红线不虚标，引擎 supports 恒 false。

## 2. 交付物

`src/core/unpackers/telock.js`：

- `TELOCK_ENGINE`（id `telock-pe32`，`outputKind: 'none'`，`runtimeVerified: false`）；
  `TELOCK_ENGINE_BOUNDARY` 四条诚实边界（supports/layers/codec/loader）。
- `TELOCK_WRAPPER_LAYERS`：四层描述符（入口/首址/写数/窗口/变换键），窗口下沿定律入表
  （L1→L2→L3 下沿=下层入口，L3→L4 为强推断，L4 尾 0x436451 为 chase halt 点非层入口）。
- `transformTelockDword` / `applyTelockWrapperLayer(s)`：L1 `((w+0x1c7081e5)^0x7f9944ba^0x690f1f6b)`、
  L2 `((w^0x1609a670^0x7d722de9)-0x5ed0ba6e)`、L3 `(w+0xfd03cb06)`、
  L4 `((w+0x43cbbce4)^0x6da5154d)+0x0255b802`（皆 mod 2^32，VA 自 firstVa 每轮 −4）。
- `decompressTelockAplib`：aPLib 族位流解码器（文法见 §3，防御模式同 fsg codec：
  输入/输出上限、truncated、gamma 溢出、back-reference 越界、终止记账）。
- `supportsTelock` 恒 `false`；`unpackTelock` 恒拒 `telock-no-target-sample`。

## 3. 解码器文法（T41 新恢复，原创静态分析）

新证据：0x436624 解码器落在 L4 写窗 [0x43644b..0x436973] 内 → 其代码在
`telock-layer3.bin`（解密态 golden）中可反汇编。工具：`资料/reverse/t41-telock/disas-decoder.py`
（Capstone 静态反汇编，不运行任何目标代码；事实来源为 MT29 已验证镜像）。

文法（MSB-first 位流；`mov dl,0x80` 桶 + `add dl,dl/jne/adc dl,dl` 位读，判定序列=字节
b7..b0 连续流；literal/offset/终止字节为 esi 顺序整字节读，与位桶交错——同 fsg codec 结构）：

- 首字节：无条件 literal（0x436632 直落）。
- `0` → literal。
- `10` → gamma 匹配族（0x436698）：gamma 值 g₁
  - `g₁==2`（0x4366b6）→ 重复距离：offset=ebp（上次 offset），len=gamma₂；
  - `g₁>=3`（0x4366e0）→ 新偏移 `offset=(g₁-3)*256+byte`，ebp 更新，len=gamma₃+增量；
    增量表（0x436704-0x436727）：`offset<=0x7f`→+2；`0x500<=offset<0x7d00`→+1；
    `offset>=0x7d00`→+2；其余 +0。
- `110` → 短匹配/终止（0x436735）：byte b；`b>>1==0` → 终止（0x436751 收尾，返回值藏
  pushal 的 eax 槽，`ret 8` stdcall(src,dst)=输出字节数）；否则 offset=`b>>1`，ebp 更新，
  len=`2+(b&1)`。
- `111`+4bit → （0x43664e-0x436689）nibble==0 → literal 0x00；否则 offset=nibble、len=1。

与 fsg codec（`src/core/codecs/fsg.js`，XStaticUnpacker MIT）同族差异：tElock **无
literalState 修正**（FSG 长匹配 `(gamma-2-literalState)*256+byte` 带 literal 后置 1/匹配
后置 0 状态，tElock 恒 `(gamma-3)*256+byte`），其余（首 literal/终止字节语义/增量表/4bit
分支）逐项同形。本实现按 tElock 实例独立编写，未复制任何反编译文本。

## 4. 测试（tests/telock.test.js，node --test 8/8 过）

1. **真实链 golden 闭环**：工具本体 → L1..L4 逐级复放，四级 SHA-256 锚点
   （`73eb373a…`/`e3df4acb…`/`ef1423e0…`/`ff7e93f1…`）+ L2/L3/L4 与三个 golden 镜像
   **逐字节**相等。
2. **层表自洽**：窗口/计数数学关系、下沿链 L1→L2→L3、L4 halt 记录、offset 映射边界。
3. **已知密钥往返**：L1..L4 变换 u32 双射（合成字 + 工具镜像真实首字，测试本地逆变换）。
4. **aPLib 向量**：literal/短匹配/4bit/终止/重复距离/gamma 长匹配/增量表五区间
   （0x7f/0x80/0x500/0x7cff/0x7d00）合成流精确输出与 consumed 记账；
   malformed 六路拒绝（previous 未建、offset 0、越界、无终止、gamma 溢出、output 上限）
   + 类型/上限拒绝。
5. **引擎语义**：supportsTelock 对工具本体输入仍恒 false；unpackTelock 拒绝码。

## 5. 诚实边界（差距）

- **无 tElock 加壳目标样本**：层变换与解码器文法均以工具本体镜像为唯一真实证据；
  引擎 supports 恒 false、unpack 恒拒，样本 + golden 到位前不注册产品路径。
- **解码器流级验证缺口**：文法自静态反汇编恢复，但 tElock payload 压缩流本身运行时
  才产生（VirtualAlloc 目标 + 运行时 API 槽），库内无流可测——`decompressTelockAplib`
  仅合成向量验证，**未对过任何真实 tElock 流**。research-signatures.js（T48）对加壳
  输出是否携带明文六常量的 boundary 同样适用此处。
- **L4 之后静态阻塞**（MT29 结论维持）：pushal 运行时寄存器、kernel32 回走种子
  `[esp+0x24]`、运行时导出解析 API 槽、SEH 驱动流——需 emulated-pe32 仿真路线（P1）。
- **接入行**（M 独占注册，样本到位后启用）：
  `src/server/engines-server.js` 加
  `import { TELOCK_ENGINE, unpackTelock, supportsTelock } from '../core/unpackers/telock.js';`
  与 `registerServerEngine({ metadata: TELOCK_ENGINE, supports: supportsTelock, unpack: unpackTelock });`
  ——当前 supports 恒 false，接线后行为不变，仅为收口导出面。

## 6. 产物清单

- `src/core/unpackers/telock.js`（新，产品）
- `tests/telock.test.js`（新，8/8）
- `资料/reverse/t41-telock/disas-decoder.py`（新，反汇编工具）
- `docs/research/telock-implementation.md`（本文）
