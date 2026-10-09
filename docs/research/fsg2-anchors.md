# FSG 2.0 静态锚定研究卡（T40）

日期：2026-10-09；执行者 F10。状态：**研究卡止步——全库无 FSG 2.0 实样**，按卡规不建 fsg2.js 引擎、不虚标支持。证据全部来自 RL!deFSG 2.0 驱动反编译（MT29，`资料/reverse/mt29-rlde-fsg*`）与我们已验的 1.x fixtures（fsg.js，只读参考）。

## 0. 结论速览

| 项 | 状态 |
|---|---|
| FSG 2.0 实样 | **无**（全库字节级扫描 0 阳性，§2） |
| fsg2.js / tests | **不建**（无样本，拒绝猜测布局） |
| 检测签名 | 已有 T48 落地（research-signatures.js FSG 2.0 条目）；升级建议见 §5 |
| 静态化 OEP | 路径论证完成（§4），三路分级，全部待样本激活 |

## 1. 证据基线与 SHA pin

| 文件 | 字节 | SHA-256 | 角色 |
|---|---:|---|---|
| `资料/老旧壳脱壳工具/万用脱壳机 RL!deFSG 2.0.exe` | 135733 | `6e90e98d7d83a6db8a53de06a2e460eb120f712bcabdb208677cc9fe7900533b` | 驱动外层原件（本轮 Get-FileHash 复核 = archive-inventory.json 一致） |
| `资料/reverse/mt29-rlde-fsg/rlde-fsg--RL!deFSG 2.0.exe` | 10240 | `f4307f224ea3cfa4420dc17b9915e0a403ddb202bd69d57025a7c704dfb60a5d` | wrapper 内层驱动（本轮复核 = mt29 README 一致） |
| `资料/reverse/mt29-rlde-fsg/` Debugger/Dumper/Importer.dll | — | 见 rlde-family.md §2 表 | 家族共用库（三哈希与 ASPack/MEW/NsPack 全同） |
| `test-results/fixtures/fsg/fsg131.bin` / `fsg133.bin` / `lab18-02.bin` | — | 见 fixtures/fsg/manifest.json | 1.31/1.33 已 pin；lab18-02 更早代（MT8 遗留） |

Ghidra case `mt29-rlde-fsg-engine`：712 指令、92 直接 CALL 逐字节验证、21 反编译 0 失败（MT29 verify.py 全过，本轮未重跑）。原工具与全部成员**从未运行**。

## 2. 样本挖掘（任务①）：无实样

方法：`资料/reverse/t40-fsg2/scan-samples.py`（只读扫描，不执行任何目标）对 `资料/` 与 `test-results/` 全部文件做字节级检索，判别锚取驱动扫描器自己的探针 dword `ff 63 0c 50`；对 PE 命中再按驱动语义检查 EP 映射窗口 200 字节内 `ad 50` 共现。报告：`t40-fsg2/scan-report.json`。

结果：**3 命中、0 样本**——

| 命中 | 偏移 | 判定 |
|---|---:|---|
| `mt29-rlde-fsg/rlde-fsg--RL!deFSG 2.0.exe` | 0xd6d | 驱动自身扫描器代码里的立即数 `0x500c63ff`（自命中，.text 内、EP 窗口外） |
| `mt29-rlde-fsg-engine/.../db.2.gbf`、`db.3.gbf` | 0x12bc3b | Ghidra 项目缓存里的同一工具字节 |

旁证：`资料/archive-inventory.json` 中 FSG 相关条目只有工具（UnFSG1.33、CoolDumpper fsg.dll、RL!deFSG 2.0），无加壳样本；UnFSG.exe 版本串止于 `FSG v1.33 (Eng) -> dulek/xt`。unipacker corpus 仅 1.31/1.33/lab18-02。**→ 研究卡为止，引擎等样本。**

## 3. 锚定清单（1.x ↔ 2.0 对照）

强度分级：**[字节实证]** 原件/fixture 字节或反汇编直接可见；**[控制流]** 反编译控制流可追但值运行时产生；**[推断]** 家族先例外推，无 2.0 直接证据。

### 3.1 检测锚

| # | 锚 | 强度 | 证据 |
|---|---|---|---|
| D1 | dword `ff 63 0c 50` = `JMP [EBX+0xC]; PUSH EAX`（2.0 尾跳+后继指令） | 驱动侧[字节实证] / 样本侧阴性[字节实证] | 驱动 00401902 以立即数 `0x500c63ff` 扫描（decompilation.txt:542）；1.31/1.33/lab18-02 三 fixture 全阴性（§2） |
| D2 | word `ad 50` = `LODSD; PUSH EAX`（导入名循环） | [字节实证]，但**家族共享非 2.0 独有** | 驱动以 `0x50ad` 扫描（00401902，decompilation.txt:532）；1.33 stub 内 EP+0x7d/EP+0x9b 两处阳性（本轮 node 验证，均在驱动 200 字节窗口内）；1.31 stub 窗口内阴性（其导入循环为 `47 8b 37 af 57` mov 形态，无 LODSD） |
| D3 | 双探针各自独立扫描：EP 映射起点、字节步进、各限 200 次迭代 | [控制流→字节实证]（循环结构反编译可见；窗口锚定 EP 为 DAT_004033c4 基址语义） | 00401902 两个 `for(iVar3=200;...)` 循环，`(int)piVar2+1` 字节步进 |
| D4 | 布点：BP1=探针1命中+1（落在 `50`）；BP3=探针2命中（`ff`）；BP2=命中+3（落在 `50`） | [字节实证] | 00401902 尾部三赋值 `DAT_00403ae4/+3/DAT_00403aec`；00401179 三次 SetBPX（BP3 mode=1 一次性） |

**判别结论**：D1 是唯一已证的 2.0 独有锚（1.x 三代样本阴性）；D2 单独出现不能判 2.0（1.33 同窗口内就有）。

### 3.2 OEP 机制锚（任务核心）

| # | 锚 | 强度 | 证据 |
|---|---|---|---|
| O1 | 1.x 尾跳 = `JE rel32`（`0f 84`），静态位移可直读：OEP = EP+je+6+i32(EP+je+2)，je=161(1.33)/218(1.31) | [字节实证] | fsg.js STUB_133/STUB_131 已双 fixture golden 验证（只读参考，本轮未改） |
| O2 | 2.0 尾跳 = `JMP [EBX+0xC]`（`ff 63 0c`）间接槽 | 驱动侧[字节实证] | D1 探针字节本身 |
| O3 | 2.0 OEP = dword **[EBX+0xC]**，与尾跳操作数同槽 | [字节实证]（驱动读法） | 004012d3：`uStack_24=2`（Debugger.dll 寄存器编号 2=EBX，rlde-family.md §3）→ GetContextData 返回值 +0xC 处 ReadProcessMemory 取 OEP（decompilation.txt:86-91），日志格式串 `OEP_Jump_BPX__>__08X` |
| O4 | 2.0 OEP 槽是**运行时值**：EBX 内容由目标进程执行产生，磁盘上未必有静态对应 | [控制流] | 驱动必须借调试上下文取 EBX，不能像 RL!deUPX 那样 `e9+rel32+5` 纯静态算出（对照 mt29-rlde-upx） |

### 3.3 导入流锚

| # | 锚 | 强度 | 证据 |
|---|---|---|---|
| I1 | 导入名读取点 = BP1（DLL 名，`LoadLibrary BPX > %s`）与 BP2（API 名/序号，`GetProcAddress BPX > %s`），各 RPM 100 字节 | [字节实证]（驱动侧） | 004011fc / 0040125b + strings.tsv |
| I2 | 导入重建 = 原位 IAT 槽保留（Importer.dll 语义：FirstThunk 记原槽、不连续拆同名描述符） | [字节实证]（家族库） | rlde-family.md §3；MT29 §13a ASPack 交叉（GUI 动态收集 ↔ aspack.js 磁盘 ILT 双路线同收敛） |
| I3 | 2.0 磁盘导入流编码形态（1.33=节列表 0 终止+末流 aPLib blob；1.31=word-list 唯一 1 记录；2.0=?） | **[推断]，开放** | 家族内已见两种形态分歧；无 2.0 样本，不得假设沿用哪一种 |

### 3.4 布局与解码器锚

| # | 锚 | 强度 | 证据 |
|---|---|---|---|
| L1 | 1.x 布局：两节（dest rawSize=0 + source）、support 表在 header slack、aPLib 族流序列、资源不压缩居于 source 头部、e_lfanew=0x0c(1.33) | [字节实证]（1.x） | fsg.js readHeaders/inspect（只读） |
| L2 | 2.0 布局 | **[推断]，未知** | 驱动只扫 EP 窗口，不揭示节布局；无样本 |
| L3 | 解码器：家族 aPLib 族（fsg.js codec，1.31/1.33 双 variant）；2.0 大概率同族变体 | **[推断]** | RL!deFSG 无自有 codec（解压由目标进程执行，同 RL!de 全系）；aPLib 是 FSG 家族连续两代实证编码 |
| L4 | 2.0 产物修复链（原 GUI）：DumpProcess → 节/头修正（00401744）→ 追加 `.ap0x` 节（004013ad 写 `.`,`a`,`p`,`0`,`x` 五字节）→ ImporterExportIAT | [字节实证]（驱动侧） | decompilation.txt:102-106、338-359 |

## 4. OEP=[EBX+0xC] 静态化路径论证（任务②）

槽位是运行时值（O4），静态化三路，按可行性排序：

1. **EP 窗口内 EBX 回切（bounded back-slice）**——首选。驱动双探针保证尾跳现场在 EP+200 映射窗口内（D3），即 stub 自包含窗口。在该窗口内对 `ff 63 0c` 前的 EBX 来源做受限回切：若为 `mov ebx,imm32` / `lea ebx,[imm32]` / 可建模栈流（`push imm32 … pop ebx`），槽位地址即静态可解，再验 `dword[VA+0xC]` 落原代码节范围。可行性先例：`mt29-telock/chase.py` 受限文法执行器已证明此窗口级追踪可闭环（19162 步）；FSG 文法更窄（无 SEH、无多层数值变换的现有证据）。**风险**：EBX 可能由解压后数据填充（tElock 运行时 API 槽静态读全 0 的同类实证，rlde-family.md §8a）→ 回切会在数据依赖处停机，如实降级。
2. **解压后重扫**——次选，依赖 L2/L3 先行。若 2.0 同族 aPLib 且布局锚定成功，先静态解出全部流，再在解压映像内找「值落入原代码节且与尾跳槽位地址一致」的 dword。本质上是用解码结果替代运行时填充。
3. **tElock 窗口下沿定律类比**——**不适用**，如实记录：tElock 定律是「下一层入口=本层最低写入地址」，依赖多层数值解码结构；FSG 2.0 无此结构，可类比的仅是「运行时槽需静态重扫」这一问题类，而非可复用的定律。真正的家族内静态先例是 RL!deUPX 的 `e9+rel32+5`——但那靠 rel32 直读，恰是 2.0 间接槽所缺。

**兜底已存在**：MT22/MT33 的 FSG auto-oep 动态 dump（dump_oep.py 绝对区间+Eip≥image_base）不依赖 [EBX+0xC] 语义，真机路径已通（late dump 实证）；静态化仅提升免运行能力，不阻塞用户可用性。

## 5. 检测签名建议（给 T48 后续，本卡未改 research-signatures.js）

现状（T48 已落地，src/core/research-signatures.js:31-37）：`required:['ad50','ff630c50'], minHits:2, mode:'file-scan'`，boundary 已诚实标注无样本未验磁盘命中。

建议升级（按 §3 证据强度）：

1. **主判据换成 D1 单锚 + EP 窗口约束**：`ff 63 0c 50` 限定在 EP 映射起点后 200 字节内（驱动语义 D3）。全文件 file-scan 有实证误报——RL!de 工具自身 0xd6d 即自命中（§2）；`ad50` 在 1.33 样本窗口内也阳性，作共现门无增量特异性（D2）。
2. 辅助门（**样本验证前不上线**，标注推断）：FSG 家族布局特征——两节、首节 rawSize=0、EP 落第二节内（L1，1.x 双样本字节实证；2.0 未证）。
3. 保持 boundary 注记，等首个 2.0 样本做磁盘命中率回填（HUMAN-5 范畴）。

## 6. 诚实边界

- 无 FSG 2.0 样本/golden：本卡全部 2.0 侧结论来自脱壳器驱动反编译，是**工具期望的 stub 形态**，不排除真实 2.0 build 存在变体（家族内 1.31↔1.33 的导入流分歧 I3 即先例）。
- 未运行任何目标/工具；未修改 fsg.js、research-signatures.js、多Agent协作.md。
- 引擎判据按卡面：无样本不虚标引擎完成。首个 2.0 样本到位后的实施顺序：§4.1 回切 → §3.4 布局锚定 → §4.2 重扫 → fsg2.js 照 fsg.js 结构（narrow-stub，分级如实）。

## 7. 交付物

- 本文档（独占）。
- `资料/reverse/t40-fsg2/scan-samples.py`（只读扫描器）+ `scan-report.json`（全库 0 阳性报告，UTF-8）。
- 无 fsg2.js / tests/fsg2.test.js（无样本，按卡面可不交）。
