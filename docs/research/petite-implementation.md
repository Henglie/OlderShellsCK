# Petite 2.2 静态解包实现（T43）

状态：已实现并验证（单样本），`src/core/unpackers/petite.js`。
引擎 `petite-22-pe32`：Petite 2.2 levels 1-9、PE32 EXE、输出 `rebuilt-pe`、`runtimeVerified: false`。

## 1. 样本结论

资料库内无「Petite 加壳的目标程序」独立样本，但存在一个等价实样：
**UnPETite 的 ENLARGE.EXE（r!sc v1.3，2000-08-06，11264 字节）本体就是 Petite 2.2 加壳的 PE**。

- SHA-256 `ed3d6a0a80dd6b1fb52b51b04b73f0106c5b929a6a5d65d4f35593eaac7d346a`
  （`资料/reverse/t43-petite/ENLARGE.EXE` 与 `资料/老旧壳脱壳工具/UnPETite/ENLARGE.EXE` 逐字节一致）。
- 壳布局：3 节（原第一节的虚拟骨架 rva 0x1000 vsz 0x22000 / `.petite` 资源节 rva 0x23000 / 尾节 rva 0x24000），
  EP RVA 0x24042，DIE 上游 `packer_Petite.2.sg` 的 2.2 分支（`B8????????68????????64FF35????????648925????????669C6050`）命中。
- 2.2 levels-1..9 版本锚：`[EP-0x42+0x68] == 0x080C78166`（2.1 为 `[+0x6B] == 0xBA0F0A8B`，本引擎拒绝）。

其他 Petite 相关材料（`资料/老旧壳脱壳工具/CoolDumpper/plugin/petite.dll` 插件、UnPETite 源码 ZIP 提取件
`资料/reverse/petite/source/*.asm`）为工具/文档，非加壳样本。`petite.asm/l0/l1_to_9` 是 r!sc 工具自身的
反汇编记录（许可未知），仅作算法对照，全部留在 `资料/`，不进 Apache 代码。

## 2. 算法要点（以实拆为准）

### 2.1 头部与预种子（pet22 init，EP 前序）

EP 前序：`mov eax, tailBase; push layer2Va; push fs:[0]; mov fs:[0], esp; pushad; push vmem`，
随后把 `.petite` 尾节里两张表拷进虚拟头区 0x780/0x7E8：

- thunk 指针块：src = tail + `[tail]` + 8，长度 dword 数 = byte `[tail+0x83]`（6 个）→ vmem+0x780；
- 库名块：src2 = src1 + n1*4 + `[tail+0x9c]` - 8，dword 数 = byte `[tail+0x81]`（10 个）→ vmem+0x7E8。

### 2.2 数据表（packer data，tail+0x1B8）

- 12 字节 move 记录：`{0x80000000|n, srcEnd, dstEnd}`；
- 16 字节 block 记录：`{compRva, size, dstRva, flag}`，size==0 只占位不解码；
- 首 dword 0 终止（静态语义）。

**move 语义（本卡关键发现）**：真实 stub 用 `std; rep movsd`，esi/edi 指向的是**首个（最高）dword 的含端位置**——
先存 `[edi]` 再递减。n 个 dword 落在 `[dstEnd-4(n-1) .. dstEnd]`（含端）。若按“排他端点”字节倒拷会整体低移
4 字节，丢失流尾 2 字节（本样块 3 的 "4b 20"），末 token 解码错一字节（"FileNameA" 变 "FileNamfA"）。

**终止符后的“头块”是 SEH 弹床而非数据**：表 null 项之后 `{0, 0xb0a, 0, 0}` 在运行期会被 stub 当 block
解压到 RVA 0——首个写即触发读保护页异常 → SEH → layer2 接管并跳 OEP，解码内容从不使用（静态强解为乱码，
ebx 越界 -4680，已证伪“原始头压缩块”假设）。r!sc 工具同样在 null 处停走。

### 2.3 levels 1-9 块解码器

- 位读取器（stub 0x4240EC）：`add dl,dl / jnz ret / mov dl,[esi] / sub esi,-1 / adc dl,dl / ret`——
  MSB 优先、每字节恰 8 数据位，`sub esi,-1` 的恒 1 进位即哨兵位，从不当数据位返回。
  已用项目基座 CPU（MT25 验证过的 x86 仿真）跑真实指令序列 40 次调用逐位对拍，与本引擎 JS 转写一致。
- 首 token 前无条件 `movsb` 原样拷贝首字节（无 XOR），ecx 清零。
- 字面量：type bit 0；`movsb` 后 `xor [edi-1], bl`，**key = 剩余计数的低字节（自减前）**。
- 匹配：type bit 1；gamma 码（种子 1，do-while 倍增）：
  - gamma>=3：新偏移 `eax = ~((gamma-3)<<dh | dhbits)`（负距离），ebp += 1 + (eax<t1) + (eax<t2)；
    阈值按 outSize 分档：<0x10000 → dh=5, t1=0xFFFFFC60, t2=0xFFFFC060；<0x40000 → dh=7, t1=0xFFFFF980,
    t2=0xFFFF8180；否则 dh=8, t1=0xFFFFFB00, t2=0xFFFF8300。距离远于 0x3A0/0x3FA0 各加 1 拷贝长。
  - gamma==2：复用上次偏移（gamma==1 是非法流，引擎按上限拒绝）。
- 长度：2 bit；0 则再 gamma 并 +2（gamma 路径最小长 4）；总长 = len + ebp。
- 计数为**有符号**：可负收尾（末块设计性越界，运行期借 jle 出口跳 SEH 弹床）。

### 2.4 fix_offsets（解码后处理）

按 block flag：bit0=1 → 扫描段内 E8/E9（`sub [rel32+1], scanPos`）与 0F 80-8F（`sub [rel32+2], scanPos`）
重定向相对引用；bit0=0 → 以 `4*(flag>>3) + ((flag>>1)&3)` 字节零填 [dst+size) 之后的尾部
（本样四段全部与相邻块边界吻合：0xCBE/0x1C8AB/0xE14/0x1000）。

### 2.5 layer2 字段与 OEP 解密

layer2 基址 = `[tail+0x48] - imageBase`（0x4400）。字段（2.2 l19 布局）：
`[+0xf]` 加密 EP、`[+0x121]` 导入描述符 RVA、`[+0x1c0]` 混淆标志（0x90909090=无混淆）、
`[+0xa8]` CRC 尺寸、byte `[+0xd0]` ROL 位数。

1. CRC：对 `[seh+0x13, seh+0x13+size]` 倒序逐字节 `xor bl` + `rol ebx, cl`；偶数 CRC 步再
   `xor bx, 1`（运行期形态值 = TEB fs:1c/fs:22 之和低 16 位 +1；EnvironmentPointer=0 且 PID<0x10000
   的常规 Win32 环境下恒为 1——零 TEB 仿真复现同一结果）。`encrypted_ep ^= CRC`。
2. 导入走链：null 终止的 FirstThunk-RVA 数组；每 thunk：名字项原地 -2（伪 hint），序号项计数器 +1；
   混淆开启时按 stub 的 `edx&7` 节奏用假 jmp 槽（EP+5 起每 5 字节）替换；
   每个 fake 槽两次 `sbb`（段 VA 与当前槽址比较）+ `ror 3` 折回 ep。
3. `oepRva = (EP+5) + ep - imageBase`；自校验 `(oepRva >>> 24) == 0`（rol8 探针）。

本样：`encrypted_ep=0xACE8F809`、`importRva=0x21000`、`mangled=0x28244CFF`（混淆开启）、CRC 0x33D/ROL 0x1B
→ **OEP = 0x2FE6**，落点为解出 .text 内合法代码（r!sc 工具自身的 fs 链序言），rol8 校验通过。

### 2.6 重建输出（UnPETite 式）

沿用 packed 头（原 DOS/可选头字段不可恢复——见 §4）：

- 擦除 layer2 窗口 `[seh, seh+crcSize)`；
- 节清单 = block 表项 + 资源目录（dir[2] 0x23000/0x800）+ 未压缩的原 packed 节（尾节随行）；
  含 layer2 的节缩 crcSize，导入节加库名块长；
- 重建 IMAGE_IMPORT_DESCRIPTOR（OFT=0/Name=复制库名/FirstThunk=原位 thunk 数组）；
  库名复制到描述符区后扫描到的空槽；EP=OEP、导入目录=importRva、重定位清零、SizeOfImage 不变；
- 节表重建：单字母名 A/B/…、raw 链自 SizeOfHeaders、0x200 对齐、特征 0xE0000060、末节 vsize 补齐。

**超出 r!sc 的修复**：混淆 thunk 槽（值 ≥ imageSize 的 stub jmp VA）的原名不可逆，但名字表是导入块内的
连续 NUL 分隔 ASCII 表——回溯（≥8 NUL 边界或非 ASCII 候选停）到表头（本样 0x21108 "CreateFileA"），
正向走到块尾（0x211DC "GetOpenFileNameA"），表序即数组序，缺席项按序回填（name-2 伪 hint，
与存活槽 -2 修正一致）。本样 4/15 槽被修复，输出导入表全部有效。

## 3. 验证

- **层 1 逐字节对拍**：静态解码（move+4 块+预种子）与“实样自有 stub 的 x86 全仿真”输出在
  [0x400,0x23000) 零差异（排除仿真自污染区：加载器解析过的 stub IAT 窗口、预种子 0x780 区、stub 的 tail+0 指针戳记）。
  golden 快照取自首次 SEH 分发瞬间（layer1 完成、layer2 未跑）。
- **端到端**：15872 字节重建输出，`parsePE` 零警告，3 模块/15 函数（KERNEL32 12 + USER32 2 + COMDLG32 1）
  与名字表完全一致，输出 SHA-256 `53f13c5cf2798551867e9b404b20ca4d1d09fb91f3b30b5cfd3220bd70978b9c`（确定性）。
- **解码器合成向量**：字面量 XOR key 演进、dist-1 重叠拷贝、偏移复用、gamma 长度下限、
  截断流/gamma 炸弹/越界表拒绝（稳定 error code）。
- `node --test tests/petite.test.js` 14/14。

## 4. 诚实边界

- **单样本**：所有布局常数仅对 ENLARGE.EXE（Petite 2.2 l19 自壳）验证；2.1/2.4/level-0/LZMA 变体
  （DIE 子集 11 条分支的其余 10 条）一律 `unsupported-petite-variant` 拒绝。
- **原头字段不恢复**：运行期“头块”= SEH 弹床（§2.2），静态无原始头数据源；DOS 存根、可选头细节、
  原节名/属性丢失（重建节单字母名）；重定位目录清零；资源沿用 packed 头的目录项。
- **未运行**：`runtimeVerified: false`，无任何真机执行（全程未运行样本/工具二进制）。
- CRC 形态值假设 EnvironmentPointer=0 且 PID<0x10000（长寿机器 PID 超 0xFFFF 时 r!sc 原工具同样失效，非本引擎引入）。
- 仿真 golden 的取得依赖前置仿真 hack（合成 TEB/栈锚/SEH 分发），仅用作层 1 对拍参照，
  不进入引擎路径；引擎是纯静态解码。

## 5. 证据索引（资料/reverse/t43-petite）

- `ENLARGE.EXE`（实样）、`golden-layer1.bin`（仿真层 1 快照）、`emu-tokens.json`/`emu-bitlog.json`（token/位级取证）；
- `final-static.mjs`（含端点修正的静态解码与 golden 对拍）、`compare.mjs`、`b3forensic.mjs`（末 token 取证）、
  `bitref.mjs`（基座 CPU 位读取器对拍）、`phasecheck.mjs`（"4b 20" 写入时机定位）、`decrypt.mjs`（OEP 解密复现）、
  `dump.mjs`/`prot2.js`/`trace3/4/5.mjs`（仿真链）；
- 前任中断会话的早期脚本（parse/fields/tail/trace/layer2/decomp/extract/prot.js）保留为过程证据。
- MT7 的 Ghidra 工程（`资料/reverse/petite/`）与 r!sc ASM 记录（`资料/reverse/petite/source/`）为算法交叉源；
  本卡未重跑 Ghidra（实样在手 + 既有反汇编 + 全仿真三方互证已覆盖）。

## 6. M 接入行

```js
import { supportsPetite, unpackPetite, PETITE_ENGINE } from './unpackers/petite.js';
```

注册候选：`PETITE_ENGINE`（id `petite-22-pe32`，catalogId `petite`，rebuilt-pe，experimental）；
检测已由 DIE 子集 2.2 EP 分支覆盖（`src/core/detect.js` + `vendor/die/db/PE/packer_Petite.2.sg`），
引擎侧 `supportsPetite` 另加 2.2 锚 dword 双重确认。fixture 为只读拷贝
`test-results/fixtures/petite/ENLARGE.EXE`（缺文件时测试显式 skip）。
