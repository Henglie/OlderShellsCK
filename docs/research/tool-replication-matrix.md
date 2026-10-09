# 逐工具研究与复刻任务矩阵

2026-10-07，MT27 / D。当前是候选交付，公共入口由 M 接入。
**MT29 @A 2026-10-08 增量**：+N13（RL!deFSG 2.0 内层提取与拆解，G51/A37 解锁）；N06 RL!deUPX 内层 I→F（A10）；A12 tElock 推进至 L4+loader 核心；记录数 259→**260**。详见 rlde-family.md §8a/§8b/§13a 与 `资料/reverse/mt29-*`。

## 口径与证据

**259 条任务记录**（MT27 基线；MT29 后 **260**）：199 条外层文件画像卡（72 GUI、41 CoolDumpper 插件、28 WCX/模块插件、11 UNP 插件、47 CLI 辅助），12→**13** 条已提取内层组件卡（MT29 增 N13），48 条算法工作包。不是 259 个脱壳引擎，也不是 259 个已支持壳版本。

本轮重算归档 **340 个文件**的完整 SHA-256；其中 253 PE + 1 非 PE 的 MZ。199 条文件卡内有 3 个相同二进制别名，去重为 **196 个文件实体**。其余 47 个 MZ/PE 是依赖库、8 个是附带样本；它们的路径/完整哈希仍在全量清单中。文本、配置、源码 ZIP 不按新引擎计数。

- `E0`：`资料/archive-inventory.json` 的精确 path 对应记录，含完整 SHA-256、导入、导出、版本资源、架构与警告；本轮复算结果由 `资料/reverse/mt27-research/audit.py --inventory` 重现。
- `E1`：`资料/reverse/mt27-research/matrix-assets.json`，逐 ID 完整 SHA-256；表内 `SHA16` 是完整哈希前 16 位，**不作为验真替代物**。
- `R`：`docs/research/rlde-family.md` 的函数、raw/VA、原创算法伪代码和 fixture 验证；私有证据目录均为 `资料/reverse/mt27-*`。
- `D0`：依赖尚未做调用级归因。实际 imports/exports 已逐文件保存在 E0；不能把缺少 CreateProcess 导入解释为静态算法。
- `I`：仅库存/身份线索；`F`：函数链已拆；`A`：算法边界已重建；`V`：限定 fixture/golden 通过。`OPEN/BLOCKED/CANDIDATE` 是复刻状态，研究报告完成不等于复刻完成。
- 外层文件表未另写的字段统一为：**目标壳版本未知；依赖 D0；核心算法待该 ID 卡拆；证据 E0+E1；验证样本/golden 无**。这是明确的缺口，不是支持声明。覆盖这些默认值的已核画像在下一节；独立算法/参数分支在算法表。

每张 `G/PC/PA/PU/C` OPEN 卡的下一阶段交付固定为：校验本行完整哈希 → 确認真实标题/导出 ABI → 至少 GUI/导出入口、核心变换、输出重建三处调用/字节证据 → 静态还原外层（如有） → 原创有界算法模型或精确阻塞点 → 固定样本 + 独立 oracle。只能按实际证据升级 `I→F→A→V`。PC/PA/PU 卡逐件认领，不能批量标成“插件算法已完成”。

## 已确认身份、依赖、版本与状态覆盖

| 文件卡 | 真实身份/目标版本证据 | 依赖与算法卡 | 研究 / 复刻 / 样本 |
|---|---|---|---|
| G50/G52/G53/G54/G57/G58/G51 | 外层同一 Delphi 自解压启动器；真正专壳 GUI 在内层（N01–N06、N13）。ASPack 2.x/MEW 1.x/NsPack 3.x/PeX 0.99/PackMan 1.x/UPX 1.x–2.x/FSG 2.0 是工具宣称，未做逐版本验收 | N08–N13；A01–A10、A37 | ASPack/MEW/NsPack/PeX/PackMan/UPX/FSG 内层已 F（UPX/FSG 为 MT29）；原 GUI 未运行；专壳动态驱动复刻 OPEN |
| G55/G56/G23 | 三个不同哈希的 RL!dePacker 副本；G56 内层 N07 可提取，但进一步保护未解除；不能把文件名 x86、`.UPX1` 或外层启动器当作新通用引擎 | A11 | BLOCKED；UPX 4.2.4 静态解码 N07 返回 CantUnpackException；无驱动名单/golden |
| G47 | tElock 名称宣称；入口转送到 `0x436001` 的 ASPack-like 多态外层，已算出两层数据变换 | A12 | A(外层局部) / BLOCKED(内层 GUI)；第三层还未恢复 |
| G21 | ORiEN 名称宣称；外层常量 word 变换后露出固定 aPLib 解码器 | A13 | A(264 字节外层) / BLOCKED(内层 GUI)；不宣称 ORiEN 目标壳算法就是 aPLib |
| G11 | DeAutoIt / ximo[LCG]，EA06 脚本解密、解压、token→AU3 文本；不是 PE 重建器 | UPX 外层；A14–A17 | 656896 字节内层静态恢复、12 个关键函数 F/A；产品复刻 OPEN，无 AutoIt golden |
| G16 | EUnpacker / fOx，内层同时含1.0/V1.2字符串；启动挂起进程、注入、RemoteMain/回传与资源/overlay修复架构 | A18，LZMA1+UPX filter | 已静态解出1226125字节，恢复4661个E8/E9；F架构 / OPEN，专壳修复与RemoveNAG仍待拆；官方UPX拒绝不再作为不可解码结论 |
| G62 | 易语言伪装精灵还原名称；`.zzage` 高熵源节，当前只有外层函数证据 | A19 | BLOCKED：未解出的外层不能充当伪装还原算法 |
| G22/G60 | **同一 SHA-256**，`prjPEArmorUnpack`；界面 Version 1.1，目标提示 PEArmor/Hying 0.46 | MFC42/MSVCRT；A20–A22 | F/A / OPEN；没有 PEArmor 独立 golden。新 ASPack/MEW 不能冒充它的全功能复刻 |
| G26 | r!sc enlarger v1.3，附 ASM，声称 Petite 2.1/2.2；外层/内层地址分开 | A31/A32；`UnPETite/UNP_SRC.ZIP` | 外层/附带源 A / OPEN；许可、内层恢复、level-0 与逐版样本待补 |
| G34 | UpxUnpacker ver0.2；会修补并间接 CALL 输入 stub | A33；A34/A35 可替换 codec | F/A / OPEN；不是纯静态 codec；未运行该 GUI |
| G03 | ArmaGeddon 2.3 final / ARTeam；调试线程、事件循环、远程重建 | A40；A41 | 已有函数报告；专用修复扩展由 A 路继续。不能推出所有 Armadillo 配置的产物上限 |
| G02/G20/G63 | Nanomites 修复副本，不同哈希/版本；G02 目录 v1.2 与资源 1.1.c 冲突 | NanoLib/Disasm；A41 | A 路研究/候选状态以其回执为准；D 未复验完成 |
| G41/G42 | UnpkT0l v1.5，中英不同二进制；手工 OEP/IAT 输入 + dump 后 PE 修正 | A03/A04；已有 `unpkt0l` case | F / 专用语义复刻 OPEN；没有新增解压引擎 |
| G71/G72 | VMUnpacke 与同标题重打包副本；125 个驱动计数线索不是逐壳支持矩阵 | VUnpackSDK.dll / unpack.avd / 可选 SUnpackSDK.dll；A42/A43 | 架构 F，B 路推进解释器；avd 名单/高级修复能力未知 |
| G08 | CoolDumpper - All Packers Generic Unpacker；宿主调度插件 | PC01–PC41，ImpREC/Disasm；A45 | 身份 I/F线索；41 插件逐件 OPEN，不能从 37 个目标名称推 37 个静态引擎 |
| G27 | Universal Extractor GUI 分发器，调用外部 codec/安装包插件 | PA/PU/C 各卡；A46 | 调度器身份 I；功能必须归到实际组件与格式版本 |
| G30/G32/G61/C39 | ExeInfoPE / PEiD / Language 2000 / TrID 是检测工具；G61 资源身份 Language 2000 4.5.1.144 | 签名库；A47 | 识别 ≠ 脱壳。Language 2000 内层仍压缩，不能凭外层 API 缺失宣称绝无执行面 |
| G04/G09/G65 | DLL 启动辅助 | 对应 GUI/插件 | 不计新壳引擎 |
| G13/G17 | **完全相同二进制**，两个目录标题 | EncryptPE 卡 | 共用研究结果，不计两算法 |
| C05/C06 | **完全相同 7z.exe**；其 7z.dll 也同哈希 | 归档 codec | 同版本别名，不计两引擎 |
| G67 | “编译工具”身份尚未核清 | 本卡静态恢复 | OPEN；不能归成已证实脱壳算法 |

旧 `generic-unpacker-claims.md` 的“所有通用 GUI 都停在 dump”与基于缺少 API 的能力排除，不作为本矩阵结论。加密驱动库、自保护代码、未知内层没有穷尽 → 能力未知；也不能反向宣称全部保护壳可恢复。`id-40000 < 0x73` 若按十进制 ID 解读是 40000–40114，共 115 项；125 驱动列表应独立核名称与去重。

## 外层逐文件卡

路径相对于 `资料/老旧壳脱壳工具/`。`版本=未验证`、`I/OPEN` 采用上文默认字段；上一节的具名覆盖优先。每行本身就是下一阶段可认领卡。

| ID | 精确真实路径 | SHA16 | 初步身份/角色 | 目标版本 | 研究 / 复刻 |
|---|---|---|---|---|---|
| G01 | `AoRE_Unpacker_0.4/AoRE_Unpacker.exe` | `dae52c09b3496c33` | GUI候选 | 未验证 | I / OPEN |
| G02 | `Armageddon_v2.3/Armadillo Nanomites Fixer v1.2/ArmNF.exe` | `0bde1ba6446c40ea` | Nanomites修复 | 未验证 | I / OPEN |
| G03 | `Armageddon_v2.3/Armageddon.exe` | `9cc693a229c455a0` | 调试脱壳GUI | 未验证 | F / OPEN |
| G04 | `Armageddon_v2.3/dll loader.exe` | `12282c3d2800ea84` | 启动辅助 | 未验证 | I / OPEN |
| G05 | `AutoEye_v2.0.0.1000/AutoEye32.exe` | `7777b0e231ec699d` | GUI候选 | 未验证 | I / OPEN |
| G06 | `AutoEye_v2.0.0.1000/AutoEye64.exe` | `b6cc0b2db543139b` | GUI候选 | 未验证 | I / OPEN |
| G07 | `AutoIt Extractor/AutoIt Extractor.exe` | `3f0a0fcd23aa26f6` | 脚本提取GUI候选 | 未验证 | I / OPEN |
| G08 | `CoolDumpper/loader.exe` | `49a3d7c6a17fad99` | 插件宿主 | 未验证 | I / OPEN |
| G09 | `CoolDumpper/tool/loaddll.exe` | `f39acd9e662234e8` | 启动辅助 | 未验证 | I / OPEN |
| G10 | `DDeM Protector 脱壳机/UnDDeM.exe` | `dcf4dd008b6a4adb` | GUI候选 | 未验证 | I / OPEN |
| G11 | `DeAutoIt.exe` | `c1ce4759c0ac4007` | EA06→AU3 | EA06字节证据 | A / OPEN |
| G12 | `DeShrink v1.6/deshrink.exe` | `e762b907f13d8afc` | GUI候选 | 未验证 | I / OPEN |
| G13 | `EPE V2 Stripper 高级版 rc4/EPE V2 Stripper 高级版 rc4.exe` | `3fdc34fb93cc6d86` | G17同体 | 未验证 | I / OPEN |
| G14 | `EPE121脱壳机/Unpacker.exe` | `877b53a3fdc5bdd1` | GUI候选 | 未验证 | I / OPEN |
| G15 | `EPE_stripper无壳版/EPE_stripper无壳版.exe` | `c4fdf802283b901c` | GUI候选 | 未验证 | I / OPEN |
| G16 | `EUnpacker_RemoveNAG.exe` | `79e4103accf21ceb` | 静态恢复内层/注入架构 | 1.0/V1.2冲突 | F局部 / OPEN |
| G17 | `EncryptPE UnPacker/EPE.exe` | `3fdc34fb93cc6d86` | G13同体 | 未验证 | I / OPEN |
| G18 | `GUnPacker0.5/GUnPacker.exe` | `2f9f29b22f552a6a` | 内层被保护 | 未验证 | I / BLOCKED |
| G19 | `Molebox_Virtualization_Studio_unpacker_v0.65/demoleition.exe` | `5a1404ad8e141ca4` | GUI候选 | 未验证 | I / OPEN |
| G20 | `Nanofixer/Armadillo Nanomites Fixer.exe` | `1df3d804a70e5d74` | Nanomites修复 | 未验证 | I / OPEN |
| G21 | `ORiEN.exe` | `25b5085843115272` | 自保护内层未恢复 | 未验证 | A局部 / BLOCKED |
| G22 | `PEArmorUnpack.exe` | `4100ea3554940ce7` | PEArmor/Hying解包 | 声称0.46 | A / OPEN |
| G23 | `RL!dePacker.exe` | `2c5dbc9749093396` | 自保护通用候选 | 未验证 | I / BLOCKED |
| G24 | `UnFSG1.33/UnFSG.exe` | `f09a27525d4a3458` | GUI候选 | 未验证 | I / OPEN |
| G25 | `UnObSiDium/UnObSiDium.exe` | `5292383439ca10f3` | GUI候选 | 未验证 | I / OPEN |
| G26 | `UnPETite/ENLARGE.EXE` | `ed3d6a0a80dd6b1f` | Petite enlarger | 声称2.1/2.2 | A局部 / OPEN |
| G27 | `Universal Extractor/UniExtract.exe` | `8e3140ed8675d52e` | 分发GUI | 各格式待核 | I / OPEN |
| G28 | `Universal Extractor/bin/AspackDie.exe` | `465e075688109b59` | GUI候选 | 未验证 | I / OPEN |
| G29 | `Universal Extractor/bin/AspackDie22.exe` | `d6da73a67fc3568b` | GUI候选 | 未验证 | I / OPEN |
| G30 | `Universal Extractor/bin/ExeInfoPe.exe` | `0f01c14d36a6f91e` | 检测器 | 非脱壳 | I / OPEN |
| G31 | `Universal Extractor/bin/Expander.exe` | `af9ef3f14e473ef0` | 提取GUI候选 | 未验证 | I / OPEN |
| G32 | `Universal Extractor/bin/PEiD.exe` | `e13171d50f45a79b` | 检测器 | 非脱壳 | I / OPEN |
| G33 | `Universal Extractor/bin/SfxSplit.exe` | `ff2f7ae9dc8f4a93` | SFX分离候选 | 未验证 | I / OPEN |
| G34 | `Universal Extractor/bin/UpxUnpacker.exe` | `f5a703c6d1c8434e` | 输入stub执行 | 未验证 | A / OPEN |
| G35 | `Universal Extractor/bin/pea.exe` | `89152f909ecdf295` | 归档GUI候选 | 未验证 | I / OPEN |
| G36 | `Unpacker ExeCryptor 2.x.x. RC1 [Public]/Unpacker ExeCryptor.exe` | `8402e72f63787562` | GUI候选 | 未验证 | I / OPEN |
| G37 | `Unpacker ExeCryptor 2.x.x. RC1 [Public]/Unpacker ExeCryptor_1.0_chs.exe` | `d98bc02a5dbaf3c3` | 汉化候选 | 未验证 | I / OPEN |
| G38 | `Unpacker_ExeCryptor_RC2_chs/Unpacker ExeCryptor RC2.exe` | `8589ace9b6de3b64` | GUI候选 | 未验证 | I / OPEN |
| G39 | `Unpacker_ExeCryptor_RC2_chs/Unpacker ExeCryptor RC2_chs.exe` | `e7629ac53bc3320a` | 汉化候选 | 未验证 | I / OPEN |
| G40 | `Unpacker_PECompact/Unpacker_PECompact.exe` | `b440ef96f8e76ef2` | GUI候选 | 声称2.X–3.X | I / OPEN |
| G41 | `UnpkT0l_Unpacked_Hanzified_English_2in1/UnpkT0l Unpacked v1.5 CN.exe` | `21a8f46535785f58` | dump后PE修正 | 无codec版本 | I / OPEN |
| G42 | `UnpkT0l_Unpacked_Hanzified_English_2in1/UnpkT0l Unpacked v1.5.exe` | `1251f678a086f93e` | dump后PE修正 | 无codec版本 | F / OPEN |
| G43 | `WSDP116/WSDP116.exe` | `77cdfe2a93d8db52` | GUI候选 | 未验证 | I / OPEN |
| G44 | `WinUpack Stripper v0.3/WUPACK.exe` | `8d0f170314c01636` | GUI候选 | 未验证 | I / OPEN |
| G45 | `WinUpack_KiLLeR/WinUpack_KiLLeR.exe` | `f482d02e56830f0f` | GUI候选 | 未验证 | I / OPEN |
| G46 | `Zp_Unpacker1.1/Zp_Unpacker1.1.exe` | `8168222eece7f942` | GUI候选 | 未验证 | I / OPEN |
| G47 | `tElock脱壳机.exe` | `3c70bf02d83265f6` | 多态内层未恢复 | 未验证 | A局部 / BLOCKED |
| G48 | `unPESpin v11/UnPesPin.exe` | `27c2b547f38461fe` | GUI候选 | 未验证 | I / OPEN |
| G49 | `yoda's Protector/yoda's Protector.exe` | `bbcf10b4b37b1f37` | GUI候选 | 未验证 | I / OPEN |
| G50 | `万用脱壳机 RL!deASPack 2.x.exe` | `e33899af26f76924` | 自解压wrapper→N01 | 声称2.x | F / OPEN |
| G51 | `万用脱壳机 RL!deFSG 2.0.exe` | `6e90e98d7d83a6db` | 自解压wrapper→N13 | 声称2.0 | F / OPEN |
| G52 | `万用脱壳机 RL!deMEW 1.x.exe` | `ff612ce167a93521` | 自解压wrapper→N02 | 声称1.x | F / OPEN |
| G53 | `万用脱壳机 RL!deNsPack 3.x.exe` | `c887d8767cdda38e` | 自解压wrapper→N03 | 声称3.x | F / OPEN |
| G54 | `万用脱壳机 RL!dePackMan 1.x.exe` | `867ca8d018810f44` | 自解压wrapper→N05 | 声称1.x | F / OPEN |
| G55 | `万用脱壳机 RL!dePacker.exe` | `b015131f86b59476` | 内层未恢复 | 未验证 | I / BLOCKED |
| G56 | `万用脱壳机 RL!dePacker_x86.exe` | `6c9a31e2edc9698b` | wrapper→N07 | 未验证 | I / BLOCKED |
| G57 | `万用脱壳机 RL!dePeX 0.99.exe` | `366d2d9dfe890355` | wrapper→N04 | 声称0.99 | F / OPEN |
| G58 | `万用脱壳机 RL!deUPX 1.x-2.x.exe` | `1e12cb1a644eddc7` | wrapper→N06 | 声称1.x–2.x | F / OPEN |
| G59 | `北斗3.X系列脱壳机/WNspack.exe` | `d371ffb8f51259ad` | GUI候选 | 声称3.x | I / OPEN |
| G60 | `完美静态脱壳机.exe` | `4100ea3554940ce7` | G22同体别名 | 声称0.46 | A / 同G22 |
| G61 | `支持 45 种编译器和 42 种加壳、加密类型查壳工具.exe` | `c686ffdacd82e0ec` | Language 2000检测器 | 非脱壳 | I / OPEN |
| G62 | `易语言伪装精灵还原.exe` | `6370656eefe07799` | 内层未恢复 | 未验证 | I / BLOCKED |
| G63 | `穿山甲Nanomites修复器.exe` | `7178e92ea3962627` | Nanomites候选 | 未验证 | I / OPEN |
| G64 | `穿山甲脱壳机-.exe` | `305bdc5ebda29bec` | GUI候选 | 未验证 | I / OPEN |
| G65 | `穿山甲脱壳机-1.6/DllLoader.exe` | `5423627a5fc96968` | 启动辅助 | 未验证 | I / OPEN |
| G66 | `穿山甲脱壳机-1.6/dilloDIE.exe` | `656b5d9bb334bf3b` | 调试GUI | 未验证 | I / OPEN |
| G67 | `编译工具.exe` | `590d76c1ad6d9779` | 身份待核 | 未验证 | I / OPEN |
| G68 | `脱壳工具tmdunpacker.exe` | `d45f6d4e5a3fba6b` | GUI候选 | 未验证 | I / OPEN |
| G69 | `脱壳机Themnet Unpacker_original.exe` | `009ef2c9fe914da7` | GUI候选 | 未验证 | I / OPEN |
| G70 | `超级巡警.exe` | `4cfdf40a1ea6df31` | GUI候选 | 未验证 | I / OPEN |
| G71 | `超级巡警脱壳机1.5 专版/VMUnpacke.exe` | `a55455b9ce1e97e9` | VM SDK宿主 | 驱动版本未知 | F架构 / OPEN |
| G72 | `超级巡警虚拟机自动脱壳机 V1.5(卡饭社区专版).exe` | `839d03f3734e8b7d` | 重打包候选 | 驱动版本未知 | I / OPEN |
| PC01 | `CoolDumpper/plugin/Acprotect.dll` | `e1952aaebd4f3d53` | 插件待拆 | 未验证 | I / OPEN |
| PC02 | `CoolDumpper/plugin/AntiDebugLib.dll` | `71766680a261bb95` | 辅助插件待拆 | 未验证 | I / OPEN |
| PC03 | `CoolDumpper/plugin/ArmProtector.dll` | `5800f61a0727a073` | 插件待拆 | 未验证 | I / OPEN |
| PC04 | `CoolDumpper/plugin/Asprotect.dll` | `ebdc934bbbc24d3e` | 插件待拆 | 未验证 | I / OPEN |
| PC05 | `CoolDumpper/plugin/BeRoExePacker.dll` | `76638fe60a521c3d` | 插件待拆 | 未验证 | I / OPEN |
| PC06 | `CoolDumpper/plugin/EXECryptor.dll` | `ba00531e5b00a7ae` | 插件待拆 | 未验证 | I / OPEN |
| PC07 | `CoolDumpper/plugin/GetEPEInfo.dll` | `98887445bb6e259d` | 辅助插件待拆 | 未验证 | I / OPEN |
| PC08 | `CoolDumpper/plugin/KByS.dll` | `3b69b3a226c40288` | 插件待拆 | 未验证 | I / OPEN |
| PC09 | `CoolDumpper/plugin/KenPack.dll` | `b5ae355ae08ab158` | 插件待拆 | 未验证 | I / OPEN |
| PC10 | `CoolDumpper/plugin/Mew.dll` | `63114c6fad4b3b0b` | 插件待拆 | 未验证 | I / OPEN |
| PC11 | `CoolDumpper/plugin/NsPack.dll` | `a2d6c72092d3e971` | 插件待拆 | 未验证 | I / OPEN |
| PC12 | `CoolDumpper/plugin/PCSHRINK.dll` | `a3c65e4d127f5f59` | 插件待拆 | 未验证 | I / OPEN |
| PC13 | `CoolDumpper/plugin/PECompact.dll` | `c4482d58d846381e` | 资源模板Mew.DLL不能定身份 | 未验证 | I / OPEN |
| PC14 | `CoolDumpper/plugin/PEncrypt.dll` | `b6d3b164e1f98f42` | 插件待拆 | 未验证 | I / OPEN |
| PC15 | `CoolDumpper/plugin/VFP.dll` | `4fa568a0eb497bc7` | 用途待核 | 未验证 | I / OPEN |
| PC16 | `CoolDumpper/plugin/armadillo.dll` | `207828e9db7e8516` | 插件待拆 | 未验证 | I / OPEN |
| PC17 | `CoolDumpper/plugin/aspack.dll` | `08470efb07e0972f` | 插件待拆 | 未验证 | I / OPEN |
| PC18 | `CoolDumpper/plugin/dbpe.dll` | `4321e5bd3398f2aa` | 插件待拆 | 未验证 | I / OPEN |
| PC19 | `CoolDumpper/plugin/exPressor.dll` | `e48b61feb1010639` | 插件待拆 | 未验证 | I / OPEN |
| PC20 | `CoolDumpper/plugin/fsg.dll` | `a75c7b27d0c3a8e8` | 插件待拆 | 未验证 | I / OPEN |
| PC21 | `CoolDumpper/plugin/hmimys.dll` | `8052b14b04b2e96c` | 插件待拆 | 未验证 | I / OPEN |
| PC22 | `CoolDumpper/plugin/hying.dll` | `e51e26e9af80d0b2` | 插件待拆 | 未验证 | I / OPEN |
| PC23 | `CoolDumpper/plugin/hying04x.dll` | `98b7b2d5f1b227b7` | 不与PC22假合并版本 | 未验证 | I / OPEN |
| PC24 | `CoolDumpper/plugin/jdpack.dll` | `a4d47e99f9305b85` | 插件待拆 | 未验证 | I / OPEN |
| PC25 | `CoolDumpper/plugin/morphine.dll` | `a393762a0dbfbaad` | 插件待拆 | 未验证 | I / OPEN |
| PC26 | `CoolDumpper/plugin/null.dll` | `e2980cf4eeb28145` | 用途待核 | 未验证 | I / OPEN |
| PC27 | `CoolDumpper/plugin/orien.dll` | `9df33f03e1ce68d9` | 插件待拆 | 未验证 | I / OPEN |
| PC28 | `CoolDumpper/plugin/packMan.dll` | `57302c59d87db912` | 插件待拆 | 未验证 | I / OPEN |
| PC29 | `CoolDumpper/plugin/pelock.dll` | `007ab1af8da8f335` | 插件待拆 | 未验证 | I / OPEN |
| PC30 | `CoolDumpper/plugin/pespin.dll` | `6ce336bd2c206537` | 插件待拆 | 未验证 | I / OPEN |
| PC31 | `CoolDumpper/plugin/petite.dll` | `8d43b5ed96bf82fe` | 插件待拆 | 未验证 | I / OPEN |
| PC32 | `CoolDumpper/plugin/polyENE.dll` | `cfb6e4a56b5f1121` | 插件待拆 | 未验证 | I / OPEN |
| PC33 | `CoolDumpper/plugin/rlpack.dll` | `65fb3e08ce2d663d` | 插件待拆 | 未验证 | I / OPEN |
| PC34 | `CoolDumpper/plugin/shoooo.dll` | `751e23b1f3434c46` | 插件待拆 | 未验证 | I / OPEN |
| PC35 | `CoolDumpper/plugin/starforce.dll` | `1788b42a83baa474` | 插件待拆 | 未验证 | I / OPEN |
| PC36 | `CoolDumpper/plugin/super.dll` | `90e01b62203b7a49` | 名称不等于全穿山甲 | 未验证 | I / OPEN |
| PC37 | `CoolDumpper/plugin/telock.dll` | `ed4b99e7fc72761a` | 插件待拆 | 未验证 | I / OPEN |
| PC38 | `CoolDumpper/plugin/upack.dll` | `096834d099cbae9a` | 插件待拆 | 未验证 | I / OPEN |
| PC39 | `CoolDumpper/plugin/upx.dll` | `3fd492062051ee64` | 插件待拆 | 未验证 | I / OPEN |
| PC40 | `CoolDumpper/plugin/vcasm.dll` | `600b2321194d41bb` | 插件待拆 | 未验证 | I / OPEN |
| PC41 | `CoolDumpper/plugin/yoda.dll` | `a520d6825690242a` | 插件待拆 | 未验证 | I / OPEN |
| PA01 | `Universal Extractor/bin/ICLRead.wcx` | `5ce04fe466d816df` | 归档插件待拆 | 未验证 | I / OPEN |
| PA02 | `Universal Extractor/bin/InstExpl.wcx` | `6057a2b23bcf5ca7` | 安装包插件待拆 | 未验证 | I / OPEN |
| PA03 | `Universal Extractor/bin/MhtUnPack.wcx` | `2bc9f929f11bc810` | 归档插件待拆 | 未验证 | I / OPEN |
| PA04 | `Universal Extractor/bin/PDunSIS.wcx` | `13518d6aac144bdb` | 归档插件待拆 | 未验证 | I / OPEN |
| PA05 | `Universal Extractor/bin/TotalObserver.wcx` | `c69b6090267e490e` | 归档插件待拆 | 未验证 | I / OPEN |
| PU01 | `Universal Extractor/bin/Unp/Bzip2_1.unp` | `30cd5ec7c6778fbd` | decoder候选 | 未验证 | I / OPEN |
| PU02 | `Universal Extractor/bin/Unp/Bzip2_2.unp` | `f7b420f1bcd3d075` | decoder候选 | 未验证 | I / OPEN |
| PU03 | `Universal Extractor/bin/Unp/Bzip2_3.unp` | `ff574a600fb1ae9d` | decoder候选 | 未验证 | I / OPEN |
| PU04 | `Universal Extractor/bin/Unp/Eschalon.unp` | `0ceb97c8c016d1a2` | decoder候选 | 未验证 | I / OPEN |
| PU05 | `Universal Extractor/bin/Unp/Gentee.unp` | `429dfb2b761ee910` | decoder候选 | 未验证 | I / OPEN |
| PU06 | `Universal Extractor/bin/Unp/inflate1.unp` | `7c4ee80c3cc8017a` | decoder候选 | 未验证 | I / OPEN |
| PU07 | `Universal Extractor/bin/Unp/inflate2.unp` | `c5d514ac97f6da17` | decoder候选 | 未验证 | I / OPEN |
| PU08 | `Universal Extractor/bin/Unp/inflate3.unp` | `fa34b0390cfb60ab` | decoder候选 | 未验证 | I / OPEN |
| PU09 | `Universal Extractor/bin/Unp/lzma.unp` | `01275fa6c27d188e` | decoder候选 | 未验证 | I / OPEN |
| PU10 | `Universal Extractor/bin/Unp/pkware.unp` | `f258b715c6f25d96` | decoder候选 | 未验证 | I / OPEN |
| PU11 | `Universal Extractor/bin/Unp/vise.unp` | `63f8f6ee57e49535` | decoder候选 | 未验证 | I / OPEN |
| PA06 | `Universal Extractor/bin/dbxplug.wcx` | `0f6dfaf483982730` | 归档插件待拆 | 未验证 | I / OPEN |
| PA07 | `Universal Extractor/bin/decMpoWCX.wcx` | `e0f1722de96c1acc` | 归档插件待拆 | 未验证 | I / OPEN |
| PA08 | `Universal Extractor/bin/hlp.wcx` | `2076da962b2f1ec6` | 归档插件待拆 | 未验证 | I / OPEN |
| PA09 | `Universal Extractor/bin/iso.wcx` | `74f24feb440fcc5c` | 归档插件待拆 | 未验证 | I / OPEN |
| PA10 | `Universal Extractor/bin/modules/gentee.so` | `cf67507daa0e60ef` | PE模块待拆 | 未验证 | I / OPEN |
| PA11 | `Universal Extractor/bin/modules/ishield.so` | `4b54873d3cf2ec1c` | PE模块待拆 | 未验证 | I / OPEN |
| PA12 | `Universal Extractor/bin/modules/isoimg.so` | `43e9a095880aba6d` | PE模块待拆 | 未验证 | I / OPEN |
| PA13 | `Universal Extractor/bin/modules/mbox.so` | `7cb487fe98c12ffe` | PE模块待拆 | 未验证 | I / OPEN |
| PA14 | `Universal Extractor/bin/modules/mime.so` | `8c71e10139c37f0d` | PE模块待拆 | 未验证 | I / OPEN |
| PA15 | `Universal Extractor/bin/modules/mpq.so` | `a9984b3b13e07482` | PE模块待拆 | 未验证 | I / OPEN |
| PA16 | `Universal Extractor/bin/modules/msi.so` | `1586b1262baab86f` | PE模块待拆 | 未验证 | I / OPEN |
| PA17 | `Universal Extractor/bin/modules/nsis.so` | `31197e20d19def8a` | PE模块待拆 | 未验证 | I / OPEN |
| PA18 | `Universal Extractor/bin/modules/pdf.so` | `e300461617b4bf5c` | PE模块待拆 | 未验证 | I / OPEN |
| PA19 | `Universal Extractor/bin/modules/pst.so` | `a7bb1d21000c180f` | PE模块待拆 | 未验证 | I / OPEN |
| PA20 | `Universal Extractor/bin/modules/relic.so` | `82294298bb8a1be5` | PE模块待拆 | 未验证 | I / OPEN |
| PA21 | `Universal Extractor/bin/modules/sfact.so` | `8f5d5fda5fe11ba4` | PE模块待拆 | 未验证 | I / OPEN |
| PA22 | `Universal Extractor/bin/modules/udfimg.so` | `31f0c77a3b1c270f` | PE模块待拆 | 未验证 | I / OPEN |
| PA23 | `Universal Extractor/bin/modules/valve.so` | `de8f9b7aaefea649` | PE模块待拆 | 未验证 | I / OPEN |
| PA24 | `Universal Extractor/bin/modules/vdisk.so` | `deb78e193f7860cb` | PE模块待拆 | 未验证 | I / OPEN |
| PA25 | `Universal Extractor/bin/modules/vp.so` | `f01a821f0ab58f36` | PE模块待拆 | 未验证 | I / OPEN |
| PA26 | `Universal Extractor/bin/modules/wise.so` | `f7715f8fcba61809` | PE模块待拆 | 未验证 | I / OPEN |
| PA27 | `Universal Extractor/bin/modules/x23cat.so` | `4dfb30f74bf2e9de` | PE模块待拆 | 未验证 | I / OPEN |
| PA28 | `Universal Extractor/bin/msi.wcx` | `bcc34cb4bcdd8902` | 归档插件待拆 | 未验证 | I / OPEN |
| C01 | `UnAutoIt/UnAutoIt-windows-amd64.exe` | `020b06f1f2921c5e` | CLI脚本候选 | 未验证 | I / OPEN |
| C02 | `UnAutoIt/UnAutoIt-windows-i686.exe` | `3529ad9089f8d3bf` | CLI脚本候选 | 未验证 | I / OPEN |
| C03 | `UnFSG1.33/FSG133Unpazker.exe` | `c281c4d189058521` | CLI脱壳候选 | 未验证 | I / OPEN |
| C04 | `UnSafeDisc_4.60_fixed/UnSafeDisc 4.60 fixed.exe` | `2ed78a4e72017615` | CLI脱壳候选 | 未验证 | I / OPEN |
| C05 | `Universal Extractor/bin/7z.exe` | `9f0a1984aaf5a7e1` | 归档CLI | 未验证 | I / OPEN |
| C06 | `Universal Extractor/bin/7z_New/7z.exe` | `9f0a1984aaf5a7e1` | C05同体 | 未验证 | I / 同C05 |
| C07 | `Universal Extractor/bin/7z_Old/7z.exe` | `3a0fa7f081d3821b` | 不同版本CLI | 未验证 | I / OPEN |
| C08 | `Universal Extractor/bin/AFPIunpack.exe` | `b60807ce459bd56c` | CLI提取候选 | 未验证 | I / OPEN |
| C09 | `Universal Extractor/bin/E_WISE_W.EXE` | `f25cf0f24f9aa398` | CLI提取候选 | 未验证 | I / OPEN |
| C10 | `Universal Extractor/bin/IsXunpack.exe` | `b9b389906763dff3` | CLI提取候选 | 未验证 | I / OPEN |
| C11 | `Universal Extractor/bin/MsiX.exe` | `3598ad3754ce45e9` | CLI提取候选 | 未验证 | I / OPEN |
| C12 | `Universal Extractor/bin/NBHextract.exe` | `fa52964cd8fe0720` | CLI提取候选 | 未验证 | I / OPEN |
| C13 | `Universal Extractor/bin/RAIU.EXE` | `8dc5ab35ddc27e1b` | CLI提取候选 | 未验证 | I / OPEN |
| C14 | `Universal Extractor/bin/UHARC04.EXE` | `a45c6f7da7d9660e` | CLI codec候选 | 未验证 | I / OPEN |
| C15 | `Universal Extractor/bin/UNACE32.EXE` | `83b0d068fca69b33` | CLI codec候选 | 未验证 | I / OPEN |
| C16 | `Universal Extractor/bin/UNUHARC06.EXE` | `8405b1d1bf605b1b` | CLI codec候选 | 未验证 | I / OPEN |
| C17 | `Universal Extractor/bin/Uharc02.exe` | `570b7b5feffa88a1` | 非PE的MZ | 未验证 | I / OPEN |
| C18 | `Universal Extractor/bin/WUN.exe` | `6b78709a4160ad4f` | CLI提取候选 | 未验证 | I / OPEN |
| C19 | `Universal Extractor/bin/arc.exe` | `802695c1cba1bab7` | CLI codec候选 | 未验证 | I / OPEN |
| C20 | `Universal Extractor/bin/b1.exe` | `273306d93b850da3` | CLI codec候选 | 未验证 | I / OPEN |
| C21 | `Universal Extractor/bin/balz.exe` | `ce2a46ae7b30e2e5` | CLI codec候选 | 未验证 | I / OPEN |
| C22 | `Universal Extractor/bin/cdirip.exe` | `96f5cf7656c54fba` | CLI提取候选 | 未验证 | I / OPEN |
| C23 | `Universal Extractor/bin/clit.exe` | `54013b4c251f1923` | CLI提取候选 | 未验证 | I / OPEN |
| C24 | `Universal Extractor/bin/cmdTotal.exe` | `140b89b4beb65f4b` | WCX宿主候选 | 未验证 | I / OPEN |
| C25 | `Universal Extractor/bin/daa2iso.exe` | `d75498d5d7778ce4` | 镜像转换候选 | 未验证 | I / OPEN |
| C26 | `Universal Extractor/bin/dark.exe` | `41d93254279d21eb` | 安装包候选 | 未验证 | I / OPEN |
| C27 | `Universal Extractor/bin/i3comp.exe` | `1bccbd7cbfee153f` | CLI codec候选 | 未验证 | I / OPEN |
| C28 | `Universal Extractor/bin/i5comp.exe` | `392b8f1423cb6218` | CLI codec候选 | 未验证 | I / OPEN |
| C29 | `Universal Extractor/bin/i6comp.exe` | `8a646da25528a344` | CLI codec候选 | 未验证 | I / OPEN |
| C30 | `Universal Extractor/bin/innounp.exe` | `7d7e399f8b53d367` | 安装包候选 | 未验证 | I / OPEN |
| C31 | `Universal Extractor/bin/kgb2_console.exe` | `08979b5158708865` | CLI codec候选 | 未验证 | I / OPEN |
| C32 | `Universal Extractor/bin/less/lessmsi.exe` | `c5336c53020ec01d` | 安装包候选 | 未验证 | I / OPEN |
| C33 | `Universal Extractor/bin/lzip.exe` | `419539536dd1c44d` | CLI codec候选 | 未验证 | I / OPEN |
| C34 | `Universal Extractor/bin/lzop.exe` | `0de04c88c0820f98` | CLI codec候选 | 未验证 | I / OPEN |
| C35 | `Universal Extractor/bin/quad.exe` | `087401a585b09641` | CLI codec候选 | 未验证 | I / OPEN |
| C36 | `Universal Extractor/bin/sim_unpacker.exe` | `42ee113ddd81cb03` | 提取候选 | 未验证 | I / OPEN |
| C37 | `Universal Extractor/bin/stix_w32.exe` | `b1a011f84a0d80dc` | 提取候选 | 未验证 | I / OPEN |
| C38 | `Universal Extractor/bin/tee.exe` | `1dc4c406ca27d0c4` | 管道辅助 | 非壳codec | I / OPEN |
| C39 | `Universal Extractor/bin/trid.exe` | `c6fc405a6435efc2` | 检测器 | 非脱壳 | I / OPEN |
| C40 | `Universal Extractor/bin/uif2iso.exe` | `b190b6b892c64f00` | 镜像转换候选 | 未验证 | I / OPEN |
| C41 | `Universal Extractor/bin/unarc.exe` | `09ea4478b379a183` | CLI codec候选 | 未验证 | I / OPEN |
| C42 | `Universal Extractor/bin/unlzx.exe` | `d924011d6937a432` | CLI codec候选 | 未验证 | I / OPEN |
| C43 | `Universal Extractor/bin/unzip.exe` | `b4abd97f03f0c8c4` | CLI codec候选 | 未验证 | I / OPEN |
| C44 | `Universal Extractor/bin/unzoo.exe` | `c43d105e297f5be9` | CLI codec候选 | 未验证 | I / OPEN |
| C45 | `Universal Extractor/bin/upx.exe` | `0dbc3c267ca8cd35` | UPX 3.91实体 | 此副本未验 | I / OPEN |
| C46 | `Universal Extractor/bin/uudeview.exe` | `e829d5cfc0000363` | 编码提取候选 | 非PE壳候选 | I / OPEN |
| C47 | `Universal Extractor/bin/zpaq.exe` | `e81cd149bb1ab2f8` | CLI codec候选 | 未验证 | I / OPEN |

## 内层组件卡（不是外层之外再加一个引擎）

路径根 `资料/reverse/rlde-family/`；完整 hash、zlib raw 起点、字节数与 consumed 在 `mt27-research/container-verification.json`。版本均为 GUI 标题声明；golden 均无。N01–N05 的依赖是 N08/N09+N11+N12。

| ID | 成员精确路径 | SHA16 | 真实职责 | 研究 / 复刻 |
|---|---|---|---|---|
| N01 | `rlde-aspack--RL!deASPack 2.x.exe` | `90d44f0dc8b2a66b` | 专壳断点GUI | F/A05 / OPEN |
| N02 | `rlde-mew--RL!deMEW 1.x.exe` | `e08bc7cd8f22a189` | 专壳断点GUI | F/A06 / OPEN |
| N03 | `rlde-nspack--RL!deNsPack 3.x.exe` | `59fe021138775660` | 专壳断点GUI | F/A07 / OPEN |
| N04 | `rlde-pex--RL!dePeX 0.99.exe` | `de8e737fff4a1d05` | 固定布局多阶段断点 | F/A08 / OPEN |
| N05 | `rlde-packman--RL!dePackMan 1.x.exe` | `a2e410b599d4f58a` | 模式扫描多阶段断点 | F/A09 / OPEN |
| N06 | `rlde-upx--RL!deUPX 1.x-2.x.exe` | `baf25539f808ac02` | 四锚+静态OEP驱动（MT29 拆解） | F/A10 / OPEN |
| N07 | `rlde-packer-x86--RL!dePacker.exe` | `8782a3b882059ab3` | 保护中通用候选 | I/A11 / BLOCKED |
| N08 | `rlde-aspack--Debugger.dll` | `f05efa3321cb6391` | Win32事件/INT3/上下文 | F/A02 / OPEN |
| N09 | `rlde-pex--Debugger.dll` | `531942e2701ed661` | 调试库不同build，需差分 | I/A02 / OPEN |
| N10 | `rlde-upx--Debugger.dll` | `a81c2eba49c578fa` | 调试库不同build，需差分 | I/A02 / OPEN |
| N11 | `rlde-aspack--Dumper.dll` | `a23183af8089caac` | 远程映像→raw=RVA PE | F/A03 / OPEN |
| N12 | `rlde-aspack--Importer.dll` | `b9a195ddcf9ed7ad` | 名字/序号/IAT槽重建 | F/A04 / OPEN |
| N13 | `mt29-rlde-fsg/rlde-fsg--RL!deFSG 2.0.exe` | `f4307f224ea3cfa4` | 双探针+OEP=[EBX+0xC] 驱动（MT29 提取+拆解） | F/A37 / OPEN |

## 独立算法、驱动与格式工作包

`R` 指本轮函数报告；`GUI` 指 `gui-unpackers-reverse.md`；`GEN` 指 `generic-unpacker-claims.md` 的具体证据而非其泛化结论。没有 fixture 的工作包不得写 V。既有产品代码的支持只来自其实现报告，不反向升级本归档对应 GUI。

| ID | 工具/哈希引用、目标版本 | 依赖 | 核心算法 / 下一阶段卡 | 证据 | 研究 / 复刻 | 验证样本 |
|---|---|---|---|---|---|---|
| A01 | G50–G58，自解压容器 | zlib标准库 | 有界成员定位、长度、字节和校验；补G51/G55容器分支 | R§2，container-verification | A / 研究提取完成 | 25成员复算；无GUI运行 |
| A02 | N08–N10 | Win32上下文/事件 | INT3保存恢复、EIP修正、一次/持久BP；不同build差分 | R§3 | F / OPEN | 无动态事件golden |
| A03 | N11、G42 | A02或外部dump | SizeOfImage捕获、OEP、raw=RVA、头/节序列；加边界重建 | R§3 | F / OPEN | 无RL动态fixture |
| A04 | N12、G42 | 函数名/序号与原槽 | IJID/ILT/hint/name与不连续IAT拆模块；原创静态构造器验收 | R§3 | F / OPEN | ASPack/MEW新引擎64函数是独立实现，不是N12验收 |
| A05 | N01，ASPack 2.x声明 | A02–A04 | 三扫描点+回调读寄存器、OEP立即数、dump/import | R§4 | A / OPEN动态驱动 | 无原GUI逐版golden |
| A06 | N02，MEW 1.x声明 | A02–A04 | JMP跟随、四断点、DLL/API/OEP回调 | R§5 | A / OPEN动态驱动 | 无原GUI逐版golden |
| A07 | N03，NsPack 3.x声明 | A02–A04 | 61 9d e9链、DLL/API模式、分支OEP | R§6 | A / OPEN | 无NsPack golden |
| A08 | N04，PeX 0.99声明 | A02–A04 | 固定EP偏移与解包后寄存器偏移安装下一组BP | R§7 | A / OPEN | 无PeX golden |
| A09 | N05，PackMan 1.x声明 | A02–A04 | 五扫描锚、五BP及API/OEP阶段 | R§7 | A / OPEN | 无PackMan golden |
| A10 | N06，UPX 1.x–2.x声明 | A02–A04 | 四探针（50 83 c7 08/50 47/57 48/e9）+OEP=e9+rel32+5 静态计算；已拆完回调（mt29-rlde-upx-engine） | R§8b | F / OPEN | 无RL!deUPX执行验收 |
| A11 | G23/G55/G56/N07 | 外层保护恢复 | 还原真实驱动表/识别库，逐driver另建卡 | R§9 | I / BLOCKED | 无名单/独立golden |
| A12 | G47，tElock宣称 | 多态数据层恢复 | L1–L4 四层算术已全解（密钥/窗口在案）；loader核心定位（SEH+kernel32回走+0x436624 aPLib族codec）；仿真路线另立项 | R§8a，mt29-telock | A四层 / BLOCKED(loader) | 972+723次变换日志，内层无golden |
| A13 | G21，ORiEN宣称 | 常量word恢复 | 66次变换→aPLib loader；0x42807a INC [ESP] 前状态需重建（chase.py 栈模型已可表达该指令），工作量阻塞 | R§8，mt27-rlde-orien | A局部 / BLOCKED | 固定decoder字节，内层无golden |
| A14 | G11，EA06 | 17-word PRNG | LCG seed、ROL9/13、两tap递减及浮点字节映射 | R§10 | A / OPEN | 无EA06原始脚本oracle |
| A15 | G11，EA06容器 | A14 | FILE/UTF16元数据解密、脚本标记定位、长度XOR、Adler32 | R§10 | A / OPEN | 无多记录/截断golden |
| A16 | G11，EA06 codec | A15 | MSB16桶、literal、15bit距离、分档长度与重叠copy | R§10 | A / OPEN | 无压缩script oracle |
| A17 | G11，AU3 token | A16 | 整数/浮点/UTF16 XOR字符串/运算符/换行→文本 | R§10 | A / OPEN | 无Unicode/token roundtrip oracle |
| A18 | G16，1.0/V1.2冲突 | LZMA1、filter、注入宿主 | 外层已解码/过滤；补正确内层导入/调用链、RemoteMain协议与专壳修复，单独核RemoveNAG | R§9，eunpacker-lzma.json | A外层/F架构 / OPEN | raw1226125字节，4661分支；没有专壳golden |
| A19 | G62，版本未知 | `.zzage`外层恢复 | 跟随入口/解码器/目录污染点，再确认伪装还原语义 | R§9 | I / BLOCKED | 原文件hash已验 |
| A20 | G22/G60，PEArmor/Hying 0.46声明 | 独立许可codec | 固定aPLib-like字节流；移植边界与token语义 | R§11、GUI§4 | A / OPEN | 无PEArmor golden |
| A21 | G22，导入/指令修复 | A20 | 记录DLL/API，FF15/FF25修复；补槽与名字/序号样本 | R§11 | F / OPEN | 无PEArmor IAT oracle |
| A22 | G22，PE写回 | A20/A21 | 分块映像、OEP、节布局/头/资源重建 | R§11 | F / OPEN | 无完整产物oracle |
| A23 | ASPack输入ep437 build | MIT Huffman参考 | 721/28/8/19 canonical字典、delta/repeat、history-LZ、有界更新 | R§12 | V / CANDIDATE | lbop20五块75168字节；稳定74844=100% |
| A24 | ASPack输入ep437 build | A23 | 精确锚、真实表、12byte块表、CALL/JMP、ILT/IAT/OEP/头 | R§12，aspack.js | V / CANDIDATE | .text45568=100%，2DLL/64函数 |
| A25 | ASPack旧六布局及2.11多态头 | A23，单独样本 | 各布局定位验证；2.11另解头，不复用现代offset | aspack-implementation旧布局表 | I / OPEN | 缺独立逐build golden |
| A26 | MEW11 SE loader | 现有FSG aPLib codec | 分块链与零填充loader目标、scattered bit helper | R§13 | V / CANDIDATE | 两loader1118/1335字节，消耗602/1076 |
| A27 | LZMA1 props5e lc4/lp0/pb2 | SDK public-domain格式 | range/model/literal/reps/距离、无EOS精确长度、终态code=0 | R§13，lzma.js | V / CANDIDATE | Python/liblzma独立向量+MEW raw |
| A28 | MEW11-SE-154 | A26/A27 | 有界list容器、压缩长度、imports/OEP与专用PE头 | R§13，mew.js | V / CANDIDATE | .text45568=100%；全payload与liblzma稳定字节100% |
| A29 | MEW10/11 non-SE | A26，版本化适配 | 连续源流/目的表/不同OEP字段及导入；独立fixture闭环 | mew-implementation参考分支 | I / OPEN | 当前明确拒绝 |
| A30 | MEW11 SE special/BCJ | A27 | 单块容器、byte-swap E8/E9恢复；独立BCJ oracle | MIT xmew.cpp | I / OPEN | 当前明确拒绝 |
| A31 | G26，Petite level1–9 | 许可/固定样本 | 块表、literal XOR、距离/长度、filter/import/TLS | GUI§3 | A局部 / OPEN | 缺逐level golden |
| A32 | G26，Petite level0 | 单独decoder | 不与level1–9混用，参数/版本化字段逐项验证 | GUI§3 | I / OPEN | 缺golden |
| A33 | G34，UpxUnpacker0.2 | 安全静态codec替换 | POPAD/RET patch + CALL输入stub必须替换；纯元数据另验 | GUI§5 | A / OPEN | 未运行原GUI |
| A34 | UPX NRV2B/2D/2E | RetDec MIT | 现有codec/限定PE驱动复用，归档GUI不反向升级 | upx-implementation | 既有产品 / 待GUI适配 | 项目既有NRV corpus |
| A35 | UPX LZMA/其他格式 | 官方工具来源或A27 | 外部官方路线与浏览器静态路线分开验收 | upx-implementation | 官方既有 / JS OPEN | 不把原归档upx.exe当发行件 |
| A36 | FSG1.31/1.33 | MIT reference | 既有aPLib/头/资源/TLS/导入复用 | fsg-implementation | 既有产品 / 待GUI适配 | 项目既有golden131/133 |
| A37 | G51、FSG2.0 | G51内层提取 | 内层已提取拆解（N13：ad 50/ff 63 0c 50 双探针、OEP=[EBX+0xC]）；静态codec布局仍需2.0样本 | R§8b，mt29-rlde-fsg | F / OPEN | 缺2.0 golden |
| A38 | MPRESS LZMAT | RetDec MIT | 既有LZMAT、filter、import及PE布局 | mpress.js | 既有产品 / 无GUI新增声明 | 项目既有fixture |
| A39 | MPRESS LZMA（含G61外层） | A27，格式证据 | 依据实际stub定位容器，不继续无锚暴力扫props | GEN§1 | I / OPEN | 缺匹配外层golden |
| A40 | G03/G66/G64 | Win32调试宿主 | 线程/异常/远程内存及配置分支，按A路证据推进 | GUI§6、armadillo-themida-unpackers | F / A路在途 | D未独验专用驱动 |
| A41 | G02/G20/G63 | NanoLib/Disasm | Nanomites分类、条件/目的恢复与patch | A路指定证据 | 在途 / 未计完成 | 按A回执独验 |
| A42 | G71/VUnpackSDK | x86执行模型/影子API | 解释器、内存/SEH、API环境、OEP回调 | GEN§4 | 架构F / B路在途 | 不从125计数推版本支持 |
| A43 | G71/unpack.avd | 已验证库格式 | 解密驱动/签名库，逐条命名去重再建算法卡 | GEN§4 | I / BLOCKED | avd plaintext名单未知 |
| A44 | G68/G69 | 指令执行/异常宿主 | 精确跟踪IAT/stolen bytes/受保护区，按C路证据推进 | C路指定证据 | 在途 / 未计完成 | 不推断Themida全版本 |
| A45 | G08/PC01–41 | 宿主ABI/ImpREC | 宿主→每插件入口、辅助插件与目标驱动区分；PC逐件验收 | E0、GEN§5 | I / OPEN | 无41插件golden |
| A46 | G27/PA/PU/C | 安装包格式/codec许可 | 分发与提取边界、流长度、文件名安全、实际decoder ABI | E0 | I / OPEN | 各组件独立oracle待补 |
| A47 | G30/G32/G61/C39 | 检测签名/脚本库 | 提取真实签名库与检测语义，明确不是解包算法 | E0、GEN§1 | I / OPEN | 不计脱壳支持数 |
| A48 | G19，Molebox2.x声明 | 资源/虚拟FS/codec | 函数追踪确认“static”路径、虚拟文件格式及重建 | archive-inventory静态线索 | I / OPEN | 未验样本/授权 |

## 下一窗口优先卡与接入

1. **A24/A28 接入卡（M）**：注册两个引擎，MEW parser fallback 放在严格 parsePE 失败后；Web/HTTP/MCP/catalog 的允许值和告警同步；独验25项并补实际入口测试。
2. **A12/A13/A11**：A12 四层数据已全解、loader 核心已定位——后续属仿真路线（emulated-pe32 家族），不再按纯静态卡推进；A13 需重建 0x42807a 前状态；A11 保留已还原层的 hash/word轨迹，恢复内层后再拆目标壳驱动。不能用外层codec冒充该GUI的功能。
3. **A14–A17**：取合法 EA06 源脚本/编译产物对，先补 PRNG/Adler/LZ/token 四个独立 oracle，再实现有界 AU3 提取。
4. **A05–A09**：依赖 A02–A04 的事件/寄存器契约，按本报告固定扫描点分别实现 driver；当前新静态 ASPack/MEW 不覆盖这些原GUI动态流程。
5. **PC01–PC41 与尚未 F 的 G 卡**：用唯一 ID/hash 逐件排；同一壳名的插件仍须先确认真实路线，不推“纯静态”或“只能dump”。

`ASPACK_ENGINE / supportsAspack / unpackAspack`、`MEW_ENGINE / supportsMew / unpackMew / parseMewPE` 为本轮产品接入清单；`decodeLzma1` 是零 DOM、无 Node 依赖的共享 codec 候选。全程原工具、原 DLL、重建 PE 均未运行；研究目录排除发行。
