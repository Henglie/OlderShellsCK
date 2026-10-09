# Bounded FSG static analysis engine

Status: integrated into the shared registry, Web, HTTP and MCP; import table rebuilt since 2026-10-05, output grade `rebuilt-pe`, targeted verification PASS.

## Delivered scope

- Engine `fsg-pe32`: pure JavaScript, PE32 x86 EXE, vetted **1.31 and 1.33 plaintext loader stubs**, two-section packed layout, SectionAlignment `0x1000`, FileAlignment `0x200`.
- Real aPLib-style decoding, per-stream consumed byte counts, original section RVAs from the support list, OEP recovery and a conventional on-disk PE.
- **Import table reconstruction**: the stub's extra compressed import stream (DLL names, function names with variant-specific first-byte markers, per-DLL original IAT RVAs) is decoded and rebuilt as a fresh `.idata` section plus IAT thunk arrays at their **original RVAs**, with data directory 1 (and 12) pointing at them. Output grade is `rebuilt-pe`; `runtimeVerified` stays `false`.
- TLS, relocations, original headers/permissions/disk layout are **not** restored. `rebuilt-pe` means structurally complete import reconstruction, **not** a verified runnable image; no path claims runtime verification.
- FSG 2.0 and other 1.x stubs remain unsupported. The selected corpus has two usable 1.31/1.33 files. `Lab18-02.exe` has an older `BB…BF…BE`/call-based loader, **not a 2.0 `87 25` loader**, and is a negative engine fixture. File names/family membership do not establish a supported variant.
- Both positive fixtures pack the same original program. They prove two different loader/support-table paths, not two diverse application payloads or broad FSG compatibility.
- Import-tail layouts are strict: a 1.31 word list without exactly one `1`-record (import destination), or a 1.33 dword tail without destination/flag/second-function-table entries, is rejected rather than downgraded; both vetted samples carry the full tail and upgrade. A malformed import blob (bad markers, unterminated or unprintable names, overlapping/misplaced IAT ranges) throws instead of guessing.

Files:

- `src/core/codecs/fsg.js`
- `src/core/unpackers/fsg.js`
- `tests/fsg.test.js`
- `scripts/fetch-fsg-fixtures.mjs`
- `licenses/xstaticunpacker-MIT.txt`
- this document and the shared registry `src/core/engines.js`

## API

```js
import { decompressFsg } from './codecs/fsg.js';
import { supportsFsg, unpackFsg, parseFsgPE, FSG_ENGINE } from './unpackers/fsg.js';

// Input is the precise stream or a tail containing concatenated streams.
// Capacity is a ceiling, not an expected decompressed length.
const { bytes: decoded, consumed } = decompressFsg(input, maxOutput);

// Structural probe: catches malformed/unsupported layouts and returns false.
// It does not decompress or promise that a payload is intact.
const supported = supportsFsg(bytes, pe);

const result = unpackFsg(bytes);
// result.bytes: independent Uint8Array
// result.metadata: {
//   engine: 'fsg-pe32', variant: '1.31' | '1.33',
//   outputKind: 'rebuilt-pe', runtimeVerified: false,
//   originalEntryPoint: <RVA>, importedModules: <rebuilt count>, warnings: [...]
// }
```

`parseFsgPE(bytes)` is an explicit FSG-only input fallback, returning a PE-compatible summary and bounded `rvaToOffset`. It checks the complete supported loader and support layout before returning. Packed imports are not enumerated (`imports: []`); that empty list is not a count of the original program's imports. `unpackFsg` independently validates input and does not trust an externally supplied PE summary.

### Explicit input-layout adapters

The actual fixtures are deliberately nonstandard:

1. **1.33:** `e_lfanew = 0x0c`; PE fields overlap unused DOS fields. Shared `parsePE` correctly refuses `invalid-pe-header` under its generic contract.
2. **1.31:** packed source starts at raw `0x200`, while `SizeOfHeaders = 0x400`. Actual section-table end is `0x188`; only slack is overlapped. Shared `parsePE` refuses `section-overlaps-headers`.

The FSG reader allows these specific structural features only with the vetted full stub, nonoverlapping actual section-table bytes, contiguous bounded destination/source virtual extents and validated indirect decoder addresses. Header RVA mapping stops at `min(SizeOfHeaders, source.rawOffset)`; it never aliases the packed raw data. No shared parser file was modified.

`analyze` routes through the registry's explicit fallback; registering only the unpacker would leave these real inputs inaccessible. A simplified single-family route is:

```js
import { supportsFsg, unpackFsg, parseFsgPE, FSG_ENGINE } from './unpackers/fsg.js';

function parseInput(bytes) {
  try { return parsePE(bytes); }
  catch (strictError) {
    if (!supportsFsg(bytes)) throw strictError;
    return parseFsgPE(bytes);
  }
}
```

Use `parseInput` only for input analysis. Generated outputs use `parsePE(result.bytes, MAX_OUTPUT)` and pass the unchanged strict parser. Candidate flag: `fullValidationAtUnpack: true`. A structurally valid stub can still have a corrupt stream or an OEP in undecoded zero-fill; those fail during unpacking.

## Decoder and bounds

The codec implements literal tokens, long gamma-coded matches, repeat-distance matches, short matches/EOS, four-bit one-byte matches and zero literals. Back-copy permits overlap. Distance-length adjustments use `0x7f`, `0x500`, `0x7d00` as in the pinned MIT implementation.

- Input is a `Uint8Array`, at most `67108864` bytes (64 MiB).
- Capacity is an integer in `[0, 134217728]` (128 MiB). A nonempty decoded stream cannot fit capacity zero.
- Output grows with actual data rather than eagerly allocating an untrusted virtual-size field.
- Every byte/tag fetch, output write and back-reference is checked. Distances must be positive and at most bytes already produced. No wraparound arithmetic for gamma values or VA/RVA subtraction.
- Gamma accumulation is limited to `MAX_OUTPUT + 2`; every nonterminal token emits at least one byte, bounding token iterations by `maxOutput + 1`.
- Each EOS is mandatory and returns the exact number of source bytes consumed, including tag and terminator bytes. Remaining source bytes belong to another stream or to packed metadata.
- Support scans/section count are capped at 96. The support region is at most `0x10000` bytes and remains within mapped header slack.
- Stream input is bounded before the loader's entry-point raw offset. Neither stub bytes nor overlay can supply missing compressed bytes.
- The import blob is the final aPLib stream and must end exactly at the stub's raw entry offset. Its decode capacity is the remaining virtual span of the hosting stream past the last decoded byte. Records are bounded: at most 256 modules, 4096 functions per module, 16384 functions and 1 MiB of names total; every name is NUL-terminated, printable and at most 512 bytes.
- Rebuilt IAT arrays must each fit inside one decoded stream's virtual span past that stream's decoded content, be disjoint from each other and from the stub's import-blob scratch range, and stay inside the packed image's destination space. Violations throw; nothing is relocated by guesswork.
- Each output stream is capped by the distance to the next distinct destination RVA. All destination extents are disjoint and inside a bounded PE image. Aggregate serialized output including headers/padding must fit 128 MiB.
- Indirect decompression addresses are checked: 1.33's table points to EP+187/175/177; 1.31's bit-reader immediate points to EP+143. Fixed stub instructions are matched in full, not just the opening opcode.
- OEP comes from the anchored conditional branch, with a signed displacement, and must map to **actually decoded bytes**, not just a virtual range.
- Fresh PE headers expose the decoded sections plus one synthesized `.idata` section; data directories 1 and 12 are set, all others cleared. Strict output parsing must report no warnings, a mapped entry point, and an import list identical (DLL names and function-name order) to the blob records.

Codec errors include `invalid-input`, `input-size-limit`, `invalid-output-limit`, `truncated-input`, `invalid-back-reference`, `output-limit`, `fsg-integer-overflow`. Container-specific rejections include `unsupported-fsg-layout`, `invalid-fsg-stub`, `invalid-fsg-pointer`, `invalid-fsg-support`, `invalid-fsg-destination`, `invalid-original-entry`, `invalid-image-base`, `invalid-import-hints`, `overlapping-iat`, `import-limit`, `output-validation-failed`, plus existing PE/alignment/size error codes. Errors use the shared `AnalysisError` API.

## Stub import-data layout

The loader stub rebuilds imports at runtime from data the packer left in the packed image; the engine mirrors that layout statically:

- After the last section stream the stub decompresses **one more aPLib stream** (the import blob) into free zero-fill of the destination section. Its destination RVA comes from the support table: in 1.33 it is the dword following the section-list terminator (then a literal `1` and a second function-table pointer); in 1.31 it is the dword of the single word-list `1`-record.
- Blob grammar: `0x01`, IAT VA (little-endian, image-based), DLL name `NUL`, repeated function names each `NUL`-terminated, then the next `0x01` record; a final terminator byte ends the list.
- Each function name's first byte is the original character **plus a variant-specific offset** (1.33: `+2`, repaired by the stub's two `dec byte ptr [esi]`; 1.31: `+3`, three decs). The terminator byte equals that offset (`0x02` / `0x03`), and `0x01` marks a new DLL.
- The IAT VA per DLL is the **original** FirstThunk RVA; rebuilt thunk arrays are written back at exactly those RVAs so absolute `call dword ptr [IAT]` references in decoded code stay valid. The engine additionally synthesizes descriptors, OriginalFirstThunk arrays, hint/name entries and DLL-name strings in a new `.idata` section and points data directory 1 at the descriptor array (directory 12 covers the IAT span).
- Independent oracle: the blob's 11 DLL records and 343 function names match the published golden image's import directory exactly for both samples (same DLL order, same name order per DLL), including repeated DLLs with distinct IAT ranges.

## Source provenance and license history

Implementation reference is **horsicq/XStaticUnpacker**, pinned revision:

`746fb24433c29b6460edebac83fdad19909d9e81`

- [xfsg.cpp](https://raw.githubusercontent.com/horsicq/XStaticUnpacker/746fb24433c29b6460edebac83fdad19909d9e81/xfsg.cpp), Git blob `0ce7f46165db5b684e4adedae03de19f9e3984a0`.
- [xfsg.h](https://raw.githubusercontent.com/horsicq/XStaticUnpacker/746fb24433c29b6460edebac83fdad19909d9e81/xfsg.h), Git blob `59f968057694c9a11df9fb32b5adcb76ee7a1178`.
- [LICENSE](https://raw.githubusercontent.com/horsicq/XStaticUnpacker/746fb24433c29b6460edebac83fdad19909d9e81/LICENSE), Git blob `e1f34b8f165bdd5304a612f7b0dde3f6ba037313`. Local `licenses/xstaticunpacker-MIT.txt` has this identical Git blob hash.

Source headers say `Copyright (c) 2017-2026 hors<horsicq@gmail.com>` and MIT; those notices remain in both JS modules. The repository LICENSE has `Copyright (c) 2019-2026 hors<horsicq@gmail.com>`; its full, unchanged text is included separately.

History checked via GitHub's commit/file APIs:

- Repository initial LICENSE at `3961b9abb1b4ddb66da98329db61cb7ff41303a7` (2025-08-27) was already MIT (`Copyright (c) 2025 Hors`). Later license-path commits are `4c8da5ea7ba941137beec8138f22541d2a65ed2c` and `a05ff64f0bcc7eea73868dd92680137153e7e925` (copyright updates).
- `xfsg.cpp` and `xfsg.h` were **added** in `c1633b9bcae7482dfae037f8efb531ac61baf3f8` (2026-07-24). Initial blobs were `65105a8e4a470d462f5f089011d705becd460d45` and `83766fb5ea4ce53d24b61374fe884382355c01ae`; both initial source headers already declared MIT.
- The initial `xfsg.h` described 1.33/2.0 as unverified and explicitly said its clean-room implementation learned the format from GPL libclamav references. The pinned header retains that provenance statement and adds earlier FSG generations.

This project adapts that MIT source, not GPL ClamAV or unipacker implementation code. The upstream clean-room statement is an upstream attribution claim, not a separately proven legal conclusion. The documented GPL reference was not copied into this implementation. Test bytes come from a separate research corpus and are not relicensed as Apache/MIT.

XStaticUnpacker attribution is included in `NOTICE`; `licenses/xstaticunpacker-MIT.txt` is distributed with bundled engine code.

## Reproducible corpus and independent oracle

Corpus: [unipacker/unipacker](https://github.com/unipacker/unipacker), pinned `160baa9447c91d53b75e5e108b196d389fa0b06e`.

The fetch script embeds fixed raw URLs, expected lengths, SHA-256 and Git-blob SHA-1, checks all three before writing, bounds response lengths/timeouts and retries transport failures at most three times. It stores a generated `manifest.json` with the same provenance. No sample or decoded PE is executed.

| Local file | Pinned upstream path | SHA-256 |
|---|---|---|
| `fsg131.bin` | `Sample/FSG/unpackme- FSG 1.31 - dulek.exe` | `28bdbc5f4268464845940e0e7c5c473af9cc1562ce573ce7a8050c3da024611b` |
| `fsg133.bin` | `Sample/FSG/unpackme- FSG 1.33 - dulek.exe` | `31889f7e66102544c199eb1fe3454641accf7844909b4252e9d9076b4a5803b1` |
| `golden131.bin` | `Tests/UnpackedSample/FSG/unpacked_unpackme- FSG 1.31 - dulek.exe` | `91b9912775aca11b09633fb4913032900ac5fac56571db9021fa8786150f7df0` |
| `golden133.bin` | `Tests/UnpackedSample/FSG/unpacked_unpackme- FSG 1.33 - dulek.exe` | `717b82d5f602b7001720223cfbf2f2366a3680346ea146e06bf7b3be9d9cf6ed` |
| `lab18-02.bin` | `Sample/FSG/Lab18-02.exe` (negative) | `7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec` |

The corpus repository is GPL-2.0; sample rights are separate and no redistribution grant is inferred. All downloaded bytes, generated output, local research scripts and manifests live under the existing git-ignored `test-results/fixtures/fsg/`. No corpus bytes are embedded in shipping source or fixtures synthesized by an encoder mirroring this decoder.

For **each** 1.31/1.33 sample the following decoded ranges equal the independently published unpacked golden, byte for byte:

| Destination RVA | Packed file offset | Compressed bytes consumed | Decoded bytes compared |
|---|---:|---:|---:|
| `0x1000` | 5796 | 133630 | 258920 |
| `0x41000` | 139426 | 1550 | 3419 |
| `0x46000` | 140976 | 12616 | 18344 |
| `0x4c000` | 153592 | 4410 | 14643 |

Total: **295326 bytes per sample**, not merely a code prefix. Original entry point `0x40300` also matches each golden. The two packed files happen to contain identical compressed payload streams; their loader stubs, headers/support lists and published golden file hashes differ. Golden comparisons do not claim equality for original headers, dynamic imports/TLS, undecoded virtual gaps or whole PE files. Additionally the rebuilt import DLL set and per-DLL function-name sets equal the golden import directory for both samples (asserted order-independently in tests; the golden's own IAT holds runtime-resolved addresses and its descriptors carry dump-specific RVA-valued fields, so byte equality there is neither possible nor claimed).

Current `unpackFsg` output for each sample: **311296 bytes**, five sections (`.fsg0`–`.fsg3` plus `.idata` at RVA `0x51000`), data directories 1/12 set, `importedModules: 11`. Both samples yield byte-identical outputs with SHA-256 `a84982b5a1334ff58da3b5b4b635c4246d2c635d2df17a3839f13de0be54c67d`. The superseded analysis-only output was 296960 bytes with SHA-256 `14de2e063bab5b5fa0c30fcb8f29317bfcfb1b2ea3199881616fb74a99db819e`; that digest is historical. Output digests are observations of this engine, **not** the independent oracle. `verification.json` records separate golden/decoded region hashes and metadata; `verify.mjs` reproduces the current artifacts (its `analysis-*.bin` filenames predate the upgrade and are regenerated on each run).

### Verification run

```text
node scripts/fetch-fsg-fixtures.mjs
node scripts/fetch-fsg-fixtures.mjs --verify
node --test tests/fsg.test.js
```

Node `v26.4.0`; targeted test run **12/12 PASS, 0 SKIP**, about 0.4 seconds. Fixtures are read-only test inputs. Missing fixtures explicitly skip dependent tests and print the fetch command; corrupt fixtures fail hash checks rather than skipping. Public-core/interface/browser integration has separate coverage in `tests/engines.test.js` and the browser suite; those files still pin the old `analysis-pe` grade for FSG and require a coordinated mainline update.

Additional negative coverage: all 1550 truncated prefixes of a real stream; 1024 PE prefixes and late truncations; wrong code/decoder pointers; wrapped/unaligned/out-of-image offsets; invalid support lists; unsupported machine/DLL/.NET; bad backreferences; gamma overflow; input/output caps; OEP in zero-fill; appended overlay isolation; precise typed-array subviews; 512 deterministic malformed streams; input immutability and repeat-output independence; corrupted import-blob bytes, missing 1.33 import-tail dwords and zeroed/misplaced 1.31 import-destination records.

## Capabilities and presentation

`supportsFsg`/`unpackFsg` are registered as `fsg-pe32`; input analysis has the FSG-only parser fallback. Capabilities/catalog:

```js
{
  id: 'fsg-pe32', family: 'FSG', architecture: 'x86',
  status: 'experimental', mode: 'static-js',
  variant: 'PE32 EXE / FSG 1.31, 1.33 / vetted plaintext stubs',
  outputKind: 'rebuilt-pe', runtimeVerified: false
}
// Catalog family id 'fsg': stage 'experimental', same limited variant text.
// The static registry define in src/core/engines.js still advertises the old
// analysis-pe grade; unpacker metadata is authoritative and flows through
// unpack/HTTP/MCP responses (mainline registry text update pending).
```

`rebuilt-pe` means the import directory, IAT and hint/name structures are fully reconstructed and the output parses cleanly; it does **not** mean the output was executed or verified runnable. `runtimeVerified` remains `false` and the UI must keep that distinction visible. `supportsFsg` returning true does not promote all FSG detections to supported.

Warning keys emitted by `unpackFsg`: `relocations-not-restored`, `original-headers-not-preserved`, `section-layout-and-permissions-inferred`, `runtime-not-verified`, plus conditional `tls-not-restored`, `overlay-not-preserved`, `signature-removed`, `fsg-overlapping-dos-header`, `fsg-overstated-header-size`. The former `analysis-only-not-runnable`, `imports-not-rebuilt` and `data-directories-cleared` keys are no longer emitted by FSG (translations remain in the shared i18n registry for other engines):

| Key | 中文 | English |
|---|---|---|
| `relocations-not-restored` | 重定位未恢复 | Relocations were not restored |
| `original-headers-not-preserved` | 使用新分析头，原始 PE 头未保留 | Fresh analysis headers replace original PE headers |
| `section-layout-and-permissions-inferred` | 节布局和权限为分析用途推定 | Section layout and permissions are inferred for analysis |
| `tls-not-restored` | TLS 未恢复 | TLS was not restored |
| `fsg-overlapping-dos-header` | FSG 的 PE 头与 DOS 字段重叠 | FSG PE header overlaps DOS fields |
| `fsg-overstated-header-size` | FSG 声明头大小覆盖了部分压缩数据 | FSG declared header size overlaps packed data |

Also retain existing `runtime-not-verified`, `overlay-not-preserved`, `signature-removed`. Display `originalEntryPoint` as an RVA; `importedModules` counts modules actually rebuilt (11 for both vetted samples). The bounded fallback's packed `imports: []` is not an import-recovery claim; only `unpackFsg` output carries rebuilt imports.

Remaining work: vetted 2.0 fixture/oracle, additional programs/options, TLS and relocation reconstruction, preservation of original directory/layout semantics, and any authorized runtime verification. Import/IAT reconstruction is delivered as described above; none of the remaining items is represented as completed, and **no output is claimed runnable (`runtimeVerified: false`)**.
