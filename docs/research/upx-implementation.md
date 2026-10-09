# Bounded UPX PE32 NRV implementation

## Delivered scope

The engine grades its output per sample. When the packed file's own data-directory records for **resources (index 2)** and **base relocations (index 5)** are present, map fully into the third (auxiliary) section's raw span, and pass bounded structural validation, they are restored as recorded and the result is a **`rebuilt-pe`**. When any recorded directory is unsatisfiable — or the layout is anything other than the validated one — the engine falls back to the previous **`analysis-pe`** behavior with those directories cleared and an explicit warning. It never guesses a layout, and it does not claim a runnable executable, the original disk image, or all UPX versions. The static `UPX_ENGINE.outputKind` remains the guaranteed floor `analysis-pe`; per-sample results may exceed it.

- Pure JavaScript NRV2B, NRV2D and NRV2E **LE32 stream decoders**.
- PE integration accepts **NRV2B only**, with the exact short EXE decoder, filter `0x26`, import stub and either of the two auxiliary tails observed below. The entire decoder is matched, with only its address operands variable. The two tails are the fixed-base exit and the byte-swapping relocation loop followed by that exit.
- A present packheader must be format `9`, version byte **13**, method `2`, filter `0x26`, with the modulo-251 header checksum. These are container fields, not a claim about a UPX release number.
- A missing packheader is accepted only with the same complete known stub, mandatory NRV end marker, original-header trailer, import hints and agreement between the trailer OEP and the final stub jump. Metadata explicitly reports `packheader-absent-no-checksum`.
- Section names do not establish support. This covers the renamed sections in `Lab18-01.exe`.
- Directory restoration covers only records pointing into the auxiliary section's raw data: the packer's uncompressed `.rsrc` copy (resource tree plus blobs at the RVAs the packed header records) and the packer's own stub relocation block. The original pre-pack relocation *table* is not byte-recoverable (only the delta hints survive), and the decompressed stream's copy of the original resource section is zeroed by the packer; both facts are documented rather than papered over.
- NRV2D/2E have hand-derived stream-vector coverage, **not real PE fixture acceptance**. PE integration rejects their method IDs. No LZMA, PE32+, DLL, .NET, TLS, exports, delay imports, altered/unknown stubs, older packheader formats, other filters or generic heuristic fallback is advertised.

## API and integration

```js
import {
  UPX_ENGINE, parseUpxInput, supportsUpx, unpackUpx,
} from './unpackers/upx.js';

const pe = parseUpxInput(bytes);
if (supportsUpx(bytes, pe)) {
  const result = unpackUpx(bytes);
  // result.bytes: independent Uint8Array, parseable PE32 disk layout
  // result.metadata.outputKind: 'rebuilt-pe' or fallback 'analysis-pe'
  // result.metadata.runtimeVerified === false
}
```

`supportsUpx(bytes, pe?)` is a preliminary, noexcept boolean probe. It never means decompression or reconstruction has succeeded. `unpackUpx(bytes)` reparses and validates the input, and throws the existing `AnalysisError` for malformed or unsupported data.

The metadata contract includes:

```json
{
  "engine": "upx-pe32-nrv",
  "variant": "PE32 NRV2B LE32 / short EXE stub / filter 0x26",
  "outputKind": "rebuilt-pe",
  "runtimeVerified": false,
  "originalEntryPoint": 4690,
  "importedModules": 2,
  "decompressedSize": 93445,
  "compressedSize": 35651,
  "restoredCalls": 1019,
  "relocatedPointers": 1676,
  "restoredDirectories": { "resource": "restored", "relocation": "restored" },
  "unrestoredMetadata": [
    "original-section-layout", "debug-directory",
    "load-configuration", "bound-imports", "certificates", "overlay"
  ],
  "warnings": [
    "runtime-not-verified", "fixed-image-base", "upx-sizeofheaders-normalized"
  ]
}
```

`restoredDirectories` reports `restored` (recorded and carried into the output), `absent` (no record in the packed header **and** none in the embedded original header — the correct empty state), or `not-restored` (a record exists but failed validation; the sample then downgrades to `analysis-pe` with `analysis-only-not-runnable`, `unrestored-metadata-cleared` and a specific reason such as `resources-unrecoverable` among its warnings). Downgrade is all-or-nothing per sample: a single unsatisfiable record drops every carried directory so the grade never overstates what the file contains.

### Explicit input-layout adapter

Both real packed fixtures declare `SizeOfHeaders=0x1000`, `FileAlignment=0x200`, `SectionAlignment=0x1000`, but their first file-backed section begins at raw **`0x400`**. The real header table fits below `0x400`. The shared parser correctly rejects these under its present strict contract with **`section-overlaps-headers`**.

`parseUpxInput` first uses the shared parser unchanged. Only for that specific error, PE32/i386, three sections, the above exact alignment/layout, and the complete supported stub does it parse a private copy with `SizeOfHeaders=0x400`. The copy is not the output artifact and the original bytes remain unchanged. Overlapping sections, header-table intersections and every other parser failure still fail. The returned PE carries `upxHeaderNormalized: true`.

The shared registry connects this adapter to input analysis before detection; otherwise both original fixtures would be rejected before `supportsUpx` is called. Normal PE inputs pass through the existing parser directly. The generic parser remains strict. `parsePE(bytes, maxBytes)` accepts the 128 MiB internal output limit; the engine validates its output with `parsePE(output, MAX_OUTPUT)`.

Registry, capabilities, UI and MCP still advertise the static floor grade (`analysis-pe`) for this engine until the shared registry metadata is updated by the mainline; per-sample results already report `rebuilt-pe` where restoration succeeds. RetDec attribution in NOTICE also applies to the codec, layout/hint handling and unfilter code.

### Codec API

```js
import { decodeNrv, decompressNrv } from './codecs/nrv.js';

const { bytes, bytesRead, steps } = decodeNrv(stream, capacity, 'NRV2B');
const decoded = decompressNrv(stream, capacity, 'NRV2E', { maxSteps: 100000 });
```

Accepted variant strings are `NRV2B`, `NRV2D`, `NRV2E`. Bits are consumed MSB-first from interleaved little-endian 32-bit control words. `capacity` is an upper bound, not an expected size. A real `0xffffffff` distance end marker is required. The codec exposes consumption instead of silently assuming all container bytes were consumed; the PE engine checks exact packheader size, or a maximum of 15 zero padding bytes before the stub.

## Reconstruction and validation

1. Validate PE identity, complete known stub and mapped source/stub extents. Require a zero-raw destination section at RVA `0x1000`, contiguous packed section, and a third auxiliary section.
2. Derive stream source and destination from stub operands; verify agreement with the section layout. If a packheader exists, check compressed Adler-32, declared lengths and decoded Adler-32.
3. Decode NRV2B with explicit read/write/backreference and operation budgets; require EOS and valid container consumption.
4. Locate the original PE header through the final decoded DWORD, not a scan for a convenient `PE` signature. Validate original sections, code extent, hints, architecture and image base. Cross-check the original OEP against the final stub jump.
5. Reverse exactly the declared number of filter-`0x26` CALL/JMP operands, bounded by the original code extent.
6. Where the known relocation tail is present, decode its bounded delta hints and restore absolute pointers at the original image base. The accepted tail explicitly byte-swaps the stored pointer values. Negative relative values can refer back into the headers. Overlapping pointer writes and unterminated hint lists are rejected.
7. Reconstruct named/ordinal import descriptors, ILTs and original IAT positions from the decoded hints and bounded packed import names. Validate total budgets and disjoint IAT extents. Append a new `.imports` section.
8. Restore the recorded resource directory (index 2) and base-relocation directory (index 5). The packed file's own directories must map entirely into the auxiliary section's raw span; the resource tree is walked (bounded node/entry/string/leaf budgets, cycle-guarded, every leaf's data RVA re-checked against the section) and the relocation blocks are checked for structure and entry types. The auxiliary section is then carried into the output at its original RVA, with its recorded name, and the two directories point back at it unchanged. Any absent record is cross-checked against the embedded original header: absence in both is the correct empty state; a record that fails mapping/validation, or an original directory with no surviving record, downgrades that sample to `analysis-pe` with the directories cleared and an explicit warning. Placement collisions between `.imports` and the carried section, or an out-of-range image end, likewise downgrade rather than guess.
9. Materialize decoded code/data into a disk-backed `.unpack` section, discard decompression/hint tails, set the recovered OEP, clear stale directories and validate the completed PE with the shared parser, including re-mapping of every carried directory in the finished file.

**Unrestored metadata is explicit.** Original section boundaries/permissions, debug directory, load configuration, bound imports, certificates and overlay are not rebuilt. The restored resource/relocation directories are the packer's *own records* (its moved `.rsrc` copy and its stub relocation block), which is exactly what the runtime image keeps — not a reconstruction of the pre-pack file's original directory values. The pre-pack relocation table survives only as delta hints; the pointers are fixed at the preferred base, dynamic-base is cleared and `fixed-image-base` remains a warning. Opaque bytes can remain in the carried section (the packer's stub import records after the resource extent). **No output is claimed runnable**: `runtimeVerified` is always `false` and `runtime-not-verified` stays in the warnings of both grades.

### Bounds

- Input: **64 MiB**; decoded capacity, image span and output file: **128 MiB**.
- Every byte/control-word read, prefix, length, backreference and copy extent is checked. Arithmetic prefixes use bounded JS numbers, not wrapping signed shifts.
- Per-decoder deterministic budget: `min(16 * (input.length + capacity) + 1024, 512 * 1024 * 1024)` operations. A caller can lower it with `maxSteps`. Counted operations include bit reads, byte reads and output bytes. All inner loops consume budget or traverse a separately bounded structure; no wall-clock assumption is required.
- Original sections: at most 96; imported modules: at most 255; functions: at most 4,095/module and 16,384 total; import strings: at most 1 MiB total, 256-byte module/512-byte function windows; rebuilt import section: at most 4 MiB; relocation pointers: at most 1,048,576.
- Directory restoration validators: resource tree at most 4,096 nodes and 65,536 entries with UTF-16 names capped at 1,024 units, every node offset, string extent and leaf data RVA bounded inside the auxiliary raw span; relocation directory at most 65,536 bytes of well-formed 4-byte-aligned blocks with entry types 0–4. Every directory record must map fully inside the auxiliary section's raw extent before anything is carried.
- No filesystem, subprocess, native addon, emulation or network use in the core engine. Fixtures are static data only.

## Actual fixture results

Run:

```sh
node scripts/fetch-upx-fixtures.mjs
node --test tests/nrv.test.js tests/upx.test.js
```

Observed on 2026-10-05, Node `v26.4.0`: **25 tests passed, 0 failed, 0 skipped**. The full suite (`npm test`, 104 tests) passes 102; the two failures are pre-existing cross-file assertions in `tests/engines.test.js` that still expect UPX results to be `analysis-pe` (see the follow-up list in the task report; those files are outside this engine's exclusive scope). Tests read only their pinned fixtures. Missing fixtures cause explicit skips with the fetch command, not synthetic replacement of the real-sample assertions.

### `lbop20_UPX.exe`

- Packed file: 38,400 bytes; stream raw `[0x400, 0x8f43)`; stub raw `0x8f50`, RVA `0x18b50`.
- Decoded stream: 93,445 bytes (`0x16d05`), original-header offset `0x16b32`.
- OEP: **`0x1252`**; 1,019 restored CALL/JMP operands; **1,676** restored relocation pointers.
- Imports: `KERNEL32.DLL` 63 functions, `USER32.dll` 1 function. All function names/order agree with the independent dump.
- Resource/relocation restoration: the packed header records resource dir `0x19000`/`0x1dc` and reloc dir `0x19298`/`0x10`, both inside the 1,024-byte third-section raw span. The resource tree is one `RT_MANIFEST` (id 1, language `0x409`) whose leaf points at RVA `0x1905c`, size `0x17d`. The relocation block is the packer stub's own four `HIGHLOW` fixups on page `0x18000`. Both directories are carried into the output unchanged; `SizeOfImage` is `0x1a000`.
- Output: **93,696 bytes**, `rebuilt-pe` (`.unpack` + `.imports` + carried `.rsrc`), no shared-parser warnings.
- Independent comparison: the **entire 45,568-byte original `.text` range**, RVA `[0x1000, 0xc200)`, equals the separately published unpacked sample byte-for-byte after unfiltering/relocation restoration. SHA-256 of both ranges: **`bc9c6394288d46d38deb5026847a4c3605eb9d6f6973bf490eb27c2cabeaf52b`**.
- The restored directories' RVA/size and bytes equal the independent dump's exactly (`0x19000`/`0x1dc` and `0x19298`/`0x10`). The golden dump is a *runtime* image: it keeps the packer's moved `.rsrc` copy, which is precisely what the restored records describe. Differences between the output and the dump inside the carried section exist only **beyond** the resource extent (`0x191dc`+), where the dump shows the stub's import thunks after runtime resolution; those bytes are inert data in the rebuilt file. The original *pre-pack* resource section (RVA `0x15000`, size `0x1e0` per the embedded header) is zeroed in the decompressed stream by the packer and is therefore not claimable; the pre-pack relocation table survives only as delta hints.
- The independent unpacked PE's import-directory size is 40 bytes despite two descriptors needing a third zero terminator. Its `import-limit` warning is documented; it is an independent code/import-content oracle, not a model of a valid rebuilt directory.
- Pre-fixup decoded SHA-256: `b9648a38169a2fa026751ec1e0ff62fcf2b7a1aed75e41becfb95b57fed8aee4`. This last digest is an implementation observation, not an independent oracle.

### `Lab18-01.exe`

- Packed file: 13,824 bytes; stream raw `[0x400, 0x31c0)`; stub raw `0x31c0`, RVA `0x9dc0`.
- Missing packheader, renamed `.text`/`.data` packed sections; exact supported NRV2B decoder/tail.
- Decoded stream: **29,793 bytes**; OEP **`0x154f`**; 209 restored CALL/JMP operands.
- Imports: `KERNEL32.DLL` 42, `ADVAPI32.dll` 2, `urlmon.dll` 1; no relocation hints.
- Directory restoration: neither the packed header nor the embedded original header records a resource or relocation directory (`restoredDirectories` reports both `absent`); its third section `UPX2` holds only the packer stub's imports and is not carried. Output: **31,232 bytes**, `rebuilt-pe`, two sections, empty directories 2/5, no shared-parser warnings.
- There is no independent full decoded golden for this second sample in the pinned directory, so its evidence is container/stub agreement and structural validation only. **The grade upgrade's evidential basis is the golden-verified `lbop20` above; `Lab18-01` demonstrates the absence-handling path, not the restoration path.**
- This is a malware-lab fixture. It was read as bytes only. Neither the packed nor unpacked executable was executed.

Other tests cover hand-derived NRV2B/2D/2E literals/EOS, explicit/reused distances, overlapping copies, extended lengths, far-distance thresholds, every truncation of small vectors, invalid references, exact typed-array subviews, all limits and 600 deterministic malformed buffers across three algorithms. PE tests cover input ownership, deterministic output, the strict header adapter, altered algorithms/filters/tails/versions, LZMA and unsupported architectures, compressed extents, corruption, overlapping sections and fixup counts, plus directory-record corruption (out-of-range RVAs, bogus tree entry counts, malformed relocation blocks) downgrading to `analysis-pe` instead of guessing.

## Reproducible corpus and provenance

Fixture repository: [unipacker/unipacker](https://github.com/unipacker/unipacker), commit **`160baa9447c91d53b75e5e108b196d389fa0b06e`**.

| Static data | Pinned raw URL | SHA-256 |
|---|---|---|
| Packed lbop20 | [Sample/UPX/lbop20_UPX.exe](https://raw.githubusercontent.com/unipacker/unipacker/160baa9447c91d53b75e5e108b196d389fa0b06e/Sample/UPX/lbop20_UPX.exe) | `e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158` |
| Packed Lab18-01 | [Sample/UPX/Lab18-01.exe](https://raw.githubusercontent.com/unipacker/unipacker/160baa9447c91d53b75e5e108b196d389fa0b06e/Sample/UPX/Lab18-01.exe) | `2ac6635a26049d354c0c46243f6451e6594b130745a08c5a99e96a64fbbbec0f` |
| Independent lbop20 dump | [Tests/UnpackedSample/UPX/unpacked_lbop20_UPX.exe](https://raw.githubusercontent.com/unipacker/unipacker/160baa9447c91d53b75e5e108b196d389fa0b06e/Tests/UnpackedSample/UPX/unpacked_lbop20_UPX.exe) | `5b8cc03b22d3bf8d00e600300ece15359dc10148d474f988b643c5ae863d0163` |

The fetch script pins both SHA-256 and size, writes `.bin` files and a URL/commit/hash manifest only under **`test-results/fixtures/upx/`**. Existing git ignore rules exclude that directory; `git check-ignore` was verified. Fixtures are not part of the distributable application and their presence does not grant redistribution rights. No unipacker implementation code was used.

### Implementation sources: RetDec MIT

Commit **`9450585772e6f1c18e5f0b2ad5518a18d6bce71e`**, Copyright (c) 2017 Avast Software:

- [NRV2B](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpacker/decompression/nrv/nrv2b_data.cpp), Git blob `81885d332f55e75d46f7bf1e6d79df96e637e68d`.
- [NRV2D](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpacker/decompression/nrv/nrv2d_data.cpp), Git blob `281b9a9d73d00e528e1f4900dd8a00007cb99c30`.
- [NRV2E](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpacker/decompression/nrv/nrv2e_data.cpp), Git blob `b30d7dc827a49e81635c5d0bbe173285afa6729f`.
- [Bit parsers](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/include/retdec/unpacker/decompression/nrv/bit_parsers.h).
- [PE decompression source/size derivation](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/decompressors/decompressor_nrv.cpp).
- [PE headers/import/relocation hints](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/pe/pe_upx_stub.cpp), and [extra-data declarations](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/pe/pe_upx_stub.h).
- [Unfilters](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/unfilter.cpp), [stub signatures](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/upx_stub_signatures.cpp), [packheader parsing/checksum](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpackertool/plugins/upx/upx_stub.cpp).
- [Pinned MIT license](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/LICENSE); existing local [`licenses/retdec-MIT.txt`](../../licenses/retdec-MIT.txt), Git blob **`bdc66a14647be44f7b3c2526925edec5f45b443a`**, retained unchanged.

The JavaScript adds strict bounds, exact variant gates and validation rather than preserving RetDec's permissive fallbacks. In particular, the pinned `setRelocationsBigEndian(bool)` implementation always sets `true`; this port establishes endianness from the accepted byte-swapping stub instead of interpreting the extra byte as a reliable endian flag.

No official GPL UPX/UCL/ClamAV implementation was copied. No official UPX oracle executable was needed or executed; the primary independent evidence is the pinned unipacker dump.
