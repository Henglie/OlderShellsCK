# NsPack 3.7 bounded static unpacker

Status: engine implemented and golden-pinned against one real packed sample; **not yet registered** in `src/core/engines.js` (registration belongs to M). Output grade `analysis-pe`, `runtimeVerified: false`.

## Delivered scope

- Engine `nspack-pe32`: pure JavaScript, PE32 x86 EXE, the single **DIE "NsPack 3.7" direct-entry stub** (`9c60e8..8bc5` pattern, `.nsp0/.nsp1/.nsp2` three-section layout, entry inside `.nsp1`).
- Two-stage codec chain, E8/E9 call-redirect restore, OEP from the stub's final `jmp`, import rebuild from the decompressed-tail walk records into a synthesized `.idata` with **original IAT RVAs preserved**, packed-header resource directory carried at its original RVA.
- Every anchor below is driven by exactly one sample: `资料/老旧壳脱壳工具/UnObSiDium/UnObSiDium.exe`
  sha256 `5292383439ca10f357c2fa3cc64047bbe1fcffe3ccb70ce2dfd5e66469612cda`
  (the tool distributed packed with NsPack 3.7). Other builds (2.9/3.1/3.3/3.5/3.6 stubs, multi-record tables, the `[ep-0x118]` runtime header-patch path, the `[ep-0x130]` relocation walker) are **rejected, not guessed** (`unsupported-variant`).

Files:

- `src/core/unpackers/nspack.js`
- `tests/nspack.test.js`
- this document
- reverse evidence: `资料/reverse/t42-nspack/` (sample-unobsidium, blob-wrapper, blob-ghidra, nspack-dll, wnspack; Ghidra 12.1.2 exports with per-artifact sha256 in each `verification.json`, all `passed: true`)

## Evidence grading

| Claim | Grade | Anchor |
| --- | --- | --- |
| Stub pattern, entry-relative anchors (`-0x184` table ptr, `-0x174` delta store, `-0x13c/-0x134/-0x133` fixer count/tag/mode, `-0x118` patch flag, `-0x130` reloc walk, `-0x100` body dest, `-0x17c` walk base, `+0x272` OEP jmp) | sample-verified | all exercised by the end-to-end unpack of the pinned sample; stub bytes in `sample-unobsidium/instructions.tsv` (58 file-backed rows for the 0x4fb6dc..0x4fb919 region) |
| Stage-1 codec grammar (tag byte = 8 data bits MSB-first, recycled carry never a data bit; literal / `10 g` long / `110 b` short / `111 n` nibble tokens; gamma; distance-conditional length increments) | golden-verified | `decodeNsPackBlob` on sample bytes `[entry+0x3c9 .. +0x53d]` (call-site math `(entry+0x62)+0x367 = VA 0x4fb9c1`) yields byte-exact equality with the Ghidra-staged blob artifact: 1681 bytes, sha256 `b1b221f80fe379b3a5d7e5fc1b8c1ea0d06afcf99d5de8f10b43a55f259417f8`, consumed `0x53d` exact |
| Stage-2 body codec = LZMA1, record config byte = props byte | sample-verified | `decodeLzma1(props=0x5d→lc3/lp0/pb2, dict=destLen)` decodes 452821 → 1024000 bytes with `consumed === srclen`; shared transcription `src/core/compression/lzma.js` |
| Redirect restore: e8/e9-only scan, tag filter in mode 1, chained byte after a patched rel32 sharing the count budget (`LOOP 0x4fb6f6`), fixer struct at `entry-0x144` | instruction-verified | `sample-unobsidium/instructions.tsv` rows 0x4fb6dc..0x4fb730; file bytes re-checked against the sample (`8db5bcfeffff .. e2c6`) |
| Mode-0 value = `bswap32(rel)` | instruction-verified, **not sample-exercised** | `86c4 c1c010 86c4` (XCHG AH,AL; ROL EAX,16; XCHG AH,AL) ≡ bswap32; sample runs mode 1, so this path is covered by synthetic vectors only |
| Mode-1 value = `bswap24(rel>>8)` | **data-anchored inference** (see below) | empirical: 1066/1066 candidate sites patch in-body to 323 distinct targets, all within the first 64 KB; 18.7 % of targets begin with a push prologue vs 0.0 % for a +0x50000 control shift |
| Import-walk record layout (`size/dllOff/iatRva/nameAreaOff` + length bytes; unseparated name concatenation; `0xff` first byte = ordinal dword, high bit cleared; `size = 0x11 + n`) | sample-verified + inferred details | layout yields the plausible 10-module/124-function import set (two KERNEL32/USER32/GDI32 groups, Delphi-style tool) on the sample; exact field semantics beyond what the sample exercises are treated as this-build constants |
| `NAMES_BASE_DELTA = 0xe6e` (dll-name base = `ep_rva - 0xe6e`) | this-build constant | derived from the single sample; rejected if names fall outside the body |

### Unresolved micro-detail (documented honestly)

The mode-1 byte twiddle in the listing at `0x4fb70b..0x4fb712` is `66 c1 e8 08 / c1 c0 10 / 86 c4`
(SHR AX,8; ROL EAX,16; XCHG AH,AL). Under strict 16-bit zero-extension semantics this yields
`((rel>>8)&0xff)<<16`, which collapses all 1066 patches to a single target — impossible for the
shipped, working tool. The implemented value `bswap24(rel>>8)` is the one the packed data demands
(see grading row above); the discrepancy between the instruction trace and the data is **not
resolved** and is the first thing to re-examine when a second NsPack 3.7 sample arrives.

## Pipeline

1. `supportsNsPack(bytes, pe)`: PE32 EXE, exactly `.nsp0/.nsp1/.nsp2`, DIE 3.7 entry pattern, `e9` OEP jump at `entry+0x272`, `[ep-0x174] == ep_rva`, `[ep-0x100] == .nsp0.rva`, mode byte ≤ 1. `unpackNsPack` re-runs this and adds: no PE warnings, `.nsp0`/`.nsp2` raw-empty, entry inside `.nsp1`, header-patch flag ≠ 1, reloc-walk size 0.
2. Record table at `[ep-0x184]` (relative): dword 0 selects the single-record form; record `{u8 props, u32 srclen@+5, u32 destlen@+9, data@+0xd}`; `destlen` must equal `.nsp0.virtualSize`.
3. Stage 2: `decodeLzma1(data, destlen, { props, dictionarySize: destlen })`, `consumed === srclen` enforced exactly.
4. Redirect restore over the body (`restoreNsPackRedirects`) with `{count: [ep-0x13c], tag: [ep-0x134], mode: [ep-0x133]}`; every patched target validated in `[destRva, destRva+destlen)`.
5. OEP = `entry+0x272+5+rel32`.
6. Import walk (`parseNsPackImportWalk`) over records at `[ep-0x17c]`, names at `ep_rva-0xe6e`; IAT ranges validated inside the body and non-overlapping.
7. Output: headers copied, sections rewritten `.nspbody`/`.rsrc`(if carried)/`.idata`, dirs 2/12 preserved-or-cleared, import dir 1 → synthesized `.idata`, output re-parsed with `parsePE` and cross-checked (module/function counts must match) before returning.

Error codes are stable `AnalysisError` codes (`unsupported-variant`, `truncated-nspack-record`, `decoded-size-mismatch`, `invalid-nspack-redirect-count`, `invalid-nspack-redirect-target`, `invalid-nspack-import-walk`, `invalid-nspack-table`, `invalid-nspack-resource`, `invalid-original-entry`, `output-validation-failed`, codec-level `invalid-back-reference` / `truncated-input` / `output-limit` / `nspack-integer-overflow`).

## Honest boundary

- `outputKind: analysis-pe`; **never executed**, `runtimeVerified: false`, fixed image base.
- Not restored: original section table (flat body emit), base relocations, TLS, debug directory, load configuration, bound imports, certificates, overlay.
- Stage 1 (codec-blob replay) is **not on the unpack path** — the stub only needs it to reconstruct its compression DLL at runtime; it is exposed as a tested pure function because it is the strongest independent evidence anchor for the family's LZ grammar.
- Single-sample engine: any deviation from the anchors above rejects rather than downgrades. No claim about NsPack 2.x/3.x-other builds is made anywhere.

## Registration line for M (engines.js)

```js
define({ id: 'nspack-pe32', family: 'NsPack', catalogId: 'nspack', variant: '3.7 DIE entry stub; single-record LZMA1 body; flat rebuild', outputKind: 'analysis-pe' }, supportsNsPack, unpackNsPack),
```

Detect-side hint already exists: `src/core/detect.js` maps section name `nsp0` → NsPack; catalog id `nspack` is present in `src/core/catalog.js`.

## Tests (`tests/nspack.test.js`, 8 tests)

1. engine surface + rejects (broken stub → `unsupported-variant`; garbage → `not-pe`).
2. stage-1 golden blob replay (consumed exact, sha pinned, byte-equal to the staged artifact).
3. codec literal/short/nibble/nibble-0/terminator vectors (decoder-faithful MSB-first bit encoder).
4. codec gamma/long/repeat + the five distance-conditional length increments.
5. codec fail-closed matrix (back-reference, truncation, gamma overflow, output limit, input validation).
6. redirect restorer: mode-1 value/tag-filter/chained, mode-0 bswap32, validation errors.
7. import walk: records, ordinals, terminator, bounds, size consistency.
8. end-to-end: sample sha-pinned, output sha `5bd7156d47d8b60217288a98e89864a269ae09f433b20eda4c1e452ea60e7b55`, OEP `0x295c`, 10 modules / 124 functions, 1066 redirects, `lc=3 lp=0 pb=2`, sections `.nspbody/.rsrc/.idata`, import list asserted.

Research-artifact-dependent tests skip cleanly when `资料/` items are absent; the synthetic-vector tests always run.
