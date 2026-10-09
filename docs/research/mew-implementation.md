# MEW engine research status

Status: researched, **not implemented as an unpacking engine** in this round (2026-10-05).

## Why

The permissive reference is [horsicq/XStaticUnpacker](https://github.com/horsicq/XStaticUnpacker)
`xmew.cpp/h` at commit `746fb24433c29b6460edebac83fdad19909d9e81` (MIT,
`licenses/xstaticunpacker-MIT.txt`). Two compression paths exist:

- **MEW 10 / MEW 11 (non-SE):** an aPLib-style bitstream structurally close to
  the FSG codec this project already ships (`src/core/codecs/fsg.js`). Porting
  is straightforward once a vetted fixture confirms the loader layout.
- **MEW 11 SE:** a stock LZMA1 stream (range coder + probability model,
  props byte `0x5E` = lc4/lp0/pb2, no end marker) framed by a small MEW
  container after the aPLib loader loop, plus an optional x86 call/jmp
  de-filter in "special" mode. The reference delegates decoding to the
  public-domain LZMA-SDK `LzmaDec`. This project has no LZMA decoder yet;
  a future port may adapt RetDec's MIT `lzma_data.cpp` (already pinned for
  the MPRESS LZMA branch) instead of the SDK.

Detection anchors (from the reference `_detect`): a bare `jmp rel32` (or
`xor eax,eax; jmp`) entry whose target is file offset `0x154/0x155/0x158`,
a loader beginning `mov esi, imm32` whose following two bytes separate
MEW 10 (`lodsb/xchg`) from MEW 11 (`mov ebx,esi`), and an empty-destination
section pair.

## Corpus evidence

`scripts/fetch-mew-fixtures.mjs` pins `Sample/MEW/lbop20_MEW.exe` from
unipacker `160baa9447c91d53b75e5e108b196d389fa0b06e`
(SHA-256 `42e83208184d5ef0ebfced4347540b4629fe2d6c901295dd0dc9eb18a5b96af5`).
Static bytes only, never executed. The file shows the classic MEW layout
(empty `MEW` destination section, one packed source section, `jmp rel32`
entry) and is kept as detection-scope evidence until an engine exists.
No `Tests/UnpackedSample/MEW` golden exists at that commit, so even a
future aPLib-path engine must first source independent goldens.

## Product behavior

- Detection: the DIE subset's MEW branches are covered by the original-script
  metadata-agreement tests (`tests/die-entry.test.js`).
- Analysis: the pinned sample carries `e_lfanew = 0x0c` (PE header overlapped
  with unused DOS fields, the same trick as FSG 1.33). With no registered MEW
  engine there is no vetted layout adapter either, so the strict parser rejects
  it with `invalid-pe-header` instead of guessing.
- Unpacking: no MEW engine is registered; `unpack` is refused.
- A future engine must keep MEW 11 SE LZMA and aPLib paths separate, add its
  own bounded header adapter (like FSG's), label output `analysis-pe`, and
  validate against independently published goldens.
