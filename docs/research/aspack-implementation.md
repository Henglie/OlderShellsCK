# ASPack engine research status

Status: researched, deliberately **not implemented as an unpacking engine** in this round (2026-10-05). No supported-version claim is made.

## Why

The only permissive-licensed reference implementation is
[horsicq/XStaticUnpacker](https://github.com/horsicq/XStaticUnpacker) `xaspack.cpp/h`
at commit `746fb24433c29b6460edebac83fdad19909d9e81` (MIT, `licenses/xstaticunpacker-MIT.txt`).
Its own header notes the code was not validated against real samples, and its
detection keys on three anchors per stub generation:

1. an exact entry-point signature,
2. a `push 0; ret` marker (`68 00 00 00 00 c3`) at an EP-relative offset,
3. a plaintext 0x72-byte constant decoder table (`compB`) at an (EP-1)-relative offset.

The table below is the vetted layout set from that source (2.11/2.11c rows
require the XEmulator x86 emulator to decrypt a polymorphic stub head and are
out of scope for a static-only engine):

| Version | Signature | marker (EP+) | blocks (EP-1+) | stride | strMlt | compB | wrkbuf | OEP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2.12 | `60 e8 03 00 00 00 e9 eb` | 0x3b9 | 0x57c | 8 | 0x70e | 0x6d6 | 0x148 | 0x39b |
| 2.2 | same | 0x414 | 0x5d0 | 12 | 0x6ca | 0x692 | 0x145 | 0x3f6 |
| 2.xx | same | 0x41f | 0x5d8 | 12 | 0x76a | 0x732 | 0x13a | 0x401 |
| 2.42 | same | 0x42b | 0x5e4 | 12 | 0x776 | 0x73e | 0x148 | 0x40d |
| 2.00 | `60 e8 70 05 00 00 eb` | 0x4fb | 0x0de | 8 | 0x623 | 0x5eb | 0x292 | 0x0d2 |
| 2.01/2.1 | `60 e8 72 05 00 00 eb` | 0x4fd | 0x0de | 8 | 0x625 | 0x5ed | 0x294 | 0x0d2 |

## Corpus evidence

Pinned by `scripts/fetch-aspack-fixtures.mjs` (static bytes only, never executed):

- `Sample/ASPack/lbop20_aspack.exe` from unipacker `160baa9447c91d53b75e5e108b196d389fa0b06e`,
  SHA-256 `a7a2f792185842ea20f100f8a0059842bc299a2e5c0318751840fdd38224800a`.
  DIE identifies it as ASPack **2.12-2.42**, but its marker sits at EP+0x437
  and its stub contains no plaintext compB table, so **none** of the six vetted
  layouts match. The correct engine answer is `unsupported-variant`.
- `Tests/UnpackedSample/ASPack/unpacked_lbop20_aspack.exe` (same commit) is a
  memory-dump golden; it cannot upgrade a packed input to a supported variant.

Six additional modern ASPack files from
[packing-box/dataset-packed-pe](https://github.com/packing-box/dataset-packed-pe)
(`packed/ASPack/`) were probed during research and discarded: all showed the
2.xx marker with plausible OEPs but no plaintext compB table anywhere in the
file — modern builds do not carry the constant table the vetted layouts anchor
on. Deriving fresh per-build layouts would require per-stub reverse
engineering with independent goldens; that work is not represented as done.

## Product behavior

- Detection: the DIE subset reports ASPack (14 direct-entry branches plus the
  `.aspack`/`.adata` section-name heuristic at low confidence).
- Unpacking: no ASPack engine is registered. `unpack` on ASPack input returns
  `unsupported-variant`; the report's `candidates` stay empty. Guessing a
  layout without the compB anchor risks restoring a wrong OEP.
- A future engine must port the Huffman decoder, the six vetted layouts,
  block-table loop, call/jmp unfilter and `_buildPE`-style analysis output,
  then validate each accepted layout against independently published goldens
  before raising `analysis-pe`.
