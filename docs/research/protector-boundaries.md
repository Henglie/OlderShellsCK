# Protector boundaries: what one-click unpacking can and cannot reach

Research note for the graded capability model. Sources: our DIE rule corpus
(docs/research/die-and-packers.md), GUI unpacker disassembly
(docs/research/gui-unpackers-reverse.md), archive inventory, and publicly
documented community knowledge about each protector line. This is a research
boundary table, not a per-version test matrix.

## Grading model

| Grade | Meaning |
| --- | --- |
| `rebuilt-pe` | Full structural rebuild; sample-accepted on a real machine |
| `dump-pe` | Runtime image captured at the OEP; IAT rebuilt to disk form where possible |
| `extract-pe` | Protected sample captured at a fixed stage; memory image analyzable, sections and data extractable; full restoration not guaranteed |
| analysis-only report | Static structural report; no execution |

## Boundary table (research assessment)

| Protector line | One-click rebuild realistic up to | Beyond that line |
| --- | --- | --- |
| UPX (all) | All formats its own decoder accepts (`upx-official`) | nothing beyond; LZMA builds included |
| FSG 1.31/1.33 | Both variants, sample-accepted | no later versions exist |
| MPRESS 2.12–2.19 | Verified 2.19 stub-0x29f layout | other stub/fix pairs need per-variant work |
| ASPack 2.1x–2.3x | Not statically anchored (no plaintext compB in modern builds) | dynamic route (`dump-pe`) applies once OEP is known |
| PECompact 2.x | Community tools exist; ours: research only | dynamic route applies |
| NsPack / Upack / RLPack / tElock / PELock | Detection subset only | dynamic route applies |
| MEW 10/11 SE | Not implemented (LZMA1/aPLib) | dynamic route applies |
| ASProtect 1.2–1.3 | Historical tools dumped + rebuilt IAT semi-automatically | 2.x: import redirection and stolen bytes defeat automatic IAT rebuild; target grade `extract-pe` |
| Obsidium / EXECryptor / ACProtect | No automatic rebuild known | anti-debug (PEB probes covered by our patch; API-level checks partially); target grade `extract-pe` |
| Armadillo (standard) | Community dumps exist for old builds | copy-memory/anti-debug layers; professional builds add code splicing; `extract-pe` at best |
| 穿山甲 Pangolin | No static or one-click route known | code mutation + IAT obfuscation + anti-debug; `extract-pe` when the sample survives our contained run |
| Themida / WinLicense | unlicense handles 1.x–2.x builds with SDK markers | 2.x+ virtualization: only `extract-pe` plus manual devirtualization; 3.x often detects contained debuggers |
| VMProtect 1.x–2.x | Partial devirtualization research-grade only | 3.x: `extract-pe`; virtualized sections stay opaque |
| Enigma Protector | unpacker tools for old 1.x–2.x exist | 3.x+: `extract-pe` |

## What "extract" means in this product

`dynamic-debug-dump` with `mode: "extract"`:

1. Contained run (DEBUG_ONLY_THIS_PROCESS + Job Object kill-on-close + timeout).
2. Anti-anti-debug v0: PEB.BeingDebugged and PEB.NtGlobalFlag are zeroed at
   the 32-bit initial breakpoint, defeating IsDebuggerPresent and
   NtGlobalFlag probes used by most legacy protectors. Kernel probes
   (ProcessDebugPort/ProcessDebugObjectHandle) are not covered yet.
3. Capture the whole image at a fixed delay after initialization, plus the
   module export map (`<out>.imports.json`) so import references remain
   analyzable.
4. Output grade `extract-pe`: analyzable memory image; sections and data
   extractable; no rebuild claim.

Sample result on this machine: the UPX fixture captured in extract mode
yields the same unpacked image as the OEP-timed dump, which validates the
capture path; protector-specific behavior will vary and is reported honestly
per sample.
