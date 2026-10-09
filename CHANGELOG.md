# Changelog

Application versions are maintained in `package.json`. This file records historical milestones; it is not a second runtime version source.

## 0.0.1 — Initial technical preview — 2026-10-05

### Added

- A shared, DOM-free JavaScript core for PE inspection, attributed detection and experimental static unpacking, used by the browser, HTTP API and MCP.
- PE32 / PE32+ structural reports with SHA-256, entropy, sections, ordinary imports, directories, entry point, overlay and warnings.
- A pinned MIT-licensed Detect It Easy rule subset: 44 FSG entry-point patterns, selected UPX entry branches and the MPRESS DOS-stub branch. Section-name heuristics are reported separately.
- A real MPRESS PE32 LZMAT pipeline for stub `0x29f`, fix `0x35`, from the RetDec 2.12–2.19 source family. Includes bounded decoding, CALL/JMP restoration, OEP/import reconstruction and structural output checks.
- Browser modules using official Google Material 3 components, Material Symbols Rounded icons and HCT-based themes; Chinese/English, system/light/dark appearance, fixed brick-red seed, top navigation and Worker-based file processing.
- Loopback HTTP capabilities/analyze/unpack endpoints and official MCP SDK stdio tools using base64 content rather than arbitrary local paths.
- Node-based command declarations and verification scripts, a separately fetched real MPRESS fixture, and research reports covering 34 grouped candidates and a 340-file archive inventory.
- Complete Apache-2.0 project license and third-party attribution for Material, Lit, DIE, RetDec, MCP SDK and Zod.
- FSG 1.31/1.33 and limited UPX NRV2B static analysis-PE engines; independent decoded/code-region golden comparisons and explicit missing-structure metadata.
- Registry-driven automatic/explicit engine selection across Web, HTTP and MCP; separate analysis-only output labels and downloads.
- Seven-family DIE subset, including 37 direct-entry patterns for ASPack/Petite/MEW/PECompact with original-rule metadata checks.
- Reproducible Ghidra static-analysis scripts and a five-tool GUI unpacker study with independently verified instruction/CALL evidence.

### Validation scope and remaining work

- Browser entry/build integration, three-engine Playwright coverage, and an optional static-only Python launcher are included. The browser suite verifies official components, localization, appearance, local processing, real-sample reconstruction, downloads and malformed input handling.
- One MPRESS 2.19 fixture has been structurally reconstructed: OEP `0x1110`, four imported modules. Output is `rebuilt-pe`, with `runtimeVerified: false`; no runtime equivalence or byte-for-byte restoration claim is made.
- MPRESS DLL, TLS, PE32+, .NET, LZMA and unimplemented stub/fix variants are unsupported. The 2.12–2.19 label identifies a source branch, not a fully tested version interval.
- FSG and UPX return `analysis-pe`, not runnable reconstructions; both use narrow known-stub input adapters and retain the strict shared output parser. NRV2D/2E codecs are not advertised as PE support.
- Full DIE-compatible host functions, the complete DIE engine/database, WASM delivery, additional unpacking engines and a broader versioned dataset remain future work. Research entries are not shipped support.
- This initial milestone is a technical preview; release publication and platform acceptance are separate from the existence of this changelog entry.
