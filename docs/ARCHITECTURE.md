# Architecture and implementation boundaries

[中文入口](../README.md) · [English overview](../README.en.md) · [API reference](API.md)

## Design

OlderShellsCK is a local-first PE analysis and static reconstruction workbench. One DOM-free JavaScript core provides the behavior for humans in a browser and automation over HTTP or MCP. The technical preview contains a seven-family DIE rule subset and three experimental static engines (MPRESS, FSG, UPX), an official M3 Web interface, a local distribution build, browser tests and an optional Python launcher.

```text
Browser: official Material Web UI + HCT themes
  -> Web Worker queue -> src/web/worker.js ---------+
                                                  |
HTTP JSON -> src/server/http.js -> Node job Worker +-> src/core/index.js
MCP stdio -> src/server/mcp.js  -> Node job Worker  |     |- PE parser / hashing / entropy
                                                  |     |- attributed DIE subset / heuristics
Direct JS caller ---------------------------------+     |- bounded LZMAT decoder
                                                         `- MPRESS / FSG / UPX pipelines
```

The browser path does not call the Node analysis API. A pure static deployment can therefore perform the implemented analysis and unpacking locally. Node is required for source builds, HTTP and MCP; Python is optional static-launcher tooling. No WASM module, native debugger, emulator or complete DIE runtime is part of the implemented pipeline.

## Modules and ownership of data

| Location | Responsibility |
| --- | --- |
| `src/core/index.js` | `capabilities`, `analyze`, `unpack`, `execute`; shared result shapes |
| `src/core/bytes.js`, `errors.js` | Bounded byte reads/writes, matching, hashing, entropy, typed errors |
| `src/core/pe.js` | PE32 / PE32+ parsing, RVA mapping, ordinary imports and structural warnings |
| `src/core/detect.js` | Selected translated DIE rules and separately attributed section heuristics |
| `src/core/catalog.js` | Research catalog; distinct from the implemented unpacker registry |
| `src/core/codecs/lzmat.js` | Bounded pure-JS LZMAT decoder |
| `src/core/unpackers/mpress.js` | Variant checks, decode/filter, imports/OEP/layout reconstruction and validation |
| `src/core/version.js` | Application version read from `package.json` |
| `src/web/` | Official M3 components, icons, bilingual presentation, theme and Worker queue |
| `src/server/transport.js` | Canonical base64 requests and serializable output bytes |
| `src/server/jobs.js`, `job-worker.js` | Node worker-thread jobs, capacity and timeout |
| `src/server/http.js`, `mcp.js` | Loopback HTTP/static serving and MCP stdio transport |
| `vendor/die/` | Seven pinned `.sg` files, derived entry patterns, manifest and original license |
| `licenses/` | Original RetDec MIT license |

Core functions consume `Uint8Array`; they do not read arbitrary filesystem paths or know about browser controls. Reports are JSON-compatible after omitting the parser's `rvaToOffset` closure. Core unpacking returns `Uint8Array` output; HTTP and MCP replace it with `dataBase64`. A caller-supplied name is display metadata, not a path capability.

## Browser presentation and computation

- `@material/web` supplies the official Material 3 Web Components. There is no separate application framework; Lit is part of the component dependency closure.
- `@material/material-color-utilities` supplies `Hct`, `SchemeTonalSpot` and `MaterialDynamicColors` for seed-derived roles. Color generation uses the official implementation; the seed is the fixed brick-red `#8f3d33`, not user-selectable.
- Material Symbols Rounded SVG paths are embedded locally. Frontend dependencies are bundled, rather than loaded from a runtime CDN.
- The interface supports Chinese and English with top navigation and system/light/dark appearance. Preferences use browser-local storage; restricted storage falls back to session behavior.
- The Worker queue runs at most `max(1, min(4, navigator.hardwareConcurrency || 2))` jobs concurrently. Each job has a 30-second budget; cancellation terminates active work and rejects queued work.
- Input `ArrayBuffer` objects are transferred into Workers. Core work stays off the UI thread, and the browser does not upload selected file contents to a remote analysis service.

Use modern browsers with ES modules, Worker and WebCrypto support, over HTTPS or localhost. Supporting a modern browser on a host OS does not establish that reconstructed Windows programs run on that OS. Official Material Web's upstream README records **maintenance mode pending new maintainers**; this is tracked as dependency status.

## Detection provenance and scope

The fixed DIE revision and original-file SHA-256 values are in `vendor/die/manifest.json`. The repository preserves twelve original `.sg` files plus the upstream MIT license; `fsg-patterns.json` derives 44 FSG patterns and `entry-patterns.json` derives 61 additional direct-entry branches.

`DIE_SCOPE` reports `engine: "die-rule-subset-js"`, `fullEngine: false`, the fixed commit and coverage:

1. FSG: 44 entry-point patterns, constrained to the implemented PE32/x86 path.
2. UPX: selected entry-point branches, excluding the patched-import heuristic.
3. MPRESS: the DOS-stub branch, not every branch of the original script.
4. ASPack 14, Petite 11, MEW 4, PECompact 8 direct-entry byte/wildcard branches. Relative-jump and quoted-byte-string patterns, post-match version overrides and fallback heuristics remain outside this adapter's scope. Generated branch metadata is checked against the pinned original scripts in isolated test contexts.

Section-name clues for other families are labeled `section-heuristic` with low confidence. They are not described as upstream DIE rule execution. Detection, candidate eligibility and full unpack validation are separate checks; none is inferred from the number of catalog entries.

Complete DIE compatibility requires more than executing `.sg` text as JavaScript. Rules depend on format objects, exact integer/address semantics, byte-pattern syntax, search, disassembly, includes, result variables and scan options. Those host functions and differential acceptance tests against a pinned engine/database remain future work.

## MPRESS reconstruction pipeline

The implemented engine is `mpress-pe32-lzmat`. The LZMAT decoder and MPRESS layout/restoration logic are adapted from the pinned MIT RetDec revision identified in [NOTICE](../NOTICE) and `licenses/retdec-MIT.txt`.

1. **Parse and select.** Require native x86 PE32 EXE and the supported entry stub `0x29f`. Reject unsupported variants; full validation rejects TLS, ambiguous PE structures and incompatible directories/layouts.
2. **Locate and bound the stream.** Resolve packed-section and fix-stub references. Check the six-byte packed header, compressed length, declared output capacity and section bounds.
3. **Decode LZMAT.** Enforce bounded input reads, output writes and back-reference distances. Require the decoded size to match the container's capacity; a decoder's end-of-stream behavior alone is not proof of container completeness.
4. **Restore code and imports.** Apply CALL/JMP operand restoration, require fix byte `0x35`, locate OEP/import hints and rebuild import descriptors, lookup tables, names/ordinals and IAT entries.
5. **Rebuild disk layout.** Put decoded content in `.unpack`, add `.imports`, calculate file/section alignment, update entry point, image/header sizes and directories. Inactive fix-stub/hint bytes remain as provenance; the entry point bypasses them.
6. **Validate output.** Reparse the PE, check warnings, mapped directories, entry-point mapping and imported module/function counts. Nonempty relocation tables require valid block boundaries, page alignment, HIGHLOW/ABSOLUTE entry types and mapped targets. The public core also generates a new analysis report for the output.

The **2.12–2.19** label identifies the upstream source family for this stub; it is not a verified interval of releases. The single real fixture is MPRESS **2.19**, with reconstructed OEP `0x1110` and four imported modules. Its evidence is structural only: `outputKind: "rebuilt-pe"`, `runtimeVerified: false`.

DLL, TLS, PE32+, .NET, LZMA, other stubs/fix variants and unsupported layouts are rejected. Overlay bytes are not preserved, the certificate directory is cleared, and byte-for-byte original-file recovery is not claimed. The current pipeline does not execute target instructions to test behavior.

### Evidence levels

These levels define acceptance criteria, not additional engines already shipped:

| Level | Evidence required |
| --- | --- |
| Detection | Attributed signature or explicit heuristic evidence |
| `payload-decoded` | A decoded stream with validated bounds/container expectations |
| `analysis-pe` | A usable analysis image, with unresolved loader/runtime structures disclosed |
| `rebuilt-pe` | Reconstructed disk PE and structural checks |
| `runtime-verified` | Recorded runtime acceptance for a particular benign sample/environment |

The current MPRESS output reaches `rebuilt-pe`; it does not reach `runtime-verified`. A future engine must retain a weaker label when its evidence is weaker.

## Engine registry and analysis-only outputs

`src/core/engines.js` owns implemented engine metadata, probes, selection and exceptional input-layout adapters. Catalog, UI and MCP enums derive from this registry. `auto` requires exactly one match; explicit IDs still undergo full validation.

Generic `parsePE` remains strict. Only complete supported FSG/UPX stubs authorize their own bounded header adapter. FSG 1.33 may use `e_lfanew=0x0c`; FSG 1.31 and supported UPX inputs can overstate header slack. Actual structure intersections and unknown stubs are not normalized. All outputs are reparsed with the unchanged strict parser.

- **FSG:** four actual decoded regions and OEP; builds fresh file-backed analysis sections, clears data directories and exposes missing import/TLS/relocation reconstruction. Both 1.31/1.33 positive fixtures match 295326 decoded bytes from independent goldens, but pack the same program.
- **UPX:** NRV2B short EXE stub, filter 0x26, bounded compressed/original-header/import/relocation hints. Restores code operands, OEP, imports and selected absolute pointers, but clears unrecovered metadata and uses a fixed image base. One entire 45568-byte code section matches an independent golden. NRV2D/2E codecs exist without advertised PE acceptance.

Both return `analysis-pe`. The UI shows a separate analysis-only message/download, and the serialized artifact metadata retains the same grade and missing-structure warnings. See [FSG](research/fsg-implementation.md) and [UPX](research/upx-implementation.md).

## HTTP and MCP

The Node HTTP service binds to `127.0.0.1`, validates local Host/Origin and fetch metadata, and confines static files to the distribution root. The MCP server uses the official SDK's stdio transport with Zod argument schemas. Both accept file bytes as canonical base64 and expose capabilities/analyze/unpack through a shared decoder, encoder and job runner.

Node jobs run in worker threads with a 30-second timeout and a per-process concurrency cap of one to four, based on `availableParallelism()`. Excess jobs return `busy`; there is no server-side persistent job queue or result store. Output is returned to the caller rather than written to an arbitrary caller-supplied path.

Public analysis accepts at most 64 MiB input; decoding/reconstruction is bounded at 128 MiB. Internal post-unpack parsing and reporting use the 128 MiB output ceiling. Import parsing additionally limits aggregate functions and name bytes, and requires strings and signatures to stay within mapped file-backed ranges. Worker memory limits and byte limits serve different purposes; neither implies unrestricted processing of every file below those sizes. See [API contracts and errors](API.md) for transport details.

## Build, version and distribution

`package.json` is the only maintained application-version source. Core/interface version fields and the browser build use it; the initial changelog heading is a historical record. Dependency resolutions and integrity hashes are tracked by `package-lock.json`.

```text
npm ci -> npm run build -> dist/ -> HTTPS static host
                            |
                            +-> npm start: static files + Node HTTP API
                            `-> optional 点我启动.py: static files + browser launch

npm dependencies + src/server/mcp.js -> MCP stdio (independent of dist/)
```

The Python launcher serves the existing `dist/` only; it does not build the app or implement the API. Static hosting can use any suitable provider. Publish the complete generated distribution with the applicable LICENSE/NOTICE material rather than extracting only JavaScript bundles.

`src/`, `scripts/`, `tests/`, `docs/`, `vendor/` and `licenses/` contain source, provenance and verification material. `dist/`, `node_modules/`, `test-results/`, Playwright output and the private `资料/` directory are ignored. Downloaded fixtures under `test-results/fixtures/` and research binaries are excluded from project releases, not relicensed under Apache-2.0.

## Verification and research baseline

Reproduction sequence:

```sh
node scripts/fetch-fixtures.mjs
node scripts/fetch-fsg-fixtures.mjs
node scripts/fetch-upx-fixtures.mjs
npm test
node scripts/check-mpress.mjs
npm run build
npx playwright install chromium firefox webkit
npm run test:e2e
```

Fixture provenance is recorded separately from test output. Core/transport/browser checks and real-file structural reconstruction do not substitute for runtime acceptance. The pinned MPRESS fixture and its source commit are identified in [NOTICE](../NOTICE); the fetch script records its SHA-256.

- [DIE and packer report](research/die-and-packers.md): 34 grouped research candidates, source/permission evidence, browser migration options and output-level distinctions.
- [Archive inventory](research/archive-inventory.md): 340 files, 253 PE files, 64 candidate family names; 42 have tool/plugin evidence and 22 only author test claims. These are inventory counts, not implemented support.
- [GUI static reverse engineering](research/gui-unpackers-reverse.md): five originals analyzed with Ghidra; raw instruction bytes and direct CALLs verified independently. Private decompilation artifacts and license-unknown code remain outside the distributable engine.

## Staged development

1. Expand the benign, provenance-tracked dataset and per-variant positive/negative tests. Record packer settings, original/packed/output hashes, structure comparisons and runtime results independently.
2. Complete DIE-compatible host functions and differential testing before expanding detection coverage. Evaluate a reproducible headless engine build separately from the pure-JS compatibility route.
3. Complete missing FSG/UPX loader structures and additional MPRESS variants. Add ASPack/Petite/PEArmor only with suitable licenses, explicit output levels and independent variant fixtures.
4. Introduce WASM where measured workloads justify it; document compiler, sources, dependency closure and reproducible builds. Keep static unpacking, bundle extraction, emulation and native debugging as separate capability classes.

Full DIE, WASM and the researched engine families are roadmap work, not functionality implied by this architecture.
