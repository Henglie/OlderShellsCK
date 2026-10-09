# OlderShellsCK · 老壳通解机

[中文](README.md) · [API / MCP](docs/API.md) · [Architecture](docs/ARCHITECTURE.md) · [Changelog](CHANGELOG.md)

A local-first workbench for PE analysis and static unpacking, for binary analysts and AI tools. The browser, HTTP API and MCP share one JavaScript core.

**This is a technical preview, not a completed all-in-one unpacker.** It integrates ten engines — three limited-variant static chains (MPRESS, FSG, UPX) plus seven server-side routes (official UPX tool, dynamic debugging, emulation, exception observation, ASPack, MEW, Armadillo) — and a DIE rule subset spanning seven families. The complete DIE engine, WASM and other variants remain future work. [package.json](package.json) is the single maintained source of the application version; interfaces report it at runtime.

## Implemented capabilities

- **Static PE inspection:** PE32 / PE32+ headers, architecture, entry point, sections, ordinary imports, data directories, overlay, SHA-256, file/section entropy and structural warnings.
- **Attributed, limited detection:** 44 FSG patterns, 61 direct-entry patterns across ASPack/Petite/MEW/PECompact/RLPack/tElock/PELock/NsPack/(Win)Upack, selected UPX entry branches and the MPRESS DOS-stub branch from a pinned DIE revision. Relative-jump patterns and full script semantics are not included. Section-name heuristics are separately labeled `section-heuristic`. No match does not prove a file is unpacked.
- **Real MPRESS reconstruction:** `mpress-pe32-lzmat` decodes LZMAT in JavaScript, restores CALL/JMP operands, OEP and imports, rebuilds the on-disk PE layout and checks the resulting structure.
- **FSG/UPX analysis extraction:** `fsg-pe32` recovers 1.31/1.33 decoded content and OEP; `upx-pe32-nrv` supports a verified NRV2B short-stub path with CALL/JMP, OEP and import restoration. These outputs are explicitly `analysis-pe`, not runnable reconstructions.
- **Official UPX tool route**: `upx-official` (server-side, win32). Invokes the official `upx -d` binary via process (GPL tool, downloaded on demand, never redistributed or linked), covering every format its own decoder accepts; output `rebuilt-pe`.
- **Dynamic debugging route (contained execution)**: `dynamic-debug-dump` (server-side, win32). A Python ctypes debugger runs the sample (`DEBUG_ONLY_THIS_PROCESS` + Job Object kill-on-close + timeout) in three usages: an explicit `oepRva` captures the in-memory image at an exact OEP breakpoint, `mode: 'auto-oep'` locates the OEP automatically, and `mode: 'extract'` captures at a fixed stage (output level dump-pe → extract-pe); a lost race degrades to a late dump labeled `dump-after-entry`. Sample execution happens only under explicit user authorization.
- **Official Material 3 UI:** Google `@material/web` components, Material Symbols Rounded icons and official Material Color Utilities HCT dynamic colors; a fixed brick-red theme (seed `#8f3d33`), top navigation, Chinese / English, system / light / dark appearance. File processing runs in Web Workers.
- **Automation:** local Node HTTP API and official MCP SDK stdio tools, taking file contents as base64.

### Engine registry (10 engines)

| Engine id | Route (route/mode) | Output level | Selection | Platform |
| --- | --- | --- | --- | --- |
| `mpress-pe32-lzmat` | static-js decoding | `rebuilt-pe` | auto-detected + explicit | any (pure JS) |
| `fsg-pe32` | static-js decoding | `rebuilt-pe` | auto-detected + explicit | any (pure JS) |
| `upx-pe32-nrv` | static-js decoding | `analysis-pe` | auto-detected + explicit | any (pure JS) |
| `upx-official` | external-tool (official `upx -d`) | `rebuilt-pe` | explicit only | win32 server |
| `dynamic-debug-dump` | dynamic-debug contained execution | `dump-pe` → `extract-pe` | explicit only (`oepRva` / `auto-oep` / `extract`) | win32 + py -3.11 |
| `emulated-pe32` | emulated execution | `dump-pe` | explicit only | server (pure JS) |
| `instrumented-exception-dump` | instrument/debug observer | `extract-pe` | explicit only | win32 + py -3.11 |
| `aspack-pe32-huffman` | static-js (bounded anchor `2.x-ep437`) | `analysis-pe` | explicit only | any (pure JS) |
| `mew-pe32-lzma1` | static-js (bounded anchor `11-SE-154`) | `analysis-pe` | explicit only | any (pure JS) |
| `armadillo-nanomites` | native dynamic-debug oracle | `dump-pe` | explicit only (requires `probePlan` / `probes`) | win32 + py -3.11 |

All engines are `experimental`; `runtimeVerified` is `true` only for `mpress-pe32-lzmat`, `fsg-pe32` and `upx-official`. Automatic selection applies to the three core static chains only; the seven server-side engines always require an explicit `engine` id. Two honest notes: `instrumented-exception-dump` is an **extract-pe observer** — one-shot INT3 context observation with memory extraction and an import-snapshot repair; `oepConfirmed` is always `false` and the result never claims to be a rebuild. `armadillo-nanomites` requires an explicit `probePlan` / `probes` (without one a synthesized degrade probe runs to the timeout and still dumps); it has **no real-sample validation** — the dump-product path is untested, with only parameter validation and quick-rejection paths covered by tests.

### Exact MPRESS scope

| Item | Current status |
| --- | --- |
| Engine | `mpress-pe32-lzmat`, `experimental` |
| Input | Native x86 PE32 EXE, LZMAT, stub `0x29f`, fix `0x35` |
| Source family | RetDec's **2.12–2.19** source branch; not a tested range of every release |
| Real-file evidence | One MPRESS **2.19** fixture; reconstructed OEP `0x1110`, 4 imported modules |
| Output level | `rebuilt-pe`; `runtimeVerified: false`, structural validation only |
| Unsupported | DLL, TLS, PE32+, .NET, LZMA, other stub/fix variants and layouts outside the implementation's constraints |

### Exact FSG and UPX scope

| Engine | Accepted scope | Output and missing structures |
| --- | --- | --- |
| `fsg-pe32` | FSG 1.31/1.33 plaintext stubs; two versions of the same program | `rebuilt-pe`; import directory and IAT rebuilt at original RVAs (11 DLLs, 343 functions matching an independent golden per group); TLS and relocations remain unrestored |
| `upx-pe32-nrv` | NRV2B LE32 short EXE stub, filter `0x26`; two real files | Graded per sample: lbop20 restores resources/relocation directory and returns `rebuilt-pe` (byte-equal to its golden); lab18-01 has no directory records and returns `analysis-pe` |

Each FSG fixture has **295326 decoded bytes** matching its independent golden, with per-DLL function-name sets matching group by group. One UPX fixture's entire **45568-byte .text** plus its resource and relocation directories match an independent golden. NRV2D/2E stream decoders do not establish PE support. See [FSG](docs/research/fsg-implementation.md) and [UPX](docs/research/upx-implementation.md) for exact evidence and missing structures.

Analysis `candidates` are preliminary; full validation takes place during unpacking. All three engines are `experimental`, return `runtimeVerified: false`, and do not promise byte-for-byte restoration or runtime equivalence.

The input limit is **64 MiB**; decoding/reconstruction and internal output analysis are bounded at **128 MiB**. Query `GET /api/v1/capabilities` for the actual limits and engine descriptors.

## Run from source

Install **Node.js 22+** and npm. From the project root:

```sh
npm ci
npm run build
npm start
```

`npm install` is also available for development; `npm ci` reproduces the committed lockfile. Open <http://127.0.0.1:8787>. The Node server serves both `dist/` and `/api/v1/*`; set the `PORT` environment variable to change its port.

The browser needs ES modules, Web Workers and WebCrypto. Use HTTPS when deployed, or localhost locally. A modern browser is the host; historical Windows PE files are the analysis targets. This does not imply support for running the web app in a Win98-era browser.

### Static deployment and optional Python launcher

`npm run build` produces `dist/`, suitable for GitHub Pages or any HTTPS static host serving the files with the correct content types. The browser processes selected files directly in Workers, without an analysis API or file-content uploads. Frontend dependencies are bundled locally; no runtime CDN is required.

The optional `点我启动.py` launcher (Python 3.9+) serves an already-built `dist/` and opens the browser automatically. Run `py 点我启动.py` on Windows or `python3 点我启动.py` elsewhere. Its scope is static launching, without dependency installation, building or `/api/v1/*`. Source builds, the HTTP API and MCP require Node; Python is not a core runtime dependency.

## Use the browser

1. Choose or drop a PE file to view its structure, detection evidence and candidate engines.
2. Review detection sources and warnings; export the JSON report when needed.
3. Choose automatic selection or a candidate engine, then download the explicitly graded analysis/rebuilt PE and its JSON report.

Analysis processes bytes statically and does not execute the submitted EXE/DLL. Language and appearance preferences are stored in the local browser. API clients explicitly send content to the local Node process.

## HTTP API and MCP

```text
GET  /api/v1/capabilities
POST /api/v1/analyze
POST /api/v1/unpack
```

POST bodies use `Content-Type: application/json`, with `dataBase64`, optional `name`, and optional `engine`. Unpacking defaults to `auto` (automatic selection covers the three core static chains only); any engine id from the table above may be given explicitly, and `GET /api/v1/capabilities` is the authoritative list. Output bytes are returned as `dataBase64`; `metadata.outputKind` declares the output grade. Arbitrary local file paths are not accepted.

Example MCP client configuration; replace the placeholder with the **absolute script path**:

```json
{
  "mcpServers": {
    "oldershellsck": {
      "command": "node",
      "args": ["/path/to/OlderShellsCK/src/server/mcp.js"]
    }
  }
}
```

Tools: `list_capabilities`, `analyze_file`, `unpack_file`. Files are passed as `dataBase64`; `name` is display metadata only. MCP uses stdio and does not require a running HTTP server. See the [API reference](docs/API.md) for complete requests, results, errors and direct JavaScript use.

## Verification and fixtures

Run in order from the project root:

```sh
 node scripts/fetch-fixtures.mjs
 node scripts/fetch-fsg-fixtures.mjs
 node scripts/fetch-upx-fixtures.mjs
 node scripts/fetch-aspack-fixtures.mjs
 node scripts/fetch-mew-fixtures.mjs
 node scripts/fetch-upx-tool.mjs
 npm test
node scripts/check-mpress.mjs
```

Fetch scripts pin upstream commits, lengths and SHA-256 under the ignored `test-results/fixtures/` directory. Tests read bytes without executing samples; fixtures are excluded from releases. Positive fixtures comprise one MPRESS, two FSG and two UPX files, including malware-lab data used only for static validation. This is not exhaustive version coverage.

Browser checks use Playwright across Chromium, Firefox, WebKit and a mobile viewport:

```sh
npm run build
npx playwright install chromium firefox webkit
npm run test:e2e
```

These are reproduction commands; the test output from a particular run is the record of its results.

## Research and staged roadmap

 - [Full DIE and historical packer research](docs/research/die-and-packers.md): **34 grouped candidates**, with source code, revisions, licenses, versions, execution modes and output levels.
 - [Full static archive inventory](docs/research/archive-inventory.md): **340 files, 253 PE files and 64 candidate family names**. **42** names have tool-path/plugin evidence; **22** appear only in accompanying author test claims.
 - [GUI tool disassembly](docs/research/gui-unpackers-reverse.md): actual Ghidra disassembly/selected decompilation on five original files; 126008 instruction byte sequences and 8988 direct CALL displacements independently verified. Some GUI tools execute the input stub even without creating a process.
  - [ASPack status](docs/research/aspack-implementation.md) / [MEW status](docs/research/mew-implementation.md): the research conclusion is that layouts outside the safety anchors must never be guessed — detect and refuse. An exact ep437 sample was later obtained, and `aspack-pe32-huffman` (`2.x-ep437`) and `mew-pe32-lzma1` (`11-SE-154`) are now implemented with bounded anchoring: decoding starts only when the anchors hit, and outputs match an independent golden section by section.
 - [Protector boundaries](docs/research/protector-boundaries.md): the graded capability model (rebuilt-pe / dump-pe / extract-pe / analysis-only) and a research table of where one-click rebuilding realistically stops for each protector line.

These are research and inventory counts, not supported-packer counts. The target research scope runs from the Win9x era through candidates existing by the end of 2025; research dates and archive listing dates are recorded separately.

1. **Dataset and acceptance baseline:** expand provenance-tracked benign MPRESS fixtures, recording version, architecture, algorithm, settings and hashes. Validate structure and actual runtime behavior separately.
2. **DIE-compatible detection:** implement the required format objects, address conversion, search, disassembly, script loading and result host functions. Differentially test against pinned DIE engine/database revisions before extending coverage claims.
3. **More static engines:** recover FSG imports and UPX resources/relocation directories, extend MPRESS variants, and validate ASPack/Petite/PEArmor against suitable licenses, complete stubs and independent fixtures. Detection and unpacking receive separate acceptance criteria.
4. **WASM and extensions:** introduce reproducible headless WASM builds where performance warrants them, with dependency-license review. Define bundle extraction, emulation and native debugging as separate capabilities.

## Layout and license

```text
src/core/          Universal JS analysis, detection, decoding and reconstruction
src/web/           Official M3 UI, HCT themes and Web Workers
src/server/        Node HTTP, MCP, job Workers and transport serialization
vendor/die/        Pinned original rules, derived entry patterns, manifest, MIT text
licenses/          Original RetDec / XStaticUnpacker MIT licenses
scripts/           Build, fixture, inventory and verification scripts
tests/             Core, interface and browser tests
docs/              API, architecture and complete research reports
dist/              Build output (ignored)
test-results/      Test output and downloaded fixtures (ignored)
资料/             Private research material (ignored, not distributed)
```

Copyright 2026 Henglie. Project code is licensed under the full [Apache-2.0 license](LICENSE); see [NOTICE](NOTICE) for third-party attribution and terms. Official Material Web is currently in **maintenance mode pending new maintainers**, as recorded in its upstream README.
