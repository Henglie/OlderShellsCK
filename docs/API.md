# API and MCP reference

[中文入口](../README.md) · [English overview](../README.en.md) · [Architecture](ARCHITECTURE.md)

The browser, HTTP API and MCP use the same operations from `src/core/index.js`. The application version comes from `package.json`; the HTTP route version (`v1`) and analysis `schemaVersion` (`1`) describe separate contracts.

This technical preview provides PE analysis and three experimental static engines: MPRESS, FSG and UPX. A detection result or research catalog entry is not an unpacking guarantee. Full DIE and WASM are not implemented.

## 1. Start the HTTP service

From the project root, with Node.js 22+, start the combined website/API service:

```sh
npm ci
npm run build
npm start
```

The default address is `http://127.0.0.1:8787`. `PORT` changes the listening port; the process binds to loopback. It serves the built `dist/` and these API routes:

| Method | Route | Result |
| --- | --- | --- |
| GET | `/api/v1/capabilities` | Core capability descriptor |
| POST | `/api/v1/analyze` | Core analysis report |
| POST | `/api/v1/unpack` | Serialized unpack result, including output bytes as base64 |

The API operations themselves use source modules and do not depend on a browser build: after dependency installation, `npm start` can serve API requests directly. A static host or the optional `点我启动.py` launcher serves only the built website; neither creates these endpoints.

The local server checks `Host`, any supplied `Origin`, and cross-site fetch metadata. Use `127.0.0.1` or `localhost` with the actual listening port. It is a loopback interface, not a public cross-origin upload service. Static routes are confined to the configured distribution root.

## 2. Request contract

POST requests require `Content-Type: application/json`. Send one JSON object:

| Field | Type | Meaning |
| --- | --- | --- |
| `dataBase64` | required string | Non-empty canonical standard base64 of the entire input file |
| `name` | optional string, at most 256 characters | Display name; defaults to `sample.exe` |
| `engine` | optional string for unpacking | Defaults to `auto`; explicit IDs: `mpress-pe32-lzmat`, `fsg-pe32`, `upx-pe32-nrv` |

`engine` has no effect on analysis. `name` is metadata, not a server-side file path. Neither HTTP nor MCP offers arbitrary local-path reads or output-path writes. Clients read their own file, encode it and decide whether to save the returned bytes.

Automatic selection requires exactly one matching engine. No match returns `unsupported-variant`; multiple matches return `ambiguous-engine` with candidate IDs. Explicit selection still performs all engine-specific validation and cannot force a wrong variant through.

Base64 must use the standard alphabet and required `=` padding, with no whitespace or `data:` prefix. URL-safe base64 is not accepted. Decoded PE input is limited to **64 MiB**. The HTTP JSON-body limit is `ceil(inputBytes / 3) * 4 + 4096` bytes, allowing base64 expansion and metadata. Fetch current limits from the capabilities endpoint rather than copying them into clients.

### Complete Node client example

Run the following as an ES module from the project root, with `npm start` running separately. It uses the separately downloaded fixture; replace that relative path with a file owned by the client. The output write is performed by this client, not by the API server.

```js
import { readFile, writeFile } from 'node:fs/promises';

const base = 'http://127.0.0.1:8787';
const dataBase64 = (await readFile('test-results/fixtures/mpress.exe')).toString('base64');

async function post(operation, body) {
  const response = await fetch(`${base}/api/v1/${operation}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(`${response.status}: ${result.error?.code ?? 'request-failed'}`);
  }
  return result;
}

const capabilities = await (await fetch(`${base}/api/v1/capabilities`)).json();
console.log(capabilities.version, capabilities.unpackers);

const report = await post('analyze', { dataBase64, name: 'mpress.exe' });
console.log(report.file, report.detections, report.candidates);

if (report.candidates.some(candidate => candidate.id === 'mpress-pe32-lzmat')) {
  const result = await post('unpack', {
    dataBase64,
    name: 'mpress.exe',
    engine: 'mpress-pe32-lzmat',
  });
  console.log(result.metadata, result.report.file.sha256);
  await writeFile('test-results/mpress.rebuilt.exe', Buffer.from(result.dataBase64, 'base64'));
}
```

A candidate can still fail full unpack validation, for example on TLS or an unsupported fix stub. Handle failure independently from detection.

## 3. Response contract

HTTP success returns the core result directly, without a `{data: ...}` or `{success: ...}` wrapper. Numbers representing RVAs, offsets and sizes are JSON numbers; `imageBase` is a hexadecimal string. Binary output is encoded only at the transport boundary.

### Capabilities

`GET /api/v1/capabilities` returns:

- `name`, `version`, `license`: application identity and current package version.
- `detection`: `{ engine, fullEngine, commit, families, coverage }`. Currently `engine` is `die-rule-subset-js`, `fullEngine` is `false`, and `families` lists seven partially covered families; the pinned commit is recorded in `vendor/die/manifest.json`.
- `limits`: `{ inputBytes, outputBytes }`, currently 64 MiB and 128 MiB respectively. Public analysis enforces the input limit; internal post-unpack validation/reporting uses the output limit. Other format, memory and timeout bounds still apply.
- `unpackers`: three implemented descriptors, each with `id`, `family`, `catalogId`, `variant`, `status: "experimental"`, `architecture: "x86"`, `mode: "static-js"`, `outputKind` and `runtimeVerified: false`. MPRESS returns `rebuilt-pe`; FSG and UPX return `analysis-pe`.
- `catalog`: 34 researched groups with `id`, `family`, `category`, `route`, `reference`, `source`, `stage`, `variant`, `engineIds`, `outputKinds`, `runtimeVerified`. `route` describes research; use `engineIds` or `unpackers` for implemented engines.

### Analysis

`POST /api/v1/analyze` returns:

| Field | Contents |
| --- | --- |
| `schemaVersion` | `1` |
| `version` | Current application version |
| `file` | `name`, byte `size`, `sha256`, Shannon `entropy` |
| `pe` | Serializable PE summary described below |
| `detection` | Detection scope, pinned commit and explicit partial coverage |
| `detections` | Array of attributed matches |
| `candidates` | Preliminary unpacker candidates; empty when none match |

The `pe` summary includes `format`, `machine`, `architecture`, `is64`, `isDll`, `isNet`, `imageBase`, `entryPointRva`, `entryPointOffset`, `sizeOfImage`, `sizeOfHeaders`, `fileAlignment`, `sectionAlignment`, `peOffset`, `optionalOffset`, `directoryOffset`, `sectionTable`, `sections`, `directories`, `imports`, `overlay`, and `warnings`. An unmapped entry-point offset is `null`. The internal `rvaToOffset` function is omitted from serialization.

- `sections`: name, RVA, virtual size, raw size/offset, characteristics, header offset and entropy.
- `directories`: PE data-directory entries in index order, each with `rva` and `size`; standard PE field semantics apply, including the security directory's file-offset convention.
- `imports`: ordinary import modules, `firstThunk` and functions identified by name/hint or ordinal. This is not a complete Windows loader model or delayed-import reconstruction.
- `overlay`: `{ offset, size }` after the mapped file sections.
- `warnings`: machine-readable structural observations; an empty list is not runtime certification.

Inputs with an exact supported FSG/UPX nonstandard header may use a family-specific parser adapter without weakening generic parsing. The report then includes `parser: "fsg-layout-adapter"` or `"upx-layout-adapter"`. FSG adds `importsEnumerated: false`; an empty imports array then means unenumerated, not zero original imports. UPX reports `declaredSizeOfHeaders` and the normalization warning separately from its effective header size. Unrecognized malformed headers remain errors.

Each detection has `family`, `version`, `source`, `confidence` and `evidence`. `version` can be an empty string. `source: "die-rule-subset"` identifies translated selected DIE rules; `source: "section-heuristic"` is weaker section-name evidence. Confidence labels are `signature` or `low`, not probabilities.

The current candidate shape is:

```json
{
  "id": "mpress-pe32-lzmat",
  "family": "MPRESS",
  "status": "experimental",
  "variant": "2.12–2.19 stub 0x29f; fix 0x35; PE32 EXE; no TLS",
  "outputKind": "rebuilt-pe",
  "fullValidationAtUnpack": true
}
```

### Unpack

`POST /api/v1/unpack` returns:

- `name`: sanitized input basename with `.unpacked.exe` for rebuilt PE or `.analysis.exe` for analysis-only PE.
- `dataBase64`: the reconstructed PE bytes in standard base64. HTTP/MCP do not return the internal `bytes` field.
- `metadata`: `engine`, `variant`, `outputKind`, `runtimeVerified`, `originalEntryPoint`, `importedModules`, `warnings`.
- `report`: a fresh analysis of the reconstructed bytes, using the same report shape as analysis.

The MPRESS engine requires x86 native PE32 EXE, LZMAT, stub `0x29f`, fix `0x35` and the expected packed/import layout. DLL, TLS, PE32+, .NET, LZMA and unknown variants are unsupported. The **2.12–2.19** variant label identifies the source family; one real **2.19** fixture is structurally validated.

MPRESS returns `outputKind: "rebuilt-pe"`. FSG 1.31/1.33 and the supported UPX NRV2B stub return `outputKind: "analysis-pe"` and the warning `analysis-only-not-runnable`. FSG does not reconstruct imports/TLS/relocations; UPX restores imports and selected absolute pointers but not resources, original section layout or a base-relocation directory. UPX additionally exposes `unrestoredMetadata`, compressed/decompressed lengths and fixup counts. See the engine research documents for variant details. All outputs are `runtimeVerified: false`; none promises original-byte identity or working runtime behavior.

## 4. Errors and job limits

HTTP failures have an `error` object with a machine-readable `code`. Core errors also carry `details`; clients should tolerate its absence for transport-generated errors. Example:

```json
{
  "error": {
    "code": "unsupported-variant",
    "details": {}
  }
}
```

| HTTP status | Typical codes / meaning |
| --- | --- |
| 400 | Invalid JSON/base64/name/request, malformed PE, unsupported variant, or core validation failure |
| 403 | `forbidden-origin`: rejected Host, Origin or cross-site request |
| 404 | `not-found`: unavailable resource, unknown API path or rejected static path |
| 405 | `method-not-allowed` |
| 408 | `timeout`: analysis/unpack job exceeded its time budget |
| 413 | `input-size-limit`: JSON/body, base64 field or decoded-input limit rejection |
| 415 | `json-required`: POST content type is not JSON |
| 503 | `busy`: job concurrency is exhausted |
| 500 | `worker-failed` or unexpected server failure |

Representative core codes include `not-pe`, `truncated-input`, `invalid-pe-header`, `invalid-section-count`, `unknown-engine`, `unsupported-variant`, `unsupported-tls`, `unsupported-fix-stub`, `ambiguous-pe`, `decoded-size-mismatch`, `invalid-back-reference`, `output-limit`, `output-size-limit`, `output-validation-failed` and `unmapped-output-directory`. The current decoder also uses `input-size-limit` for a missing, empty or non-string `dataBase64`, so those requests receive 413. Treat codes as diagnostics, not a closed enumeration of every validation branch.

Each Node job runs in a worker thread with a **30-second** default timeout. Up to `max(1, min(4, availableParallelism()))` jobs run per server process; admission limits also bound HTTP uploads and MCP file operations before base64 decoding. Excess requests return `busy` rather than entering a server queue. Worker failure is reported as `worker-failed`. The browser has a separate Worker queue; the direct core functions do not install server timeouts themselves.

## 5. MCP over stdio

After installing npm dependencies, configure an MCP-capable client with the absolute entry-script path. The path below is a portable placeholder, not a literal machine location:

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

On Windows, use an absolute Windows path encoded as valid JSON, escaping backslashes or using forward slashes. `node` must resolve in the client's environment. Using the entry script directly keeps stdout available for protocol messages. `npm run mcp` is also a project script for launching the server from the project root.

| Tool | Arguments | Result |
| --- | --- | --- |
| `list_capabilities` | `{}` | Capability descriptor |
| `analyze_file` | `{ "dataBase64": "...", "name": "sample.exe" }` | Analysis report |
| `unpack_file` | `{ "dataBase64": "...", "name": "sample.exe", "engine": "mpress-pe32-lzmat" }` | Serialized unpack result |

The `...` values above are placeholders for actual canonical base64. Only `dataBase64` is required for file tools; `name` and the unpacker's `engine` are optional. These tools do not read an arbitrary path, execute the input, or write the unpacked file to disk.

Successful tool results contain both `structuredContent` with the object and a `content` text item containing its JSON serialization. Handled operation failures set `isError: true` and return `{ "error": { "code": "...", "details": {} } }` in the same content forms; `details` is absent for the admission-limit `busy` response. Invalid tool arguments can be rejected by the MCP SDK before the operation handler runs; they need not use the core error shape.

MCP reuses the HTTP transport's content decoder/encoder and Node job runner, including byte limits, concurrency and job timeout. It is stdio-only in this project and does not require `npm start`, a browser build or Python.

The SDK server receive limit is explicitly configured for the input ceiling. Receiving large results also depends on the client: the SDK's default client frame limit is 10 MiB. Configure `StdioClientTransport({ command, args, maxBufferSize })` to fit the expected result or use HTTP for large artifacts. This server includes results in both text content and `structuredContent`, so a base64 artifact occurs twice in a response frame. The 64 MiB input path has been tested; a full 128 MiB output transfer has not.

## 6. Direct JavaScript core

The source is ES modules, usable from Node or a browser bundle without a DOM dependency. For Node, run as an ES module from the project root:

```js
import { readFile } from 'node:fs/promises';
import { capabilities, analyze, unpack, execute } from './src/core/index.js';

const bytes = new Uint8Array(await readFile('test-results/fixtures/mpress.exe'));
console.log(capabilities());

const report = await analyze(bytes, 'mpress.exe');
// Equivalent dispatcher form:
const sameReport = await execute('analyze', bytes, { name: 'mpress.exe' });

const result = await unpack(bytes, 'mpress-pe32-lzmat', 'mpress.exe');
// result.bytes is Uint8Array here; base64 encoding belongs to HTTP/MCP.
console.log(report.file.sha256, sameReport.schemaVersion, result.metadata);
```

`analyze` and `unpack` are asynchronous; `capabilities` is synchronous. Core validation throws `AnalysisError` with `code` and `details`. UI language is not part of the core contract: reports preserve language-independent fields and codes.
