import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { analyze, unpack, capabilities } from '../src/core/index.js';
import { parsePE } from '../src/core/pe.js';
import { parseInput } from '../src/core/engines.js';
import { createAppServer } from '../src/server/http.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';

const cases = [
  ['fsg/fsg131.bin', 'fsg-pe32', 'fsg-layout-adapter', 0x40300, '28bdbc5f4268464845940e0e7c5c473af9cc1562ce573ce7a8050c3da024611b', 'rebuilt-pe'],
  ['fsg/fsg133.bin', 'fsg-pe32', 'fsg-layout-adapter', 0x40300, '31889f7e66102544c199eb1fe3454641accf7844909b4252e9d9076b4a5803b1', 'rebuilt-pe'],
  ['upx/lbop20.upx.bin', 'upx-pe32-nrv', 'upx-layout-adapter', 0x1252, 'e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158', 'rebuilt-pe'],
];
const loaded = [];
for (const [file, engine, parser, ep, sha, kind] of cases) {
  let bytes;
  try { bytes = new Uint8Array(await readFile(new URL(`../test-results/fixtures/${file}`, import.meta.url))); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (bytes) { assert.equal(createHash('sha256').update(bytes).digest('hex'), sha); loaded.push({ file, engine, parser, ep, bytes }); }
  test(`public core routes ${file} through explicit layout adapter and correct output grade`, { skip: !bytes && 'Fetch FSG and UPX fixtures first' }, async () => {
    assert.throws(() => parsePE(bytes));
    const report = await analyze(bytes, file);
    assert.equal(report.pe.parser, parser);
    assert.deepEqual(report.candidates.map(candidate => candidate.id), [engine]);
    assert.equal(report.candidates[0].outputKind, engine === 'upx-pe32-nrv' ? 'analysis-pe' : kind);
    assert.equal(report.file.sha256, sha);
    const automatic = await unpack(bytes, 'auto', file), explicit = await unpack(bytes, engine, file);
    assert.deepEqual(automatic, explicit);
    assert.equal(automatic.metadata.engine, engine); assert.equal(automatic.metadata.outputKind, kind);
    assert.equal(automatic.metadata.runtimeVerified, true); assert.equal(automatic.metadata.originalEntryPoint, ep);
    assert.match(automatic.name, kind === 'analysis-pe' ? /\.analysis\.exe$/ : /\.unpacked\.exe$/);
    assert.ok(!automatic.metadata.warnings.includes('analysis-only-not-runnable'));
    assert.deepEqual(parsePE(automatic.bytes).warnings, []);
    assert.deepEqual(automatic.report, await analyze(automatic.bytes, automatic.name));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), sha);
    const broken = bytes.slice(); broken[report.pe.entryPointOffset] ^= 0xff;
    assert.throws(() => parseInput(broken), 'unrecognized stub must not normalize a malformed header');
  });
}

test('engine capabilities separate reconstruction from analysis and external tools', () => {
  const caps = capabilities();
  assert.equal(caps.unpackers.length, 12); // five worker engines (mpress/fsg/upx/nspack/petite) plus seven server engines
  assert.ok(caps.unpackers.find(engine => engine.id === 'nspack-pe32' && engine.outputKind === 'analysis-pe'));
  assert.ok(caps.unpackers.find(engine => engine.id === 'petite-22-pe32' && engine.outputKind === 'rebuilt-pe'));
  assert.equal(caps.unpackers.filter(engine => engine.outputKind === 'rebuilt-pe').length, 5);
  assert.equal(caps.unpackers.filter(engine => engine.outputKind === 'analysis-pe').length, 3);
  assert.equal(caps.unpackers.filter(engine => engine.outputKind === 'dump-pe').length, 3);
  assert.equal(caps.unpackers.filter(engine => engine.outputKind === 'extract-pe').length, 1);
  assert.equal(caps.unpackers.filter(engine => engine.mode === 'external-tool').length, 1);
  assert.equal(caps.unpackers.filter(engine => engine.mode === 'dynamic-debug').length, 2);
  assert.equal(caps.detection.families.length, 12);
  for (const engine of caps.unpackers) if (engine.catalogId !== 'dynamic') assert.ok(caps.catalog.find(item => item.engineIds.includes(engine.id)));
});

test('ASPack evidence fixture: detected by DIE, refused by every engine', async t => {
  let bytes;
  try { bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/aspack/aspack-lbop20.bin', import.meta.url))); }
  catch (error) { if (error.code !== 'ENOENT') throw error; return t.skip('Run node scripts/fetch-aspack-fixtures.mjs first'); }
  assert.equal(createHash('sha256').update(bytes).digest('hex'), 'a7a2f792185842ea20f100f8a0059842bc299a2e5c0318751840fdd38224800a');
  const report = await analyze(bytes, 'aspack-lbop20.bin');
  const hit = report.detections.find(detection => detection.family === 'ASPack');
  assert.ok(hit, 'DIE subset identifies ASPack');
  assert.equal(hit.source, 'die-rule-subset');
  assert.equal(hit.version, '2.12-2.42');
  assert.deepEqual(report.candidates, [], 'no vetted layout matches; guessing is not offered');
  await assert.rejects(unpack(bytes, 'auto', 'aspack-lbop20.bin'), error => error.code === 'unsupported-variant');
});

test('MEW evidence fixture: nonstandard header is refused by the strict analyzer', async t => {
  let bytes;
  try { bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/mew/lbop20-mew.bin', import.meta.url))); }
  catch (error) { if (error.code !== 'ENOENT') throw error; return t.skip('Run node scripts/fetch-mew-fixtures.mjs first'); }
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '42e83208184d5ef0ebfced4347540b4629fe2d6c901295dd0dc9eb18a5b96af5');
  // MEW 11 SE overlaps the PE header with unused DOS fields (e_lfanew = 0x0c).
  // Without a registered MEW engine there is no vetted layout adapter either;
  // the strict parser must reject rather than guess, mirroring ASPack policy.
  await assert.rejects(analyze(bytes, 'lbop20-mew.bin'), error => error.code === 'invalid-pe-header');
  await assert.rejects(unpack(bytes, 'auto', 'lbop20-mew.bin'), error => error.code === 'invalid-pe-header');
});


test('HTTP and official MCP SDK expose FSG/UPX selection and graded artifacts', { timeout: 45000 }, async t => {
  if (loaded.length !== cases.length) return t.skip('Fetch FSG and UPX fixtures first');
  const server = createAppServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/api/v1/`;
  const client = new Client({ name: 'multi-engine-test', version: '1' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../src/server/mcp.js', import.meta.url))], stderr: 'pipe' });
  t.after(() => client.close()); await client.connect(transport);
  const schema = (await client.listTools()).tools.find(tool => tool.name === 'unpack_file').inputSchema;
  assert.deepEqual(schema.properties.engine.enum, ['auto', 'mpress-pe32-lzmat', 'fsg-pe32', 'upx-pe32-nrv', 'nspack-pe32', 'petite-22-pe32', 'upx-official', 'dynamic-debug-dump', 'emulated-pe32', 'instrumented-exception-dump', 'aspack-pe32-huffman', 'mew-pe32-lzma1', 'armadillo-nanomites']);
  for (const fixture of [loaded[1], loaded[2]]) {
    const args = { dataBase64: Buffer.from(fixture.bytes).toString('base64'), name: fixture.file, engine: fixture.engine };
    const analysisResponse = await fetch(url + 'analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args) });
    assert.equal(analysisResponse.status, 200); const report = await analysisResponse.json();
    assert.equal(report.candidates[0].id, fixture.engine);
    const response = await fetch(url + 'unpack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args) });
    assert.equal(response.status, 200); const http = await response.json();
    assert.equal(http.metadata.outputKind, 'rebuilt-pe'); assert.equal(http.metadata.originalEntryPoint, fixture.ep);
    const mcp = await client.callTool({ name: 'unpack_file', arguments: { ...args, engine: 'auto' } });
    assert.notEqual(mcp.isError, true); assert.deepEqual(mcp.structuredContent, http);
    assert.equal(parsePE(new Uint8Array(Buffer.from(http.dataBase64, 'base64'))).entryPointRva, fixture.ep);
  }
});
