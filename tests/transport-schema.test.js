// T47: transport-level armadillo oracle options (MT30 acceptance list).
// decodeRequest unit checks for the six knobs with stable error codes, an
// HTTP end-to-end pass proving the options survive decodeRequest -> runJob
// -> engine selection without spawning the debugger, and a real MCP stdio
// session asserting the unpack_file schema exposes the same constraints.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { request as httpRequest } from 'node:http';
import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppServer } from '../src/server/http.js';
import { decodeRequest } from '../src/server/transport.js';

// Inert PE32 fixture (same shape as tests/server.test.js) with a tunable
// entry point; entryPointRva 0 makes armadillo reject before any spawn.
function minimalPE(size = 0x400, entryPointRva = 0x1000) {
  const bytes = Buffer.alloc(size);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.writeUInt32LE(0x4550, 0x80);
  bytes.writeUInt16LE(0x14c, 0x84);
  bytes.writeUInt16LE(1, 0x86);
  bytes.writeUInt16LE(0xe0, 0x94);
  bytes.writeUInt16LE(0x102, 0x96);
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(entryPointRva, optional + 16);
  bytes.writeUInt32LE(0x400000, optional + 28);
  bytes.writeUInt32LE(0x1000, optional + 32);
  bytes.writeUInt32LE(0x200, optional + 36);
  bytes.writeUInt32LE(0x2000, optional + 56);
  bytes.writeUInt32LE(0x200, optional + 60);
  bytes.writeUInt16LE(3, optional + 68);
  bytes.writeUInt32LE(16, optional + 92);
  bytes.write('.text', 0x178, 'ascii');
  bytes.writeUInt32LE(0x200, 0x180);
  bytes.writeUInt32LE(0x1000, 0x184);
  bytes.writeUInt32LE(0x200, 0x188);
  bytes.writeUInt32LE(0x200, 0x18c);
  bytes.writeUInt32LE(0x60000020, 0x19c);
  return bytes;
}

const pe = minimalPE();
const payload = { dataBase64: pe.toString('base64'), name: 'test.exe' };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

const goodProbes = [{ address: 0x401000, size: 2 }];
const goodPlan = { imageBase: 0x400000, probes: [{ address: 0x401000, size: 5, samples: [1, 2, 3] }] };

async function serve(t) {
  const root = await mkdtemp(join(tmpdir(), 't47-root-'));
  const server = createAppServer({ root });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    await rm(root, { force: true, recursive: true }).catch(() => {});
  });
  const port = server.address().port;
  return async function post(pathname, body) {
    return new Promise((resolve, reject) => {
      const request = httpRequest({
        host: '127.0.0.1', port, path: pathname, method: 'POST',
        headers: { 'content-type': 'application/json' },
      }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      });
      request.on('error', reject);
      request.end(JSON.stringify(body));
    });
  };
}

test('decodeRequest passes the six armadillo options through untouched', () => {
  const { bytes, options } = decodeRequest({
    ...payload,
    probes: goodProbes,
    probePlan: goodPlan,
    timeoutSeconds: 30,
    maxEvents: 2000,
    sampleArgs: ['--verbose'],
    imageBase: 0x400000,
  });
  assert.equal(sha(bytes), sha(pe));
  assert.deepEqual(options, {
    name: 'test.exe', engine: undefined, oepRva: undefined, mode: undefined,
    probes: goodProbes, probePlan: goodPlan, timeoutSeconds: 30, maxEvents: 2000,
    sampleArgs: ['--verbose'], imageBase: 0x400000,
  });
});

test('decodeRequest keeps the legacy four-key options when nothing new is sent', () => {
  assert.deepEqual(decodeRequest({ ...payload, mode: 'extract' }).options,
    { name: 'test.exe', engine: undefined, oepRva: undefined, mode: 'extract' });
});

test('decodeRequest rejects each knob with a stable error code', () => {
  const cases = [
    ['timeoutSeconds', [0, 0.05, 61, -1, '15', NaN, Infinity], 'invalid-timeout-seconds'],
    ['maxEvents', [0, 15, 50001, 1.5, '2000', null], 'invalid-max-events'],
    ['sampleArgs', [{}, 'args', new Array(33).fill('a'), ['ok', 1], ['a'.repeat(4097)], ['bad\0arg']], 'invalid-sample-args'],
    ['imageBase', [-1, 0x100000000, 1.5, '0x400000'], 'invalid-image-base'],
  ];
  for (const [key, values, code] of cases) {
    for (const value of values) {
      assert.throws(() => decodeRequest({ ...payload, [key]: value }), error => error.code === code, `${key}=${String(value)}`);
    }
  }
  const probeFailures = [
    [], new Array(33).fill(goodProbes[0]), [null], ['text'], [[]],
    [{ address: 0x401000 }], [{ address: 0x401000, size: 3 }], [{ size: 2 }],
    [{ address: -1, size: 2 }], [{ address: 0x100000000, size: 2 }],
    [{ address: 0x401000, size: 2, samples: [] }], [{ address: 0x401000, size: 2, samples: new Array(129).fill(1) }],
  ];
  for (const probes of probeFailures) {
    assert.throws(() => decodeRequest({ ...payload, probes }), error => error.code === 'invalid-probe-plan', JSON.stringify(probes)?.slice(0, 60));
  }
  const planFailures = [
    null, 'plan', [], 7,
    { probes: goodPlan.probes },
    { imageBase: -1, probes: goodPlan.probes },
    { imageBase: 0x400000, probes: [] },
    { imageBase: 0x400000, probes: [{ address: 0x401000, size: 2 }] },
    { imageBase: 0x500000, probes: [{ address: 0x401000, size: 2, samples: [1] }] },
  ];
  for (const probePlan of planFailures) {
    assert.throws(() => decodeRequest({ ...payload, probePlan }), error => error.code === 'invalid-probe-plan', JSON.stringify(probePlan)?.slice(0, 60));
  }
  // probes without samples stay legal; probePlan probes must carry samples.
  assert.deepEqual(decodeRequest({ ...payload, probes: [{ address: 0x401000, size: 6 }] }).options.probes,
    [{ address: 0x401000, size: 6 }]);
});

test('HTTP unpack forwards valid options and rejects bad ones with 400', async t => {
  const post = await serve(t);
  // Valid knobs ride through decodeRequest -> runJob -> engine selection;
  // entryPointRva 0 makes the armadillo engine itself reject before spawn,
  // proving the whole chain without launching the debugger.
  const armed = { dataBase64: minimalPE(0x400, 0).toString('base64'), name: 't.exe', engine: 'armadillo-nanomites' };
  const ok = await post('/api/v1/unpack', {
    ...armed, probes: goodProbes, timeoutSeconds: 1, maxEvents: 16,
    sampleArgs: [], imageBase: 0x400000,
  });
  assert.equal(ok.status, 400);
  assert.equal(ok.body.error.code, 'armadillo-unsupported-input');
  for (const [extra, code] of [
    [{ timeoutSeconds: 61 }, 'invalid-timeout-seconds'],
    [{ timeoutSeconds: 0 }, 'invalid-timeout-seconds'],
    [{ maxEvents: 15 }, 'invalid-max-events'],
    [{ maxEvents: 1.5 }, 'invalid-max-events'],
    [{ sampleArgs: ['a\0b'] }, 'invalid-sample-args'],
    [{ imageBase: -5 }, 'invalid-image-base'],
    [{ probes: [] }, 'invalid-probe-plan'],
    [{ probes: [{ address: 1, size: 9 }] }, 'invalid-probe-plan'],
    [{ probePlan: { imageBase: 0x400000, probes: [{ address: 0x100000, size: 2, samples: [1] }] } }, 'invalid-probe-plan'],
    [{ probePlan: { imageBase: 0x600000, probes: [{ address: 0x500000, size: 2, samples: [1] }] } }, 'invalid-probe-plan'],
  ]) {
    const response = await post('/api/v1/unpack', { ...payload, ...extra });
    assert.equal(response.status, 400, JSON.stringify(extra));
    assert.equal(response.body.error.code, code, JSON.stringify(extra));
  }
  // A self-consistent plan passes the transport and reaches engine selection.
  const consistent = await post('/api/v1/unpack', {
    ...payload, probePlan: { imageBase: 0x400000, probes: [{ address: 0x401000, size: 2, samples: [1] }] },
  });
  assert.equal(consistent.status, 400);
  assert.equal(consistent.body.error.code, 'unsupported-variant');
  // analyze_file stays free of the new knobs: they are unpack-only options.
  const analyze = await post('/api/v1/analyze', { ...payload, timeoutSeconds: 61 });
  assert.equal(analyze.status, 400);
  assert.equal(analyze.body.error.code, 'invalid-timeout-seconds');
});

test('real MCP stdio session exposes and enforces the armadillo schema', { timeout: 60000 }, async t => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../src/server/mcp.js', import.meta.url))],
    cwd: await mkdtemp(join(tmpdir(), 't47-mcp-')), stderr: 'pipe',
  });
  const client = new Client({ name: 'transport-schema-test', version: '1.0.0' });
  t.after(() => client.close());
  await client.connect(transport);
  const listed = await client.listTools();
  const schema = listed.tools.find(tool => tool.name === 'unpack_file').inputSchema;
  const expected = ['probes', 'probePlan', 'timeoutSeconds', 'maxEvents', 'sampleArgs', 'imageBase'];
  for (const key of expected) assert.ok(schema.properties[key], `unpack_file schema missing ${key}`);
  assert.equal(listed.tools.find(tool => tool.name === 'analyze_file').inputSchema.properties.timeoutSeconds, undefined);

  assert.equal(schema.properties.timeoutSeconds.type, 'number');
  assert.equal(schema.properties.timeoutSeconds.exclusiveMinimum, undefined);
  assert.equal(schema.properties.timeoutSeconds.minimum, 0.1);
  assert.equal(schema.properties.timeoutSeconds.maximum, 60);
  assert.equal(schema.properties.maxEvents.type, 'integer');
  assert.equal(schema.properties.maxEvents.minimum, 16);
  assert.equal(schema.properties.maxEvents.maximum, 50000);
  assert.equal(schema.properties.sampleArgs.type, 'array');
  assert.equal(schema.properties.sampleArgs.maxItems, 32);
  assert.equal(schema.properties.imageBase.type, 'integer');
  assert.equal(schema.properties.imageBase.maximum, 0xffffffff);
  assert.deepEqual(schema.properties.probes.items.properties.size.enum, [2, 5, 6]);

  function callError(result) {
    assert.equal(result.isError, true);
    return result.structuredContent?.error?.code ?? JSON.parse(result.content[0].text).error.code;
  }

  // Zod rejects schema violations before decodeRequest; the session survives.
  for (const extra of [
    { timeoutSeconds: 61 }, { timeoutSeconds: 'x' }, { maxEvents: 15 },
    { sampleArgs: [42] }, { imageBase: 1.5 },
    { probes: [{ address: 1, size: 7 }] },
    { probePlan: { imageBase: 0x400000, probes: [{ address: 0x500000, size: 2, samples: [1] }] } },
    { probes: [{ address: 1, size: 2 }], unexpected: true },
  ]) {
    const result = await client.callTool({ name: 'unpack_file', arguments: { ...payload, ...extra } });
    assert.equal(result.isError, true, JSON.stringify(extra));
  }
  assert.notEqual((await client.callTool({ name: 'list_capabilities', arguments: {} })).isError, true);

  // Legitimate values pass zod, decodeRequest and reach the engine itself.
  const armed = { dataBase64: minimalPE(0x400, 0).toString('base64'), name: 't.exe', engine: 'armadillo-nanomites' };
  const reached = await client.callTool({ name: 'unpack_file', arguments: {
    ...armed, probes: goodProbes, timeoutSeconds: 1, maxEvents: 16, sampleArgs: [], imageBase: 0x400000,
  } });
  assert.equal(callError(reached), 'armadillo-unsupported-input');
});
