import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createAppServer } from '../src/server/http.js';
import { createJobRunner, MAX_CONCURRENCY, runJob } from '../src/server/jobs.js';
import { decodeRequest, encodeResult, MAX_BASE64, MAX_JSON } from '../src/server/transport.js';
import { MAX_INPUT, MAX_OUTPUT } from '../src/core/bytes.js';
import { APP_VERSION } from '../src/core/version.js';

// A complete, inert PE32 fixture: one mapped section, no imports, no payload.
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
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
let temporary, root, workerURL, port, fixture, sharedServer;
let upxPacked, aspackPacked, mewPacked, upxTool, upxBase;

function runTool(file, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve() : reject(new Error(stderr || `exit ${code}`)));
  });
}

async function serve(t, options = {}) {
  const server = createAppServer({ root, ...options });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return server.address().port;
}

function request(path, { method = 'GET', body, headers = {}, targetPort = port, stream } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: '127.0.0.1', port: targetPort, path, method, headers, agent: false }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, text,
          body: text && res.headers['content-type']?.startsWith('application/json') ? JSON.parse(text) : undefined });
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('test-request-timeout')));
    if (stream) stream(req).catch(reject);
    else req.end(body);
  });
}

function post(operation, body = payload, options = {}) {
  return request(`/api/v1/${operation}`, { method: 'POST', body: JSON.stringify(body), ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers } });
}

function errorIs(response, status, code) {
  assert.equal(response.status, status, response.text);
  assert.equal(response.body?.error?.code, code, response.text);
  assert.equal(response.body.error.stack, undefined);
}

function checkAnalysis(report, input, name) {
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.version, APP_VERSION);
  assert.equal(report.file.name, name);
  assert.equal(report.file.size, input.length);
  assert.equal(report.file.sha256, hash(input));
  assert.equal(report.pe.format, 'PE32');
  assert.equal(report.pe.architecture, 'x86');
  assert.equal(report.pe.entryPointRva, 0x1000);
  assert.equal(report.pe.entryPointOffset, 0x200);
  assert.deepEqual(report.pe.warnings, []);
  assert.deepEqual(report.candidates, []);
}

function checkUnpacked(result) {
  const bytes = Buffer.from(result.dataBase64, 'base64');
  assert.equal(bytes.readUInt16LE(0), 0x5a4d);
  assert.equal(bytes.readUInt32LE(bytes.readUInt32LE(0x3c)), 0x4550);
  assert.equal(result.bytes, undefined);
  assert.equal(result.metadata.engine, 'mpress-pe32-lzmat');
  assert.equal(result.metadata.outputKind, 'rebuilt-pe');
  assert.equal(result.metadata.runtimeVerified, true);
  assert.equal(result.metadata.originalEntryPoint, 0x1110);
  assert.equal(result.metadata.importedModules, 4);
  assert.ok(result.metadata.warnings.includes('runtime-not-verified'));
  assert.equal(result.report.pe.entryPointRva, 0x1110);
  assert.equal(result.report.pe.imports.length, 4);
  assert.ok(result.report.pe.imports.every(module => module.functions.length > 0));
  assert.deepEqual(result.report.pe.warnings, []);
  assert.equal(result.report.file.size, bytes.length);
  assert.equal(result.report.file.sha256, hash(bytes));
  assert.doesNotMatch(result.name, /[\\/]/);
  return bytes;
}

before(async () => {
  temporary = await mkdtemp(join(tmpdir(), 'oldershells-server-'));
  root = join(temporary, 'dist');
  await Promise.all(['dist/assets', 'docs', 'src', '资料', 'dist-private'].map(path => mkdir(join(temporary, path), { recursive: true })));
  await Promise.all([
    writeFile(join(root, 'index.html'), '<!doctype html><title>isolated dist fixture</title>'),
    writeFile(join(root, 'assets/app.js'), 'export const fixture = true;'),
    writeFile(join(root, '.env'), 'PRIVATE_DIST_FILE'),
    ...['docs/internal.md', 'src/internal.js', '资料/secret.txt', 'dist-private/secret.txt', 'PROGRESS.md', 'package.json'].map(path => writeFile(join(temporary, path), 'PRIVATE_HOST_FILE')),
  ]);
  await symlink(join(temporary, 'dist-private'), join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  const workerPath = join(temporary, 'fault-worker.mjs');
  await writeFile(workerPath, `
    import { parentPort, workerData } from 'node:worker_threads';
    const { operation, options } = workerData;
    if (operation === 'hang') {
      const counter = new Int32Array(options.counter);
      Atomics.add(counter, 0, 1);
      setInterval(() => Atomics.add(counter, 0, 1), 5);
    } else if (operation === 'throw') throw new Error('private worker diagnostic');
    else if (operation === 'exit') process.exit(0);
    else if (operation === 'malformed') parentPort.postMessage(null);
    else if (operation === 'error') parentPort.postMessage({ ok: false, error: { code: 'fixture-error', details: { safe: true } } });
    else {
      if (operation === 'log') console.log('worker-diagnostic-only');
      parentPort.postMessage({ ok: true, result: { done: true } });
    }
  `);
  workerURL = pathToFileURL(workerPath);
  sharedServer = createAppServer({ root });
  await new Promise(resolve => sharedServer.listen(0, '127.0.0.1', resolve));
  port = sharedServer.address().port;
  try { fixture = await readFile(new URL('../test-results/fixtures/mpress.exe', import.meta.url)); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (fixture) assert.equal(hash(fixture), '218d5569194ee018b354c9f717047ae2dac5d6130cdf81eb24f0a9b370600136');
  try { upxPacked = await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  try { aspackPacked = await readFile(new URL('../test-results/fixtures/aspack/aspack-lbop20.bin', import.meta.url)); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  try { mewPacked = await readFile(new URL('../test-results/fixtures/mew/lbop20-mew.bin', import.meta.url)); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  upxTool = fileURLToPath(new URL('../tools/upx/upx.exe', import.meta.url));
  upxBase = fileURLToPath(new URL('../test-results/fixtures/upx-lzma/base.exe', import.meta.url));
});

after(async () => {
  if (sharedServer) {
    sharedServer.closeAllConnections();
    await new Promise(resolve => sharedServer.close(resolve));
  }
  // Only this test's uniquely-created, owned temporary fixture is removed.
  if (temporary) await rm(temporary, { recursive: true, force: true });
});

test('base64 accepts canonical binary values and transfers an exact independent byte view', () => {
  for (const input of [Buffer.from([0]), Buffer.from([0, 255]), Buffer.from([0, 255, 127]), Buffer.from(Array.from({ length: 256 }, (_, i) => i))]) {
    const { bytes } = decodeRequest({ dataBase64: input.toString('base64') });
    assert.deepEqual(Buffer.from(bytes), input);
    assert.equal(bytes.byteOffset, 0);
    assert.equal(bytes.buffer.byteLength, input.length);
  }
  const part = Uint8Array.from([99, 1, 2, 99]).subarray(1, 3);
  assert.deepEqual(encodeResult({ bytes: part, name: 'part' }), { dataBase64: 'AQI=', name: 'part' });
});

test('base64 rejects bad alphabet, padding, whitespace, Unicode and noncanonical pad bits', () => {
  for (const value of ['A', 'AAA', '====', '=AAA', 'AA=A', 'AA===AAA', 'A===', 'AA-_', 'AA A', 'AA\nA', 'AAAA\n', 'ＡAAA', 'AB==', 'AAB=', '//==', '///=']) {
    assert.throws(() => decodeRequest({ dataBase64: value }), { code: 'invalid-base64' }, value);
  }
  for (const value of [null, [], 'text', 1]) assert.throws(() => decodeRequest(value), { code: 'invalid-request' });
  for (const dataBase64 of [undefined, null, '', 1]) assert.throws(() => decodeRequest({ dataBase64 }), { code: 'input-size-limit' });
  assert.throws(() => decodeRequest({ ...payload, name: 1 }), { code: 'invalid-name' });
  assert.throws(() => decodeRequest({ ...payload, name: 'a'.repeat(257) }), { code: 'invalid-name' });
  assert.throws(() => decodeRequest({ ...payload, engine: {} }), { code: 'unknown-engine' });
  assert.deepEqual(decodeRequest({ ...payload, mode: 'extract' }).options, { name: 'test.exe', engine: undefined, oepRva: undefined, mode: 'extract' });
  assert.deepEqual(decodeRequest({ ...payload, mode: 'auto-oep', oepRva: 0x1110 }).options, { name: 'test.exe', engine: undefined, oepRva: 0x1110, mode: 'auto-oep' });
  for (const mode of ['nope', '', 'AUTO-OEP', 1, null]) assert.throws(() => decodeRequest({ ...payload, mode }), { code: 'invalid-mode' });
  for (const oepRva of [0, -1, 1.5, '0x1000', 0x10000000]) assert.throws(() => decodeRequest({ ...payload, oepRva }), { code: 'invalid-oep-rva' });
});

test('base64 handles the actual 64 MiB boundary without regex stack overflow', { timeout: 30000 }, () => {
  assert.equal(MAX_INPUT, 67108864);
  assert.equal(MAX_OUTPUT, 134217728);
  const encoded = 'A'.repeat(MAX_BASE64 - 2) + '==';
  const { bytes } = decodeRequest({ dataBase64: encoded });
  assert.equal(bytes.length, MAX_INPUT);
  assert.equal(bytes[0], 0);
  assert.equal(bytes.at(-1), 0);
  // MAX_INPUT + 1 still fits the encoded-length cap; check decoded length too.
  assert.throws(() => decodeRequest({ dataBase64: 'A'.repeat(MAX_BASE64 - 1) + '=' }), { code: 'input-size-limit' });
  assert.throws(() => decodeRequest({ dataBase64: 'A'.repeat(MAX_BASE64 + 4) }), { code: 'input-size-limit' });
  assert.throws(() => decodeRequest({ dataBase64: 'A'.repeat(MAX_BASE64 - 3) + 'B==' }), { code: 'invalid-base64' });
  assert.throws(() => encodeResult({ bytes: new Uint8Array(MAX_OUTPUT + 1) }), { code: 'output-size-limit' });
});

test('HTTP capabilities and a real worker analysis expose the shared core contract', async () => {
  const capabilities = await request('/api/v1/capabilities');
  assert.equal(capabilities.status, 200);
  assert.equal(capabilities.body.version, APP_VERSION);
  assert.deepEqual(capabilities.body.limits, { inputBytes: MAX_INPUT, outputBytes: MAX_OUTPUT });
  assert.ok(capabilities.body.unpackers.some(engine => engine.id === 'mpress-pe32-lzmat' && engine.runtimeVerified === true));
  const result = await post('analyze');
  assert.equal(result.status, 200, result.text);
  checkAnalysis(result.body, pe, 'test.exe');
  assert.equal(result.headers['access-control-allow-origin'], undefined);
});

test('HTTP MPRESS fixture unpacks and the returned bytes can be analyzed again', async t => {
  if (!fixture) return t.skip('Pinned static fixture test-results/fixtures/mpress.exe is not installed');
  const detected = await post('analyze', { dataBase64: fixture.toString('base64') });
  assert.equal(detected.status, 200, detected.text);
  assert.ok(detected.body.candidates.some(candidate => candidate.id === 'mpress-pe32-lzmat'));
  const unpacked = await post('unpack', { dataBase64: fixture.toString('base64'), name: '../fixture.exe' });
  assert.equal(unpacked.status, 200, unpacked.text);
  const output = checkUnpacked(unpacked.body);
  const analyzed = await post('analyze', { dataBase64: output.toString('base64'), name: unpacked.body.name });
  assert.equal(analyzed.status, 200, analyzed.text);
  assert.deepEqual(analyzed.body, unpacked.body.report);
});

test('HTTP malformed requests, truncated PE and unsupported unpacking fail without a path API', async () => {
  errorIs(await request('/api/v1/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{' }), 400, 'invalid-json');
  errorIs(await request('/api/v1/analyze', { method: 'POST', body: '{}' }), 415, 'json-required');
  errorIs(await request('/api/v1/analyze'), 405, 'method-not-allowed');
  errorIs(await request('/api/v1/capabilities', { method: 'POST' }), 405, 'method-not-allowed');
  errorIs(await post('analyze', null), 400, 'invalid-request');
  errorIs(await post('analyze', { path: join(temporary, 'docs/internal.md') }), 413, 'input-size-limit');
  for (const dataBase64 of ['AB==', 'AAB=', 'AA-_', 'AA A']) errorIs(await post('analyze', { dataBase64 }), 400, 'invalid-base64');
  errorIs(await post('analyze', { dataBase64: pe.subarray(0, 32).toString('base64') }), 400, 'truncated-input');
  errorIs(await post('analyze', { dataBase64: Buffer.from('not a PE').toString('base64') }), 400, 'not-pe');
  errorIs(await post('unpack', { ...payload, engine: 'unknown' }), 400, 'unknown-engine');
  errorIs(await post('unpack'), 400, 'unsupported-variant');
  // mode/oepRva validation: illegal values stop at the transport whitelist;
  // a legal mode passes validation and reaches engine selection unchanged.
  errorIs(await post('unpack', { ...payload, mode: 'dump-everything' }), 400, 'invalid-mode');
  errorIs(await post('unpack', { ...payload, mode: 'extract' }), 400, 'unsupported-variant');
  for (const oepRva of [0, -1, 1.5, 0x10000000]) errorIs(await post('unpack', { ...payload, oepRva }), 400, 'invalid-oep-rva');
  errorIs(await post('unpack', { ...payload, mode: 'auto-oep' }), 400, 'unsupported-variant');
  const nameOnly = await post('analyze', { ...payload, name: join(temporary, 'docs/internal.md') });
  assert.equal(nameOnly.body.file.sha256, hash(pe));
  assert.equal(nameOnly.body.file.size, pe.length);
});

test('HTTP rejects untrusted Host, Origin and cross-site requests', async () => {
  for (const headers of [
    { Host: `attacker.invalid:${port}` }, { Host: '127.0.0.1:1' }, { Host: `127.0.0.1.evil:${port}` },
    { Origin: 'https://attacker.invalid' }, { Origin: 'null' }, { Origin: 'http://127.0.0.1:1' },
    { Origin: `http://user@127.0.0.1:${port}` }, { Origin: `http://127.0.0.1:${port}/` }, { 'Sec-Fetch-Site': 'cross-site' },
  ]) {
    errorIs(await request('/api/v1/capabilities', { headers }), 403, 'forbidden-origin');
    errorIs(await post('analyze', payload, { headers }), 403, 'forbidden-origin');
  }
  assert.equal((await post('analyze', payload, { headers: { Host: `localhost:${port}`, Origin: `http://localhost:${port}`, 'Sec-Fetch-Site': 'same-origin' } })).status, 200);
});

test('HTTP serves only the injected dist tree with isolation headers and HEAD semantics', async () => {
  const index = await request('/');
  assert.equal(index.status, 200);
  assert.match(index.text, /isolated dist fixture/);
  assert.match(index.headers['content-type'], /text\/html/);
  assert.equal(index.headers['x-content-type-options'], 'nosniff');
  assert.equal(index.headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal(index.headers['cross-origin-embedder-policy'], 'require-corp');
  assert.match(index.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(index.headers['cache-control'], 'no-store');
  const asset = await request('/assets/app.js?v=1');
  assert.equal(asset.status, 200);
  assert.equal(asset.text, 'export const fixture = true;');
  assert.match(asset.headers['content-type'], /text\/javascript/);
  const head = await request('/index.html', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.text, '');
});

test('HTTP blocks traversal, junction escapes, internal docs, source and research files', async () => {
  for (const path of [
    '/docs/internal.md', '/src/internal.js', `/${encodeURIComponent('资料')}/secret.txt`, '/PROGRESS.md', '/package.json',
    '/../docs/internal.md', '/%2e%2e/docs/internal.md', '/%2e%2e%2fdocs/internal.md', '/..%5cdocs%5cinternal.md',
    '/assets/../../docs/internal.md', '/%252e%252e/docs/internal.md', '/escape/secret.txt', '/.env',
    '/index.html::$DATA', '/assets', '/index.html/child', '/%00', '//docs/internal.md', '/api/v1/unknown',
  ]) {
    const response = await request(path);
    errorIs(response, 404, 'not-found');
    assert.doesNotMatch(response.text, /PRIVATE_HOST_FILE|PRIVATE_DIST_FILE/);
  }
  errorIs(await request('/%zz'), 400, 'invalid-path');
});

test('HTTP enforces declared and streamed JSON byte limits and remains available', { timeout: 30000 }, async () => {
  errorIs(await request('/api/v1/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': MAX_JSON + 1 } }), 413, 'input-size-limit');
  const response = await request('/api/v1/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    stream: async req => {
      const chunk = Buffer.alloc(1024 * 1024, 0x20);
      for (let sent = 0; sent <= MAX_JSON; sent += chunk.length) {
        if (!req.write(chunk)) await once(req, 'drain');
      }
      req.end();
    },
  });
  errorIs(response, 413, 'input-size-limit');
  assert.equal((await post('analyze')).status, 200);
});

test('HTTP accepts an actual 64 MiB PE with overlay', { timeout: 60000 }, async () => {
  const input = minimalPE(MAX_INPUT);
  const response = await post('analyze', { dataBase64: input.toString('base64'), name: 'boundary.exe' });
  assert.equal(response.status, 200, response.text);
  checkAnalysis(response.body, input, 'boundary.exe');
  assert.equal(response.body.pe.overlay.size, MAX_INPUT - 0x400);
});

test('workers propagate core failures and free their bounded slots', async () => {
  assert.ok(MAX_CONCURRENCY >= 1 && MAX_CONCURRENCY <= 4);
  await assert.rejects(runJob('analyze', Uint8Array.from([0x4d, 0x5a])), { code: 'truncated-input' });
  const report = await runJob('analyze', Uint8Array.from(pe), { name: 'worker.exe' });
  checkAnalysis(report, pe, 'worker.exe');
  await assert.rejects(runJob('no-such-operation', Uint8Array.from(pe)), { code: 'unknown-operation' });
});

test('workers terminate timed-out computation, reject busy calls, and recover', { timeout: 10000 }, async () => {
  const runner = createJobRunner({ maximum: 1, timeoutMs: 1000, workerURL });
  const counter = new SharedArrayBuffer(4);
  const pending = assert.rejects(runner('hang', Uint8Array.from(pe), { counter }), { code: 'timeout' });
  await assert.rejects(runner('good', Uint8Array.from(pe)), { code: 'busy' });
  await pending;
  const view = new Int32Array(counter);
  const stoppedAt = Atomics.load(view, 0);
  assert.ok(stoppedAt > 0, 'the worker actually started its computation');
  await delay(80);
  assert.equal(Atomics.load(view, 0), stoppedAt, 'the timed-out thread stopped');
  assert.deepEqual(await runner('good', Uint8Array.from(pe)), { done: true });
});

test('worker crashes, silent exit, malformed IPC and constructor errors reject and recover', async () => {
  const runner = createJobRunner({ maximum: 1, workerURL });
  for (const operation of ['throw', 'exit', 'malformed']) {
    await assert.rejects(runner(operation, Uint8Array.from(pe)), { code: 'worker-failed' });
    assert.deepEqual(await runner('good', Uint8Array.from(pe)), { done: true });
  }
  await assert.rejects(runner('error', Uint8Array.from(pe)), { code: 'fixture-error', details: { safe: true } });
  const invalid = createJobRunner({ maximum: 1, workerURL: 'not-an-absolute-worker-path' });
  await assert.rejects(invalid('good', Uint8Array.from(pe)), { code: 'worker-failed' });
  await assert.rejects(invalid('good', Uint8Array.from(pe)), { code: 'worker-failed' });
});

test('HTTP maps real worker timeout/crash/busy failures to stable statuses', { timeout: 10000 }, async t => {
  const runner = createJobRunner({ maximum: 1, timeoutMs: 1000, workerURL });
  const counter = new SharedArrayBuffer(4);
  let entered;
  const ready = new Promise(resolve => { entered = resolve; });
  const targetPort = await serve(t, { maximum: 1, jobRunner: (_operation, bytes, options) => {
    entered();
    return runner(options.name, bytes, { counter });
  } });
  const pending = post('analyze', { ...payload, name: 'hang' }, { targetPort });
  await ready;
  errorIs(await post('analyze', payload, { targetPort }), 503, 'busy');
  assert.equal((await request('/api/v1/capabilities', { targetPort })).status, 200);
  errorIs(await pending, 408, 'timeout');
  errorIs(await post('analyze', { ...payload, name: 'throw' }, { targetPort }), 500, 'worker-failed');
  assert.equal((await post('analyze', { ...payload, name: 'good' }, { targetPort })).status, 200);
});

test('HTTP bounds uploads before buffering and releases aborted upload slots', { timeout: 10000 }, async t => {
  const server = createAppServer({ root, maximum: 1 });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const targetPort = server.address().port;
  const admitted = once(server, 'request');
  const upload = httpRequest({ hostname: '127.0.0.1', port: targetPort, path: '/api/v1/analyze', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': 1000 }, agent: false });
  upload.on('error', () => {});
  t.after(() => upload.destroy());
  upload.flushHeaders();
  const [incoming] = await admitted;
  errorIs(await post('analyze', payload, { targetPort }), 503, 'busy');
  assert.equal((await request('/api/v1/capabilities', { targetPort })).status, 200);
  const closed = new Promise(resolve => incoming.once('close', resolve));
  upload.destroy();
  await closed;
  assert.equal((await post('analyze', payload, { targetPort })).status, 200);
});

test('worker console output is redirected to stderr, never protocol stdout', async () => {
  const probe = join(temporary, 'stdout-probe.mjs');
  await writeFile(probe, `
    import { createJobRunner } from ${JSON.stringify(new URL('../src/server/jobs.js', import.meta.url).href)};
    const run = createJobRunner({ workerURL: new URL(${JSON.stringify(workerURL.href)}) });
    process.stdout.write(JSON.stringify(await run('log', new Uint8Array([1]))));
  `);
  const child = spawn(process.execPath, [probe], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);
  assert.equal(stdout, '{"done":true}');
  assert.match(stderr, /worker-diagnostic-only/);
});

test('HTTP CLI honors PORT and binds loopback independently of the current directory', { timeout: 10000 }, async t => {
  const entry = fileURLToPath(new URL('../src/server/http.js', import.meta.url));
  const child = spawn(process.execPath, [entry], { cwd: temporary, env: { ...process.env, PORT: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await once(child, 'close'); } });
  const address = await new Promise((resolve, reject) => {
    let output = '';
    child.once('error', reject);
    child.once('exit', code => reject(new Error(`HTTP exited ${code}: ${stderr}`)));
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (match) resolve(Number(match[1]));
    });
  });
  assert.ok(address > 0);
  assert.equal((await request('/api/v1/capabilities', { targetPort: address })).status, 200);
  errorIs(await request('/docs/internal.md', { targetPort: address }), 404, 'not-found');
  assert.equal(stderr, '');
});

test('official MCP SDK initializes the real stdio entry and lists/calls all tools', { timeout: 120000 }, async t => {
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../src/server/mcp.js', import.meta.url))], cwd: temporary, stderr: 'pipe' });
  const client = new Client({ name: 'server-contract-test', version: '1.0.0' });
  const errors = [];
  let stderr = '';
  transport.stderr.on('data', chunk => { stderr += chunk; });
  client.onerror = error => errors.push(error.message);
  t.after(() => client.close());
  await client.connect(transport);
  assert.deepEqual(client.getServerVersion(), { name: 'oldershellsck', version: APP_VERSION });
  assert.ok(client.getServerCapabilities().tools);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), ['analyze_file', 'list_capabilities', 'unpack_file']);
  for (const tool of listed.tools) {
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.inputSchema.properties.path, undefined);
  }
  const unpackTool = listed.tools.find(tool => tool.name === 'unpack_file');
  assert.equal(unpackTool.inputSchema.properties.dataBase64.maxLength, MAX_BASE64);
  assert.deepEqual(unpackTool.inputSchema.properties.mode.enum, ['auto-oep', 'extract']);
  assert.equal(unpackTool.inputSchema.properties.oepRva.type, 'integer');
  assert.equal(unpackTool.inputSchema.properties.oepRva.maximum, 0xFFFFFFF);
  assert.equal(listed.tools.find(tool => tool.name === 'analyze_file').inputSchema.properties.mode, undefined);

  function content(result) {
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    assert.equal(result.content[0].type, 'text');
    const value = JSON.parse(result.content[0].text);
    assert.deepEqual(result.structuredContent, value);
    return value;
  }

  await t.test('capabilities and minimal PE analysis match HTTP', async () => {
    const capabilities = content(await client.callTool({ name: 'list_capabilities', arguments: {} }));
    assert.deepEqual(capabilities, (await request('/api/v1/capabilities')).body);
    const report = content(await client.callTool({ name: 'analyze_file', arguments: payload }));
    checkAnalysis(report, pe, 'test.exe');
  });

  await t.test('MPRESS fixture unpacks through tools/call', async t => {
    if (!fixture) return t.skip('Pinned static fixture test-results/fixtures/mpress.exe is not installed');
    const result = content(await client.callTool({ name: 'unpack_file', arguments: {
      dataBase64: fixture.toString('base64'), name: 'fixture.exe', engine: 'mpress-pe32-lzmat',
    } }));
    const output = checkUnpacked(result);
    const report = content(await client.callTool({ name: 'analyze_file', arguments: { dataBase64: output.toString('base64'), name: result.name } }));
    assert.deepEqual(report, result.report);
  });

  await t.test('bad data, truncated PE and schema errors do not break the session', async () => {
    for (const [name, args, code] of [
      ['analyze_file', { dataBase64: 'AB==' }, 'invalid-base64'],
      ['analyze_file', { dataBase64: 'AAB=' }, 'invalid-base64'],
      ['analyze_file', { dataBase64: 'TVo=' }, 'truncated-input'],
      ['unpack_file', payload, 'unsupported-variant'],
      ['unpack_file', { ...payload, mode: 'auto-oep' }, 'unsupported-variant'],
    ]) {
      const result = await client.callTool({ name, arguments: args });
      assert.equal(result.isError, true);
      assert.equal(result.structuredContent.error.code, code);
      assert.equal(JSON.parse(result.content[0].text).error.code, code);
    }
    for (const [name, args] of [
      ['analyze_file', { path: join(temporary, 'docs/internal.md') }],
      ['analyze_file', { dataBase64: 123 }],
      ['unpack_file', { ...payload, engine: 'unknown' }],
      ['unpack_file', { ...payload, mode: 'nope' }],
      ['unpack_file', { ...payload, oepRva: 0 }],
      ['unknown_tool', {}],
    ]) assert.equal((await client.callTool({ name, arguments: args })).isError, true);
    assert.equal(content(await client.callTool({ name: 'list_capabilities', arguments: {} })).version, APP_VERSION);
  });

  await t.test('the full 64 MiB input succeeds beyond the SDK default 10 MiB frame', async () => {
    const input = minimalPE(MAX_INPUT);
    const args = { dataBase64: input.toString('base64'), name: 'large.exe' };
    assert.ok(JSON.stringify(args).length > 10 * 1024 * 1024);
    const report = content(await client.callTool({ name: 'analyze_file', arguments: args }, undefined, { timeout: 90000 }));
    checkAnalysis(report, input, 'large.exe');
  });

  await delay(30);
  assert.deepEqual(errors, [], 'stdout contains only valid MCP protocol messages');
  assert.equal(stderr, '');
});

test('HTTP capabilities expose the full twelve-engine registry', async () => {
  const capabilities = await request('/api/v1/capabilities');
  assert.equal(capabilities.status, 200);
  assert.deepEqual(capabilities.body.unpackers.map(engine => engine.id).sort(), [
    'armadillo-nanomites', 'aspack-pe32-huffman', 'dynamic-debug-dump', 'emulated-pe32', 'fsg-pe32',
    'instrumented-exception-dump', 'mew-pe32-lzma1', 'mpress-pe32-lzmat', 'nspack-pe32', 'petite-22-pe32',
    'upx-official', 'upx-pe32-nrv',
  ]);
});

test('HTTP emulated-pe32 emulates the pinned UPX fixture and returns dump-pe', { timeout: 30000 }, async t => {
  if (!upxPacked) return t.skip('Pinned static fixture test-results/fixtures/upx/lbop20.upx.bin is not installed');
  const response = await post('unpack', { dataBase64: upxPacked.toString('base64'), name: 'lbop20.upx.bin', engine: 'emulated-pe32' });
  assert.equal(response.status, 200, response.text);
  const bytes = Buffer.from(response.body.dataBase64, 'base64');
  assert.equal(bytes.readUInt16LE(0), 0x5a4d);
  assert.equal(bytes.readUInt32LE(bytes.readUInt32LE(0x3c)), 0x4550);
  const metadata = response.body.metadata;
  assert.equal(metadata.engine, 'emulated-pe32');
  assert.equal(metadata.mode, 'emulated');
  assert.equal(metadata.route, 'emulated');
  assert.equal(metadata.outputKind, 'dump-pe');
  assert.equal(metadata.originalEntryPoint, 0x1252);
  assert.equal(metadata.stopReason, 'verified-upx-tail-transfer');
  assert.ok(metadata.steps > 0);
  assert.ok(metadata.warnings.includes('runtime-not-verified'));
  assert.equal(response.body.report.pe.entryPointRva, 0x1252);
  assert.match(response.body.name, /unpacked\.exe$/);
  t.diagnostic(`emulated output ${bytes.length} bytes sha256=${hash(bytes)} steps=${metadata.steps}`);
});

test('HTTP instrumented-exception-dump observes a packed host and returns extract-pe', { timeout: 120000 }, async t => {
  if (process.platform !== 'win32' || !existsSync(upxTool) || !existsSync(upxBase)) {
    return t.skip('win32 + tools/upx/upx.exe + test-results/fixtures/upx-lzma/base.exe required');
  }
  // Same construction as tests/concurrency.test.js: the engine's strict parsePE
  // has no UPX layout adapter, so feed it a normally laid-out packed host.
  const dir = join(temporary, 'instrument-host');
  await mkdir(dir, { recursive: true });
  const host = join(dir, 'host.upx.exe');
  await runTool(upxTool, ['--best', '--no-progress', '-o', host, upxBase], dir);
  const packed = await readFile(host);
  const response = await post('unpack', { dataBase64: packed.toString('base64'), name: 'host.upx.exe',
    engine: 'instrumented-exception-dump', timeoutSeconds: 3, maxEvents: 8000 });
  assert.equal(response.status, 200, response.text);
  const metadata = response.body.metadata;
  assert.equal(metadata.engine, 'instrumented-exception-dump');
  assert.equal(metadata.mode, 'instrument');
  assert.equal(metadata.route, 'instrument/debug');
  assert.equal(metadata.stage, 'instrumented');
  assert.equal(metadata.outputKind, 'extract-pe');
  assert.ok(metadata.events > 0);
  assert.ok(metadata.bpHits >= 0 && metadata.bpHits <= 2);
  assert.equal(metadata.hookMode, 'one-shot');
  assert.equal(metadata.oepConfirmed, false);
  assert.equal(metadata.importsRebuilt, true);
  assert.ok(metadata.warnings.includes('extraction-stage'));
  assert.ok(metadata.warnings.includes('oep-unconfirmed'));
  const bytes = Buffer.from(response.body.dataBase64, 'base64');
  assert.equal(bytes.readUInt16LE(0), 0x5a4d);
  t.diagnostic(`instrument extract ${bytes.length} bytes sha256=${hash(bytes)} events=${metadata.events} bpHits=${metadata.bpHits}`);
});

test('HTTP instrumented-exception-dump keeps the strict parser for the legacy UPX layout', { timeout: 30000 }, async t => {
  if (!upxPacked) return t.skip('Pinned static fixture test-results/fixtures/upx/lbop20.upx.bin is not installed');
  // The legacy short-stub layout overlaps headers; this engine does not use the
  // UPX adapter, so the strict structural rejection is the expected product path.
  errorIs(await post('unpack', { dataBase64: upxPacked.toString('base64'), name: 'lbop20.upx.bin',
    engine: 'instrumented-exception-dump', timeoutSeconds: 3 }), 400, 'section-overlaps-headers');
});

test('HTTP aspack-pe32-huffman and mew-pe32-lzma1 unpack their anchored fixtures', { timeout: 30000 }, async t => {
  if (!aspackPacked || !mewPacked) return t.skip('Pinned static fixtures test-results/fixtures/aspack and /mew are not installed');
  // Both engines use bounded byte anchoring (aspack 2.x-ep437, mew 11-SE-154).
  // The lbop20 aspack sample is the exact ep437 build pinned by tests/aspack.test.js,
  // so anchoring hits and full products are asserted (verified by hand first).
  const aspack = await post('unpack', { dataBase64: aspackPacked.toString('base64'), name: 'aspack-lbop20.bin', engine: 'aspack-pe32-huffman' });
  assert.equal(aspack.status, 200, aspack.text);
  const aspackBytes = Buffer.from(aspack.body.dataBase64, 'base64');
  assert.equal(aspack.body.metadata.engine, 'aspack-pe32-huffman');
  assert.equal(aspack.body.metadata.variant, '2.x-ep437');
  assert.equal(aspack.body.metadata.outputKind, 'rebuilt-pe');
  assert.equal(aspack.body.metadata.originalEntryPoint, 0x1252);
  assert.equal(aspack.body.metadata.importedFunctions, 64);
  assert.equal(aspack.body.metadata.decodedBlocks.length, 5);
  assert.equal(aspack.body.report.pe.entryPointRva, 0x1252);
  assert.match(aspack.body.name, /unpacked\.exe$/);
  t.diagnostic(`aspack output ${aspackBytes.length} bytes sha256=${hash(aspackBytes)}`);

  const mew = await post('unpack', { dataBase64: mewPacked.toString('base64'), name: 'lbop20-mew.bin', engine: 'mew-pe32-lzma1' });
  assert.equal(mew.status, 200, mew.text);
  const mewBytes = Buffer.from(mew.body.dataBase64, 'base64');
  assert.equal(mew.body.metadata.engine, 'mew-pe32-lzma1');
  assert.equal(mew.body.metadata.variant, '11-SE-154');
  assert.equal(mew.body.metadata.outputKind, 'rebuilt-pe');
  assert.equal(mew.body.metadata.loaderBlocks, 2);
  assert.equal(mew.body.metadata.decodedBlocks[0].size, 75890);
  assert.equal(mew.body.metadata.importedFunctions, 64);
  assert.equal(mew.body.report.pe.entryPointRva, 0x1252);
  assert.ok(mew.body.metadata.warnings.includes('mew-overlapping-dos-header'));
  assert.match(mew.body.name, /unpacked\.exe$/);
  t.diagnostic(`mew output ${mewBytes.length} bytes sha256=${hash(mewBytes)}`);
});

test('HTTP armadillo-nanomites rejects an EP=0 PE before spawning the oracle', { timeout: 15000 }, async () => {
  // Entry-point validation runs before any debugger spawn (the pattern proven
  // in tests/transport-schema.test.js), so the gate rejects quickly and safely.
  const gate = { dataBase64: minimalPE(0x400, 0).toString('base64'), name: 'gate.exe', engine: 'armadillo-nanomites' };
  errorIs(await post('unpack', gate), 400, 'armadillo-unsupported-input');
  errorIs(await post('unpack', { ...gate, probes: [{ address: 0x401000, size: 2 }], timeoutSeconds: 1,
    maxEvents: 16, sampleArgs: [], imageBase: 0x400000 }), 400, 'armadillo-unsupported-input');
});
