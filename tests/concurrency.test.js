import test from 'node:test';
import assert from 'node:assert/strict';
import { execSync, spawn, spawnSync } from 'node:child_process';
import { access, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { availableParallelism, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createJobRunner, MAX_CONCURRENCY } from '../src/server/jobs.js';
import { AnalysisError } from '../src/core/errors.js';
import '../src/server/engines-server.js';
import { unpack } from '../src/core/index.js';

const FIXTURES = new URL('../test-results/fixtures/', import.meta.url);
const UPX_TOOL = fileURLToPath(new URL('../tools/upx/upx.exe', import.meta.url));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const readFixture = async relative => new Uint8Array(await readFile(new URL(relative, FIXTURES)));
const fixtureExists = async relative => { try { await access(new URL(relative, FIXTURES)); return true; } catch { return false; } };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

const isWin32 = process.platform === 'win32';
const pyReady = isWin32 && process.env.LIVE_SAMPLE_TESTS === '1' && spawnSync('py', ['-3.11', '--version'], { timeout: 20000, windowsHide: true }).status === 0;
const upxToolReady = isWin32 && existsSync(UPX_TOOL);
const CORE_FIXTURES = ['upx/lbop20.golden.bin', 'upx/lbop20.upx.bin', 'mpress.exe', 'fsg/fsg131.bin', 'aspack/aspack-lbop20.bin', 'mew/lbop20-mew.bin', 'upx-lzma/base.exe'];
const coreFixturesReady = (await Promise.all(CORE_FIXTURES.map(fixtureExists))).every(Boolean);
const serverReady = pyReady && upxToolReady && coreFixturesReady;

// Unrelated system processes make raw tasklist totals flaky on shared hosts;
// leak assertions use the descendant tree of this test process instead.
function tasklistTotals() {
  const output = execSync('tasklist /FO CSV /NH', { timeout: 30000, windowsHide: true }).toString('utf8');
  let node = 0, python = 0;
  for (const line of output.split(/\r?\n/)) {
    const name = (line.split('","')[0] || '').replace(/^"|"$/g, '').toLowerCase();
    if (name === 'node.exe') node++;
    else if (name === 'py.exe' || /^python\d*\.exe$/.test(name)) python++;
  }
  return { node, python };
}

function descendantCounts(rootPid) {
  const output = execSync('powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId | ConvertTo-Csv -NoTypeInformation"',
    { timeout: 60000, windowsHide: true }).toString('utf8');
  const byParent = new Map();
  for (const line of output.split(/\r?\n/).slice(1)) {
    const cells = line.match(/"([^"]*)"/g);
    if (!cells || cells.length < 3) continue;
    const row = { name: cells[0].slice(1, -1), pid: Number(cells[1].slice(1, -1)), ppid: Number(cells[2].slice(1, -1)) };
    if (!byParent.has(row.ppid)) byParent.set(row.ppid, []);
    byParent.get(row.ppid).push(row);
  }
  const stack = [rootPid], seen = new Set([rootPid]);
  let node = 0, python = 0;
  while (stack.length) {
    for (const row of byParent.get(stack.pop()) || []) {
      if (seen.has(row.pid)) continue;
      seen.add(row.pid);
      if (/^node(?:64)?\.exe$/i.test(row.name)) node++;
      if (/^(?:py|python\d*)\.exe$/i.test(row.name)) python++;
      stack.push(row.pid);
    }
  }
  return { node, python };
}

function codeMatch(dump, golden) {
  let same = 0;
  for (let index = 0; index < 45568; index++) if (dump[0x1000 + index] === golden[0x1000 + index]) same++;
  return same / 45568;
}

const runTool = (file, args, cwd) => new Promise((resolve, reject) => {
  const child = spawn(file, args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.on('error', reject);
  child.on('close', code => code === 0 ? resolve() : reject(new Error(stderr || `exit ${code}`)));
});

test('jobs runner: bounded concurrency, busy rejection, slot release', { skip: !coreFixturesReady && 'fixtures required (node scripts/fetch-fixtures.mjs)' }, async t => {
  const maximum = MAX_CONCURRENCY;
  t.diagnostic(`MAX_CONCURRENCY=${maximum} availableParallelism=${availableParallelism()}`);
  assert.ok(Number.isInteger(maximum) && maximum >= 1 && maximum <= 4);
  const runner = createJobRunner({ timeoutMs: 60000 });
  const golden = await readFixture('upx/lbop20.golden.bin');

  const waveStart = Date.now();
  const wave = [];
  for (let index = 0; index < maximum; index++) wave.push(runner('analyze', new Uint8Array(golden), { name: `wave-${index}.exe` }));
  for (let extra = 0; extra < 4; extra++) {
    await assert.rejects(runner('analyze', new Uint8Array(golden), { name: `over-${extra}.exe` }),
      error => error instanceof AnalysisError && error.code === 'busy', 'overflow submission must reject busy');
  }
  const results = await Promise.all(wave);
  const waveMs = Date.now() - waveStart;
  results.forEach((result, index) => {
    assert.ok(result.file, 'analyze report present');
    assert.equal(result.file.name, `wave-${index}.exe`);
    assert.equal(result.file.size, golden.length);
  });
  assert.equal(new Set(results.map(result => result.file.sha256)).size, 1, 'identical inputs hash identically');

  const seqStart = Date.now();
  const sequential = await runner('analyze', new Uint8Array(golden), { name: 'seq.exe' });
  const seqMs = Date.now() - seqStart;
  assert.equal(sequential.file.name, 'seq.exe');
  t.diagnostic(`wave(${maximum})=${waveMs}ms single=${seqMs}ms speedup=${(maximum * seqMs / waveMs).toFixed(2)}x`);

  const afterRelease = await runner('analyze', new Uint8Array(golden), { name: 'released.exe' });
  assert.equal(afterRelease.file.name, 'released.exe');
});

test('ten engines mixed batch: concurrent isolation', { timeout: 180000, skip: !serverReady && 'win32 + py -3.11 + upx tool + fixtures required' }, async t => {
  const [golden, packed, mpressBytes, fsgBytes, aspackBytes, mewBytes] = await Promise.all([
    readFixture('upx/lbop20.golden.bin'), readFixture('upx/lbop20.upx.bin'), readFixture('mpress.exe'),
    readFixture('fsg/fsg131.bin'), readFixture('aspack/aspack-lbop20.bin'), readFixture('mew/lbop20-mew.bin'),
  ]);
  const armadilloInput = new Uint8Array(golden);
  new DataView(armadilloInput.buffer).setUint32(new DataView(armadilloInput.buffer).getUint32(0x3c, true) + 24 + 16, 0, true);
  const packedSha = sha256(packed);
  // The instrument engine's strict parsePE has no UPX layout adapter, so build
  // it a normally laid-out packed host the same way tests/instrument.test.js does.
  const instrumentDir = await mkdtemp(join(tmpdir(), 'concurrency-inst-'));
  const instrumentHost = join(instrumentDir, 'host.upx.exe');
  await runTool(UPX_TOOL, ['--best', '--no-progress', '-o', instrumentHost, fileURLToPath(new URL('upx-lzma/base.exe', FIXTURES))]);
  const instrumentBytes = new Uint8Array(await readFile(instrumentHost));
  const seenDirs = new Set();
  let batchDone = false;
  const dirWatcher = (async () => {
    const deadline = Date.now() + 120000;
    while (!batchDone && Date.now() < deadline) {
      try { for (const name of await readdir(tmpdir())) if (name.startsWith('older-shells-')) seenDirs.add(name); } catch { /* transient */ }
      await sleep(100);
    }
  })();

  const jobs = [];
  const launch = (engine, bytes, name, options) => jobs.push(
    unpack(bytes, engine, name, options).then(result => ({ engine, name, result }), error => ({ engine, name, error })),
  );
  launch('mpress-pe32-lzmat', new Uint8Array(mpressBytes), 'mpress.exe');
  launch('fsg-pe32', new Uint8Array(fsgBytes), 'fsg131.bin');
  launch('upx-pe32-nrv', new Uint8Array(packed), 'upx-nrv.bin');
  launch('emulated-pe32', new Uint8Array(packed), 'upx-emu.bin');
  launch('aspack-pe32-huffman', new Uint8Array(aspackBytes), 'aspack.bin');
  launch('mew-pe32-lzma1', new Uint8Array(mewBytes), 'mew.bin');
  launch('instrumented-exception-dump', instrumentBytes, 'upx-instrument.bin', { timeoutSeconds: 3, maxEvents: 8000 });
  launch('armadillo-nanomites', armadilloInput, 'armadillo-gate.bin');
  for (let index = 0; index < 3; index++) launch('dynamic-debug-dump', new Uint8Array(packed), `dyn-${index}.bin`, { mode: 'auto-oep' });
  for (let index = 0; index < 3; index++) launch('upx-official', new Uint8Array(packed), `tool-${index}.bin`);

  const batchStart = Date.now();
  assert.equal(jobs.length, 14, '7 engines once + dynamic x3 + upx-official x3 = 14 concurrent jobs');
  const settled = await Promise.all(jobs);
  batchDone = true;
  await dirWatcher;
  const batchMs = Date.now() - batchStart;
  const byEngine = new Map();
  for (const outcome of settled) {
    if (!byEngine.has(outcome.engine)) byEngine.set(outcome.engine, []);
    byEngine.get(outcome.engine).push(outcome);
  }
  assert.equal(byEngine.size, 10, 'all ten engines represented in one batch');

  const expectFulfilled = (engine, outputKind) => {
    for (const { name, result, error } of byEngine.get(engine)) {
      assert.ok(!error, `${engine} must fulfill (${name}): ${error?.code} ${error?.details?.hint || ''}`);
      assert.equal(result.metadata.engine, engine, 'metadata never crosses engines');
      if (outputKind) assert.equal(result.metadata.outputKind, outputKind);
    }
  };
  expectFulfilled('mpress-pe32-lzmat', 'rebuilt-pe');
  expectFulfilled('fsg-pe32', 'rebuilt-pe');
  expectFulfilled('upx-pe32-nrv', 'rebuilt-pe');
  expectFulfilled('emulated-pe32', 'dump-pe');
  expectFulfilled('aspack-pe32-huffman', 'rebuilt-pe');
  expectFulfilled('mew-pe32-lzma1', 'analysis-pe');
  expectFulfilled('instrumented-exception-dump', 'extract-pe');

  const armadillo = byEngine.get('armadillo-nanomites');
  assert.equal(armadillo.length, 1);
  assert.ok(armadillo[0].error, 'armadillo must reject');
  assert.equal(armadillo[0].error.code, 'armadillo-unsupported-input');

  const dynamic = byEngine.get('dynamic-debug-dump');
  dynamic.forEach(({ name, result, error }, index) => {
    assert.ok(!error, `dynamic ${name}: ${error?.code} ${error?.details?.hint || ''}`);
    assert.equal(result.metadata.engine, 'dynamic-debug-dump');
    assert.equal(result.metadata.oepSource, 'auto-located');
    assert.ok(result.name.includes(`dyn-${index}`), 'result maps back to its own request');
    assert.ok(['dump-pe', 'rebuilt-pe', 'extract-pe'].includes(result.metadata.outputKind));
    assert.equal(String.fromCharCode(result.bytes[0], result.bytes[1]), 'MZ');
    const match = codeMatch(result.bytes, golden);
    assert.ok(match > 0.85, `dynamic ${name} dump must be substantially unpacked, got ${(100 * match).toFixed(2)}%`);
    t.diagnostic(`dynamic dyn-${index}: outputKind=${result.metadata.outputKind} importsRebuilt=${result.metadata.importsRebuilt} lateDump=${result.metadata.lateDump} codeMatch=${(100 * match).toFixed(2)}%`);
  });

  const tool = byEngine.get('upx-official');
  tool.forEach(({ result, error }, index) => {
    assert.ok(!error, `upx-official ${index}: ${error?.code} ${error?.details?.hint || ''}`);
    assert.equal(result.metadata.engine, 'upx-official');
    assert.equal(result.metadata.inputSha256, packedSha, 'input hash matches the submitted bytes only');
    assert.ok(result.name.includes(`tool-${index}`));
  });
  assert.equal(Buffer.compare(Buffer.from(tool[0].result.bytes), Buffer.from(tool[1].result.bytes)), 0, 'official runs are deterministic');
  assert.equal(Buffer.compare(Buffer.from(tool[1].result.bytes), Buffer.from(tool[2].result.bytes)), 0);

  // Every fulfilled job already implies its engine's finally-await rm succeeded
  // (a cleanup failure rejects the promise), so directory cleanup rides on the
  // fulfill assertions above. Here we positively prove the concurrent dynamic
  // instances used separate product directories while they were alive.
  const dynDirs = [...seenDirs].filter(name => name.startsWith('older-shells-dyn-'));
  assert.ok(dynDirs.length >= 3, `3 concurrent dynamic instances must use >=3 distinct temp dirs, observed ${dynDirs.length}`);
  await rm(instrumentDir, { recursive: true, force: true });
  t.diagnostic(`mixed batch wall=${batchMs}ms distinctEngineDirs=${seenDirs.size} dynDirs=${dynDirs.length}`);
});

test('worker pool: 20-job analyze batch leaves process counts unchanged', { skip: !coreFixturesReady && 'fixtures required (node scripts/fetch-fixtures.mjs)' }, async t => {
  const before = descendantCounts(process.pid);
  const totalsBefore = tasklistTotals();
  const runner = createJobRunner({ timeoutMs: 60000 });
  const golden = await readFixture('upx/lbop20.golden.bin');
  const started = Date.now();
  let completed = 0, busy = 0;
  for (let wave = 0; wave < 5; wave++) {
    const flight = [];
    for (let index = 0; index < MAX_CONCURRENCY; index++) {
      flight.push(runner('analyze', new Uint8Array(golden), { name: `w${wave}-${index}.exe` }).then(result => {
        assert.equal(result.file.size, golden.length);
        completed++;
      }));
    }
    await assert.rejects(runner('analyze', new Uint8Array(golden), { name: 'probe.exe' }), error => error.code === 'busy');
    busy++;
    await Promise.all(flight);
  }
  const wallMs = Date.now() - started;
  const after = descendantCounts(process.pid);
  const totalsAfter = tasklistTotals();
  t.diagnostic(`20 jobs in 5 waves: wall=${wallMs}ms throughput=${(20000 / wallMs).toFixed(2)} jobs/s busyProbes=${busy}`);
  t.diagnostic(`descendants node=${before.node}->${after.node} python=${before.python}->${after.python}; tasklist totals node=${totalsBefore.node}->${totalsAfter.node} python=${totalsBefore.python}->${totalsAfter.python}`);
  assert.equal(after.node, before.node, `node process leak: ${before.node} -> ${after.node}`);
  assert.equal(after.python, before.python, `python process leak: ${before.python} -> ${after.python}`);
  await sleep(100);
  const workers = (process.getActiveResourcesInfo?.() || []).filter(item => item === 'Worker');
  assert.equal(workers.length, 0, 'no worker threads must stay alive after settle');
});

test('dynamic engine: concurrent runs leave no python residue', { timeout: 180000, skip: !(pyReady && coreFixturesReady) && 'win32 + py -3.11 + fixtures required' }, async t => {
  const before = descendantCounts(process.pid);
  const totalsBefore = tasklistTotals();
  const packed = await readFixture('upx/lbop20.upx.bin');
  const started = Date.now();
  const results = await Promise.all([0, 1].map(index =>
    unpack(new Uint8Array(packed), 'dynamic-debug-dump', `cleanup-${index}.bin`, { mode: 'auto-oep' })));
  const wallMs = Date.now() - started;
  results.forEach((result, index) => {
    assert.equal(result.metadata.engine, 'dynamic-debug-dump');
    assert.ok(result.name.includes(`cleanup-${index}`));
    assert.equal(String.fromCharCode(result.bytes[0], result.bytes[1]), 'MZ');
  });
  let after = descendantCounts(process.pid);
  for (let retry = 0; retry < 10 && (after.python !== before.python || after.node !== before.node); retry++) { await sleep(500); after = descendantCounts(process.pid); }
  const totalsAfter = tasklistTotals();
  t.diagnostic(`2 concurrent dynamic runs: wall=${wallMs}ms descendants node=${before.node}->${after.node} python=${before.python}->${after.python}; tasklist totals node=${totalsBefore.node}->${totalsAfter.node} python=${totalsBefore.python}->${totalsAfter.python}`);
  assert.equal(after.python, before.python, `python residue after dynamic runs: ${before.python} -> ${after.python}`);
  assert.equal(after.node, before.node, `node residue: ${before.node} -> ${after.node}`);
});
