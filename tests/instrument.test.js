import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { parsePE } from '../src/core/pe.js';
import { AnalysisError } from '../src/core/errors.js';
import { INSTRUMENT_ENGINE, unpackInstrumented } from '../src/core/unpackers/instrument.js';

const run = promisify(execFile);
const script = fileURLToPath(new URL('../scripts/dynamic/dump_instrument.py', import.meta.url));
const source = fileURLToPath(new URL('./fixtures/instrument-host.c', import.meta.url));
const upx = fileURLToPath(new URL('../tools/upx/upx.exe', import.meta.url));
const compiler = process.env.INSTRUMENT_CL || 'C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x86\\cl.exe';
const sdk = process.env.INSTRUMENT_SDK || 'C:\\Program Files (x86)\\Windows Kits\\10';
const sdkVersion = process.env.INSTRUMENT_SDK_VERSION || '10.0.26100.0';
const vc = join(dirname(compiler), '..', '..', '..');
const directories = [];
let ready = false;
if (process.platform === 'win32') {
  try { await run('py', ['-3.11', '-X', 'utf8', '--version']); ready = process.env.LIVE_SAMPLE_TESTS === '1'; } catch {}
}
const runtime = { skip: !ready && 'requires win32 + py -3.11' };
const hosts = { skip: (!ready || !existsSync(compiler)) && 'requires win32 + py -3.11 + MSVC x86/Windows SDK' };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function temp() {
  await access(tmpdir());
  const path = await mkdtemp(join(tmpdir(), 'instrument-test-'));
  directories.push(path);
  return path;
}
after(async () => { await Promise.all(directories.map(path => rm(path, { recursive: true, force: true }))); });

let fixturePromise;
async function fixture() {
  fixturePromise ||= (async () => {
    const dir = await temp(), exe = join(dir, 'instrument-host.exe'), obj = join(dir, 'host.obj');
    const includes = ['shared', 'um', 'ucrt'].map(part => '/I' + join(sdk, 'Include', sdkVersion, part));
    await run(compiler, ['/nologo', '/c', '/O1', '/GS-', '/Zl', '/W4', '/I' + join(vc, 'include'), ...includes, '/Fo' + obj, source], { cwd: dir });
    await run(join(dirname(compiler), 'link.exe'), ['/NOLOGO', '/MACHINE:X86', '/ENTRY:start', '/BASE:0x400000',
      '/FIXED', '/DYNAMICBASE:NO', '/INCREMENTAL:NO', '/SAFESEH:NO', '/NODEFAULTLIB', '/SUBSYSTEM:CONSOLE',
      '/OUT:' + exe, '/IMPLIB:' + join(dir, 'host.lib'), obj, join(sdk, 'Lib', sdkVersion, 'um', 'x86', 'kernel32.Lib')], { cwd: dir });
    const bytes = new Uint8Array(await readFile(exe));
    return { dir, exe, bytes, pe: parsePE(bytes), exports: exportsOf(bytes) };
  })();
  return fixturePromise;
}

function exportsOf(bytes) {
  const pe = parsePE(bytes), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const at = rva => { const offset = pe.rvaToOffset(rva); assert.notEqual(offset, null); return offset; };
  const exp = at(pe.directories[0].rva), names = view.getUint32(exp + 24, true);
  const functions = at(view.getUint32(exp + 28, true)), nameTable = at(view.getUint32(exp + 32, true));
  const ordinals = at(view.getUint32(exp + 36, true));
  const result = {};
  for (let i = 0; i < names; i++) {
    const start = at(view.getUint32(nameTable + i * 4, true));
    let end = start;
    while (bytes[end]) end++;
    const name = Buffer.from(bytes.subarray(start, end)).toString('ascii').replace(/^_/, '');
    result[name] = view.getUint32(functions + view.getUint16(ordinals + i * 2, true) * 4, true);
  }
  return result;
}

function exportedDword(result, fixture, name) {
  const pe = parsePE(result.bytes, 0x8000000), offset = pe.rvaToOffset(fixture.exports[name], 4);
  assert.notEqual(offset, null, `export ${name} must be dumped`);
  return new DataView(result.bytes.buffer, result.bytes.byteOffset, result.bytes.byteLength).getUint32(offset, true);
}

async function invoke(exe, args = [], seconds = 0.65, maxEvents = 2000) {
  const dir = await temp(), dump = join(dir, 'dump.bin');
  const result = await run('py', ['-3.11', '-X', 'utf8', script, exe, dump, String(seconds), String(maxEvents), JSON.stringify(args)], {
    encoding: 'utf8', timeout: 15000, maxBuffer: 8 * 1024 * 1024,
  });
  return { info: JSON.parse(result.stdout.trim().split(/\r?\n/).pop()), dump, dir, stderr: result.stderr };
}

// Read-only OS process queries; test host and descendants are never terminated by tests.
async function alive(pids) {
  const code = "import ctypes,json,sys; k=ctypes.WinDLL('kernel32'); k.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]; k.OpenProcess.restype=ctypes.c_void_p; k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32]; k.CloseHandle.argtypes=[ctypes.c_void_p]; result=[]\nfor pid in json.loads(sys.argv[1]):\n h=k.OpenProcess(0x100000,0,pid)\n if h:\n  if k.WaitForSingleObject(h,0)==258: result.append(pid)\n  k.CloseHandle(h)\nprint(json.dumps(result))";
  const result = await run('py', ['-3.11', '-X', 'utf8', '-c', code, JSON.stringify(pids)]);
  return JSON.parse(result.stdout);
}

async function instrumentProcesses() {
  const code = "import ctypes,json; from ctypes import wintypes as w\nclass E(ctypes.Structure):\n _fields_=[('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('exe',w.WCHAR*260)]\nk=ctypes.WinDLL('kernel32'); k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]; k.CreateToolhelp32Snapshot.restype=w.HANDLE; k.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(E)]; k.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(E)]; k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenProcess.restype=w.HANDLE; k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]; k.CloseHandle.argtypes=[w.HANDLE]\ns=k.CreateToolhelp32Snapshot(2,0); e=E(); e.size=ctypes.sizeof(e); more=k.Process32FirstW(s,ctypes.byref(e)); result=[]\nwhile more:\n if e.exe.lower()=='in.exe':\n  h=k.OpenProcess(0x1000,0,e.pid)\n  if h:\n   b=ctypes.create_unicode_buffer(32768); n=w.DWORD(32768)\n   if k.QueryFullProcessImageNameW(h,0,b,ctypes.byref(n)) and 'older-shells-instrument-' in b.value: result.append(e.pid)\n   k.CloseHandle(h)\n more=k.Process32NextW(s,ctypes.byref(e))\nk.CloseHandle(s); print(json.dumps(result))";
  return JSON.parse((await run('py', ['-3.11', '-X', 'utf8', '-c', code])).stdout);
}

test('independent descriptor exposes a sample-executing instrument/debug extraction route', () => {
  assert.equal(INSTRUMENT_ENGINE.mode, 'instrument');
  assert.equal(INSTRUMENT_ENGINE.route, 'instrument/debug');
  assert.equal(INSTRUMENT_ENGINE.outputKind, 'extract-pe');
  assert.equal(INSTRUMENT_ENGINE.runtime, 'server');
  assert.equal(INSTRUMENT_ENGINE.requiresSampleExecution, true);
  assert.equal(INSTRUMENT_ENGINE.runtimeVerified, false);
});

test('self-test checks actual ctypes offsetof, KUED/stdcall stack slots, and range rejection', runtime, async () => {
  const { stdout } = await run('py', ['-3.11', '-X', 'utf8', script, '--self-test']);
  const info = JSON.parse(stdout);
  assert.equal(info.ok, true);
  assert.equal(info.checks.length, 8);
  assert.equal(info.floatSaveSize, 112);
  assert.equal(info.contextSize, 716);
  assert.deepEqual(info.offsets, { FloatSave: 28, SegGs: 140, Eip: 0xb8, EFlags: 0xc0, Esp: 0xc4, ExtendedRegisters: 0xcc });
});

test('static stat and adapter reject PE32+, DLL, CLR and invalid ranges before execution', hosts, async () => {
  const f = await fixture(), dir = await temp();
  const good = await run('py', ['-3.11', '-X', 'utf8', script, '--stat', f.exe]);
  assert.equal(JSON.parse(good.stdout).pe.magic, 0x10b);
  const mutations = {
    'pe32plus': v => { v.setUint16(f.pe.peOffset + 4, 0x8664, true); v.setUint16(f.pe.optionalOffset, 0x20b, true); v.setUint32(f.pe.optionalOffset + 108, 0, true); },
    'dll': v => v.setUint16(f.pe.peOffset + 22, 0x2102, true),
    'clr': v => v.setUint32(f.pe.directoryOffset + 14 * 8, 0x1000, true),
    'entry-range': v => v.setUint32(f.pe.optionalOffset + 16, 0xffff0000, true),
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const bytes = f.bytes.slice(); mutate(new DataView(bytes.buffer));
    const path = join(dir, name + '.exe'); await writeFile(path, bytes);
    await assert.rejects(run('py', ['-3.11', '-X', 'utf8', script, '--stat', path]), error => {
      const info = JSON.parse(error.stdout);
      assert.equal(info.ok, false); assert.equal(info.error, 'unsupported-input'); assert.equal(error.code, 2);
      return true;
    });
    await assert.rejects(unpackInstrumented(bytes, name), error => error instanceof AnalysisError && error.code === 'instrument-unsupported-input');
  }
  await assert.rejects(unpackInstrumented(f.bytes, 'host', { timeoutSeconds: NaN }), error => error instanceof AnalysisError && error.code === 'invalid-options');
});

test('real benign VEH + NtContinue hits both planted hooks once with legal user contexts', hosts, async t => {
  const f = await fixture();
  const result = await unpackInstrumented(f.bytes, 'benign-host.exe', { timeoutSeconds: 0.7 });
  const m = result.metadata, kued = m.observations.find(item => item.source === 'kued'), cont = m.observations.find(item => item.source === 'cont');
  assert.equal(m.bpHits, 2); assert.equal(m.hookHits, 2); assert.ok(m.events > m.bpHits);
  assert.ok(kued && cont, JSON.stringify(m.observations));
  assert.equal(kued.validContext, true); assert.equal(cont.validContext, true);
  assert.equal(kued.code, 0xc000001d);
  assert.equal(kued.eip, m.imageBase + f.exports.faultSite);
  assert.equal(kued.exceptionAddress, kued.eip);
  assert.equal(cont.eip, kued.eip + 2);
  assert.equal(kued.abi, 'kued32-kernel-transfer'); assert.equal(cont.abi, 'ntcontinue32-stdcall');
  assert.ok(kued.contextPointer > kued.stackPointer && kued.contextPointer - kued.stackPointer < 0x10000);
  assert.ok(cont.returnAddress > 0x10000); assert.equal(cont.testAlert, 0);
  assert.ok(m.observations.every(item => item.executableLanding && item.eflags & 2 && item.esp > 0x10000));
  assert.ok(m.hookSites.every(site => site.hits === 1 && site.armed === false));
  assert.equal(exportedDword(result, f, 'sehCount'), 3); // replay progressed through all three UD2s
  assert.equal(exportedDword(result, f, 'continueCount'), 1);
  assert.equal(exportedDword(result, f, 'phase'), 3);
  assert.equal(m.singleStep, false); assert.equal(m.debugPortHidden, false);
  assert.equal(m.outputKind, 'extract-pe'); assert.equal(m.oepConfirmed, false);
  assert.deepEqual(await alive([m.samplePid]), []);
  t.diagnostic(JSON.stringify({ events: m.events, bpHits: m.bpHits, landings: m.observations.map(item => item.eip), phase: 3 }));
});

test('Python output protocol writes the adjacent imports snapshot and cleanup precedes completion', hosts, async () => {
  const f = await fixture(), { info, dump, stderr } = await invoke(f.exe);
  assert.equal(stderr, '');
  assert.equal(info.ok, true); assert.equal(info.stage, 'instrumented'); assert.equal(info.bpHits, 2);
  assert.equal(info.observations.length, info.bpHits); assert.equal(info.singleStep, false);
  assert.equal(info.entryPoint, undefined); assert.equal(info.oepConfirmed, false);
  assert.equal(info.startupSync, 'input-entry-one-shot'); assert.equal(info.startupSyncHits, 1);
  const image = await readFile(dump), snapshot = JSON.parse(await readFile(`${dump}.imports.json`, 'utf8'));
  assert.equal(image.length, info.size);
  assert.equal(snapshot.modules.length, info.imports.modules);
  assert.equal(snapshot.modules.reduce((sum, m) => sum + m.exports.length, 0), info.imports.exports);
  assert.ok(snapshot.modules.find(module => module.dll === 'NTDLL.DLL'));
  assert.deepEqual(await alive([info.pid]), []);
});

test('benign UPX quiet host dumps golden code with zero genuine hook hits', {
  skip: hosts.skip || (!existsSync(upx) && 'requires trusted tools/upx/upx.exe'),
}, async t => {
  const f = await fixture(), dir = await temp(), packed = join(dir, 'host.upx.exe');
  await run(upx, ['--best', '--no-progress', '-o', packed, f.exe], { cwd: dir });
  const result = await unpackInstrumented(new Uint8Array(await readFile(packed)), 'benign.upx.exe', { timeoutSeconds: 0.7, sampleArgs: ['--quiet'] });
  const m = result.metadata;
  assert.equal(m.bpHits, 0); assert.ok(m.events > 0); assert.deepEqual(m.observations, []);
  assert.deepEqual(m.oepCandidates, []); assert.equal(m.outputKind, 'extract-pe');
  assert.equal(m.oepConfirmed, false); assert.equal(m.importsRebuilt, true);
  assert.ok(m.warnings.includes('no-hook-hits'));
  const golden = f.pe.sections.find(section => section.name === '.text');
  const dumpedPe = parsePE(result.bytes, 0x8000000), offset = dumpedPe.rvaToOffset(golden.rva, golden.virtualSize);
  assert.notEqual(offset, null);
  assert.deepEqual(result.bytes.subarray(offset, offset + golden.virtualSize), f.bytes.subarray(golden.rawOffset, golden.rawOffset + golden.virtualSize));
  assert.equal(exportedDword(result, f, 'phase'), 2);
  assert.deepEqual(await alive([m.samplePid]), []);
  t.diagnostic(JSON.stringify({ events: m.events, bpHits: m.bpHits, goldenCodeBytes: golden.virtualSize, match: '100%', importsRebuilt: m.importsRebuilt, outputKind: m.outputKind }));
});

test('concurrent tasks use separate mkdtemp directories and independent hook state', hosts, async () => {
  const f = await fixture(), before = new Set(await readdir(tmpdir()));
  const tasks = Promise.all([
    unpackInstrumented(f.bytes, 'quiet.exe', { timeoutSeconds: 1.1, sampleArgs: ['--quiet'] }),
    unpackInstrumented(f.bytes, 'events.exe', { timeoutSeconds: 1.1 }),
  ]);
  tasks.catch(() => {}); // attach immediately while the directory probe runs
  // Observe isolation while both Python engines are alive, without exposing temp paths in metadata.
  const dirs = [];
  for (let i = 0; i < 20 && dirs.length < 2; i++) {
    await sleep(30);
    for (const name of await readdir(tmpdir())) {
      if (!before.has(name) && name.startsWith('older-shells-instrument-') && !dirs.includes(name)) dirs.push(name);
    }
  }
  const [quiet, active] = await tasks;
  assert.equal(dirs.length, 2); assert.notEqual(dirs[0], dirs[1]);
  assert.equal(quiet.metadata.bpHits, 0); assert.equal(active.metadata.bpHits, 2);
  assert.notEqual(quiet.metadata.samplePid, active.metadata.samplePid);
  assert.equal(exportedDword(quiet, f, 'phase'), 2); assert.equal(exportedDword(active, f, 'phase'), 3);
  for (const name of dirs) await assert.rejects(access(join(tmpdir(), name)), error => error.code === 'ENOENT');
  assert.deepEqual(await alive([quiet.metadata.samplePid, active.metadata.samplePid]), []);
});

test('exit, timeout, event-limit and second-chance all remove the benign process tree', hosts, async t => {
  const f = await fixture();
  for (const [reason, sampleArgs] of [['exit', ['--tree', '--exit']], ['timeout', ['--tree', '--quiet']],
    ['event-limit', ['--tree', '--debug-events']], ['second-chance', ['--tree', '--unhandled']]]) {
    const result = await unpackInstrumented(f.bytes, `${reason}.exe`, { timeoutSeconds: 0.85, sampleArgs, maxEvents: reason === 'event-limit' ? 32 : 2000 });
    const child = exportedDword(result, f, 'childPid');
    assert.ok(child > 0, 'host must really have created a child');
    assert.equal(result.metadata.exitReason, reason);
    assert.deepEqual(await alive([result.metadata.samplePid, child]), []);
    t.diagnostic(JSON.stringify({ reason, parent: result.metadata.samplePid, child, living: 0, captureSource: result.metadata.captureSource }));
  }
});

test('adapter spawn deadline returns stable AnalysisError after tree cleanup and temp deletion', hosts, async () => {
  const f = await fixture(), beforeDirs = new Set(await readdir(tmpdir())), beforePids = new Set(await instrumentProcesses());
  const task = unpackInstrumented(f.bytes, 'deadline.exe', { timeoutSeconds: 20, timeoutMs: 1600, sampleArgs: ['--tree', '--quiet'] });
  const rejection = assert.rejects(task, error => error instanceof AnalysisError && error.code === 'tool-timeout');
  rejection.catch(() => {});
  const observed = new Set();
  for (let i = 0; i < 12 && observed.size < 2; i++) {
    await sleep(60);
    for (const pid of await instrumentProcesses()) if (!beforePids.has(pid)) observed.add(pid);
  }
  await rejection;
  assert.ok(observed.size >= 2, 'deadline test must witness the parent and its real child');
  assert.deepEqual(await alive([...observed]), []);
  assert.deepEqual((await readdir(tmpdir())).filter(name => !beforeDirs.has(name) && name.startsWith('older-shells-instrument-')), []);
});
