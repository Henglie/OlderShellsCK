import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import '../src/server/engines-server.js';
import { unpack, capabilities } from '../src/core/index.js';
import { parsePE } from '../src/core/pe.js';
import { rebuildMemoryImagePe, applyImportSnapshot, scanIndirectImports } from '../src/core/unpackers/dynamic.js';

const run = promisify(execFile);
let ready = false;
if (process.platform === 'win32') {
  try { await run('py', ['-3.11', '--version']); ready = process.env.LIVE_SAMPLE_TESTS === '1'; } catch {}
}

test('dynamic engine is registered as a sample-executing server route', { skip: !ready && 'win32 with py -3.11 required' }, () => {
  const descriptor = capabilities().unpackers.find(engine => engine.id === 'dynamic-debug-dump');
  assert.ok(descriptor);
  assert.equal(descriptor.mode, 'dynamic-debug');
  assert.equal(descriptor.runtime, 'server');
  assert.equal(descriptor.requiresSampleExecution, true);
  assert.equal(descriptor.outputKind, 'dump-pe');
});

test('dynamic dump stops exactly at the OEP of an unpacked binary', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  const result = await unpack(bytes, 'dynamic-debug-dump', 'golden.bin', { oepRva: 0x1252 });
  assert.ok(result.metadata.outputKind === 'dump-pe' || result.metadata.outputKind === 'rebuilt-pe');
  assert.equal(result.metadata.importsRebuilt === true, result.metadata.outputKind === 'rebuilt-pe');
  assert.ok(result.metadata.warnings.includes('runtime-not-verified'));
  assert.equal(result.metadata.originalEntryPoint, 0x1252);
  assert.equal(result.metadata.lateDump, false);
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 2)), 'MZ');
  const pe = parsePE(result.bytes, 0x8000000);
  assert.equal(pe.entryPointRva, 0x1252);
});

test('dynamic dump of a packed UPX sample yields the unpacked image with a late-dump warning', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const golden = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  const result = await unpack(packed, 'dynamic-debug-dump', 'lbop20.upx.bin', { oepRva: 0x1252 });
  assert.ok(result.metadata.outputKind === 'dump-pe' || result.metadata.outputKind === 'rebuilt-pe');
  if (result.metadata.lateDump) assert.ok(result.metadata.warnings.includes('dump-after-entry'));
  const dump = result.bytes;
  let same = 0;
  for (let index = 0; index < 45568; index++) if (dump[0x1000 + index] === golden[0x1000 + index]) same++;
  assert.ok(same / 45568 > 0.90, `unpacked code must substantially match the independent golden, got ${(100 * same / 45568).toFixed(2)}%`);
});

test('dynamic engine refuses to run without an explicit OEP', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  await assert.rejects(unpack(bytes, 'dynamic-debug-dump', 'golden.bin'), error => error.code === 'missing-oep');
});

test('dynamic engine auto-derives the OEP for statically known families', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const result = await unpack(packed, 'dynamic-debug-dump', 'lbop20.upx.bin', {});
  assert.equal(result.metadata.originalEntryPoint, 0x1252);
  assert.equal(result.metadata.oepSource, 'derived:upx-pe32-nrv');
  assert.ok(['dump-pe', 'rebuilt-pe'].includes(result.metadata.outputKind), `graded output expected, got ${result.metadata.outputKind}`);
});

test('auto-oep mode locates the unpacked region without a known OEP', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const golden = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  const result = await unpack(packed, 'dynamic-debug-dump', 'lbop20.upx.bin', { mode: 'auto-oep' });
  assert.equal(result.metadata.oepSource, 'auto-located');
  assert.ok(['dump-pe', 'rebuilt-pe', 'extract-pe'].includes(result.metadata.outputKind));
  let same = 0;
  for (let index = 0; index < 45568; index++) if (result.bytes[0x1000 + index] === golden[0x1000 + index]) same++;
  assert.ok(same / 45568 > 0.85, `auto-located dump must be substantially unpacked, got ${(100 * same / 45568).toFixed(2)}%`);
});

test('extract mode captures an analyzable image for protected samples', { skip: !ready && 'win32 with py -3.11 required' }, async () => {  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const golden = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  const result = await unpack(packed, 'dynamic-debug-dump', 'lbop20.upx.bin', { mode: 'extract' });
  assert.equal(result.metadata.outputKind, 'extract-pe');
  assert.ok(result.metadata.warnings.includes('extraction-stage'));
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 2)), 'MZ');
  let same = 0;
  for (let index = 0; index < 45568; index++) if (result.bytes[0x1000 + index] === golden[0x1000 + index]) same++;
  assert.ok(same / 45568 > 0.85, `extracted code must be substantially unpacked, got ${(100 * same / 45568).toFixed(2)}%`);
});

function fakeRuntimeDump() {
  const bytes = new Uint8Array(0x1400);
  const view = new DataView(bytes.buffer);
  const w16 = (o, v) => view.setUint16(o, v, true), w32 = (o, v) => view.setUint32(o, v, true);
  bytes[0] = 0x4d; bytes[1] = 0x5a; w32(0x3c, 0x40);
  w32(0x40, 0x4550); w16(0x44, 0x14c); w16(0x46, 1); w16(0x54, 0xe0); w16(0x56, 0x102);
  w16(0x58, 0x10b); w32(0x58 + 16, 0x1004); w32(0x58 + 28, 0x400000);
  w32(0x58 + 32, 0x1000); w32(0x58 + 36, 0x200); w32(0x58 + 56, 0x2000); w32(0x58 + 60, 0x400);
  w32(0x58 + 92, 16);
  w32(0x58 + 96 + 8, 0x1000); w32(0x58 + 96 + 12, 40);
  bytes.set([0x2e, 0x74, 0x65, 0x78, 0x74], 0x138);
  w32(0x138 + 8, 0x300); w32(0x138 + 12, 0x1000); w32(0x138 + 16, 0x400); w32(0x138 + 20, 0x1000); w32(0x138 + 36, 0x60000020);
  w32(0x1000 + 12, 0x1200); w32(0x1000 + 16, 0x1100);
  w32(0x1100, 0x77e21234); w32(0x1104, 0x77e22345); w32(0x1108, 0x77e23456);
  [...'KERNEL32.DLL'].forEach((c, i) => { bytes[0x1200 + i] = c.charCodeAt(0); });
  return bytes;
}

const fakeSnapshot = JSON.stringify({ modules: [{ dll: 'KERNEL32.DLL', imageBase: '0x77e20000', exports: [
  { rva: '0x1234', name: 'CreateFileW' }, { rva: '0x2345', name: 'ReadFile' }, { rva: '0x3456', ordinal: 12 }] }] });

test('import snapshot rebuilds a disk import table from runtime-resolved thunks', () => {
  const applied = applyImportSnapshot(fakeRuntimeDump(), fakeSnapshot);
  assert.equal(applied.outputKind, 'rebuilt-pe');
  assert.equal(applied.importsRebuilt, true);
  assert.equal(applied.warning, null);
  const pe = parsePE(applied.bytes);
  assert.deepEqual(pe.warnings, []);
  assert.equal(pe.sections.length, 2);
  assert.equal(pe.sections[1].name, '.idata');
  assert.equal(pe.sections[1].rva, 0x2000);
  assert.equal(pe.sections[1].rawOffset, 0x2000);
  assert.equal(pe.sections[1].rawSize, 0x200);
  assert.deepEqual(pe.directories[1], { rva: 0x2000, size: 40 });
  assert.deepEqual(pe.directories[12], { rva: 0x1100, size: 16 });
  assert.equal(pe.sizeOfImage, 0x3000);
  assert.equal(applied.bytes.length, 0x2200);
  assert.deepEqual(pe.imports, [{ name: 'KERNEL32.DLL', firstThunk: 0x1100, functions: [
    { name: 'CreateFileW', hint: 0 }, { name: 'ReadFile', hint: 0 }, { ordinal: 12 }] }]);
  const view = new DataView(applied.bytes.buffer, applied.bytes.byteOffset, applied.bytes.byteLength);
  assert.equal(view.getUint32(0x2000 + 40 + 8, true), 0x8000000c);
  assert.equal(view.getUint32(0x1100, true), 0x77e21234);
});

test('unknown runtime VA rejects the rebuild and keeps the untouched dump', () => {
  const dump = fakeRuntimeDump();
  const before = new Uint8Array(dump);
  const partial = JSON.stringify({ modules: [{ dll: 'KERNEL32.DLL', imageBase: '0x77e20000', exports: [{ rva: '0x1234', name: 'CreateFileW' }] }] });
  const applied = applyImportSnapshot(dump, partial);
  assert.equal(applied.outputKind, 'dump-pe');
  assert.equal(applied.importsRebuilt, false);
  assert.equal(applied.warning, 'imports-not-rebuilt');
  assert.deepEqual(applied.bytes, before);
  assert.deepEqual(dump, before);
});

test('absent snapshot keeps the plain dump-pe behavior', () => {
  const applied = applyImportSnapshot(fakeRuntimeDump(), null);
  assert.equal(applied.outputKind, 'dump-pe');
  assert.equal(applied.importsRebuilt, false);
  assert.equal(applied.warning, null);
});

test('malformed snapshot degrades conservatively to imports-not-rebuilt', () => {
  const applied = applyImportSnapshot(fakeRuntimeDump(), '{not-json');
  assert.equal(applied.outputKind, 'dump-pe');
  assert.equal(applied.importsRebuilt, false);
  assert.equal(applied.warning, 'imports-not-rebuilt');
});

test('scanIndirectImports collects deduped slot RVAs from call/jmp [imm32] patterns', () => {
  const bytes = fakeRuntimeDump();
  bytes.set([0xff, 0x15, 0x00, 0x11, 0x40, 0x00], 0x1000); // call [0x401100] -> slot 0x1100
  bytes.set([0xff, 0x25, 0x08, 0x11, 0x40, 0x00], 0x1010); // jmp [0x401108] -> slot 0x1108
  bytes.set([0xff, 0x15, 0x00, 0x11, 0x40, 0x00], 0x1020); // duplicate slot
  bytes.set([0xff, 0x15, 0x99, 0x99, 0x99, 0x99], 0x1030); // VA outside the image
  bytes.set([0xff, 0x15, 0x00, 0x11, 0x40, 0x00], 0x800);  // outside any executable section
  const scan = scanIndirectImports(bytes, { imageBase: 0x400000 });
  assert.deepEqual(scan.slots, [0x1100, 0x1108]);
  assert.equal(scan.count, 2);
});

function destroyedIatDump() {
  const bytes = new Uint8Array(0x1400);
  const view = new DataView(bytes.buffer);
  const w16 = (o, v) => view.setUint16(o, v, true), w32 = (o, v) => view.setUint32(o, v, true);
  bytes[0] = 0x4d; bytes[1] = 0x5a; w32(0x3c, 0x40);
  w32(0x40, 0x4550); w16(0x44, 0x14c); w16(0x46, 1); w16(0x54, 0xe0); w16(0x56, 0x102);
  w16(0x58, 0x10b); w32(0x58 + 16, 0x1004); w32(0x58 + 28, 0x400000);
  w32(0x58 + 32, 0x1000); w32(0x58 + 36, 0x200); w32(0x58 + 56, 0x2000); w32(0x58 + 60, 0x400);
  w32(0x58 + 92, 16);
  w32(0x58 + 96 + 8, 0); w32(0x58 + 96 + 12, 0); // import directory destroyed
  bytes.set([0x2e, 0x74, 0x65, 0x78, 0x74], 0x138);
  w32(0x138 + 8, 0x300); w32(0x138 + 12, 0x1000); w32(0x138 + 16, 0x400); w32(0x138 + 20, 0x1000); w32(0x138 + 36, 0x60000020);
  const slots = [0x1100, 0x1104, 0x1108, 0x110c, 0x1110];
  const values = [0x77e21234, 0x77e22345, 0x77e23456, 0x77e21234, 0xdeadbee1];
  slots.forEach((rva, index) => {
    const va = 0x400000 + rva;
    bytes.set([0xff, index === 4 ? 0x25 : 0x15, va & 0xff, (va >> 8) & 0xff, (va >> 16) & 0xff, va >>> 24], 0x1000 + index * 8);
    w32(rva, values[index]);
  });
  return bytes;
}

test('scan rebuild reconstructs a loader-compatible import table over destroyed IAT descriptors', () => {
  const applied = applyImportSnapshot(destroyedIatDump(), fakeSnapshot, { imageBase: 0x400000 });
  assert.equal(applied.outputKind, 'rebuilt-pe');
  assert.equal(applied.importsRebuilt, true);
  assert.equal(applied.method, 'scan');
  assert.equal(applied.warning, null);
  const pe = parsePE(applied.bytes);
  assert.deepEqual(pe.warnings, []);
  assert.deepEqual(pe.directories[1], { rva: 0x2000, size: 40 });
  assert.deepEqual(pe.directories[12], { rva: 0x1100, size: 20 });
  assert.deepEqual(pe.imports, [{ name: 'KERNEL32.DLL', firstThunk: 0x1100, functions: [
    { name: 'CreateFileW', hint: 0 }, { name: 'ReadFile', hint: 0 }, { ordinal: 12 }, { name: 'CreateFileW', hint: 0 }] }]);
  const view = new DataView(applied.bytes.buffer, applied.bytes.byteOffset, applied.bytes.byteLength);
  assert.equal(view.getUint32(0x1100, true), 0x77e21234); // original slot kept for the loader to refill
});

test('auto-oep dump labels the imports rebuild method when imports are rebuilt', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const result = await unpack(packed, 'dynamic-debug-dump', 'lbop20.upx.bin', { mode: 'auto-oep' });
  assert.ok(['dump-pe', 'rebuilt-pe', 'extract-pe'].includes(result.metadata.outputKind), `graded output expected, got ${result.metadata.outputKind}`);
  if (result.metadata.importsRebuilt) assert.ok(['scan', 'snapshot'].includes(result.metadata.importsRebuildMethod));
});

const jointDumpUrl = new URL('../test-results/dynamic/lbop20.dump.bin', import.meta.url);
const jointSnapshotUrl = new URL('../test-results/dynamic/lbop20.dump.bin.imports.json', import.meta.url);
const jointGoldenUrl = new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url);
const jointReady = [jointDumpUrl, jointSnapshotUrl, jointGoldenUrl].every(url => existsSync(url));

test('joint rebuild against a real tool snapshot matches the golden imports', { skip: !jointReady && 'requires test-results/dynamic/lbop20.dump.bin and its .imports.json' }, async () => {
  const dump = new Uint8Array(await readFile(jointDumpUrl));
  rebuildMemoryImagePe(dump);
  const applied = applyImportSnapshot(dump, await readFile(jointSnapshotUrl, 'utf8'));
  assert.equal(applied.outputKind, 'rebuilt-pe');
  assert.equal(applied.importsRebuilt, true);
  const mine = parsePE(applied.bytes);
  const golden = parsePE(new Uint8Array(await readFile(jointGoldenUrl)));
  const dlls = pe => [...new Set(pe.imports.map(module => module.name.toUpperCase()))].sort();
  const names = pe => new Set(pe.imports.flatMap(module => module.functions.map(fn => `${module.name.toUpperCase()}!${fn.name ?? '#' + fn.ordinal}`)));
  assert.deepEqual(dlls(mine), dlls(golden));
  const mineNames = names(mine), goldenNames = names(golden);
  assert.ok(mineNames.size > 0);
  // the UPX stub leaves its own thunks (LoadLibraryA/VirtualProtect) in the dump IAT
  const allowed = new Set([...goldenNames, 'KERNEL32.DLL!LoadLibraryA', 'KERNEL32.DLL!VirtualProtect']);
  assert.deepEqual([...mineNames].filter(name => !allowed.has(name)), []);
});

// --- anti-anti-debug v2/v3: NtQueryInformationProcess + NtQuerySystemInformation hiding (MT31/T37) ---
// Goat: a CRT-free 32-bit PE that hammers ntdll!NtQueryInformationProcess with
// the three debug-probing classes and ntdll!NtQuerySystemInformation with
// SystemKernelDebuggerInformation(0x23), logging status plus returned values
// per call to a file the test reads afterwards. Under the hooks every line
// must show the not-debugged ground truth; without them (DUMP_ANTIANTI=0
// control run) the real debugger must be observable via the NQIP fields.
const dumpOepScript = fileURLToPath(new URL('../scripts/dynamic/dump_oep.py', import.meta.url));
const cl = process.env.DYNAMIC_CL || process.env.INSTRUMENT_CL ||
  'C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x86\\cl.exe';
const sdkRoot = process.env.INSTRUMENT_SDK || 'C:\\Program Files (x86)\\Windows Kits\\10';
const sdkVersion = process.env.INSTRUMENT_SDK_VERSION || '10.0.26100.0';
const goatReady = ready && existsSync(cl);
const goatSkip = !goatReady && 'requires win32 + py -3.11 + MSVC x86/Windows SDK';
const goatDirs = [];

function goatSource(outPath) {
  return `#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef LONG NTSTATUS;
typedef NTSTATUS (__stdcall *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (__stdcall *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static char *put(char *b, const char *s) { while (*s) *b++ = *s++; return b; }
static char *puthex32(char *b, unsigned long v) {
  static const char h[] = "0123456789ABCDEF";
  for (int i = 28; i >= 0; i -= 4) *b++ = h[(v >> i) & 0xF];
  return b;
}
static char *puthex(char *b, unsigned long v) {
  static const char h[] = "0123456789ABCDEF";
  int started = 0;
  *b++ = '0'; *b++ = 'x';
  for (int i = 28; i >= 0; i -= 4) {
    unsigned long d = (v >> i) & 0xF;
    if (d || started || i == 0) { *b++ = h[d]; started = 1; }
  }
  return b;
}
__declspec(noreturn) void start(void) {
  NtQueryInformationProcess_t q = (NtQueryInformationProcess_t)
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
  NtQuerySystemInformation_t qs = (NtQuerySystemInformation_t)
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
  HANDLE f = CreateFileA("${outPath}", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (!q || !qs) { ExitProcess(2); }
  for (int i = 0; i < 400; i++) {
    unsigned long port = 0xAAAAAAAA, obj = 0xAAAAAAAA, flags = 0xAAAAAAAA, rl = 0;
    unsigned char kdi[2]; unsigned long krl = 0;
    NTSTATUS s1 = q((HANDLE)-1, 0x07, &port, 4, &rl);
    NTSTATUS s2 = q((HANDLE)-1, 0x1E, &obj, 4, NULL);
    NTSTATUS s3 = q((HANDLE)-1, 0x1F, &flags, 4, NULL);
    kdi[0] = 0xAA; kdi[1] = 0xAA;
    NTSTATUS s4 = qs(0x23, kdi, 2, &krl);
    char line[192], *b = line;
    b = put(b, "i="); b = puthex(b, (unsigned long)i);
    b = put(b, " s1="); b = puthex32(b, (unsigned long)s1);
    b = put(b, " port="); b = puthex(b, port);
    b = put(b, " s2="); b = puthex32(b, (unsigned long)s2);
    b = put(b, " obj="); b = puthex(b, obj);
    b = put(b, " s3="); b = puthex32(b, (unsigned long)s3);
    b = put(b, " flags="); b = puthex(b, flags);
    b = put(b, " s4="); b = puthex32(b, (unsigned long)s4);
    b = put(b, " en="); b = puthex(b, kdi[0]);
    b = put(b, " np="); b = puthex(b, kdi[1]);
    b = put(b, "\\r\\n");
    DWORD w;
    WriteFile(f, line, (DWORD)(b - line), &w, NULL);
    Sleep(8);
  }
  CloseHandle(f);
  ExitProcess(0);
}
`;
}

let goatPromise;
async function goat() {
  goatPromise ||= (async () => {
    const dir = await mkdtemp(join(tmpdir(), 'older-shells-anti-'));
    goatDirs.push(dir);
    const src = join(dir, 'goat.c'), obj = join(dir, 'goat.obj'), exe = join(dir, 'goat.exe');
    const seen = join(dir, 'seen.txt');
    await writeFile(src, goatSource(seen.replaceAll('\\', '/')), 'utf8');
    const vc = join(dirname(cl), '..', '..', '..');
    const includes = ['shared', 'um', 'ucrt'].map(part => '/I' + join(sdkRoot, 'Include', sdkVersion, part));
    await run(cl, ['/nologo', '/c', '/O1', '/GS-', '/Zl', '/W3', '/I' + join(vc, 'include'), ...includes, '/Fo' + obj, src], { cwd: dir });
    await run(join(dirname(cl), 'link.exe'), ['/NOLOGO', '/MACHINE:X86', '/ENTRY:start', '/BASE:0x400000',
      '/FIXED', '/DYNAMICBASE:NO', '/INCREMENTAL:NO', '/SAFESEH:NO', '/NODEFAULTLIB', '/SUBSYSTEM:CONSOLE',
      '/OUT:' + exe, '/IMPLIB:' + join(dir, 'goat.lib'), obj, join(sdkRoot, 'Lib', sdkVersion, 'um', 'x86', 'kernel32.Lib')], { cwd: dir });
    return { dir, exe, seen };
  })();
  return goatPromise;
}

async function dumpGoat(extraEnv) {
  const g = await goat();
  const dump = join(g.dir, 'dump.bin');
  // oep_rva 0x400000 lies outside the small goat image, so the OEP INT3 is
  // never planted; extract mode dumps ~1.2s after the loader breakpoint,
  // while the goat loop is still running.
  const result = await run('py', ['-3.11', '-X', 'utf8', dumpOepScript, g.exe, '0x400000', dump, '30', 'extract', '1.2'],
    { encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, PYTHONIOENCODING: 'utf8', ...extraEnv } });
  return { info: JSON.parse(result.stdout.trim().split(/\r?\n/).pop()), seen: g.seen };
}

const hiddenLine = /^i=0x[0-9A-F]+ s1=00000000 port=0x0 s2=C0000353 obj=0x0 s3=00000000 flags=0x1 s4=00000000 en=0x0 np=0x1$/;

test('dump_oep.py carries the canonical x86 CONTEXT ABI (Eip slot 0xB8, 112-byte FSA)', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  const probe = 'import importlib.util,ctypes,json,sys;'
    + 'spec=importlib.util.spec_from_file_location("m",sys.argv[1]);'
    + 'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);'
    + 'print(json.dumps({"fsa":ctypes.sizeof(m.FLOATING_SAVE_AREA),"eax":m.CONTEXT.Eax.offset,'
    + '"eip":m.WOW64_CONTEXT.Eip.offset,"esp":m.WOW64_CONTEXT.Esp.offset,"total":ctypes.sizeof(m.CONTEXT)}))';
  const { stdout } = await run('py', ['-3.11', '-X', 'utf8', '-c', probe, dumpOepScript], { encoding: 'utf8', timeout: 30000 });
  const abi = JSON.parse(stdout.trim().split(/\r?\n/).pop());
  assert.equal(abi.fsa, 112, 'FSA must be exactly 112 bytes (no ErrorOperand overhang)');
  assert.equal(abi.eax, 0xB0);
  assert.equal(abi.eip, 0xB8);
  assert.equal(abi.esp, 0xC4);
  assert.equal(abi.total, 716);
});

test('antiAntiDebug hook fakes the three NtQueryInformationProcess debug classes', { skip: goatSkip }, async () => {
  const { info, seen } = await dumpGoat({});
  assert.equal(info.ok, true, JSON.stringify(info));
  assert.ok(info.antiAntiDebug, 'antiAntiDebug must be reported');
  assert.equal(info.antiAntiDebug.planted, true, JSON.stringify(info.antiAntiDebug));
  assert.ok(info.antiAntiDebug.hits > 0, `expected hook hits, got ${JSON.stringify(info.antiAntiDebug)}`);
  assert.ok(info.antiAntiDebug.faked > 0);
  const lines = (await readFile(seen, 'utf8')).split(/\r?\n/).filter(line => line.startsWith('i='));
  assert.ok(lines.length >= 10, `goat produced only ${lines.length} observations`);
  for (const line of lines) {
    assert.match(line, hiddenLine, `every observed query must look not-debugged: ${line}`);
  }
});

test('antiAntiDebug hook fakes SystemKernelDebuggerInformation(0x23) via NtQuerySystemInformation', { skip: goatSkip }, async () => {
  const { info, seen } = await dumpGoat({});
  assert.equal(info.ok, true, JSON.stringify(info));
  const sys = info.antiAntiDebug.sysInfo;
  assert.ok(sys, `sysInfo report expected, got ${JSON.stringify(info.antiAntiDebug)}`);
  assert.equal(sys.planted, true, JSON.stringify(info.antiAntiDebug));
  assert.ok(sys.hits > 0, `expected NtQuerySystemInformation hook hits, got ${JSON.stringify(sys)}`);
  assert.ok(sys.faked > 0);
  assert.match(sys.va, /^0x[0-9a-f]+$/);
  const lines = (await readFile(seen, 'utf8')).split(/\r?\n/).filter(line => line.startsWith('i='));
  assert.ok(lines.length >= 10);
  for (const line of lines) {
    // Enabled=0, NotPresent=1 with STATUS_SUCCESS on every observation
    assert.match(line, / s4=00000000 en=0x0 np=0x1(?: |$)/, `0x23 must read not-debugged: ${line}`);
  }
});

test('DUMP_ANTIANTI=0 disables the hook and the debugger becomes observable again', { skip: goatSkip }, async () => {
  const { info, seen } = await dumpGoat({ DUMP_ANTIANTI: '0' });
  assert.equal(info.ok, true, JSON.stringify(info));
  assert.deepEqual(info.antiAntiDebug,
    { planted: false, hits: 0, reason: 'disabled', sysInfo: { planted: false, hits: 0 } });
  const lines = (await readFile(seen, 'utf8')).split(/\r?\n/).filter(line => line.startsWith('i='));
  assert.ok(lines.length >= 10);
  // Leak detection rides on the NQIP fields: on a stock host without local
  // kernel debugging, a real NtQuerySystemInformation(0x23) already answers
  // {Enabled=0, NotPresent=1} (the class watches KD, not user-mode
  // debuggers), so the s4/en/np fields cannot distinguish hooked vs bare.
  assert.ok(lines.some(line => !hiddenLine.test(line)),
    'control run must leak at least one real debug-port/object/flags observation');
});

after(async () => { await Promise.all(goatDirs.map(path => rm(path, { recursive: true, force: true }))); });
