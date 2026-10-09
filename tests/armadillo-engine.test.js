import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePE } from '../src/core/pe.js';
import { createNanomiteProbes } from '../src/core/unpackers/nanomites.js';
import { unpackArmadillo, ARMA_ENGINE, supportsArmadillo } from '../src/core/unpackers/armadillo-engine.js';

const run = promisify(execFile);
const env = { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONDONTWRITEBYTECODE: '1' };
let ready = false;
if (process.platform === 'win32') {
  try { await run('py', ['-3.11', '--version'], { env }); ready = process.env.LIVE_SAMPLE_TESTS === '1'; } catch {}
}

test('armadillo engine descriptor is an explicit-selection native server route', { skip: !ready && 'win32 with py -3.11 required' }, () => {
  assert.equal(ARMA_ENGINE.id, 'armadillo-nanomites');
  assert.equal(ARMA_ENGINE.route, 'native');
  assert.equal(ARMA_ENGINE.runtime, 'server');
  assert.equal(ARMA_ENGINE.platform, 'win32');
  assert.equal(ARMA_ENGINE.requiresSampleExecution, true);
  assert.equal(ARMA_ENGINE.outputKind, 'dump-pe');
  assert.equal(supportsArmadillo(), false);
});

test('non-x86 input is refused before any process is created', { skip: !ready && 'win32 with py -3.11 required' }, async () => {
  // PE32 layout that parses cleanly; only the machine word says x64.
  const bytes = new Uint8Array(0x1400), view = new DataView(bytes.buffer);
  const w16 = (o, v) => view.setUint16(o, v, true), w32 = (o, v) => view.setUint32(o, v, true);
  bytes[0] = 0x4d; bytes[1] = 0x5a; w32(0x3c, 0x40);
  w32(0x40, 0x4550); w16(0x44, 0x8664); w16(0x46, 1); w16(0x54, 0xe0); w16(0x56, 0x102);
  w16(0x58, 0x10b); w32(0x58 + 16, 0x1004); w32(0x58 + 28, 0x400000);
  w32(0x58 + 32, 0x1000); w32(0x58 + 36, 0x200); w32(0x58 + 56, 0x2000); w32(0x58 + 60, 0x400);
  w32(0x58 + 68, 2); w32(0x58 + 92, 16);
  w32(0x58 + 96 + 8, 0x1000); w32(0x58 + 96 + 12, 40);
  bytes.set([0x2e, 0x74, 0x65, 0x78, 0x74], 0x138);
  w32(0x138 + 8, 0x300); w32(0x138 + 12, 0x1000); w32(0x138 + 16, 0x400); w32(0x138 + 20, 0x1000); w32(0x138 + 36, 0x60000020);
  await assert.rejects(unpackArmadillo(bytes, 'x64.exe', {}), error => error.code === 'armadillo-unsupported-input');
});

// MT24's benign dual-process host (same source; compile artifacts stay in the
// harness-approved temporary directory, separate from the engine's own dirs).
const fixtureSource = String.raw`
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
__declspec(dllexport) __declspec(naked) void Nanomite(void) {
    __asm {
        _emit 0xcc
        _emit 0x90
        ret
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        _emit 0x90
        ret
    }
}
int main(int argc, char **argv) {
    int idle = argc > 1 && strcmp(argv[1], "--idle") == 0;
    int false_cc = argc > 1 && strcmp(argv[1], "--false-cc") == 0;
    if (argc > 1 && strcmp(argv[1], "--grandchild") == 0) { Sleep(INFINITE); return 0; }
    if (argc > 1 && strncmp(argv[1], "--child", 7) == 0) {
        int i;
        char path[MAX_PATH], command[2*MAX_PATH];
        STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
        GetModuleFileNameA(NULL,path,sizeof(path));
        sprintf_s(command,sizeof(command),"\"%s\" --grandchild",path);
        if (!CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) return 14;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        if (strcmp(argv[1], "--child-idle") == 0) { Sleep(INFINITE); return 0; }
        for (i=0; i<128; ++i) Nanomite();
        Sleep(INFINITE);
        return 0;
    }
    {
        char path[MAX_PATH], command[2*MAX_PATH];
        STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0}; DEBUG_EVENT ev;
        si.cb = sizeof(si);
        GetModuleFileNameA(NULL,path,sizeof(path));
        sprintf_s(command,sizeof(command),"\"%s\" %s",path,idle ? "--child-idle" : "--child");
        if (!CreateProcessA(NULL,command,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&si,&pi)) return 10;
        for (;;) {
            DWORD status = DBG_CONTINUE;
            if (!WaitForDebugEvent(&ev,1000)) continue;
            if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile)
                CloseHandle(ev.u.CreateProcessInfo.hFile);
            if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile)
                CloseHandle(ev.u.LoadDll.hFile);
            if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
                uintptr_t address = (uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
                if (code == EXCEPTION_BREAKPOINT && address == (uintptr_t)Nanomite) {
                    HANDLE thread = OpenThread(THREAD_ALL_ACCESS,FALSE,ev.dwThreadId);
                    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_FULL;
                    if (!thread || !GetThreadContext(thread,&ctx)) return 11;
                    /* Independent JLE oracle: ZF || (SF != OF). */
                    int jump = !false_cc && ((ctx.EFlags & 0x40) || (((ctx.EFlags >> 7) ^ (ctx.EFlags >> 11)) & 1));
                    ctx.Eip = (DWORD)address + (jump ? 16 : 2);
                    if (!SetThreadContext(thread,&ctx)) return 12;
                    CloseHandle(thread);
                } else if (code != EXCEPTION_BREAKPOINT) status = DBG_EXCEPTION_NOT_HANDLED;
            }
            if (!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,status)) return 13;
            if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
        }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return 0;
}
`;

let fixturePromise;
async function nativeFixture() {
  if (fixturePromise) return fixturePromise;
  fixturePromise = (async () => {
    const assetUrl = new URL('../../【项目规范】/3）项目资产与工具路径.md', import.meta.url);
    const assets = await readFile(assetUrl, 'utf8');
    const vs = assets.match(/\| `<VS根>` \| `([^`]+)`/u)?.[1];
    assert.ok(vs, 'VS root must be declared in the normative asset table');
    const vcvars = join(vs, 'VC', 'Auxiliary', 'Build', 'vcvars32.bat');
    const parent = join(process.env.LOCALAPPDATA, 'Temp', 'opencode');
    await access(parent); await access(vcvars);
    const dir = await mkdtemp(join(parent, 'armadillo-engine-b-'));
    const source = join(dir, 'oracle.c'), executable = join(dir, 'oracle.exe');
    await writeFile(source, fixtureSource, 'utf8');
    const command = `call "${vcvars}" >nul && cl /nologo /W4 /Od /MT "${source}" /Fo"${join(dir, 'oracle.obj')}" /Fe"${executable}" /link /DYNAMICBASE:NO /BASE:0x400000 /INCREMENTAL:NO`;
    await run('cmd.exe', ['/d', '/s', '/c', command], { cwd: dir, env, timeout: 120000, windowsVerbatimArguments: true });
    const disk = new Uint8Array(await readFile(executable)), pe = parsePE(disk);
    assert.equal(pe.machine, 0x14c);
    const view = new DataView(disk.buffer, disk.byteOffset, disk.byteLength);
    const exp = pe.rvaToOffset(pe.directories[0].rva, 40);
    const names = pe.rvaToOffset(view.getUint32(exp + 32, true), 4);
    const ords = pe.rvaToOffset(view.getUint32(exp + 36, true), 2);
    const functions = pe.rvaToOffset(view.getUint32(exp + 28, true), 4);
    let rva;
    for (let i = 0; i < view.getUint32(exp + 24, true); i++) {
      const nameAt = pe.rvaToOffset(view.getUint32(names + i * 4, true), 1);
      let end = nameAt; while (disk[end]) end++;
      const name = new TextDecoder().decode(disk.subarray(nameAt, end));
      if (name === 'Nanomite' || name === '_Nanomite') rva = view.getUint32(functions + view.getUint16(ords + i * 2, true) * 4, true);
    }
    assert.ok(rva, 'fixture must export its explicit probe site');
    const plan = { imageBase: 0x400000, probes: [{ address: 0x400000 + rva, size: 2, samples: createNanomiteProbes() }] };
    return { dir, executable, rva, plan };
  })();
  return fixturePromise;
}

const nativeOptions = { skip: !(ready && process.platform === 'win32') && 'Windows + py -3.11 + normative MSVC asset required', timeout: 240000 };

test('benign dual-process host end-to-end: slave dump plus full nanomite repair', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const bytes = new Uint8Array(await readFile(fixture.executable));
  const result = await unpackArmadillo(bytes, 'oracle.exe', { timeoutSeconds: 20, probePlan: fixture.plan });
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 2)), 'MZ');
  parsePE(result.bytes);
  assert.equal(result.metadata.engine, 'armadillo-nanomites');
  assert.equal(result.metadata.route, 'native');
  assert.equal(result.metadata.outputKind, 'dump-pe');
  assert.equal(result.metadata.requiresSampleExecution, true);
  assert.equal(result.metadata.runtimeVerified, false);
  assert.match(result.metadata.containment, /Job Object/);
  assert.equal(result.metadata.oracleStatus, 'observations-ready');
  assert.equal(result.metadata.dumpRole, 'slave');
  assert.equal(result.metadata.probeSource, 'explicit-plan');
  assert.deepEqual(result.metadata.nanomites, { candidates: 1, repaired: 1, unresolved: 0 });
  assert.ok(!result.metadata.warnings.includes('nanomites-unresolved'));
  assert.ok(result.metadata.warnings.includes('runtime-not-verified'));
  // JLE +14 patched over the dumped CC at the exported probe site.
  assert.equal(result.bytes[fixture.rva], 0x7e);
  assert.equal(result.bytes[fixture.rva + 1], 0x0e);
});

test('plain UPX sample degrades to a master dump with an empty oracle', nativeOptions, async () => {
  const packed = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const golden = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  const result = await unpackArmadillo(packed, 'lbop20.upx.bin', { timeoutSeconds: 4 });
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 2)), 'MZ');
  parsePE(result.bytes);
  assert.equal(result.metadata.outputKind, 'dump-pe');
  assert.equal(result.metadata.dumpRole, 'master');
  assert.equal(result.metadata.probeSource, 'synthesized-degrade');
  assert.equal(result.metadata.oracleStatus, 'probe-unavailable');
  assert.ok(['probe-timeout', 'master-exited-before-probes'].includes(result.metadata.oracleReason), String(result.metadata.oracleReason));
  assert.ok(result.metadata.warnings.includes('degraded-no-slave'));
  assert.ok(result.metadata.warnings.includes('nanomites-unresolved'));
  assert.equal(result.metadata.nanomites.repaired, 0);
  let same = 0;
  for (let index = 0; index < 45568; index++) if (result.bytes[0x1000 + index] === golden[0x1000 + index]) same++;
  assert.ok(same / 45568 > 0.85, `degraded dump must be substantially unpacked, got ${(100 * same / 45568).toFixed(2)}%`);
});

test('oracle timeout path dumps the idle slave and leaves no process-tree residue', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const bytes = new Uint8Array(await readFile(fixture.executable));
  const result = await unpackArmadillo(bytes, 'oracle.exe', { timeoutSeconds: 2, probePlan: fixture.plan, sampleArgs: ['--idle'] });
  assert.equal(result.metadata.oracleStatus, 'probe-unavailable');
  assert.equal(result.metadata.oracleReason, 'probe-timeout');
  assert.equal(result.metadata.cleanupVerified, true);
  assert.equal(result.metadata.dumpRole, 'slave');
  assert.equal(result.bytes[0], 0x4d);
  const pids = result.metadata.processes.map(p => p.pid);
  assert.ok(pids.length >= 2, 'master and slave must be reported');
  const listing = String((await run('tasklist', ['/FO', 'CSV', '/NH'], { env })).stdout || '');
  const alive = new Set([...listing.matchAll(/"([^"]+)","(\d+)"/g)].map(match => Number(match[2])));
  for (const pid of pids) assert.ok(!alive.has(pid), `pid ${pid} must be gone after cleanup`);
});

test('two concurrent engine jobs stay isolated', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const bytes = new Uint8Array(await readFile(fixture.executable));
  const [a, b] = await Promise.all([
    unpackArmadillo(bytes, 'a.exe', { timeoutSeconds: 20, probePlan: fixture.plan }),
    unpackArmadillo(bytes, 'b.exe', { timeoutSeconds: 20, probePlan: fixture.plan }),
  ]);
  for (const result of [a, b]) {
    assert.equal(result.metadata.oracleStatus, 'observations-ready');
    assert.equal(result.metadata.nanomites.repaired, 1);
    assert.equal(result.bytes[fixture.rva], 0x7e);
  }
  const pidsA = a.metadata.processes.map(p => p.pid), pidsB = b.metadata.processes.map(p => p.pid);
  assert.ok(pidsA.length >= 2 && pidsB.length >= 2);
  assert.ok(pidsA.every(pid => !pidsB.includes(pid)), 'process trees must be disjoint');
});
