import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePE } from '../src/core/pe.js';
import { createNanomiteProbes, classifyNanomite, applyNanomiteSidecar } from '../src/core/unpackers/nanomites.js';

const run = promisify(execFile);
const script = fileURLToPath(new URL('../scripts/dynamic/armadillo.py', import.meta.url));
const env = { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONDONTWRITEBYTECODE: '1' };
let python = false;
try { await run('py', ['-3.11', '--version'], { env }); python = process.env.LIVE_SAMPLE_TESTS === '1'; } catch {}
const pythonOptions = { skip: !python && 'py -3.11 required' };

async function py(code) {
  const result = await run('py', ['-3.11', '-B', '-c', `import runpy,json,ctypes,struct; m=runpy.run_path(${JSON.stringify(script)}); ${code}`], { env, maxBuffer: 2 * 1024 * 1024 });
  return JSON.parse(result.stdout);
}

test('independent x86 CONTEXT and host DEBUG_EVENT ABI offsets are exact', pythonOptions, async () => {
  const result = await py("c=m['X86_CONTEXT']; print(json.dumps([ctypes.sizeof(c),c.Eip.offset,c.EFlags.offset,c.Ecx.offset,c.Esp.offset,ctypes.sizeof(m['DEBUG_EVENT']),m['DEBUG_EVENT'].u.offset]))");
  assert.deepEqual(result.slice(0, 5), [716, 0xb8, 0xc0, 0xac, 0xc4]);
  assert.ok(result[5] === 176 && result[6] === 16 || result[5] === 96 && result[6] === 12);
});

const offline = String.raw`
plan={'imageBase':0x400000,'probes':[{'address':0x401000,'size':2,'samples':[{'eflags':0x202,'ecx':2}]}]}
s=m['OracleStateMachine'](100,plan)
s.register_slave(200,201,100,0x400000,True)
ctx={'ContextFlags':0x10007,'Eip':0x401001,'EFlags':0x246,'Ecx':99}
`;
async function offlineState(code) {
  return py(`exec(${JSON.stringify(offline + code)})`);
}

test('state machine requires master-produced slave exception, Get output, Set success and Continue success', pythonOptions, async () => {
  const result = await offlineState(String.raw`
s.slave_exception(100,200,201,0x401000,True)
update=s.context_read(100,200,201,ctx)
out=ctx.copy(); out['Eip']=0x401020
s.context_write(100,200,201,out,True)
before=s.snapshot()
s.continued(100,200,201,0x10002,True)
print(json.dumps({'update':update,'before':before,'after':s.snapshot(),'original':ctx}))
`);
  assert.equal(result.before.complete, false);
  assert.equal(result.after.complete, true);
  assert.equal(result.after.state, 'observations-complete');
  assert.equal(result.update.Ecx, 2);
  assert.equal(result.update.EFlags & 0x8c5, 0);
  assert.equal(result.original.Eip, 0x401001);
  const observation = result.after.probes[0].observations[0];
  assert.equal(observation.eip, 0x401020);
  assert.equal(observation.masterPid, 100);
  assert.equal(observation.slavePid, 200);
  assert.equal(observation.source, 'master-set-context/continue-success');
});

test('state rejects forged PID ownership and our single-process breakpoint as a master oracle', pythonOptions, async () => {
  const result = await offlineState(String.raw`
reasons=[]
for action in [lambda:s.register_slave(100,201,100,0x400000,True),
               lambda:s.register_slave(300,301,999,0x400000,True),
               lambda:s.register_slave(300,301,100,0x400000,False),
               lambda:s.slave_exception(200,200,201,0x401000,True),
               lambda:s.slave_exception(100,100,201,0x401000,True)]:
    try: action()
    except m['BackendError'] as e: reasons.append(e.reason)
print(json.dumps(reasons))
`);
  assert.deepEqual(result, ['invalid-slave-ownership', 'invalid-slave-ownership', 'invalid-slave-ownership', 'event-not-from-master', 'unknown-slave']);
});

test('unsuccessful Set/Continue and unhandled slave CC cannot produce observations', pythonOptions, async () => {
  const result = await offlineState(String.raw`
results=[]
for set_ok,continue_ok,status in [(False,True,0x10002),(True,False,0x10002),(True,True,0x80010001)]:
    s=m['OracleStateMachine'](100,plan); s.register_slave(200,201,100,0x400000,True)
    s.slave_exception(100,200,201,0x401000,True); s.context_read(100,200,201,ctx)
    out=ctx.copy(); out['Eip']=0x401020
    s.context_write(100,200,201,out,set_ok); s.continued(100,200,201,status,continue_ok)
    results.append(s.snapshot())
print(json.dumps(results))
`);
  assert.ok(result.every(r => !r.complete && r.probes[0].observations.length === 0 && r.status === 'probe-unavailable'));
});

test('thread identity and missing CONTROL/INTEGER bits cannot borrow another pending probe', pythonOptions, async () => {
  const result = await offlineState(String.raw`
s.slave_exception(100,200,201,0x401000,True)
other=s.context_read(100,200,999,ctx)
bad=ctx.copy(); bad['ContextFlags']=0x10001
try: s.context_read(100,200,201,bad)
except m['BackendError'] as e: reason=e.reason
print(json.dumps([other,reason,s.snapshot()['complete']]))
`);
  assert.deepEqual(result, [null, 'incomplete-context', false]);
});

test('repeated Get reapplies the same input; latest successful Set is the observation; multiple owners are refused', pythonOptions, async () => {
  const result = await offlineState(String.raw`
s.slave_exception(100,200,201,0x401000,True)
first=s.context_read(100,200,201,ctx); second=s.context_read(100,200,201,ctx)
out=ctx.copy(); out['Eip']=0x401020; s.context_write(100,200,201,out,True)
out['Eip']=0x401030; s.context_write(100,200,201,out,True)
s.continued(100,200,201,0x10002,True)
t=m['OracleStateMachine'](100,plan); t.register_slave(200,201,100,0x400000,True)
t.slave_exception(100,200,201,0x401000,True)
try: t.slave_exception(100,200,202,0x401000,True)
except m['BackendError'] as e: reason=e.reason
print(json.dumps([first==second,s.snapshot()['probes'][0]['observations'][0]['eip'],reason]))
`);
  assert.deepEqual(result, [true, 0x401030, 'ambiguous-probe-owner']);
});

test('native plans reject duplicate sites/samples, unbounded inputs and unsafe flag classes', pythonOptions, async () => {
  const result = await offlineState(String.raw`
reasons=[]
for mutation in ['flags','repeat','site','count']:
    p=json.loads(json.dumps(plan))
    if mutation=='flags': p['probes'][0]['samples'][0]['eflags']=0x302
    if mutation=='repeat': p['probes'][0]['samples']*=2
    if mutation=='site': p['probes']*=2
    if mutation=='count': p['probes'][0]['samples']*=129
    try: m['validate_plan'](p)
    except m['BackendError'] as e: reasons.append(e.reason)
print(json.dumps(reasons))
`);
  assert.deepEqual(result, ['unsupported-probe-flags', 'duplicate-probe-sample', 'invalid-probe-site', 'invalid-probe-samples']);
});

test('independent state instances isolate probes and snapshots', pythonOptions, async () => {
  const result = await offlineState(String.raw`
t=m['OracleStateMachine'](300,plan); t.register_slave(400,401,300,0x400000,True)
s.slave_exception(100,200,201,0x401000,True); s.context_read(100,200,201,ctx)
out=ctx.copy(); out['Eip']=0x401020
s.context_write(100,200,201,out,True); s.continued(100,200,201,0x10002,True)
snapshot=s.snapshot(); snapshot['probes'][0]['observations'][0]['eip']=0
print(json.dumps([s.snapshot(),t.snapshot()]))
`);
  assert.equal(result[0].probes[0].observations[0].eip, 0x401020);
  assert.equal(result[1].probes[0].observations.length, 0);
});

test('missing explicit probe plan returns a stable sidecar error without starting a process', pythonOptions, async () => {
  let result;
  try { await run('py', ['-3.11', '-B', script, '--mode', 'probe'], { env }); }
  catch (error) { result = JSON.parse(error.stdout); assert.equal(error.code, 3); }
  assert.equal(result.status, 'probe-unavailable');
  assert.equal(result.reason, 'missing-probe-plan');
  assert.deepEqual(result.processes, []);
  assert.equal(result.complete, false);
});

// Original benign fixture, embedded here to respect MT24's five-file write lock.
// Compiled artifacts/source stay in the harness-approved temporary directory.
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

// Machine-specific paths are sourced from the normative asset table, not copied into the backend.
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
    const dir = await mkdtemp(join(parent, 'armadillo-mt24-'));
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
    const raw = pe.rvaToOffset(rva, 17);
    assert.deepEqual([...disk.slice(raw, raw + 3)], [0xcc, 0x90, 0xc3]);
    assert.equal(disk[raw + 16], 0xc3);
    const memory = new Uint8Array(pe.sizeOfImage);
    for (const section of pe.sections) memory.set(disk.subarray(section.rawOffset, section.rawOffset + section.rawSize), section.rva);
    const address = 0x400000 + rva;
    const planPath = join(dir, 'plan.json');
    await writeFile(planPath, JSON.stringify({ imageBase: 0x400000,
      probes: [{ address, size: 2, samples: createNanomiteProbes() }] }));
    return { dir, executable, memory, address, rva, planPath };
  })();
  return fixturePromise;
}

async function observe(fixture, sampleArgs = [], timeout = 15, name = 'observations', maxEvents = 20000) {
  const sidecarPath = join(fixture.dir, `${name}.json`);
  const args = ['-3.11', '-B', script, '--mode', 'probe', '--sample', fixture.executable,
    '--probe-plan', fixture.planPath, '--sidecar', sidecarPath, '--timeout', String(timeout), '--max-events', String(maxEvents),
    ...sampleArgs.map(arg => `--sample-arg=${arg}`)];
  let output;
  try { output = await run('py', args, { env, timeout: 30000, maxBuffer: 2 * 1024 * 1024 }); }
  catch (error) { assert.equal(error.code, 3, error.stderr || error.message); output = error; }
  const result = JSON.parse(output.stdout);
  assert.deepEqual(JSON.parse(await readFile(sidecarPath, 'utf8')), result);
  return result;
}

const nativeOptions = { skip: !(python && process.platform === 'win32') && 'Windows + py -3.11 + normative MSVC asset required', timeout: 120000 };

test('real benign master debugs its slave; captures all 128 observations and repairs an independent JLE golden', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const result = await observe(fixture);
  assert.equal(result.status, 'observations-ready', JSON.stringify({ reason: result.reason, detail: result.detail, events: result.debugEventCount, apis: result.installedApis }));
  assert.equal(result.complete, true);
  assert.deepEqual(new Set(result.installedApis), new Set(['WaitForDebugEvent', 'GetThreadContext', 'SetThreadContext', 'ContinueDebugEvent']));
  const master = result.processes.find(p => p.role === 'master'), slave = result.processes.find(p => p.role === 'slave');
  assert.ok(master && slave && master.pid !== slave.pid);
  assert.equal(slave.parentPid, master.pid);
  assert.equal(slave.debuggerPid, master.pid);
  assert.equal(slave.insideJob, true);
  assert.equal(result.probes[0].observations.length, 128);
  for (const observation of result.probes[0].observations) {
    assert.equal(observation.masterPid, master.pid);
    assert.equal(observation.slavePid, slave.pid);
    const sf = (observation.eflags >>> 7) & 1, of = (observation.eflags >>> 11) & 1;
    const jump = !!(observation.eflags & 0x40) || sf !== of;
    assert.equal(observation.eip, fixture.address + (jump ? 16 : 2));
  }
  const classified = classifyNanomite(result.probes[0].observations, result.probes[0]);
  assert.equal(classified.record.condition, 'jle');
  const patched = applyNanomiteSidecar(fixture.memory, result, { mode: 'probe' });
  assert.deepEqual([...patched.bytes.slice(fixture.rva, fixture.rva + 2)], [0x7e, 0x0e]);
  assert.equal(fixture.memory[fixture.rva], 0xcc);
  assert.deepEqual(result.cleanup.survivors, []);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.cleanup.jobAssigned, true);
  assert.equal(result.cleanup.processTreePids.length, 3);
  assert.ok(result.cleanup.processTreePids.includes(slave.pid));
});

test('real master handling a false CC yields ambiguous-target, never a guessed JMP', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const result = await observe(fixture, ['--false-cc'], 15, 'false-cc');
  assert.equal(result.status, 'observations-ready', result.reason);
  assert.equal(classifyNanomite(result.probes[0].observations, result.probes[0]).reason, 'ambiguous-target');
  const patched = applyNanomiteSidecar(fixture.memory, result, { mode: 'probe' });
  assert.equal(patched.repaired.length, 0);
  assert.equal(patched.bytes[fixture.rva], 0xcc);
  assert.equal(result.cleanup.verified, true);
});

test('real idle master/slave timeout cleans both Job Object members and reports probe-unavailable', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const result = await observe(fixture, ['--idle'], 2, 'timeout');
  assert.equal(result.status, 'probe-unavailable');
  assert.equal(result.complete, false);
  assert.equal(result.reason, 'probe-timeout');
  assert.equal(result.probes[0].observations.length, 0);
  assert.equal(result.processes.filter(p => p.role === 'slave').length, 1);
  assert.equal(result.cleanup.verified, true);
  assert.deepEqual(result.cleanup.survivors, []);
  assert.equal(result.cleanup.processTreePids.length, 3);
});

test('native debug-event budget terminates with event-limit and verifies cleanup', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const result = await observe(fixture, [], 15, 'budget', 1);
  assert.equal(result.status, 'probe-unavailable');
  assert.equal(result.reason, 'event-limit');
  assert.equal(result.complete, false);
  assert.equal(result.debugEventCount, 1);
  assert.equal(result.cleanup.verified, true);
});

test('unsupported x64 master is refused before any process is created', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const file = join(fixture.dir, 'unsupported-x64.bin');
  const bytes = new Uint8Array(128), view = new DataView(bytes.buffer);
  bytes.set([0x4d, 0x5a]); view.setUint32(0x3c, 64, true);
  bytes.set([0x50, 0x45, 0, 0, 0x64, 0x86], 64); view.setUint16(88, 0x20b, true);
  await writeFile(file, bytes);
  let result;
  try { await run('py', ['-3.11', '-B', script, '--mode', 'probe', '--sample', file, '--probe-plan', fixture.planPath], { env }); }
  catch (error) { result = JSON.parse(error.stdout); assert.equal(error.code, 3); }
  assert.equal(result.status, 'unsupported');
  assert.equal(result.reason, 'unsupported-architecture');
  assert.deepEqual(result.processes, []);
});

test('native records mode transports explicit records and does not claim byte repair', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const request = join(fixture.dir, 'records.json');
  await writeFile(request, JSON.stringify({ imageBase: 0x400000, nanRecords: [
    { address: fixture.address, destination: fixture.address + 16, size: 2, jumpType: 12 }] }));
  const result = JSON.parse((await run('py', ['-3.11', '-B', script, '--mode', 'records', '--records', request], { env })).stdout);
  assert.equal(result.status, 'records-ready');
  assert.equal(result.complete, false);
  assert.deepEqual(result.processes, []);
  const repaired = applyNanomiteSidecar(fixture.memory, result, { mode: 'records' });
  assert.deepEqual([...repaired.bytes.slice(fixture.rva, fixture.rva + 2)], [0x7e, 0x0e]);
});

test('two real native jobs have distinct process trees and independent oracle state', nativeOptions, async () => {
  const fixture = await nativeFixture();
  const results = await Promise.all([observe(fixture, [], 15, 'concurrent-a'), observe(fixture, [], 15, 'concurrent-b')]);
  assert.ok(results.every(r => r.complete && r.cleanup.verified), JSON.stringify(results.map(r => [r.reason, r.detail])));
  const trees = results.map(r => r.processes.map(p => p.pid));
  assert.ok(trees[0].every(pid => !trees[1].includes(pid)));
  assert.ok(results.every(r => r.probes[0].observations.length === 128));
});
