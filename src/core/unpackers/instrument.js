// Server-only, independent exception/context observer. The original tmdunpacker
// injects a handler DLL; this route uses two one-shot debugger-owned INT3 hooks.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePE } from '../pe.js';
import { AnalysisError, requireThat } from '../errors.js';
import { rebuildMemoryImagePe, applyImportSnapshot } from './dynamic.js';

const SCRIPT = fileURLToPath(new URL('../../../scripts/dynamic/dump_instrument.py', import.meta.url));
const MAX_IMAGE = 0x8000000;
const MAX_LOG = 8 * 1024 * 1024;

export const INSTRUMENT_ENGINE = Object.freeze({
  id: 'instrumented-exception-dump', family: 'Generic (instrumented)', catalogId: 'dynamic',
  variant: 'x86 KiUserExceptionDispatcher/NtContinue one-shot context observation',
  outputKind: 'extract-pe', runtimeVerified: false, status: 'experimental', architecture: 'x86',
  mode: 'instrument', route: 'instrument/debug', runtime: 'server', platform: 'win32',
  requiresSampleExecution: true,
});

function runPython(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn('py', ['-3.11', '-X', 'utf8', SCRIPT, ...args], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONUTF8: '1', INSTRUMENT_PARENT_PIPE: '1' },
    });
    let out = '', err = '', failure = null, killer = null;
    const stop = error => {
      if (failure) return;
      failure = error;
      // Cooperative EOF lets Python run finally/Job Object cleanup first.
      child.stdin.end();
      killer = setTimeout(() => {
        if (!child.pid) return;
        // py is a launcher: killing only its PID can leave python running.
        const kill = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        kill.on('error', () => { child.kill(); });
      }, 750);
    };
    const timer = setTimeout(() => stop(new AnalysisError('tool-timeout')), timeoutMs);
    child.stdin.on('error', () => {}); // EOF after natural exit is harmless
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      if (out.length + chunk.length <= MAX_LOG) out += chunk;
      else stop(new AnalysisError('tool-error', { hint: 'instrument output limit' }));
    });
    child.stderr.on('data', chunk => { if (err.length + chunk.length <= MAX_LOG) err += chunk; });
    child.on('error', error => {
      failure ||= new AnalysisError(error.code === 'ENOENT' ? 'engine-unavailable' : 'tool-error', { hint: error.code || '' });
    });
    // Settle ONLY after close: temp removal must not race a writing Python process.
    child.on('close', code => {
      clearTimeout(timer); clearTimeout(killer);
      if (failure) reject(failure);
      else resolve({ out, err, code });
    });
  });
}

function validateProtocol(info) {
  requireThat(info && typeof info === 'object' && info.stage === 'instrumented', 'tool-error', { hint: 'invalid instrument protocol' });
  requireThat(info.ok === true, info.error === 'unsupported-input' ? 'instrument-unsupported-input' : 'instrument-failed',
    { hint: String(info.detail || info.error || '').slice(0, 300) });
  requireThat(Number.isInteger(info.imageBase) && info.imageBase >= 0x10000 && info.imageBase <= 0xffff0000 &&
    Number.isInteger(info.size) && info.size >= 0x1000 && info.size <= MAX_IMAGE && info.imageBase + info.size <= 0xffff0000 &&
    Number.isInteger(info.events) && info.events >= 0 && info.events <= 100000 &&
    Number.isInteger(info.bpHits) && info.bpHits >= 0 && info.bpHits <= 2 && info.bpHits <= info.events &&
    Array.isArray(info.observations) && info.observations.length === info.bpHits &&
    Array.isArray(info.oepCandidates) && info.oepCandidates.length <= 8 &&
    info.oepCandidates.every(rva => Number.isInteger(rva) && rva > 0 && rva < info.size) &&
    info.hookMode === 'one-shot' && info.singleStep === false && info.oepConfirmed === false,
  'tool-error', { hint: 'invalid instrument counters/ranges' });
}

export async function unpackInstrumented(bytes, name = 'sample.exe', options = {}) {
  requireThat(typeof process !== 'undefined' && process.versions?.node && process.platform === 'win32',
    'engine-unavailable', { hint: 'win32 + py -3.11 required' });
  const pe = parsePE(bytes);
  const subsystem = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(pe.optionalOffset + 68, true);
  requireThat(pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet && [2, 3].includes(subsystem) &&
    pe.entryPointRva > 0 && pe.entryPointRva < pe.sizeOfImage && pe.sizeOfImage <= MAX_IMAGE,
  'instrument-unsupported-input', { hint: 'native x86 PE32 EXE only' });
  requireThat(options && typeof options === 'object', 'invalid-options');
  const seconds = options.timeoutSeconds ?? 20;
  const maxEvents = options.maxEvents ?? 2000;
  const timeoutMs = options.timeoutMs ?? seconds * 1000 + 10000;
  const sampleArgs = options.sampleArgs ?? [];
  requireThat(Number.isFinite(seconds) && seconds >= 0.1 && seconds <= 120 &&
    Number.isInteger(maxEvents) && maxEvents >= 16 && maxEvents <= 100000 &&
    Number.isInteger(timeoutMs) && timeoutMs >= 50 && timeoutMs <= 180000 &&
    Array.isArray(sampleArgs) && sampleArgs.length <= 32 &&
    sampleArgs.every(arg => typeof arg === 'string' && arg.length <= 4096 && !arg.includes('\0')),
  'invalid-options');
  let dir;
  try {
    dir = await mkdtemp(join(tmpdir(), 'older-shells-instrument-'));
    const input = join(dir, 'in.exe'), output = join(dir, 'dump.bin');
    await writeFile(input, bytes);
    const run = await runPython([input, output, String(seconds), String(maxEvents), JSON.stringify(sampleArgs)], timeoutMs);
    let info;
    try { info = JSON.parse(run.out.trim().split(/\r?\n/).pop()); }
    catch { throw new AnalysisError('tool-error', { hint: (run.err || run.out).slice(0, 300), exitCode: run.code }); }
    validateProtocol(info);
    requireThat(run.code === 0, 'tool-error', { hint: 'instrument process failed', exitCode: run.code });
    const dump = new Uint8Array(await readFile(output));
    requireThat(dump.length === info.size, 'tool-error', { hint: 'dump size mismatch' });
    rebuildMemoryImagePe(dump);
    parsePE(dump, MAX_IMAGE);
    const snapshot = await readFile(`${output}.imports.json`, 'utf8');
    const applied = applyImportSnapshot(dump, snapshot, { imageBase: info.imageBase });
    parsePE(applied.bytes, MAX_IMAGE);
    const safeName = String(name).split(/[\\/]/).pop().replace(/[^\w.\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'sample.exe';
    return {
      bytes: applied.bytes, name: safeName.replace(/\.exe$/i, '') + '.instrument.extract.exe',
      metadata: {
        engine: INSTRUMENT_ENGINE.id, variant: INSTRUMENT_ENGINE.variant,
        mode: 'instrument', route: 'instrument/debug', stage: 'instrumented', outputKind: 'extract-pe',
        runtimeVerified: false, requiresSampleExecution: true, imageBase: info.imageBase,
        oepConfirmed: false, oepQuality: 'observed-landing-only', oepCandidates: info.oepCandidates,
        // A repaired IAT is only one dimension of repair. No confirmed OEP => extract-pe.
        importsRebuilt: applied.importsRebuilt, importsRebuildMethod: applied.method,
        imports: info.imports, lateDump: Boolean(info.late), exitReason: info.exitReason,
        events: info.events, bpHits: info.bpHits, hookHits: info.bpHits, hookMode: info.hookMode,
        hookSites: info.hookSites, observations: info.observations, singleStep: false, debugPortHidden: false,
        startupSync: info.startupSync, startupSyncHits: info.startupSyncHits,
        captureSource: info.captureSource, captureAgeMs: info.captureAgeMs, samplePid: info.pid,
        containment: 'DEBUG_ONLY_THIS_PROCESS + unnamed Job Object kill-on-close',
        warnings: ['extraction-stage', 'oep-unconfirmed', 'one-shot-hook-coverage', 'runtime-not-verified',
          ...(info.bpHits === 0 ? ['no-hook-hits'] : []), ...(applied.warning ? [applied.warning] : [])],
      },
      report: undefined,
    };
  } catch (error) {
    if (error instanceof AnalysisError) throw error;
    throw new AnalysisError('tool-error', { hint: String(error.code || error.message || '').slice(0, 300) });
  } finally {
    if (dir) {
      try { await rm(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 }); }
      catch (error) { throw new AnalysisError('tool-error', { hint: `instrument cleanup: ${error.code || ''}` }); }
    }
  }
}
