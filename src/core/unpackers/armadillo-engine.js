// Server-side Armadillo orchestration engine: spawns the independent x86
// master/slave nanomite oracle (scripts/dynamic/armadillo.py) in an isolated
// temp directory with Job Object containment, reads the target memory dump
// plus the oracle sidecar, and repairs nanomite branches through the pure-JS
// chain (rebuildMemoryImagePe -> applyNanomiteSidecar -> parsePE).
// Route: native explicit selection only; win32 + py -3.11 server.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePE } from '../pe.js';
import { AnalysisError, requireThat } from '../errors.js';
import { rebuildMemoryImagePe, ensureExecutableEntryPoint } from './dynamic.js';
import { applyNanomiteSidecar, createNanomiteProbes, parseNanomiteSidecar } from './nanomites.js';

const SCRIPT = fileURLToPath(new URL('../../../scripts/dynamic/armadillo.py', import.meta.url));
const MAX_IMAGE = 0x8000000;
const MAX_LOG = 2 * 1024 * 1024;

export const ARMA_ENGINE = Object.freeze({
  id: 'armadillo-nanomites', family: 'Armadillo', catalogId: 'armadillo',
  variant: 'x86 master/slave nanomite oracle; target memory dump + JS sidecar repair',
  outputKind: 'dump-pe', runtimeVerified: false, status: 'experimental', architecture: 'x86',
  mode: 'dynamic-debug', route: 'native', runtime: 'server', platform: 'win32',
  requiresSampleExecution: true,
});

export function supportsArmadillo() { return false; } // explicit selection only

function u32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function runPython(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn('py', ['-3.11', '-B', SCRIPT, ...args], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONDONTWRITEBYTECODE: '1' },
    });
    let out = '', err = '', failure = null, killer = null;
    const stop = error => {
      if (failure) return;
      failure = error;
      // py is a launcher: killing only its PID can leave python running.
      killer = setTimeout(() => {
        if (!child.pid) return;
        const kill = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        kill.on('error', () => { child.kill(); });
      }, 500);
    };
    const timer = setTimeout(() => stop(new AnalysisError('armadillo-timeout')), timeoutMs);
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      if (out.length + chunk.length <= MAX_LOG) out += chunk;
      else stop(new AnalysisError('tool-error', { hint: 'armadillo output limit' }));
    });
    child.stderr.on('data', chunk => { if (err.length + chunk.length <= MAX_LOG) err += chunk; });
    child.on('error', error => {
      failure ||= new AnalysisError(error.code === 'ENOENT' ? 'engine-unavailable' : 'tool-error', { hint: error.code || '' });
    });
    child.on('close', () => {
      clearTimeout(timer); clearTimeout(killer);
      if (failure) reject(failure);
      else resolve({ out, err });
    });
  });
}

/** Probe sites are caller-proven candidates; samples default to the exhaustive 128. */
function buildProbePlan(options, imageBase, entryPointRva) {
  if (options.probePlan !== undefined) {
    const plan = options.probePlan;
    requireThat(plan && typeof plan === 'object' && !Array.isArray(plan) && u32(plan.imageBase)
      && Array.isArray(plan.probes) && plan.probes.length > 0 && plan.probes.length <= 32
      && plan.probes.every(probe => probe && typeof probe === 'object' && u32(probe.address)
        && [2, 5, 6].includes(probe.size) && probe.address >= plan.imageBase
        && Array.isArray(probe.samples) && probe.samples.length > 0 && probe.samples.length <= 128),
    'invalid-probe-plan');
    return { plan, source: 'explicit-plan' };
  }
  if (options.probes !== undefined) {
    const probes = options.probes;
    requireThat(Array.isArray(probes) && probes.length > 0 && probes.length <= 32
      && probes.every(probe => probe && typeof probe === 'object' && u32(probe.address)
        && [2, 5, 6].includes(probe.size) && probe.address >= imageBase
        && (probe.samples === undefined || (Array.isArray(probe.samples) && probe.samples.length > 0 && probe.samples.length <= 128))),
    'invalid-probe-plan');
    return { plan: { imageBase, probes: probes.map(probe => ({ address: probe.address, size: probe.size,
      samples: probe.samples ?? createNanomiteProbes() })) }, source: 'explicit-probes' };
  }
  // Non-dual-process degrade: a phantom site that never executes keeps the
  // sample running until the oracle timeout, then the image is still dumped.
  requireThat(u32(entryPointRva) && entryPointRva > 0 && u32(imageBase + entryPointRva), 'invalid-probe-plan');
  return { plan: { imageBase, probes: [{ address: imageBase + entryPointRva, size: 2, samples: createNanomiteProbes() }] },
    source: 'synthesized-degrade' };
}

export async function unpackArmadillo(bytes, name = 'sample.exe', options = {}) {
  requireThat(typeof process !== 'undefined' && process.versions?.node && process.platform === 'win32',
    'engine-unavailable', { hint: 'win32 + py -3.11 required' });
  requireThat(options && typeof options === 'object', 'invalid-options');
  // Packed inputs (UPX-style overlapping headers) go through the layout adapters.
  const { parseInput } = await import('../engines.js');
  const pe = parseInput(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const subsystem = view.getUint16(pe.peOffset + 24 + 68, true);
  requireThat(pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet && [2, 3].includes(subsystem)
    && pe.entryPointRva > 0 && pe.entryPointRva < pe.sizeOfImage && pe.sizeOfImage <= MAX_IMAGE,
  'armadillo-unsupported-input', { hint: 'native x86 PE32 EXE only' });
  const seconds = options.timeoutSeconds ?? 15;
  const maxEvents = options.maxEvents ?? 20000;
  const timeoutMs = options.timeoutMs ?? seconds * 1000 + 15000;
  const sampleArgs = options.sampleArgs ?? [];
  requireThat(Number.isFinite(seconds) && seconds >= 0.1 && seconds <= 60 &&
    Number.isInteger(maxEvents) && maxEvents >= 16 && maxEvents <= 50000 &&
    Number.isInteger(timeoutMs) && timeoutMs >= 50 && timeoutMs <= 300000 &&
    Array.isArray(sampleArgs) && sampleArgs.length <= 32 &&
    sampleArgs.every(arg => typeof arg === 'string' && arg.length <= 4096 && !arg.includes('\0')) &&
    (options.imageBase === undefined || u32(options.imageBase)),
  'invalid-options');
  const imageBase = options.imageBase ?? Number.parseInt(pe.imageBase, 16);
  const { plan, source } = buildProbePlan(options, imageBase, pe.entryPointRva);
  let dir;
  try {
    dir = await mkdtemp(join(tmpdir(), 'older-shells-arma-'));
    const input = join(dir, 'in.exe'), dumpPath = join(dir, 'dump.bin');
    const planPath = join(dir, 'plan.json'), sidecarPath = join(dir, 'sidecar.json');
    await writeFile(input, bytes);
    await writeFile(planPath, JSON.stringify(plan));
    const args = ['--mode', 'probe', '--sample', input, '--probe-plan', planPath,
      '--sidecar', sidecarPath, '--dump', dumpPath, '--timeout', String(seconds),
      '--max-events', String(maxEvents), ...sampleArgs.map(arg => `--sample-arg=${arg}`)];
    const run = await runPython(args, timeoutMs);
    let sidecar;
    try { sidecar = JSON.parse(await readFile(sidecarPath, 'utf8')); }
    catch { throw new AnalysisError('tool-error', { hint: (run.err || run.out).slice(0, 300) }); }
    const parsed = parseNanomiteSidecar(sidecar);
    const dumpInfo = sidecar.dump;
    requireThat(dumpInfo && typeof dumpInfo === 'object' && dumpInfo.requested === true,
      'tool-error', { hint: 'missing dump record' });
    requireThat(dumpInfo.ok === true, 'armadillo-dump-failed',
      { hint: String(dumpInfo.reason || ''), role: dumpInfo.role || null, stage: dumpInfo.stage || null });
    let dump;
    try { dump = new Uint8Array(await readFile(dumpPath)); }
    catch { throw new AnalysisError('armadillo-dump-failed', { hint: 'dump file unreadable' }); }
    requireThat(dump.length >= 0x400 && dump[0] === 0x4d && dump[1] === 0x5a && dump.length <= MAX_IMAGE,
      'armadillo-dump-invalid');
    rebuildMemoryImagePe(dump);
    ensureExecutableEntryPoint(dump);
    parsePE(dump, MAX_IMAGE);
    const applied = applyNanomiteSidecar(dump, parsed, { mode: 'probe' });
    ensureExecutableEntryPoint(applied.bytes);
    parsePE(applied.bytes, MAX_IMAGE);
    const nanomites = { candidates: parsed.probes.length, repaired: applied.repaired.length,
      unresolved: applied.unresolved.length };
    const warnings = ['runtime-not-verified'];
    if (parsed.status !== 'observations-ready') warnings.push('oracle-incomplete');
    if (dumpInfo.role === 'master') warnings.push('degraded-no-slave');
    if (nanomites.unresolved > 0) warnings.push('nanomites-unresolved');
    if (sidecar.cleanup?.verified !== true) warnings.push('cleanup-unverified');
    const safeName = String(name).split(/[\\/]/).pop().replace(/[^\w.\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'sample.exe';
    return {
      bytes: applied.bytes, name: safeName.replace(/\.exe$/i, '') + '.armadillo.dump.exe',
      metadata: {
        engine: ARMA_ENGINE.id, variant: ARMA_ENGINE.variant, mode: 'dynamic-debug', route: 'native',
        outputKind: 'dump-pe', runtimeVerified: false, requiresSampleExecution: true,
        probeSource: source, oracleState: sidecar.state ?? null, oracleStatus: parsed.status ?? null,
        oracleReason: sidecar.reason ?? null, dumpRole: dumpInfo.role, dumpStage: dumpInfo.stage ?? null,
        imageBase: dumpInfo.imageBase ?? null, sizeOfImage: dump.length,
        ...(nanomites.repaired > 0 || nanomites.unresolved > 0 ? { nanomites } : {}),
        containment: 'DEBUG_ONLY_THIS_PROCESS on master + Job Object kill-on-close; master stays the slave debugger',
        cleanupVerified: sidecar.cleanup?.verified === true,
        processes: (sidecar.processes ?? []).map(p => ({ pid: p.pid, role: p.role })),
        warnings,
      },
      report: undefined,
    };
  } catch (error) {
    if (error instanceof AnalysisError) throw error;
    throw new AnalysisError('tool-error', { hint: String(error.code || error.message || '').slice(0, 300) });
  } finally {
    if (dir) {
      try { await rm(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 }); }
      catch (error) { throw new AnalysisError('tool-error', { hint: `armadillo cleanup: ${error.code || ''}` }); }
    }
  }
}
