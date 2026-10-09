import { AnalysisError } from '../errors.js';
import { emulationLimits } from '../emulation/limits.js';
import { parseEmulatedPE, validateEmulatedPE, loadPE, dumpPE, parseFsgEmulatedPE, loadFsgPE, dumpFsgPE } from '../emulation/pe-loader.js';
import { inspectProfile, TerminalMonitor, inspectFsgProfile, FsgTerminalMonitor } from '../emulation/profiles.js';

export const EMULATED_ENGINE = Object.freeze({
  id: 'emulated-pe32', route: 'emulated', mode: 'emulated', architecture: 'x86', status: 'experimental',
  family: 'UPX', catalogId: 'upx', outputKind: 'dump-pe', runtimeVerified: false,
  variant: 'UPX PE32 NRV short stub; interpreted x86 and symbolic Win32',
});

function inspectUpx(bytes, pe) {
  const parsed = parseEmulatedPE(bytes);
  if (pe && (pe.machine !== parsed.machine || pe.entryPointRva !== parsed.entryPointRva)) return null;
  validateEmulatedPE(parsed);
  return { profile: inspectProfile(bytes, parsed) };
}

function inspectFsg(bytes, pe) {
  const parsed = parseFsgEmulatedPE(bytes);
  if (pe && (pe.machine !== parsed.machine || pe.entryPointRva !== parsed.entryPointRva)) return null;
  return { pe: parsed, profile: inspectFsgProfile(bytes, parsed) };
}

/** Noexcept preliminary profile check. A true result is not a decode guarantee. */
export function supportsEmulated(bytes, pe) {
  try {
    // Revalidate the actual bytes; optional cached PE data is not a trust boundary.
    if (inspectUpx(bytes, pe)) return true;
  } catch { /* try the FSG profile */ }
  try {
    if (inspectFsg(bytes, pe)) return true;
    return false;
  } catch { return false; }
}

function unpackUpx(bytes, name, limits) {
  const pe = parseEmulatedPE(bytes, limits);
  validateEmulatedPE(pe, limits);
  const profile = inspectProfile(bytes, pe), state = loadPE(bytes, pe, limits, name);
  const monitor = new TerminalMonitor(profile, state);
  while (!monitor.observe(state.cpu.step())) { /* fuel is charged inside CPU.step, including REP */ }
  const output = dumpPE(state, profile.originalEntryPoint);
  return { bytes: output, metadata: {
    engine: EMULATED_ENGINE.id, mode: 'emulated', route: 'emulated', outputKind: 'dump-pe', runtimeVerified: false,
    variant: profile.variant, originalEntryPoint: profile.originalEntryPoint,
    steps: state.cpu.steps, stopReason: 'verified-upx-tail-transfer',
    decompressedSize: monitor.decodedSize, mappedImageSize: state.image.size,
    memoryBytes: state.memory.allocated, writeBytes: state.memory.writeBytes,
    shadowApiCalls: state.win32.calls,
    shadowApis: Array.from(state.win32.used, ([api, calls]) => ({ api, calls })),
    resolvedImports: Array.from(state.win32.entries.values(), ({ address, dll, api, implemented }) =>
      ({ address, dll, api, implemented })),
    importsRebuilt: false, resourcesRebuilt: false,
    unrestoredMetadata: ['disk-import-table', 'original-section-layout', 'resource-directory', 'base-relocation-directory',
      'tls', 'load-configuration', 'debug-directory', 'bound-imports', 'certificates', 'overlay'],
    warnings: ['runtime-not-verified', 'imports-not-rebuilt', 'resources-not-rebuilt',
      'unrestored-metadata-cleared', 'symbolic-iat-addresses', 'fixed-image-base',
      ...(pe.emulatedHeadersNormalized ? ['upx-sizeofheaders-normalized'] : [])],
  } };
}

function unpackFsg(bytes, name, limits, plan) {
  const state = loadFsgPE(bytes, plan.pe, limits, name);
  const monitor = new FsgTerminalMonitor(plan.profile, state);
  while (!monitor.observe(state.cpu.step())) { /* fuel is charged inside CPU.step, including REP */ }
  const { profile } = plan;
  const output = dumpFsgPE(state, profile.originalEntryPoint);
  return { bytes: output, metadata: {
    engine: EMULATED_ENGINE.id, mode: 'emulated', route: 'emulated', outputKind: 'dump-pe', runtimeVerified: false,
    variant: profile.variant, originalEntryPoint: profile.originalEntryPoint,
    steps: state.cpu.steps, stopReason: 'verified-fsg-tail-transfer',
    decompressedSize: monitor.decodedBytes, mappedImageSize: state.image.size,
    memoryBytes: state.memory.allocated, writeBytes: state.memory.writeBytes,
    shadowApiCalls: state.win32.calls,
    shadowApis: Array.from(state.win32.used, ([api, calls]) => ({ api, calls })),
    resolvedImports: Array.from(state.win32.entries.values(), ({ address, dll, api, implemented }) =>
      ({ address, dll, api, implemented })),
    importsRebuilt: false, resourcesRebuilt: false,
    unrestoredMetadata: ['disk-import-table', 'original-section-layout', 'resource-directory', 'base-relocation-directory',
      'tls', 'load-configuration', 'debug-directory', 'bound-imports', 'certificates', 'overlay'],
    warnings: ['runtime-not-verified', 'imports-not-rebuilt', 'resources-not-rebuilt',
      'unrestored-metadata-cleared', 'symbolic-iat-addresses', 'fixed-image-base',
      'fsg-entry-section-execute-injected', 'fsg-dump-headers-relocated', ...plan.pe.warnings],
  } };
}

export function unpackEmulated(bytes, name = 'input.exe', options = {}) {
  const limits = emulationLimits(options);
  try {
    return unpackUpx(bytes, name, limits);
  } catch (upxError) {
    if (!(upxError instanceof AnalysisError)) throw upxError;
    let plan = null;
    try { plan = inspectFsg(bytes); } catch { throw upxError; }
    return unpackFsg(bytes, name, limits, plan);
  }
}
