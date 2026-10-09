import { parsePE } from './pe.js';
import { detect, DIE_SCOPE } from './detect.js';
import { CATALOG } from './catalog.js';
import { APP_VERSION } from './version.js';
import { entropy, sha256, MAX_INPUT, MAX_OUTPUT } from './bytes.js';
import { ENGINES, allEngines, candidates, parseInput, selectEngine } from './engines.js';
import { requireThat } from './errors.js';

export function capabilities() {
  return { name: 'OlderShellsCK', version: APP_VERSION, license: 'Apache-2.0', detection: DIE_SCOPE,
    limits: { inputBytes: MAX_INPUT, outputBytes: MAX_OUTPUT },
    unpackers: allEngines().map(({ metadata }) => ({ ...metadata })),
    catalog: CATALOG };
}

async function makeReport(bytes, name, pe) {
  const { rvaToOffset, ...summary } = pe;
  return { schemaVersion: 1, version: APP_VERSION, file: { name: String(name).slice(0, 256), size: bytes.length, sha256: await sha256(bytes), entropy: entropy(bytes) },
    pe: summary, detection: DIE_SCOPE, detections: detect(bytes, pe),
    candidates: candidates(bytes, pe),
  };
}

export async function analyze(bytes, name = 'sample.exe') {
  return makeReport(bytes, name, parseInput(bytes));
}

export async function unpack(bytes, engine = 'auto', name = 'sample.exe', options = {}) {
  const selected = selectEngine(bytes, engine);
  const result = await selected.unpack(bytes, name, options);
  const safeName = String(name).split(/[\\/]/).pop().replace(/[^\w.\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'sample.exe';
  const suffix = result.metadata.outputKind === 'analysis-pe' ? 'analysis.exe' : 'unpacked.exe';
  const report = await makeReport(result.bytes, `${safeName}.${suffix}`, parsePE(result.bytes, MAX_OUTPUT));
  return { bytes: result.bytes, name: report.file.name, metadata: result.metadata, report };
}

export async function execute(operation, bytes, options = {}) {
  if (operation === 'analyze') return analyze(bytes, options.name);
  if (operation === 'unpack') return unpack(bytes, options.engine, options.name, options);
  requireThat(false, 'unknown-operation');
}
