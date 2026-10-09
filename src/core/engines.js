import { unpackMpress, supportsMpress } from './unpackers/mpress.js';
import { unpackFsg, supportsFsg, parseFsgPE } from './unpackers/fsg.js';
import { unpackUpx, supportsUpx, parseUpxInput } from './unpackers/upx.js';
import { unpackNsPack, supportsNsPack } from './unpackers/nspack.js';
import { unpackPetite, supportsPetite } from './unpackers/petite.js';
import { parsePE } from './pe.js';
import { requireThat } from './errors.js';

const define = (metadata, supports, unpack) => Object.freeze({ metadata: Object.freeze({
  ...metadata, status: 'experimental', architecture: 'x86', mode: 'static-js', runtimeVerified: metadata.runtimeVerified ?? false,
}), supports, unpack });

export const ENGINES = Object.freeze([
  define({ id: 'mpress-pe32-lzmat', family: 'MPRESS', catalogId: 'mpress', variant: '2.12–2.19 stub 0x29f; fix 0x35; PE32 EXE; no TLS', outputKind: 'rebuilt-pe', runtimeVerified: true }, supportsMpress, unpackMpress),
  define({ id: 'fsg-pe32', family: 'FSG', catalogId: 'fsg', variant: '1.31 / 1.33 plaintext stubs; PE32 EXE', outputKind: 'rebuilt-pe', runtimeVerified: true }, supportsFsg, unpackFsg),
  define({ id: 'upx-pe32-nrv', family: 'UPX', catalogId: 'upx', variant: 'NRV2B LE32; short PE32 EXE stub; filter 0x26', outputKind: 'analysis-pe' }, supportsUpx, unpackUpx),
  define({ id: 'nspack-pe32', family: 'NsPack', catalogId: 'nspack', variant: '3.7 DIE entry stub; single-record LZMA1 body; flat rebuild', outputKind: 'analysis-pe' }, supportsNsPack, unpackNsPack),
  define({ id: 'petite-22-pe32', family: 'Petite', catalogId: 'petite', variant: '2.2 levels 1-9; move-record + layered decode; obfuscated import walk', outputKind: 'rebuilt-pe' }, supportsPetite, unpackPetite),
]);

const serverEngines = [];
export function registerServerEngine(entry) { serverEngines.push(entry); }
export function allEngines() { return [...ENGINES, ...serverEngines]; }

export function parseInput(bytes) {
  try { return parsePE(bytes); }
  catch (strictError) {
    if (!['invalid-pe-header', 'section-overlaps-headers'].includes(strictError.code)) throw strictError;
    if (supportsFsg(bytes)) return { ...parseFsgPE(bytes), importsEnumerated: false, parser: 'fsg-layout-adapter' };
    if (strictError.code === 'section-overlaps-headers') {
      try {
        const pe = parseUpxInput(bytes);
        return { ...pe, parser: 'upx-layout-adapter', declaredSizeOfHeaders: 0x1000,
          warnings: [...pe.warnings, 'upx-sizeofheaders-normalized'] };
      } catch { /* Preserve the strict parser's failure for unrecognized layouts. */ }
    }
    throw strictError;
  }
}

export function candidates(bytes, pe) {
  return ENGINES.filter(engine => engine.supports(bytes, pe)).map(({ metadata }) => ({
    id: metadata.id, family: metadata.family, status: metadata.status, variant: metadata.variant,
    outputKind: metadata.outputKind, fullValidationAtUnpack: true,
  }));
}

export function selectEngine(bytes, id = 'auto') {
  if (id !== 'auto') {
    const engine = allEngines().find(e => e.metadata.id === id);
    requireThat(engine, 'unknown-engine'); return engine;
  }
  const pe = parseInput(bytes), available = ENGINES.filter(engine => engine.supports(bytes, pe));
  requireThat(available.length > 0, 'unsupported-variant');
  requireThat(available.length === 1, 'ambiguous-engine', { engines: available.map(engine => engine.metadata.id) });
  return available[0];
}
