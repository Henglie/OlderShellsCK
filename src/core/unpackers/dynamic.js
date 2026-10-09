// Server-side dynamic engine: runs the sample under a Python ctypes debugger
// (scripts/dynamic/dump_oep.py) with Job Object containment, breaks at a
// caller-supplied OEP and dumps the in-memory image. When the tool also emits
// <dump>.imports.json (runtime export snapshot), the memory-resolved IAT is
// rebuilt into a disk import table and the output upgrades to rebuilt-pe.
// Route: dynamic debugging. Requires sample execution; win32 + python only.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePE } from '../pe.js';
import { align } from '../bytes.js';
import { AnalysisError, requireThat } from '../errors.js';

const SCRIPT = fileURLToPath(new URL('../../../scripts/dynamic/dump_oep.py', import.meta.url));

export const DYNAMIC_ENGINE = Object.freeze({
  id: 'dynamic-debug-dump', family: 'Generic (dynamic)', catalogId: 'dynamic',
  variant: 'known-OEP guard/INT3 dump; Job Object contained',
  outputKind: 'dump-pe', runtimeVerified: false, status: 'experimental', architecture: 'x86',
  mode: 'dynamic-debug', runtime: 'server', platform: 'win32', requiresSampleExecution: true,
});

export function supportsDynamic() { return false; } // explicit choice with oepRva only

function runPython(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('py', ['-3.11', SCRIPT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', chunk => { out += chunk; });
    child.stderr.on('data', chunk => { err += chunk; });
    const timer = setTimeout(() => { child.kill(); reject(Object.assign(new Error('dynamic dump timeout'), { code: 'tool-timeout' })); }, 180000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', () => { clearTimeout(timer); resolve({ out, err }); });
  });
}

export function rebuildMemoryImagePe(dump) {
  // Memory dump: make raw offsets equal RVAs so the strict parser can read it.
  const view = new DataView(dump.buffer, dump.byteOffset, dump.byteLength);
  const e_lfanew = view.getUint32(0x3c, true);
  const optional = e_lfanew + 4 + 20;
  const fileAlignment = view.getUint32(optional + 0x24, true) || 0x200;
  const sectionAlignment = view.getUint32(optional + 0x20, true) || 0x1000;
  const count = view.getUint16(e_lfanew + 4 + 2, true);
  let offset = optional + view.getUint16(e_lfanew + 4 + 16, true);
  const sections = [];
  for (let index = 0; index < count; index++) {
    sections.push({ offset, virtualSize: view.getUint32(offset + 8, true), virtualAddress: view.getUint32(offset + 12, true) });
    offset += 40;
  }
  // Packed headers overstate section spans (UPX0 covers the whole image);
  // shrink each to the next section's address so nothing overlaps virtually.
  const sorted = [...sections].sort((a, b) => a.virtualAddress - b.virtualAddress);
  for (const section of sections) {
    const next = sorted.find(other => other.virtualAddress > section.virtualAddress);
    if (next) section.virtualSize = Math.min(section.virtualSize, next.virtualAddress - section.virtualAddress);
  }
  for (let index = 0; index < count; index++) {
    const section = sections[index];
    const { virtualSize, virtualAddress } = section;
    offset = section.offset;
    const rawSize = Math.min((virtualSize + fileAlignment - 1) & -fileAlignment, dump.length - virtualAddress);
    view.setUint32(offset + 16, rawSize, true);            // SizeOfRawData
    view.setUint32(offset + 20, virtualAddress, true);     // PointerToRawData = RVA
    view.setUint32(offset + 8, Math.min((virtualSize + sectionAlignment - 1) & -sectionAlignment, dump.length - virtualAddress), true);
  }
  return dump;
}

export function ensureExecutableEntryPoint(dump) {
  // The dumped header keeps the packer's entry point; once the OEP is written
  // back, its section needs execute permission or the loader refuses (DEP).
  const view = new DataView(dump.buffer, dump.byteOffset, dump.byteLength);
  const e_lfanew = view.getUint32(0x3c, true);
  const optional = e_lfanew + 4 + 20;
  const entryPointRva = view.getUint32(optional + 0x10, true);
  const count = view.getUint16(e_lfanew + 4 + 2, true);
  let offset = optional + view.getUint16(e_lfanew + 4 + 16, true);
  for (let index = 0; index < count; index++) {
    const virtualSize = view.getUint32(offset + 8, true);
    const virtualAddress = view.getUint32(offset + 12, true);
    if (entryPointRva >= virtualAddress && entryPointRva < virtualAddress + virtualSize) {
      view.setUint32(offset + 36, 0xe0000060, true);
    }
    offset += 40;
  }
  return dump;
}

const IMPORT_TEXT = /^[\x20-\x7e]{1,512}$/;
const IMPORT_HEX = /^0x[0-9a-f]{1,12}$/i;

function decodeBytes(bytes, from, to) {
  let text = '';
  for (let index = from; index < to; index++) text += String.fromCharCode(bytes[index]);
  return text;
}

function buildExportMap(modules) {
  requireThat(Array.isArray(modules) && modules.length > 0 && modules.length <= 4096, 'imports-not-rebuilt');
  const map = new Map();
  let total = 0;
  for (const module of modules) {
    requireThat(module && typeof module === 'object' && typeof module.dll === 'string' && IMPORT_TEXT.test(module.dll), 'imports-not-rebuilt');
    requireThat(typeof module.imageBase === 'string' && IMPORT_HEX.test(module.imageBase), 'imports-not-rebuilt');
    const base = Number.parseInt(module.imageBase, 16);
    requireThat(Array.isArray(module.exports) && module.exports.length <= 65536, 'imports-not-rebuilt');
    for (const entry of module.exports) {
      requireThat(entry && typeof entry === 'object' && typeof entry.rva === 'string' && IMPORT_HEX.test(entry.rva), 'imports-not-rebuilt');
      const named = typeof entry.name === 'string';
      requireThat(named ? IMPORT_TEXT.test(entry.name) && entry.ordinal === undefined : Number.isInteger(entry.ordinal) && entry.ordinal >= 1 && entry.ordinal <= 0xffff, 'imports-not-rebuilt');
      const va = base + Number.parseInt(entry.rva, 16);
      requireThat(Number.isSafeInteger(va) && va > 0 && va <= 0xffffffff, 'imports-not-rebuilt');
      requireThat(++total <= 262144, 'imports-not-rebuilt');
      if (!map.has(va)) map.set(va, named ? { module: module.dll, name: entry.name } : { module: module.dll, ordinal: entry.ordinal });
    }
  }
  return map;
}

function analyzeRuntimeImports(dump, pe, map) {
  requireThat(!pe.is64 && pe.directories.length >= 13, 'imports-not-rebuilt');
  const view = new DataView(dump.buffer, dump.byteOffset, dump.byteLength);
  const at = (rva, size) => { requireThat(Number.isInteger(rva) && rva >= 0 && rva + size <= dump.length, 'imports-not-rebuilt'); return rva; };
  const directory = pe.directories[1];
  requireThat(directory && directory.rva > 0 && directory.size > 0, 'imports-not-rebuilt');
  const entries = [];
  let functions = 0, terminated = false;
  for (let index = 0; index < 256; index++) {
    const offset = at(directory.rva + index * 20, 20);
    const fields = [0, 4, 8, 12, 16].map(shift => view.getUint32(offset + shift, true));
    if (fields.every(value => !value)) { terminated = true; break; }
    const nameOffset = at(fields[3], 1);
    const limit = Math.min(nameOffset + 512, dump.length);
    let cursor = nameOffset;
    while (cursor < limit && dump[cursor]) cursor++;
    requireThat(cursor < limit && cursor > nameOffset, 'imports-not-rebuilt');
    requireThat(fields[4] > 0, 'imports-not-rebuilt');
    const resolved = [];
    for (let slot = 0; slot < 4096; slot++) {
      const position = at(fields[4] + slot * 4, 4);
      const va = view.getUint32(position, true);
      if (!va) break;
      const hit = map.get(va);
      requireThat(hit, 'imports-not-rebuilt');
      resolved.push(hit);
      requireThat(++functions <= 16384, 'imports-not-rebuilt');
    }
    requireThat(resolved.length > 0, 'imports-not-rebuilt');
    entries.push({ dll: { text: decodeBytes(dump, nameOffset, cursor), bytes: dump.slice(nameOffset, cursor) }, thunkRva: fields[4], functions: resolved });
  }
  requireThat(terminated && entries.length > 0, 'imports-not-rebuilt');
  return entries;
}

function buildImportPayload(entries, baseRva) {
  let cursor = (entries.length + 1) * 20;
  const intRvas = entries.map(entry => { const rva = cursor; cursor += (entry.functions.length + 1) * 4; return rva; });
  const hintRvas = entries.map(entry => entry.functions.map(fn => {
    if (!fn.name) return 0;
    cursor += cursor & 1;
    const rva = cursor;
    cursor += fn.name.length + 3;
    return rva;
  }));
  const dllRvas = entries.map(entry => { const rva = cursor; cursor += entry.dll.bytes.length + 1; return rva; });
  const payload = new Uint8Array(cursor);
  const view = new DataView(payload.buffer);
  entries.forEach((entry, index) => {
    view.setUint32(index * 20, baseRva + intRvas[index], true);
    view.setUint32(index * 20 + 12, baseRva + dllRvas[index], true);
    view.setUint32(index * 20 + 16, entry.thunkRva, true);
    entry.functions.forEach((fn, slot) => view.setUint32(intRvas[index] + slot * 4, fn.name ? baseRva + hintRvas[index][slot] : 0x80000000 | fn.ordinal, true));
    hintRvas[index].forEach((rva, slot) => { if (rva) for (let k = 0; k < entry.functions[slot].name.length; k++) payload[rva + 2 + k] = entry.functions[slot].name.charCodeAt(k); });
    payload.set(entry.dll.bytes, dllRvas[index]);
  });
  return payload;
}

function placeImportPayload(dump, pe, payload, entries, baseRva) {
  const fileAlignment = pe.fileAlignment || 0x200;
  const sectionAlignment = pe.sectionAlignment || 0x1000;
  const rawSize = align(payload.length, fileAlignment);
  requireThat(baseRva + rawSize <= 0xffffffff && baseRva + rawSize - dump.length <= 0x1000000, 'imports-not-rebuilt');
  const out = new Uint8Array(baseRva + rawSize);
  out.set(dump);
  out.set(payload, baseRva);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  if (pe.sections.length < 96 && pe.sectionTable + (pe.sections.length + 1) * 40 <= pe.sizeOfHeaders) {
    const offset = pe.sectionTable + pe.sections.length * 40;
    out.set([0x2e, 0x69, 0x64, 0x61, 0x74, 0x61], offset); // .idata
    view.setUint32(offset + 8, payload.length, true);
    view.setUint32(offset + 12, baseRva, true);
    view.setUint32(offset + 16, rawSize, true);
    view.setUint32(offset + 20, baseRva, true); // raw = RVA, same identity semantics
    view.setUint32(offset + 36, 0xC0000040, true);
    view.setUint16(pe.peOffset + 6, pe.sections.length + 1, true);
  } else {
    const last = pe.sections.reduce((a, b) => (b.rva >= a.rva ? b : a));
    const end = baseRva + rawSize;
    view.setUint32(last.headerOffset + 8, Math.max(last.virtualSize, end - last.rva), true);
    view.setUint32(last.headerOffset + 16, end - last.rva, true);
    view.setUint32(last.headerOffset + 20, last.rva, true);
  }
  view.setUint32(pe.optionalOffset + 56, align(baseRva + rawSize, sectionAlignment), true);
  view.setUint32(pe.directoryOffset + 8, baseRva, true);
  view.setUint32(pe.directoryOffset + 12, (entries.length + 1) * 20, true);
  const from = Math.min(...entries.map(entry => entry.thunkRva));
  const to = Math.max(...entries.map(entry => entry.thunkRva + (entry.functions.length + 1) * 4));
  view.setUint32(pe.directoryOffset + 96, from, true);
  view.setUint32(pe.directoryOffset + 100, to - from, true);
  return out;
}

function verifyRebuiltImports(after, entries, beforeWarnings) {
  const previous = new Set(beforeWarnings);
  requireThat(after.warnings.every(warning => previous.has(warning) && !warning.startsWith('invalid-import') && warning !== 'import-limit'), 'imports-not-rebuilt');
  requireThat(after.imports.length === entries.length, 'imports-not-rebuilt');
  entries.forEach((entry, index) => {
    const module = after.imports[index];
    requireThat(module && module.name === entry.dll.text && module.firstThunk === entry.thunkRva && module.functions.length === entry.functions.length, 'imports-not-rebuilt');
    module.functions.forEach((fn, slot) => {
      const want = entry.functions[slot];
      requireThat(want.name ? fn.name === want.name && fn.hint === 0 : fn.ordinal === want.ordinal && fn.name === undefined, 'imports-not-rebuilt');
    });
  });
}

export function rebuildImportsFromSnapshot(dump, snapshot) {
  let modules = null;
  if (typeof snapshot === 'string' && snapshot) {
    try {
      const parsed = JSON.parse(snapshot);
      if (parsed && Array.isArray(parsed.modules)) modules = parsed.modules;
    } catch { /* unusable snapshot */ }
  }
  if (!modules) return { ok: false };
  try {
    const before = parsePE(dump);
    const entries = analyzeRuntimeImports(dump, before, buildExportMap(modules));
    const baseRva = align(Math.max(before.sizeOfImage, before.sizeOfHeaders, dump.length, ...before.sections.map(section => section.rva + Math.max(section.virtualSize, section.rawSize))), before.sectionAlignment || 0x1000);
    const out = placeImportPayload(dump, before, buildImportPayload(entries, baseRva), entries, baseRva);
    const after = parsePE(out);
    verifyRebuiltImports(after, entries, before.warnings);
    return { ok: true, bytes: out, imports: after.imports };
  } catch (error) {
    if (error instanceof AnalysisError) return { ok: false };
    throw error;
  }
}

function indirectScanRanges(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const whole = [[0x40, bytes.length]];
  if (view.getUint16(0, true) !== 0x5a4d) return { exec: [], fallback: whole };
  const e_lfanew = view.getUint32(0x3c, true);
  if (e_lfanew < 0x40 || e_lfanew + 24 > bytes.length || view.getUint32(e_lfanew, true) !== 0x4550) return { exec: [], fallback: whole };
  const count = view.getUint16(e_lfanew + 6, true);
  const optionalSize = view.getUint16(e_lfanew + 20, true);
  const optional = e_lfanew + 24;
  const sizeOfHeaders = view.getUint32(optional + 60, true);
  const fallback = sizeOfHeaders >= optional + optionalSize && sizeOfHeaders < bytes.length ? [[sizeOfHeaders, bytes.length]] : whole;
  const exec = [];
  if (count > 0 && count <= 96 && optional + optionalSize + count * 40 <= bytes.length) {
    let offset = optional + optionalSize;
    for (let index = 0; index < count; index++) {
      const virtualSize = view.getUint32(offset + 8, true);
      const virtualAddress = view.getUint32(offset + 12, true);
      if (view.getUint32(offset + 36, true) & 0x20000000) {
        const from = Math.max(virtualAddress, sizeOfHeaders, 0x40);
        const to = Math.min(virtualAddress + Math.max(virtualSize, 1), bytes.length);
        if (from < to) exec.push([from, to]);
      }
      offset += 40;
    }
  }
  return { exec, fallback };
}

export function scanIndirectImports(bytes, options = {}) {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0x40, 'invalid-input');
  const imageBase = options.imageBase;
  requireThat(Number.isInteger(imageBase) && imageBase > 0 && imageBase <= 0xffffffff, 'invalid-image-base');
  const collect = ranges => {
    const slots = new Set();
    for (const [from, to] of ranges) {
      for (let index = from; index + 6 <= to; index++) {
        if (bytes[index] !== 0xff) continue;
        const modrm = bytes[index + 1];
        if (modrm !== 0x15 && modrm !== 0x25) continue;
        const va = (bytes[index + 2] | (bytes[index + 3] << 8) | (bytes[index + 4] << 16) | (bytes[index + 5] << 24)) >>> 0;
        const rva = va - imageBase;
        if (rva > 0 && rva + 4 <= bytes.length) slots.add(rva);
      }
    }
    return slots;
  };
  const ranges = indirectScanRanges(bytes);
  let slots = collect(ranges.exec);
  if (!slots.size) slots = collect(ranges.fallback);
  return { slots: [...slots].sort((a, b) => a - b), count: slots.size };
}

function scanModuleEntries(dll, items) {
  // One thunk array spans first..last slot of the group so FirstThunk keeps
  // pointing at the original slot RVAs (code stays unpatched); gaps between
  // slots are filled with a duplicate import the loader harmlessly resolves.
  const filler = items[0].fn;
  const runs = [];
  for (const item of items) {
    const run = runs[runs.length - 1];
    if (run && (item.rva - run.startRva) / 4 + 1 <= 4096) run.items.push(item);
    else runs.push({ startRva: item.rva, items: [item] });
  }
  return runs.map(run => {
    const span = (run.items[run.items.length - 1].rva - run.startRva) / 4 + 1;
    const functions = new Array(span).fill(filler);
    for (const item of run.items) functions[(item.rva - run.startRva) / 4] = item.fn;
    return { dll: { text: dll, bytes: Uint8Array.from(dll, ch => ch.charCodeAt(0)) }, thunkRva: run.startRva, functions, realFunctions: run.items.length };
  });
}

export function rebuildImportsByScan(bytes, imageBase, exportMap, options = {}) {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0x40, 'invalid-input');
  requireThat(Number.isInteger(imageBase) && imageBase > 0 && imageBase <= 0xffffffff, 'imports-not-rebuilt');
  requireThat(exportMap instanceof Map && exportMap.size > 0, 'imports-not-rebuilt');
  const slots = Array.isArray(options.slots) && options.slots.every(rva => Number.isInteger(rva) && rva > 0)
    ? options.slots
    : scanIndirectImports(bytes, { imageBase }).slots;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const byModule = new Map();
  let droppedSlots = 0;
  for (const rva of slots) {
    const hit = rva % 4 === 0 && rva + 4 <= bytes.length ? exportMap.get(view.getUint32(rva, true)) : null;
    if (!hit || (!hit.name && !Number.isInteger(hit.ordinal))) { droppedSlots++; continue; }
    if (!byModule.has(hit.module)) byModule.set(hit.module, []);
    byModule.get(hit.module).push({ rva, fn: hit.name ? { name: hit.name } : { ordinal: hit.ordinal } });
  }
  requireThat(byModule.size > 0, 'imports-not-rebuilt');
  const entries = [];
  const modules = [];
  for (const [dll, items] of byModule) {
    items.sort((a, b) => a.rva - b.rva);
    entries.push(...scanModuleEntries(dll, items));
    modules.push({ name: dll, functions: items.length });
  }
  const before = parsePE(bytes);
  requireThat(!before.is64 && before.directories.length >= 13, 'imports-not-rebuilt');
  const baseRva = align(Math.max(before.sizeOfImage, before.sizeOfHeaders, bytes.length, ...before.sections.map(section => section.rva + Math.max(section.virtualSize, section.rawSize))), before.sectionAlignment || 0x1000);
  const out = placeImportPayload(bytes, before, buildImportPayload(entries, baseRva), entries, baseRva);
  const after = parsePE(out);
  verifyRebuiltImports(after, entries, before.warnings);
  return { bytes: out, modules, droppedSlots };
}

function tryScanRebuild(dump, snapshot, options) {
  let modules = null;
  if (typeof snapshot === 'string' && snapshot) {
    try {
      const parsed = JSON.parse(snapshot);
      if (parsed && Array.isArray(parsed.modules)) modules = parsed.modules;
    } catch { /* unusable snapshot */ }
  }
  if (!modules) return null;
  const imageBase = Number(options?.imageBase);
  if (!Number.isInteger(imageBase) || imageBase <= 0) return null;
  try {
    const scan = scanIndirectImports(dump, { imageBase });
    if (scan.count < 4) return null;
    return rebuildImportsByScan(dump, imageBase, buildExportMap(modules), { slots: scan.slots });
  } catch (error) {
    if (error instanceof AnalysisError) return null;
    throw error;
  }
}

export function applyImportSnapshot(dump, snapshot, options = {}) {
  if (snapshot === null || snapshot === undefined) return { bytes: dump, outputKind: 'dump-pe', importsRebuilt: false, warning: null };
  const rebuilt = rebuildImportsFromSnapshot(dump, snapshot);
  if (rebuilt.ok) return { bytes: rebuilt.bytes, outputKind: 'rebuilt-pe', importsRebuilt: true, warning: null, method: 'snapshot' };
  const scanned = tryScanRebuild(dump, snapshot, options);
  if (scanned) return { bytes: scanned.bytes, outputKind: 'rebuilt-pe', importsRebuilt: true, warning: null, method: 'scan' };
  return { bytes: dump, outputKind: 'dump-pe', importsRebuilt: false, warning: 'imports-not-rebuilt' };
}

export async function unpackDynamic(bytes, name = 'sample.exe', options = {}) {
  requireThat(typeof process !== 'undefined' && process.versions?.node, 'engine-unavailable', { hint: 'server-side engine' });
  requireThat(process.platform === 'win32', 'engine-unavailable', { hint: 'win32 only' });
  let oepRva = Number(options.oepRva);
  let oepSource = 'caller';
  const autoLocate = options.mode === 'auto-oep';
  if (!autoLocate && (!Number.isInteger(oepRva) || oepRva <= 0)) {
    // Auto-derive the OEP from the static engines for families whose stub
    // layout is already fully known (MPRESS / FSG / UPX NRV2B).
    const { ENGINES, parseInput } = await import('../engines.js');
    const pe = parseInput(bytes);
    const engine = ENGINES.find(entry => entry.supports(bytes, pe));
    requireThat(engine, 'missing-oep', { hint: 'no oepRva given and no static engine can derive the OEP for this family' });
    const derived = await engine.unpack(bytes, name, {});
    oepRva = derived.metadata.originalEntryPoint;
    oepSource = `derived:${derived.metadata.engine}`;
  }
  if (autoLocate) { oepRva = 0; oepSource = 'auto-located'; }
  else requireThat(Number.isInteger(oepRva) && oepRva > 0 && oepRva < 0x10000000, 'missing-oep', { hint: 'dynamic-debug-dump requires oepRva or mode auto-oep/extract' });
  const dir = await mkdtemp(join(tmpdir(), 'older-shells-dyn-'));
  try {
    const input = join(dir, 'in.exe'), output = join(dir, 'dump.bin');
    await writeFile(input, bytes);
    const extract = options.mode === 'extract';
    const args = autoLocate
      ? [input, 'auto', output, '25', 'oep', '0.25']
      : extract
        ? [input, `0x${oepRva.toString(16)}`, output, '25', 'extract', '0.5']
        : [input, `0x${oepRva.toString(16)}`, output, '25'];
    const { out } = await runPython(args);
    let info;
    try { info = JSON.parse(out.trim().split('\n').pop()); } catch { requireThat(false, 'tool-error', { hint: out.slice(0, 200) }); }
    requireThat(info.ok, info.error === 'timeout before OEP breakpoint' ? 'dynamic-race-lost' : 'dynamic-failed', { hint: info.error || '' });
    const dump = new Uint8Array(await readFile(output));
    rebuildMemoryImagePe(dump);
    ensureExecutableEntryPoint(dump);
    parsePE(dump);
    let snapshot = null;
    try { snapshot = await readFile(`${output}.imports.json`, 'utf8'); } catch { /* mapping unavailable */ }
    let runtimeBase = Number(info.imageBase);
    if (!Number.isInteger(runtimeBase) || runtimeBase <= 0) runtimeBase = Number.parseInt(parsePE(dump).imageBase, 16);
    const applied = applyImportSnapshot(dump, snapshot, { imageBase: runtimeBase });
    ensureExecutableEntryPoint(applied.bytes);
    const safeName = String(name).split(/[\\/]/).pop().replace(/[^\w.\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'sample.exe';
    return {
      bytes: applied.bytes, name: safeName.replace(/\.exe$/i, '') + (extract ? '.extract.exe' : '.dump.exe'),
      metadata: {
        engine: DYNAMIC_ENGINE.id, variant: DYNAMIC_ENGINE.variant, outputKind: extract ? 'extract-pe' : applied.outputKind, runtimeVerified: false,
        mode: 'dynamic-debug', requiresSampleExecution: true, originalEntryPoint: oepRva, oepSource, importsRebuilt: applied.importsRebuilt,
        importsRebuildMethod: applied.importsRebuilt ? applied.method : undefined,
        lateDump: Boolean(info.late), containment: 'DEBUG_ONLY_THIS_PROCESS + Job Object kill-on-close',
        warnings: [...(extract ? ['extraction-stage', 'runtime-not-verified'] : info.late ? ['dump-after-entry', 'runtime-not-verified'] : ['runtime-not-verified']), ...(applied.warning ? [applied.warning] : [])],
      },
      report: undefined,
    };
  } finally { await rm(dir, { recursive: true, force: true }); }
}
