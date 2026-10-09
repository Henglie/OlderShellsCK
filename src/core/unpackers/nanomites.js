// Original implementation of the documented ArmInline and dilloDIE formats.
// This module patches a raw=RVA memory image; it does not rebuild a PE or scan CCs.
import { requireThat } from '../errors.js';

export const NANOMITE_LIMITS = Object.freeze({
  records: 65536, tableBytes: 2 * 1024 * 1024, imageBytes: 128 * 1024 * 1024,
  observations: 4096, instructionSpans: 131072,
});
export const NANOMITE_SCHEMA = 'armadillo-oracle/v1';
export const FLAG_MASK = 0x8c5; // OF, SF, ZF, PF, CF; AF is irrelevant to Jcc.

const JCC = Object.freeze(['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
  'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']);
const COUNTERS = Object.freeze([0, 1, 2, 0x10000]);
const ARM_TYPES = Object.freeze({
  2: 'jmp', 3: 'jne', 4: 'je', 5: 'jb', 6: 'jbe', 7: 'ja', 8: 'jae',
  9: 'jg', 10: 'jge', 11: 'jl', 12: 'jle', 13: 'jp', 14: 'jp', 15: 'jnp',
  16: 'jnp', 17: 'js', 18: 'jns', 21: 'jb', 22: 'jae', 23: 'jo', 24: 'jno',
});
export const NANOMITE_CONDITIONS = Object.freeze(['jmp', ...JCC, 'loopne', 'loope', 'loop', 'jecxz']);

function uint32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function bounded(value, fallback, maximum, code) {
  value ??= fallback;
  requireThat(Number.isInteger(value) && value > 0 && value <= maximum, code);
  return value;
}

function inputBytes(bytes, limit) {
  requireThat(bytes instanceof Uint8Array, 'invalid-input');
  requireThat(!(typeof SharedArrayBuffer !== 'undefined' && bytes.buffer instanceof SharedArrayBuffer), 'shared-input');
  requireThat(bytes.byteLength <= limit, 'nanomite-size-limit');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/** Strict Count + Count*16 framing. Semantic errors remain explicit records. */
export function parseArmInlineNan(bytes, options = {}) {
  const view = inputBytes(bytes, NANOMITE_LIMITS.tableBytes);
  const limit = bounded(options.maxRecords, NANOMITE_LIMITS.records, NANOMITE_LIMITS.records, 'nanomite-record-limit');
  requireThat(bytes.length >= 4, 'truncated-nan-table');
  const count = view.getUint32(0, true);
  requireThat(count <= limit, 'nanomite-record-limit');
  requireThat(bytes.length === 4 + count * 16, bytes.length < 4 + count * 16 ? 'truncated-nan-table' : 'trailing-nan-data');
  const records = [];
  for (let i = 0; i < count; i++) {
    const offset = 4 + i * 16;
    records.push({ address: view.getUint32(offset, true), destination: view.getUint32(offset + 4, true),
      size: view.getUint32(offset + 8, true), jumpType: view.getUint32(offset + 12, true), source: 'arminline', offset });
  }
  return records;
}

function decodeBranch(bytes, address) {
  let condition, displacement;
  if (bytes.length === 2) {
    const opcode = bytes[0];
    condition = opcode === 0xeb ? 'jmp' : opcode >= 0x70 && opcode <= 0x7f ? JCC[opcode & 15]
      : ({ 0xe0: 'loopne', 0xe1: 'loope', 0xe2: 'loop', 0xe3: 'jecxz' })[opcode];
    displacement = bytes[1] < 128 ? bytes[1] : bytes[1] - 256;
  } else if (bytes.length === 5 && bytes[0] === 0xe9) {
    condition = 'jmp';
    displacement = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(1, true);
  } else if (bytes.length === 6 && bytes[0] === 0x0f && bytes[1] >= 0x80 && bytes[1] <= 0x8f) {
    condition = JCC[bytes[1] & 15];
    displacement = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(2, true);
  }
  if (!condition) return { reason: 'unknown-opcode' };
  const destination = address + bytes.length + displacement;
  if (!uint32(destination)) return { reason: 'address-overflow' };
  return { condition, destination };
}

/** No guessed terminator or padding: the supplied slice is the entire stream. */
export function parseDilloDieRecords(bytes, options = {}) {
  const view = inputBytes(bytes, NANOMITE_LIMITS.tableBytes);
  const limit = bounded(options.maxRecords, NANOMITE_LIMITS.records, NANOMITE_LIMITS.records, 'nanomite-record-limit');
  const records = [];
  for (let offset = 0; offset < bytes.length;) {
    requireThat(records.length < limit, 'nanomite-record-limit');
    requireThat(bytes.length - offset >= 5, 'truncated-dillo-record', { offset });
    const address = view.getUint32(offset, true), size = bytes[offset + 4];
    requireThat([2, 5, 6].includes(size), 'invalid-dillo-size', { offset, size });
    requireThat(size <= bytes.length - offset - 5, 'truncated-dillo-record', { offset });
    const encoding = Uint8Array.from(bytes.subarray(offset + 5, offset + 5 + size));
    const decoded = decodeBranch(encoding, address);
    records.push({ address, size, ...decoded, encoding, source: 'dillodie', offset,
      ...(address === 0 ? { marker: true, reason: 'marker-record' } : {}) });
    offset += 5 + size;
  }
  return records;
}

/** Exhaustive flags, not the six values from the legacy decision tree. */
export function createFlagProbes() {
  return Array.from({ length: 32 }, (_, bits) => 0x202 | (bits & 1) | ((bits & 2) << 1)
    | ((bits & 4) << 4) | ((bits & 8) << 4) | ((bits & 16) << 7));
}

/** ECX classes also distinguish LOOP/LOOPcc/JECXZ from a constant JMP/Jcc. */
export function createNanomiteProbes() {
  return COUNTERS.flatMap(ecx => createFlagProbes().map(eflags => ({ eflags, ecx })));
}

function taken(condition, eflags, ecx) {
  const cf = !!(eflags & 1), pf = !!(eflags & 4), zf = !!(eflags & 0x40);
  const sf = !!(eflags & 0x80), of = !!(eflags & 0x800);
  switch (condition) {
    case 'jmp': return true;
    case 'jo': return of;
    case 'jno': return !of;
    case 'jb': return cf;
    case 'jae': return !cf;
    case 'je': return zf;
    case 'jne': return !zf;
    case 'jbe': return cf || zf;
    case 'ja': return !cf && !zf;
    case 'js': return sf;
    case 'jns': return !sf;
    case 'jp': return pf;
    case 'jnp': return !pf;
    case 'jl': return sf !== of;
    case 'jge': return sf === of;
    case 'jle': return zf || sf !== of;
    case 'jg': return !zf && sf === of;
    case 'loopne': return ((ecx - 1) >>> 0) !== 0 && !zf;
    case 'loope': return ((ecx - 1) >>> 0) !== 0 && zf;
    case 'loop': return ((ecx - 1) >>> 0) !== 0;
    case 'jecxz': return ecx === 0;
    default: return null;
  }
}

function encodingFor(record) {
  const { condition, size, address, destination } = record;
  const cc = JCC.indexOf(condition);
  if ((condition === 'jmp' && ![2, 5].includes(size)) || (cc >= 0 && ![2, 6].includes(size))
    || (['loopne', 'loope', 'loop', 'jecxz'].includes(condition) && size !== 2)) return { reason: 'invalid-instruction-length' };
  if (!NANOMITE_CONDITIONS.includes(condition)) return { reason: 'unknown-condition' };
  const displacement = destination - (address + size);
  if (size === 2 && (displacement < -128 || displacement > 127)) return { reason: 'rel8-out-of-range' };
  if (size !== 2 && (displacement < -0x80000000 || displacement > 0x7fffffff)) return { reason: 'rel32-out-of-range' };
  const bytes = new Uint8Array(size), view = new DataView(bytes.buffer);
  if (size === 2) {
    bytes[0] = condition === 'jmp' ? 0xeb : cc >= 0 ? 0x70 + cc
      : ({ loopne: 0xe0, loope: 0xe1, loop: 0xe2, jecxz: 0xe3 })[condition];
    view.setInt8(1, displacement);
  } else if (size === 5) {
    bytes[0] = 0xe9; view.setInt32(1, displacement, true);
  } else {
    bytes[0] = 0x0f; bytes[1] = 0x80 + cc; view.setInt32(2, displacement, true);
  }
  return { bytes };
}

/** Length is independent evidence. Never infer it as the smallest forward EIP. */
export function classifyNanomite(observations, { address, size, destination } = {}) {
  const unresolved = reason => ({ status: 'unresolved', reason });
  if (!uint32(address) || ![2, 5, 6].includes(size) || !uint32(address + size)) return unresolved('invalid-probe-site');
  requireThat(Array.isArray(observations) && observations.length <= NANOMITE_LIMITS.observations, 'nanomite-probe-limit');
  const samples = new Map();
  for (const sample of observations) {
    if (!sample || !uint32(sample.eflags) || !uint32(sample.ecx) || !uint32(sample.eip)) return unresolved('invalid-observation');
    const key = `${sample.eflags & FLAG_MASK}:${sample.ecx}`;
    if (samples.has(key) && samples.get(key).eip !== sample.eip) return unresolved('inconsistent-observations');
    samples.set(key, { eflags: sample.eflags, ecx: sample.ecx, eip: sample.eip });
  }
  if (!createNanomiteProbes().every(p => samples.has(`${p.eflags & FLAG_MASK}:${p.ecx}`))) return unresolved('incomplete-probes');
  const fallThrough = address + size, outcomes = [...new Set([...samples.values()].map(p => p.eip))];
  if (outcomes.length > 2) return unresolved('inconsistent-observations');
  const targets = outcomes.filter(eip => eip !== fallThrough);
  if (targets.length !== 1) return unresolved('ambiguous-target');
  const target = targets[0];
  if (destination !== undefined && (!uint32(destination) || destination !== target)) return unresolved('destination-mismatch');
  const candidates = NANOMITE_CONDITIONS.filter(condition => {
    if (encodingFor({ address, destination: target, size, condition }).reason) return false;
    return [...samples.values()].every(p => p.eip === (taken(condition, p.eflags, p.ecx) ? target : fallThrough));
  });
  if (candidates.length !== 1) return { ...unresolved(candidates.length ? 'ambiguous-condition' : 'unknown-condition'), candidates };
  return { status: 'resolved', record: { address, destination: target, size, condition: candidates[0], source: 'oracle' } };
}

function normalizeRecord(record, options) {
  if (!record || typeof record !== 'object' || !uint32(record.address) || !uint32(record.destination)
    || !uint32(record.size)) return { reason: record?.reason || 'invalid-record' };
  if (record.marker || record.address === 0) return { reason: 'marker-record' };
  if (record.reason) return { reason: record.reason };
  let condition = record.condition;
  if (record.jumpType !== undefined) {
    if (record.jumpType === 0) return { reason: 'unknown-jump-type' };
    if (record.jumpType === 1) return { reason: 'not-nanomite' };
    if (record.jumpType === 20) return { reason: 'unsupported-jncxz' }; // No single x86 instruction.
    const mapped = record.jumpType === 19 && options.counterBits === 32 ? 'jecxz' : ARM_TYPES[record.jumpType];
    if (!mapped) return { reason: record.jumpType === 19 ? 'ambiguous-counter-width' : 'unknown-jump-type' };
    if (condition !== undefined && condition !== mapped) return { reason: 'ambiguous-record' };
    condition = mapped;
  }
  return { address: record.address, destination: record.destination, size: record.size, condition };
}

function sortedSpans(spans, base, size) {
  if (spans === undefined) return null;
  requireThat(Array.isArray(spans) && spans.length <= NANOMITE_LIMITS.instructionSpans, 'nanomite-span-limit');
  const sorted = spans.map(s => {
    requireThat(s && uint32(s.address) && Number.isInteger(s.size) && s.size >= 1 && s.size <= 15
      && s.address >= base && s.address + s.size <= base + size, 'invalid-instruction-span');
    return { address: s.address, end: s.address + s.size };
  }).sort((a, b) => a.address - b.address);
  for (let i = 1; i < sorted.length; i++) requireThat(sorted[i].address >= sorted[i - 1].end, 'overlapping-instruction-spans');
  return sorted;
}

function boundaryReason(spans, address) {
  if (!spans) return null;
  let lo = 0, hi = spans.length;
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (spans[mid].address <= address) lo = mid + 1; else hi = mid; }
  const span = spans[lo - 1];
  return span?.address === address ? null : span && address < span.end ? 'not-instruction-boundary' : 'unverified-instruction-boundary';
}

function inIndirectOperand(image, rva) {
  // Conservative local rejection, not an LDE: known FF15/FF25 disp32 slots.
  for (let start = Math.max(0, rva - 5); start <= rva - 2; start++) {
    if (image[start] === 0xff && [0x15, 0x25].includes(image[start + 1]) && rva < start + 6) return true;
  }
  return false;
}

/** Valid records are applied independently, but every member of an overlap is refused. */
export function repairNanomites(image, records, options = {}) {
  inputBytes(image, NANOMITE_LIMITS.imageBytes);
  requireThat(options.layout === 'raw-rva', 'unsupported-image-layout');
  const base = options.imageBase, size = options.sizeOfImage ?? image.length;
  requireThat(uint32(base) && Number.isInteger(size) && size > 0 && size <= image.length
    && base + size <= 0x100000000, 'invalid-image-range');
  const limit = bounded(options.maxRecords, NANOMITE_LIMITS.records, NANOMITE_LIMITS.records, 'nanomite-record-limit');
  requireThat(Array.isArray(records) && records.length <= limit, 'nanomite-record-limit');
  const spans = sortedSpans(options.instructionSpans, base, size);
  const ranges = options.executableRanges;
  if (ranges !== undefined) {
    requireThat(Array.isArray(ranges) && ranges.length <= 96 && ranges.every(r => r && uint32(r.address)
      && Number.isInteger(r.size) && r.size > 0 && r.address >= base && r.address + r.size <= base + size), 'invalid-executable-ranges');
  }
  const intervals = records.flatMap((r, index) => r && uint32(r.address) && uint32(r.size) && r.size > 0
    ? [{ start: r.address, end: r.address + r.size, index }] : []).sort((a, b) => a.start - b.start);
  const overlaps = new Set();
  let group = [], end = -1;
  const finishGroup = () => { if (group.length > 1) for (const index of group) overlaps.add(index); };
  for (const interval of intervals) {
    if (interval.start >= end) { finishGroup(); group = []; end = -1; }
    group.push(interval.index); end = Math.max(end, interval.end);
  }
  finishGroup();
  const bytes = Uint8Array.from(image), repaired = [], unresolved = [];
  for (const [index, record] of records.entries()) {
    const normalized = normalizeRecord(record, options);
    let reason = overlaps.has(index) ? 'overlapping-records' : normalized.reason;
    const { address, destination, size: length } = normalized;
    const rva = address - base;
    if (!reason && (!Number.isInteger(length) || ![2, 5, 6].includes(length))) reason = 'invalid-instruction-length';
    if (!reason && (rva < 0 || rva + length > size || !uint32(address + length))) reason = 'site-outside-image';
    if (!reason && (destination < base || destination >= base + size)) reason = 'destination-outside-image';
    if (!reason && ranges && !ranges.some(r => address >= r.address && address + length <= r.address + r.size)) reason = 'site-not-executable';
    if (!reason) reason = boundaryReason(spans, address);
    if (!reason && image[rva] !== 0xcc) reason = 'site-not-int3';
    if (!reason && inIndirectOperand(image, rva)) reason = 'int3-in-indirect-operand';
    const encoded = reason ? null : encodingFor(normalized);
    reason ||= encoded?.reason;
    if (!reason && record.encoding !== undefined) {
      const encoding = record.encoding;
      if (!(encoding instanceof Uint8Array || Array.isArray(encoding)) || encoding.length !== length
        || !Array.from(encoding).every((v, i) => Number.isInteger(v) && v === encoded.bytes[i])) reason = 'encoding-mismatch';
    }
    if (reason) { unresolved.push({ index, address: record?.address ?? null, reason }); continue; }
    bytes.set(encoded.bytes, rva);
    repaired.push({ index, ...normalized, bytes: encoded.bytes });
  }
  return { bytes, repaired, unresolved, complete: unresolved.length === 0 };
}

/** Sidecar transport is deliberately separate from image patching and native execution. */
export function parseNanomiteSidecar(input) {
  if (typeof input === 'string') {
    requireThat(input.length <= NANOMITE_LIMITS.tableBytes, 'nanomite-size-limit');
    try { input = JSON.parse(input); } catch { requireThat(false, 'invalid-nanomite-sidecar'); }
  }
  requireThat(input && input.schema === NANOMITE_SCHEMA && input.layout === 'raw-rva' && uint32(input.imageBase)
    && Array.isArray(input.nanRecords) && input.nanRecords.length <= NANOMITE_LIMITS.records
    && Array.isArray(input.probes) && input.probes.length <= NANOMITE_LIMITS.records
    && Array.isArray(input.processes) && input.processes.length <= 64, 'invalid-nanomite-sidecar');
  let count = 0;
  const nanRecords = input.nanRecords.map(r => {
    requireThat(r && typeof r === 'object' && !Array.isArray(r), 'invalid-nanomite-sidecar');
    if (r.encoding !== undefined) {
      requireThat((r.encoding instanceof Uint8Array || Array.isArray(r.encoding)) && [2, 5, 6].includes(r.encoding.length)
        && r.encoding.length === r.size && Array.from(r.encoding).every(v => Number.isInteger(v) && v >= 0 && v <= 255), 'invalid-nanomite-encoding');
    }
    return { ...r, ...(r.encoding !== undefined ? { encoding: Uint8Array.from(r.encoding) } : {}) };
  });
  const probes = input.probes.map(p => {
    requireThat(p && Array.isArray(p.observations) && p.observations.length <= NANOMITE_LIMITS.observations
      && (count += p.observations.length) <= NANOMITE_LIMITS.records, 'nanomite-probe-limit');
    return { ...p, observations: p.observations.map(o => ({ ...o })) };
  });
  return { schema: input.schema, layout: input.layout, imageBase: input.imageBase, status: input.status,
    nanRecords, probes, processes: input.processes.map(p => ({ ...p })) };
}

/** mode is mandatory: choose supplied records OR classify completed oracle probes. */
export function applyNanomiteSidecar(image, input, options = {}) {
  const sidecar = parseNanomiteSidecar(input);
  requireThat(['records', 'probe'].includes(options.mode), 'missing-nanomite-mode');
  requireThat(options.imageBase === undefined || options.imageBase === sidecar.imageBase, 'image-base-mismatch');
  const diagnostics = [];
  let records = sidecar.nanRecords;
  if (options.mode === 'probe') {
    records = [];
    for (const [index, probe] of sidecar.probes.entries()) {
      if (sidecar.status !== 'observations-ready' || probe.reason || probe.status && probe.status !== 'observations-ready') {
        diagnostics.push({ index, address: probe.address, reason: probe.reason || 'probe-unavailable' });
        continue;
      }
      const classified = classifyNanomite(probe.observations, probe);
      if (classified.record) records.push(classified.record);
      else diagnostics.push({ index, address: probe.address, reason: probe.reason || classified.reason });
    }
    if (!sidecar.probes.length) diagnostics.push({ index: null, address: null, reason: 'probe-unavailable' });
  }
  const result = repairNanomites(image, records, { ...options, layout: sidecar.layout, imageBase: sidecar.imageBase });
  result.unresolved.push(...diagnostics);
  result.complete = result.unresolved.length === 0;
  return result;
}
