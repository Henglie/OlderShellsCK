// FSG section/support-table layout adapted from XStaticUnpacker (MIT).
// Copyright (c) 2017-2026 hors<horsicq@gmail.com>
// xfsg.cpp/h @ 746fb24433c29b6460edebac83fdad19909d9e81.
// See licenses/xstaticunpacker-MIT.txt and docs/research/fsg-implementation.md.
import { Bytes, MAX_INPUT, MAX_OUTPUT, align, entropy, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { decompressFsg } from '../codecs/fsg.js';

export const FSG_ENGINE = Object.freeze({
  id: 'fsg-pe32', family: 'fsg', variants: Object.freeze(['1.31', '1.33']),
  outputKind: 'rebuilt-pe', runtimeVerified: true, stage: 'experimental',
});

// Vetted plaintext stubs. Only embedded addresses / OEP displacements vary.
// Check the entire decompressor, not just a mov opcode or section names.
const STUB_133 = 'be........ad93ad97ad5696b280a4b680ff1373f933c9ff13731633c0ff13731fb68041b010ff1312c073fa753caaebe0ff530802f683d901750eff5304eb26acd1e8742f13c9eb1a9148c1e008acff53043d007d0000730a80fc05730683f87f77024141958bc5b600568bf72bf0f3a45eeb9d8bd65ead48740a7902ad50568bf297eb87ad935e46ad9756ff1395ac84c075fbfe0e74f0790546ad50eb09fe0e0f84........5655ff5304abebe033c941ff1313c9ff1372f8c302d275058a164612d2c3';
const STUB_131 = 'bb........bf........be........53bb........b280a4b680ffd373f933c9ffd3731633c0ffd37323b68041b010ffd312c073fa7542aaebe0e84600000002f683d9017510e838000000eb28acd1e8744813c9eb1c9148c1e008ace8220000003d007d0000730a80fc05730683f87f77024141958bc5b600568bf72bf0f3a45eeb9733c941ffd313c9ffd372f8c302d275058a164612d2c35b5b0fb73b4f74084f7413c1e70ceb078b7b025783c3044343e958ffffff5fbb........478b37af57ff139533c0ae75fdfe0f74effe0f750647ff37afeb09fe0f0f84........5755ff53048906ad85c075d98becc3';

function readHeaders(bytes) {
  requireThat(bytes instanceof Uint8Array, 'invalid-input');
  requireThat(bytes.length > 0 && bytes.length <= MAX_INPUT, 'input-size-limit');
  const input = new Bytes(bytes);
  requireThat(input.u16(0) === 0x5a4d, 'not-pe');
  const peOffset = input.u32(0x3c);
  // FSG 1.33 deliberately overlaps unused DOS fields with the PE header.
  requireThat(peOffset === 0x0c || peOffset >= 0x40, 'invalid-pe-header');
  requireThat(input.u32(peOffset) === 0x4550, 'not-pe');
  const machine = input.u16(peOffset + 4), count = input.u16(peOffset + 6);
  const optionalOffset = peOffset + 24, optionalSize = input.u16(peOffset + 20);
  requireThat(machine === 0x14c && input.u16(optionalOffset) === 0x10b, 'unsupported-variant');
  requireThat(!(input.u16(peOffset + 22) & 0x2000), 'unsupported-variant');
  requireThat(count === 2 && optionalSize === 0xe0, 'unsupported-fsg-layout');
  input.range(optionalOffset, optionalSize);
  const directoryOffset = optionalOffset + 96, sectionTable = optionalOffset + optionalSize;
  const headerEnd = sectionTable + count * 40;
  input.range(sectionTable, count * 40);
  requireThat(input.u32(directoryOffset - 4) === 16, 'unsupported-directories');
  const directories = Array.from({ length: 16 }, (_, i) => ({ rva: input.u32(directoryOffset + i * 8), size: input.u32(directoryOffset + i * 8 + 4) }));
  requireThat(!directories[14].rva && !directories[14].size, 'unsupported-variant');
  const sizeOfHeaders = input.u32(optionalOffset + 60), sizeOfImage = input.u32(optionalOffset + 56);
  const sectionAlignment = input.u32(optionalOffset + 32), fileAlignment = input.u32(optionalOffset + 36);
  requireThat(sectionAlignment === 0x1000 && fileAlignment === 0x200, 'unsupported-alignment');
  requireThat(sizeOfHeaders >= headerEnd && sizeOfHeaders <= bytes.length, 'invalid-header-size');
  requireThat(sizeOfImage > 0 && sizeOfImage <= MAX_OUTPUT && sizeOfImage % sectionAlignment === 0, 'output-size-limit');
  const base = input.u32(optionalOffset + 28);
  requireThat(base % 0x10000 === 0 && base + sizeOfImage <= 0x100000000, 'invalid-image-base');
  const sections = Array.from({ length: count }, (_, i) => {
    const h = sectionTable + i * 40;
    const s = { name: input.string(h, 8), headerOffset: h, virtualSize: input.u32(h + 8), rva: input.u32(h + 12),
      rawSize: input.u32(h + 16), rawOffset: input.u32(h + 20), characteristics: input.u32(h + 36) };
    requireThat(s.virtualSize > 0 && s.rva >= align(sizeOfHeaders, sectionAlignment) && s.rva % sectionAlignment === 0, 'invalid-section-rva');
    requireThat(s.rva + Math.max(s.virtualSize, s.rawSize) <= sizeOfImage, 'invalid-section-rva');
    if (s.rawSize) {
      input.range(s.rawOffset, s.rawSize);
      // Actual PE/section headers are never aliased. Only unused header slack
      // may be overstated by SizeOfHeaders (observed on the vetted 1.31).
      requireThat(s.rawOffset >= headerEnd && s.rawOffset % fileAlignment === 0, 'unsupported-fsg-layout');
    } else requireThat(s.rawOffset === 0, 'unsupported-fsg-layout');
    return s;
  });
  const [destination, source] = sections;
  requireThat(destination.rawSize === 0 && source.rawSize > 0 && source.rawSize < destination.virtualSize && source.rawSize <= source.virtualSize, 'unsupported-fsg-layout');
  requireThat(destination.rva + destination.virtualSize === source.rva, 'unsupported-fsg-layout');
  const headerMapEnd = Math.min(sizeOfHeaders, source.rawOffset);
  const rvaToOffset = (rva, length = 1) => {
    if (!Number.isSafeInteger(rva) || !Number.isSafeInteger(length) || rva < 0 || length < 0) return null;
    const size = Math.max(1, length);
    if (rva + size <= headerMapEnd) return rva;
    const delta = rva - source.rva;
    return delta >= 0 && delta + size <= source.rawSize ? source.rawOffset + delta : null;
  };
  const entryPointRva = input.u32(optionalOffset + 16), entryPointOffset = rvaToOffset(entryPointRva);
  requireThat(entryPointRva >= source.rva && entryPointOffset !== null, 'invalid-fsg-stub');
  const warnings = [];
  if (peOffset < 0x40) warnings.push('fsg-overlapping-dos-header');
  if (source.rawOffset < sizeOfHeaders) warnings.push('fsg-overstated-header-size');
  return { format: 'PE32', architecture: 'x86', machine, is64: false, isDll: false, isNet: false,
    peOffset, optionalOffset, directoryOffset, sectionTable, sizeOfHeaders, sizeOfImage, fileAlignment, sectionAlignment,
    imageBase: `0x${base.toString(16)}`, entryPointRva, entryPointOffset, sections, directories,
    overlay: { offset: source.rawOffset + source.rawSize, size: bytes.length - source.rawOffset - source.rawSize },
    imports: [], warnings, rvaToOffset, headerEnd };
}

function inspect(bytes) {
  const pe = readHeaders(bytes), input = new Bytes(bytes), ep = pe.entryPointOffset;
  const [destination, source] = pe.sections, base = Number(pe.imageBase);
  let variant, je;
  if (pe.rvaToOffset(pe.entryPointRva, STUB_133.length / 2) === ep && matchHex(bytes, ep, STUB_133)) { variant = '1.33'; je = 161; }
  else if (pe.rvaToOffset(pe.entryPointRva, STUB_131.length / 2) === ep && matchHex(bytes, ep, STUB_131)) { variant = '1.31'; je = 218; }
  else requireThat(false, 'unsupported-variant');
  requireThat(pe.peOffset !== 0x0c || variant === '1.33', 'unsupported-fsg-layout');
  const vaToRva = value => {
    requireThat(value >= base && value - base < pe.sizeOfImage, 'invalid-fsg-pointer');
    return value - base;
  };
  const support = vaToRva(input.u32(ep + 1));
  const supportEnd = Math.min(source.rawOffset, pe.sizeOfHeaders);
  requireThat(support >= pe.headerEnd && support < supportEnd && supportEnd - support <= 0x10000, 'invalid-fsg-support');
  const rvas = [destination.rva];
  let streamRva, cursor = support, ended = false, importDest = -1;
  const supportRange = size => requireThat(cursor + size <= supportEnd, 'invalid-fsg-support');
  if (variant === '1.33') {
    supportRange(12);
    const functionsRva = vaToRva(input.u32(support));
    const functions = pe.rvaToOffset(functionsRva, 12);
    requireThat(functions !== null, 'invalid-fsg-pointer');
    for (const [i, offset] of [187, 175, 177].entries()) {
      requireThat(vaToRva(input.u32(functions + i * 4)) === pe.entryPointRva + offset, 'invalid-fsg-pointer');
    }
    requireThat(vaToRva(input.u32(support + 4)) === destination.rva, 'invalid-fsg-destination');
    streamRva = vaToRva(input.u32(support + 8)); cursor += 12;
    for (let i = 0; i < 96; i++) {
      supportRange(4);
      const value = input.u32(cursor); cursor += 4;
      if (value === 0) { ended = true; break; }
      rvas.push(vaToRva(value - 1));
    }
    // After the section-list terminator the stub reads the compressed import
    // blob's destination VA, a literal 1 and a second function-table pointer.
    supportRange(4);
    importDest = vaToRva(input.u32(cursor)); cursor += 4;
    supportRange(4);
    requireThat(input.u32(cursor) === 1, 'invalid-fsg-support'); cursor += 4;
    supportRange(4);
    vaToRva(input.u32(cursor)); cursor += 4;
  } else {
    requireThat(vaToRva(input.u32(ep + 17)) === pe.entryPointRva + 143, 'invalid-fsg-pointer');
    requireThat(vaToRva(input.u32(ep + 6)) === destination.rva, 'invalid-fsg-destination');
    streamRva = vaToRva(input.u32(ep + 11));
    const importDests = [];
    for (let i = 0; i < 96; i++) {
      supportRange(2);
      const value = input.u16(cursor); cursor += 2;
      if (value === 2) { ended = true; break; }
      if (value === 1) { supportRange(4); importDests.push(vaToRva(input.u32(cursor))); cursor += 4; }
      else {
        requireThat(value > 2, 'invalid-fsg-support');
        rvas.push(vaToRva((value - 2) * 4096));
      }
    }
    // A word-1 record carries the import blob's destination VA; exactly one.
    requireThat(importDests.length === 1, 'invalid-fsg-support');
    importDest = importDests[0];
  }
  requireThat(ended && rvas.length <= 96 && new Set(rvas).size === rvas.length, 'invalid-fsg-support');
  const sorted = [...rvas].sort((a, b) => a - b);
  for (const rva of sorted) requireThat(rva >= destination.rva && rva < source.rva && rva % 0x1000 === 0, 'invalid-fsg-destination');
  requireThat(importDest >= destination.rva && importDest < source.rva, 'invalid-fsg-destination');
  const streamOffset = pe.rvaToOffset(streamRva);
  requireThat(streamRva >= source.rva && streamOffset !== null && streamOffset < ep, 'invalid-fsg-pointer');
  const originalEntryPoint = pe.entryPointRva + je + 6 + input.i32(ep + je + 2);
  requireThat(originalEntryPoint >= destination.rva && originalEntryPoint < source.rva, 'invalid-original-entry');
  const streams = rvas.map(rva => ({ rva, virtualSize: (sorted[sorted.indexOf(rva) + 1] ?? source.rva) - rva }));
  return { pe, variant, streamOffset, streams, originalEntryPoint, importDest };
}

// The stub decompresses one extra aPLib stream holding the original import
// description: per DLL { 0x01, IAT VA, dll name NUL, function names NUL },
// ended by a terminator byte. Each name's first byte is the original character
// plus a variant-specific offset (1.33 repairs with two `dec byte ptr [esi]`,
// 1.31 with three); the terminator byte equals that offset.
function parseFsgImports(blob, base, delta) {
  requireThat(blob.length > 2 && blob.length <= MAX_OUTPUT, 'invalid-import-hints');
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const readName = start => {
    let end = start;
    while (end < blob.length && blob[end]) end++;
    requireThat(end > start && end < blob.length && end - start <= 512, 'invalid-import-hints');
    const value = Array.from(blob.subarray(start, end), b => String.fromCharCode(b)).join('');
    requireThat(/^[\x21-\x7e]+$/.test(value.slice(1)), 'invalid-import-hints');
    return { value, end: end + 1 };
  };
  let cursor = 0, total = 0, ended = false;
  const modules = [];
  while (!ended) {
    requireThat(modules.length < 256, 'import-limit');
    requireThat(blob[cursor] === 1, 'invalid-import-hints');
    requireThat(cursor + 5 <= blob.length, 'invalid-import-hints');
    const pointer = view.getUint32(cursor + 1, true);
    const dll = readName(cursor + 5); cursor = dll.end;
    const functions = [];
    while (blob[cursor] !== 1 && blob[cursor] !== delta) {
      const raw = readName(cursor); cursor = raw.end;
      const name = String.fromCharCode(raw.value.charCodeAt(0) - delta) + raw.value.slice(1);
      requireThat(/^[\x21-\x7e]+$/.test(name), 'invalid-import-hints');
      functions.push({ name });
      requireThat(functions.length <= 4096 && ++total <= 16384, 'import-limit');
    }
    requireThat(functions.length > 0, 'invalid-import-hints');
    requireThat(Number.isSafeInteger(pointer) && pointer >= base && pointer % 4 === 0 && pointer - base < 0x100000000, 'invalid-import-hints');
    modules.push({ dll: dll.value, functions, firstThunk: pointer - base });
    if (blob[cursor] === delta) { cursor++; ended = true; }
  }
  requireThat(cursor === blob.length && modules.length > 0, 'invalid-import-hints');
  return modules;
}

// An explicit FSG-only parser for main's fallback path. Does not relax parsePE.
// It returns only after full stub + bounded support-layout validation. Packed
// imports are intentionally not enumerated; the analysis output has none.
export function parseFsgPE(bytes) {
  const { pe } = inspect(bytes);
  for (const s of pe.sections) s.entropy = entropy(bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize));
  return pe;
}

export function supportsFsg(bytes, pe) {
  try {
    if (pe && (pe.machine !== 0x14c || pe.is64 || pe.isNet || pe.isDll)) return false;
    inspect(bytes);
    return true;
  } catch { return false; }
}

export function unpackFsg(bytes) {
  const plan = inspect(bytes), { pe, streams, originalEntryPoint, importDest } = plan;
  const [destination, source] = pe.sections, base = Number(pe.imageBase);
  let cursor = plan.streamOffset;
  for (const s of streams) {
    const decoded = decompressFsg(bytes.subarray(cursor, pe.entryPointOffset), s.virtualSize);
    requireThat(decoded.bytes.length > 0 && decoded.consumed > 0, 'decoded-size-mismatch');
    s.content = decoded.bytes;
    cursor += decoded.consumed;
  }
  streams.sort((a, b) => a.rva - b.rva);
  requireThat(streams.some(s => originalEntryPoint >= s.rva && originalEntryPoint < s.rva + s.content.length), 'invalid-original-entry');
  // The import blob is the last aPLib stream, decoded by the stub into free
  // zero-fill past the last decoded section content.
  const blobHost = streams.find(s => importDest >= s.rva + s.content.length && importDest < s.rva + s.virtualSize);
  requireThat(blobHost !== undefined, 'invalid-fsg-destination');
  const blob = decompressFsg(bytes.subarray(cursor, pe.entryPointOffset), blobHost.rva + blobHost.virtualSize - importDest);
  cursor += blob.consumed;
  requireThat(cursor === pe.entryPointOffset, 'invalid-fsg-stub');
  const modules = parseFsgImports(blob.bytes, base, plan.variant === '1.31' ? 3 : 2);
  const iatRanges = [];
  for (const module of modules) {
    requireThat(module.firstThunk >= destination.rva && module.firstThunk < source.rva, 'invalid-import-hints');
    const end = module.firstThunk + (module.functions.length + 1) * 4;
    const host = streams.find(s => module.firstThunk >= s.rva + s.content.length && end <= s.rva + s.virtualSize);
    requireThat(host !== undefined, 'invalid-import-hints');
    requireThat(!iatRanges.some(r => module.firstThunk < r.end && r.start < end) &&
      (end <= importDest || module.firstThunk >= importDest + blob.bytes.length), 'overlapping-iat');
    iatRanges.push({ start: module.firstThunk, end, module, host });
  }
  // FSG leaves the original resource section uncompressed at the head of its
  // source section: recover the tree plus data and point data directory 2 at
  // it again (the sample fails to start without its dialogs and strings).
  function resourceSpan(content) {
    const view = new DataView(content.buffer, content.byteOffset, content.byteLength);
    if (content.length < 16) return null;
    let span = 0;
    const walk = (offset, depth) => {
      if (depth > 3 || offset + 16 > content.length) return false;
      span = Math.max(span, offset + 16);
      const named = view.getUint16(offset + 12, true), ids = view.getUint16(offset + 14, true);
      if (named > 0x7fff || ids > 0x7fff || named + ids === 0) return false;
      for (let index = 0; index < named + ids; index++) {
        const at = offset + 16 + index * 8;
        if (at + 8 > content.length) return false;
        span = Math.max(span, at + 8);
        const child = view.getUint32(at + 4, true);
        if (child & 0x80000000) { if (!walk(child & 0x7fffffff, depth + 1)) return false; }
        else {
          const leaf = child & 0x7fffffff;
          if (leaf + 8 > content.length) return false;
          const size = view.getUint32(leaf + 4, true);
          if (!size || leaf + 8 + size > content.length) return false;
          span = Math.max(span, leaf + 8 + size);
        }
      }
      return true;
    };
    return walk(0, 1) ? span : null;
  }
  const sourceRaw = bytes.subarray(source.rawOffset, source.rawOffset + source.rawSize);
  const resourceSize = resourceSpan(sourceRaw);
  const importRva = resourceSize ? align(source.rva + resourceSize, 0x1000) : source.rva;
  let importSize = (modules.length + 1) * 20;
  for (const module of modules) {
    module.nameOffset = importSize; importSize += module.dll.length + 1;
    importSize = align(importSize, 4);
    module.iltOffset = importSize; importSize += (module.functions.length + 1) * 4;
    for (const fn of module.functions) { importSize = align(importSize, 2); fn.nameOffset = importSize; importSize += fn.name.length + 3; }
  }
  requireThat(importSize <= 4 * 1024 * 1024, 'import-limit');
  // The original TLS directory lives in the DOS area (RVA < first section).
  // Its data, index variable and callback array sit inside decoded streams,
  // so copying the 24-byte directory itself into .idata revives TLS support.
  let tlsBytes = null;
  const tlsRva0 = pe.directories[9].rva, tlsSize0 = pe.directories[9].size;
  if (tlsRva0 && tlsSize0 === 24 && tlsRva0 < pe.sections[0].rva) {
    const raw = bytes.subarray(tlsRva0, tlsRva0 + 24);
    const header = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const base = Number(pe.imageBase);
    const start = header.getUint32(0, true) - base, end = header.getUint32(4, true) - base, callbacks = header.getUint32(16, true);
    if (streams.some(s => start >= s.rva && end <= s.rva + s.virtualSize) &&
        (callbacks === 0 || streams.some(s => callbacks - base >= s.rva && callbacks - base < s.rva + s.virtualSize))) {
      tlsBytes = raw;
      importSize = align(importSize, 4);
      importSize += 24;
    }
  }
  const tlsOffset = tlsBytes ? importSize - 24 : 0;
  const importBytes = new Uint8Array(importSize), imp = new Bytes(importBytes);
  const text = new TextEncoder();
  for (const [index, module] of modules.entries()) {
    imp.put32(index * 20, importRva + module.iltOffset);
    imp.put32(index * 20 + 12, importRva + module.nameOffset);
    imp.put32(index * 20 + 16, module.firstThunk);
    importBytes.set(text.encode(module.dll), module.nameOffset);
    for (const [j, fn] of module.functions.entries()) {
      imp.put32(module.iltOffset + j * 4, importRva + fn.nameOffset);
      importBytes.set(text.encode(fn.name), fn.nameOffset + 2);
    }
  }
  const peOffset = 0x80, optional = peOffset + 24, table = optional + 0xe0;
  const headers = align(table + (streams.length + 2) * 40, 0x200);
  requireThat(headers <= streams[0].rva, 'unsupported-header-growth');
  let size = headers;
  for (const s of streams) {
    s.rawOffset = size;
    const iatSpan = Math.max(0, ...iatRanges.filter(r => r.host === s).map(r => r.end - s.rva));
    s.rawSize = align(Math.max(s.content.length, iatSpan), 0x200);
    size += s.rawSize;
  }
  // Decoded streams never carry the resources: they stay uncompressed in the
  // packer's source section (recovered above as resourceSize).
  const resourceRawOffset = size, resourceRawSize = resourceSize ? align(resourceSize, 0x200) : 0;
  size += resourceRawSize;
  const importRawOffset = size, importRawSize = align(importSize, 0x200);
  size += importRawSize;
  requireThat(size <= MAX_OUTPUT, 'output-size-limit');
  const output = new Uint8Array(size), out = new Bytes(output);
  out.put16(0, 0x5a4d); out.put32(0x3c, peOffset); out.put32(peOffset, 0x4550);
  out.put16(peOffset + 4, 0x14c); out.put16(peOffset + 6, streams.length + (resourceSize ? 2 : 1));
  out.put16(peOffset + 20, 0xe0); out.put16(peOffset + 22, 0x010f);
  out.put16(optional, 0x10b); out.put32(optional + 4, size - headers);
  out.put32(optional + 16, originalEntryPoint); out.put32(optional + 20, streams[0].rva);
  out.put32(optional + 28, Number(pe.imageBase));
  out.put32(optional + 32, 0x1000); out.put32(optional + 36, 0x200);
  out.put16(optional + 40, 4); out.put16(optional + 48, 4);
  out.put32(optional + 56, align(importRva + importSize, 0x1000)); out.put32(optional + 60, headers);
  out.put16(optional + 68, new Bytes(bytes).u16(pe.optionalOffset + 68));
  out.put32(optional + 72, 0x100000); out.put32(optional + 76, 0x1000);
  out.put32(optional + 80, 0x100000); out.put32(optional + 84, 0x1000); out.put32(optional + 92, 16);
  out.put32(optional + 96 + 8, importRva); out.put32(optional + 96 + 12, (modules.length + 1) * 20);
  if (resourceSize) { out.put32(optional + 96 + 2 * 8, source.rva); out.put32(optional + 96 + 2 * 8 + 4, resourceSize); }
  if (tlsBytes) { out.put32(optional + 96 + 9 * 8, importRva + tlsOffset); out.put32(optional + 96 + 9 * 8 + 4, 24); importBytes.set(tlsBytes, tlsOffset); }
  const iatStart = Math.min(...iatRanges.map(r => r.start)), iatEnd = Math.max(...iatRanges.map(r => r.end));
  out.put32(optional + 96 + 12 * 8, iatStart); out.put32(optional + 96 + 12 * 8 + 4, iatEnd - iatStart);
  for (const [i, s] of streams.entries()) {
    const h = table + 40 * i;
    output.set(text.encode(`.fsg${i}`), h);
    out.put32(h + 8, s.virtualSize); out.put32(h + 12, s.rva);
    out.put32(h + 16, s.rawSize); out.put32(h + 20, s.rawOffset); out.put32(h + 36, 0xe0000060);
    output.set(s.content, s.rawOffset);
  }
  const ih = table + 40 * streams.length;
  if (resourceSize) {
    output.set(text.encode('.rsrc'), ih);
    out.put32(ih + 8, resourceSize); out.put32(ih + 12, source.rva);
    out.put32(ih + 16, resourceRawSize); out.put32(ih + 20, resourceRawOffset); out.put32(ih + 36, 0x40000040);
    output.set(sourceRaw.subarray(0, resourceSize), resourceRawOffset);
  }
  const ih2 = ih + (resourceSize ? 40 : 0);
  output.set(text.encode('.idata'), ih2);
  out.put32(ih2 + 8, importSize); out.put32(ih2 + 12, importRva);
    out.put32(ih2 + 16, importRawSize); out.put32(ih2 + 20, importRawOffset); out.put32(ih2 + 36, 0xC0000040);
  output.set(importBytes, importRawOffset);
  for (const r of iatRanges) {
    const offset = r.host.rawOffset + (r.start - r.host.rva);
    for (const [j, fn] of r.module.functions.entries()) out.put32(offset + j * 4, importRva + fn.nameOffset);
    out.put32(offset + r.module.functions.length * 4, 0);
  }
  const validated = parsePE(output, MAX_OUTPUT);
  requireThat(validated.warnings.length === 0 && validated.entryPointOffset !== null, 'output-validation-failed');
  requireThat(validated.imports.length === modules.length && validated.imports.every((m, i) =>
    m.name.toLowerCase() === modules[i].dll.toLowerCase() && m.functions.length === modules[i].functions.length &&
    m.functions.every((f, j) => f.name === modules[i].functions[j].name)), 'output-validation-failed');
  return { bytes: output, metadata: {
    engine: FSG_ENGINE.id, variant: plan.variant, outputKind: 'rebuilt-pe', runtimeVerified: true,
    acceptance: 'both rebuilt fixtures (1.31/1.33) showed golden-identical windows on Henglie\'s machine (2026-10-05)',
    originalEntryPoint, importedModules: modules.length, resourcesRestored: Boolean(resourceSize), tlsRestored: Boolean(tlsBytes),
    warnings: ['relocations-not-restored', 'original-headers-not-preserved',
      'section-layout-and-permissions-inferred', 'runtime-not-verified', ...pe.warnings,
      ...(pe.overlay.size ? ['overlay-not-preserved'] : []),
      ...(!tlsBytes && (pe.directories[9].rva || pe.directories[9].size) ? ['tls-not-restored'] : []),
      ...(pe.directories[4].size ? ['signature-removed'] : [])],
  } };
}
