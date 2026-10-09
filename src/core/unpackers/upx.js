// UPX NRV/PE layout, hints and unfilter semantics adapted from RetDec (MIT).
// Copyright (c) 2017 Avast Software. See licenses/retdec-MIT.txt.
// Pinned sources and the exact, deliberately narrow accepted stub are documented in
// docs/research/upx-implementation.md. No UPX/UCL/ClamAV implementation is incorporated.
import { Bytes, align, matchHex, MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { decodeNrv } from '../codecs/nrv.js';
import { decodeLzma1 } from '../compression/lzma.js';

export const UPX_ENGINE = Object.freeze({
  id: 'upx-pe32-nrv', outputKind: 'analysis-pe', runtimeVerified: false,
  variant: 'PE32 NRV2B LE32 / short EXE stub / filter 0x26',
});

// LZMA1 branch (T44): stub, block framing and parameters recovered from a
// self-made official upx 4.2.4 --lzma sample packed from the lbop20 golden
// (tools/upx/upx.exe, manifest-recorded). Same narrow-stub philosophy as the
// NRV2B branch: only the observed decoder layout is accepted, never guessed.
// Sample SHA-256: 946f8839288ecf23... (test-results/fixtures/upx/lzma-424.upx.bin).
// The shared prefix differs from NRV2B from EP+0xC (89e5... vs 83cdff...) and
// carries the unpacked/packed sizes as push immediates at EP+0x21 and EP+0x2B.
const LZMA_DECODER = '60be........8dbe........5789e58d9c2480c1ffff31c05039dc75fb46465368........5783c3045368........5683c3045350c7030300020055575653';
const LZMA_IMPORT_OFFSET = 0xadc, LZMA_EXIT_OFFSET = 0xb24, LZMA_EXIT_JUMP_OFFSET = 0xb61;
const LZMA_BLOCK_HEADER = '1a03', LZMA_PROPS = 0x5d, LZMA_DICTIONARY = 0x30000;

// Full decoder identity from the two pinned corpus files; only the source VA and
// destination displacement are variable. This is signature data, never executed.
const DECODER = '60be........8dbe........57eb0b90' +
  '8a064688074701db75078b1e83eefc11db72edb80100000001db75078b1e83eefc11db11c001db73ef75098b1e83eefc11db73e4' +
  '31c983e803720dc1e0088a064683f0ff747489c501db75078b1e83eefc11db11c901db75078b1e83eefc11db11c97520' +
  '4101db75078b1e83eefc11db11c901db73ef75098b1e83eefc11db73e483c10281fd00f3ffff83d1018d142f83fdfc760f' +
  '8a02428807474975f7e963ffffff908b0283c204890783c70483e90477f101cfe94cffffff5e';
const FILTER = '89f7b9........8a07472ce83c0177f7803f..75f28b078a5f0466c1e808c1c01086c429f880ebe801f0890783c70588d8e2d9';
const IMPORT_STUB = '8dbe........8b0709c0743c8b5f048d8430........01f35083c708ff96........958a074708c074dc89f95748f2ae55ff96........09c07407890383c304ebe1ff96........';
const STUB_SIZE = (DECODER.length + FILTER.length + IMPORT_STUB.length) / 2;
const RELOC_STUB = '83c7048d5efc31c08a074709c074223cef771101c38b0386c4c1c01086c401f08903ebe2240fc1e010668b0783c702ebe2';
const EXIT_STUB = '8bae........8dbe00f0ffffbb0010000050546a045357ffd58d87........80207f8060287f585054505357ffd558618d4424806a0039c475fa83ec80e9........';

function stubTail(bytes, pe) {
  const start = pe.entryPointOffset + STUB_SIZE;
  const relocations = matchHex(bytes, start, RELOC_STUB);
  const exit = start + (relocations ? RELOC_STUB.length / 2 : 0), end = exit + EXIT_STUB.length / 2;
  requireThat(pe.rvaToOffset(pe.entryPointRva, end - pe.entryPointOffset) === pe.entryPointOffset &&
    matchHex(bytes, exit, EXIT_STUB), 'unsupported-upx-tail');
  return { relocations, originalEntryPoint: pe.entryPointRva + end - pe.entryPointOffset + new Bytes(bytes).i32(end - 4) };
}

// The 4.2.4 LZMA stub ends with the same shared exit frame as the NRV2B one,
// followed by a far jump whose rel32 target is the original entry point.
function lzmaStubTail(bytes, pe) {
  const ep = pe.entryPointOffset, jump = ep + LZMA_EXIT_JUMP_OFFSET;
  requireThat(pe.rvaToOffset(pe.entryPointRva, LZMA_EXIT_JUMP_OFFSET + 5) === ep &&
    matchHex(bytes, ep + LZMA_EXIT_OFFSET, EXIT_STUB) && new Bytes(bytes).u8(jump) === 0xe9, 'unsupported-upx-tail');
  return { relocations: false, originalEntryPoint: pe.entryPointRva + LZMA_EXIT_JUMP_OFFSET + 5 + new Bytes(bytes).i32(jump + 1) };
}

function knownStub(bytes, pe) {
  const ep = pe.entryPointOffset;
  return pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet && ep !== null &&
    pe.rvaToOffset(pe.entryPointRva, STUB_SIZE) === ep &&
    matchHex(bytes, ep, DECODER) && matchHex(bytes, ep + DECODER.length / 2, FILTER) &&
    matchHex(bytes, ep + (DECODER.length + FILTER.length) / 2, IMPORT_STUB) && Boolean(stubTail(bytes, pe));
}

function knownLzmaStub(bytes, pe) {
  const ep = pe.entryPointOffset;
  return pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet && ep !== null &&
    pe.rvaToOffset(pe.entryPointRva, LZMA_DECODER.length / 2) === ep &&
    matchHex(bytes, ep, LZMA_DECODER) && matchHex(bytes, ep + LZMA_IMPORT_OFFSET, IMPORT_STUB) &&
    Boolean(lzmaStubTail(bytes, pe));
}

/** Strict parser adapter for the observed UPX oversized-SizeOfHeaders convention.
 * Does not change the input or the shared parser. Exported for the main registry's
 * parse-before-detect integration. All other parse failures propagate unchanged.
 */
export function parseUpxInput(bytes) {
  try { return parsePE(bytes); } catch (error) {
    if (error.code !== 'section-overlaps-headers') throw error;
    const b = new Bytes(bytes), nt = b.u32(0x3c), op = nt + 24;
    const count = b.u16(nt + 6), table = op + b.u16(nt + 20), fa = b.u32(op + 36);
    requireThat(bytes.length <= MAX_INPUT && b.u16(nt + 4) === 0x14c && b.u16(op) === 0x10b &&
      b.u32(op + 60) === 0x1000 && b.u32(op + 32) === 0x1000 && fa === 0x200 && count === 3,
    'unsupported-upx-header-layout');
    const actualHeaders = align(table + count * 40, fa);
    requireThat(actualHeaders === 0x400 && b.u32(table + 16) === 0 && b.u32(table + 12) === 0x1000 &&
      b.u32(table + 40 + 20) === actualHeaders, 'unsupported-upx-header-layout');
    const normalized = Uint8Array.from(bytes);
    new Bytes(normalized).put32(op + 60, actualHeaders);
    const pe = parsePE(normalized);
    requireThat(pe.warnings.length === 0 && knownStub(bytes, pe), 'unsupported-upx-header-layout');
    return { ...pe, upxHeaderNormalized: true };
  }
}

/** Preliminary signature/layout check only; a true result is not a successful decode. */
export function supportsUpx(bytes, pe) {
  try {
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > MAX_INPUT) return false;
    const parsed = pe ?? parseUpxInput(bytes);
    const stub = knownStub(bytes, parsed) ? 'nrv2b' : knownLzmaStub(bytes, parsed) ? 'lzma1' : null;
    if (!stub) return false;
    const ph = readPackHeader(bytes);
    // The packheader is optional evidence (stripped layouts like lab18-01);
    // when present it must agree with the stub's decoder identity.
    if (ph) requireThat(stub === (ph.method === 2 ? 'nrv2b' : 'lzma1'), 'unsupported-upx-version');
    return true;
  } catch { return false; }
}

function readPackHeader(bytes) {
  const b = new Bytes(bytes);
  let result = null;
  for (let pos = 0; pos + 32 <= Math.min(bytes.length, 1024); pos++) {
    if (!matchHex(bytes, pos, '55505821')) continue;
    // Only the observed v13, Win32/i386 packheaders: method 2 (NRV2B LE32,
    // always filter 0x26) and 14 (LZMA1, observed only with filter 0 so far).
    const method = b.u8(pos + 6);
    requireThat(result === null && b.u8(pos + 4) === 13 && b.u8(pos + 5) === 9 && [2, 14].includes(method),
      'unsupported-upx-version');
    let checksum = 0;
    for (let i = 4; i < 31; i++) checksum += b.u8(pos + i);
    requireThat(checksum % 251 === b.u8(pos + 31), 'invalid-upx-checksum');
    requireThat(b.u8(pos + 28) === (method === 2 ? 0x26 : 0), 'unsupported-upx-filter');
    result = { offset: pos, method, unpackedSize: b.u32(pos + 16), packedSize: b.u32(pos + 20),
      unpackedAdler: b.u32(pos + 8), packedAdler: b.u32(pos + 12), parameter: b.u8(pos + 29) };
  }
  return result;
}

function adler32(bytes) {
  let a = 1, b = 0;
  for (let pos = 0; pos < bytes.length;) {
    const end = Math.min(pos + 5552, bytes.length);
    while (pos < end) { a += bytes[pos++]; b += a; }
    a %= 65521; b %= 65521;
  }
  return (b * 65536 + a) >>> 0;
}

function originalHeader(content, packed, lzma = false) {
  const b = new Bytes(content), start = b.u32(content.length - 4);
  b.range(start, 248);
  requireThat(b.u32(start) === 0x4550 && b.u16(start + 4) === 0x14c && b.u16(start + 20) === 224 &&
    b.u16(start + 24) === 0x10b && !(b.u16(start + 22) & 0x2000), 'invalid-upx-original-header');
  const count = b.u16(start + 6), op = start + 24;
  requireThat(count > 0 && count <= 96 && b.u32(op + 92) === 16 && b.u32(op + 28) === Number(packed.imageBase),
    'invalid-upx-original-header');
  const end = start + 248 + count * 40;
  b.range(start, end - start);
  requireThat(end + 4 <= content.length, 'invalid-upx-original-header');
  const directories = Array.from({ length: 16 }, (_, i) => ({ rva: b.u32(op + 96 + i * 8), size: b.u32(op + 100 + i * 8) }));
  requireThat(!directories[9].rva && !directories[14].rva && !directories[13].rva && !directories[0].rva,
    'unsupported-upx-directories');
  let extra = end, importHints = 0, relocHints = 0, bigEndian = false;
  if (directories[1].rva) { importHints = b.u32(extra); extra += 8; }
  if (directories[5].rva && directories[5].size && !(b.u16(start + 22) & 1)) {
    relocHints = b.u32(extra); bigEndian = true;
    // The accepted relocation stub explicitly byte-swaps each pointer. RetDec's
    // setRelocationsBigEndian(bool) also always sets true; the flag is not an endian oracle.
    requireThat(b.u8(extra + 4) <= 1, 'invalid-upx-relocations'); extra += 5;
  }
  // Observed extra-data layouts: fields, 0..3 alignment bytes, original-header pointer.
  requireThat(extra <= content.length - 4 && content.length - 4 - extra <= 3, 'unsupported-upx-extra-data');
  for (let i = extra; i < content.length - 4; i++) requireThat(b.u8(i) === 0, 'unsupported-upx-extra-data');
  requireThat(importHints > 0 && importHints < start && (!relocHints || (relocHints > importHints && relocHints < start)),
    'invalid-upx-hints');
  const cut = Math.min(start, importHints, relocHints || start);
  const sections = [];
  for (let i = 0; i < count; i++) {
    const s = start + 248 + i * 40, rva = b.u32(s + 12), size = Math.max(b.u32(s + 8), b.u32(s + 16));
    requireThat(size > 0 && rva >= packed.sections[0].rva && rva + size <= packed.sections[0].rva + cut &&
      !sections.some(p => rva < p.rva + p.size && p.rva < rva + size), 'invalid-upx-original-sections');
    sections.push({ rva, size, characteristics: b.u32(s + 36) });
  }
  const entryPoint = b.u32(op + 16), codeStart = b.u32(op + 20) - packed.sections[0].rva, codeSize = b.u32(op + 4);
  requireThat(sections.some(s => (s.characteristics & 0x20000000) && entryPoint >= s.rva && entryPoint < s.rva + s.size),
    'invalid-original-entry');
  // With the filter off (the only LZMA shape accepted so far) BaseOfCode has
  // no runtime meaning, so multi-section originals only need a bounded extent;
  // the NRV2B path keeps the single-section exactness its filter requires.
  requireThat((lzma ? codeStart + codeSize <= cut : codeStart === 0 && codeSize <= cut) && codeSize > 0,
    'invalid-upx-code-extent');
  return { entryPoint, codeStart, codeSize, importHints, relocHints, bigEndian, start, cut, directories };
}

function unfilter(content, size, count, parameter) {
  const b = new Bytes(content);
  requireThat(count > 0 && count <= size, 'invalid-upx-filter-count');
  let restored = 0;
  for (let pos = 0; pos < size && restored < count;) {
    const opcode = content[pos++];
    if ((opcode !== 0xe8 && opcode !== 0xe9) || content[pos] !== parameter) continue;
    requireThat(pos + 4 <= size, 'invalid-upx-filter-extent');
    const target = content[pos + 1] * 65536 + content[pos + 2] * 256 + content[pos + 3];
    b.put32(pos, target - pos);
    pos += 4; restored++;
  }
  requireThat(restored === count, 'invalid-upx-filter-count');
}

function restoreRelocations(content, header, base) {
  if (!header.relocHints) return 0;
  const b = new Bytes(content);
  let cursor = header.relocHints, address = -4, count = 0;
  for (;;) {
    requireThat(cursor < header.start, 'invalid-upx-relocations');
    let delta = b.u8(cursor++);
    if (!delta) {
      requireThat(cursor === header.start, 'invalid-upx-relocations');
      return count;
    }
    if (delta > 0xef) {
      requireThat(cursor + 2 <= header.start, 'invalid-upx-relocations');
      delta = (delta & 15) * 65536 + b.u16(cursor); cursor += 2;
    }
    requireThat(delta >= 4 && ++count <= 1048576, 'invalid-upx-relocations');
    address += delta;
    requireThat(address >= 0 && address + 4 <= header.cut, 'invalid-upx-relocations');
    const value = header.bigEndian ? b.view.getInt32(address, false) : b.i32(address);
    requireThat(value + base >= 0 && value + base <= 0xffffffff, 'invalid-upx-relocations');
    b.put32(address, value + base);
  }
}

// The third section carries the packer's uncompressed copies of the resource tree
// and its own stub relocations; the recorded directories point back into that raw
// span. Both validators are bounded structural self-checks, never executed.
function validResources(bytes, directory, auxiliary) {
  const b = new Bytes(bytes), seen = new Set();
  let entries = 0;
  requireThat(directory.rva >= auxiliary.rva && directory.size > 0 &&
    directory.size <= auxiliary.rawSize - (directory.rva - auxiliary.rva), 'invalid-upx-resources');
  const visit = offset => {
    requireThat(Number.isInteger(offset) && offset >= 0 && offset + 16 <= auxiliary.rawSize &&
      seen.size < 4096 && !seen.has(offset), 'invalid-upx-resources');
    seen.add(offset);
    const count = b.u16(auxiliary.rawOffset + offset + 12) + b.u16(auxiliary.rawOffset + offset + 14);
    entries += count;
    requireThat(count <= 4096 && entries <= 65536 && offset + 16 + count * 12 <= auxiliary.rawSize, 'invalid-upx-resources');
    for (let i = 0; i < count; i++) {
      const at = auxiliary.rawOffset + offset + 16 + i * 12, name = b.u32(at), target = b.u32(at + 4);
      if (name & 0x80000000) {
        const from = name & 0x7fffffff, length = b.u16(auxiliary.rawOffset + from);
        requireThat(length <= 1024 && from + 2 + length * 2 <= auxiliary.rawSize, 'invalid-upx-resources');
      }
      if (target & 0x80000000) visit(target & 0x7fffffff);
      else {
        requireThat(target + 16 <= auxiliary.rawSize, 'invalid-upx-resources');
        const rva = b.u32(auxiliary.rawOffset + target), size = b.u32(auxiliary.rawOffset + target + 4);
        requireThat(rva >= auxiliary.rva && size > 0 && size <= auxiliary.rawSize - (rva - auxiliary.rva), 'invalid-upx-resources');
      }
    }
  };
  visit(directory.rva - auxiliary.rva);
}

function validRelocations(bytes, directory, auxiliary) {
  const b = new Bytes(bytes), base = directory.rva - auxiliary.rva;
  requireThat(base >= 0 && directory.size >= 8 && directory.size <= auxiliary.rawSize - base, 'invalid-upx-relocations');
  for (let cursor = 0; cursor !== directory.size;) {
    requireThat(cursor + 8 <= directory.size, 'invalid-upx-relocations');
    const at = auxiliary.rawOffset + base + cursor, block = b.u32(at + 4);
    requireThat(block >= 8 && block % 4 === 0 && block <= directory.size - cursor, 'invalid-upx-relocations');
    for (let i = 8; i < block; i += 2) requireThat(b.u16(at + i) >>> 12 <= 4, 'invalid-upx-relocations');
    cursor += block;
  }
}

function attempt(task) {
  try { task(); return true; } catch (error) {
    if (error.code === 'truncated-input' || (typeof error.code === 'string' && error.code.startsWith('invalid-upx-'))) return false;
    throw error;
  }
}

function readImports(content, header, bytes, pe) {
  const b = new Bytes(content), input = new Bytes(bytes), modules = [], ranges = [];
  const directory = pe.directories[1];
  requireThat(directory?.rva && directory.size, 'invalid-upx-imports');
  const ilt = pe.rvaToOffset(directory.rva, directory.size);
  requireThat(ilt !== null, 'invalid-upx-imports');
  let cursor = header.importHints, total = 0, nameBudget = 0;
  const limit = header.relocHints || header.start;
  const string = (reader, at, end, max) => {
    const name = reader.cstring(at, Math.min(max, end - at));
    requireThat(name.length > 0 && /^[\x21-\x7e]+$/.test(name), 'invalid-upx-import-name');
    nameBudget += name.length;
    requireThat(nameBudget <= 1024 * 1024, 'import-limit');
    return name;
  };
  for (;;) {
    requireThat(cursor + 4 <= limit, 'invalid-upx-imports');
    const nameOffset = b.u32(cursor); cursor += 4;
    if (!nameOffset) break;
    requireThat(modules.length < 255 && nameOffset < directory.size && cursor + 4 <= limit, 'import-limit');
    const name = string(input, ilt + nameOffset, ilt + directory.size, 256);
    requireThat(pe.imports.some(m => m.name === name), 'invalid-upx-import-name');
    const iat = b.u32(cursor); cursor += 4;
    const functions = [];
    for (;;) {
      requireThat(cursor < limit, 'invalid-upx-imports');
      const hint = b.u8(cursor++);
      if (!hint) break;
      requireThat(++total <= 16384 && functions.length < 4095, 'import-limit');
      if (hint < 0x80) {
        const name = string(b, cursor, limit, 512); cursor += name.length + 1;
        functions.push({ name });
      } else {
        requireThat(cursor + 2 <= limit, 'invalid-upx-imports');
        functions.push({ ordinal: b.u16(cursor) }); cursor += 2;
      }
    }
    const end = iat + (functions.length + 1) * 4;
    requireThat(functions.length > 0 && iat >= header.codeSize && iat % 4 === 0 && end <= header.cut &&
      !ranges.some(r => iat < r.end && r.start < end), 'invalid-upx-iat');
    ranges.push({ start: iat, end }); modules.push({ name, functions, iat });
  }
  requireThat(modules.length > 0 && cursor === limit, 'invalid-upx-imports');
  return modules;
}

function makeImports(modules, content, rva, destinationRva) {
  let size = (modules.length + 1) * 20;
  for (const m of modules) {
    m.nameOffset = size; size += m.name.length + 1;
    m.ilt = align(size, 4); size = m.ilt + (m.functions.length + 1) * 4;
    for (const fn of m.functions) if (fn.name) { fn.offset = align(size, 2); size = fn.offset + fn.name.length + 3; }
  }
  requireThat(size <= 4 * 1024 * 1024, 'import-limit');
  const result = new Uint8Array(size), out = new Bytes(result), data = new Bytes(content), text = new TextEncoder();
  for (const [i, m] of modules.entries()) {
    out.put32(i * 20, rva + m.ilt); out.put32(i * 20 + 12, rva + m.nameOffset);
    out.put32(i * 20 + 16, destinationRva + m.iat);
    result.set(text.encode(m.name), m.nameOffset);
    for (const [j, fn] of m.functions.entries()) {
      const value = fn.name ? rva + fn.offset : (0x80000000 | fn.ordinal) >>> 0;
      out.put32(m.ilt + j * 4, value); data.put32(m.iat + j * 4, value);
      if (fn.name) result.set(text.encode(fn.name), fn.offset + 2);
    }
    data.put32(m.iat + m.functions.length * 4, 0);
  }
  return result;
}

export function unpackUpx(bytes) {
  const pe = parseUpxInput(bytes), input = new Bytes(bytes);
  requireThat(supportsUpx(bytes, pe), 'unsupported-variant');
  requireThat(pe.warnings.length === 0 && pe.directories.length === 16, 'ambiguous-pe');
  requireThat(!pe.directories[9]?.rva && !pe.directories[0]?.rva && !pe.directories[13]?.rva, 'unsupported-upx-directories');
  requireThat(pe.sectionAlignment === 0x1000 && pe.fileAlignment === 0x200, 'unsupported-alignment');
  requireThat(pe.sections.length === 3, 'unsupported-upx-layout');
  const [destination, packed, auxiliary] = pe.sections, ep = pe.entryPointOffset;
  requireThat(!destination.rawSize && destination.rva === 0x1000 && destination.virtualSize > 0 &&
    destination.rva + destination.virtualSize === packed.rva && packed.rva + packed.virtualSize === auxiliary.rva &&
    pe.entryPointRva >= packed.rva && pe.entryPointRva < packed.rva + packed.rawSize, 'unsupported-upx-layout');
  const startRva = input.u32(ep + 2) - Number(pe.imageBase);
  requireThat(startRva === packed.rva && startRva + input.i32(ep + 8) === destination.rva, 'invalid-upx-packed-address');
  const span = pe.entryPointRva - startRva, capacity = pe.entryPointRva - destination.rva;
  requireThat(span > 0 && capacity > 0 && capacity <= MAX_OUTPUT && pe.sizeOfImage <= MAX_OUTPUT, 'output-size-limit');
  const start = pe.rvaToOffset(startRva, span);
  requireThat(start !== null, 'invalid-upx-packed-extent');
  const ph = readPackHeader(bytes);
  const lzma = ph?.method === 14;
  if (ph) requireThat(ph.packedSize > 0 && ph.packedSize <= span && ph.unpackedSize > 0 && ph.unpackedSize <= capacity,
    'invalid-upx-packed-extent');
  const stream = bytes.subarray(start, start + (ph?.packedSize ?? span));
  if (ph) requireThat(adler32(stream) === ph.packedAdler, 'invalid-upx-data-checksum');
  let decoded, content;
  if (lzma) {
    // upx 4.2.4 block: two-byte framing header, then a raw LZMA1 stream whose
    // exact consumption the stub pushes as packedSize-2 (EP+0x2B).
    requireThat(matchHex(bytes, start, LZMA_BLOCK_HEADER) &&
      input.u32(ep + 0x21) === ph.unpackedSize && input.u32(ep + 0x2b) === ph.packedSize - 2, 'unsupported-upx-lzma-block');
    const result = decodeLzma1(bytes.subarray(start + 2, start + ph.packedSize), ph.unpackedSize,
      { props: LZMA_PROPS, dictionarySize: LZMA_DICTIONARY });
    requireThat(result.consumed === ph.packedSize - 2, 'invalid-upx-lzma-block');
    decoded = { bytesRead: ph.packedSize, bytes: result.bytes };
  } else {
    decoded = decodeNrv(stream, ph?.unpackedSize ?? capacity, 'NRV2B');
    requireThat(span - decoded.bytesRead >= 0 && span - decoded.bytesRead < 16, 'invalid-upx-packed-extent');
    for (let i = start + decoded.bytesRead; i < start + span; i++) requireThat(bytes[i] === 0, 'invalid-upx-padding');
  }
  content = decoded.bytes;
  if (ph) requireThat(decoded.bytesRead === ph.packedSize && decoded.bytes.length === ph.unpackedSize &&
    adler32(decoded.bytes) === ph.unpackedAdler, 'invalid-upx-data-checksum');
  const header = originalHeader(content, pe, lzma);
  const tail = lzma ? lzmaStubTail(bytes, pe) : stubTail(bytes, pe);
  requireThat(tail.relocations === Boolean(header.relocHints) && tail.originalEntryPoint === header.entryPoint,
    'invalid-upx-original-entry');
  let count = 0, parameter = 0;
  if (!lzma) {
    const filter = ep + DECODER.length / 2, importStub = filter + FILTER.length / 2;
    parameter = input.u8(filter + 18), count = input.u32(filter + 3);
    requireThat(!ph || ph.parameter === parameter, 'invalid-upx-filter');
    requireThat(input.u32(importStub + 2) === header.importHints &&
      input.u32(importStub + 18) + destination.rva === pe.directories[1].rva, 'invalid-upx-import-stub');
    unfilter(content, header.codeSize, count, parameter);
  }
  const relocatedPointers = restoreRelocations(content, header, Number(pe.imageBase) + destination.rva);
  const modules = readImports(content, header, bytes, pe);
  const importRva = align(destination.rva + header.cut, pe.sectionAlignment);
  const imports = makeImports(modules, content, importRva, destination.rva);
  const importRawSize = align(imports.length, pe.fileAlignment);
  const restored = { resource: 'absent', relocation: 'absent' }, reasons = [], records = [];
  for (const [index, name] of [[2, 'resource'], [5, 'relocation']]) {
    const directory = pe.directories[index], suffix = name === 'resource' ? 'resources' : 'relocations';
    if (!directory.rva && !directory.size) {
      if (header.directories[index].rva) { restored[name] = 'not-restored'; reasons.push(`${suffix}-not-recorded`); }
      continue;
    }
    const mapped = attempt(() => {
      requireThat(directory.rva && directory.size && directory.rva >= auxiliary.rva &&
        directory.size <= auxiliary.rawSize - (directory.rva - auxiliary.rva), `invalid-upx-${suffix}`);
      if (index === 2) validResources(bytes, directory, auxiliary); else validRelocations(bytes, directory, auxiliary);
    });
    const consistent = index !== 2 || Boolean(header.directories[2].rva);
    if (mapped && consistent) { restored[name] = 'restored'; records.push({ index, name, directory }); }
    else { restored[name] = 'not-restored'; reasons.push(`${suffix}-${consistent ? 'unrecoverable' : 'inconsistent'}`); }
  }
  if (reasons.length) {
    for (const record of records) restored[record.name] = 'not-restored';
    records.length = 0;
  }
  let carried = records.length > 0;
  if (carried && (auxiliary.rva + Math.max(auxiliary.virtualSize, auxiliary.rawSize) > 0x100000000 ||
    importRva + importRawSize > auxiliary.rva)) {
    carried = false; reasons.push('auxiliary-section-overlap');
    for (const record of records) restored[record.name] = 'not-restored';
  }
  const headerSize = align(pe.sectionTable + 80, pe.fileAlignment), rawSize = align(header.cut, pe.fileAlignment);
  // The recovered resource directory keeps its original RVA, so the carried
  // data is merged into the .imports section (two-section layout): a third
  // standalone section made some Windows loaders reject the image.
  const mergedRawSize = carried ? align(auxiliary.rva - importRva, 1) + align(auxiliary.rawSize, pe.fileAlignment) : importRawSize;
  const importsSpan = carried ? auxiliary.rva + Math.max(auxiliary.virtualSize, auxiliary.rawSize) - importRva : importRawSize;
  const outputSize = headerSize + rawSize + mergedRawSize;
  requireThat(outputSize <= MAX_OUTPUT && importRva + importRawSize <= MAX_OUTPUT, 'output-size-limit');
  const output = new Uint8Array(outputSize), out = new Bytes(output);
  output.set(bytes.subarray(0, pe.sectionTable));
  out.put16(pe.peOffset + 6, 2); out.put32(pe.peOffset + 12, 0); out.put32(pe.peOffset + 16, 0);
  out.put16(pe.peOffset + 22, out.u16(pe.peOffset + 22) | 1);
  out.put32(pe.optionalOffset + 4, rawSize); out.put32(pe.optionalOffset + 8, mergedRawSize);
  out.put32(pe.optionalOffset + 12, 0); out.put32(pe.optionalOffset + 16, header.entryPoint);
  out.put32(pe.optionalOffset + 20, destination.rva); out.put32(pe.optionalOffset + 24, importRva);
  out.put32(pe.optionalOffset + 56, align(carried
    ? Math.max(importRva + importRawSize, auxiliary.rva + Math.max(auxiliary.virtualSize, auxiliary.rawSize))
    : importRva + importRawSize, pe.sectionAlignment));
  out.put32(pe.optionalOffset + 60, headerSize); out.put32(pe.optionalOffset + 64, 0);
  out.put16(pe.optionalOffset + 70, out.u16(pe.optionalOffset + 70) & ~0x40);
  output.fill(0, pe.directoryOffset, pe.directoryOffset + 128);
  out.put32(pe.directoryOffset + 8, importRva); out.put32(pe.directoryOffset + 12, (modules.length + 1) * 20);
  const iatStart = Math.min(...modules.map(m => m.iat)), iatEnd = Math.max(...modules.map(m => m.iat + (m.functions.length + 1) * 4));
  out.put32(pe.directoryOffset + 96, destination.rva + iatStart); out.put32(pe.directoryOffset + 100, iatEnd - iatStart);
  if (carried) for (const record of records) {
    out.put32(pe.directoryOffset + record.index * 8, record.directory.rva);
    out.put32(pe.directoryOffset + record.index * 8 + 4, record.directory.size);
  }
  const sections = [
    { name: '.unpack', rva: destination.rva, virtualSize: header.cut, rawSize, rawOffset: headerSize, flags: 0xe0000060 },
    { name: '.imports', rva: importRva, virtualSize: importsSpan, rawSize: mergedRawSize, rawOffset: headerSize + rawSize, flags: 0xC0000040 },
  ];
  for (const [i, s] of sections.entries()) {
    const at = pe.sectionTable + i * 40;
    output.set(new TextEncoder().encode(s.name), at);
    out.put32(at + 8, s.virtualSize); out.put32(at + 12, s.rva); out.put32(at + 16, s.rawSize);
    out.put32(at + 20, s.rawOffset); out.put32(at + 36, s.flags);
  }
  output.set(content.subarray(0, header.cut), headerSize); output.set(imports, headerSize + rawSize);
  if (carried) output.set(bytes.subarray(auxiliary.rawOffset, auxiliary.rawOffset + auxiliary.rawSize), headerSize + rawSize + (auxiliary.rva - importRva));
  const validated = parsePE(output, MAX_OUTPUT);
  requireThat(validated.warnings.length === 0 && validated.entryPointOffset !== null && validated.imports.length === modules.length &&
    validated.imports.every((m, i) => m.name === modules[i].name && m.functions.length === modules[i].functions.length) &&
    records.every(record => !carried || validated.rvaToOffset(record.directory.rva, record.directory.size) !== null) &&
    sections.every(s => s.rawOffset + s.rawSize <= output.length),
    'output-validation-failed');
  const upgraded = reasons.length === 0;
  const unrestoredMetadata = ['original-section-layout',
    ...(restored.resource === 'not-restored' ? ['resources'] : []),
    ...(restored.relocation === 'not-restored' ? ['base-relocation-directory'] : []),
    'debug-directory', 'load-configuration', 'bound-imports', 'certificates', 'overlay'];
  return { bytes: output, metadata: {
    engine: UPX_ENGINE.id, variant: lzma ? 'PE32 LZMA1 / upx 4.2.4 stub / no filter' : UPX_ENGINE.variant,
    outputKind: upgraded ? 'rebuilt-pe' : 'analysis-pe',
    runtimeVerified: !lzma && upgraded,
    acceptance: !lzma && upgraded ? 'rebuilt lbop20 fixture ran like the official upx -d output on Henglie\'s machine (2026-10-05)' : undefined,
    originalEntryPoint: header.entryPoint, importedModules: modules.length, unrestoredMetadata, restoredDirectories: restored,
    decompressedSize: content.length, compressedSize: decoded.bytesRead, restoredCalls: count, relocatedPointers,
    warnings: [...(upgraded ? [] : ['analysis-only-not-runnable', 'unrestored-metadata-cleared', ...reasons]),
      'runtime-not-verified', 'fixed-image-base',
      ...(ph ? [] : ['packheader-absent-no-checksum']), ...(pe.upxHeaderNormalized ? ['upx-sizeofheaders-normalized'] : [])],
  } };
}
