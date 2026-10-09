// NsPack 3.x static unpacker (PE32). Layout, two-stage codec chain, import
// tail format and the E8/E9 call-redirect restorer are original findings of
// T42 static analysis (docs/research/nspack-implementation.md,
// 资料/reverse/t42-nspack): no closed-source decompiled text is reproduced.
// Stage 2 reuses the project's independent LZMA1 transcription (compression/lzma.js).
import { Bytes, MAX_OUTPUT, align, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { decodeLzma1 } from '../compression/lzma.js';

export const NSPACK_ENGINE = Object.freeze({
  id: 'nspack-pe32', family: 'NsPack', catalogId: 'nspack',
  variant: '3.7 DIE entry stub; single-record LZMA1 body; flat rebuild',
  outputKind: 'analysis-pe', runtimeVerified: false,
});

// Honest capability boundary: one real packed sample (UnObSiDium.exe itself,
// the tool distributed packed with NsPack) drives every anchor below. Other
// NsPack builds (2.9/3.1/3.3/3.5/3.6 stubs, multi-record tables, the
// [ep-0x118]/[ep-0x130] header/relocation restore paths) are rejected, not guessed.
export const NSPACK_ENGINE_BOUNDARY = Object.freeze({
  sample: '资料/老旧壳脱壳工具/UnObSiDium/UnObSiDium.exe sha256 5292383439ca10f357c2fa3cc64047bbe1fcffe3ccb70ce2dfd5e66469612cda (DIE 3.7 entry pattern, .nsp0/.nsp1/.nsp2)',
  stage1: 'aPLib-family LZ grammar of stub VA 0x4fb919 (ADD DL,DL bitstream: each tag byte contributes 8 data bits MSB-first; the refill-time carry bit recycles between groups and is never a data bit) unpacks the 0x53d-byte codec blob; golden replay = Ghidra-staged artifact sha256 b1b221f80fe379b3a5d7e5fc1b8c1ea0d06afcf99d5de8f10b43a55f259417f8 (1681 bytes, consumed 0x53d exact)',
  stage2: 'record config byte IS the LZMA properties byte (lc+9*lp+45*pb); body decoded with the shared decodeLzma1, consumed must equal srclen exactly',
  redirects: 'E8/E9 restore per stub 0x4fb6dc..0x4fb730 (mode/tag/count at entry-0x133/-0x134/-0x13c; sample: mode 1, tag 5, count 1066): mode-1 value bswap24(rel>>8) is data-anchored, not instruction-verified (all 1066 patches land in-body at 323 distinct sub-64KB targets, 18.7% push prologues vs 0.0% for a +0x50000 control shift); the 66-prefixed SHR AX,8 trace stays unresolved; mode-0 value bswap32 is instruction-verified (86c4 c1c010 86c4) but not sample-exercised',
  imports: 'rebuilt from the decompressed-tail walk records (size/nameoff/iatrva/namearea/lengths) into a synthesized .idata; original IAT RVAs preserved',
  notRestored: 'original section table (flat body emit), relocations, TLS/debug/load-config, overlay; never executed (runtimeVerified false)',
});

// DIE db/PE/packer_NsPack.2.sg "3.7" direct-entry pattern.
const STUB_37 = '9c60e8..........83....8d8d........8039..0f..........c601..8bc5';
const STUB_END = 0x277;            // entry..entry+0x277 is this stub build
const OEP_JUMP_AT = 0x272;         // e9 <oep rel32> at entry+0x272
const TABLE_PTR_AT = -0x184;       // u32: record table offset from entry
const DELTA_STORE_AT = -0x174;     // u32: link-time entry RVA (delta = ImageBase)
const FIXER_COUNT_AT = -0x13c;     // u32: E8/E9 redirect count
const FIXER_TAG_AT = -0x134;       // u8: redirect low-byte tag
const FIXER_MODE_AT = -0x133;      // u8: 0 = bswap mode, 1 = (rel>>8) mode
const HEADER_PATCH_FLAG_AT = -0x118; // u8: runtime dd patch path (unsupported here)
const RELOC_WALK_AT = -0x130;      // u32 size at +8 of that struct (unsupported here)
const BODY_DEST_AT = -0x100;       // u32: decompression dest RVA (== .nsp0 rva)
const WALK_BASE_AT = -0x17c;       // u32: import walk records RVA (inside body)
const NAMES_BASE_DELTA = 0xe6e;    // dll-name base = ep_rva - 0xe6e (inside body)
const MAX_RECORDS = 64, MAX_FUNCTIONS_PER_RECORD = 4096, MAX_NAME = 512;

export function supportsNsPack(bytes, pe) {
  if (!(bytes instanceof Uint8Array) || !pe) return false;
  if (pe.machine !== 0x14c || pe.is64 || pe.isNet || pe.isDll || pe.entryPointOffset === null) return false;
  const names = pe.sections.map(s => s.name);
  if (names.length !== 3 || names[0] !== '.nsp0' || names[1] !== '.nsp1' || names[2] !== '.nsp2') return false;
  if (!matchHex(bytes, pe.entryPointOffset, STUB_37)) return false;
  const ep = pe.entryPointOffset, rva = pe.entryPointRva;
  if (ep + STUB_END > bytes.length || bytes[ep + OEP_JUMP_AT] !== 0xe9) return false;
  const input = new Bytes(bytes);
  if (input.u32(ep + DELTA_STORE_AT) !== rva) return false;
  const destRva = input.u32(ep + BODY_DEST_AT);
  if (destRva !== pe.sections[0].rva) return false;
  if (input.u8(ep + FIXER_MODE_AT) > 1) return false;
  return true;
}

// Stage-1 codec-blob decoder: instruction-level replay of the stub routine at
// VA 0x4fb919. Bit source = ADD DL,DL semantics: each tag byte yields its 8
// bits MSB-first; the bit carried out at refill time is re-stashed as the new
// group's tail and never surfaces as a data bit. Tokens:
//   0        literal
//   10 g     g==2: repeat last offset, len gamma
//            g>=3: offset (g-3)*256+byte (new last), len gamma, +2 if offset
//                  <=0x7f or >=0x7d00, +1 if 0x500<=offset<0x7d00
//   110 b    offset b>>1 (0 = end), len 2+(b&1), updates last
//   111 n    4-bit nibble n: 0 -> literal 0x00, else offset n len 1 (last untouched)
// gamma: v=1; do { v=v*2+bit } while(bit())
export function decodeNsPackBlob(input, maxOutput) {
  requireThat(input instanceof Uint8Array && input.length > 0, 'invalid-input');
  requireThat(Number.isInteger(maxOutput) && maxOutput > 0 && maxOutput <= MAX_OUTPUT, 'invalid-output-limit');
  const out = new Uint8Array(maxOutput);
  let written = 0, source = 0, tag = 0x80, last = 0;
  const byte = () => { requireThat(source < input.length, 'truncated-input'); return input[source++]; };
  const bit = () => {
    const value = tag >>> 7;
    tag = (tag << 1) & 0xff;
    if (tag === 0) { const fresh = byte(); tag = ((fresh << 1) | value) & 0xff; return fresh >>> 7; }
    return value;
  };
  const gamma = () => {
    let value = 1;
    for (;;) {
      value = value * 2 + bit();
      requireThat(value <= MAX_OUTPUT + 2, 'nspack-integer-overflow');
      if (!bit()) return value;
    }
  };
  const emit = v => { requireThat(written < maxOutput, 'output-limit'); out[written++] = v; };
  const copy = (distance, length) => {
    requireThat(distance > 0 && distance <= written, 'invalid-back-reference');
    requireThat(length <= maxOutput - written, 'output-limit');
    for (let i = 0; i < length; i++, written++) out[written] = out[written - distance];
  };
  emit(byte());
  for (;;) {
    if (!bit()) { emit(byte()); continue; }
    if (!bit()) {
      const lead = gamma();
      requireThat(lead >= 2, 'invalid-nspack-stream');
      if (lead === 2) { copy(last, gamma()); continue; }
      const distance = (lead - 3) * 0x100 + byte();
      last = distance;
      let length = gamma();
      if (distance <= 0x7f || distance >= 0x7d00) length += 2;
      else if (distance >= 0x500) length += 1;
      copy(distance, length);
      continue;
    }
    if (!bit()) {
      const control = byte(), distance = control >>> 1;
      if (distance === 0) return { bytes: out.slice(0, written), consumed: source };
      last = distance;
      copy(distance, 2 + (control & 1));
      continue;
    }
    let nibble = 0x10;
    for (;;) {
      const shifted = nibble >>> 7;
      nibble = ((nibble << 1) | bit()) & 0xff;
      if (shifted) break;
    }
    if (nibble === 0) emit(0); else copy(nibble, 1);
  }
}

// E8/E9 call-redirect restorer over the decompressed body (stub routine at
// VA 0x4fb6dc..0x4fb730; fixer struct at entry-0x144: body ptr, count at +8,
// tag at +0x10, mode at +0x11). Mode 1 patches only rel32 whose low byte
// equals the tag, with value bswap24(rel>>8); mode 0 patches every e8/e9
// with value bswap32(rel). Mode 0 is a direct instruction transcription
// (XCHG AH,AL; ROL EAX,16; XCHG AH,AL); mode 1 is data-anchored: the
// 66-prefixed SHR AX,8 in the listing does not reconcile with the packed
// encoding under strict zero-extension semantics, so the implemented value
// is the one validated on the sample (see NSPACK_ENGINE_BOUNDARY).
// new rel = value - rel32_va + scan_base. A chained e8/e9 byte right after
// a patched rel32 is consumed from the same count budget (LOOP 0x4fb6f6).
export function restoreNsPackRedirects(body, bodyRva, { count, tag, mode }) {
  requireThat(body instanceof Uint8Array && body.length > 5, 'invalid-input');
  requireThat(Number.isInteger(count) && count > 0 && count <= body.length, 'invalid-nspack-redirect-count');
  requireThat(mode === 0 || mode === 1, 'invalid-input');
  const reader = new Bytes(body);
  const decode = rel => mode
    ? (((rel >>> 8 & 0xff) << 16) | ((rel >>> 16 & 0xff) << 8) | (rel >>> 24)) >>> 0
    : (((rel & 0xff) << 24) | ((rel & 0xff00) << 8) | ((rel >>> 8) & 0xff00) | (rel >>> 24)) >>> 0;
  const patched = [];
  let at = 0, remaining = count;
  while (remaining > 0) {
    const opcode = reader.u8(at++);
    if ((opcode - 0xe8) >>> 0 > 1) continue;
    let rel = reader.u32(at);
    if (mode === 1 && (rel & 0xff) !== tag) continue;
    const rel32Rva = bodyRva + at;
    reader.put32(at, (decode(rel) - rel32Rva + bodyRva) >>> 0);
    patched.push({ at, rva: rel32Rva });
    at += 5;
    remaining--;
    if ((reader.u8(at - 1) - 0xe8) >>> 0 <= 1) {
      // chained e8/e9: the next rel32 is patched without rescanning
      while (remaining > 0) {
        rel = reader.u32(at);
        if (mode === 1 && (rel & 0xff) !== tag) { at++; break; }
        const chainedRva = bodyRva + at;
        reader.put32(at, (decode(rel) - chainedRva + bodyRva) >>> 0);
        patched.push({ at, rva: chainedRva });
        at += 5;
        remaining--;
        if ((reader.u8(at - 1) - 0xe8) >>> 0 > 1) break;
      }
    }
  }
  return { patched };
}

// Import walk over the decompressed tail: records {size, dllNameOff, iatRva,
// nameAreaOff, length bytes...0}. Names are unseparated concatenations; the
// k-th name spans nameArea + sum(previous lengths), length bytes each.
// 0xff first byte = ordinal (dword at +1, high bit cleared).
export function parseNsPackImportWalk(body, bodyRva, walkRva, namesRva) {
  requireThat(body instanceof Uint8Array, 'invalid-input');
  const walkOff = walkRva - bodyRva, namesOff = namesRva - bodyRva;
  const reader = new Bytes(body);
  requireThat(walkOff >= 0 && walkOff + 12 <= body.length, 'invalid-nspack-import-walk');
  requireThat(namesOff >= 0 && namesOff < body.length, 'invalid-nspack-import-walk');
  const modules = [];
  let at = walkOff;
  for (let index = 0; index < MAX_RECORDS; index++) {
    if (reader.u32(at) === 0 && reader.u32(at + 4) === 0 && reader.u32(at + 8) === 0) return { modules, endOffset: at };
    const size = reader.u32(at);
    const dllOff = reader.u32(at + 4);
    const iatRva = reader.u32(at + 8);
    const nameAreaOff = reader.u32(at + 12);
    requireThat(size >= 0x12 && at + size <= body.length, 'invalid-nspack-import-walk');
    const dllAt = namesOff + dllOff;
    const dll = reader.cstring(dllAt);
    requireThat(dll.length >= 4 && /^[ -~]{4,}$/.test(dll), 'invalid-nspack-import-walk');
    const functions = [];
    let cursor = at + 0x10, nameAt = at + nameAreaOff;
    for (let f = 0; f < MAX_FUNCTIONS_PER_RECORD; f++) {
      const length = reader.u8(cursor++);
      if (length === 0) break;
      requireThat(length >= 2 && length <= MAX_NAME, 'invalid-nspack-import-walk');
      requireThat(nameAt >= 0 && nameAt + length <= body.length, 'invalid-nspack-import-walk');
      if (body[nameAt] === 0xff) {
        functions.push({ ordinal: reader.u32(nameAt + 1) & 0x7fffffff, length: 5 });
      } else {
        const name = String.fromCharCode(...body.subarray(nameAt, nameAt + length));
        requireThat(/^[!-~]+$/.test(name), 'invalid-nspack-import-walk');
        functions.push({ name, length });
      }
      nameAt += length;
    }
    requireThat(functions.length > 0 && size === 0x11 + functions.length, 'invalid-nspack-import-walk');
    modules.push({ dll, iatRva, functions });
    at += size;
    requireThat(at <= body.length, 'invalid-nspack-import-walk');
  }
  requireThat(false, 'invalid-nspack-import-walk');
}

function buildImportDirectory(modules, sectionRva, fileAlignment) {
  // layout: descriptors | dll names | INT arrays | hint/name entries
  let cursor = (modules.length + 1) * 20;
  const plans = modules.map(module => {
    const dllAt = cursor; cursor += module.dll.length + 1;
    const intAt = cursor; cursor += (module.functions.length + 1) * 4;
    const thunks = module.functions.map(fn => {
      if (fn.ordinal !== undefined) return { ordinal: fn.ordinal };
      const at = cursor; cursor += 2 + fn.name.length + 1;
      return { name: fn.name, at };
    });
    return { module, dllAt, intAt, thunks };
  });
  const rawSize = align(cursor, fileAlignment);
  const bytes = new Uint8Array(rawSize), out = new Bytes(bytes);
  plans.forEach((plan, index) => {
    const at = index * 20;
    out.put32(at + 0, sectionRva + plan.intAt);            // OriginalFirstThunk (INT)
    out.put32(at + 3 * 4, sectionRva + plan.dllAt);        // Name
    out.put32(at + 4 * 4, plan.module.iatRva);             // FirstThunk (original IAT RVA)
    bytes.set(new TextEncoder().encode(plan.module.dll), plan.dllAt);
    plan.thunks.forEach((thunk, i) => out.put32(plan.intAt + i * 4,
      thunk.ordinal !== undefined ? (0x80000000 | thunk.ordinal) >>> 0 : sectionRva + thunk.at));
  });
  plans.forEach(plan => plan.thunks.forEach(thunk => {
    if (thunk.name === undefined) return;
    bytes.set(new TextEncoder().encode(thunk.name), thunk.at + 2);
  }));
  return { bytes, size: rawSize };
}

export function unpackNsPack(bytes) {
  const pe = parsePE(bytes);
  requireThat(supportsNsPack(bytes, pe), 'unsupported-variant');
  requireThat(pe.warnings.length === 0, 'ambiguous-pe', { warnings: pe.warnings });
  const input = new Bytes(bytes), ep = pe.entryPointOffset, rva = pe.entryPointRva;
  const [nsp0, nsp1] = pe.sections;
  requireThat(nsp0.rawSize === 0 && nsp1.rawSize > 0 && pe.sections[2].rawSize === 0, 'unsupported-variant');
  requireThat(rva >= nsp1.rva && rva < nsp1.rva + Math.max(nsp1.virtualSize, nsp1.rawSize), 'unsupported-variant');
  // Unsupported stub paths for this build: the runtime header-dd patch runs
  // only when the [ep-0x118] flag is exactly 1, and the [ep-0x130] relocation
  // walker only with a non-zero size; both must be disabled as in the sample.
  requireThat(input.u8(ep + HEADER_PATCH_FLAG_AT) !== 1, 'unsupported-variant');
  requireThat(input.u32(ep + RELOC_WALK_AT + 8) === 0, 'unsupported-variant');

  // Record table: dword 0 at table start selects the single-record form.
  const tableRva = rva + input.i32(ep + TABLE_PTR_AT);
  const tableOffset = pe.rvaToOffset(tableRva, 12);
  requireThat(tableOffset !== null, 'invalid-nspack-table');
  requireThat(input.u32(tableOffset) === 0, 'unsupported-variant');
  const recordAt = tableOffset + 4;
  const config = input.u8(recordAt);
  const lc = config % 9, lp = Math.floor(config / 9) % 5, pb = Math.floor(config / 45);
  requireThat(config < 0xe1 && lc + lp <= 4, 'unsupported-variant');
  const srcLen = input.u32(recordAt + 5);
  const destLen = input.u32(recordAt + 9);
  const destRva = input.u32(ep + BODY_DEST_AT);
  requireThat(destLen > 0 && destLen <= MAX_OUTPUT && destLen === nsp0.virtualSize, 'invalid-nspack-record');
  requireThat(destRva === nsp0.rva, 'invalid-nspack-record');
  const dataAt = recordAt + 0xd;
  requireThat(srcLen > 0 && dataAt + srcLen <= nsp1.rawOffset + nsp1.rawSize, 'truncated-nspack-record');
  const decoded = decodeLzma1(bytes.subarray(dataAt, dataAt + srcLen), destLen, { props: config, dictionarySize: destLen });
  requireThat(decoded.consumed === srcLen, 'decoded-size-mismatch');
  const body = decoded.bytes;

  // E8/E9 call-redirect restore over the decompressed body.
  const fixer = { count: input.u32(ep + FIXER_COUNT_AT), tag: input.u8(ep + FIXER_TAG_AT), mode: input.u8(ep + FIXER_MODE_AT) };
  requireThat(fixer.count > 0 && fixer.count <= body.length, 'invalid-nspack-redirect-count');
  const { patched } = restoreNsPackRedirects(body, destRva, fixer);
  for (const site of patched) {
    const target = destRva + site.at + 4 + new Bytes(body).i32(site.at);
    requireThat(target >= destRva && target < destRva + destLen, 'invalid-nspack-redirect-target');
  }

  // Original entry point: the stub's final JMP at entry+0x272.
  const oep = rva + OEP_JUMP_AT + 5 + input.i32(ep + OEP_JUMP_AT + 1);
  requireThat(oep >= destRva && oep < destRva + destLen, 'invalid-original-entry');

  // Import walk over the decompressed tail.
  const walkRva = input.u32(ep + WALK_BASE_AT);
  const namesRva = rva - NAMES_BASE_DELTA;
  const { modules } = parseNsPackImportWalk(body, destRva, walkRva, namesRva);
  const slots = [];
  for (const module of modules) {
    const end = module.iatRva + module.functions.length * 4;
    requireThat(module.iatRva >= destRva && end <= destRva + destLen, 'invalid-nspack-import-walk');
    for (const used of slots) requireThat(module.iatRva >= used.end || end <= used.start, 'invalid-nspack-import-walk');
    slots.push({ start: module.iatRva, end });
  }

  // Resource directory of the packed header stays at its original RVA.
  const resource = pe.directories[2];
  const carryResource = Boolean(resource?.rva && resource.size);
  let resourceRaw = null;
  if (carryResource) {
    const at = pe.rvaToOffset(resource.rva, resource.size);
    requireThat(at !== null && resource.rva >= nsp1.rva, 'invalid-nspack-resource');
    resourceRaw = { raw: bytes.slice(at, at + resource.size) };
  }

  // Output assembly: flat body + carried resources + synthesized imports.
  const headerSize = align(pe.sectionTable + 3 * 40, pe.fileAlignment);
  const bodyRaw = align(destLen, pe.fileAlignment);
  const rsrcRva = align(destRva + destLen, pe.sectionAlignment);
  const rsrcRaw = align(resourceRaw?.raw.length ?? 0, pe.fileAlignment);
  const importRva = align(rsrcRva + (carryResource ? rsrcRaw : 0), pe.sectionAlignment);
  const imports = buildImportDirectory(modules, importRva, pe.fileAlignment);
  const outputSize = headerSize + bodyRaw + rsrcRaw + imports.size;
  requireThat(outputSize <= MAX_OUTPUT, 'output-size-limit');
  const output = new Uint8Array(outputSize), out = new Bytes(output);
  output.set(bytes.subarray(0, pe.sectionTable));
  out.put16(pe.peOffset + 6, 3); out.put32(pe.peOffset + 12, 0); out.put32(pe.peOffset + 16, 0);
  out.put32(pe.optionalOffset + 16, oep);
  out.put32(pe.optionalOffset + 56, align(importRva + imports.size, pe.sectionAlignment));
  out.put32(pe.optionalOffset + 60, headerSize);
  output.fill(0, pe.directoryOffset, pe.directoryOffset + 128);
  out.put32(pe.directoryOffset + 8, importRva); out.put32(pe.directoryOffset + 12, imports.size);
  if (carryResource) { out.put32(pe.directoryOffset + 16, resource.rva); out.put32(pe.directoryOffset + 20, resource.size); }
  const iatStart = Math.min(...modules.map(m => m.iatRva));
  const iatEnd = Math.max(...modules.map(m => m.iatRva + m.functions.length * 4));
  out.put32(pe.directoryOffset + 12 * 8, iatStart); out.put32(pe.directoryOffset + 12 * 8 + 4, iatEnd - iatStart);
  const sections = [
    { name: '.nspbody', rva: destRva, virtualSize: destLen, rawSize: bodyRaw, rawOffset: headerSize, flags: 0xe0000060 },
    ...((carryResource ? [{ name: '.rsrc', rva: resource.rva, virtualSize: resource.size, rawSize: rsrcRaw,
      rawOffset: headerSize + bodyRaw, flags: 0x40000040 }] : [])),
    { name: '.idata', rva: importRva, virtualSize: imports.size, rawSize: imports.size,
      rawOffset: headerSize + bodyRaw + rsrcRaw, flags: 0xc0000040 },
  ];
  sections.forEach((s, i) => {
    const at = pe.sectionTable + i * 40;
    output.set(new TextEncoder().encode(s.name), at);
    out.put32(at + 8, s.virtualSize); out.put32(at + 12, s.rva); out.put32(at + 16, s.rawSize);
    out.put32(at + 20, s.rawOffset); out.put32(at + 36, s.flags);
  });
  output.set(body, headerSize);
  if (carryResource) output.set(resourceRaw.raw, headerSize + bodyRaw);
  output.set(imports.bytes, headerSize + bodyRaw + rsrcRaw);

  const validated = parsePE(output, MAX_OUTPUT);
  requireThat(validated.warnings.length === 0 && validated.entryPointOffset !== null &&
    validated.imports.length === modules.length &&
    validated.imports.every((m, i) => m.name.toLowerCase() === modules[i].dll.toLowerCase() &&
      m.functions.length === modules[i].functions.length) &&
    sections.every(s => s.rawOffset + s.rawSize <= output.length), 'output-validation-failed');

  return { bytes: output, metadata: {
    engine: NSPACK_ENGINE.id, variant: NSPACK_ENGINE.variant,
    outputKind: 'analysis-pe', runtimeVerified: false,
    originalEntryPoint: oep, importedModules: modules.length,
    importedFunctions: modules.reduce((n, m) => n + m.functions.length, 0),
    lzmaProperties: `lc=${lc} lp=${lp} pb=${pb}`, decompressedSize: destLen, compressedSize: srcLen,
    restoredRedirects: patched.length,
    unrestoredMetadata: ['original-section-layout', 'base-relocation-directory', 'debug-directory',
      'load-configuration', 'bound-imports', 'certificates', 'overlay'],
    warnings: ['runtime-not-verified', 'analysis-only-not-runnable', 'fixed-image-base',
      'original-section-table-not-recovered', 'flat-body-emit', 'e8e9-call-redirect-restored',
      'imports-rebuilt-from-tail-records', ...(carryResource ? ['resources-carried-at-original-rva'] : [])],
  } };
}
