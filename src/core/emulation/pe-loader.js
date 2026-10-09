import { Bytes, align, matchHex, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { parseFsgPE } from '../unpackers/fsg.js';
import { Memory, READ, WRITE, EXECUTE } from './memory.js';
import { ShadowWin32 } from './win32.js';
import { CPU } from './cpu.js';
import { emulationLimits } from './limits.js';

/** Local normalization of the measured UPX header-slack convention only. */
export function parseEmulatedPE(bytes, limits = emulationLimits()) {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= limits.maxInput,
    'input-size-limit', { max: limits.maxInput });
  try { return parsePE(bytes, limits.maxInput); } catch (error) {
    if (error.code !== 'section-overlaps-headers') throw error;
    const b = new Bytes(bytes), nt = b.u32(0x3c), op = nt + 24, table = op + b.u16(nt + 20);
    requireThat(b.u16(nt + 4) === 0x14c && b.u16(nt + 6) === 3 && b.u16(op) === 0x10b &&
      b.u32(op + 60) === 0x1000 && b.u32(op + 32) === 0x1000 && b.u32(op + 36) === 0x200 &&
      b.u32(table + 16) === 0 && b.u32(table + 12) === 0x1000 && b.u32(table + 60) === 0x400 &&
      align(table + 120, 0x200) === 0x400, 'unsupported-emulated-header-layout');
    const ep = b.u32(op + 16), rva = b.u32(table + 52), rawSize = b.u32(table + 56);
    requireThat(ep >= rva && ep + 16 <= rva + rawSize &&
      matchHex(bytes, 0x400 + ep - rva, '60be........8dbe........57eb0b90'), 'unsupported-emulated-header-layout');
    const normalized = Uint8Array.from(bytes);
    new Bytes(normalized).put32(op + 60, 0x400);
    const pe = parsePE(normalized, limits.maxInput);
    return { ...pe, emulatedHeadersNormalized: true };
  }
}

export function validateEmulatedPE(pe, limits = emulationLimits()) {
  requireThat(pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet,
    'unsupported-emulated-pe');
  requireThat(pe.warnings.length === 0, 'ambiguous-pe', { warnings: pe.warnings });
  requireThat(!pe.directories[9]?.rva && !pe.directories[9]?.size && !pe.directories[13]?.rva && !pe.directories[13]?.size,
    'unsupported-emulated-directories');
  requireThat(pe.fileAlignment === 0x200 && pe.sectionAlignment === 0x1000, 'unsupported-alignment');
  requireThat(pe.sizeOfImage > 0 && pe.sizeOfImage % 4096 === 0 && pe.sizeOfImage <= limits.maxOutput,
    'emulation-output-limit', { max: limits.maxOutput, requested: pe.sizeOfImage });
  const base = Number(pe.imageBase);
  requireThat(Number.isInteger(base) && base % 65536 === 0 && base > 0 && base + pe.sizeOfImage <= 0x50000000,
    'unsupported-emulated-address-layout');
  requireThat(pe.sizeOfHeaders <= pe.sizeOfImage && pe.entryPointOffset !== null && pe.entryPointRva > 0,
    'invalid-emulated-entry');
  for (const section of pe.sections) {
    requireThat(section.rva % 4096 === 0 && section.rva >= align(pe.sizeOfHeaders, 4096) &&
      section.rva + Math.max(section.virtualSize, section.rawSize) <= pe.sizeOfImage, 'invalid-section-rva');
  }
  requireThat(pe.sections.some(s => (s.characteristics & 0x20000000) && pe.entryPointRva >= s.rva &&
    pe.entryPointRva < s.rva + Math.max(s.virtualSize, s.rawSize)), 'invalid-emulated-entry');
}

export function loadPE(bytes, pe, options = {}, name = 'input.exe') {
  const limits = emulationLimits(options);
  requireThat(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= limits.maxInput,
    'input-size-limit', { max: limits.maxInput });
  pe ??= parseEmulatedPE(bytes, limits);
  validateEmulatedPE(pe, limits);
  const base = Number(pe.imageBase), memory = new Memory(limits);
  const image = memory.map(base, pe.sizeOfImage, { permissions: 0, label: 'PE image', trackWrites: true });
  memory.initialize(base, bytes.subarray(0, pe.sizeOfHeaders));
  memory.protect(base, pe.sizeOfHeaders, READ);
  for (const s of pe.sections) {
    if (s.rawSize) {
      requireThat(s.rawOffset >= 0 && s.rawSize <= bytes.length - s.rawOffset, 'truncated-input');
      memory.initialize(base + s.rva, bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize));
    }
    const size = Math.max(s.virtualSize, s.rawSize);
    if (size) memory.protect(base + s.rva, size,
      (s.characteristics & 0x40000000 ? READ : 0) | (s.characteristics & 0x80000000 ? WRITE : 0) |
      (s.characteristics & 0x20000000 ? EXECUTE : 0));
  }
  const stack = memory.map(0x70000000 - limits.stackSize, limits.stackSize, { label: 'stack' });
  const win32 = new ShadowWin32(memory, { ...limits, imageBase: base, name });
  let imported = 0;
  for (const module of pe.imports) {
    const handle = win32.module(module.name);
    for (const [index, fn] of module.functions.entries()) {
      requireThat(++imported <= limits.maxApiEntries, 'emulation-api-limit');
      const rva = module.firstThunk + index * 4;
      requireThat(pe.rvaToOffset(rva, 4) !== null, 'invalid-import-thunk');
      // Loader writes are not decoder writes, even for a readonly IAT page.
      image.view.setUint32(rva, win32.resolve(handle, fn.name ?? fn.ordinal), true);
    }
  }
  const initialEsp = stack.end - 16;
  const cpu = new CPU(memory, { eip: base + pe.entryPointRva, esp: initialEsp, stack, maxSteps: limits.maxSteps, win32 });
  return { pe, base, memory, image, stack, win32, cpu, initialEsp, limits };
}

/** Analysis dump: disk raw offsets equal RVA, with a rebuilt, strictly valid section table. */
export function dumpPE(state, originalEntryPoint) {
  return finishDump(Uint8Array.from(state.image.bytes), state.pe, state.image, originalEntryPoint, state.limits);
}

function finishDump(output, pe, image, originalEntryPoint, limits) {
  requireThat(image.size <= limits.maxOutput && image.size <= MAX_OUTPUT, 'emulation-output-limit');
  const out = new Bytes(output);
  const sections = [...pe.sections].sort((a, b) => a.rva - b.rva);
  const headerSize = align(pe.sectionTable + pe.sections.length * 40, pe.fileAlignment);
  requireThat(headerSize <= sections[0].rva, 'output-validation-failed');
  let codeSize = 0, dataSize = 0;
  for (const [i, s] of sections.entries()) {
    const end = i + 1 < sections.length ? sections[i + 1].rva : image.size;
    const size = Math.min(align(Math.max(s.virtualSize, s.rawSize), pe.fileAlignment), end - s.rva);
    requireThat(size > 0 && size % pe.fileAlignment === 0, 'output-validation-failed');
    out.put32(s.headerOffset + 8, size);
    out.put32(s.headerOffset + 16, size); out.put32(s.headerOffset + 20, s.rva);
    output.fill(0, s.headerOffset + 24, s.headerOffset + 36);
    const flags = s.characteristics | (originalEntryPoint >= s.rva && originalEntryPoint < s.rva + size ? 0x20000000 : 0);
    out.put32(s.headerOffset + 36, flags);
    if (flags & 0x20000000) codeSize += size; else dataSize += size;
  }
  out.put32(pe.peOffset + 12, 0); out.put32(pe.peOffset + 16, 0);
  out.put32(pe.optionalOffset + 4, codeSize); out.put32(pe.optionalOffset + 8, dataSize);
  out.put32(pe.optionalOffset + 12, 0); out.put32(pe.optionalOffset + 16, originalEntryPoint);
  out.put32(pe.optionalOffset + 56, image.size); out.put32(pe.optionalOffset + 60, headerSize);
  out.put32(pe.optionalOffset + 64, 0);
  out.put16(pe.peOffset + 22, out.u16(pe.peOffset + 22) | 1);
  out.put16(pe.optionalOffset + 70, out.u16(pe.optionalOffset + 70) & ~0x40);
  output.fill(0, pe.directoryOffset, pe.directoryOffset + pe.directories.length * 8);
  const verified = parsePE(output, limits.maxOutput);
  requireThat(verified.warnings.length === 0 && verified.entryPointOffset !== null &&
    verified.sections.every(s => s.rawOffset === s.rva && s.rawOffset + s.rawSize <= output.length), 'output-validation-failed');
  return output;
}

function cstringAt(bytes, offset) {
  requireThat(Number.isInteger(offset) && offset >= 0 && offset < bytes.length, 'invalid-import-thunk');
  let value = '';
  while (offset < bytes.length && bytes[offset] && value.length < 512) value += String.fromCharCode(bytes[offset++]);
  requireThat(value.length > 0 && value.length < 512 && offset < bytes.length, 'invalid-import-thunk');
  return value;
}

// The vetted FSG parser (unpackers/fsg.js, read-only reuse) already enforces
// machine, alignment, the two-section layout, the plaintext stub, support
// table and OEP bounds. Here only emulation-specific layout is re-checked.
export function validateFsgEmulatedPE(pe, limits = emulationLimits(), bytes = null) {
  const base = Number(pe.imageBase);
  requireThat(Number.isInteger(base) && base % 65536 === 0 && base > 0 && base + pe.sizeOfImage <= 0x50000000,
    'unsupported-emulated-address-layout');
  requireThat(pe.sizeOfImage % 4096 === 0 && pe.sizeOfImage <= limits.maxOutput,
    'emulation-output-limit', { max: limits.maxOutput, requested: pe.sizeOfImage });
  for (const [index, d] of pe.directories.entries()) {
    if (d.rva || d.size) requireThat(index === 1 || index === 2 || index === 9,
      'unsupported-emulated-directories', { index });
  }
  // The stub resolves its own imports through the packed import directory;
  // without it the tail `call [ebx]` cannot be serviced.
  requireThat(pe.directories[1].rva > 0 && pe.rvaToOffset(pe.directories[1].rva, 20) !== null,
    'unsupported-emulated-directories');
  const tls = pe.directories[9];
  if (tls.rva) {
    const at = pe.rvaToOffset(tls.rva, 24);
    requireThat(tls.size === 24 && at !== null && bytes instanceof Uint8Array && at + 24 <= bytes.length,
      'unsupported-emulated-directories');
    // A real loader dispatches TLS callbacks before the entry point; with a
    // null callback pointer the directory is inert packed-image data.
    requireThat(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at + 16, true) === 0,
      'unsupported-emulated-directories');
  }
  requireThat(pe.sections.some(s => pe.entryPointRva >= s.rva &&
    pe.entryPointRva < s.rva + Math.max(s.virtualSize, s.rawSize)), 'invalid-emulated-entry');
}

export function parseFsgEmulatedPE(bytes, limits = emulationLimits()) {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= limits.maxInput,
    'input-size-limit', { max: limits.maxInput });
  const pe = parseFsgPE(bytes);
  validateFsgEmulatedPE(pe, limits, bytes);
  return pe;
}

export function loadFsgPE(bytes, pe, options = {}, name = 'input.exe') {
  const limits = emulationLimits(options);
  requireThat(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= limits.maxInput,
    'input-size-limit', { max: limits.maxInput });
  validateFsgEmulatedPE(pe, limits, bytes);
  const base = Number(pe.imageBase), memory = new Memory(limits);
  const image = memory.map(base, pe.sizeOfImage, { permissions: 0, label: 'PE image', trackWrites: true });
  memory.initialize(base, bytes.subarray(0, pe.sizeOfHeaders));
  memory.protect(base, pe.sizeOfHeaders, READ);
  const entry = pe.sections.find(s => pe.entryPointRva >= s.rva &&
    pe.entryPointRva < s.rva + Math.max(s.virtualSize, s.rawSize));
  for (const s of pe.sections) {
    if (s.rawSize) {
      requireThat(s.rawOffset >= 0 && s.rawSize <= bytes.length - s.rawOffset, 'truncated-input');
      memory.initialize(base + s.rva, bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize));
    }
    const size = Math.max(s.virtualSize, s.rawSize);
    if (size) memory.protect(base + s.rva, size,
      (s.characteristics & 0x40000000 ? READ : 0) | (s.characteristics & 0x80000000 ? WRITE : 0) |
      (s.characteristics & 0x20000000 ? EXECUTE : 0) | (s === entry ? EXECUTE : 0));
  }
  const win32 = new ShadowWin32(memory, { ...limits, imageBase: base, name });
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = pe.rvaToOffset(pe.directories[1].rva, 20), terminated = false;
  for (let d = 0; d <= 256 && at !== null; d++, at += 20) {
    const ilt = view.getUint32(at, true), nameRva = view.getUint32(at + 12, true), ft = view.getUint32(at + 16, true);
    if (!ilt && !nameRva && !ft) { terminated = true; break; }
    const handle = win32.module(cstringAt(bytes, pe.rvaToOffset(nameRva)));
    const list = pe.rvaToOffset(ilt || ft);
    requireThat(list !== null && pe.rvaToOffset(ft, 4) !== null, 'invalid-import-thunk');
    for (let i = 0; i <= 4096; i++) {
      const thunk = view.getUint32(list + i * 4, true);
      if (!thunk) break;
      requireThat(i < 4096, 'invalid-import-thunk');
      const api = thunk & 0x80000000 ? thunk & 0xffff : cstringAt(bytes, pe.rvaToOffset(thunk) + 2);
      // Loader writes are not decoder writes; mirror loadPE's direct image store.
      image.view.setUint32(ft + i * 4, win32.resolve(handle, api), true);
    }
  }
  requireThat(terminated, 'invalid-import-thunk');
  const stack = memory.map(0x70000000 - limits.stackSize, limits.stackSize, { label: 'stack' });
  const cpu = new CPU(memory, { eip: base + pe.entryPointRva, esp: stack.end - 16, stack, maxSteps: limits.maxSteps, win32 });
  return { pe, base, memory, image, stack, win32, cpu, initialEsp: stack.end - 16, limits };
}

// FSG 1.33 carries e_lfanew = 0x0c, which the strict output parser rejects.
// Relocate the measured headers to a fixed 0x100 and rebuild a minimal DOS
// header before the shared raw=RVA dump logic runs.
export function dumpFsgPE(state, originalEntryPoint) {
  const { pe, limits } = state;
  const output = Uint8Array.from(state.image.bytes), view = new DataView(output.buffer);
  const headerEnd = pe.sectionTable + pe.sections.length * 40;
  requireThat(0x100 + headerEnd - pe.peOffset <= Math.min(...pe.sections.map(s => s.rva)),
    'output-validation-failed');
  // Copy first: the DOS-header slate below 0x100 overlaps the old source range.
  output.copyWithin(0x100, pe.peOffset, headerEnd);
  output.fill(0, 2, 0x100);
  view.setUint16(0, 0x5a4d, true); view.setUint32(0x3c, 0x100, true);
  const shift = 0x100 - pe.peOffset;
  const cloned = { ...pe, peOffset: 0x100, optionalOffset: pe.optionalOffset + shift,
    directoryOffset: pe.directoryOffset + shift, sectionTable: pe.sectionTable + shift,
    sections: pe.sections.map(s => ({ ...s, headerOffset: s.headerOffset + shift })) };
  return finishDump(output, cloned, state.image, originalEntryPoint, limits);
}
