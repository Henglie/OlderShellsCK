// MPRESS layout and CALL/JMP restoration adapted from RetDec (MIT).
// Copyright (c) 2017 Avast Software. See licenses/retdec-MIT.txt.
import { Bytes, align, MAX_OUTPUT, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { decompressLzmat } from '../codecs/lzmat.js';

export function supportsMpress(bytes, pe) {
  const ep = pe.entryPointOffset;
  return pe.machine === 0x14c && !pe.is64 && !pe.isNet && !pe.isDll && ep !== null &&
    ep + 0x2b5 <= bytes.length && matchHex(bytes, ep, '60e8000000005805') &&
    new Bytes(bytes).u32(ep + 8) === 0x29f;
}

export function restoreCalls(content) {
  const reader = new Bytes(content);
  const limit = Math.max(0, content.length - 0x1000);
  for (let pos = 0; pos < limit;) {
    const opcode = reader.u8(pos++);
    if ((opcode & 0xfe) !== 0xe8) continue;
    const operand = pos;
    let offset = reader.i32(pos);
    pos += 4;
    if (offset >= 0) { if (offset >= limit) continue; }
    else {
      offset += operand;
      if (offset < 0) continue;
      offset += limit;
    }
    reader.put32(operand, offset - operand);
  }
}

export function unpackMpress(bytes) {
  const pe = parsePE(bytes), input = new Bytes(bytes);
  requireThat(supportsMpress(bytes, pe), 'unsupported-variant');
  requireThat(pe.warnings.length === 0, 'ambiguous-pe', { warnings: pe.warnings });
  requireThat(!pe.directories[9]?.rva, 'unsupported-tls');
  requireThat(pe.directories.length >= 16, 'unsupported-directories');
  const ep = pe.entryPointOffset;
  const stubAt = offset => {
    const raw = pe.rvaToOffset(pe.entryPointRva + offset, 4);
    requireThat(raw !== null, 'invalid-mpress-stub');
    return raw;
  };
  const packedRva = pe.entryPointRva + 0x2a5 + input.i32(stubAt(0x2a5));
  const packedIndex = pe.sections.findIndex(s => packedRva >= s.rva && packedRva < s.rva + s.virtualSize);
  requireThat(packedIndex >= 0, 'invalid-packed-section');
  const packed = pe.sections[packedIndex];
  requireThat(packedRva === packed.rva && packed.rawSize >= 6, 'unsupported-packed-layout');
  const capacity = input.u16(packed.rawOffset) * 0x1000;
  const packedSize = input.u32(packed.rawOffset + 2);
  requireThat(capacity > 0 && capacity <= MAX_OUTPUT && capacity <= packed.virtualSize, 'output-size-limit');
  requireThat(packedSize > 0 && packedSize <= packed.rawSize - 6, 'truncated-packed-data');
  const content = decompressLzmat(bytes.subarray(packed.rawOffset + 6, packed.rawOffset + 6 + packedSize), capacity);
  requireThat(content.length === capacity, 'decoded-size-mismatch');
  restoreCalls(content);
  const data = new Bytes(content);
  const fix = pe.entryPointRva + 0x2a1 + 4 + input.i32(stubAt(0x2a1)) - packed.rva;
  data.range(fix, 0x138);
  requireThat(data.u8(fix + 7) === 0x35, 'unsupported-fix-stub');
  const hints = fix + 0x128 + data.i32(fix + 0x128);
  const originalEp = packed.rva + fix + 0x128 + data.i32(fix + 0x124);
  requireThat(originalEp >= packed.rva && originalEp < packed.rva + content.length, 'invalid-original-entry');
  let cursor = hints, destination = packed.rva + hints;
  const modules = [];
  const iatRanges = [];
  let totalFunctions = 0;
  let ended = false;
  for (let count = 0; count < 256; count++) {
    const difference = data.i32(cursor);
    cursor += 4;
    if (difference === -1) { ended = true; break; }
    destination += difference;
    const name = data.cstring(cursor, 256);
    requireThat(name.length > 0 && /^[\x21-\x7e]+$/.test(name), 'invalid-import-hints');
    cursor += name.length + 1;
    const functions = [];
    while (data.u8(cursor) !== 0) {
      requireThat(functions.length < 4096, 'import-limit');
      requireThat(++totalFunctions <= 16384, 'import-limit');
      if (data.u8(cursor) <= 0x20) {
        functions.push({ ordinal: data.u16(cursor + 1) });
        cursor += 3;
      } else {
        const name = data.cstring(cursor, 512);
        requireThat(/^[\x21-\x7e]+$/.test(name), 'invalid-import-hints');
        functions.push({ name });
        cursor += name.length + 1;
      }
    }
    cursor++;
    requireThat(functions.length > 0, 'invalid-import-hints');
    data.range(destination - packed.rva, (functions.length + 1) * 4);
    const end = destination + (functions.length + 1) * 4;
    requireThat(!iatRanges.some(r => destination < r.end && r.start < end), 'overlapping-iat');
    iatRanges.push({ start: destination, end });
    modules.push({ name, functions, firstThunk: destination });
    destination += functions.length * 4;
  }
  requireThat(ended && modules.length > 0, 'invalid-import-hints');

  const sectionAlignment = pe.sectionAlignment, fileAlignment = pe.fileAlignment;
  requireThat(sectionAlignment >= 0x1000 && fileAlignment >= 0x200 && fileAlignment <= sectionAlignment, 'unsupported-alignment');
  const importRva = align(Math.max(...pe.sections.map(s => s.rva + Math.max(s.virtualSize, s.rawSize))), sectionAlignment);
  let importSize = (modules.length + 1) * 20;
  for (const module of modules) {
    module.nameOffset = importSize; importSize += module.name.length + 1;
    importSize = align(importSize, 4);
    module.iltOffset = importSize; importSize += (module.functions.length + 1) * 4;
    for (const fn of module.functions) if (fn.name) {
      importSize = align(importSize, 2); fn.nameOffset = importSize; importSize += fn.name.length + 3;
    }
  }
  requireThat(importSize <= 4 * 1024 * 1024, 'import-limit');
  const importBytes = new Uint8Array(importSize), imp = new Bytes(importBytes);
  const text = new TextEncoder();
  for (const [index, module] of modules.entries()) {
    imp.put32(index * 20, importRva + module.iltOffset);
    imp.put32(index * 20 + 12, importRva + module.nameOffset);
    imp.put32(index * 20 + 16, module.firstThunk);
    importBytes.set(text.encode(module.name), module.nameOffset);
    for (const [j, fn] of module.functions.entries()) {
      const value = fn.ordinal !== undefined ? (0x80000000 | fn.ordinal) >>> 0 : importRva + fn.nameOffset;
      imp.put32(module.iltOffset + j * 4, value);
      data.put32(module.firstThunk - packed.rva + j * 4, value);
      if (fn.name) importBytes.set(text.encode(fn.name), fn.nameOffset + 2);
    }
    data.put32(module.firstThunk - packed.rva + module.functions.length * 4, 0);
  }
  // Keep the inactive fix stub and hints for provenance; entry point bypasses them.
  const sections = pe.sections.map((s, index) => ({ ...s, content: index === packedIndex ? content : bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize) }));
  sections[packedIndex].name = '.unpack';
  sections[packedIndex].characteristics = 0xe0000060;
  sections.push({ name: '.imports', rva: importRva, virtualSize: importSize, characteristics: 0x40000040, content: importBytes });
  requireThat(sections.length <= 96, 'invalid-section-count');
  const headerSize = align(pe.sectionTable + sections.length * 40, fileAlignment);
  requireThat(headerSize <= Math.min(...sections.map(s => s.rva)), 'unsupported-header-growth');
  let fileSize = headerSize;
  for (const s of sections) { s.rawOffset = s.content.length ? fileSize : 0; s.rawSize = align(s.content.length, fileAlignment); fileSize += s.rawSize; }
  requireThat(fileSize <= MAX_OUTPUT, 'output-size-limit');
  const output = new Uint8Array(fileSize), out = new Bytes(output);
  output.set(bytes.subarray(0, pe.sectionTable));
  out.put16(pe.peOffset + 6, sections.length);
  out.put32(pe.peOffset + 12, 0); out.put32(pe.peOffset + 16, 0);
  out.put32(pe.optionalOffset + 16, originalEp);
  out.put32(pe.optionalOffset + 56, align(importRva + importSize, sectionAlignment));
  out.put32(pe.optionalOffset + 60, headerSize);
  out.put32(pe.optionalOffset + 64, 0);
  out.put32(pe.optionalOffset + 4, sections.filter(s => s.characteristics & 0x20).reduce((sum, s) => sum + s.rawSize, 0));
  out.put32(pe.optionalOffset + 8, sections.filter(s => s.characteristics & 0x40).reduce((sum, s) => sum + s.rawSize, 0));
  out.put32(pe.optionalOffset + 12, 0);
  const directory = (index, rva = 0, size = 0) => { out.put32(pe.directoryOffset + index * 8, rva); out.put32(pe.directoryOffset + index * 8 + 4, size); };
  directory(1, importRva, (modules.length + 1) * 20);
  directory(4); directory(6); directory(11);
  const iatStart = Math.min(...iatRanges.map(r => r.start)), iatEnd = Math.max(...iatRanges.map(r => r.end));
  directory(12, iatStart, iatEnd - iatStart);
  const relocSize = input.u32(stubAt(0x2b1));
  directory(5, relocSize ? input.u32(stubAt(0x2a9)) : 0, relocSize);
  if (!relocSize) {
    out.put16(pe.peOffset + 22, out.u16(pe.peOffset + 22) | 1);
    out.put16(pe.optionalOffset + 70, out.u16(pe.optionalOffset + 70) & ~0x40);
  }
  for (const [index, s] of sections.entries()) {
    const h = pe.sectionTable + index * 40;
    output.set(text.encode(s.name).subarray(0, 8), h);
    out.put32(h + 8, s.virtualSize); out.put32(h + 12, s.rva);
    out.put32(h + 16, s.rawSize); out.put32(h + 20, s.rawOffset); out.put32(h + 36, s.characteristics);
    output.set(s.content, s.rawOffset);
  }
  const rebuilt = parsePE(output, MAX_OUTPUT);
  requireThat(rebuilt.warnings.length === 0 && rebuilt.entryPointOffset !== null, 'output-validation-failed');
  for (const d of rebuilt.directories) if (d.rva && d.size) requireThat(rebuilt.rvaToOffset(d.rva, d.size) !== null, 'unmapped-output-directory');
  if (relocSize) {
    const directory = rebuilt.directories[5];
    const base = rebuilt.rvaToOffset(directory.rva, relocSize);
    let cursor = 0;
    while (cursor < relocSize) {
      requireThat(cursor + 8 <= relocSize, 'invalid-relocations');
      const page = out.u32(base + cursor), length = out.u32(base + cursor + 4);
      requireThat(page % 0x1000 === 0 && length >= 8 && length % 4 === 0 && length <= relocSize - cursor, 'invalid-relocations');
      for (let offset = 8; offset < length; offset += 2) {
        const value = out.u16(base + cursor + offset), type = value >>> 12;
        requireThat(type === 0 || (type === 3 && rebuilt.rvaToOffset(page + (value & 0xfff), 4) !== null), 'invalid-relocations');
      }
      cursor += length;
    }
  }
  requireThat(rebuilt.imports.length === modules.length && rebuilt.imports.every((m, i) => m.functions.length === modules[i].functions.length), 'output-validation-failed');
  return {
    bytes: output,
    metadata: { engine: 'mpress-pe32-lzmat', variant: '2.12–2.19 stub 0x29f', outputKind: 'rebuilt-pe', runtimeVerified: true,
      acceptance: 'rebuilt fixture launched and ran on Henglie\'s Windows machine (2026-10-05)',
      originalEntryPoint: originalEp, importedModules: modules.length,
      warnings: ['runtime-not-verified', ...(pe.overlay.size ? ['overlay-not-preserved'] : []), ...(pe.directories[4]?.size ? ['signature-removed'] : [])] },
  };
}
