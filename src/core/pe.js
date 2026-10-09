import { Bytes, entropy, MAX_INPUT, MAX_OUTPUT } from './bytes.js';
import { requireThat } from './errors.js';

export function parsePE(bytes, maxBytes = MAX_INPUT) {
  requireThat(bytes instanceof Uint8Array, 'invalid-input');
  requireThat(Number.isInteger(maxBytes) && maxBytes > 0 && maxBytes <= MAX_OUTPUT, 'invalid-input-limit');
  requireThat(bytes.length > 0 && bytes.length <= maxBytes, 'input-size-limit', { max: maxBytes });
  const reader = new Bytes(bytes);
  requireThat(reader.u16(0) === 0x5a4d, 'not-pe');
  const peOffset = reader.u32(0x3c);
  requireThat(peOffset >= 0x40, 'invalid-pe-header');
  requireThat(reader.u32(peOffset) === 0x4550, 'not-pe');
  const machine = reader.u16(peOffset + 4);
  const sectionCount = reader.u16(peOffset + 6);
  const optionalSize = reader.u16(peOffset + 20);
  const optionalOffset = peOffset + 24;
  reader.range(optionalOffset, optionalSize);
  const magic = reader.u16(optionalOffset);
  requireThat(magic === 0x10b || magic === 0x20b, 'unsupported-pe-magic');
  const is64 = magic === 0x20b;
  const directoryOffset = optionalOffset + (is64 ? 112 : 96);
  requireThat(optionalSize >= (is64 ? 112 : 96), 'invalid-optional-header');
  const directoryCount = reader.u32(directoryOffset - 4);
  requireThat(directoryCount <= 16 && directoryOffset + directoryCount * 8 <= optionalOffset + optionalSize, 'invalid-directories');
  requireThat(sectionCount > 0 && sectionCount <= 96, 'invalid-section-count');
  const sectionTable = optionalOffset + optionalSize;
  reader.range(sectionTable, sectionCount * 40);
  const sizeOfHeaders = reader.u32(optionalOffset + 60);
  requireThat(sizeOfHeaders >= sectionTable + sectionCount * 40 && sizeOfHeaders <= bytes.length, 'invalid-header-size');
  const sections = [];
  let imageEnd = sizeOfHeaders;
  const warnings = [];
  for (let i = 0; i < sectionCount; i++) {
    const offset = sectionTable + i * 40;
    const section = {
      name: reader.string(offset, 8), virtualSize: reader.u32(offset + 8), rva: reader.u32(offset + 12),
      rawSize: reader.u32(offset + 16), rawOffset: reader.u32(offset + 20), characteristics: reader.u32(offset + 36), headerOffset: offset,
    };
    if (section.rawSize) {
      reader.range(section.rawOffset, section.rawSize);
      requireThat(section.rawOffset >= sizeOfHeaders, 'section-overlaps-headers');
      imageEnd = Math.max(imageEnd, section.rawOffset + section.rawSize);
    }
    requireThat(section.rva + Math.max(section.virtualSize, section.rawSize) <= 0x100000000, 'invalid-section-rva');
    if (section.rva < sizeOfHeaders && Math.max(section.virtualSize, section.rawSize)) warnings.push('section-overlaps-header-rvas');
    for (const previous of sections) {
      if (section.rawSize && previous.rawSize && section.rawOffset < previous.rawOffset + previous.rawSize && previous.rawOffset < section.rawOffset + section.rawSize) warnings.push('overlapping-raw-sections');
      if (section.rva < previous.rva + Math.max(previous.virtualSize, previous.rawSize) && previous.rva < section.rva + Math.max(section.virtualSize, section.rawSize)) warnings.push('overlapping-virtual-sections');
    }
    section.entropy = entropy(bytes.subarray(section.rawOffset, section.rawOffset + section.rawSize));
    sections.push(section);
  }
  const directories = Array.from({ length: directoryCount }, (_, index) => ({ rva: reader.u32(directoryOffset + index * 8), size: reader.u32(directoryOffset + index * 8 + 4) }));
  const rvaToOffset = (rva, size = 1) => {
    if (!Number.isInteger(rva) || rva < 0 || !Number.isInteger(size) || size < 0) return null;
    const end = rva + Math.max(size, 1);
    if (end > 0x100000000) return null;
    const hits = sections.filter(s => rva < s.rva + Math.max(s.virtualSize, s.rawSize) && end > s.rva);
    if (rva < sizeOfHeaders) return hits.length === 0 && rva + size <= sizeOfHeaders ? rva : null;
    if (hits.length !== 1) return null;
    const s = hits[0], delta = rva - s.rva;
    if (delta < 0 || delta + size > s.rawSize) return null;
    return s.rawOffset + delta;
  };
  const entryPointRva = reader.u32(optionalOffset + 16);
  const entryPointOffset = rvaToOffset(entryPointRva);
  if (entryPointRva && entryPointOffset === null) warnings.push('entry-point-unmapped');
  const imports = [];
  let totalImportNames = 0, totalImportFunctions = 0;
  const mappedString = rva => {
    const offset = rvaToOffset(rva);
    requireThat(offset !== null, 'invalid-import-name');
    const value = reader.cstring(offset);
    requireThat(rvaToOffset(rva, value.length + 1) === offset, 'invalid-import-name');
    totalImportNames += value.length;
    requireThat(totalImportNames <= 1024 * 1024, 'import-limit');
    return value;
  };
  const importDir = directories[1];
  if (importDir?.rva && importDir.size) {
    try {
      let terminated = false;
      for (let i = 0; i < Math.min(256, Math.floor(importDir.size / 20)); i++) {
        const offset = rvaToOffset(importDir.rva + i * 20, 20);
        requireThat(offset !== null, 'invalid-import-table');
        const fields = Array.from({ length: 5 }, (_, j) => reader.u32(offset + j * 4));
        if (fields.every(value => value === 0)) { terminated = true; break; }
        const nameOffset = rvaToOffset(fields[3]);
        requireThat(nameOffset !== null, 'invalid-import-name');
        const module = { name: mappedString(fields[3]), firstThunk: fields[4], functions: [] };
        let thunkTerminated = false;
        for (let j = 0; j < 4096; j++) {
          const thunk = rvaToOffset((fields[0] || fields[4]) + j * (is64 ? 8 : 4), is64 ? 8 : 4);
          requireThat(thunk !== null, 'invalid-import-thunk');
          const low = reader.u32(thunk), high = is64 ? reader.u32(thunk + 4) : 0;
          if (!low && !high) { thunkTerminated = true; break; }
          requireThat(++totalImportFunctions <= 16384, 'import-limit');
          if ((is64 ? high : low) & 0x80000000) module.functions.push({ ordinal: low & 0xffff });
          else {
            requireThat(!high, 'invalid-import-thunk');
            const hint = rvaToOffset(low, 3);
            requireThat(hint !== null, 'invalid-import-thunk');
            module.functions.push({ name: mappedString(low + 2), hint: reader.u16(hint) });
          }
        }
        requireThat(thunkTerminated, 'import-limit');
        imports.push(module);
      }
      requireThat(terminated, 'import-limit');
    } catch (error) { warnings.push(error.code || 'invalid-import-table'); }
  }
  return {
    format: is64 ? 'PE32+' : 'PE32', machine, architecture: ({ 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64', 0x1c4: 'ARM' })[machine] || `0x${machine.toString(16)}`,
    is64, isDll: Boolean(reader.u16(peOffset + 22) & 0x2000), isNet: Boolean(directories[14]?.rva),
    imageBase: is64 ? `0x${reader.view.getBigUint64(optionalOffset + 24, true).toString(16)}` : `0x${reader.u32(optionalOffset + 28).toString(16)}`,
    entryPointRva, entryPointOffset, sizeOfImage: reader.u32(optionalOffset + 56), sizeOfHeaders,
    fileAlignment: reader.u32(optionalOffset + 36), sectionAlignment: reader.u32(optionalOffset + 32),
    peOffset, optionalOffset, directoryOffset, sectionTable, sections, directories, imports,
    overlay: { offset: imageEnd, size: bytes.length - imageEnd }, warnings: [...new Set(warnings)], rvaToOffset,
  };
}
