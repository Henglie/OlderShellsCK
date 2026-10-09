// Huffman/LZ format adapted from XStaticUnpacker xaspack.cpp (MIT).
// Copyright (c) 2017-2026 hors<horsicq@gmail.com>
// Revision 746fb24433c29b6460edebac83fdad19909d9e81.
// See licenses/xstaticunpacker-MIT.txt; modern layout independently byte-verified
// in docs/research/rlde-family.md. No closed-source decompilation is reused.
//
// RL!deASPack 2.x rebuild cross-evidence (docs/research/rlde-family.md §4/§12/§13a,
// private disassembly evidence 资料/reverse/mt27-rlde-aspack*): the GUI unpacker
// breakpoints the import-name loop, the DLL/API phases and the OEP hand-off —
// its probe `c2 0c 00 68` (`ret 0xc; push`) has exactly one hit in the pinned
// corpus at ep+0x434, i.e. the same instruction frame this engine anchors at
// ep+0x417. That frame encodes the OEP hand-off statically as `mov eax,<OEP>`
// (ep+0x418; the imm32 dword is a unique file occurrence on the corpus), which
// the GUI instead reads at run time. The GUI then dumps the image with
// raw=RVA/rawSize=VirtualSize and appends a `.ap0x` section rebuilt by
// Importer.dll while keeping the original IAT slots. This engine's disk
// equivalent keeps the complete decoded descriptor/ILT/name structure at its
// original RVAs (the ep437 stream still carries it, unlike FSG whose stream
// forces .idata synthesis) and restores the IAT slots from the ILT in place.
// Relocations: ASPack repoints data directory 5 at its own stub block
// (0x17fc8/8 on the corpus), which dies with the removed stub sections; the
// original table survives inside the decoded .reloc section and is recovered
// by a strict block walk (see walkRelocationSpan).
import { Bytes, MAX_INPUT, MAX_OUTPUT, align, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';

export const ASPACK_ENGINE = Object.freeze({
  id: 'aspack-pe32-huffman', family: 'aspack', catalogId: 'aspack', variants: Object.freeze(['2.x-ep437']),
  outputKind: 'analysis-pe', runtimeVerified: false, stage: 'experimental',
});

const TABLE = '0001020304050607080a0c0e1014181c202830384050607080a0c0e000000000000000000101010102020202030303030404040405050505000000000101020203030404050506060707080809090a0a0b0b0c0c0d0d0e0e0f0f101011111111111111111111111111111212121212121212';
const ANCHORS = [
  [0, '60e803000000e9eb045d4555c3e801000000eb5d'],
  [0xac, '8db5dd050000833e000f8416010000'],
  [0x107, 'e8d3050000b30080fb00754d'],
  [0x143, '803e..75f32400c1c0182bc38906'],
  [0x197, '83c60c833e000f852fffffff'],
  [0x27b, 'be........8b95a004000003f28b460c85c0'],
  [0x417, 'b8........500385a0040000590bc9898526040000617508b801000000c20c006800000000c3'],
  [0x6df, '8b44241081ec540300008d4c240450e8a8030000'],
  [0xa9b, '5356578bf933d233c08db768020000891656e8570200008a8c30........'],
  [0xad4, '68d1020000e848fdffff506a1c8d8fa0000000e83afdffff506a08'],
  [0xb7a, '81ec0c030000538bd955568d6b04576a018bcd'],
  [0xd09, 'e801000000905e81ee........c3'],
  [0xd17, '83ec148b44241c535556c70000000000'],
];

function inspect(bytes) {
  requireThat(bytes instanceof Uint8Array && bytes.length <= MAX_INPUT, 'invalid-input');
  const pe = parsePE(bytes), b = new Bytes(bytes), ep = pe.entryPointOffset;
  requireThat(pe.machine === 0x14c && !pe.is64 && !pe.isDll && !pe.isNet, 'unsupported-variant');
  requireThat(pe.warnings.length === 0, 'ambiguous-pe');
  requireThat(pe.sectionAlignment === 0x1000 && pe.fileAlignment === 0x200, 'unsupported-alignment');
  requireThat(pe.sizeOfImage > 0 && pe.sizeOfImage <= MAX_OUTPUT && pe.sizeOfImage % 0x1000 === 0, 'output-size-limit');
  const base = Number(pe.imageBase);
  requireThat(base + pe.sizeOfImage <= 0x100000000 && base % 0x10000 === 0, 'invalid-image-base');
  requireThat(pe.directories.length === 16 && !pe.directories[9].rva && !pe.directories[13].rva, 'unsupported-directories');
  const count = pe.sections.length;
  requireThat(count >= 3 && ep !== null, 'unsupported-variant');
  const stub = pe.sections[count - 2], scratch = pe.sections[count - 1];
  requireThat(pe.entryPointRva === stub.rva + 1 && scratch.rawSize === 0 && scratch.rva === stub.rva + stub.virtualSize, 'unsupported-variant');
  for (const [off, pattern] of ANCHORS) {
    requireThat(pe.rvaToOffset(pe.entryPointRva + off, pattern.length / 2) === ep + off && matchHex(bytes, ep + off, pattern), 'unsupported-variant');
  }
  requireThat(pe.rvaToOffset(pe.entryPointRva + 0x749, 114) === ep + 0x749 && matchHex(bytes, ep + 0x749, TABLE), 'unsupported-variant');
  // CALL/POP gives EBP=AEP+0x12, not AEP-1. Validate both obfuscated table
  // references by resolving their arithmetic as data (no stub execution).
  const helper = pe.entryPointRva + 0xd0e - b.u32(ep + 0xd12);
  const tableRva = (helper + b.u32(ep + 0xab5)) >>> 0;
  requireThat(tableRva === pe.entryPointRva + 0x781, 'unsupported-variant');
  const sections = pe.sections.slice(0, -2).map(s => ({ ...s }));
  for (const s of pe.sections) requireThat(s.rva >= 0x1000 && s.rva % 0x1000 === 0 &&
    s.virtualSize > 0 && s.rva + Math.max(s.rawSize, s.virtualSize) <= pe.sizeOfImage, 'invalid-section-rva');
  const originalEntryPoint = b.u32(ep + 0x418), importRva = b.u32(ep + 0x27c);
  requireThat(sections.some(s => originalEntryPoint >= s.rva && originalEntryPoint < s.rva + s.virtualSize && (s.characteristics & 0x20000000)), 'invalid-original-entry');
  const blocks = [], seen = []; let terminated = false;
  for (let i = 0; i < 96; i++) {
    const at = pe.rvaToOffset(pe.entryPointRva + 0x5ef + i * 12, 12);
    requireThat(at !== null, 'invalid-aspack-blocks');
    const rva = b.u32(at), size = b.u32(at + 4), characteristics = b.u32(at + 8);
    if (!rva) { requireThat(!size && !characteristics, 'invalid-aspack-blocks'); terminated = true; break; }
    const host = sections.find(s => rva >= s.rva && rva < s.rva + s.virtualSize);
    requireThat(host && size > 0 && size <= host.rva + host.virtualSize - rva, 'invalid-aspack-blocks');
    requireThat(!seen.some(v => rva < v.end && v.start < rva + size), 'overlapping-aspack-blocks');
    const raw = pe.rvaToOffset(rva);
    requireThat(raw !== null && (characteristics & 0x40000000) !== 0 && (characteristics & 0x000000e0) !== 0, 'invalid-aspack-blocks');
    requireThat(!blocks.some(v => v.hostRva === host.rva && v.characteristics !== characteristics), 'invalid-aspack-blocks');
    host.characteristics = characteristics;
    const available = host.rawSize - (rva - host.rva);
    blocks.push({ rva, size, raw, available, characteristics, hostRva: host.rva }); seen.push({ start: rva, end: rva + size });
  }
  requireThat(terminated && blocks.length > 0 && blocks.some(v => originalEntryPoint >= v.rva && originalEntryPoint < v.rva + v.size), 'invalid-aspack-blocks');
  return { pe, sections, blocks, originalEntryPoint, importRva, table: bytes.slice(ep + 0x749, ep + 0x749 + 114), mark: b.u8(ep + 0x145) };
}

// Canonical MSB Huffman decode with strict byte, tree, output and update budgets.
export function decodeAspackBlock(input, size, table) {
  requireThat(input instanceof Uint8Array && input.length <= MAX_INPUT, 'invalid-input');
  requireThat(Number.isInteger(size) && size > 0 && size <= MAX_OUTPUT, 'invalid-output-limit');
  requireThat(table instanceof Uint8Array && table.length === 114, 'invalid-aspack-table');
  let bitPosition = 0;
  const bits = n => {
    requireThat(n >= 0 && n <= 24 && bitPosition + n <= input.length * 8, 'truncated-input');
    let value = 0;
    for (let i = 0; i < n; i++, bitPosition++) value = value * 2 + ((input[bitPosition >>> 3] >>> (7 - (bitPosition & 7))) & 1);
    return value;
  };
  const build = lengths => {
    const counts = new Uint16Array(16), first = new Uint32Array(16), symbols = Array.from({ length: 16 }, () => []);
    for (const n of lengths) { requireThat(n <= 15, 'invalid-huffman-tree'); if (n) counts[n]++; }
    let code = 0;
    for (let n = 1; n <= 15; n++) { code = (code + counts[n - 1]) * 2; first[n] = code; requireThat(code + counts[n] <= 2 ** n, 'invalid-huffman-tree'); }
    requireThat(code + counts[15] === 32768, 'invalid-huffman-tree');
    for (let i = 0; i < lengths.length; i++) if (lengths[i]) symbols[lengths[i]].push(i);
    return { counts, first, symbols };
  };
  const symbol = t => {
    let code = 0;
    for (let n = 1; n <= 15; n++) { code = code * 2 + bits(1); const index = code - t.first[n]; if (index >= 0 && index < t.counts[n]) return t.symbols[n][index]; }
    requireThat(false, 'invalid-huffman-code');
  };
  let previous = new Uint8Array(757), dicts, special, updates = 0;
  const update = () => {
    requireThat(++updates <= 4096, 'aspack-dictionary-limit');
    if (!bits(1)) previous.fill(0);
    const meta = build(Uint8Array.from({ length: 19 }, () => bits(4))), next = new Uint8Array(757);
    for (let at = 0; at < next.length;) {
      const value = symbol(meta);
      if (value < 16) { next[at] = (previous[at] + value) & 15; at++; }
      else {
        const length = value === 16 ? bits(2) + 3 : value === 17 ? bits(3) + 3 : bits(7) + 11;
        const byte = value === 16 && at > 0 ? next[at - 1] : 0;
        const end = Math.min(next.length, at + length); next.fill(byte, at, end); at = end;
      }
    }
    dicts = [build(next.subarray(0, 721)), build(next.subarray(721, 749)), build(next.subarray(749))];
    special = next.subarray(749).some(v => v !== 3); previous = next;
  };
  const bases = []; let sum = 0;
  for (let i = 0; i < 58; i++) { requireThat(table[56 + i] <= 24, 'invalid-aspack-table'); bases.push(sum); sum += 2 ** table[56 + i]; }
  const output = new Uint8Array(size), history = [0, 0, 0]; let written = 0;
  update();
  while (written < size) {
    const value = symbol(dicts[0]);
    if (value < 256) { output[written++] = value; continue; }
    if (value === 720) { update(); continue; }
    const slot = (value - 256) >>> 3; let count = ((value - 256) & 7) + 2;
    if (count === 9) { const s = symbol(dicts[1]); count += table[s] + bits(table[28 + s]); }
    const n = table[56 + slot];
    let distance = bases[slot] + (special && n >= 3 ? bits(n - 3) * 8 + symbol(dicts[2]) : bits(n));
    if (distance < 3) { const old = history[distance]; if (distance) { history[distance] = history[0]; history[0] = old; } distance = old; }
    else { history[2] = history[1]; history[1] = history[0]; history[0] = distance -= 3; }
    distance++;
    requireThat(distance <= written && count <= size - written, 'invalid-back-reference');
    for (let i = 0; i < count; i++, written++) output[written] = output[written - distance];
  }
  return { bytes: output, consumed: Math.ceil(bitPosition / 8), dictionaryUpdates: updates };
}

// Directory-restoration validators, modeled on the vetted upx.js checks but
// reading the decoded image (RVA == offset). All bounds are structural
// self-checks only; nothing is ever executed. The tree walk returns the data
// leaves instead of deciding their fate: on this generation ASPack shrank the
// original .rsrc to the tree itself and re-hosted the leaf data verbatim at
// its original RVAs inside the packer section (pinned corpus: the RT_MANIFEST
// at 0x18080/0x17d, byte-identical to both the ASPack golden dump and the same
// original program's UPX golden leaf). Unmapped leaves are rescued from the
// packed file's own raw bytes, never fabricated.
function collectResourceLeaves(m, directory, mapped) {
  requireThat(directory.size >= 16 && mapped(directory.rva, directory.size), 'invalid-aspack-resources');
  const seen = new Set(), leaves = [];
  let entries = 0;
  const visit = offset => {
    requireThat(Number.isInteger(offset) && offset >= 0 && offset + 16 <= directory.size &&
      seen.size < 4096 && !seen.has(offset), 'invalid-aspack-resources');
    seen.add(offset);
    const count = m.u16(directory.rva + offset + 12) + m.u16(directory.rva + offset + 14);
    entries += count;
    requireThat(count <= 4096 && entries <= 65536 && offset + 16 + count * 8 <= directory.size, 'invalid-aspack-resources');
    for (let i = 0; i < count; i++) {
      const at = directory.rva + offset + 16 + i * 8, name = m.u32(at), target = m.u32(at + 4);
      if (name & 0x80000000) {
        const from = name & 0x7fffffff, length = m.u16(directory.rva + from);
        requireThat(length <= 1024 && from + 2 + length * 2 <= directory.size, 'invalid-aspack-resources');
      }
      if (target & 0x80000000) visit(target & 0x7fffffff);
      else {
        requireThat(target + 16 <= directory.size, 'invalid-aspack-resources');
        const rva = m.u32(directory.rva + target), size = m.u32(directory.rva + target + 4);
        requireThat(size > 0 && size <= 4 * 1024 * 1024, 'invalid-aspack-resources');
        leaves.push({ rva, size });
      }
    }
  };
  visit(0);
  requireThat(leaves.length > 0, 'invalid-aspack-resources');
  return leaves;
}

function validateRelocationRecord(m, directory, mapped, sizeOfImage) {
  requireThat(directory.size >= 8 && mapped(directory.rva, directory.size), 'invalid-aspack-relocations');
  let cursor = 0;
  while (cursor !== directory.size) {
    requireThat(directory.size - cursor >= 8, 'invalid-aspack-relocations');
    const at = directory.rva + cursor, page = m.u32(at), size = m.u32(at + 4);
    requireThat(page > 0 && page % 0x1000 === 0 && page + 0x1000 <= sizeOfImage &&
      size >= 8 && size % 4 === 0 && size <= directory.size - cursor, 'invalid-aspack-relocations');
    for (let entry = 8; entry < size; entry += 2) requireThat(m.u16(at + entry) >>> 12 <= 4, 'invalid-aspack-relocations');
    cursor += size;
  }
}

// Original base-relocation recovery. The packed header's directory 5 points at
// the packer stub's own block (unmappable once the stub sections are dropped),
// so the original table is rebuilt from the decoded `.reloc` section: a strict
// block walk with bounded pages/types, an explicit zero pair or section end as
// terminator, and an all-zero tail requirement. On the pinned corpus this
// yields {0x16000, 0xdc0}, byte-identical to the independent golden dump's
// .reloc section (3520/3520 bytes) with 1676 HIGHLOW entries — the same count
// the same original program shows under UPX (docs/research/rlde-family.md §12).
function walkRelocationSpan(m, section, sizeOfImage) {
  requireThat(section.virtualSize >= 8, 'invalid-aspack-relocations');
  const end = section.rva + section.virtualSize;
  let span = 0, blocks = 0;
  while (end - (section.rva + span) >= 8) {
    const page = m.u32(section.rva + span), size = m.u32(section.rva + span + 4);
    if (!page && !size) break;
    requireThat(page > 0 && page % 0x1000 === 0 && page + 0x1000 <= sizeOfImage &&
      size >= 8 && size % 4 === 0 && size <= end - (section.rva + span), 'invalid-aspack-relocations');
    for (let entry = 8; entry < size; entry += 2) requireThat(m.u16(section.rva + span + entry) >>> 12 <= 4, 'invalid-aspack-relocations');
    span += size;
    requireThat(++blocks <= 65536, 'invalid-aspack-relocations');
  }
  requireThat(span > 0, 'invalid-aspack-relocations');
  for (let at = section.rva + span; at < end; at++) requireThat(m.u8(at) === 0, 'invalid-aspack-relocations');
  return span;
}

function attemptDirectory(task) {
  try { task(); return true; } catch (error) {
    if (error.code === 'invalid-aspack-resources' || error.code === 'invalid-aspack-relocations') return false;
    throw error;
  }
}

export function supportsAspack(bytes, pe) {
  try { if (pe && (pe.machine !== 0x14c || pe.is64 || pe.isDll || pe.isNet)) return false; inspect(bytes); return true; } catch { return false; }
}

export function unpackAspack(bytes) {
  const plan = inspect(bytes), { pe, sections, originalEntryPoint } = plan;
  const image = new Uint8Array(pe.sizeOfImage), m = new Bytes(image);
  for (const s of sections) image.set(bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize), s.rva);
  const decodedBlocks = [];
  for (const [index, block] of plan.blocks.entries()) {
    const decoded = decodeAspackBlock(bytes.subarray(block.raw, block.raw + block.available), block.size, plan.table);
    if (index === 0) {
      const r = new Bytes(decoded.bytes);
      for (let at = 0; at < decoded.bytes.length - 5; at++) {
        if ((decoded.bytes[at] === 0xe8 || decoded.bytes[at] === 0xe9) && decoded.bytes[at + 1] === plan.mark) {
          const target = r.u32(at + 1) >>> 8; r.put32(at + 1, target - at); at += 4;
        }
      }
    }
    image.set(decoded.bytes, block.rva);
    decodedBlocks.push({ rva: block.rva, size: block.size, consumed: decoded.consumed, dictionaryUpdates: decoded.dictionaryUpdates });
  }
  const mapped = (rva, size) => sections.some(s => rva >= s.rva && rva + size <= s.rva + s.virtualSize);
  const name = rva => {
    requireThat(mapped(rva, 1), 'invalid-import-hints'); const value = m.cstring(rva, 512);
    requireThat(value.length > 0 && /^[\x21-\x7e]+$/.test(value) && mapped(rva, value.length + 1), 'invalid-import-hints'); return value;
  };
  let importSize = 0, importedModules = 0, importedFunctions = 0; const iats = [];
  for (let i = 0; i < 256; i++) {
    const at = plan.importRva + i * 20; requireThat(mapped(at, 20), 'invalid-import-hints');
    const fields = Array.from({ length: 5 }, (_, j) => m.u32(at + j * 4)); importSize += 20;
    if (fields.every(v => v === 0)) break;
    requireThat(i < 255, 'import-limit'); name(fields[3]);
    const ilt = fields[0] || fields[4], iat = fields[4]; let ended = false;
    requireThat(ilt % 4 === 0 && iat % 4 === 0, 'invalid-import-hints');
    for (let j = 0; j < 4096; j++) {
      requireThat(mapped(ilt + j * 4, 4) && mapped(iat + j * 4, 4), 'invalid-import-hints');
      const value = m.u32(ilt + j * 4); m.put32(iat + j * 4, value);
      if (!value) { iats.push({ start: iat, end: iat + (j + 1) * 4 }); ended = true; break; }
      requireThat(++importedFunctions <= 16384, 'import-limit');
      if (value & 0x80000000) requireThat((value & 0x7fff0000) === 0, 'invalid-import-hints');
      else { requireThat(mapped(value, 3), 'invalid-import-hints'); name(value + 2); }
    }
    requireThat(ended, 'import-limit'); importedModules++;
  }
  requireThat(importedModules > 0 && !iats.some((v, i) => iats.slice(0, i).some(p => v.start < p.end && p.start < v.end)), 'invalid-import-hints');
  // Per-sample directory grading (fsg.js/upx.js model): a directory is only
  // carried into rebuilt-pe output when it is either the packed header's own
  // record, mapped into the decoded image and structurally valid, or — for
  // relocations — recovered from the decoded .reloc section by the strict walk.
  // Any recorded-but-unrecoverable directory keeps the output honest at
  // analysis-pe with a specific warning; nothing is guessed.
  const restoredDirectories = { resource: 'absent', relocation: 'absent' };
  const reasons = [], directoryRecords = [];
  let relocationSource, resourceDataSection = null;
  const resourceDirectory = pe.directories[2];
  if (resourceDirectory.rva || resourceDirectory.size) {
    let leaves = null;
    if (attemptDirectory(() => { leaves = collectResourceLeaves(m, resourceDirectory, mapped); })) {
      // Leaves inside the decoded image are already final; leaves ASPack
      // re-hosted in its own section are rescued from the packed file's raw
      // bytes at their original RVAs and wrapped in one derived section that
      // exactly covers their aligned extent.
      const external = leaves.filter(leaf => !mapped(leaf.rva, leaf.size));
      const rescued = external.length === 0 || attemptDirectory(() => {
        requireThat(external.length <= 65536, 'invalid-aspack-resources');
        for (const [i, leaf] of external.entries()) {
          requireThat(!sections.some(s => leaf.rva < s.rva + s.virtualSize && s.rva < leaf.rva + leaf.size) &&
            !external.slice(0, i).some(p => leaf.rva < p.rva + p.size && p.rva < leaf.rva + leaf.size), 'invalid-aspack-resources');
          const at = pe.rvaToOffset(leaf.rva, leaf.size);
          requireThat(at !== null, 'invalid-aspack-resources');
          leaf.raw = at;
        }
        const lowest = Math.min(...external.map(leaf => leaf.rva));
        const start = Math.floor(lowest / 0x1000) * 0x1000;
        const end = align(Math.max(...external.map(leaf => leaf.rva + leaf.size)), 0x1000);
        requireThat(end - start > 0 && end - start <= 4 * 1024 * 1024 &&
          !sections.some(s => start < s.rva + s.virtualSize && s.rva < end), 'invalid-aspack-resources');
        resourceDataSection = { rva: start, virtualSize: end - start, leaves: external };
      });
      if (leaves && rescued) {
        restoredDirectories.resource = 'restored';
        directoryRecords.push({ index: 2, rva: resourceDirectory.rva, size: resourceDirectory.size });
      } else {
        restoredDirectories.resource = 'not-restored';
        reasons.push('resources-not-restorable');
      }
    } else {
      restoredDirectories.resource = 'not-restored';
      reasons.push('resources-not-restorable');
    }
  }
  const relocationDirectory = pe.directories[5];
  if (relocationDirectory.rva && relocationDirectory.size &&
    attemptDirectory(() => validateRelocationRecord(m, relocationDirectory, mapped, pe.sizeOfImage))) {
    restoredDirectories.relocation = 'restored';
    relocationSource = 'header-record';
    directoryRecords.push({ index: 5, rva: relocationDirectory.rva, size: relocationDirectory.size });
  } else {
    const relocSection = sections.find(s => s.name === '.reloc' && (s.characteristics & 0x02000000));
    let span = 0;
    if (relocSection) attemptDirectory(() => { span = walkRelocationSpan(m, relocSection, pe.sizeOfImage); });
    if (span > 0) {
      restoredDirectories.relocation = 'restored';
      relocationSource = 'reloc-section-walk';
      directoryRecords.push({ index: 5, rva: relocSection.rva, size: span });
    } else if (relocationDirectory.rva || relocationDirectory.size || sections.some(s => s.name === '.reloc')) {
      restoredDirectories.relocation = 'not-restored';
      reasons.push('relocations-not-restorable');
    }
  }
  const upgraded = reasons.length === 0;
  const headers = align(pe.sectionTable + (sections.length + (resourceDataSection ? 1 : 0)) * 40, 0x200);
  let size = headers;
  const layout = sections.map(s => { const rawOffset = size, rawSize = align(s.virtualSize, 0x200); size += rawSize; return { ...s, rawOffset, rawSize }; });
  if (resourceDataSection) {
    // Derived wrapper for the rescued resource data: a zero-filled, 0x1000-
    // aligned section covering exactly the leaf extent, bytes copied from the
    // packed file at their original RVAs (verified against two independent
    // goldens on the corpus). No layout beyond the extent is invented.
    const content = new Uint8Array(resourceDataSection.virtualSize);
    for (const leaf of resourceDataSection.leaves) content.set(bytes.subarray(leaf.raw, leaf.raw + leaf.size), leaf.rva - resourceDataSection.rva);
    const rawSize = align(resourceDataSection.virtualSize, 0x200);
    layout.push({ name: '.rsdata', rva: resourceDataSection.rva, virtualSize: resourceDataSection.virtualSize,
      rawOffset: size, rawSize, characteristics: 0x40000040, content });
    size += rawSize;
  }
  requireThat(size <= MAX_OUTPUT, 'output-size-limit');
  const output = new Uint8Array(size), out = new Bytes(output);
  output.set(bytes.subarray(0, pe.sectionTable));
  out.put16(pe.peOffset + 6, layout.length); out.put32(pe.peOffset + 12, 0); out.put32(pe.peOffset + 16, 0);
  out.put32(pe.optionalOffset + 16, originalEntryPoint); out.put32(pe.optionalOffset + 56, align(Math.max(...layout.map(s => s.rva + s.virtualSize)), 0x1000));
  out.put32(pe.optionalOffset + 60, headers); out.put32(pe.optionalOffset + 64, 0);
  out.put32(pe.optionalOffset + 4, layout.filter(s => s.characteristics & 0x20).reduce((n,s) => n+s.rawSize,0));
  out.put32(pe.optionalOffset + 8, layout.filter(s => s.characteristics & 0x40).reduce((n,s) => n+s.rawSize,0));
  out.put32(pe.optionalOffset + 12, 0);
  for (let i = 0; i < 16; i++) {
    let { rva, size } = pe.directories[i];
    if ([2, 4, 5, 6, 11, 12].includes(i) || (rva && !mapped(rva, size))) rva = size = 0;
    if (i === 1) { rva = plan.importRva; size = importSize; }
    out.put32(pe.directoryOffset + i * 8, rva); out.put32(pe.directoryOffset + i * 8 + 4, size);
  }
  for (const record of directoryRecords) {
    out.put32(pe.directoryOffset + record.index * 8, record.rva);
    out.put32(pe.directoryOffset + record.index * 8 + 4, record.size);
  }
  const iatStart = Math.min(...iats.map(v => v.start)), iatEnd = Math.max(...iats.map(v => v.end));
  out.put32(pe.directoryOffset + 12 * 8, iatStart); out.put32(pe.directoryOffset + 12 * 8 + 4, iatEnd - iatStart);
  for (const [i, s] of layout.entries()) {
    const h = pe.sectionTable + i * 40;
    if (s.headerOffset !== undefined) output.set(bytes.subarray(s.headerOffset, s.headerOffset + 40), h);
    else output.set(Uint8Array.of(0x2e, 0x72, 0x73, 0x64, 0x61, 0x74, 0x61), h); // .rsdata
    out.put32(h + 8, s.virtualSize); out.put32(h + 12, s.rva);
    out.put32(h + 16, s.rawSize); out.put32(h + 20, s.rawOffset);
    out.put32(h + 36, s.characteristics);
    output.set(s.content ?? image.subarray(s.rva, s.rva + s.virtualSize), s.rawOffset);
  }
  const result = parsePE(output, MAX_OUTPUT);
  requireThat(result.warnings.length === 0 && result.entryPointOffset !== null && result.imports.length === importedModules &&
    result.imports.reduce((n,m) => n+m.functions.length,0) === importedFunctions &&
    directoryRecords.every(record => result.rvaToOffset(record.rva, record.size) !== null), 'output-validation-failed');
  return { bytes: output, metadata: { engine: ASPACK_ENGINE.id, variant: '2.x-ep437',
    outputKind: upgraded ? 'rebuilt-pe' : 'analysis-pe', runtimeVerified: false,
    originalEntryPoint, importedModules, importedFunctions, importsRebuilt: true,
    restoredDirectories, ...(relocationSource ? { relocationSource } : {}),
    ...(resourceDataSection ? { resourceDataSection: { rva: resourceDataSection.rva, virtualSize: resourceDataSection.virtualSize } } : {}),
    decodedBlocks,
    warnings: [...(upgraded ? [] : ['analysis-only-not-runnable', ...reasons, 'unrestored-directories-cleared']),
      'runtime-not-verified', 'original-file-layout-not-preserved', 'debug-directory-removed',
      ...(pe.overlay.size ? ['overlay-not-preserved'] : []), ...(pe.directories[4].size ? ['signature-removed'] : [])] } };
}
